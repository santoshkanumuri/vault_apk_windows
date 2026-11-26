//! M2: two devices that edit different fields of the same login (or folder) while apart get both
//! edits, instead of a conflict to review. Shared with Android (`EntryFieldMerge.kt`); the rule
//! and its vectors are in the Android repository's `scripts/sync-vectors/entry_merge.py`, and
//! `fixtures/entry-merge-v1.json` here is the same file byte for byte.
//!
//! Nothing on the wire changes. The merged record goes out as an ordinary signed change whose
//! version is the per-device maximum of the two versions (`RecordVersion::merged`), with no extra
//! count, so older versions of both apps apply it and close their copy of the conflict. Two devices
//! that merge the same pair write the same version and content: each sees the other's change as
//! equal, and no new conflict starts. A conflict stays for the user when the same field changed to
//! different values, the item type changed, or an edit met a delete.

use std::{cmp::Ordering, collections::BTreeSet};

use serde_json::{Map, Number, Value};

/// Entity types whose concurrent upserts merge field by field.
pub const ENTITY_TYPES: [&str; 2] = ["entry", "group"];

/// Fields of the record that take the later value instead of making a conflict.
const LATEST: [&str; 2] = ["updatedAt", "lastOpenedAt"];

/// The record's object inside the payload, by entity type.
const OBJECT_KEYS: [&str; 2] = ["entry", "group"];

fn object_key(entity_type: &str) -> Option<&'static str> {
    match entity_type {
        "entry" => Some("entry"),
        "group" => Some("group"),
        _ => None,
    }
}

/// A delete's payload: `{"deleted": true}`.
pub fn is_delete(payload: &Value) -> bool {
    payload.get("deleted") == Some(&Value::Bool(true))
        && !OBJECT_KEYS.iter().any(|key| payload.as_object().is_some_and(|object| object.contains_key(*key)))
}

/// The merged payload, or `None` when the user has to decide. `base` is the payload of the change
/// both sides started from (the change whose version is the per-device minimum of the two), or
/// `None` when this device doesn't hold it. Symmetric: swapping `local` and `remote` gives the
/// same result, so every device computes the same merge.
pub fn merge(entity_type: &str, base: Option<&Value>, local: &Value, remote: &Value) -> Option<Value> {
    let key = object_key(entity_type)?;
    if is_delete(local) || is_delete(remote) {
        return (is_delete(local) && is_delete(remote)).then(|| serde_json::json!({"deleted": true}));
    }
    let local_object = local.get(key)?.as_object()?;
    let remote_object = remote.get(key)?.as_object()?;
    if !same(local_object.get("id"), remote_object.get("id")) {
        return None;
    }
    let start = match base.filter(|base| !is_delete(base) && base.get(key).is_some_and(Value::is_object)) {
        Some(base) => base,
        None if equivalent(key, entity_type, local, remote) => local,
        None => return None,
    };
    let base_object = start.get(key)?.as_object()?;
    if entity_type == "entry"
        && !(same(base_object.get("type"), local_object.get("type")) && same(local_object.get("type"), remote_object.get("type")))
    {
        return None;
    }
    let mut result = Map::new();
    result.insert(key.to_owned(), Value::Object(merge_object(base_object, local_object, remote_object, true)?));
    if entity_type == "entry" {
        let (b, l, r) = (group_ids(start), group_ids(local), group_ids(remote));
        let ids: BTreeSet<String> = l
            .intersection(&r)
            .chain(l.difference(&b))
            .chain(r.difference(&b))
            .cloned()
            .collect();
        result.insert("groupIds".to_owned(), Value::Array(ids.into_iter().map(Value::String).collect()));
    }
    let (start, local, remote) = (start.as_object()?, local.as_object()?, remote.as_object()?);
    let others: BTreeSet<&String> = start.keys().chain(local.keys()).chain(remote.keys())
        .filter(|other| other.as_str() != key && other.as_str() != "groupIds")
        .collect();
    for other in others {
        if let Some(value) = three_way(other, start, local, remote, false)? {
            result.insert(other.clone(), value);
        }
    }
    Some(Value::Object(result))
}

fn merge_object(base: &Map<String, Value>, local: &Map<String, Value>, remote: &Map<String, Value>, latest: bool) -> Option<Map<String, Value>> {
    let keys: BTreeSet<&String> = base.keys().chain(local.keys()).chain(remote.keys()).collect();
    let mut out = Map::new();
    for key in keys {
        if let Some(value) = three_way(key, base, local, remote, latest)? {
            out.insert(key.clone(), value);
        }
    }
    Some(out)
}

/// `None`: a conflict. `Some(None)`: the key is left out (its value is null or missing).
fn three_way(key: &str, base: &Map<String, Value>, local: &Map<String, Value>, remote: &Map<String, Value>, latest: bool) -> Option<Option<Value>> {
    let (b, l, r) = (value(base, key), value(local, key), value(remote, key));
    if latest && LATEST.contains(&key) {
        if let (Some(Value::Number(x)), Some(Value::Number(y))) = (l, r) {
            let later = if compare(x, y) != Some(Ordering::Less) { l } else { r };
            return Some(later.cloned());
        }
    }
    if same(l, b) {
        Some(r.cloned())
    } else if same(r, b) || same(l, r) {
        Some(l.cloned())
    } else {
        None
    }
}

/// Equal apart from the latest-wins fields: two devices chose the same side, no base needed.
fn equivalent(key: &str, entity_type: &str, local: &Value, remote: &Value) -> bool {
    let (Some(l), Some(r)) = (local.get(key).and_then(Value::as_object), remote.get(key).and_then(Value::as_object)) else {
        return false;
    };
    if !l.keys().chain(r.keys()).filter(|field| !LATEST.contains(&field.as_str())).all(|field| same(value(l, field), value(r, field))) {
        return false;
    }
    let (Some(lo), Some(ro)) = (local.as_object(), remote.as_object()) else { return false };
    if !lo.keys().chain(ro.keys()).filter(|other| other.as_str() != key && other.as_str() != "groupIds")
        .all(|other| same(value(lo, other), value(ro, other)))
    {
        return false;
    }
    entity_type != "entry" || group_ids(local) == group_ids(remote)
}

fn group_ids(payload: &Value) -> BTreeSet<String> {
    payload
        .get("groupIds")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().map(|id| id.as_str().map_or_else(|| id.to_string(), str::to_owned)).collect())
        .unwrap_or_default()
}

fn value<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !value.is_null())
}

/// The same JSON value: numbers by value, a missing key and null alike.
pub fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a.filter(|v| !v.is_null()), b.filter(|v| !v.is_null())) {
        (None, None) => true,
        (None, _) | (_, None) => false,
        (Some(Value::Number(x)), Some(Value::Number(y))) => compare(x, y) == Some(Ordering::Equal),
        (Some(Value::Object(x)), Some(Value::Object(y))) => {
            x.keys().chain(y.keys()).all(|key| same(value(x, key), value(y, key)))
        }
        (Some(Value::Array(x)), Some(Value::Array(y))) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(Some(p), Some(q)))
        }
        (Some(x), Some(y)) => x == y,
    }
}

/// Numbers by value: integers exactly, anything else as a double.
fn compare(x: &Number, y: &Number) -> Option<Ordering> {
    fn integer(number: &Number) -> Option<i128> {
        number.as_i64().map(i128::from).or_else(|| number.as_u64().map(i128::from))
    }
    match (integer(x), integer(y)) {
        (Some(a), Some(b)) => Some(a.cmp(&b)),
        _ => x.as_f64()?.partial_cmp(&y.as_f64()?),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::protocol::{RecordVersion, VersionRelation};

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../fixtures/entry-merge-v1.json")).unwrap()
    }

    fn version(value: &Value) -> RecordVersion {
        RecordVersion::new(value.as_object().unwrap().iter().map(|(device, counter)| (device.clone(), counter.as_u64().unwrap())).collect())
    }

    /// The per-device minimum of two versions, zero counters dropped (the base's version).
    fn meet(local: &RecordVersion, remote: &RecordVersion) -> RecordVersion {
        crate::conflicts::meet(local, remote)
    }

    #[test]
    fn every_case_merges_as_the_shared_rule_says() {
        let vectors = vectors();
        assert_eq!(vectors["rule"], "entry-merge-v1");
        let cases = vectors["cases"].as_array().unwrap();
        assert!(cases.len() >= 15);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let base = Some(&case["base"]).filter(|base| !base.is_null());
            let expected = Some(&case["expected"]).filter(|expected| !expected.is_null());
            // Both directions: every device computes the same result, whichever side is its own.
            for (first, second) in [(&case["local"], &case["remote"]), (&case["remote"], &case["local"])] {
                let merged = merge(case["entityType"].as_str().unwrap(), base, first, second);
                match expected {
                    None => assert_eq!(merged, None, "{name}"),
                    Some(expected) => assert!(same(Some(expected), merged.as_ref()), "{name}: {merged:?}"),
                }
            }
        }
    }

    #[test]
    fn the_merge_version_includes_both_sides_with_no_extra_count() {
        for case in vectors()["versions"].as_array().unwrap() {
            let (local, remote) = (version(&case["local"]), version(&case["remote"]));
            assert_eq!(meet(&local, &remote), version(&case["meet"]));
            assert_eq!(local.merged(&remote), version(&case["join"]));
            assert_eq!(local.merged(&remote), remote.merged(&local));
            // The merge is newer than both sides, so it settles the conflict everywhere.
            assert_eq!(local.merged(&remote).relation_to(&local), VersionRelation::After);
            assert_eq!(local.merged(&remote).relation_to(&remote), VersionRelation::After);
        }
    }

    #[test]
    fn numbers_compare_by_value() {
        assert!(same(Some(&json!(30)), Some(&json!(30.0))));
        assert!(same(None, Some(&Value::Null)));
        assert!(!same(Some(&json!("30")), Some(&json!(30))));
        assert!(!same(Some(&json!(true)), Some(&json!(1))));
        assert!(is_delete(&json!({"deleted": true})));
        assert!(!is_delete(&json!({"deleted": true, "entry": {}})));
    }
}
