//! Joining a group while keeping this PC's items, matched by ID (feature `merge-join-v1`), and
//! "Mark as lost" for a managing phone that is gone. Android: `MergeJoin.kt`. Shared vectors:
//! `fixtures/merge-join-v1.json` (card_app `scripts/sync-vectors/lineage_merge.py`).
//!
//! Merge rule ([`decide`]) for each of this PC's items with the same ID as the group's:
//! - same content (the fields conflict review shows): nothing to do;
//! - both copies come from the same old group and this PC's old version is BEFORE or EQUAL the
//!   group's old version: the group saw this copy and moved on (kept, or dropped to Recently deleted);
//! - otherwise a new item is added under its own ID, and an item that differs becomes a conflict
//!   to review on every device. Nothing is decided by "newest wins".
//!
//! The freeze ([`LostFreeze`]) is local only: the old group's membership stays at the count it had,
//! and changes by the lost device after its last known one are refused.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    membership::MembershipEvent,
    protocol::{RecordVersion, VersionRelation},
    sync::GENESIS_HASH,
};

pub const FEATURE: &str = "merge-join-v1";

/// The fields compared for "same content". `lastOpenedAt` and `updatedAt` never make copies differ.
pub const ENTRY_FIELDS: [&str; 20] = [
    "type", "title", "primaryValue", "secondaryValue", "tertiaryValue", "fourthValue", "notes", "tags",
    "favorite", "sortOrder", "color", "network", "linkedAuthenticatorId", "linkedApps", "autofillSignatures",
    "autofillOrigins", "cardKind", "totpAlgorithm", "totpDigits", "totpPeriod",
];
pub const GROUP_FIELDS: [&str; 3] = ["name", "notes", "folderType"];
pub const PASSKEY_FIELDS: [&str; 8] = ["id", "rpId", "userHandle", "username", "displayName", "privateKey", "publicKey", "createdAt"];

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sync_lost_manager (
    vault_id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL,
    membership_count INTEGER NOT NULL,
    head_sequence INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    marked_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_lineage (
    from_vault_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    record_version_json TEXT NOT NULL,
    deleted INTEGER NOT NULL,
    content_digest TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (entity_type, entity_id)
);";

/// The tables, with `content_digest` added to a `sync_lineage` made before it existed.
fn schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(SCHEMA)?;
    let has_digest: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('sync_lineage') WHERE name = 'content_digest')", [], |row| row.get(0))?;
    if !has_digest {
        db.execute_batch("ALTER TABLE sync_lineage ADD COLUMN content_digest TEXT NOT NULL DEFAULT ''")?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Same,
    KeepHost,
    Drop,
    Add,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostState {
    Present,
    Deleted,
    Absent,
}

/// One field as text: missing or null is empty, booleans are true/false, numbers are integers.
pub fn normalize(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(number)) => number
            .as_i64()
            .map(|value| value.to_string())
            .or_else(|| number.as_u64().map(|value| value.to_string()))
            .unwrap_or_else(|| (number.as_f64().unwrap_or_default() as i64).to_string()),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// `left` and `right` are payload-shaped: `{"entry": …, "groupIds": […]}`, `{"group": …}` or `{"passkey": …}`.
pub fn same_content(entity_type: &str, left: &Value, right: &Value) -> bool {
    let same = |field: &str, fields: &[&str]| fields.iter().all(|name| normalize(left[field].get(name)) == normalize(right[field].get(name)));
    let groups = |value: &Value| {
        let mut ids: Vec<String> = value["groupIds"].as_array().into_iter().flatten().filter_map(|id| id.as_str().map(str::to_owned)).collect();
        ids.sort();
        ids
    };
    match entity_type {
        "entry" => same("entry", &ENTRY_FIELDS) && groups(left) == groups(right),
        "group" => same("group", &GROUP_FIELDS),
        "passkey" => same("passkey", &PASSKEY_FIELDS),
        _ => false,
    }
}

/// SHA-256 of the compared fields of a payload (`same_content`): equal digests mean the same content.
pub fn content_digest(entity_type: &str, payload: &Value) -> String {
    use sha2::{Digest, Sha256};
    let (field, fields): (&str, &[&str]) = match entity_type {
        "entry" => ("entry", &ENTRY_FIELDS),
        "group" => ("group", &GROUP_FIELDS),
        "passkey" => ("passkey", &PASSKEY_FIELDS),
        _ => return String::new(),
    };
    let mut values: Vec<String> = fields.iter().map(|name| normalize(payload[field].get(name))).collect();
    if entity_type == "entry" {
        let mut ids: Vec<String> = payload["groupIds"].as_array().into_iter().flatten().filter_map(|id| id.as_str().map(str::to_owned)).collect();
        ids.sort();
        values.push(ids.join(","));
    }
    hex::encode(Sha256::digest(values.join("\u{0}").as_bytes()))
}

/// `joiner_old`: this PC's version in the old group; `lineage`: the group's (record or delete).
/// `joiner_unchanged`: this PC's copy is still the one it had in the old group (its content digest
/// matches the lineage row). An item edited after leaving was never seen by the group, so it
/// becomes a conflict instead of being replaced or dropped (M3 of the key-rotation review).
pub fn decide(same: bool, host: HostState, shared: bool, joiner_old: Option<&RecordVersion>, lineage: Option<&RecordVersion>,
    joiner_unchanged: bool) -> Outcome {
    if host == HostState::Present && same {
        return Outcome::Same;
    }
    let seen = shared
        && joiner_unchanged
        && matches!((joiner_old, lineage), (Some(old), Some(theirs))
            if matches!(old.relation_to(theirs), VersionRelation::Before | VersionRelation::Equal));
    if seen {
        return if host == HostState::Present { Outcome::KeepHost } else { Outcome::Drop };
    }
    if host == HostState::Absent { Outcome::Add } else { Outcome::Conflict }
}

/// "Mark as lost" on this PC for group `vault_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LostFreeze {
    pub device_id: String,
    pub membership_count: u64,
    pub head_sequence: u64,
    pub head_hash: String,
}

impl LostFreeze {
    /// The `RemovalCutoff` predicate for the lost device; other authors pass.
    pub fn allows(&self, device_id: &str, sequence: u64, hash: &str) -> bool {
        device_id != self.device_id
            || ((1..=self.head_sequence).contains(&sequence) && (sequence != self.head_sequence || hash == self.head_hash))
    }

    /// The old group's history as it was when the device was marked lost.
    pub fn cap(&self, events: Vec<MembershipEvent>) -> Vec<MembershipEvent> {
        let count = usize::try_from(self.membership_count).unwrap_or(usize::MAX);
        events.into_iter().take(count).collect()
    }
}

pub fn cap(freeze: Option<&LostFreeze>, events: Vec<MembershipEvent>) -> Vec<MembershipEvent> {
    match freeze {
        Some(freeze) => freeze.cap(events),
        None => events,
    }
}

pub fn lost_freeze(db: &Connection, vault_id: &str) -> rusqlite::Result<Option<LostFreeze>> {
    db.execute_batch(SCHEMA)?;
    db.query_row(
        "SELECT device_id, membership_count, head_sequence, head_hash FROM sync_lost_manager WHERE vault_id = ?1",
        [vault_id],
        |row| {
            Ok(LostFreeze {
                device_id: row.get(0)?,
                membership_count: row.get::<_, i64>(1)?.max(0) as u64,
                head_sequence: row.get::<_, i64>(2)?.max(0) as u64,
                head_hash: row.get(3)?,
            })
        },
    )
    .optional()
}

/// The managing device of the current group, frozen at what this PC knows now. Only a member
/// that does not manage the group.
pub fn mark_lost(db: &Connection, vault_id: &str, local_device_id: &str, events: &[MembershipEvent], now: i64) -> Result<LostFreeze, String> {
    let verified = crate::membership::verify(events).map_err(|_| "This PC is not in a shared sync group".to_owned())?;
    if verified.vault_id != vault_id
        || !verified.members.get(local_device_id).is_some_and(|member| member.active)
        || verified.members.values().filter(|member| member.active).count() < 2
    {
        return Err("This PC is not in a shared sync group".to_owned());
    }
    if verified.manager_device_id == local_device_id {
        return Err("This PC manages the group".to_owned());
    }
    let head: Option<(i64, String)> = db
        .query_row(
            "SELECT sequence, hash FROM sync_device_heads WHERE vault_id = ?1 AND device_id = ?2",
            params![vault_id, verified.manager_device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let (sequence, hash) = head.unwrap_or((0, GENESIS_HASH.to_owned()));
    let freeze = LostFreeze {
        device_id: verified.manager_device_id.clone(),
        membership_count: events.len() as u64,
        head_sequence: sequence.max(0) as u64,
        head_hash: hash,
    };
    db.execute_batch(SCHEMA).map_err(|error| error.to_string())?;
    db.execute(
        "INSERT OR REPLACE INTO sync_lost_manager (vault_id, device_id, membership_count, head_sequence, head_hash, marked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![vault_id, freeze.device_id, events.len() as i64, freeze.head_sequence as i64, freeze.head_hash, now],
    )
    .map_err(|error| error.to_string())?;
    Ok(freeze)
}

pub fn clear_lost(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(SCHEMA)?;
    db.execute("DELETE FROM sync_lost_manager", [])?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LineageRecord {
    pub entity_type: String,
    pub entity_id: String,
    pub record_version_json: String,
}

/// Snapshot v4 `lineage`: the record versions of the group the host came from, without payloads.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Lineage {
    pub from_vault_id: String,
    pub records: Vec<LineageRecord>,
    pub tombstones: Vec<LineageRecord>,
}

impl Lineage {
    pub const MAX_ROWS: usize = 200_000;

    pub fn parse(value: &Value) -> Option<Self> {
        let lineage: Self = serde_json::from_value(value.clone()).ok()?;
        let valid = !lineage.from_vault_id.trim().is_empty()
            && lineage.records.len() + lineage.tombstones.len() <= Self::MAX_ROWS
            && lineage.records.iter().chain(&lineage.tombstones).all(|row| {
                !row.entity_type.trim().is_empty()
                    && !row.entity_id.trim().is_empty()
                    && serde_json::from_str::<RecordVersion>(&row.record_version_json)
                        .is_ok_and(|version| !version.counters().is_empty() && version.counters().values().all(|counter| *counter > 0))
            });
        valid.then_some(lineage)
    }

    pub fn version(&self, entity_type: &str, entity_id: &str) -> Option<RecordVersion> {
        self.records
            .iter()
            .chain(&self.tombstones)
            .find(|row| row.entity_type == entity_type && row.entity_id == entity_id)
            .and_then(|row| serde_json::from_str(&row.record_version_json).ok())
    }
}

/// This PC's old-group versions before it leaves a group: `(entity_type, entity_id) -> (version, deleted)`.
pub fn current_versions(db: &Connection) -> rusqlite::Result<Vec<(String, String, String, bool)>> {
    let mut rows: Vec<(String, String, String, bool)> = db
        .prepare("SELECT entity_type, entity_id, record_version_json FROM vault_records WHERE entity_type IN ('entry', 'group', 'passkey')")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, false)))?
        .collect::<rusqlite::Result<_>>()?;
    let tombstones: Vec<(String, String, String, bool)> = db
        .prepare("SELECT entity_type, entity_id, record_version_json FROM sync_tombstones WHERE entity_type IN ('entry', 'group', 'passkey')")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, true)))?
        .collect::<rusqlite::Result<_>>()?;
    for tombstone in tombstones {
        if !rows.iter().any(|row| row.0 == tombstone.0 && row.1 == tombstone.1) {
            rows.push(tombstone);
        }
    }
    Ok(rows)
}

/// Keeps `rows` as the lineage of group `from_vault_id`, with the content digest of each item now
/// (`digests`, `content_digest`). Only the most recent old group is kept.
pub fn save_lineage(db: &Connection, from_vault_id: &str, rows: &[(String, String, String, bool)],
    digests: &std::collections::HashMap<(String, String), String>) -> rusqlite::Result<()> {
    schema(db)?;
    db.execute("DELETE FROM sync_lineage", [])?;
    for (entity_type, entity_id, version, deleted) in rows {
        let digest = digests.get(&(entity_type.clone(), entity_id.clone())).map(String::as_str).unwrap_or_default();
        db.execute(
            "INSERT OR REPLACE INTO sync_lineage (from_vault_id, entity_type, entity_id, record_version_json, deleted, content_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![from_vault_id, entity_type, entity_id, version, deleted, digest],
        )?;
    }
    Ok(())
}

/// One kept lineage row: entity type, entity ID, old-group version, content digest when this PC left.
pub type LineageRow = (String, String, String, String);

/// The lineage this PC kept when it last left a group: its old group's ID and rows.
pub fn saved_lineage(db: &Connection) -> rusqlite::Result<Option<(String, Vec<LineageRow>)>> {
    schema(db)?;
    let rows: Vec<(String, String, String, String, String)> = db
        .prepare("SELECT from_vault_id, entity_type, entity_id, record_version_json, content_digest FROM sync_lineage ORDER BY entity_type, entity_id")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let Some(from) = rows.first().map(|row| row.0.clone()) else {
        return Ok(None);
    };
    Ok(Some((from.clone(), rows.into_iter().filter(|row| row.0 == from).map(|row| (row.1, row.2, row.3, row.4)).collect())))
}

/// A copy of the encrypted vault before a merge writes into it (same key, same format). Copies
/// older than seven days next to it are removed first.
pub fn backup_before_join(db: &Connection, vault_path: &std::path::Path, now: i64) -> Result<std::path::PathBuf, String> {
    let folder = vault_path.parent().ok_or("The vault folder is unavailable")?.join("join-backups");
    std::fs::create_dir_all(&folder).map_err(|_| "Could not save a backup before joining".to_owned())?;
    if let Ok(entries) = std::fs::read_dir(&folder) {
        for entry in entries.flatten() {
            let old = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age.as_secs() > 7 * 24 * 60 * 60);
            if old {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let target = folder.join(format!("before-join-{now}.db"));
    let partial = folder.join(format!("before-join-{now}.partial"));
    let _ = std::fs::remove_file(&partial);
    let result = db
        .execute("VACUUM INTO ?1", [partial.to_string_lossy().as_ref()])
        .map_err(|_| "Could not save a backup before joining".to_owned())
        .and_then(|_| std::fs::rename(&partial, &target).map_err(|_| "Could not save a backup before joining".to_owned()));
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    result.map(|_| target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../fixtures/merge-join-v1.json")).unwrap()
    }

    fn version(value: &Value) -> Option<RecordVersion> {
        value.as_object().map(|counters| {
            RecordVersion::new(counters.iter().map(|(device, counter)| (device.clone(), counter.as_u64().unwrap())).collect())
        })
    }

    #[test]
    fn the_vector_file_describes_this_protocol() {
        let vectors = vectors();
        assert_eq!(vectors["feature"], FEATURE);
        assert!(crate::protocol::SYNC_FEATURES.contains(&FEATURE));
        let names = |key: &str| -> Vec<String> { vectors[key].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect() };
        assert_eq!(names("entryFields"), ENTRY_FIELDS);
        assert_eq!(names("groupFields"), GROUP_FIELDS);
        assert_eq!(names("passkeyFields"), PASSKEY_FIELDS);
    }

    /// M3: the digest of a lineage row tells an item edited after leaving from the copy the group saw.
    #[test]
    fn the_content_digest_follows_the_compared_fields_only() {
        let entry = |title: &str, opened: i64| serde_json::json!({"entry": {"id": "e1", "type": "PASSWORD", "title": title,
            "lastOpenedAt": opened, "favorite": false}, "groupIds": ["b", "a"]});
        assert_eq!(content_digest("entry", &entry("Mail", 1)), content_digest("entry", &entry("Mail", 99)));
        assert_ne!(content_digest("entry", &entry("Mail", 1)), content_digest("entry", &entry("Mail 2", 1)));
        let mut regrouped = entry("Mail", 1);
        regrouped["groupIds"] = serde_json::json!(["a"]);
        assert_ne!(content_digest("entry", &entry("Mail", 1)), content_digest("entry", &regrouped));
        // Saved and read back with the lineage row.
        let db = Connection::open_in_memory().unwrap();
        let digests = std::collections::HashMap::from([(("entry".to_owned(), "e1".to_owned()), "ab".to_owned())]);
        save_lineage(&db, "old", &[("entry".into(), "e1".into(), "{}".into(), false)], &digests).unwrap();
        assert_eq!(saved_lineage(&db).unwrap().unwrap().1[0].3, "ab");
        // A table from before the column gets it.
        let old = Connection::open_in_memory().unwrap();
        old.execute_batch("CREATE TABLE sync_lineage (from_vault_id TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
            record_version_json TEXT NOT NULL, deleted INTEGER NOT NULL, PRIMARY KEY (entity_type, entity_id));
            INSERT INTO sync_lineage VALUES ('old', 'entry', 'e1', '{}', 0);").unwrap();
        assert_eq!(saved_lineage(&old).unwrap().unwrap().1[0].3, "");
    }

    #[test]
    fn every_case_decides_like_the_vectors() {
        let vectors = vectors();
        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 23);
        for case in cases {
            let kind = case["entityType"].as_str().unwrap();
            let host = match case["host"]["state"].as_str().unwrap() {
                "present" => HostState::Present,
                "deleted" => HostState::Deleted,
                _ => HostState::Absent,
            };
            let theirs = &case["host"]["content"];
            let same = !theirs.is_null() && same_content(kind, &case["joiner"]["content"], theirs);
            let outcome = decide(same, host, case["lineage"]["shared"].as_bool().unwrap(),
                version(&case["joiner"]["oldVersion"]).as_ref(), version(&case["lineage"]["version"]).as_ref(),
                !case["joiner"]["changedSinceLineage"].as_bool().unwrap());
            let expected = match case["expected"].as_str().unwrap() {
                "same" => Outcome::Same,
                "keepHost" => Outcome::KeepHost,
                "drop" => Outcome::Drop,
                "add" => Outcome::Add,
                _ => Outcome::Conflict,
            };
            assert_eq!(outcome, expected, "{}", case["name"]);
        }
    }

    #[test]
    fn the_freeze_keeps_the_old_group_as_it_was() {
        let vectors = vectors();
        let freeze = &vectors["freeze"];
        let rule = LostFreeze {
            device_id: freeze["deviceId"].as_str().unwrap().to_owned(),
            membership_count: freeze["membershipCount"].as_u64().unwrap(),
            head_sequence: freeze["headSequence"].as_u64().unwrap(),
            head_hash: freeze["headHash"].as_str().unwrap().to_owned(),
        };
        for change in freeze["changes"].as_array().unwrap() {
            assert_eq!(rule.allows(change["deviceId"].as_str().unwrap(), change["sequence"].as_u64().unwrap(),
                change["hash"].as_str().unwrap()), change["allowed"].as_bool().unwrap(), "{change}");
        }
        for events in freeze["events"].as_array().unwrap() {
            let offered = events["offered"].as_u64().unwrap() as usize;
            let kept = usize::try_from(rule.membership_count).unwrap().min(offered);
            assert_eq!(kept, events["kept"].as_u64().unwrap() as usize);
        }
    }

    #[test]
    fn a_lineage_is_checked_before_use() {
        let good = serde_json::json!({"fromVaultId": "old", "records": [{"entityType": "entry", "entityId": "e1",
            "recordVersionJson": "{\"counters\":{\"dev\":2}}"}], "tombstones": []});
        let lineage = Lineage::parse(&good).unwrap();
        assert_eq!(lineage.version("entry", "e1"), Some(RecordVersion::from_entries([("dev", 2)])));
        assert_eq!(lineage.version("entry", "e2"), None);
        let mut blank = good.clone();
        blank["fromVaultId"] = "".into();
        assert!(Lineage::parse(&blank).is_none());
        let mut zero = good.clone();
        zero["records"][0]["recordVersionJson"] = "{\"counters\":{\"dev\":0}}".into();
        assert!(Lineage::parse(&zero).is_none());
        assert!(Lineage::parse(&Value::Null).is_none());
    }

    #[test]
    fn the_freeze_and_the_lineage_are_stored_locally() {
        let db = Connection::open_in_memory().unwrap();
        assert_eq!(lost_freeze(&db, "v").unwrap(), None);
        db.execute_batch(SCHEMA).unwrap();
        db.execute("INSERT INTO sync_lost_manager VALUES ('v', 'phone', 3, 7, 'ab', 1)", []).unwrap();
        let freeze = lost_freeze(&db, "v").unwrap().unwrap();
        assert_eq!((freeze.membership_count, freeze.head_sequence), (3, 7));
        assert_eq!(lost_freeze(&db, "other").unwrap(), None);
        clear_lost(&db).unwrap();
        assert_eq!(lost_freeze(&db, "v").unwrap(), None);
        save_lineage(&db, "old", &[("entry".into(), "e1".into(), "{\"counters\":{\"a\":1}}".into(), false)], &Default::default()).unwrap();
        let (from, rows) = saved_lineage(&db).unwrap().unwrap();
        assert_eq!(from, "old");
        assert_eq!(rows.len(), 1);
    }
}
