//! Exact duplicate logins, as on Android (`security/PasswordDuplicates.kt`).
//!
//! Two logins belong to the same set when every field the user controls matches and they sit in
//! the same folders. Ids, and the dates that only record when an entry was made or used, are left
//! out, so a copy an import left behind still matches the original. A login with a photo is never
//! part of a set: equal photo rows would not prove the pictures themselves are equal.

use std::collections::{BTreeMap, BTreeSet};

/// Fields that say when an entry was made or used, not what it holds.
const IGNORED: [&str; 5] = ["id", "createdAt", "updatedAt", "lastOpenedAt", "sortOrder"];

/// One set of identical logins.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DuplicateSet {
    /// The oldest copy. It stays.
    pub keep: String,
    /// The other copies, oldest first. These are the ones the user can pick for deletion.
    pub remove: Vec<String>,
}

/// What logins are grouped by: every field the user controls, and the folders the entry is in.
/// `None` for an entry this comparison cannot read, which is then left out of every set, because a
/// set must be certain before anything is offered for deletion.
fn fingerprint(entry: &serde_json::Value) -> Option<String> {
    let object = entry.as_object()?;
    let mut fields: BTreeMap<&str, &serde_json::Value> = BTreeMap::new();
    for (name, value) in object {
        if IGNORED.contains(&name.as_str()) || name == "groupIds" {
            continue;
        }
        fields.insert(name, value);
    }
    // A folder is a set, not a list: the same two folders in another order are the same membership.
    let mut groups = BTreeSet::new();
    if let Some(value) = object.get("groupIds") {
        for group in value.as_array()? {
            groups.insert(group.as_str()?);
        }
    }
    serde_json::to_string(&(fields, groups)).ok()
}

fn text<'a>(entry: &'a serde_json::Value, field: &str) -> &'a str {
    entry[field].as_str().unwrap_or_default()
}

/// Every set of identical logins among `entries`, by the rules above. `with_photos` holds the ids
/// of entries that have a photo. Sets are ordered by the kept copy, so the review reads the same
/// way each time it is opened.
pub fn duplicate_sets(
    entries: &[serde_json::Value],
    with_photos: &BTreeSet<String>,
) -> Vec<DuplicateSet> {
    let mut matched: BTreeMap<String, Vec<&serde_json::Value>> = BTreeMap::new();
    for entry in entries {
        let id = text(entry, "id");
        if id.is_empty() || text(entry, "type") != "PASSWORD" || with_photos.contains(id) {
            continue;
        }
        if let Some(fingerprint) = fingerprint(entry) {
            matched.entry(fingerprint).or_default().push(entry);
        }
    }
    let mut sets: Vec<(String, &str, &str, DuplicateSet)> = Vec::new();
    for (_, mut copies) in matched {
        if copies.len() < 2 {
            continue;
        }
        // The oldest copy is the one that stays, as on Android.
        copies.sort_by_key(|entry| {
            (
                entry["createdAt"].as_i64().unwrap_or_default(),
                text(entry, "id"),
            )
        });
        let keeper = copies.remove(0);
        sets.push((
            text(keeper, "title").to_lowercase(),
            text(keeper, "primaryValue"),
            text(keeper, "id"),
            DuplicateSet {
                keep: text(keeper, "id").to_owned(),
                remove: copies
                    .into_iter()
                    .map(|entry| text(entry, "id").to_owned())
                    .collect(),
            },
        ));
    }
    sets.sort_by(|left, right| {
        (&left.0, left.1, left.2).cmp(&(&right.0, right.1, right.2))
    });
    sets.into_iter().map(|(.., set)| set).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A saved login, as `list_entries` returns one.
    fn login(id: &str, created_at: i64) -> serde_json::Value {
        serde_json::json!({
            "id": id, "type": "PASSWORD", "title": "Mail", "primaryValue": "me@example.com",
            "secondaryValue": "synthetic-test-password", "tertiaryValue": "https://mail.example.com",
            "fourthValue": "", "cardKind": "CREDIT", "network": "", "totpAlgorithm": "SHA1",
            "totpDigits": 6, "totpPeriod": 30, "linkedApps": "", "autofillSignatures": "",
            "autofillOrigins": "", "linkedAuthenticatorId": "", "notes": "", "color": 0xFF08704A_u64,
            "tags": "", "favorite": false, "lastOpenedAt": 0, "sortOrder": created_at,
            "createdAt": created_at, "updatedAt": created_at, "groupIds": []
        })
    }

    fn none() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn copies_match_on_their_fields_alone_and_the_oldest_one_stays() {
        let mut second = login("b", 20);
        second["lastOpenedAt"] = 99.into();
        second["sortOrder"] = 1.into();
        second["updatedAt"] = 500.into();
        let entries = vec![login("c", 30), login("a", 10), second];
        assert_eq!(
            duplicate_sets(&entries, &none()),
            vec![DuplicateSet {
                keep: "a".to_owned(),
                remove: vec!["b".to_owned(), "c".to_owned()]
            }]
        );
    }

    #[test]
    fn copies_made_at_the_same_moment_are_ordered_by_id() {
        let entries = vec![login("b", 10), login("a", 10)];
        assert_eq!(
            duplicate_sets(&entries, &none()),
            vec![DuplicateSet {
                keep: "a".to_owned(),
                remove: vec!["b".to_owned()]
            }]
        );
    }

    #[test]
    fn anything_the_user_can_change_keeps_two_logins_apart() {
        let mut different_password = login("b", 20);
        different_password["secondaryValue"] = "synthetic-other-password".into();
        let mut different_note = login("c", 20);
        different_note["notes"] = "Work".into();
        let mut different_tag = login("d", 20);
        different_tag["tags"] = "work".into();
        let mut favourite = login("e", 20);
        favourite["favorite"] = true.into();
        let mut a_field_short = login("f", 20);
        a_field_short.as_object_mut().unwrap().remove("fourthValue");
        for other in [
            different_password,
            different_note,
            different_tag,
            favourite,
            a_field_short,
        ] {
            assert_eq!(
                duplicate_sets(&[login("a", 10), other.clone()], &none()),
                Vec::new(),
                "{other}"
            );
        }
    }

    #[test]
    fn a_folder_is_a_set_of_folders_and_not_their_order() {
        let mut first = login("a", 10);
        first["groupIds"] = serde_json::json!(["work", "mail"]);
        let mut second = login("b", 20);
        second["groupIds"] = serde_json::json!(["mail", "work"]);
        let mut only_one_folder = login("c", 30);
        only_one_folder["groupIds"] = serde_json::json!(["work"]);
        assert_eq!(
            duplicate_sets(&[first, second, only_one_folder], &none()),
            vec![DuplicateSet {
                keep: "a".to_owned(),
                remove: vec!["b".to_owned()]
            }]
        );
    }

    #[test]
    fn a_login_with_a_photo_is_left_out() {
        let with_photo = BTreeSet::from(["b".to_owned()]);
        assert_eq!(
            duplicate_sets(&[login("a", 10), login("b", 20)], &with_photo),
            Vec::new()
        );
        assert_eq!(
            duplicate_sets(
                &[login("a", 10), login("b", 20), login("c", 30)],
                &with_photo
            ),
            vec![DuplicateSet {
                keep: "a".to_owned(),
                remove: vec!["c".to_owned()]
            }]
        );
    }

    #[test]
    fn only_logins_are_compared() {
        let code = |id: &str| {
            serde_json::json!({"id": id, "type": "AUTHENTICATOR", "title": "Mail",
                "secondaryValue": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "createdAt": 10, "groupIds": []})
        };
        assert_eq!(duplicate_sets(&[code("a"), code("b")], &none()), Vec::new());
    }

    #[test]
    fn an_entry_this_comparison_cannot_read_is_left_out() {
        let mut odd_groups = login("b", 20);
        odd_groups["groupIds"] = serde_json::json!([7]);
        let mut groups_not_a_list = login("c", 30);
        groups_not_a_list["groupIds"] = "work".into();
        let not_an_object = serde_json::json!([login("d", 40)]);
        assert_eq!(
            duplicate_sets(
                &[
                    login("a", 10),
                    odd_groups,
                    groups_not_a_list,
                    not_an_object,
                    login("", 50)
                ],
                &none()
            ),
            Vec::new()
        );
    }

    #[test]
    fn sets_are_ordered_by_the_copy_that_stays() {
        let set = |id: &str, title: &str, user: &str, created_at: i64| {
            let mut entry = login(id, created_at);
            entry["title"] = title.into();
            entry["primaryValue"] = user.into();
            entry
        };
        let entries = vec![
            set("c1", "Zephyr", "me@example.com", 10),
            set("c2", "Zephyr", "me@example.com", 20),
            set("a1", "apex", "me@example.com", 10),
            set("a2", "apex", "me@example.com", 20),
            set("b1", "Bakery", "ann@example.com", 10),
            set("b2", "Bakery", "ann@example.com", 20),
            set("b3", "Bakery", "zoe@example.com", 10),
            set("b4", "Bakery", "zoe@example.com", 20),
        ];
        assert_eq!(
            duplicate_sets(&entries, &none())
                .into_iter()
                .map(|set| set.keep)
                .collect::<Vec<_>>(),
            vec!["a1", "b1", "b3", "c1"]
        );
    }
}
