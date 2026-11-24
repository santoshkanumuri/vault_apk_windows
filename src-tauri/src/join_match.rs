//! When a PC that already holds items joins a group (`snapshot_import.rs`), each of its items is
//! matched against the group's items, so the same item does not show twice afterwards.
//!
//! - [`Match::Same`]: the group has the same item, and the PC's copy holds nothing the group's
//!   copy lacks. The PC's copy is dropped.
//! - [`Match::Differs`]: the group has the same account (or note title, card number, code) with
//!   other content, for example another password. The group's version stays; the PC's version
//!   goes to Recently deleted for review (`local_recovery::keep_join_copy`).
//! - [`Match::New`]: added to the group as a new item, as before.
//!
//! The account rules follow Android's import matching: `sameImportedAccount` and
//! `sameImportedLogin` in `security/BrowserPasswords.kt`, and `authenticatorImportStatuses` in
//! `security/AuthenticatorImport.kt`. Nothing here changes what goes over the wire.

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub enum Match {
    /// The group's item with the same content.
    Same(String),
    /// The group's item for the same account, with other content.
    Differs(String),
    New,
}

/// The group's items (entries and notes, in backup JSON), indexed by their match keys.
pub struct GroupItems<'a> {
    by_key: HashMap<String, Vec<&'a Value>>,
}

impl<'a> GroupItems<'a> {
    pub fn new(items: impl IntoIterator<Item = &'a Value>) -> Self {
        let mut by_key: HashMap<String, Vec<&'a Value>> = HashMap::new();
        for item in items {
            for key in keys(item) {
                by_key.entry(key).or_default().push(item);
            }
        }
        for candidates in by_key.values_mut() {
            candidates.sort_by(|a, b| text(a, "id").cmp(text(b, "id")));
        }
        Self { by_key }
    }

    /// Finds the group's item for a PC item (entry JSON, or a note as `vault::note_sync_json`).
    pub fn find(&self, local: &Value) -> Match {
        let mut candidates: BTreeMap<&str, &Value> = BTreeMap::new();
        for key in keys(local) {
            for item in self.by_key.get(&key).into_iter().flatten() {
                candidates.insert(text(item, "id"), item);
            }
        }
        if let Some((id, _)) = candidates.iter().find(|(_, item)| covers(item, local)) {
            return Match::Same((*id).to_owned());
        }
        match candidates.keys().next() {
            Some(id) => Match::Differs((*id).to_owned()),
            None => Match::New,
        }
    }
}

/// What this PC's join did with its items. The pairing screen and the activity log show it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JoinSummary {
    /// The group already had these items; the PC's copies were dropped.
    pub already_there: u32,
    /// The group has another version; the PC's version is in Recently deleted.
    pub needs_review: u32,
    /// New to the group; they sync to the other devices as ordinary changes.
    pub added: u32,
    /// Same ID as the group's item with other content: both versions wait in Sync conflicts.
    pub conflicts: u32,
    /// Deleted in the group after it had this PC's version: this PC's copy is in Recently deleted.
    pub deleted_in_group: u32,
}

impl JoinSummary {
    /// One or more short sentences, or `None` when the PC had no items.
    pub fn describe(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.already_there > 0 {
            parts.push(match self.already_there {
                1 => "1 item from this PC was already on your phone.".to_owned(),
                count => format!("{count} items from this PC were already on your phone."),
            });
        }
        if self.needs_review > 0 {
            parts.push(match self.needs_review {
                1 => "1 needs review: your phone's version is kept, and this PC's version is in Recently deleted.".to_owned(),
                count => format!("{count} need review: your phone's versions are kept, and this PC's versions are in Recently deleted."),
            });
        }
        if self.added > 0 {
            parts.push(match self.added {
                1 => "1 new item from this PC was added.".to_owned(),
                count => format!("{count} new items from this PC were added."),
            });
        }
        if self.conflicts > 0 {
            parts.push(match self.conflicts {
                1 => "1 item differs from the group's copy. Review it in Sync conflicts.".to_owned(),
                count => format!("{count} items differ from the group's copies. Review them in Sync conflicts."),
            });
        }
        if self.deleted_in_group > 0 {
            parts.push(match self.deleted_in_group {
                1 => "1 item was deleted in the group. It is in Recently deleted.".to_owned(),
                count => format!("{count} items were deleted in the group. They are in Recently deleted."),
            });
        }
        (!parts.is_empty()).then(|| parts.join(" "))
    }
}

fn text<'v>(value: &'v Value, key: &str) -> &'v str {
    value[key].as_str().unwrap_or_default()
}

/// Lowercase and trimmed, for titles and names in keys.
fn fold(value: &str) -> String {
    value.trim().to_lowercase()
}

/// A login's site: the host (and port) without scheme, user info, path or trailing dot.
/// "https://GitHub.com/login" and "github.com" give the same site.
pub fn site(url: &str) -> String {
    let url = url.trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
    host.trim_end_matches('.').to_lowercase()
}

fn digits(value: &str) -> String {
    value.chars().filter(char::is_ascii_digit).collect()
}

/// A code's secret as Android compares it: no spaces, uppercase, no "=" padding.
fn secret(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .to_uppercase()
        .trim_end_matches('=')
        .to_owned()
}

/// The keys that make two items "the same account" (or the same note, card or code).
fn keys(item: &Value) -> Vec<String> {
    let kind = text(item, "type");
    let title = fold(text(item, "title"));
    let primary = text(item, "primaryValue").trim();
    let mut keys = Vec::new();
    match kind {
        "PASSWORD" => {
            let site = site(text(item, "tertiaryValue"));
            if site.is_empty() {
                // Android's fallback: same title, username and website text.
                keys.push(format!("P~\u{1f}{title}\u{1f}{primary}\u{1f}{}", text(item, "tertiaryValue").trim()));
            } else {
                keys.push(format!("P\u{1f}{site}\u{1f}{primary}"));
            }
        }
        "CARD" => {
            let number = digits(primary);
            if number.len() >= 8 {
                keys.push(format!("C\u{1f}{number}"));
            } else if !title.is_empty() {
                keys.push(format!("C~\u{1f}{title}"));
            }
        }
        "AUTHENTICATOR" => {
            let secret = secret(text(item, "secondaryValue"));
            if !secret.is_empty() {
                keys.push(format!("A\u{1f}{secret}"));
            }
            // Android's "conflict": same issuer and account with another secret.
            keys.push(format!("A~\u{1f}{title}\u{1f}{}", primary.to_lowercase()));
        }
        "QUESTION" => keys.push(format!("Q\u{1f}{title}\u{1f}{}", primary.to_lowercase())),
        "AUTOFILL" if !title.is_empty() => keys.push(format!("F\u{1f}{title}")),
        "NOTE" if !title.is_empty() => keys.push(format!("N\u{1f}{title}")),
        _ => {}
    }
    keys
}

/// True when dropping `local` loses nothing: every value it holds is the same in `group`.
/// Learned autofill links, colors, favorites and times are not content.
fn covers(group: &Value, local: &Value) -> bool {
    let kind = text(local, "type");
    if text(group, "type") != kind {
        return false;
    }
    // Text the person typed: the PC's value must be empty or the same (trimmed).
    let mut trimmed = vec!["title", "notes", "tags"];
    // Secrets compare exactly: a trailing space can be part of a password.
    let mut exact = vec![];
    match kind {
        "PASSWORD" => {
            trimmed.push("primaryValue");
            exact.push("secondaryValue");
            if site(text(local, "tertiaryValue")) != site(text(group, "tertiaryValue")) {
                return false;
            }
        }
        "CARD" => {
            trimmed.extend(["secondaryValue", "tertiaryValue", "network"]);
            exact.push("fourthValue");
            let number = digits(text(local, "primaryValue"));
            if !number.is_empty() && number != digits(text(group, "primaryValue")) {
                return false;
            }
            if local["cardKind"] != group["cardKind"] {
                return false;
            }
        }
        "AUTHENTICATOR" => {
            trimmed.push("primaryValue");
            if secret(text(local, "secondaryValue")) != secret(text(group, "secondaryValue"))
                || !text(local, "totpAlgorithm").eq_ignore_ascii_case(text(group, "totpAlgorithm"))
                || local["totpDigits"].as_i64() != group["totpDigits"].as_i64()
                || local["totpPeriod"].as_i64() != group["totpPeriod"].as_i64()
            {
                return false;
            }
        }
        "QUESTION" => {
            trimmed.push("primaryValue");
            exact.push("secondaryValue");
        }
        "AUTOFILL" => {
            if !same_profile(text(local, "primaryValue"), text(group, "primaryValue")) {
                return false;
            }
        }
        "NOTE" => {}
        _ => return false,
    }
    trimmed.iter().all(|field| {
        let mine = text(local, field).trim();
        mine.is_empty() || mine == text(group, field).trim()
    }) && exact.iter().all(|field| {
        let mine = text(local, field);
        mine.is_empty() || mine == text(group, field)
    })
}

/// Contact details are a JSON object of text fields: every value on the PC must be on the phone.
fn same_profile(local: &str, group: &str) -> bool {
    match (serde_json::from_str::<Value>(local), serde_json::from_str::<Value>(group)) {
        (Ok(Value::Object(mine)), Ok(Value::Object(theirs))) => mine.iter().all(|(key, value)| match value {
            Value::String(value) if value.trim().is_empty() => true,
            Value::String(value) => theirs.get(key).and_then(Value::as_str).is_some_and(|other| other.trim() == value.trim()),
            Value::Null => true,
            other => theirs.get(key) == Some(other),
        }),
        _ => local.trim().is_empty() || local.trim() == group.trim(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn login(id: &str, url: &str, user: &str, password: &str) -> Value {
        json!({"id": id, "type": "PASSWORD", "title": "GitHub", "primaryValue": user,
            "secondaryValue": password, "tertiaryValue": url, "notes": "", "tags": ""})
    }

    #[test]
    fn a_login_matches_by_site_and_username_and_differs_by_password() {
        let phone = [login("p1", "https://github.com", "alice", "s3cret")];
        let group = GroupItems::new(&phone);
        assert_eq!(group.find(&login("w1", "https://GitHub.com/login", "alice", "s3cret")), Match::Same("p1".into()));
        assert_eq!(group.find(&login("w2", "github.com", "alice", "other")), Match::Differs("p1".into()));
        assert_eq!(group.find(&login("w3", "https://github.com", "bob", "s3cret")), Match::New);
        assert_eq!(group.find(&login("w4", "https://gitlab.com", "alice", "s3cret")), Match::New);
        // A trailing space is part of a password: not the same.
        assert_eq!(group.find(&login("w5", "https://github.com", "alice", "s3cret ")), Match::Differs("p1".into()));
    }

    #[test]
    fn extra_text_on_the_pc_is_not_dropped() {
        let phone = [login("p1", "https://github.com", "alice", "s3cret")];
        let group = GroupItems::new(&phone);
        let mut with_notes = login("w1", "https://github.com", "alice", "s3cret");
        with_notes["notes"] = "Recovery codes in the safe".into();
        assert_eq!(group.find(&with_notes), Match::Differs("p1".into()));
        // The phone holding more than the PC is fine: the PC loses nothing.
        let mut phone_notes = login("p2", "https://example.com", "alice", "x");
        phone_notes["notes"] = "Only on the phone".into();
        let phone = [phone_notes];
        let group = GroupItems::new(&phone);
        assert_eq!(group.find(&login("w2", "https://example.com", "alice", "x")), Match::Same("p2".into()));
    }

    #[test]
    fn a_login_without_a_website_uses_android_fallback() {
        let mut phone = login("p1", "", "alice", "pin");
        phone["title"] = "Router".into();
        let phone = [phone];
        let group = GroupItems::new(&phone);
        let mut same = login("w1", "", "alice", "pin");
        same["title"] = "router ".into();
        assert_eq!(group.find(&same), Match::Differs("p1".into()), "title text differs");
        same["title"] = "Router".into();
        assert_eq!(group.find(&same), Match::Same("p1".into()));
    }

    #[test]
    fn cards_codes_notes_questions_and_details() {
        let phone = [
            json!({"id": "c1", "type": "CARD", "title": "Visa", "primaryValue": "4111 1111 1111 1111",
                "secondaryValue": "A Doe", "tertiaryValue": "12/30", "fourthValue": "123", "cardKind": "CREDIT", "network": "Visa"}),
            json!({"id": "a1", "type": "AUTHENTICATOR", "title": "GitHub", "primaryValue": "alice",
                "secondaryValue": "JBSW Y3DP EHPK 3PXP", "totpAlgorithm": "SHA1", "totpDigits": 6, "totpPeriod": 30}),
            json!({"id": "n1", "type": "NOTE", "title": "Wi-Fi", "notes": "guest / tea-time"}),
            json!({"id": "q1", "type": "QUESTION", "title": "Bank", "primaryValue": "First pet?", "secondaryValue": "Rex"}),
            json!({"id": "f1", "type": "AUTOFILL", "title": "Home", "primaryValue": "{\"name\":\"A Doe\",\"city\":\"Oslo\"}"}),
        ];
        let group = GroupItems::new(&phone);
        let card = json!({"id": "w", "type": "CARD", "title": "Visa", "primaryValue": "4111111111111111",
            "secondaryValue": "A Doe", "tertiaryValue": "12/30", "fourthValue": "", "cardKind": "CREDIT", "network": "Visa"});
        assert_eq!(group.find(&card), Match::Same("c1".into()));
        let mut expiry = card.clone();
        expiry["tertiaryValue"] = "01/31".into();
        assert_eq!(group.find(&expiry), Match::Differs("c1".into()));
        let code = json!({"id": "w", "type": "AUTHENTICATOR", "title": "GitHub", "primaryValue": "alice",
            "secondaryValue": "jbswy3dpehpk3pxp==", "totpAlgorithm": "sha1", "totpDigits": 6, "totpPeriod": 30});
        assert_eq!(group.find(&code), Match::Same("a1".into()));
        let mut reissued = code.clone();
        reissued["secondaryValue"] = "NEWSECRET234".into();
        assert_eq!(group.find(&reissued), Match::Differs("a1".into()), "same issuer and account, new secret");
        let note = json!({"id": "w", "type": "NOTE", "title": "wi-fi", "notes": "guest / tea-time"});
        assert_eq!(group.find(&note), Match::Differs("n1".into()), "title text differs");
        assert_eq!(group.find(&json!({"id": "w", "type": "NOTE", "title": "Wi-Fi", "notes": "guest / tea-time"})), Match::Same("n1".into()));
        assert_eq!(group.find(&json!({"id": "w", "type": "NOTE", "title": "Wi-Fi", "notes": "new"})), Match::Differs("n1".into()));
        assert_eq!(group.find(&json!({"id": "w", "type": "NOTE", "title": "Other", "notes": "guest / tea-time"})), Match::New);
        assert_eq!(group.find(&json!({"id": "w", "type": "QUESTION", "title": "Bank", "primaryValue": "first pet?", "secondaryValue": "Rex"})), Match::Differs("q1".into()));
        assert_eq!(group.find(&json!({"id": "w", "type": "QUESTION", "title": "Bank", "primaryValue": "First pet?", "secondaryValue": "Rex"})), Match::Same("q1".into()));
        assert_eq!(group.find(&json!({"id": "w", "type": "AUTOFILL", "title": "Home", "primaryValue": "{\"name\":\"A Doe\",\"city\":\"\"}"})), Match::Same("f1".into()));
        assert_eq!(group.find(&json!({"id": "w", "type": "AUTOFILL", "title": "Home", "primaryValue": "{\"name\":\"A Doe\",\"city\":\"Bergen\"}"})), Match::Differs("f1".into()));
        // A note never matches a login, even with the same title.
        assert_eq!(group.find(&json!({"id": "w", "type": "NOTE", "title": "GitHub", "notes": ""})), Match::New);
    }

    #[test]
    fn an_exact_copy_wins_over_an_earlier_near_match() {
        let phone = [login("a", "https://github.com", "alice", "old"), login("b", "https://github.com", "alice", "new")];
        let group = GroupItems::new(&phone);
        assert_eq!(group.find(&login("w", "https://github.com", "alice", "new")), Match::Same("b".into()));
        assert_eq!(group.find(&login("w", "https://github.com", "alice", "third")), Match::Differs("a".into()));
    }

    #[test]
    fn the_summary_reads_as_plain_sentences() {
        assert_eq!(JoinSummary::default().describe(), None);
        assert_eq!(
            JoinSummary { already_there: 12, needs_review: 2, added: 3, ..Default::default() }.describe().unwrap(),
            "12 items from this PC were already on your phone. 2 need review: your phone's versions are kept, \
             and this PC's versions are in Recently deleted. 3 new items from this PC were added."
        );
        assert_eq!(
            JoinSummary { already_there: 1, needs_review: 1, added: 1, ..Default::default() }.describe().unwrap(),
            "1 item from this PC was already on your phone. 1 needs review: your phone's version is kept, \
             and this PC's version is in Recently deleted. 1 new item from this PC was added."
        );
    }
}
