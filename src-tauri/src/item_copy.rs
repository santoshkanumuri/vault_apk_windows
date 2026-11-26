//! "Duplicate" for an item, as on Android (`VaultViewModel.duplicateEntry`): a new item with the
//! same details, titled "<title> copy", without the secrets that belong to one account or one
//! card. The copy is a new item of its own: it syncs as one, and nothing links it to the item it
//! came from.

use serde_json::Value;

/// What a copy's title adds, as on Android.
const COPY_SUFFIX: &str = " copy";
/// The longest title an item or a note may have, in bytes (`validate_entry`, `save_rich_note`).
const MAX_TITLE_BYTES: usize = 500;

/// "<title> copy", shortened at a character boundary when the title is already near the limit.
pub fn copy_title(title: &str) -> String {
    let title = title.trim();
    let mut end = title.len().min(MAX_TITLE_BYTES - COPY_SUFFIX.len());
    while !title.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{COPY_SUFFIX}", title[..end].trim_end())
}

/// The draft of a copy of the stored item `stored` (its `data_json`), for `save_entry` without
/// an ID. `None` for an authenticator: each one is added with its own setup key, so a copy would
/// only show the same codes twice.
///
/// Kept: the type, the username or other first value (not a card's number), the website or card
/// expiry, notes, tags, color, folders (`group_ids`) and the site and app links. Left empty: a
/// login's password, a card's number, cardholder name and security code, a security answer, and
/// the link to an authenticator, so the copy holds no secret of the account or card it came from.
/// The copy is not a favorite and was never opened. Photos, previous passwords and passkeys stay
/// with the original.
pub fn entry_copy(stored: &Value, group_ids: &[String], now: i64) -> Option<Value> {
    let entry_type = stored["type"].as_str()?;
    if entry_type == "AUTHENTICATOR" {
        return None;
    }
    let mut copy = stored.as_object()?.clone();
    for key in ["id", "createdAt", "updatedAt"] {
        copy.remove(key);
    }
    copy.insert("title".into(), copy_title(stored["title"].as_str().unwrap_or_default()).into());
    if entry_type == "CARD" {
        copy.insert("primaryValue".into(), "".into());
    }
    copy.insert("secondaryValue".into(), "".into());
    // Only a note keeps its fourth value (its formatting); a card's is its security code. Notes
    // are copied with `note_copy` on this PC, but an item of that type stays safe here too.
    if entry_type != "NOTE" {
        copy.insert("fourthValue".into(), "".into());
    }
    copy.insert("linkedAuthenticatorId".into(), "".into());
    copy.insert("favorite".into(), false.into());
    copy.insert("lastOpenedAt".into(), 0.into());
    copy.insert("sortOrder".into(), now.into());
    copy.insert("groupIds".into(), group_ids.into());
    Some(Value::Object(copy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stored(entry_type: &str) -> Value {
        json!({
            "id": "original", "type": entry_type, "title": "Bank", "primaryValue": "first",
            "secondaryValue": "secret", "tertiaryValue": "third", "fourthValue": "fourth",
            "cardKind": "DEBIT", "network": "Visa", "totpAlgorithm": "SHA1", "totpDigits": 6, "totpPeriod": 30,
            "linkedApps": "com.bank.app", "autofillSignatures": "sig", "autofillOrigins": "https://bank.example",
            "linkedAuthenticatorId": "code-1", "notes": "branch 12", "color": 4278219850u64, "tags": "money",
            "favorite": true, "lastOpenedAt": 99, "sortOrder": 5, "createdAt": 1, "updatedAt": 2,
        })
    }

    #[test]
    fn a_login_copy_keeps_the_username_and_site_but_not_the_password() {
        let copy = entry_copy(&stored("PASSWORD"), &["work".to_owned()], 1_000).unwrap();
        assert_eq!(copy["title"], "Bank copy");
        assert_eq!(copy["primaryValue"], "first");
        assert_eq!(copy["secondaryValue"], "");
        assert_eq!(copy["tertiaryValue"], "third");
        assert_eq!(copy["fourthValue"], "");
        assert_eq!(copy["linkedAuthenticatorId"], "");
        assert_eq!((copy["notes"].as_str(), copy["tags"].as_str()), (Some("branch 12"), Some("money")));
        assert_eq!(copy["autofillOrigins"], "https://bank.example");
        assert_eq!(copy["linkedApps"], "com.bank.app");
        assert_eq!((copy["favorite"].as_bool(), copy["lastOpenedAt"].as_i64(), copy["sortOrder"].as_i64()), (Some(false), Some(0), Some(1_000)));
        assert_eq!(copy["groupIds"], json!(["work"]));
        // A new item: save_entry gives it its own ID and times.
        for key in ["id", "createdAt", "updatedAt"] {
            assert!(copy.get(key).is_none(), "{key}");
        }
    }

    #[test]
    fn a_card_copy_keeps_only_the_expiry_and_the_look() {
        let copy = entry_copy(&stored("CARD"), &[], 1_000).unwrap();
        // Number, cardholder name and security code are left empty.
        assert_eq!((copy["primaryValue"].as_str(), copy["secondaryValue"].as_str(), copy["fourthValue"].as_str()), (Some(""), Some(""), Some("")));
        assert_eq!(copy["tertiaryValue"], "third");
        assert_eq!((copy["network"].as_str(), copy["cardKind"].as_str()), (Some("Visa"), Some("DEBIT")));
        assert_eq!(copy["color"], 4278219850u64);
    }

    #[test]
    fn a_security_question_copy_leaves_out_the_answer() {
        let copy = entry_copy(&stored("QUESTION"), &[], 1_000).unwrap();
        assert_eq!((copy["primaryValue"].as_str(), copy["secondaryValue"].as_str()), (Some("first"), Some("")));
    }

    #[test]
    fn an_address_copy_keeps_its_details() {
        let copy = entry_copy(&stored("AUTOFILL"), &[], 1_000).unwrap();
        assert_eq!(copy["primaryValue"], "first");
    }

    #[test]
    fn an_authenticator_is_not_copied() {
        assert!(entry_copy(&stored("AUTHENTICATOR"), &[], 1_000).is_none());
        assert!(entry_copy(&json!({"title": "no type"}), &[], 1_000).is_none());
    }

    #[test]
    fn the_title_says_copy_and_stays_within_the_limit() {
        assert_eq!(copy_title("Bank"), "Bank copy");
        assert_eq!(copy_title("  Bank  "), "Bank copy");
        let long = "é".repeat(300); // 600 bytes
        let title = copy_title(&long);
        assert!(title.len() <= MAX_TITLE_BYTES, "{}", title.len());
        assert!(title.ends_with(" copy"));
        assert!(title.starts_with("éé"));
        let exact = "a".repeat(MAX_TITLE_BYTES);
        assert_eq!(copy_title(&exact).len(), MAX_TITLE_BYTES);
    }
}
