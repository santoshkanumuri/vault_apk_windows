//! Import from a KeePass database (`.kdbx`: KeePassXC, KeePass 2, KeePassDX, Strongbox ...).
//!
//! The file is opened in memory with the user's KeePass password and key file, and never stored.
//! Each KeePass entry with a password becomes a Nuvori login:
//! - Title, UserName, Password, URL and Notes go to the same Nuvori fields.
//! - The group path and the entry's own tags become tags, for example "KeePass: Work / Mail".
//! - Other fields are added to the notes as "Name: value" lines, so nothing is lost.
//! - A TOTP setup (`otp` field, or KeePass 2's `TimeOtp-*` fields) becomes an authenticator code
//!   linked to the login.
//!
//! An entry without a password (a KeePass "secure note", or a username alone) becomes a Nuvori
//! note with its fields as text, and a code-only entry becomes an authenticator code.
//!
//! Not imported: entries in the Recycle Bin and the templates group, earlier versions (history),
//! attachments, and passkeys (KeePassXC `KPEX_PASSKEY_*` fields); the preview counts them.
//! A login that already exists with the same website, username and password is skipped.

use std::collections::BTreeSet;

use keepass::{Database, DatabaseKey, db::fields};
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

/// A larger file is refused before parsing.
pub const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum KeepassError {
    #[error("Enter the KeePass password, choose its key file, or both.")]
    NoKey,
    #[error("The KeePass file is larger than 32 MB.")]
    TooLarge,
    #[error("The password or key file is wrong for this KeePass database.")]
    WrongKey,
    #[error("This file isn't a KeePass database Nuvori can read.")]
    Unreadable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Code {
    /// Base32, upper case, without padding.
    pub secret: String,
    pub algorithm: &'static str,
    pub digits: u32,
    pub period: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub code: Option<Code>,
}

impl Login {
    pub fn has_password(&self) -> bool {
        !self.password.trim().is_empty()
    }

    /// The text of a note for an entry without a password.
    pub fn note_body(&self) -> String {
        let mut lines = Vec::new();
        if !self.username.is_empty() { lines.push(format!("Username: {}", self.username)); }
        if !self.url.is_empty() { lines.push(format!("Website: {}", self.url)); }
        if !self.tags.is_empty() { lines.push(format!("Tags: {}", self.tags)); }
        let mut body = lines.join("
");
        if !self.notes.is_empty() {
            if !body.is_empty() { body.push_str("

"); }
            body.push_str(&self.notes);
        }
        if body.is_empty() { self.title.clone() } else { body }
    }
}

impl Drop for Login {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.notes.zeroize();
        if let Some(code) = &mut self.code {
            code.secret.zeroize();
        }
    }
}

/// What the file holds, before anything is saved.
#[derive(Debug, Default)]
pub struct Plan {
    pub logins: Vec<Login>,
    pub in_recycle_bin: usize,
    pub without_content: usize,
    pub attachments: usize,
    pub passkeys: usize,
}

/// The preview the import dialog shows. No secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub logins: usize,
    pub codes: usize,
    /// Entries without a password and without a code: imported as notes.
    pub notes: usize,
    pub groups: Vec<String>,
    pub in_recycle_bin: usize,
    pub without_content: usize,
    pub attachments: usize,
    pub passkeys: usize,
    /// Filled in by the import: logins that were already in the vault.
    pub duplicates: usize,
    /// Filled in by the import: codes that Nuvori could not use (bad setup key or settings).
    pub codes_skipped: usize,
}

impl Plan {
    pub fn summary(&self) -> Summary {
        let groups: BTreeSet<String> = self.logins.iter()
            .filter_map(|login| login.tags.split(", ").find_map(|tag| tag.strip_prefix("KeePass: ")).map(str::to_owned))
            .collect();
        Summary {
            logins: self.logins.iter().filter(|login| login.has_password()).count(),
            codes: self.logins.iter().filter(|login| login.code.is_some()).count(),
            notes: self.logins.iter().filter(|login| !login.has_password() && login.code.is_none()).count(),
            groups: groups.into_iter().take(50).collect(),
            in_recycle_bin: self.in_recycle_bin,
            without_content: self.without_content,
            attachments: self.attachments,
            passkeys: self.passkeys,
            ..Summary::default()
        }
    }
}

/// Opens `data` with the password and key file and lists what an import would add.
pub fn read(data: &[u8], password: &str, key_file: Option<&[u8]>) -> Result<Plan, KeepassError> {
    if data.len() > MAX_FILE_BYTES {
        return Err(KeepassError::TooLarge);
    }
    if password.is_empty() && key_file.is_none() {
        return Err(KeepassError::NoKey);
    }
    let mut key = DatabaseKey::new();
    if !password.is_empty() {
        key = key.with_password(password);
    }
    if let Some(mut file) = key_file {
        key = key.with_keyfile(&mut file).map_err(|_| KeepassError::Unreadable)?;
    }
    let database = Database::parse(data, key).map_err(|error| match error {
        // KDBX 4 checks the key with a header HMAC (Key); KDBX 3 finds out while decrypting (Cryptography).
        keepass::db::DatabaseOpenError::Key(_) | keepass::db::DatabaseOpenError::Cryptography(_) => KeepassError::WrongKey,
        _ => KeepassError::Unreadable,
    })?;
    Ok(plan(&database))
}

fn plan(database: &Database) -> Plan {
    let recycle_bin = database.meta.recyclebin_uuid.filter(|_| database.meta.recyclebin_enabled != Some(false));
    let templates = database.meta.entry_templates_group;
    let root = database.root().id().uuid();
    let mut plan = Plan::default();
    for entry in database.iter_all_entries() {
        // The group path from the top, without the root group; stop at the Recycle Bin or templates.
        let mut path = Vec::new();
        let mut excluded = false;
        let mut group_id = Some(entry.parent().id());
        while let Some(current) = group_id.and_then(|id| database.group(id)) {
            let id = current.id().uuid();
            if Some(id) == recycle_bin || Some(id) == templates {
                excluded = true;
            }
            if id != root {
                path.push(current.name.trim().replace(',', " "));
            }
            group_id = current.parent().map(|parent| parent.id());
        }
        if excluded {
            plan.in_recycle_bin += 1;
            continue;
        }
        path.reverse();
        plan.attachments += entry.attachments().count();
        let field = |name: &str| entry.get(name).unwrap_or_default().trim().to_owned();
        let username = field(fields::USERNAME);
        let password = Zeroizing::new(entry.get(fields::PASSWORD).unwrap_or_default().to_owned());
        let url = field(fields::URL);
        let code = code_of(&entry);
        let mut passkey = false;
        let mut extra = Vec::new();
        let mut names: Vec<&String> = entry.fields.keys().collect();
        names.sort();
        for name in names {
            if fields::KNOWN_FIELDS.contains(&name.as_str()) || name == fields::OTP || name.starts_with("TimeOtp-") {
                continue;
            }
            if name.starts_with("KPEX_PASSKEY_") {
                passkey = true;
                continue;
            }
            let value = entry.get(name).unwrap_or_default().trim();
            if !value.is_empty() {
                extra.push(format!("{name}: {value}"));
            }
        }
        if passkey {
            plan.passkeys += 1;
        }
        let mut notes = entry.get(fields::NOTES).unwrap_or_default().trim().to_owned();
        if username.is_empty() && password.trim().is_empty() && code.is_none() && url.is_empty() && notes.is_empty() && extra.is_empty() {
            plan.without_content += 1;
            continue;
        }
        if !extra.is_empty() {
            if !notes.is_empty() {
                notes.push_str("\n\n");
            }
            notes.push_str("KeePass fields:\n");
            notes.push_str(&extra.join("\n"));
        }
        let mut tags: Vec<String> = Vec::new();
        if !path.is_empty() {
            tags.push(format!("KeePass: {}", path.join(" / ")));
        }
        tags.extend(entry.tags.iter().map(|tag| tag.trim().replace(',', " ")).filter(|tag| !tag.is_empty()));
        let title = Some(field(fields::TITLE)).filter(|title| !title.is_empty())
            .or_else(|| host(&url))
            .or_else(|| Some(username.clone()).filter(|name| !name.is_empty()))
            .unwrap_or_else(|| "KeePass entry".to_owned());
        plan.logins.push(Login {
            title: title.chars().take(200).collect(),
            username,
            password: password.to_string(),
            url,
            notes,
            tags: tags.join(", "),
            code,
        });
    }
    plan
}

fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// The entry's TOTP: KeePassXC's `otp` URI, or KeePass 2's `TimeOtp-*` fields.
fn code_of(entry: &keepass::db::Entry) -> Option<Code> {
    let clean = |secret: &str| -> Option<String> {
        let secret: String = secret.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-').collect::<String>().to_ascii_uppercase();
        (!secret.is_empty() && secret.bytes().all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))).then_some(secret)
    };
    if let Ok(totp) = entry.get_otp() {
        let algorithm = match totp.algorithm {
            keepass::db::TOTPAlgorithm::Sha1 => "SHA1",
            keepass::db::TOTPAlgorithm::Sha256 => "SHA256",
            keepass::db::TOTPAlgorithm::Sha512 => "SHA512",
            _ => return None,
        };
        let secret = Zeroizing::new(totp.get_secret());
        return Some(Code { secret: clean(&secret)?, algorithm, digits: totp.digits, period: totp.period });
    }
    let secret = entry.get("TimeOtp-Secret-Base32")?;
    let algorithm = match entry.get("TimeOtp-Algorithm").unwrap_or("HMAC-SHA-1") {
        "HMAC-SHA-256" => "SHA256",
        "HMAC-SHA-512" => "SHA512",
        _ => "SHA1",
    };
    Some(Code {
        secret: clean(secret)?,
        algorithm,
        digits: entry.get("TimeOtp-Length").and_then(|value| value.parse().ok()).unwrap_or(6),
        period: entry.get("TimeOtp-Period").and_then(|value| value.parse().ok()).unwrap_or(30),
    })
}

#[cfg(test)]
mod tests {
    use keepass::{Database, DatabaseKey, db::fields};

    use super::*;

    /// A real KDBX 4 file, written by the keepass crate with the given password.
    fn kdbx(password: &str, build: impl FnOnce(&mut Database)) -> Vec<u8> {
        let mut database = Database::new();
        build(&mut database);
        let mut bytes = Vec::new();
        database.save(&mut bytes, DatabaseKey::new().with_password(password)).unwrap();
        bytes
    }

    fn sample(database: &mut Database) {
        let mut root = database.root_mut();
        let mut mail = root.add_entry();
        mail.set_unprotected(fields::TITLE, "Mail");
        mail.set_unprotected(fields::USERNAME, "me@example.com");
        mail.set_protected(fields::PASSWORD, "synthetic-mail-pass");
        mail.set_unprotected(fields::URL, "https://mail.example.org/login");
        mail.set_unprotected(fields::NOTES, "Recovery codes are in the safe.");
        mail.set_protected("PIN", "4321");
        mail.set_protected("otp", "otpauth://totp/Example:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=30&digits=6&algorithm=SHA256");
        mail.tags.push("personal".to_owned());
        drop(mail);
        let mut work = root.add_group();
        work.name = "Work".to_owned();
        let mut vpn = work.add_entry();
        vpn.set_unprotected(fields::TITLE, "");
        vpn.set_unprotected(fields::URL, "https://vpn.example.com");
        vpn.set_protected(fields::PASSWORD, "synthetic-vpn-pass");
        vpn.set_protected("KPEX_PASSKEY_PRIVATE_KEY_PEM", "not imported");
        drop(vpn);
        let mut note = work.add_entry();
        note.set_unprotected(fields::TITLE, "Office Wi-Fi");
        note.set_unprotected(fields::NOTES, "Network: Example-Office");
        drop(note);
        let mut empty = work.add_entry();
        empty.set_unprotected(fields::TITLE, "Empty");
        drop(empty);
        drop(work);
        let mut bin = root.add_group();
        bin.name = "Recycle Bin".to_owned();
        let bin_id = bin.id().uuid();
        let mut deleted = bin.add_entry();
        deleted.set_unprotected(fields::TITLE, "Deleted");
        deleted.set_protected(fields::PASSWORD, "gone");
        drop(deleted);
        drop(bin);
        drop(root);
        database.meta.recyclebin_uuid = Some(bin_id);
        database.meta.recyclebin_enabled = Some(true);
    }

    #[test]
    fn a_kdbx4_file_maps_to_logins_codes_and_notes() {
        let plan = read(&kdbx("synthetic-keepass", sample), "synthetic-keepass", None).unwrap();
        let summary = plan.summary();
        assert_eq!((summary.logins, summary.codes, summary.notes), (2, 1, 1));
        assert_eq!((summary.in_recycle_bin, summary.without_content, summary.passkeys), (1, 1, 1));
        assert_eq!(summary.groups, ["Work"]);

        let mail = plan.logins.iter().find(|login| login.title == "Mail").unwrap();
        assert_eq!((mail.username.as_str(), mail.password.as_str(), mail.url.as_str()),
            ("me@example.com", "synthetic-mail-pass", "https://mail.example.org/login"));
        assert_eq!(mail.notes, "Recovery codes are in the safe.\n\nKeePass fields:\nPIN: 4321");
        assert_eq!(mail.tags, "personal");
        assert_eq!(mail.code, Some(Code { secret: "JBSWY3DPEHPK3PXP".to_owned(), algorithm: "SHA256", digits: 6, period: 30 }));

        // No title: the website's host names it. The group becomes a tag; passkey fields stay out.
        let vpn = plan.logins.iter().find(|login| login.password == "synthetic-vpn-pass").unwrap();
        assert_eq!((vpn.title.as_str(), vpn.tags.as_str()), ("vpn.example.com", "KeePass: Work"));
        assert!(!vpn.notes.contains("KPEX"));

        let note = plan.logins.iter().find(|login| login.title == "Office Wi-Fi").unwrap();
        assert!(!note.has_password());
        assert_eq!(note.note_body(), "Tags: KeePass: Work\n\nNetwork: Example-Office");
    }

    #[test]
    fn a_wrong_or_missing_key_and_other_files_are_refused() {
        let file = kdbx("synthetic-keepass", sample);
        assert!(matches!(read(&file, "wrong password", None), Err(KeepassError::WrongKey)));
        assert!(matches!(read(&file, "", None), Err(KeepassError::NoKey)));
        assert!(matches!(read(b"PK\x03\x04 not a keepass file", "synthetic-keepass", None), Err(KeepassError::Unreadable)));
        assert!(matches!(read(&vec![0; MAX_FILE_BYTES + 1], "x", None), Err(KeepassError::TooLarge)));
    }

    #[test]
    fn keepass_2_time_otp_fields_become_a_code() {
        let file = kdbx("synthetic-keepass", |database| {
            let mut root = database.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Bank");
            entry.set_protected(fields::PASSWORD, "synthetic-bank-pass");
            entry.set_protected("TimeOtp-Secret-Base32", "jbsw y3dp ehpk 3pxp");
            entry.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA-512");
            entry.set_unprotected("TimeOtp-Length", "8");
            entry.set_unprotected("TimeOtp-Period", "60");
        });
        let plan = read(&file, "synthetic-keepass", None).unwrap();
        assert_eq!(plan.logins[0].code, Some(Code { secret: "JBSWY3DPEHPK3PXP".to_owned(), algorithm: "SHA512", digits: 8, period: 60 }));
        assert!(plan.logins[0].notes.is_empty(), "TimeOtp fields are not copied into the notes");
    }

    /// Files that KeePassXC and KeePass wrote (keepass-rs `tests/resources`, password "demopass",
    /// or "test" for the TOTP sample).
    /// Run: `NUVORI_KDBX_FIXTURES=<folder> cargo test --lib keepass_import -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs downloaded KeePass test files"]
    fn files_from_keepass_apps_open() {
        let folder = std::path::PathBuf::from(std::env::var("NUVORI_KDBX_FIXTURES").expect("NUVORI_KDBX_FIXTURES"));
        let mut opened = 0;
        for entry in std::fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("kdbx") {
                continue;
            }
            let key_file = std::fs::read(path.with_extension("keyx")).ok();
            // The TOTP sample uses the password "test".
            let password = if path.to_string_lossy().contains("totp") { "test" } else { "demopass" };
            let plan = read(&std::fs::read(&path).unwrap(), password, key_file.as_deref())
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            println!("{}: {:?}", path.file_name().unwrap().to_string_lossy(), plan.summary());
            assert!(matches!(read(&std::fs::read(&path).unwrap(), "wrong", None), Err(KeepassError::WrongKey)), "{}", path.display());
            opened += 1;
        }
        assert!(opened > 0);
    }
}
