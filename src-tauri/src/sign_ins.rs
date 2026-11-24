//! Sign-in methods: which "Sign in with <provider>" button, and which account, the user used on a site.
//!
//! The browser extension notices a finished sign-in through a provider's OAuth or OpenID Connect
//! authorize endpoint (extension/signins.js), asks the user, and sends the site, the provider and
//! the account it could read (`record_sign_in`). On the next visit it asks for the site's methods
//! (`query_sign_ins`) and shows a small reminder. Nothing here is a secret: no password, token,
//! authorization code or URL is ever stored. The rows live in the encrypted vault database, one per
//! (site, provider, account), keyed by the registrable domain like website icons and related logins.
//!
//! The extension is not trusted. The app checks the setting, the site, the provider (a fixed list),
//! that the site is not the provider's own, and the account text before it stores anything.
//!
//! The rows sync with the group as entity `sign_in_method`, protocol `sign-in-methods-v1`
//! (`sign_in_sync.rs`); the shared vectors come from the Android repository's
//! `scripts/sync-vectors/sign_in_methods.py`.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::browser;

/// Most stored rows. The least recently used go first.
pub const MAX_ROWS: i64 = 5000;
/// Longest account (an email address or a user name), in characters.
pub const MAX_ACCOUNT_CHARS: usize = 256;
/// Most methods `query_sign_ins` returns for one site.
pub const MAX_PER_SITE: usize = 10;
const SETTINGS_FILE: &str = "sign-ins.json";
/// Tauri event after a change from the browser. The page reloads its list.
pub const EVENT: &str = "sign-ins-changed";

/// One sign-in provider. `own_domains` and `own_labels` name the provider's own sites: signing in to
/// them with the provider is not a "sign-in with a provider" on another site, so it is never stored.
/// `own_labels` matches the label before the public suffix (google.de, amazon.co.uk).
pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    own_domains: &'static [&'static str],
    own_labels: &'static [&'static str],
}

/// The fixed list. The extension (signins.js) and the Windows page (src/lib/signIns.ts) use the same ids.
pub const PROVIDERS: [Provider; 10] = [
    Provider { id: "google", name: "Google", own_domains: &["youtube.com", "gmail.com", "android.com", "withgoogle.com", "googleusercontent.com", "blogger.com"], own_labels: &["google"] },
    Provider { id: "apple", name: "Apple", own_domains: &["apple.com", "icloud.com", "apple.co"], own_labels: &[] },
    Provider { id: "microsoft", name: "Microsoft", own_domains: &["microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com", "bing.com", "xbox.com", "skype.com", "msn.com", "azure.com", "windows.com", "sharepoint.com", "onedrive.com", "microsoft365.com", "cloud.microsoft"], own_labels: &[] },
    Provider { id: "github", name: "GitHub", own_domains: &["github.com"], own_labels: &[] },
    Provider { id: "facebook", name: "Facebook", own_domains: &["facebook.com", "fb.com", "messenger.com", "instagram.com", "meta.com", "threads.net", "threads.com"], own_labels: &[] },
    Provider { id: "x", name: "X", own_domains: &["x.com", "twitter.com"], own_labels: &[] },
    Provider { id: "linkedin", name: "LinkedIn", own_domains: &["linkedin.com"], own_labels: &[] },
    Provider { id: "discord", name: "Discord", own_domains: &["discord.com", "discordapp.com", "discord.gg"], own_labels: &[] },
    Provider { id: "amazon", name: "Amazon", own_domains: &["amazon.com", "a2z.com"], own_labels: &["amazon"] },
    Provider { id: "slack", name: "Slack", own_domains: &["slack.com"], own_labels: &[] },
];

pub fn provider(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| provider.id == id)
}

impl Provider {
    /// True when `site` (a registrable domain) belongs to this provider.
    pub fn owns(&self, site: &str) -> bool {
        let label = site.split('.').next().unwrap_or_default();
        self.own_domains.contains(&site) || self.own_labels.contains(&label)
    }
}

pub fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS local_sign_ins (
            id TEXT NOT NULL PRIMARY KEY,
            site TEXT NOT NULL,
            provider TEXT NOT NULL,
            account TEXT NOT NULL,
            account_key TEXT NOT NULL,
            first_used_at INTEGER NOT NULL,
            last_used_at INTEGER NOT NULL,
            use_count INTEGER NOT NULL,
            UNIQUE (site, provider, account_key)
        );
        CREATE INDEX IF NOT EXISTS local_sign_ins_site ON local_sign_ins (site);",
    )
}

/// Why `record` or `set_account` refused. The browser only sees one generic status.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The "Remember sign-in methods" setting is off.
    Off,
    /// HTTP, an IP address or a public suffix: no registrable domain.
    NoSite,
    UnknownProvider,
    /// The provider's own site, such as Google on youtube.com.
    OwnSite,
    /// Too long, or control or invisible format characters.
    BadAccount,
    Missing,
    Storage,
}

/// One remembered method, as camelCase JSON for the page and the extension.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignIn {
    pub id: String,
    pub site: String,
    pub provider: String,
    /// "" when the account is not known.
    pub account: String,
    pub first_used_at: i64,
    pub last_used_at: i64,
    pub use_count: i64,
}

/// The registrable domain of a page origin, or `None` for HTTP, an IP address or a public suffix.
pub fn site_of_origin(origin: &str) -> Option<String> {
    browser::registrable_site(&browser::canonical_https_origin(origin)?)
}

/// The registrable domain of a login's saved website, as the Windows list shows it: a bare host
/// ("seedr.cc") or an http address counts as that host's HTTPS site. Same rule as website icons
/// (`site_icons::site_of_login_url`).
pub fn site_of_login_url(url: &str) -> Option<String> {
    let url = url.trim();
    let https = match url.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => format!("https://{rest}"),
        Some(_) => url.to_owned(),
        None => format!("https://{url}"),
    };
    browser::registrable_site(&browser::stored_login_origin(&https)?)
}

/// The account as stored: trimmed, at most [MAX_ACCOUNT_CHARS] characters, without control or
/// format characters. `Ok(None)` when empty. The key ignores case, because providers do.
pub fn clean_account(account: Option<&str>) -> Result<Option<(String, String)>, Refused> {
    let Some(text) = account.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    if text.chars().count() > MAX_ACCOUNT_CHARS || text.chars().any(|c| c.is_control() || browser::is_format_char(c)) {
        return Err(Refused::BadAccount);
    }
    Ok(Some((text.to_owned(), text.to_lowercase())))
}

fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SignIn> {
    Ok(SignIn {
        id: row.get(0)?,
        site: row.get(1)?,
        provider: row.get(2)?,
        account: row.get(3)?,
        first_used_at: row.get(4)?,
        last_used_at: row.get(5)?,
        use_count: row.get(6)?,
    })
}

const COLUMNS: &str = "id, site, provider, account, first_used_at, last_used_at, use_count";

fn by_key(connection: &Connection, site: &str, provider: &str, key: &str) -> rusqlite::Result<Option<SignIn>> {
    connection
        .query_row(
            &format!("SELECT {COLUMNS} FROM local_sign_ins WHERE site = ?1 AND provider = ?2 AND account_key = ?3"),
            params![site, provider, key],
            row,
        )
        .optional()
}

fn by_id(connection: &Connection, id: &str) -> rusqlite::Result<Option<SignIn>> {
    connection.query_row(&format!("SELECT {COLUMNS} FROM local_sign_ins WHERE id = ?1"), [id], row).optional()
}

/// Notes one sign-in on `origin` with `provider` and the account the extension read, if any.
///
/// - A known account adds to its row, or makes one. A row without an account for the same site and
///   provider joins it: it was this account before the extension could read it.
/// - No account adds to the only row for that site and provider; otherwise to the row without one.
pub fn record(
    connection: &mut Connection,
    origin: &str,
    provider_id: &str,
    account: Option<&str>,
    enabled: bool,
    now: i64,
) -> Result<SignIn, Refused> {
    if !enabled {
        return Err(Refused::Off);
    }
    let site = site_of_origin(origin).ok_or(Refused::NoSite)?;
    let provider = provider(provider_id).ok_or(Refused::UnknownProvider)?;
    if provider.owns(&site) {
        return Err(Refused::OwnSite);
    }
    let account = clean_account(account)?;
    let storage = |_| Refused::Storage;
    let transaction = connection.transaction().map_err(storage)?;
    let target = match &account {
        Some((_, key)) => by_key(&transaction, &site, provider.id, key).map_err(storage)?,
        None => {
            let rows = for_site(&transaction, &site).map_err(storage)?;
            let same: Vec<&SignIn> = rows.iter().filter(|row| row.provider == provider.id).collect();
            match same.as_slice() {
                [only] => Some((*only).clone()),
                _ => same.iter().find(|row| row.account.is_empty()).map(|row| (*row).clone()),
            }
        }
    };
    let id = match target {
        Some(existing) => {
            transaction
                .execute(
                    "UPDATE local_sign_ins SET last_used_at = MAX(last_used_at, ?2), use_count = use_count + 1 WHERE id = ?1",
                    params![existing.id, now],
                )
                .map_err(storage)?;
            existing.id
        }
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            let (text, key) = account.clone().unwrap_or_default();
            transaction
                .execute(
                    "INSERT INTO local_sign_ins (id, site, provider, account, account_key, first_used_at, last_used_at, use_count)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)",
                    params![id, site, provider.id, text, key, now],
                )
                .map_err(storage)?;
            id
        }
    };
    if account.is_some()
        && let Some(unknown) = by_key(&transaction, &site, provider.id, "").map_err(storage)?
    {
        fold(&transaction, &unknown, &id).map_err(storage)?;
        // The group's row without an account goes too (sign_in_sync.rs).
        crate::sign_in_sync::note_local_delete(&transaction, &site, provider.id, "").map_err(storage)?;
    }
    // Eviction is housekeeping on this PC: it writes no delete.
    trim(&transaction).map_err(storage)?;
    let stored = by_id(&transaction, &id).map_err(storage)?.ok_or(Refused::Storage)?;
    transaction.commit().map_err(storage)?;
    Ok(stored)
}

/// Adds `from`'s history to the row `into`, then deletes `from`.
fn fold(connection: &Connection, from: &SignIn, into: &str) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE local_sign_ins SET first_used_at = MIN(first_used_at, ?2), last_used_at = MAX(last_used_at, ?3),
             use_count = use_count + ?4 WHERE id = ?1",
        params![into, from.first_used_at, from.last_used_at, from.use_count],
    )?;
    connection.execute("DELETE FROM local_sign_ins WHERE id = ?1", [&from.id])?;
    Ok(())
}

/// Keeps the [MAX_ROWS] most recently used rows.
fn trim(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute(
        "DELETE FROM local_sign_ins WHERE id NOT IN
            (SELECT id FROM local_sign_ins ORDER BY last_used_at DESC, rowid DESC LIMIT ?1)",
        [MAX_ROWS],
    )?;
    Ok(())
}

fn for_site(connection: &Connection, site: &str) -> rusqlite::Result<Vec<SignIn>> {
    connection
        .prepare(&format!("SELECT {COLUMNS} FROM local_sign_ins WHERE site = ?1 ORDER BY last_used_at DESC, account_key"))?
        .query_map([site], row)?
        .collect()
}

/// The site of `origin` and its methods, most recently used first; `None` when the origin has no site.
pub fn for_origin(connection: &Connection, origin: &str) -> rusqlite::Result<Option<(String, Vec<SignIn>)>> {
    let Some(site) = site_of_origin(origin) else {
        return Ok(None);
    };
    let mut rows = for_site(connection, &site)?;
    rows.truncate(MAX_PER_SITE);
    Ok(Some((site, rows)))
}

/// Every row, by site, then most recently used first.
pub fn list(connection: &Connection) -> rusqlite::Result<Vec<SignIn>> {
    connection
        .prepare(&format!("SELECT {COLUMNS} FROM local_sign_ins ORDER BY site, last_used_at DESC, account_key"))?
        .query_map([], row)?
        .collect()
}

/// Deletes one row. False when it was already gone. The sync group gets a delete (sign_in_sync.rs).
pub fn delete(connection: &Connection, id: &str) -> rusqlite::Result<bool> {
    let Some(row) = by_id(connection, id)? else {
        return Ok(false);
    };
    crate::sign_in_sync::note_local_delete(connection, &row.site, &row.provider, &row.account.trim().to_lowercase())?;
    Ok(connection.execute("DELETE FROM local_sign_ins WHERE id = ?1", [id])? == 1)
}

/// Sets or clears the account of one row. When another row of the same site and provider already
/// has that account, the two become one.
pub fn set_account(connection: &mut Connection, id: &str, account: Option<&str>) -> Result<SignIn, Refused> {
    let storage = |_| Refused::Storage;
    let (text, key) = clean_account(account)?.unwrap_or_default();
    let transaction = connection.transaction().map_err(storage)?;
    let current = by_id(&transaction, id).map_err(storage)?.ok_or(Refused::Missing)?;
    // Another account key is another sync entity: the old one is deleted in the group (sign_in_sync.rs).
    let current_key = current.account.trim().to_lowercase();
    if current_key != key {
        crate::sign_in_sync::note_local_delete(&transaction, &current.site, &current.provider, &current_key).map_err(storage)?;
    }
    let kept = match by_key(&transaction, &current.site, &current.provider, &key).map_err(storage)? {
        Some(other) if other.id != current.id => {
            fold(&transaction, &current, &other.id).map_err(storage)?;
            other.id
        }
        _ => {
            transaction
                .execute("UPDATE local_sign_ins SET account = ?2, account_key = ?3 WHERE id = ?1", params![id, text, key])
                .map_err(storage)?;
            current.id
        }
    };
    let stored = by_id(&transaction, &kept).map_err(storage)?.ok_or(Refused::Storage)?;
    transaction.commit().map_err(storage)?;
    Ok(stored)
}

/// For each site with a method, the ids of the logins saved for it (same registrable domain), so the
/// page can link the two. Logins without a usable website are left out.
pub fn logins_by_site(connection: &Connection) -> rusqlite::Result<BTreeMap<String, Vec<String>>> {
    let sites: std::collections::HashSet<String> = connection
        .prepare("SELECT DISTINCT site FROM local_sign_ins")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if sites.is_empty() {
        return Ok(found);
    }
    let mut logins = connection.prepare("SELECT id, data_json FROM local_entries WHERE type = 'PASSWORD' ORDER BY id")?;
    for item in logins.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))? {
        let (id, json) = item?;
        let url = serde_json::from_str::<serde_json::Value>(&json)
            .ok()
            .and_then(|entry| entry["tertiaryValue"].as_str().map(str::to_owned));
        if let Some(site) = url.as_deref().and_then(site_of_login_url).filter(|site| sites.contains(site)) {
            found.entry(site).or_default().push(id);
        }
    }
    Ok(found)
}

/// What the commands return: `{ "enabled": true, "items": [...], "logins": { "example.com": ["id"] } }`.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub enabled: bool,
    pub items: Vec<SignIn>,
    pub logins: BTreeMap<String, Vec<String>>,
}

pub fn view(connection: &Connection, enabled: bool) -> rusqlite::Result<View> {
    Ok(View { enabled, items: list(connection)?, logins: logins_by_site(connection)? })
}

// The setting lives in `sign-ins.json` next to the vault, like `site-icons.json`, because the browser
// handler reads it on pipe threads that have no window or vault handle. Default on.

struct Preference {
    file: PathBuf,
    enabled: Mutex<bool>,
}

static PREFERENCE: OnceLock<Preference> = OnceLock::new();
static NOTIFY: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Reads the setting (default on) and registers what runs after a change from the browser.
pub fn install(directory: &std::path::Path, notify: impl Fn() + Send + Sync + 'static) {
    let file = directory.join(SETTINGS_FILE);
    let enabled = std::fs::read_to_string(&file).map(|text| parse_enabled(&text)).unwrap_or(true);
    let _ = PREFERENCE.set(Preference { file, enabled: Mutex::new(enabled) });
    let _ = NOTIFY.set(Box::new(notify));
    crate::browser_ipc::set_sign_in_methods(enabled);
}

fn parse_enabled(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| value["enabled"].as_bool())
        .unwrap_or(true)
}

pub fn enabled() -> bool {
    PREFERENCE.get().is_none_or(|preference| preference.enabled.lock().map(|on| *on).unwrap_or(true))
}

/// Turning it off stops new records and the reminders. The rows stay until the user deletes them:
/// each one was confirmed by the user, unlike a website icon that the extension can fetch again.
pub fn set_enabled(enabled: bool) -> std::io::Result<()> {
    let Some(preference) = PREFERENCE.get() else {
        return Err(std::io::Error::other("Sign-in methods are not ready."));
    };
    let mut current = preference.enabled.lock().map_err(|_| std::io::Error::other("Sign-in methods are busy."))?;
    std::fs::write(&preference.file, serde_json::json!({ "enabled": enabled }).to_string())?;
    *current = enabled;
    crate::browser_ipc::set_sign_in_methods(enabled);
    Ok(())
}

/// Tells the open window that the list changed.
pub fn notify_changed() {
    if let Some(notify) = NOTIFY.get() {
        notify();
    }
}

/// Sync (`sign-in-methods-v1`, `sign_in_sync.rs`): the entity id of one row. The first 32 hex
/// characters of HMAC-SHA256(content key, prefix + site + "\n" + provider + "\n" + account key), so the
/// plain-text id shows neither the site, the provider nor the account.
/// Shared vectors: `fixtures/sign-in-methods-v1.json` (Android `scripts/sync-vectors/sign_in_methods.py`).
pub const SYNC_ID_PREFIX: &str = "nuvori-sync-sign-in-method-id-v1:";

pub fn sync_entity_id(content_key: &[u8], site: &str, provider: &str, account: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(content_key).expect("any HMAC key length");
    mac.update(SYNC_ID_PREFIX.as_bytes());
    mac.update(format!("{site}\n{provider}\n{}", account.trim().to_lowercase()).as_bytes());
    hex::encode(mac.finalize().into_bytes())[..32].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_rules_match_the_shared_sync_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!("../fixtures/sign-in-methods-v1.json")).unwrap();
        assert_eq!(vectors["idPrefix"], SYNC_ID_PREFIX);
        assert_eq!(vectors["maxAccountChars"], MAX_ACCOUNT_CHARS as u64);
        let providers: Vec<&str> = vectors["providers"].as_array().unwrap().iter().map(|id| id.as_str().unwrap()).collect();
        assert_eq!(providers, PROVIDERS.iter().map(|provider| provider.id).collect::<Vec<_>>());
        let key = hex::decode(vectors["contentKeyHex"].as_str().unwrap()).unwrap();
        for case in vectors["entityIds"].as_array().unwrap() {
            let (site, provider, account) = (case["site"].as_str().unwrap(), case["provider"].as_str().unwrap(), case["account"].as_str().unwrap());
            assert_eq!(sync_entity_id(&key, site, provider, account), case["entityId"].as_str().unwrap(), "{account}");
            // The local row key is the same account key.
            let local = clean_account(Some(account)).unwrap().map(|(_, key)| key).unwrap_or_default();
            assert_eq!(local, case["accountKey"].as_str().unwrap(), "{account}");
        }
        for account in vectors["accounts"]["valid"].as_array().unwrap() {
            assert!(clean_account(Some(account.as_str().unwrap())).is_ok(), "{account}");
        }
        for account in vectors["accounts"]["invalid"].as_array().unwrap() {
            assert_eq!(clean_account(Some(account.as_str().unwrap())), Err(Refused::BadAccount), "{account}");
        }
    }
    use crate::vault::VaultStore;

    fn database() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        initialize(&connection).unwrap();
        connection
    }

    fn rows(connection: &Connection) -> Vec<(String, String, String, i64)> {
        list(connection).unwrap().into_iter().map(|row| (row.site, row.provider, row.account, row.use_count)).collect()
    }

    #[test]
    fn records_by_registrable_domain_and_counts_uses() {
        let mut db = database();
        let first = record(&mut db, "https://app.example.co.uk", "github", Some(" octocat "), true, 100).unwrap();
        assert_eq!((first.site.as_str(), first.provider.as_str(), first.account.as_str()), ("example.co.uk", "github", "octocat"));
        assert_eq!((first.first_used_at, first.last_used_at, first.use_count), (100, 100, 1));
        // Another page of the same site, the same account in other case: the same row.
        let again = record(&mut db, "https://www.example.co.uk", "github", Some("OctoCat"), true, 200).unwrap();
        assert_eq!(again.id, first.id);
        assert_eq!((again.account.as_str(), again.first_used_at, again.last_used_at, again.use_count), ("octocat", 100, 200, 2));
        // An older time never moves "last used" back.
        let late = record(&mut db, "https://example.co.uk", "github", Some("octocat"), true, 150).unwrap();
        assert_eq!((late.last_used_at, late.use_count), (200, 3));
        // Another account and another provider are rows of their own.
        record(&mut db, "https://example.co.uk", "github", Some("hubot"), true, 300).unwrap();
        record(&mut db, "https://example.co.uk", "google", Some("me@example.com"), true, 400).unwrap();
        let (site, methods) = for_origin(&db, "https://login.example.co.uk").unwrap().unwrap();
        assert_eq!(site, "example.co.uk");
        assert_eq!(methods.iter().map(|row| row.account.as_str()).collect::<Vec<_>>(), ["me@example.com", "hubot", "octocat"]);
        assert!(for_origin(&db, "https://other.example").unwrap().unwrap().1.is_empty());
        assert!(for_origin(&db, "http://example.co.uk").unwrap().is_none());
    }

    #[test]
    fn refuses_what_the_extension_must_not_store() {
        let mut db = database();
        let origin = "https://example.com";
        assert_eq!(record(&mut db, origin, "github", None, false, 1), Err(Refused::Off));
        for bad in ["http://example.com", "https://192.168.1.10", "https://[::1]", "https://github.io", "https://example.com/", "example.com", ""] {
            assert_eq!(record(&mut db, bad, "github", None, true, 1), Err(Refused::NoSite), "{bad}");
        }
        for bad in ["", "GitHub", "gitlab", "github ", "okta"] {
            assert_eq!(record(&mut db, origin, bad, None, true, 1), Err(Refused::UnknownProvider), "{bad}");
        }
        // The provider's own sites, including country domains.
        for (own, provider) in [("https://mail.google.com", "google"), ("https://www.google.co.uk", "google"), ("https://www.youtube.com", "google"),
            ("https://github.com", "github"), ("https://portal.azure.com", "microsoft"), ("https://outlook.live.com", "microsoft"),
            ("https://www.amazon.de", "amazon"), ("https://twitter.com", "x"), ("https://acme.slack.com", "slack"), ("https://www.icloud.com", "apple")] {
            assert_eq!(record(&mut db, own, provider, None, true, 1), Err(Refused::OwnSite), "{own}");
        }
        // Another provider on those sites is a real sign-in method.
        assert!(record(&mut db, "https://acme.slack.com", "google", None, true, 1).is_ok());
        // A user's own site under a public suffix is not the platform's site.
        assert_eq!(record(&mut db, "https://alice.github.io", "github", None, true, 1).unwrap().site, "alice.github.io");
        let long = "a".repeat(MAX_ACCOUNT_CHARS + 1);
        for bad in [long.as_str(), "me\u{0}@example.com", "line\nbreak", "evil\u{202E}moc.elpmaxe@me", "zero\u{200B}width"] {
            assert_eq!(record(&mut db, origin, "github", Some(bad), true, 1), Err(Refused::BadAccount), "{bad:?}");
        }
        let exact = "a".repeat(MAX_ACCOUNT_CHARS);
        assert_eq!(record(&mut db, origin, "github", Some(&exact), true, 1).unwrap().account, exact);
        assert_eq!(rows(&db).len(), 3);
    }

    #[test]
    fn an_unknown_account_joins_the_only_row_or_waits_for_one() {
        let mut db = database();
        let origin = "https://example.com";
        // No row yet: a row without an account.
        let unknown = record(&mut db, origin, "github", None, true, 10).unwrap();
        assert_eq!(unknown.account, "");
        // The account becomes known: the earlier row joins it.
        let known = record(&mut db, origin, "github", Some("octocat"), true, 20).unwrap();
        assert_eq!((known.first_used_at, known.last_used_at, known.use_count), (10, 20, 2));
        assert_eq!(rows(&db), [("example.com".into(), "github".into(), "octocat".into(), 2)]);
        // Unknown again with one row for the provider: that row.
        assert_eq!(record(&mut db, origin, "github", None, true, 30).unwrap().id, known.id);
        // Two accounts: an unknown one cannot pick, so it gets its own row and keeps adding to it.
        record(&mut db, origin, "github", Some("hubot"), true, 40).unwrap();
        let open = record(&mut db, origin, "github", None, true, 50).unwrap();
        assert_eq!(open.account, "");
        assert_eq!(record(&mut db, origin, "github", Some("   "), true, 60).unwrap().id, open.id);
        // Another provider's rows never count.
        record(&mut db, origin, "google", Some("me@example.com"), true, 70).unwrap();
        assert_eq!(rows(&db).len(), 4);
    }

    #[test]
    fn editing_an_account_merges_with_an_existing_row() {
        let mut db = database();
        let origin = "https://example.com";
        let octo = record(&mut db, origin, "github", Some("octocat"), true, 10).unwrap();
        record(&mut db, origin, "google", None, true, 15).unwrap();
        let hubot = record(&mut db, origin, "github", Some("hubot"), true, 20).unwrap();
        // Rename to a free name: same row.
        let renamed = set_account(&mut db, &hubot.id, Some("Hubot-2")).unwrap();
        assert_eq!((renamed.id.as_str(), renamed.account.as_str()), (hubot.id.as_str(), "Hubot-2"));
        // Rename onto an existing account: one row with both histories.
        let merged = set_account(&mut db, &renamed.id, Some("OCTOCAT")).unwrap();
        assert_eq!((merged.id.as_str(), merged.account.as_str(), merged.use_count, merged.first_used_at, merged.last_used_at),
            (octo.id.as_str(), "octocat", 2, 10, 20));
        // Clearing the account is allowed; bad text and missing rows are refused.
        assert_eq!(set_account(&mut db, &merged.id, None).unwrap().account, "");
        assert_eq!(set_account(&mut db, &merged.id, Some("a\tb")), Err(Refused::BadAccount));
        assert_eq!(set_account(&mut db, "missing", Some("x")), Err(Refused::Missing));
        assert!(delete(&db, &merged.id).unwrap());
        assert!(!delete(&db, &merged.id).unwrap());
        assert_eq!(rows(&db), [("example.com".into(), "google".into(), String::new(), 1)]);
    }

    #[test]
    fn keeps_at_most_max_rows_and_drops_the_least_recently_used() {
        let mut db = database();
        let transaction = db.transaction().unwrap();
        for index in 0..MAX_ROWS {
            transaction
                .execute(
                    "INSERT INTO local_sign_ins (id, site, provider, account, account_key, first_used_at, last_used_at, use_count)
                     VALUES (?1, ?2, 'github', '', '', ?3, ?3, 1)",
                    params![format!("row{index}"), format!("filler{index}.example"), 100 + index],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        record(&mut db, "https://new.example", "google", None, true, 1_000_000).unwrap();
        let all = list(&db).unwrap();
        assert_eq!(all.len() as i64, MAX_ROWS);
        assert!(all.iter().any(|row| row.site == "new.example"));
        assert!(!all.iter().any(|row| row.site == "filler0.example"), "the oldest row was dropped");
    }

    #[test]
    fn views_link_logins_of_the_same_site_and_are_camel_case() {
        let directory = std::env::temp_dir().join(format!("nuvori-sign-ins-{}", uuid::Uuid::new_v4()));
        let mut vault = VaultStore::new(&directory).create("synthetic-test-password").unwrap();
        for (title, url) in [("GitHub", "https://github.com/login"), ("Example", "www.example.com/login"), ("App", "http://app.example.com"), ("Other", "https://other.example")] {
            vault
                .save_entry(serde_json::json!({"type": "PASSWORD", "title": title, "primaryValue": "me",
                    "secondaryValue": "pw", "tertiaryValue": url}))
                .unwrap();
        }
        let connection = vault.connection();
        record(connection, "https://login.example.com", "google", Some("me@example.com"), true, 5).unwrap();
        let view = view(connection, true).unwrap();
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["items"][0]["site"], "example.com");
        assert_eq!(json["items"][0]["lastUsedAt"], 5);
        assert_eq!(json["items"][0]["useCount"], 1);
        let linked = view.logins.get("example.com").cloned().unwrap_or_default();
        assert_eq!(linked.len(), 2, "the bare host and the http address both count");
        assert!(!view.logins.contains_key("github.com"), "only sites that have a method");
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_setting_defaults_on_and_survives_bad_files() {
        assert!(parse_enabled("not json"));
        assert!(parse_enabled("{}"));
        assert!(!parse_enabled(r#"{"enabled":false}"#));
    }

    #[test]
    fn provider_ids_match_the_extension_and_page() {
        let ids: Vec<&str> = PROVIDERS.iter().map(|provider| provider.id).collect();
        assert_eq!(ids, ["google", "apple", "microsoft", "github", "facebook", "x", "linkedin", "discord", "amazon", "slack"]);
        let script = include_str!("../../extension/signins.js");
        let page = include_str!("../../src/lib/signIns.ts");
        for id in ids {
            assert!(script.contains(&format!("id: \"{id}\"")), "signins.js lacks {id}");
            assert!(page.contains(&format!("\"{id}\"")), "signIns.ts lacks {id}");
        }
    }
}
