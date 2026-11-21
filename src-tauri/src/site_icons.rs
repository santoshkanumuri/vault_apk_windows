//! Website icons the browser extension captured, kept only on this PC.
//!
//! When the user visits a site that already has a login or passkey in the vault, the extension
//! re-encodes the page's favicon to a small PNG and sends it here (`save_site_icon`). The icon
//! goes into the encrypted vault database next to the items, keyed by registrable domain. It is
//! never synced, never part of a backup's item list, and never fetched by the app: no network
//! code lives here. The Android app does not capture icons; both apps ship a built-in icon set.
//!
//! The extension is not trusted. The app checks the user's setting, the site, the size and the
//! PNG itself before it stores anything. The app stores the original validated bytes.

use std::{
    collections::{BTreeMap, HashSet},
    io::Cursor,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::browser;

/// Most stored icons. The oldest `updated_at` goes first.
pub const MAX_ICONS: i64 = 2000;
/// Largest PNG the app accepts, after base64 decoding.
pub const MAX_PNG_BYTES: usize = 32 * 1024;
/// A stored icon is asked for again after this long, so a site's new logo shows up.
const REFRESH_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;
const MIN_SIDE: u32 = 16;
const MAX_SIDE: u32 = 64;
const SETTINGS_FILE: &str = "site-icons.json";
/// Tauri event after a successful save. The page reloads its icon list.
pub const EVENT: &str = "site-icons-changed";

pub fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS local_site_icons (
            site TEXT NOT NULL PRIMARY KEY,
            png BLOB NOT NULL,
            updated_at INTEGER NOT NULL
        );",
    )
}

/// Why `save` refused an icon. The browser only sees one generic status.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The "Website icons" setting is off.
    Off,
    /// The origin has no registrable domain, or no login or passkey uses it.
    NoMatch,
    /// Not a PNG, wrong size, or too many bytes.
    BadImage,
    Storage,
}

/// The registrable domain of a page origin, or `None` for HTTP, an IP address or a public suffix.
pub fn site_of_origin(origin: &str) -> Option<String> {
    browser::registrable_site(&browser::canonical_https_origin(origin)?)
}

/// The registrable domain of a login's saved website. Logins typed on a phone are often a bare host
/// ("seedr.cc") or an http address; an icon only decorates the row, so both count as that host's
/// HTTPS site. Filling keeps its own stricter rules (`login_url_matches_origin`).
fn site_of_login_url(url: &str) -> Option<String> {
    let url = url.trim();
    let https = match url.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => format!("https://{rest}"),
        Some(_) => url.to_owned(),
        None => format!("https://{url}"),
    };
    browser::registrable_site(&browser::stored_login_origin(&https)?)
}

/// A passkey's rpId is a bare host: it is the same as an HTTPS address for that host.
fn site_of_rp_id(rp_id: &str) -> Option<String> {
    site_of_login_url(&format!("https://{rp_id}"))
}

/// Registrable domains of every login and passkey in the vault.
pub fn known_sites(connection: &Connection) -> rusqlite::Result<HashSet<String>> {
    let mut sites = HashSet::new();
    let mut logins = connection.prepare("SELECT data_json FROM local_entries WHERE type = 'PASSWORD'")?;
    for json in logins.query_map([], |row| row.get::<_, String>(0))? {
        let url = serde_json::from_str::<serde_json::Value>(&json?)
            .ok()
            .and_then(|entry| entry["tertiaryValue"].as_str().map(str::to_owned));
        sites.extend(url.as_deref().and_then(site_of_login_url));
    }
    let mut passkeys = connection.prepare("SELECT rp_id FROM local_passkeys")?;
    for rp_id in passkeys.query_map([], |row| row.get::<_, String>(0))? {
        sites.extend(site_of_rp_id(&rp_id?));
    }
    Ok(sites)
}

/// True when the extension should send an icon for this origin: the setting is on, a login or
/// passkey uses the site, and the stored icon is missing or at least 30 days old.
pub fn wanted(connection: &Connection, origin: &str, enabled: bool, now: i64) -> rusqlite::Result<bool> {
    let Some(site) = site_of_origin(origin).filter(|_| enabled) else {
        return Ok(false);
    };
    if !known_sites(connection)?.contains(&site) {
        return Ok(false);
    }
    let stored: Option<i64> = connection
        .query_row("SELECT updated_at FROM local_site_icons WHERE site = ?1", [&site], |row| row.get(0))
        .optional()?;
    Ok(stored.is_none_or(|updated| now.saturating_sub(updated) >= REFRESH_MILLIS))
}

/// True when `bytes` is a complete PNG of 16 to 64 pixels on each side. The decoder reads every
/// pixel, so a truncated or corrupt file fails here. Sizes are read before any pixel buffer
/// exists, so a hostile header cannot make the app allocate much.
pub fn valid_png(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_PNG_BYTES || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return false;
    }
    let Ok(mut reader) = png::Decoder::new(Cursor::new(bytes)).read_info() else {
        return false;
    };
    let info = reader.info();
    if !(MIN_SIDE..=MAX_SIDE).contains(&info.width) || !(MIN_SIDE..=MAX_SIDE).contains(&info.height) {
        return false;
    }
    let mut frame = vec![0; reader.output_buffer_size()];
    reader.next_frame(&mut frame).is_ok() && reader.finish().is_ok()
}

/// Stores an icon the extension sent for `origin`.
pub fn save(connection: &Connection, origin: &str, png: &[u8], enabled: bool, now: i64) -> Result<(), Refused> {
    if !enabled {
        return Err(Refused::Off);
    }
    let site = site_of_origin(origin).ok_or(Refused::NoMatch)?;
    if !known_sites(connection).map_err(|_| Refused::Storage)?.contains(&site) {
        return Err(Refused::NoMatch);
    }
    if !valid_png(png) {
        return Err(Refused::BadImage);
    }
    connection
        .execute(
            "INSERT OR REPLACE INTO local_site_icons (site, png, updated_at) VALUES (?1, ?2, ?3)",
            params![site, png, now],
        )
        .map_err(|_| Refused::Storage)?;
    // Keep the newest MAX_ICONS rows.
    connection
        .execute(
            "DELETE FROM local_site_icons WHERE site NOT IN
                (SELECT site FROM local_site_icons ORDER BY updated_at DESC, rowid DESC LIMIT ?1)",
            [MAX_ICONS],
        )
        .map_err(|_| Refused::Storage)?;
    Ok(())
}

/// On vault open: drops icons for sites that no longer have a login or passkey, and every icon
/// when the setting is off.
pub fn purge(connection: &Connection, enabled: bool) -> rusqlite::Result<()> {
    if !enabled {
        return clear(connection);
    }
    let known = known_sites(connection)?;
    let stored: Vec<String> = connection
        .prepare("SELECT site FROM local_site_icons")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for site in stored.iter().filter(|site| !known.contains(*site)) {
        connection.execute("DELETE FROM local_site_icons WHERE site = ?1", [site])?;
    }
    Ok(())
}

pub fn clear(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute("DELETE FROM local_site_icons", [])?;
    Ok(())
}

/// Every stored icon as a `data:image/png;base64,...` URL, keyed by registrable domain.
pub fn data_urls(connection: &Connection) -> rusqlite::Result<BTreeMap<String, String>> {
    connection
        .prepare("SELECT site, png FROM local_site_icons")?
        .query_map([], |row| {
            let png: Vec<u8> = row.get(1)?;
            Ok((row.get::<_, String>(0)?, format!("data:image/png;base64,{}", STANDARD.encode(png))))
        })?
        .collect()
}

/// What the commands return, as camelCase JSON: `{ "enabled": true, "icons": { "github.com": "data:..." } }`.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub enabled: bool,
    pub icons: BTreeMap<String, String>,
}

// The setting lives in `site-icons.json` next to the vault, like `auto-type.json`, because the
// browser handler needs it from threads that have no window or vault handle.

struct Preference {
    file: PathBuf,
    enabled: Mutex<bool>,
}

static PREFERENCE: OnceLock<Preference> = OnceLock::new();
static NOTIFY: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Reads the setting (default on) and registers what runs after a saved icon.
pub fn install(directory: &std::path::Path, notify: impl Fn() + Send + Sync + 'static) {
    let file = directory.join(SETTINGS_FILE);
    let enabled = std::fs::read_to_string(&file).map(|text| parse_enabled(&text)).unwrap_or(true);
    let _ = PREFERENCE.set(Preference { file, enabled: Mutex::new(enabled) });
    let _ = NOTIFY.set(Box::new(notify));
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

pub fn set_enabled(enabled: bool) -> std::io::Result<()> {
    let Some(preference) = PREFERENCE.get() else {
        return Err(std::io::Error::other("Website icons are not ready."));
    };
    let mut current = preference.enabled.lock().map_err(|_| std::io::Error::other("Website icons are busy."))?;
    std::fs::write(&preference.file, serde_json::json!({ "enabled": enabled }).to_string())?;
    *current = enabled;
    Ok(())
}

/// Tells the open window that an icon changed.
pub fn notify_saved() {
    if let Some(notify) = NOTIFY.get() {
        notify();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultStore;

    const DAY: i64 = 24 * 60 * 60 * 1000;

    fn png_of(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().unwrap();
        writer.write_image_data(&vec![200; (width * height * 4) as usize]).unwrap();
        writer.finish().unwrap();
        bytes
    }

    fn temp_directory() -> PathBuf {
        std::env::temp_dir().join(format!("nuvori-site-icons-{}", uuid::Uuid::new_v4()))
    }

    /// A vault with logins for accounts.google.com and alice.github.io, and a passkey for example.org.
    fn vault_with_sites() -> (crate::vault::UnlockedVault, PathBuf) {
        let directory = temp_directory();
        let mut vault = VaultStore::new(&directory).create("synthetic-test-password").unwrap();
        for (title, url) in [("Google", "https://accounts.google.com/signin"), ("Pages", "https://alice.github.io")] {
            vault
                .save_entry(serde_json::json!({"type": "PASSWORD", "title": title, "primaryValue": "me",
                    "secondaryValue": "pw", "tertiaryValue": url}))
                .unwrap();
        }
        vault
            .connection()
            .execute("INSERT INTO local_passkeys (id, rp_id, data_json) VALUES ('p1', 'example.org', '{}')", [])
            .unwrap();
        (vault, directory)
    }

    #[test]
    fn sites_match_by_registrable_domain() {
        let (mut vault, directory) = vault_with_sites();
        let connection = vault.connection();
        let now = 1_000 * DAY;
        // A login for accounts.google.com wants an icon for the www host and the apex.
        assert!(wanted(connection, "https://www.google.com", true, now).unwrap());
        assert!(wanted(connection, "https://google.com", true, now).unwrap());
        // A passkey rpId counts, with a subdomain origin.
        assert!(wanted(connection, "https://login.example.org", true, now).unwrap());
        // Another site, plain HTTP, and an IP address never want one.
        assert!(!wanted(connection, "https://other.example", true, now).unwrap());
        assert!(!wanted(connection, "http://www.google.com", true, now).unwrap());
        assert!(!wanted(connection, "https://192.168.1.10", true, now).unwrap());
        assert!(!wanted(connection, "https://[::1]", true, now).unwrap());
        // github.io is a public suffix: alice.github.io is its own site, and github.io itself has none.
        assert!(wanted(connection, "https://alice.github.io", true, now).unwrap());
        assert!(!wanted(connection, "https://bob.github.io", true, now).unwrap());
        assert!(!wanted(connection, "https://github.io", true, now).unwrap());
        // The setting off wins.
        assert!(!wanted(connection, "https://www.google.com", false, now).unwrap());
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn bare_host_and_http_logins_count_as_their_site() {
        assert_eq!(site_of_login_url("seedr.cc").as_deref(), Some("seedr.cc"));
        assert_eq!(site_of_login_url(" www.skechers.com/login ").as_deref(), Some("skechers.com"));
        assert_eq!(site_of_login_url("http://accounts.google.com/x").as_deref(), Some("google.com"));
        assert_eq!(site_of_login_url("android://com.example.app"), None);
        assert_eq!(site_of_login_url("192.168.1.1"), None);
        assert_eq!(site_of_login_url(""), None);
    }

    #[test]
    fn a_login_on_the_platform_host_does_not_match_user_sites() {
        let directory = temp_directory();
        let mut vault = VaultStore::new(&directory).create("synthetic-test-password").unwrap();
        vault
            .save_entry(serde_json::json!({"type": "PASSWORD", "title": "Pages", "primaryValue": "me",
                "secondaryValue": "pw", "tertiaryValue": "https://github.io"}))
            .unwrap();
        let connection = vault.connection();
        assert!(known_sites(connection).unwrap().is_empty());
        assert!(!wanted(connection, "https://alice.github.io", true, 0).unwrap());
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn save_checks_everything_before_it_stores() {
        let (mut vault, directory) = vault_with_sites();
        let connection = vault.connection();
        let good = png_of(64, 64);
        let google = "https://www.google.com";
        assert_eq!(save(connection, google, &good, false, 5), Err(Refused::Off));
        assert_eq!(save(connection, "http://www.google.com", &good, true, 5), Err(Refused::NoMatch));
        assert_eq!(save(connection, "https://192.168.1.10", &good, true, 5), Err(Refused::NoMatch));
        assert_eq!(save(connection, "https://other.example", &good, true, 5), Err(Refused::NoMatch));
        assert_eq!(save(connection, google, b"", true, 5), Err(Refused::BadImage));
        assert_eq!(save(connection, google, b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>", true, 5), Err(Refused::BadImage));
        assert_eq!(save(connection, google, &good[..good.len() - 12], true, 5), Err(Refused::BadImage), "truncated");
        assert_eq!(save(connection, google, &png_of(128, 128), true, 5), Err(Refused::BadImage));
        assert_eq!(save(connection, google, &png_of(15, 64), true, 5), Err(Refused::BadImage));
        assert_eq!(save(connection, google, &png_of(64, 65), true, 5), Err(Refused::BadImage));
        let mut padded = good.clone();
        padded.resize(MAX_PNG_BYTES + 1, 0);
        assert_eq!(save(connection, google, &padded, true, 5), Err(Refused::BadImage), "over 32 KB");
        assert!(data_urls(connection).unwrap().is_empty());
        save(connection, google, &good, true, 5).unwrap();
        save(connection, "https://login.example.org", &png_of(16, 32), true, 6).unwrap();
        let icons = data_urls(connection).unwrap();
        assert_eq!(icons.keys().map(String::as_str).collect::<Vec<_>>(), ["example.org", "google.com"]);
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn icon_wanted_until_fresh_then_again_after_30_days() {
        let (mut vault, directory) = vault_with_sites();
        let connection = vault.connection();
        let now = 500 * DAY;
        assert!(wanted(connection, "https://www.google.com", true, now).unwrap());
        save(connection, "https://www.google.com", &png_of(64, 64), true, now).unwrap();
        assert!(!wanted(connection, "https://www.google.com", true, now).unwrap());
        assert!(!wanted(connection, "https://www.google.com", true, now + 29 * DAY).unwrap());
        assert!(wanted(connection, "https://www.google.com", true, now + 30 * DAY).unwrap());
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn at_most_2000_icons_and_the_oldest_go_first() {
        let (mut vault, directory) = vault_with_sites();
        let connection = vault.connection();
        let transaction = connection.unchecked_transaction().unwrap();
        for index in 0..MAX_ICONS {
            transaction
                .execute(
                    "INSERT INTO local_site_icons (site, png, updated_at) VALUES (?1, x'00', ?2)",
                    params![format!("filler{index}.example"), 100 + index],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        save(connection, "https://www.google.com", &png_of(64, 64), true, 10_000).unwrap();
        let icons = data_urls(connection).unwrap();
        assert_eq!(icons.len() as i64, MAX_ICONS);
        assert!(icons.contains_key("google.com"));
        assert!(!icons.contains_key("filler0.example"), "the oldest row was evicted");
        assert!(icons.contains_key("filler1.example"));
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn purge_on_open_drops_icons_without_a_login_or_passkey() {
        let (mut vault, directory) = vault_with_sites();
        let connection = vault.connection();
        for site in ["google.com", "example.org", "gone.example"] {
            connection
                .execute("INSERT INTO local_site_icons (site, png, updated_at) VALUES (?1, x'00', 1)", [site])
                .unwrap();
        }
        purge(connection, true).unwrap();
        assert_eq!(data_urls(connection).unwrap().keys().collect::<Vec<_>>(), ["example.org", "google.com"]);
        purge(connection, false).unwrap();
        assert!(data_urls(connection).unwrap().is_empty());
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unlocking_purges_orphan_icons() {
        let (mut vault, directory) = vault_with_sites();
        // The fake passkey row is not a real record, so unlock could not read it.
        vault.connection().execute("DELETE FROM local_passkeys", []).unwrap();
        vault
            .connection()
            .execute("INSERT INTO local_site_icons (site, png, updated_at) VALUES ('gone.example', x'00', 1)", [])
            .unwrap();
        drop(vault);
        let mut again = VaultStore::new(&directory).unlock("synthetic-test-password").unwrap();
        assert!(data_urls(again.connection()).unwrap().is_empty(), "gone.example had no login or passkey");
        drop(again);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn views_are_camel_case_with_data_urls() {
        let (mut vault, directory) = vault_with_sites();
        let connection = vault.connection();
        let good = png_of(64, 64);
        save(connection, "https://www.google.com", &good, true, 5).unwrap();
        let view = View { enabled: true, icons: data_urls(connection).unwrap() };
        let json = serde_json::to_value(&view).unwrap();
        let url = json["icons"]["google.com"].as_str().unwrap();
        assert_eq!(url, format!("data:image/png;base64,{}", STANDARD.encode(&good)));
        assert_eq!(json["enabled"], true);
        let empty = serde_json::to_value(View { enabled: false, icons: BTreeMap::new() }).unwrap();
        assert_eq!(empty, serde_json::json!({"enabled": false, "icons": {}}));
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_setting_defaults_on_and_survives_bad_files() {
        assert!(parse_enabled("not json"));
        assert!(parse_enabled("{}"));
        assert!(!parse_enabled(r#"{"enabled":false}"#));
    }
}
