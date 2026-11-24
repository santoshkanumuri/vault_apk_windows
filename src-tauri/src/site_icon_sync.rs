//! Synced website icons (protocol `site-icons-v1`, shared with Android `SiteIconSyncRules.kt`).
//!
//! The browser extension captures a site's icon on this PC (`site_icons.rs`). This module shares it
//! with the sync group, so the phone and other PCs show the same icon.
//!
//! - Sync entity [ENTITY_TYPE], always an upsert. The entity id is [entity_id]: an HMAC of the site
//!   under the group's content key, because entity ids travel in plain text and must not show which
//!   sites the vault holds.
//! - Plaintext `{"siteIcon":{"site":"<site>","png":"<standard base64>"}}`, encrypted like every
//!   other change. The receiver recomputes the id from the site and checks the PNG.
//! - Concurrent changes never become a conflict: the later `occurredAtUtc` wins, then the greater
//!   device ID ([crate::appearance::incoming_wins]).
//! - Released builds stop a writer's whole chain at an unknown entity type, so icons are written only
//!   while every other active member announced [FEATURE] ([crate::appearance::gate_open_for]), over
//!   Wi-Fi or in its Google Drive progress file. Until then they wait, and [flush] writes them later.
//! - `site_icon_sync_state` remembers the bytes last written or received per site, so an unchanged
//!   icon (the 30-day refresh) writes nothing and a received icon is never sent back.
//! - `site_icon_captures` remembers this PC's own last capture per site. Two PCs can draw one logo
//!   into slightly different bytes, so once the group has an icon for a site, a capture is sent only
//!   when it differs from this PC's previous capture: the site changed its logo. Without this rule
//!   the two PCs would replace each other's icon at every 30-day refresh, forever.
//!
//! Shared test vectors: `fixtures/site-icons-v1.json` (Android `scripts/sync-vectors/site_icons.py`).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    change_store::{ChangeStore, StoredVaultRecord},
    identity::{DeviceIdentity, DeviceIdentityStore},
    membership,
    payload,
    protocol::{RecordVersion, VersionRelation},
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
    vault::UnlockedVault,
};

pub const FEATURE: &str = crate::protocol::SITE_ICONS_FEATURE;
pub const ENTITY_TYPE: &str = "site_icon";
pub const ID_PREFIX: &str = "nuvori-sync-site-icon-id-v1:";
/// Most icon changes one flush writes, so one sync session stays small. The rest go next time.
const FLUSH_LIMIT: usize = 50;

pub(crate) const STATE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS site_icon_sync_state (
    site TEXT PRIMARY KEY NOT NULL,
    png_sha256 TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    updated_by_device TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS site_icon_captures (
    site TEXT PRIMARY KEY NOT NULL,
    png_sha256 TEXT NOT NULL,
    changed INTEGER NOT NULL
);";

/// The first 32 lowercase hex characters of HMAC-SHA256(content key, [ID_PREFIX] + site).
pub fn entity_id(content_key: &[u8], site: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(content_key).expect("any HMAC key length");
    mac.update(ID_PREFIX.as_bytes());
    mac.update(site.as_bytes());
    hex::encode(mac.finalize().into_bytes())[..32].to_owned()
}

/// A lowercase ASCII host name with at least two labels, not an IPv4 address. No scheme, port or path.
pub fn valid_site(site: &str) -> bool {
    if site.is_empty() || site.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = site.split('.').collect();
    let label_ok = |label: &&str| {
        let bytes = label.as_bytes();
        (1..=63).contains(&bytes.len())
            && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
    };
    labels.len() >= 2 && labels.iter().all(label_ok) && !labels.iter().all(|label| label.bytes().all(|b| b.is_ascii_digit()))
}

/// The plaintext of one icon change.
pub fn payload_json(site: &str, png: &[u8]) -> Value {
    json!({"siteIcon": {"site": site, "png": STANDARD.encode(png)}})
}

/// The site and PNG of a decrypted payload whose entity id is `entity_id`, or `None` when the id
/// belongs to another site or the site or the image is invalid. Extra keys are ignored.
pub fn parse_payload(payload: &Value, entity_id: &str, content_key: &[u8]) -> Option<(String, Vec<u8>)> {
    let icon = payload.get("siteIcon")?;
    let site = icon.get("site")?.as_str()?;
    let png = STANDARD.decode(icon.get("png")?.as_str()?).ok()?;
    (valid_site(site) && self::entity_id(content_key, site) == entity_id && crate::site_icons::valid_png(&png))
        .then(|| (site.to_owned(), png))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_utc() -> Result<String, String> {
    OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| "The system clock is unavailable".to_owned())
}

/// Who last wrote or delivered the icon of `site`, and the hash of its bytes.
pub(crate) fn synced_state(db: &Connection, site: &str) -> rusqlite::Result<Option<(String, String, String)>> {
    db.execute_batch(STATE_SCHEMA)?;
    db.query_row(
        "SELECT png_sha256, updated_at_utc, updated_by_device FROM site_icon_sync_state WHERE site = ?1",
        [site],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
}

pub(crate) fn remember_synced(db: &Connection, site: &str, png: &[u8], at: &str, device: &str) -> rusqlite::Result<()> {
    db.execute_batch(STATE_SCHEMA)?;
    db.execute(
        "INSERT INTO site_icon_sync_state (site, png_sha256, updated_at_utc, updated_by_device) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(site) DO UPDATE SET png_sha256 = excluded.png_sha256, updated_at_utc = excluded.updated_at_utc,
             updated_by_device = excluded.updated_by_device",
        params![site, sha256_hex(png), at, device],
    )?;
    Ok(())
}

/// Notes an icon this PC's extension just captured. `changed` is true when this PC captured the site
/// before and the bytes differ now: the site changed its logo.
pub(crate) fn remember_capture(db: &Connection, site: &str, png: &[u8]) -> rusqlite::Result<()> {
    db.execute_batch(STATE_SCHEMA)?;
    let hash = sha256_hex(png);
    let previous: Option<String> =
        db.query_row("SELECT png_sha256 FROM site_icon_captures WHERE site = ?1", [site], |row| row.get(0)).optional()?;
    let changed = previous.is_some_and(|previous| previous != hash);
    db.execute(
        "INSERT INTO site_icon_captures (site, png_sha256, changed) VALUES (?1, ?2, ?3)
         ON CONFLICT(site) DO UPDATE SET png_sha256 = excluded.png_sha256, changed = excluded.changed",
        params![site, hash, changed],
    )?;
    Ok(())
}

/// Stores an icon that arrived through sync, when the "Website icons" setting is on. With the setting
/// off this PC keeps no icons at all; after it is turned on, the extension captures the site again.
pub(crate) fn store_received(db: &Connection, site: &str, png: &[u8], now_millis: i64) -> rusqlite::Result<()> {
    if !crate::site_icons::enabled() {
        return Ok(());
    }
    db.execute(
        "INSERT OR REPLACE INTO local_site_icons (site, png, updated_at) VALUES (?1, ?2, ?3)",
        params![site, png, now_millis],
    )?;
    db.execute(
        "DELETE FROM local_site_icons WHERE site NOT IN
            (SELECT site FROM local_site_icons ORDER BY updated_at DESC, rowid DESC LIMIT ?1)",
        [crate::site_icons::MAX_ICONS],
    )?;
    Ok(())
}

/// Writes a signed change for each stored icon whose bytes differ from the last synced ones, when
/// the setting is on and the gate is open. Returns how many changes it wrote. The vault lock must be held.
pub(crate) fn flush(vault: &mut UnlockedVault, identity_store: &DeviceIdentityStore) -> Result<usize, String> {
    if !crate::site_icons::enabled() {
        return Ok(0);
    }
    let events = vault.stored_membership().map_err(|error| error.to_string())?;
    flush_with(vault.connection(), &events, identity_store, FLUSH_LIMIT)
}

/// [flush], with failures only logged: the icons wait for the next sync.
pub(crate) fn flush_installed(vault: &mut UnlockedVault, identity_store: &DeviceIdentityStore) {
    if let Err(error) = flush(vault, identity_store) {
        crate::activity::diagnostic(crate::activity::Category::Sync, "Website icons kept for a later sync", error);
    }
}

pub(crate) fn flush_with(
    db: &mut Connection,
    events: &[membership::MembershipEvent],
    identity_store: &DeviceIdentityStore,
    limit: usize,
) -> Result<usize, String> {
    if events.is_empty() || !identity_store.exists() {
        return Ok(0);
    }
    let membership = membership::verify(events).map_err(|error| error.to_string())?;
    let local = identity_store.get_or_create().map_err(|error| error.to_string())?;
    if !crate::appearance::gate_open_for(db, &membership, &local.device_id, FEATURE) {
        return Ok(0);
    }
    let waiting = waiting(db, limit).map_err(|error| error.to_string())?;
    let mut written = 0;
    for (site, png) in waiting {
        let at = now_utc()?;
        write_change(db, identity_store, &local, &membership.vault_id, &site, &png, &at).map_err(|error| error.to_string())?;
        remember_synced(db, &site, &png, &at, &local.device_id).map_err(|error| error.to_string())?;
        written += 1;
    }
    Ok(written)
}

/// Stored icons to write, newest first, at most `limit`: the first icon of a site the group has none
/// for, and a capture of a changed logo (see the module notes). Rows that would not pass the
/// receiver's checks are left out.
pub(crate) fn waiting(db: &Connection, limit: usize) -> rusqlite::Result<Vec<(String, Vec<u8>)>> {
    db.execute_batch(STATE_SCHEMA)?;
    let mut statement = db.prepare(
        "SELECT icon.site, icon.png, state.png_sha256, capture.png_sha256, capture.changed FROM local_site_icons icon
         LEFT JOIN site_icon_sync_state state ON state.site = icon.site
         LEFT JOIN site_icon_captures capture ON capture.site = icon.site
         ORDER BY icon.updated_at DESC, icon.site",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<bool>>(4)?.unwrap_or(false),
        ))
    })?;
    let mut waiting = Vec::new();
    for row in rows {
        let (site, png, synced, captured, changed) = row?;
        if waiting.len() >= limit {
            break;
        }
        let hash = sha256_hex(&png);
        let send = match synced {
            None => true,
            Some(synced) => synced != hash && changed && captured.as_deref() == Some(hash.as_str()),
        };
        if send && valid_site(&site) && crate::site_icons::valid_png(&png) {
            waiting.push((site, png));
        }
    }
    Ok(waiting)
}

/// Signs one icon change as the next link of this device's chain, with record version = current
/// version with this device's counter + 1, in one transaction with the head and record.
fn write_change(
    db: &mut Connection,
    identity_store: &DeviceIdentityStore,
    local: &DeviceIdentity,
    vault_id: &str,
    site: &str,
    png: &[u8],
    occurred_at: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let content_key: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(db.query_row(
        "SELECT content_key FROM sync_group_state WHERE vault_id = ?1",
        [vault_id],
        |row| row.get(0),
    )?);
    let id = entity_id(&content_key, site);
    let head: Option<(i64, String)> = db
        .query_row(
            "SELECT sequence, hash FROM sync_device_heads WHERE vault_id = ?1 AND device_id = ?2",
            params![vault_id, local.device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (sequence, previous_hash) =
        head.map_or((1, GENESIS_HASH.to_owned()), |(sequence, hash)| (sequence as u64 + 1, hash));
    let current = ChangeStore::record(db, ENTITY_TYPE, &id)?;
    let base_revision = current.as_ref().map_or(0, |record| record.revision);
    let mut counters = current
        .as_ref()
        .map(|record| serde_json::from_str::<RecordVersion>(&record.record_version_json))
        .transpose()?
        .unwrap_or_default()
        .counters()
        .clone();
    *counters.entry(local.device_id.clone()).or_default() += 1;
    let version = RecordVersion::new(counters);
    let mutation_id = uuid::Uuid::new_v4().to_string();
    let encrypted = payload::encrypt_in(
        db,
        &content_key,
        ENTITY_TYPE,
        vault_id,
        &mutation_id,
        &id,
        &serde_json::to_vec(&payload_json(site, png))?,
    )?;
    let operation = ChangeRecord::create_signed_with(
        vault_id,
        &local.device_id,
        sequence,
        previous_hash,
        mutation_id,
        ENTITY_TYPE,
        &id,
        ChangeKind::Upsert,
        base_revision,
        version.clone(),
        occurred_at,
        encrypted.ciphertext,
        encrypted.nonce,
        |message| identity_store.sign(message),
    )?;
    let record = StoredVaultRecord {
        entity_type: ENTITY_TYPE.to_owned(),
        entity_id: id,
        payload_ciphertext: operation.payload_ciphertext.clone(),
        revision: base_revision + 1,
        record_version_json: serde_json::to_string(&version)?,
    };
    ChangeStore::save_record_and_operation(db, &record, &operation, local)?;
    Ok(())
}

/// The change each icon entity of a snapshot settles on: of its readable changes that no other
/// change of the same entity includes, the last writer. Returns (change, site, png).
pub(crate) fn snapshot_choices<'a>(operations: &[&'a ChangeRecord], content_key: &[u8]) -> Vec<(&'a ChangeRecord, String, Vec<u8>)> {
    let readable: Vec<(&ChangeRecord, String, Vec<u8>)> = operations
        .iter()
        .filter(|operation| operation.entity_type == ENTITY_TYPE && operation.kind == ChangeKind::Upsert)
        .filter_map(|operation| {
            let plaintext = zeroize::Zeroizing::new(payload::decrypt(content_key, operation).ok()?);
            let (site, png) = parse_payload(&serde_json::from_slice(&plaintext).ok()?, &operation.entity_id, content_key)?;
            Some((*operation, site, png))
        })
        .collect();
    let stamp = |operation: &ChangeRecord| crate::appearance::Stamp::new(Some(&operation.occurred_at_utc), Some(&operation.device_id));
    let mut chosen: Vec<(&ChangeRecord, String, Vec<u8>)> = Vec::new();
    for (index, (operation, site, png)) in readable.iter().enumerate() {
        let included = readable.iter().any(|(other, ..)| {
            other.entity_id == operation.entity_id
                && other.hash != operation.hash
                && operation.record_version.relation_to(&other.record_version) == VersionRelation::Before
        });
        if included {
            continue;
        }
        let later_sibling = readable.iter().enumerate().any(|(other_index, (other, ..))| {
            other_index != index
                && other.entity_id == operation.entity_id
                && !readable.iter().any(|(third, ..)| {
                    third.entity_id == other.entity_id
                        && third.hash != other.hash
                        && other.record_version.relation_to(&third.record_version) == VersionRelation::Before
                })
                && stamp(other) > stamp(operation)
        });
        if !later_sibling {
            chosen.push((*operation, site.clone(), png.clone()));
        }
    }
    chosen
}

/// After a snapshot import: stores the icon each entity settles on and remembers it as synced.
pub(crate) fn adopt_from_snapshot(db: &Connection, choices: &[(&ChangeRecord, String, Vec<u8>)]) -> rusqlite::Result<()> {
    let now = crate::activity::now_millis() as i64;
    for (operation, site, png) in choices {
        store_received(db, site, png, now)?;
        remember_synced(db, site, png, &operation.occurred_at_utc, &operation.device_id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../fixtures/site-icons-v1.json")).unwrap()
    }

    fn content_key(vectors: &Value) -> Vec<u8> {
        hex::decode(vectors["contentKeyHex"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn the_vector_file_describes_this_protocol() {
        let vectors = vectors();
        assert_eq!(vectors["feature"], FEATURE);
        assert_eq!(vectors["entityType"], ENTITY_TYPE);
        assert_eq!(vectors["idPrefix"], ID_PREFIX);
        assert_eq!(vectors["maxPngBytes"], crate::site_icons::MAX_PNG_BYTES as u64);
        assert!(crate::protocol::SYNC_FEATURES.contains(&FEATURE));
    }

    #[test]
    fn entity_ids_match_the_vectors() {
        let vectors = vectors();
        let key = content_key(&vectors);
        for case in vectors["entityIds"].as_array().unwrap() {
            assert_eq!(entity_id(&key, case["site"].as_str().unwrap()), case["entityId"].as_str().unwrap());
        }
    }

    #[test]
    fn sites_and_pngs_follow_the_shared_rules() {
        let vectors = vectors();
        for site in vectors["sites"]["valid"].as_array().unwrap() {
            assert!(valid_site(site.as_str().unwrap()), "{site}");
        }
        for site in vectors["sites"]["invalid"].as_array().unwrap() {
            assert!(!valid_site(site.as_str().unwrap()), "{site}");
        }
        for case in vectors["pngs"].as_array().unwrap() {
            let bytes = STANDARD.decode(case["base64"].as_str().unwrap()).unwrap();
            assert_eq!(crate::site_icons::valid_png(&bytes), case["valid"].as_bool().unwrap(), "{}", case["name"]);
        }
    }

    #[test]
    fn every_payload_case_decrypts_and_parses_or_is_rejected() {
        let vectors = vectors();
        let key = content_key(&vectors);
        let vault_id = vectors["vaultId"].as_str().unwrap();
        let mutation_id = vectors["mutationId"].as_str().unwrap();
        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 9);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let entity = case["entityId"].as_str().unwrap();
            let change = ChangeRecord::create(
                vault_id, "device-a", 1, GENESIS_HASH, mutation_id, ENTITY_TYPE, entity, ChangeKind::Upsert, 0,
                RecordVersion::from_entries([("device-a", 1)]), "2026-11-21T10:00:00Z",
                case["payloadCiphertext"].as_str().unwrap(), case["payloadNonce"].as_str().unwrap(), "unsigned",
            );
            let plaintext = payload::decrypt(&key, &change).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(plaintext, case["plaintext"].as_str().unwrap().as_bytes(), "{name}");
            let parsed = parse_payload(&serde_json::from_slice(&plaintext).unwrap(), entity, &key);
            if case["valid"].as_bool().unwrap() {
                let (site, png) = parsed.unwrap_or_else(|| panic!("{name}"));
                assert_eq!(site, case["expected"]["site"].as_str().unwrap(), "{name}");
                assert_eq!(sha256_hex(&png), case["expected"]["pngSha256"].as_str().unwrap(), "{name}");
            } else {
                assert!(parsed.is_none(), "{name}");
            }
        }
    }

    fn signed_change(device: &str, sequence: u64, version: RecordVersion, at: &str, site: &str, png: &[u8]) -> ChangeRecord {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let key = [5u8; 32];
        let id = entity_id(&key, site);
        let mutation = format!("m-{device}-{sequence}");
        let body = serde_json::to_vec(&payload_json(site, png)).unwrap();
        let encrypted = payload::encrypt(&key, ENTITY_TYPE, "vault-a", &mutation, &id, &body).unwrap();
        ChangeRecord::create_signed_with("vault-a", device, sequence, GENESIS_HASH, mutation, ENTITY_TYPE, &id,
            ChangeKind::Upsert, 0, version, at, encrypted.ciphertext, encrypted.nonce,
            |bytes| Ok::<_, ()>(ed25519_dalek::Signer::sign(&signer, bytes).to_bytes()))
            .unwrap()
    }

    #[test]
    fn a_snapshot_takes_the_last_writer_of_each_site() {
        let vectors = vectors();
        let png = |index: usize| STANDARD.decode(vectors["pngs"][index]["base64"].as_str().unwrap()).unwrap();
        let first = signed_change("aaaa", 1, RecordVersion::from_entries([("aaaa", 1)]), "2026-11-21T10:00:00Z", "github.com", &png(0));
        let replaced = signed_change("aaaa", 2, RecordVersion::from_entries([("aaaa", 2)]), "2026-11-20T10:00:00Z", "github.com", &png(1));
        let early = signed_change("aaaa", 3, RecordVersion::from_entries([("aaaa", 3)]), "2026-11-21T10:00:00Z", "bbc.co.uk", &png(0));
        let late = signed_change("bbbb", 1, RecordVersion::from_entries([("bbbb", 1)]), "2026-11-21T11:00:00Z", "bbc.co.uk", &png(2));
        let chosen = snapshot_choices(&[&first, &replaced, &early, &late], &[5; 32]);
        let by_site: std::collections::HashMap<&str, &ChangeRecord> =
            chosen.iter().map(|(operation, site, _)| (site.as_str(), *operation)).collect();
        assert_eq!(by_site.len(), 2);
        assert_eq!(by_site["github.com"].hash, replaced.hash, "a change that includes another wins even with an earlier clock");
        assert_eq!(by_site["bbc.co.uk"].hash, late.hash, "concurrent changes: the last writer");
    }

    #[test]
    fn concurrent_changes_follow_last_writer_wins() {
        for case in vectors()["lastWriterWins"].as_array().unwrap() {
            let current = crate::appearance::Stamp::new(case["currentAt"].as_str(), case["currentDevice"].as_str());
            let incoming = crate::appearance::Stamp::new(case["incomingAt"].as_str(), case["incomingDevice"].as_str());
            assert_eq!(crate::appearance::incoming_wins(&current, &incoming), case["incomingWins"].as_bool().unwrap(), "{case}");
        }
    }

    #[test]
    fn only_new_or_changed_icons_wait_to_be_written() {
        let db = Connection::open_in_memory().unwrap();
        crate::site_icons::initialize(&db).unwrap();
        let vectors = vectors();
        let png = |index: usize| STANDARD.decode(vectors["pngs"][index]["base64"].as_str().unwrap()).unwrap();
        let insert = |site: &str, bytes: &[u8], at: i64| {
            db.execute("INSERT OR REPLACE INTO local_site_icons (site, png, updated_at) VALUES (?1, ?2, ?3)", params![site, bytes, at])
                .unwrap();
        };
        insert("github.com", &png(0), 3);
        insert("bbc.co.uk", &png(1), 2);
        insert("unchanged.example", &png(2), 1);
        insert("Bad.example", &png(0), 4);
        remember_synced(&db, "unchanged.example", &png(2), "2026-11-21T10:00:00Z", "pc").unwrap();
        // Another PC's icon for bbc.co.uk arrived; this PC then drew the same logo into other bytes.
        remember_synced(&db, "bbc.co.uk", &png(0), "2026-11-21T10:00:00Z", "laptop").unwrap();
        remember_capture(&db, "bbc.co.uk", &png(1)).unwrap();
        let sites = |limit| waiting(&db, limit).unwrap().into_iter().map(|(site, _)| site).collect::<Vec<_>>();
        assert_eq!(sites(10), ["github.com"], "a new site goes; same bytes, a first capture of a shared icon and bad sites stay out");
        assert_eq!(sites(0), Vec::<String>::new());

        // The 30-day refresh captures the same bytes again: still nothing, so two PCs never ping-pong.
        remember_capture(&db, "bbc.co.uk", &png(1)).unwrap();
        assert_eq!(sites(10), ["github.com"]);

        // The site changed its logo: this PC's capture differs from its own last one, so it goes.
        insert("bbc.co.uk", &png(2), 2);
        remember_capture(&db, "bbc.co.uk", &png(2)).unwrap();
        assert_eq!(sites(10), ["github.com", "bbc.co.uk"], "newest first");
        assert_eq!(sites(1), ["github.com"]);
        remember_synced(&db, "github.com", &png(0), "2026-11-21T11:00:00Z", "pc").unwrap();
        remember_synced(&db, "bbc.co.uk", &png(2), "2026-11-21T11:00:00Z", "pc").unwrap();
        assert!(sites(10).is_empty());
    }

    #[test]
    fn the_gate_needs_every_other_member_to_announce_site_icons() {
        let db = Connection::open_in_memory().unwrap();
        ChangeStore::initialize(&db).unwrap();
        db.execute_batch("CREATE TABLE sync_group_state (vault_id TEXT NOT NULL PRIMARY KEY, content_key BLOB NOT NULL, transport_secret BLOB NOT NULL);
            INSERT INTO sync_group_state VALUES ('vault-a', x'00', x'00');").unwrap();
        let group = crate::appearance::tests::membership(&[("pc", true), ("phone", true)]);
        let announce = |list: &[&str]| {
            let list: Vec<String> = list.iter().map(|feature| (*feature).to_owned()).collect();
            crate::appearance::record_peer_features(&db, "vault-a", "phone", &list).unwrap();
        };
        announce(&[crate::protocol::APPEARANCE_FEATURE]);
        assert!(crate::appearance::gate_open(&db, &group, "pc"));
        assert!(!crate::appearance::gate_open_for(&db, &group, "pc", FEATURE), "a 2.3.3 phone: closed");
        announce(&crate::protocol::SYNC_FEATURES);
        assert!(crate::appearance::gate_open_for(&db, &group, "pc", FEATURE));
    }

    #[test]
    fn the_writer_payload_round_trips() {
        let key = [7u8; 32];
        let png = STANDARD.decode(vectors()["pngs"][0]["base64"].as_str().unwrap()).unwrap();
        let id = entity_id(&key, "github.com");
        assert_eq!(parse_payload(&payload_json("github.com", &png), &id, &key), Some(("github.com".to_owned(), png)));
    }
}
