//! Synced vault appearance (protocol `appearance-v1`, shared with Android): one accent and one
//! background for the whole sync group.
//!
//! - Device-only file `appearance.json` next to the vault: `{accent, surface, updatedAtUtc,
//!   updatedByDevice, pendingSync}`. It is not secret and is readable while the vault is locked,
//!   so the unlock screen uses it.
//! - Sync entity `"appearance"`, id `"vault"`, always an upsert with the plaintext payload
//!   `{"appearance":{"accent":"<id>","surface":"<id>"}}`, encrypted like every other change.
//! - Released builds (2.2.3) stop a writer's whole chain at an unknown entity type, so a change is
//!   written only while this vault is in a sync group and every other active member last
//!   announced [FEATURE] in an authenticated Wi-Fi session ([gate_open]). Until then the choice
//!   stays local with `pendingSync` set, and [flush] writes it later.
//! - Incoming changes are applied in `incoming_apply.rs` with the rules in [incoming_wins]: never
//!   a conflict, never an echo.

use std::{
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, OnceLock},
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    change_store::{ChangeStore, StoredVaultRecord},
    identity::{DeviceIdentity, DeviceIdentityStore},
    membership::{self, VerifiedMembership},
    payload,
    protocol::RecordVersion,
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
    vault::UnlockedVault,
};

/// Announced in the sync handshake `features` list by builds that read appearance changes.
pub const FEATURE: &str = crate::protocol::APPEARANCE_FEATURE;
pub const ENTITY_TYPE: &str = "appearance";
pub const ENTITY_ID: &str = "vault";
pub const DEFAULT_ACCENT: &str = "green";
pub const DEFAULT_SURFACE: &str = "sage";
/// Sent to every window with a [View] whenever the stored appearance changes.
pub const EVENT: &str = "appearance-changed";
const FILE: &str = "appearance.json";

/// Device-only record of what each group member last announced in an authenticated session.
pub(crate) const PEER_FEATURES_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sync_peer_features (
    vault_id TEXT NOT NULL, peer_device_id TEXT NOT NULL, features_json TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL, PRIMARY KEY (vault_id, peer_device_id))";

/// `^[a-z][a-z0-9-]{0,31}$`. An id from a newer palette is valid; only its shape is checked.
pub fn valid_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// The accent and surface ids of a decrypted payload. `None` when either is missing or invalid.
/// Extra keys are ignored.
pub fn parse_payload(payload: &Value) -> Option<(String, String)> {
    let appearance = payload.get("appearance")?;
    let id = |key: &str| appearance.get(key).and_then(Value::as_str).filter(|id| valid_id(id)).map(str::to_owned);
    Some((id("accent")?, id("surface")?))
}

pub fn payload_json(accent: &str, surface: &str) -> Value {
    json!({"appearance": {"accent": accent, "surface": surface}})
}

/// Who wrote a value and when. Ordered by the instant, then by device ID as a plain string. A
/// missing or unreadable time sorts first (it loses); a missing device counts as "".
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stamp {
    at: Option<OffsetDateTime>,
    device: String,
}

impl Stamp {
    pub fn new(at: Option<&str>, device: Option<&str>) -> Self {
        Stamp {
            at: at.and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok()),
            device: device.unwrap_or_default().to_owned(),
        }
    }
}

/// Last writer wins: true when `incoming` is strictly later than `current`.
pub fn incoming_wins(current: &Stamp, incoming: &Stamp) -> bool {
    incoming > current
}

/// The contents of `appearance.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub accent: String,
    pub surface: String,
    pub updated_at_utc: Option<String>,
    pub updated_by_device: Option<String>,
    pub pending_sync: bool,
}

impl Default for Stored {
    fn default() -> Self {
        Stored {
            accent: DEFAULT_ACCENT.to_owned(),
            surface: DEFAULT_SURFACE.to_owned(),
            updated_at_utc: None,
            updated_by_device: None,
            pending_sync: false,
        }
    }
}

impl Stored {
    /// Reads the file text. Anything unreadable falls back to the default, field by field.
    pub fn parse(text: &str) -> Stored {
        let defaults = Stored::default();
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            return defaults;
        };
        let id = |key: &str, default: String| {
            value[key].as_str().filter(|id| valid_id(id)).map_or(default, str::to_owned)
        };
        let text = |key: &str| value[key].as_str().filter(|text| !text.is_empty() && text.len() <= 256).map(str::to_owned);
        Stored {
            accent: id("accent", defaults.accent),
            surface: id("surface", defaults.surface),
            updated_at_utc: text("updatedAtUtc"),
            updated_by_device: text("updatedByDevice"),
            pending_sync: value["pendingSync"].as_bool().unwrap_or(false),
        }
    }

    pub fn to_json(&self) -> String {
        json!({
            "accent": self.accent,
            "surface": self.surface,
            "updatedAtUtc": self.updated_at_utc,
            "updatedByDevice": self.updated_by_device,
            "pendingSync": self.pending_sync,
        })
        .to_string()
    }

    pub fn stamp(&self) -> Stamp {
        Stamp::new(self.updated_at_utc.as_deref(), self.updated_by_device.as_deref())
    }

    pub fn view(&self) -> View {
        View { accent: self.accent.clone(), surface: self.surface.clone(), pending_sync: self.pending_sync }
    }
}

/// What `get_appearance`, `set_appearance` and the [EVENT] return.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub accent: String,
    pub surface: String,
    pub pending_sync: bool,
}

type Notify = Box<dyn Fn(&View) + Send + Sync>;

/// `appearance.json` with a lock for read-decide-write steps. Lock order: the vault state lock
/// (when held) before [AppearanceStore::lock], never the other way round.
pub struct AppearanceStore {
    file: PathBuf,
    /// This device's sync identity (the same file `VaultStore::identity_store` uses).
    identity_file: PathBuf,
    local_device: Mutex<Option<String>>,
    lock: Mutex<()>,
    notify: Option<Notify>,
}

impl AppearanceStore {
    pub fn new(directory: &Path) -> Self {
        AppearanceStore {
            file: directory.join(FILE),
            identity_file: directory.join("device-identity-v1.json"),
            local_device: Mutex::new(None),
            lock: Mutex::new(()),
            notify: None,
        }
    }

    /// This device's sync ID, once it has one.
    pub(crate) fn local_device(&self) -> Option<String> {
        let mut known = self.local_device.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if known.is_none() {
            let identity = DeviceIdentityStore::new(&self.identity_file);
            *known = identity.exists().then(|| identity.get_or_create().ok()).flatten().map(|identity| identity.device_id);
        }
        known.clone()
    }

    #[cfg(test)]
    pub(crate) fn set_local_device(&self, device: &str) {
        *self.local_device.lock().unwrap() = Some(device.to_owned());
    }

    /// The stamp the stored value competes with. A pending value that was never written and has
    /// no device ID competes as this device, the ID it will carry once written (as on Android).
    pub(crate) fn competing_stamp(&self, stored: &Stored) -> Stamp {
        let device = stored
            .updated_by_device
            .clone()
            .or_else(|| stored.pending_sync.then(|| self.local_device()).flatten());
        Stamp::new(stored.updated_at_utc.as_deref(), device.as_deref())
    }

    pub fn with_notify(directory: &Path, notify: impl Fn(&View) + Send + Sync + 'static) -> Self {
        AppearanceStore { notify: Some(Box::new(notify)), ..Self::new(directory) }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The stored value; the default when the file is missing or unreadable.
    pub fn load(&self) -> Stored {
        std::fs::read_to_string(&self.file).map(|text| Stored::parse(&text)).unwrap_or_default()
    }

    /// Writes the file through a temporary file, so a crash never leaves half a file.
    pub(crate) fn save(&self, stored: &Stored) -> std::io::Result<()> {
        if let Some(parent) = self.file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = self.file.with_extension("json.tmp");
        std::fs::write(&temporary, stored.to_json())?;
        std::fs::rename(&temporary, &self.file)
    }

    pub fn view(&self) -> View {
        let _guard = self.lock();
        self.load().view()
    }

    pub(crate) fn notify(&self, view: &View) {
        if let Some(notify) = &self.notify {
            notify(view);
        }
    }

    /// Saves this device's choice with now as its time, waiting for sync.
    pub fn set_local(&self, accent: &str, surface: &str, device: Option<&str>) -> Result<View, String> {
        if !valid_id(accent) || !valid_id(surface) {
            return Err("Unknown accent or background".to_owned());
        }
        let stored = Stored {
            accent: accent.to_owned(),
            surface: surface.to_owned(),
            updated_at_utc: Some(now_utc()?),
            updated_by_device: device.map(str::to_owned),
            pending_sync: true,
        };
        {
            let _guard = self.lock();
            self.save(&stored).map_err(|error| {
                crate::activity::diagnostic(crate::activity::Category::Vault, "Could not save the appearance", error);
                "The appearance could not be saved on this PC.".to_owned()
            })?;
        }
        let view = stored.view();
        self.notify(&view);
        Ok(view)
    }
}

static INSTALLED: OnceLock<AppearanceStore> = OnceLock::new();

/// Called once at startup. Sync code reaches the store through [installed].
pub fn install(store: AppearanceStore) {
    let _ = INSTALLED.set(store);
}

pub fn installed() -> Option<&'static AppearanceStore> {
    INSTALLED.get()
}

fn now_utc() -> Result<String, String> {
    OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| "The system clock is unavailable".to_owned())
}

/// Remembers what an active member announced: in an authenticated Wi-Fi session, or in its sealed
/// Google Drive progress file (`features`, from 2.3.1 on Windows and 2.3.4 on Android). A member
/// that announced nothing anywhere keeps the gate closed (the safe side).
pub(crate) fn record_peer_features(db: &Connection, vault_id: &str, peer: &str, features: &[String]) -> rusqlite::Result<()> {
    db.execute_batch(PEER_FEATURES_SCHEMA)?;
    let encoded = serde_json::to_string(features).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    db.execute(
        "INSERT INTO sync_peer_features (vault_id, peer_device_id, features_json, recorded_at_utc) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(vault_id, peer_device_id) DO UPDATE SET features_json = excluded.features_json,
             recorded_at_utc = excluded.recorded_at_utc",
        params![vault_id, peer, encoded, now_utc().unwrap_or_default()],
    )?;
    Ok(())
}

/// The features `peer` last announced, or `None` when no authenticated session recorded any.
pub(crate) fn peer_features(db: &Connection, vault_id: &str, peer: &str) -> Option<Vec<String>> {
    db.execute_batch(PEER_FEATURES_SCHEMA).ok()?;
    let encoded: String = db
        .query_row(
            "SELECT features_json FROM sync_peer_features WHERE vault_id = ?1 AND peer_device_id = ?2",
            params![vault_id, peer],
            |row| row.get(0),
        )
        .optional()
        .ok()??;
    serde_json::from_str(&encoded).ok()
}

/// The write gate: this vault is in a sync group, it has at least one other active member, and
/// every other active member last announced [FEATURE]. Removed members are ignored; a member with
/// nothing recorded closes the gate. A lone device never writes, so an older build paired later
/// cannot receive an appearance change in its pairing snapshot.
pub(crate) fn gate_open(db: &Connection, membership: &VerifiedMembership, local_device: &str) -> bool {
    gate_open_for(db, membership, local_device, FEATURE)
}

/// [gate_open] for any optional feature, for example `site-icons-v1` (`site_icon_sync.rs`).
pub(crate) fn gate_open_for(db: &Connection, membership: &VerifiedMembership, local_device: &str, feature: &str) -> bool {
    let enrolled = db
        .query_row("SELECT EXISTS(SELECT 1 FROM sync_group_state WHERE vault_id = ?1)", [&membership.vault_id], |row| {
            row.get::<_, bool>(0)
        })
        .unwrap_or(false);
    let mut others = membership.members.values().filter(|member| member.active && member.device_id != local_device).peekable();
    enrolled
        && others.peek().is_some()
        && others.all(|member| {
            peer_features(db, &membership.vault_id, &member.device_id)
                .is_some_and(|features| features.iter().any(|announced| announced == feature))
        })
}

/// Writes the waiting appearance as a signed change when the gate is open, then clears
/// `pendingSync`. Returns true when a change was written. The vault lock must be held.
pub(crate) fn flush(store: &AppearanceStore, vault: &mut UnlockedVault, identity_store: &DeviceIdentityStore) -> Result<bool, String> {
    let events = vault.stored_membership().map_err(|error| error.to_string())?;
    flush_with(store, vault.connection(), &events, identity_store)
}

/// [flush] with the installed store. Failures are only logged: the value stays pending.
pub(crate) fn flush_installed(vault: &mut UnlockedVault, identity_store: &DeviceIdentityStore) {
    if let Some(store) = installed()
        && let Err(error) = flush(store, vault, identity_store)
    {
        crate::activity::diagnostic(crate::activity::Category::Sync, "Appearance change kept for a later sync", error);
    }
}

pub(crate) fn flush_with(
    store: &AppearanceStore,
    db: &mut Connection,
    events: &[membership::MembershipEvent],
    identity_store: &DeviceIdentityStore,
) -> Result<bool, String> {
    // Held from reading the value to clearing `pendingSync`: a choice saved meanwhile waits for
    // this lock, so pending is cleared only for the value that was written.
    let guard = store.lock();
    let mut stored = store.load();
    if !stored.pending_sync || events.is_empty() || !identity_store.exists() {
        return Ok(false);
    }
    let membership = membership::verify(events).map_err(|error| error.to_string())?;
    let local = identity_store.get_or_create().map_err(|error| error.to_string())?;
    if !gate_open(db, &membership, &local.device_id) {
        return Ok(false);
    }
    // The change carries the time the value was chosen, so every device compares the same instant.
    let occurred_at = match &stored.updated_at_utc {
        Some(at) if Stamp::new(Some(at), None).at.is_some() => at.clone(),
        _ => now_utc()?,
    };
    write_change(db, identity_store, &local, &membership.vault_id, &stored.accent, &stored.surface, &occurred_at)
        .map_err(|error| error.to_string())?;
    stored.pending_sync = false;
    stored.updated_at_utc = Some(occurred_at);
    stored.updated_by_device = Some(local.device_id);
    store.save(&stored).map_err(|error| error.to_string())?;
    drop(guard);
    store.notify(&stored.view());
    Ok(true)
}

/// Signs one appearance change as the next link of this device's chain, with record version =
/// current version with this device's counter + 1, in one transaction with the head and record.
fn write_change(
    db: &mut Connection,
    identity_store: &DeviceIdentityStore,
    local: &DeviceIdentity,
    vault_id: &str,
    accent: &str,
    surface: &str,
    occurred_at: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let content_key: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(db.query_row(
        "SELECT content_key FROM sync_group_state WHERE vault_id = ?1",
        [vault_id],
        |row| row.get(0),
    )?);
    let head: Option<(i64, String)> = db
        .query_row(
            "SELECT sequence, hash FROM sync_device_heads WHERE vault_id = ?1 AND device_id = ?2",
            params![vault_id, local.device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (sequence, previous_hash) =
        head.map_or((1, GENESIS_HASH.to_owned()), |(sequence, hash)| (sequence as u64 + 1, hash));
    let current = ChangeStore::record(db, ENTITY_TYPE, ENTITY_ID)?;
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
        ENTITY_ID,
        &serde_json::to_vec(&payload_json(accent, surface))?,
    )?;
    let operation = ChangeRecord::create_signed_with(
        vault_id,
        &local.device_id,
        sequence,
        previous_hash,
        mutation_id,
        ENTITY_TYPE,
        ENTITY_ID,
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
        entity_id: ENTITY_ID.to_owned(),
        payload_ciphertext: operation.payload_ciphertext.clone(),
        revision: base_revision + 1,
        record_version_json: serde_json::to_string(&version)?,
    };
    ChangeStore::save_record_and_operation(db, &record, &operation, local)?;
    Ok(())
}

/// The appearance change a device joining by snapshot adopts (as on Android): among the readable
/// appearance changes that no other change includes, the last writer by [incoming_wins] order.
pub(crate) fn snapshot_choice<'a>(
    operations: &[&'a ChangeRecord],
    content_key: &[u8],
) -> Option<(&'a ChangeRecord, String, String)> {
    let readable: Vec<(&ChangeRecord, String, String)> = operations
        .iter()
        .filter(|operation| {
            operation.entity_type == ENTITY_TYPE && operation.kind == ChangeKind::Upsert && operation.entity_id == ENTITY_ID
        })
        .filter_map(|operation| {
            let plaintext = zeroize::Zeroizing::new(payload::decrypt(content_key, operation).ok()?);
            let (accent, surface) = parse_payload(&serde_json::from_slice(&plaintext).ok()?)?;
            Some((*operation, accent, surface))
        })
        .collect();
    let included = |operation: &ChangeRecord| {
        readable.iter().any(|(other, ..)| {
            other.hash != operation.hash
                && operation.record_version.relation_to(&other.record_version) == crate::protocol::VersionRelation::Before
        })
    };
    let stamp = |operation: &ChangeRecord| Stamp::new(Some(&operation.occurred_at_utc), Some(&operation.device_id));
    let index = (0..readable.len())
        .filter(|index| !included(readable[*index].0))
        .max_by_key(|index| stamp(readable[*index].0))?;
    readable.into_iter().nth(index)
}

/// After a snapshot import: takes the group's value unless this device holds a pending choice
/// that is later (last writer wins, as for an incoming change).
pub(crate) fn adopt_from_snapshot(store: &AppearanceStore, operation: &ChangeRecord, accent: String, surface: String) -> std::io::Result<()> {
    let guard = store.lock();
    let stored = store.load();
    let incoming = Stamp::new(Some(&operation.occurred_at_utc), Some(&operation.device_id));
    if stored.pending_sync && !incoming_wins(&store.competing_stamp(&stored), &incoming) {
        return Ok(());
    }
    let next = Stored {
        accent,
        surface,
        updated_at_utc: Some(operation.occurred_at_utc.clone()),
        updated_by_device: Some(operation.device_id.clone()),
        pending_sync: false,
    };
    store.save(&next)?;
    drop(guard);
    if next.view() != stored.view() {
        store.notify(&next.view());
    }
    Ok(())
}

/// The `set_appearance` command: saves this device's choice, then writes it at once when the
/// vault is unlocked and the gate is open.
pub(crate) fn set_from_ui(state: &crate::ManagedState, accent: &str, surface: &str) -> Result<View, String> {
    let store = installed().ok_or("Appearance is unavailable")?;
    if !valid_id(accent) || !valid_id(surface) {
        return Err("Unknown accent or background".to_owned());
    }
    let identity_store = state.lock().map_err(|_| "Vault state is unavailable")?.store.identity_store();
    let device = identity_store.exists().then(|| identity_store.get_or_create().ok()).flatten().map(|identity| identity.device_id);
    store.set_local(accent, surface, device.as_deref())?;
    if let Ok(mut app) = state.lock()
        && let Some(vault) = app.unlocked.as_mut()
        && vault.is_enrolled().unwrap_or(false)
    {
        flush_installed(vault, &identity_store);
    }
    Ok(store.view())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::membership::VerifiedMember;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        feature: String,
        entity_type: String,
        entity_id: String,
        content_key_hex: String,
        vault_id: String,
        mutation_id: String,
        aad: String,
        cases: Vec<Case>,
        last_writer_wins: Vec<LastWriter>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        name: String,
        plaintext: String,
        payload_ciphertext: String,
        payload_nonce: String,
        expected: Option<Expected>,
    }

    #[derive(serde::Deserialize)]
    struct Expected {
        accent: String,
        surface: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LastWriter {
        current: Option<Writer>,
        incoming: Writer,
        incoming_wins: bool,
    }

    #[derive(serde::Deserialize)]
    struct Writer {
        at: String,
        device: String,
    }

    fn vector() -> Vector {
        serde_json::from_str(include_str!("../fixtures/appearance-v1.json")).unwrap()
    }

    #[test]
    fn shared_vector_decrypts_and_parses_like_android() {
        let vector = vector();
        assert_eq!((vector.feature.as_str(), vector.entity_type.as_str(), vector.entity_id.as_str()), (FEATURE, ENTITY_TYPE, ENTITY_ID));
        assert_eq!(vector.aad, format!("nuvori-sync-{ENTITY_TYPE}-v1:{}:{}:{ENTITY_ID}", vector.vault_id, vector.mutation_id));
        let key = hex::decode(&vector.content_key_hex).unwrap();
        assert!(!vector.cases.is_empty());
        for case in &vector.cases {
            let change = ChangeRecord::create(
                &vector.vault_id, "device-a", 1, GENESIS_HASH, &vector.mutation_id, &vector.entity_type,
                &vector.entity_id, ChangeKind::Upsert, 0, RecordVersion::from_entries([("device-a", 1)]),
                "2026-11-13T10:00:00Z", &case.payload_ciphertext, &case.payload_nonce, "unsigned",
            );
            let plaintext = payload::decrypt(&key, &change).unwrap_or_else(|error| panic!("{}: {error}", case.name));
            assert_eq!(plaintext, case.plaintext.as_bytes(), "{}", case.name);
            let parsed = parse_payload(&serde_json::from_slice(&plaintext).unwrap());
            let expected = case.expected.as_ref().map(|ids| (ids.accent.clone(), ids.surface.clone()));
            assert_eq!(parsed, expected, "{}", case.name);
            // Another entity ID or mutation must not decrypt.
            let mut moved = change.clone();
            moved.entity_id = "other".to_owned();
            assert!(payload::decrypt(&key, &moved).is_err(), "{}", case.name);
        }
    }

    #[test]
    fn shared_vector_last_writer_wins() {
        let vector = vector();
        assert!(!vector.last_writer_wins.is_empty());
        for (index, case) in vector.last_writer_wins.iter().enumerate() {
            let current = case.current.as_ref().map_or_else(|| Stamp::new(None, None), |writer| {
                Stamp::new(Some(&writer.at), Some(&writer.device))
            });
            let incoming = Stamp::new(Some(&case.incoming.at), Some(&case.incoming.device));
            assert_eq!(incoming_wins(&current, &incoming), case.incoming_wins, "case {index}");
        }
    }

    #[test]
    fn ids_follow_the_shared_pattern() {
        for good in ["green", "a", "aurora-2", "x1", &"a".repeat(32)] {
            assert!(valid_id(good), "{good}");
        }
        for bad in ["", "Blue", "1blue", "-a", "blue!", "blue green", &"a".repeat(33), "grün"] {
            assert!(!valid_id(bad), "{bad}");
        }
        assert_eq!(parse_payload(&json!({"appearance": {"accent": "blue", "surface": "slate"}, "x": 1})),
            Some(("blue".to_owned(), "slate".to_owned())));
        assert_eq!(parse_payload(&json!({"appearance": {"accent": "blue"}})), None);
        assert_eq!(parse_payload(&json!({"accent": "blue", "surface": "slate"})), None);
    }

    #[test]
    fn stored_file_parses_field_by_field_and_round_trips() {
        assert_eq!(Stored::parse(""), Stored::default());
        assert_eq!(Stored::parse("not json"), Stored::default());
        assert_eq!(Stored::parse("[]"), Stored::default());
        let defaults = Stored::default();
        assert_eq!((defaults.accent.as_str(), defaults.surface.as_str(), defaults.pending_sync), ("green", "sage", false));
        let mixed = Stored::parse(r#"{"accent":"Bad!","surface":"aurora-2","updatedAtUtc":5,"updatedByDevice":"d","pendingSync":"yes"}"#);
        assert_eq!(mixed, Stored {
            accent: "green".to_owned(),
            surface: "aurora-2".to_owned(),
            updated_at_utc: None,
            updated_by_device: Some("d".to_owned()),
            pending_sync: false,
        });
        let saved = Stored {
            accent: "blue".to_owned(),
            surface: "slate".to_owned(),
            updated_at_utc: Some("2026-11-13T10:00:00Z".to_owned()),
            updated_by_device: Some("device-a".to_owned()),
            pending_sync: true,
        };
        assert_eq!(Stored::parse(&saved.to_json()), saved);
        let json: Value = serde_json::from_str(&saved.to_json()).unwrap();
        assert_eq!(json["pendingSync"], true);
        assert_eq!(json["updatedAtUtc"], "2026-11-13T10:00:00Z");
    }

    #[test]
    fn the_store_saves_a_local_choice_as_pending_and_notifies() {
        let directory = std::env::temp_dir().join(format!("nuvori-appearance-{}", uuid::Uuid::new_v4()));
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let store = AppearanceStore::with_notify(&directory, {
            let seen = seen.clone();
            move |view| seen.lock().unwrap().push(view.clone())
        });
        assert_eq!(store.view(), View { accent: "green".to_owned(), surface: "sage".to_owned(), pending_sync: false });
        assert!(store.set_local("Blue", "slate", None).is_err());
        let view = store.set_local("blue", "slate", Some("device-a")).unwrap();
        assert_eq!(view, View { accent: "blue".to_owned(), surface: "slate".to_owned(), pending_sync: true });
        assert_eq!(store.view(), view);
        let stored = store.load();
        assert_eq!(stored.updated_by_device.as_deref(), Some("device-a"));
        assert!(stored.stamp() > Stamp::new(None, None));
        assert_eq!(seen.lock().unwrap().as_slice(), [view]);
        let _ = std::fs::remove_dir_all(directory);
    }

    pub(crate) fn member(id: &str, active: bool) -> VerifiedMember {
        VerifiedMember {
            device_id: id.to_owned(),
            public_key: [0; 32],
            active,
            added_by_device_id: "phone".to_owned(),
            membership_sequence: 1,
            key_epoch: 1,
            removal_cutoff: None,
        }
    }

    pub(crate) fn membership(members: &[(&str, bool)]) -> VerifiedMembership {
        VerifiedMembership {
            vault_id: "vault-a".to_owned(),
            manager_device_id: "phone".to_owned(),
            key_epoch: 1,
            head: String::new(),
            members: members.iter().map(|(id, active)| ((*id).to_owned(), member(id, *active))).collect(),
            pending_transfer: None,
            transfer_accepted: false,
        }
    }

    fn features(list: &[&str]) -> Vec<String> {
        list.iter().map(|feature| (*feature).to_owned()).collect()
    }

    #[test]
    fn peer_features_round_trip_and_replace_the_last_session() {
        let db = Connection::open_in_memory().unwrap();
        assert_eq!(peer_features(&db, "vault-a", "phone"), None);
        record_peer_features(&db, "vault-a", "phone", &features(&["removal-cutoff-v1", FEATURE])).unwrap();
        assert_eq!(peer_features(&db, "vault-a", "phone"), Some(features(&["removal-cutoff-v1", FEATURE])));
        assert_eq!(peer_features(&db, "vault-b", "phone"), None, "features belong to one group");
        record_peer_features(&db, "vault-a", "phone", &[]).unwrap();
        assert_eq!(peer_features(&db, "vault-a", "phone"), Some(Vec::new()), "a downgrade replaces the record");
    }

    #[test]
    fn the_gate_needs_enrollment_and_every_other_active_member() {
        let db = Connection::open_in_memory().unwrap();
        ChangeStore::initialize(&db).unwrap();
        db.execute_batch("CREATE TABLE sync_group_state (vault_id TEXT NOT NULL PRIMARY KEY, content_key BLOB NOT NULL, transport_secret BLOB NOT NULL)").unwrap();
        let group = membership(&[("pc", true), ("phone", true), ("tablet", true), ("old", false)]);
        record_peer_features(&db, "vault-a", "phone", &features(&[FEATURE])).unwrap();
        record_peer_features(&db, "vault-a", "tablet", &features(&[FEATURE])).unwrap();
        assert!(!gate_open(&db, &group, "pc"), "not enrolled: closed");
        db.execute("INSERT INTO sync_group_state VALUES ('vault-a', x'00', x'00')", []).unwrap();
        assert!(gate_open(&db, &group, "pc"), "all others announced; the removed member is ignored");
        record_peer_features(&db, "vault-a", "tablet", &features(&["removal-cutoff-v1"])).unwrap();
        assert!(!gate_open(&db, &group, "pc"), "one active member without the feature: closed");
        let larger = membership(&[("pc", true), ("phone", true), ("laptop", true)]);
        assert!(!gate_open(&db, &larger, "pc"), "an active member with nothing recorded: closed");
        let alone = membership(&[("pc", true), ("old", false)]);
        record_peer_features(&db, "vault-a", "old", &features(&[FEATURE])).unwrap();
        assert!(!gate_open(&db, &alone, "pc"), "a lone device never writes");
    }

    #[test]
    fn a_pending_value_without_a_device_competes_as_this_device() {
        let directory = std::env::temp_dir().join(format!("nuvori-appearance-{}", uuid::Uuid::new_v4()));
        let store = AppearanceStore::new(&directory);
        store.set_local_device("mmmm");
        let pending = Stored {
            updated_at_utc: Some("2026-11-13T10:00:00Z".to_owned()),
            pending_sync: true,
            ..Stored::default()
        };
        let at = |device: &str| Stamp::new(Some("2026-11-13T10:00:00Z"), Some(device));
        assert!(!incoming_wins(&store.competing_stamp(&pending), &at("aaaa")));
        assert!(incoming_wins(&store.competing_stamp(&pending), &at("zzzz")));
        let written = Stored { pending_sync: false, ..pending.clone() };
        assert!(incoming_wins(&store.competing_stamp(&written), &at("aaaa")), "only a pending value takes this device's ID");
        let unreadable = Stored { updated_at_utc: Some("yesterday".to_owned()), ..pending };
        assert!(incoming_wins(&store.competing_stamp(&unreadable), &Stamp::new(Some("2000-01-01T00:00:00Z"), None)),
            "an unreadable time is the earliest");
    }

    fn signed_change(device: &str, sequence: u64, version: RecordVersion, at: &str, body: Value) -> ChangeRecord {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let key = [5u8; 32];
        let mutation = format!("m-{device}-{sequence}");
        let encrypted = payload::encrypt(&key, ENTITY_TYPE, "vault-a", &mutation, ENTITY_ID, &serde_json::to_vec(&body).unwrap()).unwrap();
        ChangeRecord::create_signed_with("vault-a", device, sequence, GENESIS_HASH, mutation, ENTITY_TYPE, ENTITY_ID,
            ChangeKind::Upsert, 0, version, at, encrypted.ciphertext, encrypted.nonce,
            |bytes| Ok::<_, ()>(ed25519_dalek::Signer::sign(&signer, bytes).to_bytes()))
            .unwrap()
    }

    #[test]
    fn a_snapshot_adopts_the_last_writer_among_changes_no_other_includes() {
        let first = signed_change("aaaa", 1, RecordVersion::from_entries([("aaaa", 1)]), "2026-11-13T10:00:00Z",
            payload_json("blue", "slate"));
        let after = signed_change("bbbb", 1, RecordVersion::from_entries([("aaaa", 1), ("bbbb", 1)]), "2026-11-13T09:00:00Z",
            payload_json("red", "stone"));
        let concurrent = signed_change("cccc", 1, RecordVersion::from_entries([("cccc", 1)]), "2026-11-13T09:30:00Z",
            payload_json("teal", "ocean"));
        let unreadable = signed_change("dddd", 1, RecordVersion::from_entries([("dddd", 9)]), "2030-01-01T00:00:00Z",
            payload_json("Bad!", "ocean"));
        let operations = [&first, &after, &concurrent, &unreadable];
        let (chosen, accent, surface) = snapshot_choice(&operations, &[5; 32]).unwrap();
        assert_eq!((chosen.hash.as_str(), accent.as_str(), surface.as_str()), (concurrent.hash.as_str(), "teal", "ocean"),
            "the first change is included by another, so its later time does not count");
        assert!(snapshot_choice(&[&unreadable], &[5; 32]).is_none());

        let directory = std::env::temp_dir().join(format!("nuvori-appearance-{}", uuid::Uuid::new_v4()));
        let store = AppearanceStore::new(&directory);
        store.set_local_device("pc");
        store.save(&Stored {
            accent: "plum".to_owned(),
            surface: "plum".to_owned(),
            updated_at_utc: Some("2026-11-13T12:00:00Z".to_owned()),
            updated_by_device: None,
            pending_sync: true,
        }).unwrap();
        adopt_from_snapshot(&store, chosen, accent.clone(), surface.clone()).unwrap();
        assert_eq!(store.view(), View { accent: "plum".to_owned(), surface: "plum".to_owned(), pending_sync: true },
            "a later pending choice on this PC wins and stays pending");
        store.save(&Stored::default()).unwrap();
        adopt_from_snapshot(&store, chosen, accent, surface).unwrap();
        assert_eq!(store.view(), View { accent: "teal".to_owned(), surface: "ocean".to_owned(), pending_sync: false });
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn the_writer_signs_the_next_link_with_the_chosen_time_and_a_dominating_version() {
        let directory = std::env::temp_dir().join(format!("nuvori-appearance-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let identity_store = DeviceIdentityStore::new(directory.join("device-identity-v1.json"));
        let local = identity_store.get_or_create().unwrap();
        let mut db = Connection::open_in_memory().unwrap();
        ChangeStore::initialize(&db).unwrap();
        db.execute_batch("CREATE TABLE sync_group_state (vault_id TEXT NOT NULL PRIMARY KEY, content_key BLOB NOT NULL, transport_secret BLOB NOT NULL)").unwrap();
        db.execute("INSERT INTO sync_group_state VALUES ('vault-a', ?1, x'00')", [vec![5u8; 32]]).unwrap();
        // A merged record from earlier concurrent changes by other devices.
        db.execute("INSERT INTO vault_records VALUES ('appearance', 'vault', 'x', 3, '{\"counters\":{\"phone\":2,\"tablet\":1}}')", []).unwrap();

        write_change(&mut db, &identity_store, &local, "vault-a", "blue", "slate", "2026-11-13T10:00:00Z").unwrap();
        write_change(&mut db, &identity_store, &local, "vault-a", "teal", "ocean", "2026-11-13T11:00:00Z").unwrap();
        let rows: Vec<(i64, String, String, String, String, String)> = db
            .prepare("SELECT sequence, previous_hash, hash, record_version_json, occurred_at_utc, mutation_id FROM sync_operations ORDER BY sequence")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].0, rows[0].1.as_str()), (1, GENESIS_HASH));
        assert_eq!((rows[1].0, rows[1].1.as_str()), (2, rows[0].2.as_str()), "the next link of this device's chain");
        assert_eq!(rows[0].4, "2026-11-13T10:00:00Z", "the change carries the time the value was chosen");
        let version: RecordVersion = serde_json::from_str(&rows[1].3).unwrap();
        assert_eq!(version, RecordVersion::new([("phone".to_owned(), 2), ("tablet".to_owned(), 1), (local.device_id.clone(), 2)].into()));
        let record = ChangeStore::record(&db, ENTITY_TYPE, ENTITY_ID).unwrap().unwrap();
        assert_eq!((record.revision, record.record_version_json), (5, rows[1].3.clone()));
        let change = ChangeRecord::create("vault-a", &local.device_id, 2, "", &rows[1].5, ENTITY_TYPE, ENTITY_ID,
            ChangeKind::Upsert, 0, version, "", record.payload_ciphertext.clone(),
            db.query_row("SELECT payload_nonce FROM sync_operations WHERE sequence = 2", [], |row| row.get::<_, String>(0)).unwrap(), "");
        let plaintext = payload::decrypt(&[5; 32], &change).unwrap();
        assert_eq!(parse_payload(&serde_json::from_slice(&plaintext).unwrap()), Some(("teal".to_owned(), "ocean".to_owned())));
        let _ = std::fs::remove_dir_all(directory);
    }
}
