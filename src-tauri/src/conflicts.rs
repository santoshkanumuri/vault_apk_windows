//! Conflict review and resolution, mirroring Android `SyncConflictResolver`.
//!
//! A choice becomes a normal signed change by this device. Its record version merges both
//! conflicting versions (per-device maximum) and then counts this device once more, so every
//! peer sees it as newer than both sides and closes its own copy of the conflict, whatever order
//! the three changes arrive in.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    incoming_apply::{self, ApplyError},
    payload,
    photo_blobs::PhotoBlobs,
    protocol::RecordVersion,
    snapshot::SnapshotMember,
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncConflict {
    pub id: String,
    /// entry | note | folder | passkey | photo
    pub entity_type: &'static str,
    pub entity_id: String,
    /// Shown in the app only. Never log it.
    pub title: String,
    /// Unix milliseconds of the change Windows currently shows.
    pub local_updated_at: i64,
    /// Unix milliseconds of the other device's change.
    pub remote_updated_at: i64,
    pub remote_device: String,
    /// Which fields differ (labels only, never values), or which side deleted.
    pub summary: String,
}

#[derive(Debug, Error)]
pub enum ConflictError {
    #[error("This conflict has already been resolved.")]
    NotFound,
    #[error("An incoming passkey cannot replace a different credential with the same ID. Keep this device's passkey.")]
    PasskeyReplace,
    #[error("The other version needs its photo first. Sync again, then choose.")]
    PhotoPending,
    #[error("The other version refers to a folder or code that has not arrived yet. Sync again, then choose.")]
    DependencyPending,
    #[error("The conflict history is incomplete.")]
    MissingHistory,
    #[error("The conflict could not be resolved.")]
    Storage(#[from] rusqlite::Error),
    #[error("The conflict could not be resolved.")]
    Apply(ApplyError),
    #[error("The conflict could not be resolved.")]
    Data,
}

impl From<ApplyError> for ConflictError {
    fn from(error: ApplyError) -> Self {
        match error {
            ApplyError::MissingPhotoBlob => Self::PhotoPending,
            ApplyError::MissingPhotoDependency
            | ApplyError::MissingEntryDependency
            | ApplyError::MissingGroupDependency => Self::DependencyPending,
            other => Self::Apply(other),
        }
    }
}

struct OpenConflict {
    id: String,
    entity_type: String,
    entity_id: String,
    remote_hash: String,
    remote_version: RecordVersion,
}

const OPERATION_COLUMNS: &str = "format_version, vault_id, device_id, sequence, previous_hash, mutation_id, entity_type, entity_id, kind, base_revision, record_version_json, occurred_at_utc, payload_ciphertext, payload_nonce, device_signature, hash";

fn operations_for(db: &Connection, entity_type: &str, entity_id: &str) -> Result<Vec<ChangeRecord>, ConflictError> {
    let mut statement = db.prepare(&format!(
        "SELECT {OPERATION_COLUMNS} FROM sync_operations WHERE entity_type = ?1 AND entity_id = ?2 ORDER BY device_id, sequence"
    ))?;
    let rows = statement.query_map(params![entity_type, entity_id], |row| {
        let kind: String = row.get(8)?;
        let version: String = row.get(10)?;
        let sequence: i64 = row.get(3)?;
        let base: i64 = row.get(9)?;
        Ok((
            ChangeRecord {
                format_version: row.get(0)?,
                vault_id: row.get(1)?,
                device_id: row.get(2)?,
                sequence: sequence as u64,
                previous_hash: row.get(4)?,
                mutation_id: row.get(5)?,
                entity_type: row.get(6)?,
                entity_id: row.get(7)?,
                kind: if kind == "delete" { ChangeKind::Delete } else { ChangeKind::Upsert },
                base_revision: base as u64,
                record_version: RecordVersion::default(),
                occurred_at_utc: row.get(11)?,
                payload_ciphertext: row.get(12)?,
                payload_nonce: row.get(13)?,
                device_signature: row.get(14)?,
                hash: row.get(15)?,
            },
            version,
        ))
    })?;
    rows.map(|row| {
        let (mut operation, version) = row?;
        operation.record_version = serde_json::from_str(&version).map_err(|_| ConflictError::Data)?;
        Ok(operation)
    })
    .collect()
}

fn open_conflicts(db: &Connection, id: Option<&str>) -> Result<Vec<OpenConflict>, ConflictError> {
    let mut statement = db.prepare(
        "SELECT conflict_id, entity_type, entity_id, remote_change_hash, remote_version_json
         FROM sync_conflicts WHERE resolved_at_utc = '' AND (?1 IS NULL OR conflict_id = ?1)
         ORDER BY detected_at_utc, conflict_id",
    )?;
    let rows = statement.query_map([id], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get::<_, String>(4)?))
    })?;
    rows.map(|row| {
        let (id, entity_type, entity_id, remote_hash, version) = row?;
        Ok(OpenConflict {
            id,
            entity_type,
            entity_id,
            remote_hash,
            remote_version: serde_json::from_str(&version).map_err(|_| ConflictError::Data)?,
        })
    })
    .collect()
}

/// The version and revision Windows currently holds for a record (live or deleted).
fn current_state(db: &Connection, entity_type: &str, entity_id: &str) -> Result<(RecordVersion, Option<u64>), ConflictError> {
    let record: Option<(String, i64)> = db
        .query_row(
            "SELECT record_version_json, revision FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
            params![entity_type, entity_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((version, revision)) = record {
        return Ok((serde_json::from_str(&version).map_err(|_| ConflictError::Data)?, Some(revision as u64)));
    }
    let tombstone: Option<String> = db
        .query_row(
            "SELECT record_version_json FROM sync_tombstones WHERE entity_type = ?1 AND entity_id = ?2",
            params![entity_type, entity_id],
            |row| row.get(0),
        )
        .optional()?;
    let version = tombstone.ok_or(ConflictError::MissingHistory)?;
    Ok((serde_json::from_str(&version).map_err(|_| ConflictError::Data)?, None))
}

struct Sides {
    local: ChangeRecord,
    remote: ChangeRecord,
    local_version: RecordVersion,
    revision: u64,
}

fn sides(db: &Connection, conflict: &OpenConflict) -> Result<Sides, ConflictError> {
    let operations = operations_for(db, &conflict.entity_type, &conflict.entity_id)?;
    let (local_version, revision) = current_state(db, &conflict.entity_type, &conflict.entity_id)?;
    let local = operations
        .iter()
        .rev()
        .find(|operation| operation.record_version == local_version)
        .cloned()
        .ok_or(ConflictError::MissingHistory)?;
    let remote = operations
        .iter()
        .find(|operation| operation.hash == conflict.remote_hash)
        .cloned()
        .ok_or(ConflictError::MissingHistory)?;
    // A deleted record has no revision row; its delete change was based on the last revision.
    let revision = revision.unwrap_or(local.base_revision + 1);
    Ok(Sides { local, remote, local_version, revision })
}

fn decrypt(content_key: &[u8], operation: &ChangeRecord) -> Result<Value, ConflictError> {
    let plaintext = Zeroizing::new(payload::decrypt(content_key, operation).map_err(|_| ConflictError::Data)?);
    serde_json::from_slice(&plaintext).map_err(|_| ConflictError::Data)
}

fn millis(rfc3339: &str) -> i64 {
    OffsetDateTime::parse(rfc3339, &Rfc3339)
        .map(|time| (time.unix_timestamp_nanos() / 1_000_000) as i64)
        .unwrap_or(0)
}

fn device_label(db: &Connection, device_id: &str) -> String {
    let short: String = device_id.chars().take(8).collect();
    let member: Option<String> = db
        .query_row("SELECT member_json FROM sync_memberships WHERE device_id = ?1", [device_id], |row| row.get(0))
        .optional()
        .ok()
        .flatten();
    member
        .and_then(|json| serde_json::from_str::<SnapshotMember>(&json).ok())
        .map(|member| member.display_name)
        .filter(|name| !name.trim().is_empty())
        .map_or(short.clone(), |name| format!("{name} · {short}"))
}

const ENTRY_LABELS: [(&str, &str); 20] = [
    ("title", "Title"), ("primaryValue", "Primary value"), ("secondaryValue", "Secret value"),
    ("tertiaryValue", "Third value"), ("fourthValue", "Fourth value"), ("notes", "Notes"),
    ("tags", "Tags"), ("favorite", "Favorite"), ("sortOrder", "Order"), ("color", "Color"),
    ("network", "Network"), ("linkedAuthenticatorId", "Linked authenticator"),
    ("linkedApps", "Linked apps"), ("autofillSignatures", "Autofill signatures"),
    ("autofillOrigins", "Autofill origins"), ("cardKind", "Card kind"),
    ("totpAlgorithm", "Code algorithm"), ("totpDigits", "Code digits"),
    ("totpPeriod", "Code period"), ("type", "Type"),
];

/// Field labels that differ. Values are never included.
fn summary(entity_type: &str, local: Option<&Value>, remote: Option<&Value>) -> String {
    let (Some(local), Some(remote)) = (local, remote) else {
        return if local.is_none() { "Deleted on this PC, edited on the other device" } else { "Edited on this PC, deleted on the other device" }.to_owned();
    };
    let mut different: Vec<&str> = Vec::new();
    match entity_type {
        "entry" => {
            let entry_type = local["entry"]["type"].as_str().unwrap_or_default();
            for (field, label) in ENTRY_LABELS {
                if local["entry"][field] != remote["entry"][field] {
                    different.push(match (field, entry_type) {
                        ("primaryValue", "CARD") => "Card number",
                        ("primaryValue", "PASSWORD") => "Username",
                        ("secondaryValue", "PASSWORD") => "Password",
                        ("secondaryValue", "QUESTION") => "Answer",
                        ("secondaryValue", "AUTHENTICATOR") => "Code setup key",
                        _ => label,
                    });
                }
            }
            if local["groupIds"] != remote["groupIds"] {
                different.push("Folders");
            }
        }
        "group" => {
            for (field, label) in [("name", "Name"), ("notes", "Notes"), ("folderType", "Folder type")] {
                if local["group"][field] != remote["group"][field] {
                    different.push(label);
                }
            }
        }
        "photo" => different.push("Image version"),
        "photo_cover" => different.push("Cover photo"),
        "passkey" => different.push("Passkey"),
        _ => {}
    }
    if different.is_empty() {
        "Edited on both devices".to_owned()
    } else {
        format!("Different: {}", different.join(", "))
    }
}

fn title_of(entity_type: &str, value: &Value) -> String {
    match entity_type {
        "entry" => value["entry"]["title"].as_str(),
        "group" => value["group"]["name"].as_str(),
        "passkey" => value["passkey"]["rpId"].as_str(),
        _ => None,
    }
    .unwrap_or("Photo")
    .to_owned()
}

pub fn list(db: &Connection, content_key: &[u8]) -> Result<Vec<SyncConflict>, ConflictError> {
    let mut result = Vec::new();
    for conflict in open_conflicts(db, None)? {
        let Ok(sides) = sides(db, &conflict) else { continue };
        let local = (sides.local.kind == ChangeKind::Upsert).then(|| decrypt(content_key, &sides.local)).transpose()?;
        let remote = (sides.remote.kind == ChangeKind::Upsert).then(|| decrypt(content_key, &sides.remote)).transpose()?;
        let shown = local.as_ref().or(remote.as_ref());
        let entity_type = match conflict.entity_type.as_str() {
            "entry" if shown.is_some_and(|value| value["entry"]["type"] == "NOTE") => "note",
            "entry" => "entry",
            "group" => "folder",
            "passkey" => "passkey",
            _ => "photo",
        };
        result.push(SyncConflict {
            id: conflict.id.clone(),
            entity_type,
            entity_id: conflict.entity_id.clone(),
            title: shown.map_or_else(|| "Deleted item".to_owned(), |value| title_of(&conflict.entity_type, value)),
            local_updated_at: millis(&sides.local.occurred_at_utc),
            remote_updated_at: millis(&sides.remote.occurred_at_utc),
            remote_device: device_label(db, &sides.remote.device_id),
            summary: summary(&conflict.entity_type, local.as_ref(), remote.as_ref()),
        });
    }
    Ok(result)
}

/// Records the chosen side as a signed change by `device_id` and applies it locally.
pub fn resolve<E>(
    db: &mut Connection,
    id: &str,
    keep_remote: bool,
    content_key: &[u8],
    device_id: &str,
    blobs: Option<&PhotoBlobs>,
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64], E>,
) -> Result<ChangeRecord, ConflictError> {
    let conflict = open_conflicts(db, Some(id))?.into_iter().next().ok_or(ConflictError::NotFound)?;
    if keep_remote && conflict.entity_type == "passkey" {
        return Err(ConflictError::PasskeyReplace);
    }
    let sides = sides(db, &conflict)?;
    let selected = if keep_remote { &sides.remote } else { &sides.local };
    let mut counters = sides.local_version.counters().clone();
    for (device, counter) in conflict.remote_version.counters() {
        let entry = counters.entry(device.clone()).or_default();
        *entry = (*entry).max(*counter);
    }
    let own = counters.entry(device_id.to_owned()).or_default();
    *own = own.checked_add(1).ok_or(ConflictError::Data)?;
    let plaintext = Zeroizing::new(payload::decrypt(content_key, selected).map_err(|_| ConflictError::Data)?);
    let payload_json: Value = serde_json::from_slice(&plaintext).map_err(|_| ConflictError::Data)?;
    let mutation_id = uuid::Uuid::new_v4().to_string();
    let encrypted = payload::encrypt(content_key, &selected.entity_type, &selected.vault_id, &mutation_id, &selected.entity_id, &plaintext)
        .map_err(|_| ConflictError::Data)?;
    let head: Option<(i64, String)> = db
        .query_row(
            "SELECT sequence, hash FROM sync_device_heads WHERE vault_id = ?1 AND device_id = ?2",
            params![selected.vault_id, device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (sequence, previous) = head.map_or((1, GENESIS_HASH.to_owned()), |(sequence, hash)| (sequence as u64 + 1, hash));
    let occurred = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| ConflictError::Data)?;
    let operation = ChangeRecord::create_signed_with(
        &selected.vault_id, device_id, sequence, previous, mutation_id, &selected.entity_type,
        &selected.entity_id, selected.kind.clone(), sides.revision, RecordVersion::new(counters),
        occurred, encrypted.ciphertext, encrypted.nonce, sign,
    )
    .map_err(|_| ConflictError::Data)?;
    let transaction = db.transaction()?;
    transaction.execute(
        "INSERT INTO sync_operations (mutation_id, format_version, vault_id, device_id, sequence, previous_hash,
             entity_type, entity_id, kind, base_revision, record_version_json, occurred_at_utc,
             payload_ciphertext, payload_nonce, device_signature, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            operation.mutation_id, i64::from(operation.format_version), operation.vault_id, operation.device_id,
            operation.sequence as i64, operation.previous_hash, operation.entity_type, operation.entity_id,
            if operation.kind == ChangeKind::Upsert { "upsert" } else { "delete" },
            operation.base_revision as i64,
            serde_json::to_string(&operation.record_version).map_err(|_| ConflictError::Data)?,
            operation.occurred_at_utc, operation.payload_ciphertext, operation.payload_nonce,
            operation.device_signature, operation.hash,
        ],
    )?;
    transaction.execute(
        "INSERT INTO sync_device_heads (vault_id, device_id, sequence, hash) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(vault_id, device_id) DO UPDATE SET sequence = excluded.sequence, hash = excluded.hash",
        params![operation.vault_id, operation.device_id, operation.sequence as i64, operation.hash],
    )?;
    let payload_json = incoming_apply::resolve_links(&transaction, &operation, &payload_json)?;
    incoming_apply::materialize_checked(&transaction, &operation, &payload_json, content_key, blobs)?;
    let open: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sync_conflicts WHERE conflict_id = ?1 AND resolved_at_utc = '')",
        [id],
        |row| row.get(0),
    )?;
    if open {
        return Err(ConflictError::Data);
    }
    transaction.commit()?;
    Ok(operation)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;
    use crate::{change_store::ChangeStore, incoming_apply::{ApplyOutcome, IncomingApply}};

    const KEY: [u8; 32] = [4; 32];

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        ChangeStore::initialize(&db).unwrap();
        db.execute_batch(
            "CREATE TABLE local_entries (id TEXT PRIMARY KEY, type TEXT NOT NULL, data_json TEXT NOT NULL, updated_at INTEGER NOT NULL);
             CREATE TABLE local_notes (id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
             CREATE TABLE local_note_details (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
             CREATE TABLE local_groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, notes TEXT NOT NULL, folder_type TEXT NOT NULL);
             CREATE TABLE entry_groups (entry_id TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY (entry_id, group_id));
             CREATE TABLE local_passkeys (id TEXT PRIMARY KEY, rp_id TEXT NOT NULL, data_json TEXT NOT NULL);
             CREATE TABLE local_entry_photos (id TEXT PRIMARY KEY, entry_id TEXT NOT NULL, mime_type TEXT NOT NULL,
                 data BLOB NOT NULL, is_cover INTEGER NOT NULL DEFAULT 0, added_at INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE sync_memberships (vault_id TEXT NOT NULL, device_id TEXT NOT NULL, member_json TEXT NOT NULL, PRIMARY KEY (vault_id, device_id));",
        )
        .unwrap();
        db
    }

    fn entry(title: &str, password: &str) -> Value {
        json!({"entry": {
            "id": "entry-a", "type": "PASSWORD", "title": title, "primaryValue": "user",
            "secondaryValue": password, "tertiaryValue": "", "fourthValue": "", "cardKind": "CREDIT",
            "network": "", "totpAlgorithm": "SHA1", "totpDigits": 6, "totpPeriod": 30, "linkedApps": "",
            "autofillSignatures": "", "autofillOrigins": "", "linkedAuthenticatorId": "", "notes": "",
            "color": 1, "tags": "", "favorite": false, "lastOpenedAt": 0, "sortOrder": 1,
            "createdAt": 1, "updatedAt": 2
        }, "groupIds": []})
    }

    #[allow(clippy::too_many_arguments)]
    fn change(seed: u8, device: &str, sequence: u64, previous: &str, version: RecordVersion, base: u64, body: Value, at: &str) -> ChangeRecord {
        let mutation = format!("{device}-{sequence}");
        let encrypted = payload::encrypt(&KEY, "entry", "vault-a", &mutation, "entry-a", &serde_json::to_vec(&body).unwrap()).unwrap();
        let signer = SigningKey::from_bytes(&[seed; 32]);
        ChangeRecord::create_signed_with("vault-a", device, sequence, previous, mutation, "entry", "entry-a",
            ChangeKind::Upsert, base, version, at, encrypted.ciphertext, encrypted.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()))
        .unwrap()
    }

    fn receive(db: &mut Connection, operation: &ChangeRecord) -> ApplyOutcome {
        db.execute(
            "INSERT INTO sync_operations (mutation_id, format_version, vault_id, device_id, sequence, previous_hash,
                 entity_type, entity_id, kind, base_revision, record_version_json, occurred_at_utc,
                 payload_ciphertext, payload_nonce, device_signature, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![operation.mutation_id, i64::from(operation.format_version), operation.vault_id, operation.device_id,
                operation.sequence as i64, operation.previous_hash, operation.entity_type, operation.entity_id, "upsert",
                operation.base_revision as i64, serde_json::to_string(&operation.record_version).unwrap(),
                operation.occurred_at_utc, operation.payload_ciphertext, operation.payload_nonce,
                operation.device_signature, operation.hash],
        )
        .unwrap();
        db.execute(
            "INSERT INTO sync_device_heads (vault_id, device_id, sequence, hash) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(vault_id, device_id) DO UPDATE SET sequence = excluded.sequence, hash = excluded.hash",
            params![operation.vault_id, operation.device_id, operation.sequence as i64, operation.hash],
        )
        .unwrap();
        IncomingApply::apply(db, operation, &KEY).unwrap()
    }

    fn title(db: &Connection) -> String {
        let json: String = db.query_row("SELECT data_json FROM local_entries WHERE id = 'entry-a'", [], |row| row.get(0)).unwrap();
        serde_json::from_str::<Value>(&json).unwrap()["title"].as_str().unwrap().to_owned()
    }

    fn open_count(db: &Connection) -> i64 {
        db.query_row("SELECT count(*) FROM sync_conflicts WHERE resolved_at_utc = ''", [], |row| row.get(0)).unwrap()
    }

    #[test]
    fn resolution_converges_whatever_order_changes_arrive_in() {
        let base = change(42, "phone", 1, GENESIS_HASH, RecordVersion::from_entries([("phone", 1)]), 0, entry("Base", "one"), "2026-10-01T10:00:00Z");
        let windows = change(41, "windows", 1, GENESIS_HASH, RecordVersion::from_entries([("phone", 1), ("windows", 1)]), 1, entry("Windows name", "two"), "2026-10-01T11:00:00Z");
        let phone = change(42, "phone", 2, &base.hash, RecordVersion::from_entries([("phone", 2)]), 1, entry("Phone name", "three"), "2026-10-01T12:00:00Z");

        // Windows: its own edit is current when the phone's edit arrives.
        let mut pc = database();
        receive(&mut pc, &base);
        receive(&mut pc, &windows);
        assert_eq!(receive(&mut pc, &phone), ApplyOutcome::Conflict);
        let listed = list(&pc, &KEY).unwrap();
        assert_eq!(listed.len(), 1);
        let conflict = &listed[0];
        assert_eq!((conflict.entity_type, conflict.title.as_str()), ("entry", "Windows name"));
        assert_eq!(conflict.summary, "Different: Title, Password");
        assert!(!conflict.summary.contains("three") && !conflict.summary.contains("two"));
        assert_eq!(conflict.remote_device, "phone");
        assert_eq!(conflict.remote_updated_at - conflict.local_updated_at, 3_600_000);
        let signer = SigningKey::from_bytes(&[41; 32]);
        let resolution = resolve(&mut pc, &conflict.id, true, &KEY, "windows", None, |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes())).unwrap();
        assert_eq!(resolution.record_version, RecordVersion::from_entries([("phone", 2), ("windows", 2)]));
        assert_eq!((title(&pc), open_count(&pc)), ("Phone name".to_owned(), 0));
        assert!(matches!(resolve(&mut pc, &conflict.id, true, &KEY, "windows", None, |_| Ok::<_, ()>([0; 64])), Err(ConflictError::NotFound)));

        // Phone and two other devices receive the same three changes in different orders.
        for order in [[&base, &phone, &windows, &resolution], [&base, &windows, &phone, &resolution], [&base, &windows, &resolution, &phone]] {
            let mut device = database();
            for operation in order {
                receive(&mut device, operation);
            }
            assert_eq!((title(&device), open_count(&device)), ("Phone name".to_owned(), 0));
        }
    }

    #[test]
    fn keeping_this_side_also_wins_everywhere() {
        let base = change(42, "phone", 1, GENESIS_HASH, RecordVersion::from_entries([("phone", 1)]), 0, entry("Base", "one"), "2026-10-01T10:00:00Z");
        let windows = change(41, "windows", 1, GENESIS_HASH, RecordVersion::from_entries([("phone", 1), ("windows", 1)]), 1, entry("Windows name", "two"), "2026-10-01T11:00:00Z");
        let phone = change(42, "phone", 2, &base.hash, RecordVersion::from_entries([("phone", 2)]), 1, entry("Phone name", "three"), "2026-10-01T12:00:00Z");
        let mut pc = database();
        for operation in [&base, &windows, &phone] {
            receive(&mut pc, operation);
        }
        let id = list(&pc, &KEY).unwrap()[0].id.clone();
        let signer = SigningKey::from_bytes(&[41; 32]);
        let resolution = resolve(&mut pc, &id, false, &KEY, "windows", None, |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes())).unwrap();
        assert_eq!(title(&pc), "Windows name");
        let mut phone_db = database();
        for operation in [&base, &phone, &windows, &resolution] {
            receive(&mut phone_db, operation);
        }
        assert_eq!((title(&phone_db), open_count(&phone_db)), ("Windows name".to_owned(), 0));
    }
}
