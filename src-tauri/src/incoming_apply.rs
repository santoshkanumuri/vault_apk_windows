//! Applies persisted Android-compatible entry, group, and passkey operations to the Windows materialized view.
//! Photos follow Android `IncomingEntryChangeApplier`: an upsert applies once its encrypted blob
//! has arrived and its entry exists, a cover change once its photo exists, and an applied change
//! that includes both sides of an open conflict resolves it.
//!
//! The caller supplies a content key for `payload::decrypt`; transport authentication and
//! membership authorization are intentionally handled before this module is called.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::Value;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroize;

use crate::{
    passkeys::{PasskeyError, VaultPasskey},
    photo_blobs::{self, PhotoBlobs},
    payload::{self, PayloadError},
    protocol::{RecordVersion, VersionRelation},
    sync::{ChangeKind, ChangeRecord},
};

const APPLIED_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS sync_applied_operations (
        mutation_id TEXT NOT NULL PRIMARY KEY
            REFERENCES sync_operations(mutation_id),
        change_hash TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (outcome IN ('applied', 'conflict', 'obsolete')),
        applied_at_utc TEXT NOT NULL
    );";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    Conflict,
    Obsolete,
    Replay,
}

pub struct IncomingApply;

impl IncomingApply {
    /// Decrypts, validates, materializes, and marks one persisted operation atomically.
    /// Without a blob store, photo uploads are left waiting.
    pub fn apply(
        connection: &mut Connection,
        operation: &ChangeRecord,
        content_key: &[u8],
    ) -> Result<ApplyOutcome, ApplyError> {
        Self::apply_with_blobs(connection, operation, content_key, None)
    }

    pub fn apply_with_blobs(
        connection: &mut Connection,
        operation: &ChangeRecord,
        content_key: &[u8],
        blobs: Option<&PhotoBlobs>,
    ) -> Result<ApplyOutcome, ApplyError> {
        let supported = match operation.entity_type.as_str() {
            "entry" | "group" | "passkey" | "photo_cover" => true,
            "device_name" => operation.kind == ChangeKind::Upsert,
            "photo" => operation.kind == ChangeKind::Delete || blobs.is_some(),
            _ => false,
        };
        if !supported {
            return Err(ApplyError::UnsupportedEntity);
        }
        if content_key.len() != 32 {
            return Err(ApplyError::InvalidContentKey);
        }

        let mut plaintext = payload::decrypt(content_key, operation)?;
        let payload =
            serde_json::from_slice::<Value>(&plaintext).map_err(|_| ApplyError::InvalidPayload);
        plaintext.zeroize();
        let payload = payload?;
        validate_payload(operation, &payload)?;

        connection.execute_batch(APPLIED_SCHEMA)?;
        let transaction = connection.transaction()?;

        let stored_hash: Option<String> = transaction
            .query_row(
                "SELECT hash FROM sync_operations WHERE mutation_id = ?1",
                [&operation.mutation_id],
                |row| row.get(0),
            )
            .optional()?;
        if stored_hash.as_deref() != Some(operation.hash.as_str()) {
            return Err(ApplyError::OperationNotPersisted);
        }
        let marker: Option<String> = transaction
            .query_row(
                "SELECT change_hash FROM sync_applied_operations WHERE mutation_id = ?1",
                [&operation.mutation_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(marker_hash) = marker {
            if marker_hash != operation.hash {
                return Err(ApplyError::MutationIdReused);
            }
            return Ok(ApplyOutcome::Replay);
        }

        let payload = resolve_links(&transaction, operation, &payload)?;

        let outcome = match current_state(&transaction, operation)? {
            None => {
                materialize_checked(&transaction, operation, &payload, content_key, blobs)?;
                ApplyOutcome::Applied
            }
            Some(state) => match operation.record_version.relation_to(&state.version) {
                VersionRelation::After => {
                    materialize_checked(&transaction, operation, &payload, content_key, blobs)?;
                    ApplyOutcome::Applied
                }
                VersionRelation::Concurrent => {
                    let local_hash = state.change_hash.ok_or(ApplyError::CurrentChangeNotFound)?;
                    transaction.execute(
                        "INSERT INTO sync_conflicts (
                             conflict_id, entity_type, entity_id, local_change_hash,
                             remote_change_hash, local_version_json, remote_version_json,
                             detected_at_utc
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            uuid::Uuid::new_v4().to_string(),
                            operation.entity_type,
                            operation.entity_id,
                            local_hash,
                            operation.hash,
                            serde_json::to_string(&state.version)?,
                            serde_json::to_string(&operation.record_version)?,
                            now_utc()?,
                        ],
                    )?;
                    ApplyOutcome::Conflict
                }
                VersionRelation::Before | VersionRelation::Equal => ApplyOutcome::Obsolete,
            },
        };

        transaction.execute(
            "INSERT INTO sync_applied_operations (mutation_id, change_hash, outcome, applied_at_utc)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                operation.mutation_id,
                operation.hash,
                match outcome {
                    ApplyOutcome::Applied => "applied",
                    ApplyOutcome::Conflict => "conflict",
                    ApplyOutcome::Obsolete => "obsolete",
                    ApplyOutcome::Replay => unreachable!(),
                },
                now_utc()?,
            ],
        )?;
        transaction.commit()?;
        Ok(outcome)
    }
}

/// Materializes an operation that wins, then closes every open conflict for the record whose
/// two versions it includes (Android resolves conflicts the same way).
pub(crate) fn materialize_checked(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
    payload: &Value,
    content_key: &[u8],
    blobs: Option<&PhotoBlobs>,
) -> Result<(), ApplyError> {
    validate_payload(operation, payload)?;
    // Android records only the version when the image or cover has nothing left to attach to.
    let mut record_only = false;
    let mut photo = None;
    if operation.kind == ChangeKind::Upsert && operation.entity_type == "photo" {
        let details = &payload["photo"];
        let entry_id = details["entryId"].as_str().unwrap_or_default();
        if entry_deleted(transaction, entry_id)? {
            record_only = true;
        } else {
            let (hash, size) = (
                details["blobHash"].as_str().ok_or(ApplyError::InvalidPayload)?,
                details["blobSize"].as_u64().ok_or(ApplyError::InvalidPayload)?,
            );
            let blobs = blobs.ok_or(ApplyError::UnsupportedEntity)?;
            if !blobs.has(hash, size) {
                return Err(ApplyError::MissingPhotoBlob);
            }
            if !entry_exists(transaction, entry_id)? {
                return Err(ApplyError::MissingPhotoDependency);
            }
            photo = Some(
                blobs
                    .decrypt(content_key, &operation.vault_id, &operation.entity_id, hash, size)
                    .map_err(|_| ApplyError::InvalidPayload)?,
            );
        }
    }
    if operation.kind == ChangeKind::Upsert && operation.entity_type == "photo_cover" {
        let cover = payload["coverPhotoId"].as_str().unwrap_or_default();
        let owner: Option<String> = transaction
            .query_row("SELECT entry_id FROM local_entry_photos WHERE id = ?1", [cover], |row| row.get(0))
            .optional()?;
        match owner {
            // A cover for a deleted entry or a deleted photo has nothing left to mark.
            None if entry_deleted(transaction, &operation.entity_id)? || tombstoned(transaction, "photo", cover)? => {
                record_only = true;
            }
            None => return Err(ApplyError::MissingPhotoDependency),
            Some(owner) if owner != operation.entity_id => return Err(ApplyError::InvalidPayload),
            Some(_) => {}
        }
    }
    materialize(transaction, operation, payload, photo.as_deref().map(Vec::as_slice), record_only)?;
    resolve_dominated_conflicts(transaction, operation)
}

fn tombstoned(connection: &Connection, entity_type: &str, id: &str) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sync_tombstones WHERE entity_type = ?1 AND entity_id = ?2)",
        params![entity_type, id],
        |row| row.get(0),
    )
}

/// The entry is absent here and its delete is known, so it is not merely late.
pub(crate) fn entry_deleted(connection: &Connection, id: &str) -> rusqlite::Result<bool> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_entries WHERE id = ?1)
             OR EXISTS(SELECT 1 FROM local_notes WHERE id = ?1)",
        [id],
        |row| row.get(0),
    )?;
    Ok(!exists && tombstoned(connection, "entry", id)?)
}

fn entry_exists(transaction: &Transaction<'_>, id: &str) -> Result<bool, ApplyError> {
    Ok(transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_entries WHERE id = ?1)
             OR EXISTS(SELECT 1 FROM local_notes WHERE id = ?1)",
        [id],
        |row| row.get(0),
    )?)
}

fn resolve_dominated_conflicts(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
) -> Result<(), ApplyError> {
    let open: Vec<(String, String, String)> = transaction
        .prepare(
            "SELECT conflict_id, local_version_json, remote_version_json FROM sync_conflicts
             WHERE entity_type = ?1 AND entity_id = ?2 AND resolved_at_utc = ''",
        )?
        .query_map(params![operation.entity_type, operation.entity_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<Result<_, _>>()?;
    for (id, local, remote) in open {
        let dominates = [local, remote].iter().all(|json| {
            serde_json::from_str::<RecordVersion>(json).is_ok_and(|version| {
                matches!(
                    operation.record_version.relation_to(&version),
                    VersionRelation::After | VersionRelation::Equal
                )
            })
        });
        if dominates {
            transaction.execute(
                "UPDATE sync_conflicts SET resolved_at_utc = ?2 WHERE conflict_id = ?1",
                params![id, now_utc()?],
            )?;
        }
    }
    Ok(())
}

struct CurrentState {
    version: RecordVersion,
    change_hash: Option<String>,
}

fn current_state(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
) -> Result<Option<CurrentState>, ApplyError> {
    let current: Option<(String, String)> = transaction
        .query_row(
            "SELECT record_version_json, payload_ciphertext FROM vault_records
             WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let tombstone: Option<(String, String)> = transaction
        .query_row(
            "SELECT record_version_json, change_hash FROM sync_tombstones
             WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    match (current, tombstone) {
        (Some(_), Some(_)) => Err(ApplyError::CorruptMaterializedState),
        (Some((version_json, payload_ciphertext)), None) => {
            let version: RecordVersion = serde_json::from_str(&version_json)?;
            let change_hash: Option<String> = transaction
                .query_row(
                    "SELECT hash FROM sync_operations
                     WHERE entity_type = ?1 AND entity_id = ?2
                       AND record_version_json = ?3 AND payload_ciphertext = ?4
                     ORDER BY sequence DESC LIMIT 1",
                    params![
                        operation.entity_type,
                        operation.entity_id,
                        version_json,
                        payload_ciphertext
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(Some(CurrentState {
                version,
                change_hash,
            }))
        }
        (None, Some((version_json, change_hash))) => Ok(Some(CurrentState {
            version: serde_json::from_str(&version_json)?,
            change_hash: Some(change_hash),
        })),
        (None, None) => Ok(None),
    }
}

/// Fits an incoming entry's links to this device's records, as Android `EntryLinkRules` does.
/// A link to a folder or code whose delete is known is dropped, a folder of another item type is
/// dropped, and one folder of the entry's type is kept. Only a link that may still arrive makes
/// the change wait. Returns the payload to materialize; other changes pass through unchanged.
pub(crate) fn resolve_links(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
    payload: &Value,
) -> Result<Value, ApplyError> {
    if operation.kind != ChangeKind::Upsert || operation.entity_type != "entry" {
        return Ok(payload.clone());
    }
    let entry_type = payload["entry"]["type"]
        .as_str()
        .ok_or(ApplyError::InvalidPayload)?;
    let mut resolved = payload.clone();
    let linked_id = payload["entry"]["linkedAuthenticatorId"].as_str().unwrap_or_default();
    if !linked_id.is_empty() {
        let keep = if entry_type != "PASSWORD" || linked_id == operation.entity_id {
            false
        } else {
            let linked_type: Option<String> = transaction
                .query_row("SELECT type FROM local_entries WHERE id = ?1", [linked_id], |row| row.get(0))
                .optional()?;
            match linked_type {
                Some(linked_type) => linked_type == "AUTHENTICATOR",
                // A note with that ID, or a known delete: the code will not arrive.
                None if entry_exists(transaction, linked_id)? || tombstoned(transaction, "entry", linked_id)? => false,
                None => return Err(ApplyError::MissingEntryDependency),
            }
        };
        if !keep {
            resolved["entry"]["linkedAuthenticatorId"] = Value::String(String::new());
        }
    }
    let mut groups: Vec<&str> = Vec::new();
    let mut folder: Option<&str> = None;
    for group_id in payload["groupIds"].as_array().ok_or(ApplyError::InvalidPayload)? {
        let group_id = group_id.as_str().ok_or(ApplyError::InvalidPayload)?;
        let folder_type: Option<String> = transaction
            .query_row("SELECT folder_type FROM local_groups WHERE id = ?1", [group_id], |row| row.get(0))
            .optional()?;
        match folder_type {
            None if tombstoned(transaction, "group", group_id)? => {}
            None => return Err(ApplyError::MissingGroupDependency),
            Some(folder_type) if folder_type.is_empty() => groups.push(group_id),
            Some(folder_type) if folder_type == entry_type => {
                folder = Some(folder.map_or(group_id, |known| known.min(group_id)));
            }
            Some(_) => {}
        }
    }
    groups.extend(folder);
    resolved["groupIds"] = Value::Array(groups.into_iter().map(|id| Value::String(id.to_owned())).collect());
    Ok(resolved)
}

fn validate_payload(operation: &ChangeRecord, payload: &Value) -> Result<(), ApplyError> {
    match operation.kind {
        ChangeKind::Upsert => {
            if operation.entity_type == "device_name" {
                // Android LocalDeviceNameChangeWriter: a device only names itself.
                let name = payload.get("name").and_then(Value::as_str).unwrap_or_default();
                let valid = operation.entity_id == operation.device_id
                    && !name.trim().is_empty()
                    && name.chars().count() <= 40
                    && !name.chars().any(char::is_control);
                return if valid { Ok(()) } else { Err(ApplyError::InvalidPayload) };
            }
            if operation.entity_type == "photo" {
                let photo = payload.get("photo").and_then(Value::as_object).ok_or(ApplyError::InvalidPayload)?;
                let text = |name: &str| photo.get(name).and_then(Value::as_str);
                let valid = text("id") == Some(operation.entity_id.as_str())
                    && text("entryId").is_some_and(|id| !id.is_empty() && id.len() <= 128)
                    && photo.get("isCover").and_then(Value::as_bool).is_some()
                    && photo.get("addedAt").and_then(Value::as_i64).is_some()
                    && text("blobHash").is_some_and(photo_blobs::valid_hash)
                    && photo.get("blobSize").and_then(Value::as_u64).is_some_and(photo_blobs::valid_size);
                return if valid { Ok(()) } else { Err(ApplyError::InvalidPayload) };
            }
            if operation.entity_type == "photo_cover" {
                let cover = payload
                    .get("coverPhotoId")
                    .and_then(Value::as_str)
                    .ok_or(ApplyError::InvalidPayload)?;
                if cover.is_empty()
                    || cover.len() > 128
                    || !cover.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                {
                    return Err(ApplyError::InvalidPayload);
                }
                return Ok(());
            }
            if operation.entity_type == "passkey" {
                let passkey: VaultPasskey = serde_json::from_value(
                    payload
                        .get("passkey")
                        .cloned()
                        .ok_or(ApplyError::InvalidPayload)?,
                )?;
                if passkey.id != operation.entity_id {
                    return Err(ApplyError::InvalidPayload);
                }
                passkey.validate()?;
                return Ok(());
            }
            if operation.entity_type == "group" {
                let group = payload
                    .get("group")
                    .and_then(Value::as_object)
                    .ok_or(ApplyError::InvalidPayload)?;
                let id = group
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or(ApplyError::InvalidPayload)?;
                let name = group
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(ApplyError::InvalidPayload)?;
                let notes = group
                    .get("notes")
                    .and_then(Value::as_str)
                    .ok_or(ApplyError::InvalidPayload)?;
                let folder_type = group
                    .get("folderType")
                    .and_then(Value::as_str)
                    .ok_or(ApplyError::InvalidPayload)?;
                if id != operation.entity_id
                    || name.trim().is_empty()
                    || name.len() > 500
                    || notes.len() > 1_048_576
                    || !matches!(
                        folder_type,
                        "" | "CARD"
                            | "PASSWORD"
                            | "QUESTION"
                            | "NOTE"
                            | "AUTHENTICATOR"
                            | "AUTOFILL"
                    )
                {
                    return Err(ApplyError::InvalidPayload);
                }
                return Ok(());
            }
            let entry = payload
                .get("entry")
                .and_then(Value::as_object)
                .ok_or(ApplyError::InvalidPayload)?;
            let group_ids = payload
                .get("groupIds")
                .and_then(Value::as_array)
                .ok_or(ApplyError::InvalidPayload)?;
            if group_ids.iter().any(|id| !id.is_string()) {
                return Err(ApplyError::InvalidPayload);
            }
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .ok_or(ApplyError::InvalidPayload)?;
            let title = entry
                .get("title")
                .and_then(Value::as_str)
                .ok_or(ApplyError::InvalidPayload)?;
            let entry_type = entry
                .get("type")
                .and_then(Value::as_str)
                .ok_or(ApplyError::InvalidPayload)?;
            if id != operation.entity_id || title.trim().is_empty() || title.len() > 500 {
                return Err(ApplyError::InvalidPayload);
            }
            if !matches!(
                entry_type,
                "CARD" | "QUESTION" | "PASSWORD" | "NOTE" | "AUTHENTICATOR" | "AUTOFILL"
            ) {
                return Err(ApplyError::InvalidPayload);
            }
            if entry_type == "NOTE" {
                for key in ["notes", "createdAt", "updatedAt"] {
                    if !entry.contains_key(key) {
                        return Err(ApplyError::InvalidPayload);
                    }
                }
                if entry["notes"].as_str().is_none()
                    || entry["createdAt"].as_i64().is_none()
                    || entry["updatedAt"].as_i64().is_none()
                {
                    return Err(ApplyError::InvalidPayload);
                }
            } else {
                for key in [
                    "primaryValue",
                    "secondaryValue",
                    "tertiaryValue",
                    "fourthValue",
                    "cardKind",
                    "network",
                    "totpAlgorithm",
                    "linkedApps",
                    "autofillSignatures",
                    "autofillOrigins",
                    "linkedAuthenticatorId",
                    "notes",
                    "tags",
                ] {
                    if entry.get(key).and_then(Value::as_str).is_none() {
                        return Err(ApplyError::InvalidPayload);
                    }
                }
                for key in [
                    "totpDigits",
                    "totpPeriod",
                    "color",
                    "lastOpenedAt",
                    "sortOrder",
                    "createdAt",
                    "updatedAt",
                ] {
                    if !entry.get(key).is_some_and(Value::is_number) {
                        return Err(ApplyError::InvalidPayload);
                    }
                }
                if entry.get("favorite").and_then(Value::as_bool).is_none() {
                    return Err(ApplyError::InvalidPayload);
                }
            }
            Ok(())
        }
        ChangeKind::Delete => {
            if payload.get("deleted").and_then(Value::as_bool) == Some(true) {
                Ok(())
            } else {
                Err(ApplyError::InvalidPayload)
            }
        }
    }
}

fn materialize(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
    payload: &Value,
    photo_bytes: Option<&[u8]>,
    record_only: bool,
) -> Result<(), ApplyError> {
    let version_json = serde_json::to_string(&operation.record_version)?;
    match operation.kind {
        ChangeKind::Upsert => {
            if record_only {
                // The version is recorded below; there is nothing to show on this device.
            } else if operation.entity_type == "device_name" {
                let member: Option<String> = transaction
                    .query_row("SELECT member_json FROM sync_memberships WHERE vault_id = ?1 AND device_id = ?2",
                        params![operation.vault_id, operation.entity_id], |row| row.get(0))
                    .optional()?;
                if let Some(member) = member {
                    let mut member: Value = serde_json::from_str(&member)?;
                    member["displayName"] = payload["name"].clone();
                    transaction.execute(
                        "UPDATE sync_memberships SET member_json = ?3 WHERE vault_id = ?1 AND device_id = ?2",
                        params![operation.vault_id, operation.entity_id, serde_json::to_string(&member)?],
                    )?;
                }
            } else if operation.entity_type == "photo" {
                let photo = &payload["photo"];
                let bytes = photo_bytes.ok_or(ApplyError::MissingPhotoBlob)?;
                let entry_id = photo["entryId"].as_str().ok_or(ApplyError::InvalidPayload)?;
                // Android keeps an existing photo's cover flag; a new cover replaces the old one.
                let existing: Option<bool> = transaction
                    .query_row("SELECT is_cover FROM local_entry_photos WHERE id = ?1", [&operation.entity_id], |row| row.get(0))
                    .optional()?;
                let is_cover = existing.unwrap_or(photo["isCover"].as_bool().unwrap_or(false));
                if is_cover && existing.is_none() {
                    transaction.execute("UPDATE local_entry_photos SET is_cover = 0 WHERE entry_id = ?1", [entry_id])?;
                }
                transaction.execute(
                    "INSERT INTO local_entry_photos (id, entry_id, mime_type, data, is_cover, added_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(id) DO UPDATE SET entry_id = excluded.entry_id, mime_type = excluded.mime_type,
                         data = excluded.data, is_cover = excluded.is_cover, added_at = excluded.added_at",
                    params![operation.entity_id, entry_id, photo_blobs::sniff_mime(bytes), bytes, is_cover,
                        photo["addedAt"].as_i64()],
                )?;
                transaction.execute(
                    "INSERT INTO sync_attachment_manifests (attachment_id, owner_entity_type, owner_entity_id,
                         encrypted_file_name, ciphertext_hash, size_bytes, key_epoch)
                     VALUES (?1, 'entry', ?2, ?3, ?3, ?4, 1)
                     ON CONFLICT(attachment_id) DO UPDATE SET owner_entity_id = excluded.owner_entity_id,
                         encrypted_file_name = excluded.encrypted_file_name,
                         ciphertext_hash = excluded.ciphertext_hash, size_bytes = excluded.size_bytes",
                    params![operation.entity_id, entry_id, photo["blobHash"].as_str(), photo["blobSize"].as_i64()],
                )?;
            } else if operation.entity_type == "photo_cover" {
                // Entity ID is the entry; the caller checked the photo belongs to it.
                transaction.execute(
                    "UPDATE local_entry_photos SET is_cover = (id = ?2) WHERE entry_id = ?1",
                    params![operation.entity_id, payload["coverPhotoId"].as_str()],
                )?;
            } else if operation.entity_type == "passkey" {
                let passkey = &payload["passkey"];
                let existing: Option<String> = transaction
                    .query_row(
                        "SELECT data_json FROM local_passkeys WHERE id = ?1",
                        [&operation.entity_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if existing.is_some_and(|existing| {
                    serde_json::from_str::<Value>(&existing).ok().as_ref() != Some(passkey)
                }) {
                    return Err(ApplyError::PasskeyIdConflict);
                }
                transaction.execute("INSERT OR IGNORE INTO local_passkeys (id, rp_id, data_json) VALUES (?1, ?2, ?3)",
                    params![operation.entity_id, passkey["rpId"].as_str(), serde_json::to_string(passkey)?])?;
            } else if operation.entity_type == "group" {
                let group = &payload["group"];
                transaction.execute(
                    "INSERT INTO local_groups (id, name, notes, folder_type) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(id) DO UPDATE SET name = excluded.name, notes = excluded.notes,
                         folder_type = excluded.folder_type",
                    params![operation.entity_id, group["name"].as_str(), group["notes"].as_str(), group["folderType"].as_str()],
                )?;
                // A folder holds one item type. Items of another type leave it, as on Android.
                let folder_type = group["folderType"].as_str().unwrap_or_default();
                if !folder_type.is_empty() {
                    transaction.execute(
                        "DELETE FROM entry_groups WHERE group_id = ?1 AND entry_id IN (
                             SELECT links.entry_id FROM entry_groups links
                             LEFT JOIN local_entries entries ON entries.id = links.entry_id
                             WHERE links.group_id = ?1 AND COALESCE(entries.type, 'NOTE') != ?2)",
                        params![operation.entity_id, folder_type],
                    )?;
                }
            } else {
                let entry = &payload["entry"];
                let entry_type = entry["type"].as_str().ok_or(ApplyError::InvalidPayload)?;
                let updated_at = entry["updatedAt"]
                    .as_i64()
                    .ok_or(ApplyError::InvalidPayload)?;
                if entry_type == "NOTE" {
                    // An entry that changed type must not stay visible under its old type.
                    transaction.execute(
                        "DELETE FROM local_entries WHERE id = ?1",
                        [&operation.entity_id],
                    )?;
                    transaction.execute(
                        "INSERT INTO local_notes (id, title, body, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(id) DO UPDATE SET title = excluded.title, body = excluded.body,
                         created_at = excluded.created_at, updated_at = excluded.updated_at",
                        params![
                            operation.entity_id,
                            entry["title"].as_str(),
                            entry["notes"].as_str(),
                            entry["createdAt"].as_i64(),
                            updated_at,
                        ],
                    )?;
                    transaction.execute(
                        "INSERT INTO local_note_details (id, data_json) VALUES (?1, ?2)
                         ON CONFLICT(id) DO UPDATE SET data_json = excluded.data_json",
                        params![operation.entity_id, serde_json::to_string(entry)?],
                    )?;
                } else {
                    transaction.execute(
                    "INSERT INTO local_entries (id, type, data_json, updated_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(id) DO UPDATE SET type = excluded.type, data_json = excluded.data_json,
                         updated_at = excluded.updated_at",
                    params![
                        operation.entity_id,
                        entry_type,
                        serde_json::to_string(entry)?,
                        updated_at,
                    ],
                )?;
                    transaction.execute(
                        "DELETE FROM local_notes WHERE id = ?1",
                        [&operation.entity_id],
                    )?;
                    transaction.execute(
                        "DELETE FROM local_note_details WHERE id = ?1",
                        [&operation.entity_id],
                    )?;
                }
                transaction.execute(
                    "DELETE FROM entry_groups WHERE entry_id = ?1",
                    [&operation.entity_id],
                )?;
                for group_id in payload["groupIds"]
                    .as_array()
                    .ok_or(ApplyError::InvalidPayload)?
                {
                    transaction.execute(
                        "INSERT INTO entry_groups (entry_id, group_id) VALUES (?1, ?2)",
                        params![operation.entity_id, group_id.as_str()],
                    )?;
                }
            }
            transaction.execute(
                "DELETE FROM sync_tombstones WHERE entity_type = ?1 AND entity_id = ?2",
                params![operation.entity_type, operation.entity_id],
            )?;
            transaction.execute(
                "INSERT INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(entity_type, entity_id) DO UPDATE SET
                     payload_ciphertext = excluded.payload_ciphertext,
                     revision = excluded.revision,
                     record_version_json = excluded.record_version_json",
                params![
                    operation.entity_type,
                    operation.entity_id,
                    operation.payload_ciphertext,
                    to_i64(
                        operation
                            .base_revision
                            .checked_add(1)
                            .ok_or(ApplyError::IntegerOverflow)?
                    )?,
                    version_json,
                ],
            )?;
        }
        ChangeKind::Delete => {
            if operation.entity_type == "photo" {
                transaction.execute(
                    "DELETE FROM local_entry_photos WHERE id = ?1",
                    [&operation.entity_id],
                )?;
                transaction.execute(
                    "DELETE FROM sync_attachment_manifests WHERE attachment_id = ?1",
                    [&operation.entity_id],
                )?;
            } else if operation.entity_type == "photo_cover" {
                // Android never deletes a cover record; nothing to materialize.
            } else if operation.entity_type == "passkey" {
                transaction.execute(
                    "DELETE FROM local_passkeys WHERE id = ?1",
                    [&operation.entity_id],
                )?;
            } else if operation.entity_type == "group" {
                transaction.execute(
                    "DELETE FROM entry_groups WHERE group_id = ?1",
                    [&operation.entity_id],
                )?;
                transaction.execute(
                    "DELETE FROM local_groups WHERE id = ?1",
                    [&operation.entity_id],
                )?;
            } else {
                transaction.execute(
                    "DELETE FROM local_entries WHERE id = ?1",
                    [&operation.entity_id],
                )?;
                transaction.execute(
                    "DELETE FROM local_notes WHERE id = ?1",
                    [&operation.entity_id],
                )?;
                transaction.execute(
                    "DELETE FROM local_note_details WHERE id = ?1",
                    [&operation.entity_id],
                )?;
                transaction.execute(
                    "DELETE FROM entry_groups WHERE entry_id = ?1",
                    [&operation.entity_id],
                )?;
                // Photos belong to their entry; keep no orphaned image data after a delete.
                transaction.execute(
                    "DELETE FROM local_entry_photos WHERE entry_id = ?1",
                    [&operation.entity_id],
                )?;
                transaction.execute(
                    "DELETE FROM sync_attachment_manifests WHERE owner_entity_id = ?1",
                    [&operation.entity_id],
                )?;
            }
            transaction.execute(
                "DELETE FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
                params![operation.entity_type, operation.entity_id],
            )?;
            transaction.execute(
                "INSERT INTO sync_tombstones (
                     tombstone_id, entity_type, entity_id, deleted_by_device_id, delete_sequence,
                     record_version_json, deleted_at_utc, change_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(entity_type, entity_id) DO UPDATE SET
                     tombstone_id = excluded.tombstone_id,
                     deleted_by_device_id = excluded.deleted_by_device_id,
                     delete_sequence = excluded.delete_sequence,
                     record_version_json = excluded.record_version_json,
                     deleted_at_utc = excluded.deleted_at_utc,
                     change_hash = excluded.change_hash",
                params![
                    operation.mutation_id,
                    operation.entity_type,
                    operation.entity_id,
                    operation.device_id,
                    to_i64(operation.sequence)?,
                    version_json,
                    operation.occurred_at_utc,
                    operation.hash,
                ],
            )?;
        }
    }
    Ok(())
}

fn to_i64(value: u64) -> Result<i64, ApplyError> {
    value.try_into().map_err(|_| ApplyError::IntegerOverflow)
}

fn now_utc() -> Result<String, ApplyError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| ApplyError::Clock)
}

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("encrypted database operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("incoming record version serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("sync payload could not be decrypted: {0}")]
    Payload(#[from] PayloadError),
    #[error("operation is not a persisted change")]
    OperationNotPersisted,
    #[error("incoming entity type is not supported")]
    UnsupportedEntity,
    #[error("photo data is still transferring")]
    MissingPhotoBlob,
    #[error("photo or cover waits for its entry or image")]
    MissingPhotoDependency,
    #[error("incoming entry refers to a group Windows has not received yet")]
    MissingGroupDependency,
    #[error("incoming passkey ID has different key material")]
    PasskeyIdConflict,
    #[error("incoming passkey is invalid: {0}")]
    Passkey(#[from] PasskeyError),
    #[error("linked authenticator is not available yet")]
    MissingEntryDependency,
    #[error("content key must be 32 bytes")]
    InvalidContentKey,
    #[error("incoming entry payload is invalid")]
    InvalidPayload,
    #[error("incoming mutation ID was reused")]
    MutationIdReused,
    #[error("materialized record and tombstone both exist")]
    CorruptMaterializedState,
    #[error("current materialized record has no matching sync operation")]
    CurrentChangeNotFound,
    #[error("incoming sync counter is too large for SQLite")]
    IntegerOverflow,
    #[error("system clock could not format an application time")]
    Clock,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rusqlite::{Connection, params};
    use serde_json::{Value, json};

    use crate::{
        change_store::ChangeStore,
        payload,
        protocol::RecordVersion,
        sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
    };

    use super::{ApplyOutcome, IncomingApply};

    const CONTENT_KEY: [u8; 32] = [4; 32];

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        ChangeStore::initialize(&connection).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE local_entries (
                     id TEXT NOT NULL PRIMARY KEY, type TEXT NOT NULL,
                     data_json TEXT NOT NULL, updated_at INTEGER NOT NULL
                 );
                 CREATE TABLE local_notes (
                     id TEXT NOT NULL PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
                     created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                 );
                 CREATE TABLE local_note_details (
                     id TEXT NOT NULL PRIMARY KEY, data_json TEXT NOT NULL
                 );
                 CREATE TABLE local_groups (
                     id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, notes TEXT NOT NULL,
                     folder_type TEXT NOT NULL
                 );
                 CREATE TABLE entry_groups (
                     entry_id TEXT NOT NULL, group_id TEXT NOT NULL,
                     PRIMARY KEY (entry_id, group_id)
                 );
                 CREATE TABLE local_passkeys (
                     id TEXT NOT NULL PRIMARY KEY, rp_id TEXT NOT NULL, data_json TEXT NOT NULL
                 );
                 CREATE TABLE local_entry_photos (
                     id TEXT NOT NULL PRIMARY KEY, entry_id TEXT NOT NULL, mime_type TEXT NOT NULL,
                     data BLOB NOT NULL, is_cover INTEGER NOT NULL DEFAULT 0,
                     added_at INTEGER NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();
        connection
    }

    fn entry(id: &str, title: &str) -> Value {
        json!({
            "id": id, "type": "PASSWORD", "title": title,
            "primaryValue": "", "secondaryValue": "secret",
            "tertiaryValue": "", "fourthValue": "", "cardKind": "CREDIT",
            "network": "", "totpAlgorithm": "SHA1", "totpDigits": 6,
            "totpPeriod": 30, "linkedApps": "", "autofillSignatures": "",
            "autofillOrigins": "", "linkedAuthenticatorId": "", "notes": "",
            "color": 4278716490_u64, "tags": "", "favorite": false,
            "lastOpenedAt": 0, "sortOrder": 100, "createdAt": 100,
            "updatedAt": 200
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn operation(
        signer: &SigningKey,
        device: &str,
        sequence: u64,
        previous_hash: &str,
        mutation: &str,
        version: RecordVersion,
        kind: ChangeKind,
        payload_json: Value,
        base_revision: u64,
    ) -> ChangeRecord {
        let plaintext = serde_json::to_vec(&payload_json).unwrap();
        let encrypted = payload::encrypt(
            &CONTENT_KEY,
            "entry",
            "vault-a",
            mutation,
            "entry-a",
            &plaintext,
        )
        .unwrap();
        ChangeRecord::create_signed_with(
            "vault-a",
            device,
            sequence,
            previous_hash,
            mutation,
            "entry",
            "entry-a",
            kind,
            base_revision,
            version,
            "2026-09-26T12:00:00Z",
            encrypted.ciphertext,
            encrypted.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()),
        )
        .unwrap()
    }

    fn insert_persisted(connection: &Connection, operation: &ChangeRecord) {
        connection
            .execute(
                "INSERT INTO sync_operations (
                    mutation_id, format_version, vault_id, device_id, sequence, previous_hash,
                    entity_type, entity_id, kind, base_revision, record_version_json,
                    occurred_at_utc, payload_ciphertext, payload_nonce, device_signature, hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    operation.mutation_id,
                    i64::from(operation.format_version),
                    operation.vault_id,
                    operation.device_id,
                    operation.sequence as i64,
                    operation.previous_hash,
                    operation.entity_type,
                    operation.entity_id,
                    match operation.kind {
                        ChangeKind::Upsert => "upsert",
                        ChangeKind::Delete => "delete",
                    },
                    operation.base_revision as i64,
                    serde_json::to_string(&operation.record_version).unwrap(),
                    operation.occurred_at_utc,
                    operation.payload_ciphertext,
                    operation.payload_nonce,
                    operation.device_signature,
                    operation.hash,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sync_device_heads (vault_id, device_id, sequence, hash)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(vault_id, device_id) DO UPDATE SET sequence = excluded.sequence, hash = excluded.hash",
                params![operation.vault_id, operation.device_id, operation.sequence as i64, operation.hash],
            )
            .unwrap();
    }

    fn applied_count(connection: &Connection) -> i64 {
        connection
            .query_row("SELECT COUNT(*) FROM sync_applied_operations", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn typed_operation(
        signer: &SigningKey,
        sequence: u64,
        previous_hash: &str,
        mutation: &str,
        entity_type: &str,
        entity_id: &str,
        kind: ChangeKind,
        payload_json: Value,
    ) -> ChangeRecord {
        let encrypted = payload::encrypt(
            &CONTENT_KEY,
            entity_type,
            "vault-a",
            mutation,
            entity_id,
            &serde_json::to_vec(&payload_json).unwrap(),
        )
        .unwrap();
        ChangeRecord::create_signed_with(
            "vault-a",
            "device-b",
            sequence,
            previous_hash,
            mutation,
            entity_type,
            entity_id,
            kind,
            0,
            RecordVersion::from_entries([("device-b", sequence)]),
            "2026-09-26T12:00:00Z",
            encrypted.ciphertext,
            encrypted.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()),
        )
        .unwrap()
    }

    fn photo_count(connection: &Connection, entry_id: &str) -> i64 {
        connection
            .query_row(
                "SELECT count(*) FROM local_entry_photos WHERE entry_id = ?1",
                [entry_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn android_photo_deletes_and_cover_changes_apply_but_uploads_wait_for_blobs() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[33; 32]);
        connection
            .execute_batch(
                "INSERT INTO local_entry_photos (id, entry_id, mime_type, data, is_cover, added_at) VALUES
                     ('photo-a', 'entry-a', 'image/png', x'00', 1, 10),
                     ('photo-b', 'entry-a', 'image/png', x'00', 0, 20);",
            )
            .unwrap();
        let upload = typed_operation(&signer, 1, GENESIS_HASH, "m-upload", "photo", "photo-c", ChangeKind::Upsert,
            json!({"photo": {"id": "photo-c", "entryId": "entry-a", "isCover": false, "addedAt": 30,
                "blobHash": "a".repeat(64), "blobSize": 10}}));
        insert_persisted(&connection, &upload);
        assert!(matches!(
            IncomingApply::apply(&mut connection, &upload, &CONTENT_KEY),
            Err(super::ApplyError::UnsupportedEntity)
        ));
        let cover = typed_operation(&signer, 2, &upload.hash, "m-cover", "photo_cover", "entry-a", ChangeKind::Upsert,
            json!({"coverPhotoId": "photo-b"}));
        insert_persisted(&connection, &cover);
        assert_eq!(IncomingApply::apply(&mut connection, &cover, &CONTENT_KEY).unwrap(), ApplyOutcome::Applied);
        let cover_id: String = connection
            .query_row("SELECT id FROM local_entry_photos WHERE is_cover = 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(cover_id, "photo-b");
        let missing_cover = typed_operation(&signer, 3, &cover.hash, "m-cover-2", "photo_cover", "entry-a", ChangeKind::Upsert,
            json!({"coverPhotoId": "photo-c"}));
        insert_persisted(&connection, &missing_cover);
        assert!(matches!(
            IncomingApply::apply(&mut connection, &missing_cover, &CONTENT_KEY),
            Err(super::ApplyError::MissingPhotoDependency)
        ), "a cover waits until Windows has its photo, as on Android");
        let covers: i64 = connection
            .query_row("SELECT count(*) FROM local_entry_photos WHERE is_cover = 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(covers, 1);
        let delete = typed_operation(&signer, 4, &missing_cover.hash, "m-delete", "photo", "photo-a", ChangeKind::Delete,
            json!({"deleted": true}));
        insert_persisted(&connection, &delete);
        assert_eq!(IncomingApply::apply(&mut connection, &delete, &CONTENT_KEY).unwrap(), ApplyOutcome::Applied);
        assert_eq!(photo_count(&connection, "entry-a"), 1);
        let tombstone: String = connection
            .query_row("SELECT entity_type FROM sync_tombstones WHERE entity_id = 'photo-a'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(tombstone, "photo");
    }

    #[test]
    fn deleting_an_entry_removes_its_photos_and_type_changes_do_not_duplicate() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[34; 32]);
        let save = operation(&signer, "device-b", 1, GENESIS_HASH, "entry-save",
            RecordVersion::from_entries([("device-b", 1)]), ChangeKind::Upsert,
            json!({"entry": entry("entry-a", "Login"), "groupIds": []}), 0);
        insert_persisted(&connection, &save);
        IncomingApply::apply(&mut connection, &save, &CONTENT_KEY).unwrap();
        let mut note = entry("entry-a", "Now a note");
        note["type"] = "NOTE".into();
        let retyped = operation(&signer, "device-b", 2, &save.hash, "entry-retype",
            RecordVersion::from_entries([("device-b", 2)]), ChangeKind::Upsert,
            json!({"entry": note, "groupIds": []}), 1);
        insert_persisted(&connection, &retyped);
        IncomingApply::apply(&mut connection, &retyped, &CONTENT_KEY).unwrap();
        let visible: i64 = connection
            .query_row("SELECT (SELECT count(*) FROM local_entries) + (SELECT count(*) FROM local_notes)", [], |row| row.get(0))
            .unwrap();
        assert_eq!(visible, 1);
        connection
            .execute("INSERT INTO local_entry_photos (id, entry_id, mime_type, data) VALUES ('p', 'entry-a', 'image/png', x'00')", [])
            .unwrap();
        let delete = operation(&signer, "device-b", 3, &retyped.hash, "entry-delete",
            RecordVersion::from_entries([("device-b", 3)]), ChangeKind::Delete,
            json!({"deleted": true}), 2);
        insert_persisted(&connection, &delete);
        IncomingApply::apply(&mut connection, &delete, &CONTENT_KEY).unwrap();
        assert_eq!(photo_count(&connection, "entry-a"), 0);
    }

    #[test]
    fn applies_group_before_an_entry_that_references_it() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[31; 32]);
        let group_payload = json!({"group": {
            "id": "group-a", "name": "Work", "notes": "", "folderType": "PASSWORD"
        }});
        let encrypted = payload::encrypt(
            &CONTENT_KEY,
            "group",
            "vault-a",
            "group-mutation",
            "group-a",
            &serde_json::to_vec(&group_payload).unwrap(),
        )
        .unwrap();
        let group_change = ChangeRecord::create_signed_with(
            "vault-a",
            "device-b",
            1,
            GENESIS_HASH,
            "group-mutation",
            "group",
            "group-a",
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([("device-b", 1)]),
            "2026-09-26T12:00:00Z",
            encrypted.ciphertext,
            encrypted.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()),
        )
        .unwrap();
        insert_persisted(&connection, &group_change);
        assert_eq!(
            IncomingApply::apply(&mut connection, &group_change, &CONTENT_KEY).unwrap(),
            ApplyOutcome::Applied
        );
        let entry_change = operation(
            &signer,
            "device-b",
            2,
            &group_change.hash,
            "entry-mutation",
            RecordVersion::from_entries([("device-b", 1)]),
            ChangeKind::Upsert,
            json!({"entry": entry("entry-a", "Work login"), "groupIds": ["group-a"]}),
            0,
        );
        insert_persisted(&connection, &entry_change);
        assert_eq!(
            IncomingApply::apply(&mut connection, &entry_change, &CONTENT_KEY).unwrap(),
            ApplyOutcome::Applied
        );
        let link: String = connection
            .query_row(
                "SELECT group_id FROM entry_groups WHERE entry_id = 'entry-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(link, "group-a");
    }

    #[test]
    fn applies_an_android_format_passkey_and_its_deletion() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use p256::{
            SecretKey,
            pkcs8::{EncodePrivateKey, EncodePublicKey},
        };
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[32; 32]);
        let secret = SecretKey::from_slice(&[8; 32]).unwrap();
        let passkey = json!({
            "id": URL_SAFE_NO_PAD.encode([7; 32]), "rpId": "example.com",
            "userHandle": URL_SAFE_NO_PAD.encode([3; 16]), "username": "alice",
            "displayName": "Alice", "privateKey": URL_SAFE_NO_PAD.encode(secret.to_pkcs8_der().unwrap().as_bytes()),
            "publicKey": URL_SAFE_NO_PAD.encode(secret.public_key().to_public_key_der().unwrap().as_bytes()),
            "createdAt": 100,
        });
        let id = passkey["id"].as_str().unwrap();
        let encrypted = payload::encrypt(
            &CONTENT_KEY,
            "passkey",
            "vault-a",
            "passkey-upsert",
            id,
            &serde_json::to_vec(&json!({"passkey": passkey})).unwrap(),
        )
        .unwrap();
        let change = ChangeRecord::create_signed_with(
            "vault-a",
            "device-b",
            1,
            GENESIS_HASH,
            "passkey-upsert",
            "passkey",
            id,
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([("device-b", 1)]),
            "2026-09-26T12:00:00Z",
            encrypted.ciphertext,
            encrypted.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()),
        )
        .unwrap();
        insert_persisted(&connection, &change);
        assert_eq!(
            IncomingApply::apply(&mut connection, &change, &CONTENT_KEY).unwrap(),
            ApplyOutcome::Applied
        );
        let count: i64 = connection
            .query_row("SELECT count(*) FROM local_passkeys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let encrypted = payload::encrypt(
            &CONTENT_KEY,
            "passkey",
            "vault-a",
            "passkey-delete",
            id,
            br#"{"deleted":true}"#,
        )
        .unwrap();
        let deletion = ChangeRecord::create_signed_with(
            "vault-a",
            "device-b",
            2,
            &change.hash,
            "passkey-delete",
            "passkey",
            id,
            ChangeKind::Delete,
            1,
            RecordVersion::from_entries([("device-b", 2)]),
            "2026-09-26T12:01:00Z",
            encrypted.ciphertext,
            encrypted.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()),
        )
        .unwrap();
        insert_persisted(&connection, &deletion);
        assert_eq!(
            IncomingApply::apply(&mut connection, &deletion, &CONTENT_KEY).unwrap(),
            ApplyOutcome::Applied
        );
        let count: i64 = connection
            .query_row("SELECT count(*) FROM local_passkeys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn applies_android_entry_upsert_and_marks_it_idempotently() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[17; 32]);
        let change = operation(
            &signer,
            "device-b",
            1,
            GENESIS_HASH,
            "mutation-upsert",
            RecordVersion::from_entries([("device-b", 1)]),
            ChangeKind::Upsert,
            json!({"entry": entry("entry-a", "Remote login"), "groupIds": []}),
            0,
        );
        insert_persisted(&connection, &change);

        assert_eq!(
            IncomingApply::apply(&mut connection, &change, &CONTENT_KEY).unwrap(),
            ApplyOutcome::Applied
        );
        let stored: String = connection
            .query_row(
                "SELECT data_json FROM local_entries WHERE id = 'entry-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&stored).unwrap()["title"],
            "Remote login"
        );
        assert_eq!(applied_count(&connection), 1);
        assert_eq!(
            IncomingApply::apply(&mut connection, &change, &CONTENT_KEY).unwrap(),
            ApplyOutcome::Replay
        );
        assert_eq!(applied_count(&connection), 1);
    }

    #[test]
    fn applies_delete_as_tombstone_after_removing_materialized_entry() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[17; 32]);
        let upsert = operation(
            &signer,
            "device-b",
            1,
            GENESIS_HASH,
            "mutation-upsert",
            RecordVersion::from_entries([("device-b", 1)]),
            ChangeKind::Upsert,
            json!({"entry": entry("entry-a", "Remote login"), "groupIds": []}),
            0,
        );
        insert_persisted(&connection, &upsert);
        IncomingApply::apply(&mut connection, &upsert, &CONTENT_KEY).unwrap();

        let deletion = operation(
            &signer,
            "device-b",
            2,
            &upsert.hash,
            "mutation-delete",
            RecordVersion::from_entries([("device-b", 2)]),
            ChangeKind::Delete,
            json!({"deleted": true}),
            1,
        );
        insert_persisted(&connection, &deletion);
        assert_eq!(
            IncomingApply::apply(&mut connection, &deletion, &CONTENT_KEY).unwrap(),
            ApplyOutcome::Applied
        );
        let entry_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM local_entries WHERE id = 'entry-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let tombstone_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sync_tombstones WHERE entity_id = 'entry-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let record_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM vault_records WHERE entity_id = 'entry-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((entry_count, tombstone_count, record_count), (0, 1, 0));
    }

    #[test]
    fn stores_concurrent_update_as_conflict_without_overwriting_local_entry() {
        let mut connection = connection();
        let local_signer = SigningKey::from_bytes(&[21; 32]);
        let local_entry = entry("entry-a", "Local version");
        let local_json = serde_json::to_string(&local_entry).unwrap();
        let local_version = RecordVersion::from_entries([("device-a", 1)]);
        let local_change = operation(
            &local_signer,
            "device-a",
            1,
            GENESIS_HASH,
            "mutation-local",
            local_version.clone(),
            ChangeKind::Upsert,
            json!({"entry": local_entry, "groupIds": []}),
            0,
        );
        insert_persisted(&connection, &local_change);
        connection
            .execute(
                "INSERT INTO local_entries (id, type, data_json, updated_at) VALUES ('entry-a', 'PASSWORD', ?1, 200)",
                [&local_json],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json)
                 VALUES ('entry', 'entry-a', ?1, 1, ?2)",
                params![
                    local_change.payload_ciphertext,
                    serde_json::to_string(&local_version).unwrap()
                ],
            )
            .unwrap();

        let remote_signer = SigningKey::from_bytes(&[22; 32]);
        let remote = operation(
            &remote_signer,
            "device-b",
            1,
            GENESIS_HASH,
            "mutation-remote",
            RecordVersion::from_entries([("device-b", 1)]),
            ChangeKind::Upsert,
            json!({"entry": entry("entry-a", "Remote version"), "groupIds": []}),
            0,
        );
        insert_persisted(&connection, &remote);

        assert_eq!(
            IncomingApply::apply(&mut connection, &remote, &CONTENT_KEY).unwrap(),
            ApplyOutcome::Conflict
        );
        let stored: String = connection
            .query_row(
                "SELECT data_json FROM local_entries WHERE id = 'entry-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&stored).unwrap()["title"],
            "Local version"
        );
        let conflict_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sync_conflicts WHERE entity_id = 'entry-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(conflict_count, 1);
        assert_eq!(applied_count(&connection), 1);
    }

    #[test]
    fn marker_failure_rolls_back_materialized_record() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[17; 32]);
        let change = operation(
            &signer,
            "device-b",
            1,
            GENESIS_HASH,
            "mutation-upsert",
            RecordVersion::from_entries([("device-b", 1)]),
            ChangeKind::Upsert,
            json!({"entry": entry("entry-a", "Remote login"), "groupIds": []}),
            0,
        );
        insert_persisted(&connection, &change);
        connection
            .execute_batch(
                "CREATE TRIGGER reject_applied_marker BEFORE INSERT ON sync_applied_operations
                 BEGIN SELECT RAISE(ABORT, 'test rejection'); END;",
            )
            .unwrap();

        assert!(IncomingApply::apply(&mut connection, &change, &CONTENT_KEY).is_err());
        let entry_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM local_entries", [], |row| row.get(0))
            .unwrap();
        let record_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM vault_records", [], |row| row.get(0))
            .unwrap();
        assert_eq!((entry_count, record_count), (0, 0));
    }

    #[test]
    fn defers_entry_until_its_linked_authenticator_exists() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[17; 32]);
        let mut linked_entry = entry("entry-a", "Remote login");
        linked_entry["linkedAuthenticatorId"] = "auth-missing".into();
        let change = operation(
            &signer,
            "device-b",
            1,
            GENESIS_HASH,
            "mutation-linked",
            RecordVersion::from_entries([("device-b", 1)]),
            ChangeKind::Upsert,
            json!({"entry": linked_entry, "groupIds": []}),
            0,
        );
        insert_persisted(&connection, &change);

        assert!(matches!(
            IncomingApply::apply(&mut connection, &change, &CONTENT_KEY),
            Err(super::ApplyError::MissingEntryDependency)
        ));
        let entry_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM local_entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(entry_count, 0);
        assert_eq!(applied_count(&connection), 0);
    }

    fn tombstone(connection: &Connection, entity_type: &str, entity_id: &str) {
        connection
            .execute(
                "INSERT INTO sync_tombstones (tombstone_id, entity_type, entity_id, deleted_by_device_id,
                     delete_sequence, record_version_json, deleted_at_utc, change_hash)
                 VALUES (?1, ?2, ?3, 'device-a', 1, '{\"counters\":{\"device-a\":1}}', '2026-09-26T11:00:00Z', ?4)",
                params![format!("t-{entity_id}"), entity_type, entity_id, "c".repeat(64)],
            )
            .unwrap();
    }

    #[test]
    fn links_to_deleted_or_mismatched_records_are_dropped_like_android() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[19; 32]);
        tombstone(&connection, "entry", "auth-gone");
        tombstone(&connection, "group", "group-gone");
        connection
            .execute_batch(
                "INSERT INTO local_groups (id, name, notes, folder_type) VALUES
                     ('plain', 'Work', '', ''), ('cards', 'Cards', '', 'CARD'),
                     ('logins-b', 'B', '', 'PASSWORD'), ('logins-a', 'A', '', 'PASSWORD');",
            )
            .unwrap();
        let mut linked_entry = entry("entry-a", "Remote login");
        linked_entry["linkedAuthenticatorId"] = "auth-gone".into();
        let change = operation(
            &signer,
            "device-b",
            1,
            GENESIS_HASH,
            "mutation-links",
            RecordVersion::from_entries([("device-b", 1)]),
            ChangeKind::Upsert,
            json!({"entry": linked_entry, "groupIds": ["group-gone", "plain", "cards", "logins-b", "logins-a"]}),
            0,
        );
        insert_persisted(&connection, &change);
        assert_eq!(IncomingApply::apply(&mut connection, &change, &CONTENT_KEY).unwrap(), ApplyOutcome::Applied);
        let data: String = connection
            .query_row("SELECT data_json FROM local_entries WHERE id = 'entry-a'", [], |row| row.get(0))
            .unwrap();
        let data: Value = serde_json::from_str(&data).unwrap();
        assert_eq!(data["linkedAuthenticatorId"], "", "a link to a deleted code is dropped");
        let mut groups: Vec<String> = connection
            .prepare("SELECT group_id FROM entry_groups WHERE entry_id = 'entry-a'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        groups.sort();
        assert_eq!(groups, ["logins-a", "plain"], "deleted and other-type folders go; one folder of the type stays");

        // A group that is neither here nor deleted may still arrive: the change waits.
        let waiting = operation(
            &signer,
            "device-b",
            2,
            &change.hash,
            "mutation-waits",
            RecordVersion::from_entries([("device-b", 2)]),
            ChangeKind::Upsert,
            json!({"entry": entry("entry-a", "Late"), "groupIds": ["group-late"]}),
            0,
        );
        insert_persisted(&connection, &waiting);
        assert!(matches!(
            IncomingApply::apply(&mut connection, &waiting, &CONTENT_KEY),
            Err(super::ApplyError::MissingGroupDependency)
        ));
    }

    #[test]
    fn photos_and_covers_of_a_deleted_entry_record_their_version_only() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[23; 32]);
        tombstone(&connection, "entry", "entry-gone");
        let directory = std::env::temp_dir().join(format!("nuvori-apply-{}", uuid::Uuid::new_v4()));
        let blobs = crate::photo_blobs::PhotoBlobs::new(&directory);
        let upload = typed_operation(&signer, 1, GENESIS_HASH, "m-upload", "photo", "photo-x", ChangeKind::Upsert,
            json!({"photo": {"id": "photo-x", "entryId": "entry-gone", "isCover": true, "addedAt": 30,
                "blobHash": "a".repeat(64), "blobSize": 100}}));
        insert_persisted(&connection, &upload);
        assert_eq!(
            IncomingApply::apply_with_blobs(&mut connection, &upload, &CONTENT_KEY, Some(&blobs)).unwrap(),
            ApplyOutcome::Applied,
            "the image is never needed for a deleted entry"
        );
        let cover = typed_operation(&signer, 2, &upload.hash, "m-cover", "photo_cover", "entry-gone", ChangeKind::Upsert,
            json!({"coverPhotoId": "photo-x"}));
        insert_persisted(&connection, &cover);
        assert_eq!(
            IncomingApply::apply_with_blobs(&mut connection, &cover, &CONTENT_KEY, Some(&blobs)).unwrap(),
            ApplyOutcome::Applied
        );
        assert_eq!(photo_count(&connection, "entry-gone"), 0);
        assert_eq!(applied_count(&connection), 2);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_folder_that_changes_type_releases_items_of_another_type() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[29; 32]);
        connection
            .execute_batch(
                "INSERT INTO local_entries (id, type, data_json, updated_at) VALUES
                     ('login', 'PASSWORD', '{}', 1), ('card', 'CARD', '{}', 1);
                 INSERT INTO entry_groups (entry_id, group_id) VALUES ('login', 'group-a'), ('card', 'group-a');",
            )
            .unwrap();
        let change = typed_operation(&signer, 1, GENESIS_HASH, "m-group", "group", "group-a", ChangeKind::Upsert,
            json!({"group": {"id": "group-a", "name": "Cards", "notes": "", "folderType": "CARD"}}));
        insert_persisted(&connection, &change);
        assert_eq!(IncomingApply::apply(&mut connection, &change, &CONTENT_KEY).unwrap(), ApplyOutcome::Applied);
        let members: Vec<String> = connection
            .prepare("SELECT entry_id FROM entry_groups WHERE group_id = 'group-a'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(members, ["card"]);
    }
}
