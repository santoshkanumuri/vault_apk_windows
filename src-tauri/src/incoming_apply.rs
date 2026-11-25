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
    appearance::{self, AppearanceStore},
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

    /// Appearance changes go to the store installed at startup (`appearance::install`).
    pub fn apply_with_blobs(
        connection: &mut Connection,
        operation: &ChangeRecord,
        content_key: &[u8],
        blobs: Option<&PhotoBlobs>,
    ) -> Result<ApplyOutcome, ApplyError> {
        Self::apply_with_appearance(connection, operation, content_key, blobs, appearance::installed())
    }

    /// Without an appearance store, appearance changes are left waiting.
    pub fn apply_with_appearance(
        connection: &mut Connection,
        operation: &ChangeRecord,
        content_key: &[u8],
        blobs: Option<&PhotoBlobs>,
        appearance_store: Option<&AppearanceStore>,
    ) -> Result<ApplyOutcome, ApplyError> {
        let supported = match operation.entity_type.as_str() {
            "entry" | "group" | "passkey" | "photo_cover" => true,
            "device_name" => operation.kind == ChangeKind::Upsert,
            "photo" => operation.kind == ChangeKind::Delete || blobs.is_some(),
            // A delete is not supported but readable: `validate_payload` sets it aside.
            appearance::ENTITY_TYPE => appearance_store.is_some(),
            // A delete is not supported but readable: `validate_payload` sets it aside.
            crate::site_icon_sync::ENTITY_TYPE => true,
            crate::sign_in_sync::ENTITY_TYPE => true,
            // A delete is readable but invalid: `validate_payload` sets it aside.
            crate::master_password::ENTITY_TYPE => true,
            _ => false,
        };
        if !supported {
            return Err(ApplyError::UnsupportedEntity);
        }
        // A managing device marked as lost here: nothing after its last known change, even if it
        // arrived before ("Mark as lost", `merge_join.rs`).
        if crate::merge_join::lost_freeze(connection, &operation.vault_id)?
            .is_some_and(|freeze| !freeze.allows(&operation.device_id, operation.sequence, &operation.hash))
        {
            return Err(ApplyError::FrozenAuthor);
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

        if operation.entity_type == appearance::ENTITY_TYPE {
            let store = appearance_store.ok_or(ApplyError::UnsupportedEntity)?;
            let (outcome, changed) = apply_appearance(&transaction, operation, &payload, store)?;
            mark_applied(&transaction, operation, outcome)?;
            transaction.commit()?;
            if let Some(view) = changed {
                store.notify(&view);
            }
            return Ok(outcome);
        }

        if operation.entity_type == crate::site_icon_sync::ENTITY_TYPE {
            // The entity id is an HMAC of the site under the content key: checked here, with the key.
            let (site, png) = crate::site_icon_sync::parse_payload(&payload, &operation.entity_id, content_key)
                .ok_or(ApplyError::InvalidPayload)?;
            let (outcome, stored) = apply_site_icon(&transaction, operation, &site, &png)?;
            mark_applied(&transaction, operation, outcome)?;
            transaction.commit()?;
            if stored {
                crate::site_icons::notify_saved();
            }
            return Ok(outcome);
        }

        if operation.entity_type == crate::master_password::ENTITY_TYPE {
            // `master-password-v1`: nothing to materialize. The vault reads the current check from
            // the applied changes, with the membership (`UnlockedVault::refresh_master_password`).
            mark_applied(&transaction, operation, ApplyOutcome::Applied)?;
            transaction.commit()?;
            return Ok(ApplyOutcome::Applied);
        }

        if operation.entity_type == crate::sign_in_sync::ENTITY_TYPE {
            // The entity id is an HMAC of the site, provider and account: checked here, with the key.
            let incoming = match operation.kind {
                ChangeKind::Upsert => Some(
                    crate::sign_in_sync::parse_payload(&payload, &operation.entity_id, content_key).ok_or(ApplyError::InvalidPayload)?,
                ),
                ChangeKind::Delete => None,
            };
            let (outcome, changed) = apply_sign_in_method(&transaction, operation, incoming.as_ref(), content_key)?;
            mark_applied(&transaction, operation, outcome)?;
            transaction.commit()?;
            if changed {
                crate::sign_ins::notify_changed();
            }
            return Ok(outcome);
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

        mark_applied(&transaction, operation, outcome)?;
        transaction.commit()?;
        Ok(outcome)
    }
}

fn mark_applied(transaction: &Transaction<'_>, operation: &ChangeRecord, outcome: ApplyOutcome) -> Result<(), ApplyError> {
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
    Ok(())
}

/// Protocol `appearance-v1`. Against the record state for ("appearance", "vault"): an incoming
/// version that dominates applies; an older or equal one is obsolete; a concurrent one is decided
/// by last writer wins against the stored value. A pending local value that was never written
/// competes the same way. Every applied or concurrent case stores the pointwise maximum of both
/// versions, so the next local change dominates both. Never a conflict, never a new change.
/// Returns the new view when the stored value changed, to announce after the commit.
fn apply_appearance(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
    payload: &Value,
    store: &AppearanceStore,
) -> Result<(ApplyOutcome, Option<appearance::View>), ApplyError> {
    let (accent, surface) = appearance::parse_payload(payload).ok_or(ApplyError::InvalidPayload)?;
    let current: Option<(String, i64)> = transaction
        .query_row(
            "SELECT record_version_json, revision FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let current = current
        .map(|(json, revision)| serde_json::from_str::<RecordVersion>(&json).map(|version| (version, revision)))
        .transpose()?;
    let relation = current.as_ref().map(|(version, _)| operation.record_version.relation_to(version));
    if matches!(relation, Some(VersionRelation::Before | VersionRelation::Equal)) {
        return Ok((ApplyOutcome::Obsolete, None));
    }
    let dominates = relation.is_none_or(|relation| relation == VersionRelation::After);

    let _guard = store.lock();
    let stored = store.load();
    let incoming = appearance::Stamp::new(Some(&operation.occurred_at_utc), Some(&operation.device_id));
    let value_wins = (dominates && !stored.pending_sync) || appearance::incoming_wins(&store.competing_stamp(&stored), &incoming);

    let merged = current
        .as_ref()
        .map_or_else(|| operation.record_version.clone(), |(version, _)| version.merged(&operation.record_version));
    let merged_json = serde_json::to_string(&merged)?;
    if dominates || value_wins {
        // The record now holds the incoming change. A pending local value that wins stays in
        // `appearance.json` and is written later on top of this version.
        let revision = current.as_ref().map_or(0, |(_, revision)| *revision).max(to_i64(operation.base_revision)?);
        transaction.execute(
            "INSERT INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(entity_type, entity_id) DO UPDATE SET payload_ciphertext = excluded.payload_ciphertext,
                 revision = excluded.revision, record_version_json = excluded.record_version_json",
            params![
                operation.entity_type,
                operation.entity_id,
                operation.payload_ciphertext,
                revision.checked_add(1).ok_or(ApplyError::IntegerOverflow)?,
                merged_json
            ],
        )?;
    } else {
        transaction.execute(
            "UPDATE vault_records SET record_version_json = ?3 WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id, merged_json],
        )?;
    }
    if !value_wins {
        return Ok((ApplyOutcome::Applied, None));
    }
    let next = appearance::Stored {
        accent,
        surface,
        updated_at_utc: Some(operation.occurred_at_utc.clone()),
        updated_by_device: Some(operation.device_id.clone()),
        pending_sync: false,
    };
    // Written before the commit: if the commit fails, the retry writes the same value again.
    store.save(&next).map_err(|_| ApplyError::AppearanceStorage)?;
    Ok((ApplyOutcome::Applied, (next.view() != stored.view()).then(|| next.view())))
}

/// Protocol `site-icons-v1`, as [apply_appearance] for one record per site: a dominating version
/// applies; an older or equal one is obsolete; a concurrent one is decided by last writer wins against
/// the stamp in `site_icon_sync_state`. Every applied or concurrent case stores the merged version.
/// Never a conflict. The bytes are remembered as synced, so [crate::site_icon_sync::flush] never
/// sends them back. Returns whether the icon was stored, to announce after the commit.
fn apply_site_icon(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
    site: &str,
    png: &[u8],
) -> Result<(ApplyOutcome, bool), ApplyError> {
    let current: Option<(String, i64)> = transaction
        .query_row(
            "SELECT record_version_json, revision FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let current = current
        .map(|(json, revision)| serde_json::from_str::<RecordVersion>(&json).map(|version| (version, revision)))
        .transpose()?;
    let relation = current.as_ref().map(|(version, _)| operation.record_version.relation_to(version));
    if matches!(relation, Some(VersionRelation::Before | VersionRelation::Equal)) {
        return Ok((ApplyOutcome::Obsolete, false));
    }
    let dominates = relation.is_none_or(|relation| relation == VersionRelation::After);
    let known = crate::site_icon_sync::synced_state(transaction, site)?;
    let stored_stamp = appearance::Stamp::new(
        known.as_ref().map(|(_, at, _)| at.as_str()),
        known.as_ref().map(|(_, _, device)| device.as_str()),
    );
    let incoming = appearance::Stamp::new(Some(&operation.occurred_at_utc), Some(&operation.device_id));
    let value_wins = dominates || appearance::incoming_wins(&stored_stamp, &incoming);

    let merged = current
        .as_ref()
        .map_or_else(|| operation.record_version.clone(), |(version, _)| version.merged(&operation.record_version));
    let merged_json = serde_json::to_string(&merged)?;
    if value_wins {
        let revision = current.as_ref().map_or(0, |(_, revision)| *revision).max(to_i64(operation.base_revision)?);
        transaction.execute(
            "INSERT INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(entity_type, entity_id) DO UPDATE SET payload_ciphertext = excluded.payload_ciphertext,
                 revision = excluded.revision, record_version_json = excluded.record_version_json",
            params![
                operation.entity_type,
                operation.entity_id,
                operation.payload_ciphertext,
                revision.checked_add(1).ok_or(ApplyError::IntegerOverflow)?,
                merged_json
            ],
        )?;
        crate::site_icon_sync::store_received(transaction, site, png, crate::activity::now_millis() as i64)?;
        crate::site_icon_sync::remember_synced(transaction, site, png, &operation.occurred_at_utc, &operation.device_id)?;
    } else {
        transaction.execute(
            "UPDATE vault_records SET record_version_json = ?3 WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id, merged_json],
        )?;
    }
    Ok((if value_wins { ApplyOutcome::Applied } else { ApplyOutcome::Obsolete }, value_wins && crate::site_icons::enabled()))
}

/// Protocol `sign-in-methods-v1` (`sign_in_sync.rs`), never a conflict. The version vectors decide first,
/// against the live record or else the tombstone: older or equal is obsolete, a dominating change applies.
/// Concurrent upserts merge field by field; an upsert concurrent with a delete goes to the later writer.
/// A local change that was never written (a re-record, or a delete waiting for the gate) competes like a
/// concurrent one. Every applied or concurrent case stores the merged version. Returns whether this PC's
/// list changed, to announce after the commit.
fn apply_sign_in_method(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
    incoming: Option<&crate::sign_in_sync::Method>,
    content_key: &[u8],
) -> Result<(ApplyOutcome, bool), ApplyError> {
    use crate::sign_in_sync::{self as sync, DELETED, Method};
    let record: Option<(RecordVersion, i64)> = transaction
        .query_row(
            "SELECT record_version_json, revision FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .map(|(json, revision)| serde_json::from_str::<RecordVersion>(&json).map(|version| (version, revision)))
        .transpose()?;
    let tombstone: Option<(RecordVersion, String, String)> = transaction
        .query_row(
            "SELECT record_version_json, deleted_at_utc, deleted_by_device_id FROM sync_tombstones WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        )
        .optional()?
        .map(|(json, at, device)| serde_json::from_str::<RecordVersion>(&json).map(|version| (version, at, device)))
        .transpose()?;
    // A live record supersedes a stale tombstone (an older snapshot may carry both).
    let live = record.is_some();
    let current_version = record.as_ref().map(|(version, _)| version).or(tombstone.as_ref().map(|(version, ..)| version));
    let relation = current_version.map(|version| operation.record_version.relation_to(version));
    if matches!(relation, Some(VersionRelation::Before | VersionRelation::Equal)) {
        return Ok((ApplyOutcome::Obsolete, false));
    }
    let dominates = relation.is_none_or(|relation| relation == VersionRelation::After);
    let merged = current_version.map_or_else(|| operation.record_version.clone(), |version| version.merged(&operation.record_version));
    let merged_json = serde_json::to_string(&merged)?;
    let incoming_stamp = appearance::Stamp::new(Some(&operation.occurred_at_utc), Some(&operation.device_id));
    let state = sync::synced_state(transaction, &operation.entity_id)?;
    let current_stamp = match (&tombstone, &state) {
        (Some((_, at, device)), _) if !live => appearance::Stamp::new(Some(at), Some(device)),
        (_, Some(state)) => state.stamp(),
        _ => appearance::Stamp::new(None, None),
    };
    let local = match incoming {
        Some(method) => sync::local_by_key(transaction, method)?,
        None => sync::local_by_entity(transaction, content_key, &operation.entity_id)?,
    };
    // A row of this PC that differs from what was last synced holds uses not written yet.
    let pending_local = local.as_ref().is_some_and(|(_, method)| state.as_ref().is_none_or(|state| state.hash != method.hash()));
    let revision = record.as_ref().map_or(0, |(_, revision)| *revision).max(to_i64(operation.base_revision)?);
    let next_revision = revision.checked_add(1).ok_or(ApplyError::IntegerOverflow)?;

    let Some(method) = incoming else {
        // A delete. A local use after it that was never written competes as a later upsert.
        let wins = dominates || !live || appearance::incoming_wins(&current_stamp, &incoming_stamp);
        if !wins {
            transaction.execute(
                "UPDATE vault_records SET record_version_json = ?3 WHERE entity_type = ?1 AND entity_id = ?2",
                params![operation.entity_type, operation.entity_id, merged_json],
            )?;
            return Ok((ApplyOutcome::Obsolete, false));
        }
        transaction.execute(
            "DELETE FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id],
        )?;
        transaction.execute(
            "INSERT INTO sync_tombstones (tombstone_id, entity_type, entity_id, deleted_by_device_id, delete_sequence,
                 record_version_json, deleted_at_utc, change_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(entity_type, entity_id) DO UPDATE SET tombstone_id = excluded.tombstone_id,
                 deleted_by_device_id = excluded.deleted_by_device_id, delete_sequence = excluded.delete_sequence,
                 record_version_json = excluded.record_version_json, deleted_at_utc = excluded.deleted_at_utc,
                 change_hash = excluded.change_hash",
            params![operation.mutation_id, operation.entity_type, operation.entity_id, operation.device_id,
                to_i64(operation.sequence)?, merged_json, operation.occurred_at_utc, operation.hash],
        )?;
        let deleted_at = sync::millis(&operation.occurred_at_utc);
        let mut changed = false;
        if let Some((id, own)) = &local
            && !(pending_local && deleted_at.is_some_and(|at| own.last_used_at > at))
        {
            changed = transaction.execute("DELETE FROM local_sign_ins WHERE id = ?1", [id])? == 1;
        }
        sync::remember_synced(transaction, &operation.entity_id, DELETED, "", &operation.occurred_at_utc, &operation.device_id)?;
        return Ok((ApplyOutcome::Applied, changed));
    };

    if !dominates && !live && tombstone.is_some() && !sync::upsert_beats_delete(&current_stamp, &incoming_stamp) {
        // The delete is the later writer: the method stays deleted.
        transaction.execute(
            "UPDATE sync_tombstones SET record_version_json = ?3 WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id, merged_json],
        )?;
        return Ok((ApplyOutcome::Obsolete, false));
    }
    let incoming_later = dominates || appearance::incoming_wins(&current_stamp, &incoming_stamp);
    // (value for this PC, hash and account to remember as synced, and their stamp)
    let (value, synced_hash, synced_account, stamp_at, stamp_device) = if !dominates && live {
        // Concurrent upserts: both sides compute the same merge and write nothing more. A pending local
        // value keeps the incoming hash, so its extra uses are written later.
        let current = local.as_ref().map_or_else(|| method.clone(), |(_, own)| own.clone());
        let value = sync::merge(&current, &current_stamp, method, &incoming_stamp);
        let (at, device) = match &state {
            Some(state) if !incoming_later => (state.at.clone(), state.device.clone()),
            _ => (operation.occurred_at_utc.clone(), operation.device_id.clone()),
        };
        let hash = if pending_local { method.hash() } else { value.hash() };
        let account = value.account.clone();
        (value, hash, account, at, device)
    } else {
        // The incoming change includes everything seen here. Uses this PC never wrote stay (min and max).
        let value = match &local {
            Some((_, own)) if pending_local => Method {
                first_used_at: own.first_used_at.min(method.first_used_at),
                last_used_at: own.last_used_at.max(method.last_used_at),
                use_count: own.use_count.max(method.use_count),
                ..method.clone()
            },
            _ => method.clone(),
        };
        (value, method.hash(), method.account.clone(), operation.occurred_at_utc.clone(), operation.device_id.clone())
    };
    // A delete of this method waiting on this PC competes like a concurrent delete.
    let waiting_delete = sync::pending_delete(transaction, method)?
        .is_some_and(|at| !sync::upsert_beats_delete(&appearance::Stamp::new(Some(&at), None), &incoming_stamp));
    transaction.execute(
        "INSERT INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(entity_type, entity_id) DO UPDATE SET payload_ciphertext =
             CASE WHEN ?6 THEN excluded.payload_ciphertext ELSE vault_records.payload_ciphertext END,
             revision = excluded.revision, record_version_json = excluded.record_version_json",
        params![operation.entity_type, operation.entity_id, operation.payload_ciphertext, next_revision, merged_json, incoming_later],
    )?;
    transaction.execute(
        "DELETE FROM sync_tombstones WHERE entity_type = ?1 AND entity_id = ?2",
        params![operation.entity_type, operation.entity_id],
    )?;
    sync::remember_synced(transaction, &operation.entity_id, &synced_hash, &synced_account, &stamp_at, &stamp_device)?;
    let changed = !waiting_delete && sync::store_received(transaction, &value)?;
    Ok((ApplyOutcome::Applied, changed))
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
            // The blob is sealed with the content key of the epoch the photo names (`epoch_keys.rs`).
            let epoch = details["keyEpoch"].as_u64().unwrap_or(1);
            let key = crate::payload::key_for(content_key, &operation.vault_id, epoch)?;
            photo = Some(
                blobs
                    .decrypt(&key, &operation.vault_id, &operation.entity_id, hash, size)
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
    if operation.entity_type == crate::master_password::ENTITY_TYPE {
        // `master-password-v1`: a check under the vault ID or a switch under the author's own device
        // ID, always an upsert. Whether a check's author was the managing device is decided on read.
        let valid = crate::master_password::read(&operation.vault_id, &operation.device_id, &operation.entity_id,
            operation.kind == ChangeKind::Upsert, payload).is_some();
        return if valid { Ok(()) } else { Err(ApplyError::InvalidPayload) };
    }
    if operation.entity_type == crate::sign_in_sync::ENTITY_TYPE {
        // `sign-in-methods-v1`: an upsert (checked in full, with the id, in `IncomingApply::apply_with_appearance`)
        // or the entry delete shape.
        let valid = match operation.kind {
            ChangeKind::Upsert => crate::sign_in_sync::parse_method(payload).is_some(),
            ChangeKind::Delete => payload.get("deleted").and_then(Value::as_bool) == Some(true),
        };
        return if valid { Ok(()) } else { Err(ApplyError::InvalidPayload) };
    }
    if operation.entity_type == crate::site_icon_sync::ENTITY_TYPE {
        // `site-icons-v1`: always an upsert. The site, the id and the image are checked with the
        // content key in `IncomingApply::apply_with_appearance`.
        let valid = operation.kind == ChangeKind::Upsert
            && payload.pointer("/siteIcon/site").and_then(Value::as_str).is_some()
            && payload.pointer("/siteIcon/png").and_then(Value::as_str).is_some();
        return if valid { Ok(()) } else { Err(ApplyError::InvalidPayload) };
    }
    if operation.entity_type == appearance::ENTITY_TYPE {
        // `appearance-v1`: one record, always an upsert, two ids of the shared shape.
        let valid = operation.kind == ChangeKind::Upsert
            && operation.entity_id == appearance::ENTITY_ID
            && appearance::parse_payload(payload).is_some();
        return if valid { Ok(()) } else { Err(ApplyError::InvalidPayload) };
    }
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
                    // This PC keeps the password that a paired device replaced (local_recovery.rs).
                    crate::local_recovery::note_entry_write(transaction, &operation.entity_id, entry, local_now())?;
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
                // A paired device deleted it: this PC keeps a copy in Recently deleted.
                crate::local_recovery::keep_deleted(transaction, &operation.entity_id, local_now(), true)?;
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

/// This PC's clock, for the local history and trash only (never part of a signed change).
fn local_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_millis() as i64)
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
    #[error("the appearance file could not be saved")]
    AppearanceStorage,
    #[error("the author was marked as lost on this device")]
    FrozenAuthor,
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
        crate::local_recovery::initialize(&connection).unwrap();
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

    /// A paired device changes a login's password, then deletes the login. This PC keeps the old
    /// password and a copy of the login (local_recovery.rs); the signed changes are unchanged.
    #[test]
    fn a_remote_password_change_and_delete_are_kept_on_this_pc() {
        let mut connection = connection();
        let signer = SigningKey::from_bytes(&[17; 32]);
        let first = operation(&signer, "device-b", 1, GENESIS_HASH, "mutation-1",
            RecordVersion::from_entries([("device-b", 1)]), ChangeKind::Upsert,
            json!({"entry": entry("entry-a", "Remote login"), "groupIds": []}), 0);
        insert_persisted(&connection, &first);
        IncomingApply::apply(&mut connection, &first, &CONTENT_KEY).unwrap();
        assert!(crate::local_recovery::previous_passwords(&connection, "entry-a").unwrap().is_empty());

        let mut changed = entry("entry-a", "Remote login");
        changed["secondaryValue"] = json!("new secret");
        changed["updatedAt"] = json!(300);
        let second = operation(&signer, "device-b", 2, &first.hash, "mutation-2",
            RecordVersion::from_entries([("device-b", 2)]), ChangeKind::Upsert,
            json!({"entry": changed, "groupIds": []}), 1);
        insert_persisted(&connection, &second);
        IncomingApply::apply(&mut connection, &second, &CONTENT_KEY).unwrap();
        let history = crate::local_recovery::previous_passwords(&connection, "entry-a").unwrap();
        assert_eq!(history.iter().map(|old| old.password.as_str()).collect::<Vec<_>>(), ["secret"]);

        let deletion = operation(&signer, "device-b", 3, &second.hash, "mutation-3",
            RecordVersion::from_entries([("device-b", 3)]), ChangeKind::Delete, json!({"deleted": true}), 2);
        insert_persisted(&connection, &deletion);
        assert_eq!(IncomingApply::apply(&mut connection, &deletion, &CONTENT_KEY).unwrap(), ApplyOutcome::Applied);
        let trash = crate::local_recovery::trashed_items(&connection).unwrap();
        assert_eq!(trash.len(), 1);
        assert_eq!((trash[0].title.as_str(), trash[0].item_type.as_str(), trash[0].deleted_elsewhere), ("Remote login", "PASSWORD", true));
        let (item_id, kind, data, _) = crate::local_recovery::trashed(&connection, &trash[0].id).unwrap().unwrap();
        assert_eq!((item_id.as_str(), kind.as_str(), data["secondaryValue"].as_str()), ("entry-a", "entry", Some("new secret")));
        // The previous password stays with the trashed copy until it is restored or purged.
        assert_eq!(crate::local_recovery::previous_passwords(&connection, "entry-a").unwrap().len(), 1);
        // The tombstone is applied as before.
        let tombstones: i64 = connection
            .query_row("SELECT COUNT(*) FROM sync_tombstones WHERE entity_id = 'entry-a'", [], |row| row.get(0)).unwrap();
        assert_eq!(tombstones, 1);
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

    #[allow(clippy::too_many_arguments)]
    fn icon_change(device: &str, sequence: u64, previous: &str, version: RecordVersion, at: &str, kind: ChangeKind,
        entity_id: &str, site: &str, png: &[u8]) -> ChangeRecord {
        let signer = SigningKey::from_bytes(&[43; 32]);
        let mutation = format!("icon-{device}-{sequence}");
        let body = serde_json::to_vec(&crate::site_icon_sync::payload_json(site, png)).unwrap();
        let encrypted = payload::encrypt(&CONTENT_KEY, "site_icon", "vault-a", &mutation, entity_id, &body).unwrap();
        ChangeRecord::create_signed_with("vault-a", device, sequence, previous, mutation, "site_icon", entity_id,
            kind, 0, version, at, encrypted.ciphertext, encrypted.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()))
            .unwrap()
    }

    fn test_png(side: u32, shade: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, side, side);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.write_header().unwrap().write_image_data(&vec![shade; (side * side * 4) as usize]).unwrap();
        bytes
    }

    fn stored_icon(connection: &Connection, site: &str) -> Option<Vec<u8>> {
        connection.query_row("SELECT png FROM local_site_icons WHERE site = ?1", [site], |row| row.get(0)).ok()
    }

    #[test]
    fn site_icons_apply_merge_by_last_writer_and_refuse_a_forged_id() {
        let mut connection = connection();
        crate::site_icons::initialize(&connection).unwrap();
        let id = crate::site_icon_sync::entity_id(&CONTENT_KEY, "github.com");
        let (blue, red) = (test_png(32, 40), test_png(32, 200));
        let apply = |connection: &mut Connection, change: &ChangeRecord| {
            insert_persisted(connection, change);
            IncomingApply::apply(connection, change, &CONTENT_KEY)
        };

        let first = icon_change("pc", 1, GENESIS_HASH, RecordVersion::from_entries([("pc", 1)]), "2026-11-21T10:00:00Z",
            ChangeKind::Upsert, &id, "github.com", &blue);
        assert_eq!(apply(&mut connection, &first).unwrap(), ApplyOutcome::Applied);
        assert_eq!(stored_icon(&connection, "github.com"), Some(blue.clone()));
        let second = icon_change("pc", 2, &first.hash, RecordVersion::from_entries([("pc", 2)]), "2026-11-21T09:00:00Z",
            ChangeKind::Upsert, &id, "github.com", &red);
        assert_eq!(apply(&mut connection, &second).unwrap(), ApplyOutcome::Applied, "a dominating version applies even with an older time");
        assert_eq!(stored_icon(&connection, "github.com"), Some(red.clone()));

        let concurrent = icon_change("laptop", 1, GENESIS_HASH, RecordVersion::from_entries([("laptop", 1)]),
            "2026-11-21T08:00:00Z", ChangeKind::Upsert, &id, "github.com", &blue);
        assert_eq!(apply(&mut connection, &concurrent).unwrap(), ApplyOutcome::Obsolete, "the earlier writer loses");
        assert_eq!(stored_icon(&connection, "github.com"), Some(red.clone()));
        let version: String = connection
            .query_row("SELECT record_version_json FROM vault_records WHERE entity_type = 'site_icon' AND entity_id = ?1", [&id],
                |row| row.get(0))
            .unwrap();
        assert_eq!(serde_json::from_str::<RecordVersion>(&version).unwrap(), RecordVersion::from_entries([("pc", 2), ("laptop", 1)]));
        assert_eq!(conflict_count(&connection), 0);
        // A received icon counts as synced, so the writer never sends it back.
        let (hash, ..) = crate::site_icon_sync::synced_state(&connection, "github.com").unwrap().unwrap();
        assert_eq!(hash, hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&red)));

        let forged = icon_change("pc", 3, &second.hash, RecordVersion::from_entries([("pc", 3)]), "2026-11-21T11:00:00Z",
            ChangeKind::Upsert, &id, "gitlab.com", &blue);
        assert!(matches!(apply(&mut connection, &forged), Err(super::ApplyError::InvalidPayload)));
        let delete = icon_change("laptop", 2, &concurrent.hash, RecordVersion::from_entries([("pc", 3), ("laptop", 2)]), "2026-11-21T11:00:00Z",
            ChangeKind::Delete, &id, "github.com", &blue);
        assert!(matches!(apply(&mut connection, &delete), Err(super::ApplyError::InvalidPayload)));
        assert_eq!(stored_icon(&connection, "github.com"), Some(red));
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_in_change(device: &str, sequence: u64, previous: &str, version: RecordVersion, at: &str, entity_id: &str,
        method: Option<&crate::sign_in_sync::Method>) -> ChangeRecord {
        let signer = SigningKey::from_bytes(&[44; 32]);
        let mutation = format!("sign-in-{device}-{sequence}");
        let body = serde_json::to_vec(&method.map_or(json!({"deleted": true}), crate::sign_in_sync::payload_json)).unwrap();
        let encrypted = payload::encrypt(&CONTENT_KEY, "sign_in_method", "vault-a", &mutation, entity_id, &body).unwrap();
        let kind = if method.is_some() { ChangeKind::Upsert } else { ChangeKind::Delete };
        ChangeRecord::create_signed_with("vault-a", device, sequence, previous, mutation, "sign_in_method", entity_id,
            kind, 0, version, at, encrypted.ciphertext, encrypted.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()))
            .unwrap()
    }

    fn sign_in_rows(connection: &Connection) -> Vec<(String, i64, i64, i64)> {
        crate::sign_ins::list(connection).unwrap().into_iter()
            .map(|row| (row.account, row.first_used_at, row.last_used_at, row.use_count)).collect()
    }

    fn entity_version(connection: &Connection, table: &str, entity_id: &str) -> Option<RecordVersion> {
        connection
            .query_row(&format!("SELECT record_version_json FROM {table} WHERE entity_type = 'sign_in_method' AND entity_id = ?1"),
                [entity_id], |row| row.get::<_, String>(0))
            .ok()
            .map(|json| serde_json::from_str(&json).unwrap())
    }

    /// The cross-device scenario of the spec: the PC records, the phone receives and deletes, the PC applies the
    /// tombstone; a later use on the PC brings the method back and wins over a concurrent delete; concurrent upserts
    /// merge; a forged id is refused. Never a conflict.
    #[test]
    fn sign_in_methods_merge_delete_and_come_back_across_devices() {
        use crate::sign_in_sync::{self as sync, Method};
        let mut connection = connection();
        crate::sign_ins::initialize(&connection).unwrap();
        connection.execute_batch("CREATE TABLE sync_group_state (vault_id TEXT NOT NULL PRIMARY KEY, content_key BLOB NOT NULL,
            transport_secret BLOB NOT NULL)").unwrap();
        connection.execute("INSERT INTO sync_group_state VALUES ('vault-a', ?1, x'00')", [CONTENT_KEY.to_vec()]).unwrap();
        let directory = std::env::temp_dir().join(format!("nuvori-sign-in-sync-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let identity_store = crate::identity::DeviceIdentityStore::new(directory.join("device-identity-v1.json"));
        let pc = identity_store.get_or_create().unwrap();
        let apply = |connection: &mut Connection, change: &ChangeRecord| {
            insert_persisted(connection, change);
            IncomingApply::apply(connection, change, &CONTENT_KEY)
        };
        let t = |at: &str| sync::millis(at).unwrap();

        // The PC records a sign-in and writes it.
        crate::sign_ins::record(&mut connection, "https://example.com", "github", Some("octocat"), true, t("2026-11-20T09:00:00Z")).unwrap();
        assert_eq!(sync::write_waiting(&mut connection, &identity_store, &pc, "vault-a", 50, t("2026-11-20T09:00:00Z")).unwrap(), 1);
        let octo = Method { site: "example.com".into(), provider: "github".into(), account: "octocat".into(),
            first_used_at: t("2026-11-20T09:00:00Z"), last_used_at: t("2026-11-20T09:00:00Z"), use_count: 1 };
        let id = octo.entity_id(&CONTENT_KEY);
        let written = entity_version(&connection, "vault_records", &id).unwrap();
        assert_eq!(written, RecordVersion::new([(pc.device_id.clone(), 1)].into()));

        // The phone deletes it after receiving it: the delete dominates, the row goes, a tombstone stays.
        let mut phone_version = written.counters().clone();
        phone_version.insert("phone".into(), 1);
        let delete = sign_in_change("phone", 1, GENESIS_HASH, RecordVersion::new(phone_version.clone()), "2026-11-20T10:00:00Z", &id, None);
        assert_eq!(apply(&mut connection, &delete).unwrap(), ApplyOutcome::Applied);
        assert!(sign_in_rows(&connection).is_empty());
        assert!(entity_version(&connection, "vault_records", &id).is_none());
        assert_eq!(entity_version(&connection, "sync_tombstones", &id), Some(RecordVersion::new(phone_version.clone())));
        assert_eq!(sync::write_waiting(&mut connection, &identity_store, &pc, "vault-a", 50, t("2026-11-20T10:00:00Z")).unwrap(), 0,
            "a received delete is never sent back");

        // A laptop's earlier concurrent upsert loses to the later delete; the tombstone takes the merged version.
        let laptop = sign_in_change("laptop", 1, GENESIS_HASH, RecordVersion::from_entries([("laptop", 1)]), "2026-11-20T09:30:00Z", &id,
            Some(&Method { account: "OctoCat".into(), use_count: 4, ..octo.clone() }));
        assert_eq!(apply(&mut connection, &laptop).unwrap(), ApplyOutcome::Obsolete);
        assert!(sign_in_rows(&connection).is_empty());
        phone_version.insert("laptop".into(), 1);
        assert_eq!(entity_version(&connection, "sync_tombstones", &id), Some(RecordVersion::new(phone_version.clone())));

        // The PC uses it again: the upsert dominates the tombstone, so the method comes back everywhere.
        crate::sign_ins::record(&mut connection, "https://example.com", "github", Some("octocat"), true, t("2026-11-20T11:00:00Z")).unwrap();
        assert_eq!(sync::write_waiting(&mut connection, &identity_store, &pc, "vault-a", 50, t("2026-11-20T11:00:00Z")).unwrap(), 1);
        assert!(entity_version(&connection, "sync_tombstones", &id).is_none());
        let revived = entity_version(&connection, "vault_records", &id).unwrap();
        assert_eq!(revived.relation_to(&RecordVersion::new(phone_version.clone())), crate::protocol::VersionRelation::After);

        // The phone deleted it again without seeing the re-use, earlier than the PC's write: the re-use wins.
        let mut concurrent = phone_version.clone();
        concurrent.insert("phone".into(), 2);
        let late_delete = sign_in_change("phone", 2, &delete.hash, RecordVersion::new(concurrent), "2026-11-20T10:30:00Z", &id, None);
        assert_eq!(apply(&mut connection, &late_delete).unwrap(), ApplyOutcome::Obsolete);
        assert_eq!(sign_in_rows(&connection), [("octocat".to_owned(), t("2026-11-20T11:00:00Z"), t("2026-11-20T11:00:00Z"), 1)]);
        let kept = entity_version(&connection, "vault_records", &id).unwrap();
        assert_eq!(kept.counters().get("phone"), Some(&2), "the merged version is stored");

        // A laptop upsert concurrent with the live record merges field by field (the later writer's spelling).
        let laptop_late = sign_in_change("laptop", 2, &laptop.hash, RecordVersion::from_entries([("laptop", 2)]), "2099-01-01T00:00:00Z", &id,
            Some(&Method { account: "OctoCat".into(), first_used_at: 5, last_used_at: 6, use_count: 9, ..octo.clone() }));
        assert_eq!(apply(&mut connection, &laptop_late).unwrap(), ApplyOutcome::Applied);
        assert_eq!(sign_in_rows(&connection), [("OctoCat".to_owned(), 5, t("2026-11-20T11:00:00Z"), 9)]);
        assert_eq!(sync::write_waiting(&mut connection, &identity_store, &pc, "vault-a", 50, t("2026-11-20T11:00:00Z")).unwrap(), 0,
            "both sides compute the same merge: no new write");

        // A forged id (another account's) and a delete without its flag are refused.
        let forged = sign_in_change("laptop", 3, &laptop_late.hash, RecordVersion::from_entries([("laptop", 3)]), "2099-01-01T00:00:01Z", &id,
            Some(&Method { account: "hubot".into(), ..octo.clone() }));
        assert!(matches!(apply(&mut connection, &forged), Err(super::ApplyError::InvalidPayload)));
        assert_eq!(conflict_count(&connection), 0);
        let _ = std::fs::remove_dir_all(directory);
    }

    struct AppearanceFixture {
        directory: std::path::PathBuf,
        store: crate::appearance::AppearanceStore,
        seen: std::sync::Arc<std::sync::Mutex<Vec<crate::appearance::View>>>,
    }

    impl AppearanceFixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!("nuvori-appearance-apply-{}", uuid::Uuid::new_v4()));
            let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let store = crate::appearance::AppearanceStore::with_notify(&directory, {
                let seen = seen.clone();
                move |view| seen.lock().unwrap().push(view.clone())
            });
            AppearanceFixture { directory, store, seen }
        }

        fn ids(&self) -> (String, String, bool) {
            let stored = self.store.load();
            (stored.accent, stored.surface, stored.pending_sync)
        }
    }

    impl Drop for AppearanceFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn appearance_change(device: &str, sequence: u64, previous: &str, version: RecordVersion, at: &str,
        kind: ChangeKind, entity_id: &str, body: Value) -> ChangeRecord {
        let signer = SigningKey::from_bytes(&[41; 32]);
        let mutation = format!("appearance-{device}-{sequence}");
        let encrypted = payload::encrypt(&CONTENT_KEY, "appearance", "vault-a", &mutation, entity_id,
            &serde_json::to_vec(&body).unwrap()).unwrap();
        ChangeRecord::create_signed_with("vault-a", device, sequence, previous, mutation, "appearance", entity_id,
            kind, 0, version, at, encrypted.ciphertext, encrypted.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()))
            .unwrap()
    }

    fn colors(accent: &str, surface: &str) -> Value {
        json!({"appearance": {"accent": accent, "surface": surface}})
    }

    fn apply_appearance(connection: &mut Connection, fixture: &AppearanceFixture, change: &ChangeRecord)
        -> Result<ApplyOutcome, super::ApplyError> {
        insert_persisted(connection, change);
        IncomingApply::apply_with_appearance(connection, change, &CONTENT_KEY, None, Some(&fixture.store))
    }

    fn appearance_record(connection: &Connection) -> (RecordVersion, String) {
        let (version, ciphertext): (String, String) = connection
            .query_row("SELECT record_version_json, payload_ciphertext FROM vault_records WHERE entity_type = 'appearance' AND entity_id = 'vault'",
                [], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap();
        (serde_json::from_str(&version).unwrap(), ciphertext)
    }

    fn conflict_count(connection: &Connection) -> i64 {
        connection.query_row("SELECT count(*) FROM sync_conflicts", [], |row| row.get(0)).unwrap()
    }

    fn owned(accent: &str, surface: &str, pending: bool) -> (String, String, bool) {
        (accent.to_owned(), surface.to_owned(), pending)
    }

    #[test]
    fn appearance_that_dominates_applies_and_older_or_equal_is_obsolete() {
        let mut connection = connection();
        let fixture = AppearanceFixture::new();
        let first = appearance_change("phone", 1, GENESIS_HASH, RecordVersion::from_entries([("phone", 1)]),
            "2026-11-13T10:00:00Z", ChangeKind::Upsert, "vault", colors("blue", "slate"));
        assert_eq!(apply_appearance(&mut connection, &fixture, &first).unwrap(), ApplyOutcome::Applied);
        assert_eq!(fixture.ids(), owned("blue", "slate", false));
        // Unknown ids from a newer palette are kept as received.
        let second = appearance_change("phone", 2, &first.hash, RecordVersion::from_entries([("phone", 2)]),
            "2026-11-13T09:00:00Z", ChangeKind::Upsert, "vault", colors("ultraviolet", "aurora-2"));
        assert_eq!(apply_appearance(&mut connection, &fixture, &second).unwrap(), ApplyOutcome::Applied,
            "a dominating version applies even with an older time");
        assert_eq!(fixture.ids(), owned("ultraviolet", "aurora-2", false));
        assert_eq!(appearance_record(&connection), (RecordVersion::from_entries([("phone", 2)]), second.payload_ciphertext.clone()));

        let older = appearance_change("tablet", 1, GENESIS_HASH, RecordVersion::from_entries([("phone", 1)]),
            "2026-11-13T12:00:00Z", ChangeKind::Upsert, "vault", colors("red", "stone"));
        assert_eq!(apply_appearance(&mut connection, &fixture, &older).unwrap(), ApplyOutcome::Obsolete);
        let equal = appearance_change("tablet", 2, &older.hash, RecordVersion::from_entries([("phone", 2)]),
            "2026-11-13T12:00:00Z", ChangeKind::Upsert, "vault", colors("red", "stone"));
        assert_eq!(apply_appearance(&mut connection, &fixture, &equal).unwrap(), ApplyOutcome::Obsolete);
        assert_eq!(fixture.ids(), owned("ultraviolet", "aurora-2", false));
        assert_eq!(IncomingApply::apply_with_appearance(&mut connection, &second, &CONTENT_KEY, None, Some(&fixture.store)).unwrap(),
            ApplyOutcome::Replay);
        assert_eq!((applied_count(&connection), conflict_count(&connection)), (4, 0));
        assert_eq!(fixture.seen.lock().unwrap().len(), 2, "one event per stored change");
    }

    #[test]
    fn concurrent_appearance_uses_last_writer_wins_both_ways_and_keeps_the_maximum_version() {
        let mut connection = connection();
        let fixture = AppearanceFixture::new();
        connection
            .execute("INSERT INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json)
                      VALUES ('appearance', 'vault', 'local-ciphertext', 1, '{\"counters\":{\"pc\":1}}')", [])
            .unwrap();
        fixture.store.save(&crate::appearance::Stored {
            accent: "teal".to_owned(), surface: "ocean".to_owned(),
            updated_at_utc: Some("2026-11-13T10:00:00Z".to_owned()), updated_by_device: Some("pc".to_owned()),
            pending_sync: false,
        }).unwrap();

        let later = appearance_change("phone", 1, GENESIS_HASH, RecordVersion::from_entries([("phone", 1)]),
            "2026-11-13T10:00:05Z", ChangeKind::Upsert, "vault", colors("blue", "slate"));
        assert_eq!(apply_appearance(&mut connection, &fixture, &later).unwrap(), ApplyOutcome::Applied);
        assert_eq!(fixture.ids(), owned("blue", "slate", false), "the later writer wins");
        assert_eq!(appearance_record(&connection),
            (RecordVersion::from_entries([("pc", 1), ("phone", 1)]), later.payload_ciphertext.clone()));

        let earlier = appearance_change("tablet", 1, GENESIS_HASH, RecordVersion::from_entries([("tablet", 1)]),
            "2026-11-13T09:59:00Z", ChangeKind::Upsert, "vault", colors("red", "stone"));
        assert_eq!(apply_appearance(&mut connection, &fixture, &earlier).unwrap(), ApplyOutcome::Applied);
        assert_eq!(fixture.ids(), owned("blue", "slate", false), "the earlier writer loses");
        assert_eq!(appearance_record(&connection),
            (RecordVersion::from_entries([("pc", 1), ("phone", 1), ("tablet", 1)]), later.payload_ciphertext.clone()),
            "the stored version includes both, the stored value stays");
        assert_eq!(conflict_count(&connection), 0);
        assert_eq!(fixture.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_pending_local_appearance_competes_with_incoming_changes() {
        let mut connection = connection();
        let fixture = AppearanceFixture::new();
        fixture.store.set_local("red", "stone", Some("pc")).unwrap();
        let older = appearance_change("phone", 1, GENESIS_HASH, RecordVersion::from_entries([("phone", 1)]),
            "2020-01-01T00:00:00Z", ChangeKind::Upsert, "vault", colors("blue", "slate"));
        assert_eq!(apply_appearance(&mut connection, &fixture, &older).unwrap(), ApplyOutcome::Applied);
        assert_eq!(fixture.ids(), owned("red", "stone", true), "an older incoming value loses; the choice stays pending");
        assert_eq!(appearance_record(&connection).0, RecordVersion::from_entries([("phone", 1)]),
            "the record still holds the incoming version, so the later write dominates it");

        let newer = appearance_change("phone", 2, &older.hash, RecordVersion::from_entries([("phone", 2)]),
            "2099-01-01T00:00:00Z", ChangeKind::Upsert, "vault", colors("blue", "slate"));
        assert_eq!(apply_appearance(&mut connection, &fixture, &newer).unwrap(), ApplyOutcome::Applied);
        assert_eq!(fixture.ids(), owned("blue", "slate", false), "a later incoming value wins and clears pending");
        assert_eq!(conflict_count(&connection), 0);
        let operations: i64 = connection
            .query_row("SELECT count(*) FROM sync_operations WHERE device_id = 'pc'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(operations, 0, "applying never writes a change");
    }

    #[test]
    fn appearance_deletes_bad_ids_and_other_records_are_unreadable() {
        let mut connection = connection();
        let fixture = AppearanceFixture::new();
        let version = |sequence| RecordVersion::from_entries([("phone", sequence)]);
        let delete = appearance_change("phone", 1, GENESIS_HASH, version(1), "2026-11-13T10:00:00Z",
            ChangeKind::Delete, "vault", json!({"deleted": true}));
        assert!(matches!(apply_appearance(&mut connection, &fixture, &delete), Err(super::ApplyError::InvalidPayload)));
        let bad_id = appearance_change("phone", 2, &delete.hash, version(2), "2026-11-13T10:00:00Z",
            ChangeKind::Upsert, "vault", colors("Blue!", "slate"));
        assert!(matches!(apply_appearance(&mut connection, &fixture, &bad_id), Err(super::ApplyError::InvalidPayload)));
        let other = appearance_change("phone", 3, &bad_id.hash, version(3), "2026-11-13T10:00:00Z",
            ChangeKind::Upsert, "theme", colors("blue", "slate"));
        assert!(matches!(apply_appearance(&mut connection, &fixture, &other), Err(super::ApplyError::InvalidPayload)));
        let fine = appearance_change("phone", 4, &other.hash, version(4), "2026-11-13T10:00:00Z",
            ChangeKind::Upsert, "vault", colors("blue", "slate"));
        insert_persisted(&connection, &fine);
        assert!(matches!(IncomingApply::apply_with_appearance(&mut connection, &fine, &CONTENT_KEY, None, None),
            Err(super::ApplyError::UnsupportedEntity)), "without a store the change waits");
        assert_eq!(IncomingApply::apply_with_appearance(&mut connection, &fine, &CONTENT_KEY, None, Some(&fixture.store)).unwrap(),
            ApplyOutcome::Applied);
        assert_eq!(fixture.ids(), owned("blue", "slate", false));
        assert_eq!(applied_count(&connection), 1);
    }
}
