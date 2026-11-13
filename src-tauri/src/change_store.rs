use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use thiserror::Error;

use crate::{
    identity::{DeviceIdentity, verify_signature},
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH, SYNC_FORMAT_VERSION},
};

pub struct ChangeStore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredVaultRecord {
    pub entity_type: String,
    pub entity_id: String,
    pub payload_ciphertext: String,
    pub revision: u64,
    pub record_version_json: String,
}

impl ChangeStore {
    pub fn initialize(connection: &Connection) -> Result<(), StoreError> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS vault_records (
                 entity_type TEXT NOT NULL,
                 entity_id TEXT NOT NULL,
                 payload_ciphertext TEXT NOT NULL,
                 revision INTEGER NOT NULL,
                 record_version_json TEXT NOT NULL,
                 PRIMARY KEY (entity_type, entity_id)
             );
             CREATE TABLE IF NOT EXISTS sync_operations (
                 mutation_id TEXT NOT NULL PRIMARY KEY,
                 format_version INTEGER NOT NULL,
                 vault_id TEXT NOT NULL,
                 device_id TEXT NOT NULL,
                 sequence INTEGER NOT NULL,
                 previous_hash TEXT NOT NULL,
                 entity_type TEXT NOT NULL,
                 entity_id TEXT NOT NULL,
                 kind TEXT NOT NULL CHECK (kind IN ('upsert', 'delete')),
                 base_revision INTEGER NOT NULL,
                 record_version_json TEXT NOT NULL,
                 occurred_at_utc TEXT NOT NULL,
                 payload_ciphertext TEXT NOT NULL,
                 payload_nonce TEXT NOT NULL,
                 device_signature TEXT NOT NULL,
                 hash TEXT NOT NULL UNIQUE,
                 UNIQUE (vault_id, device_id, sequence)
             );
             CREATE INDEX IF NOT EXISTS sync_operations_entity
                 ON sync_operations (entity_type, entity_id);
             CREATE TABLE IF NOT EXISTS sync_device_heads (
                 vault_id TEXT NOT NULL,
                 device_id TEXT NOT NULL,
                 sequence INTEGER NOT NULL,
                 hash TEXT NOT NULL,
                 PRIMARY KEY (vault_id, device_id)
             );
             CREATE TABLE IF NOT EXISTS sync_tombstones (
                 tombstone_id TEXT NOT NULL PRIMARY KEY,
                 entity_type TEXT NOT NULL,
                 entity_id TEXT NOT NULL,
                 deleted_by_device_id TEXT NOT NULL,
                 delete_sequence INTEGER NOT NULL,
                 record_version_json TEXT NOT NULL,
                 deleted_at_utc TEXT NOT NULL,
                 change_hash TEXT NOT NULL,
                 UNIQUE (entity_type, entity_id)
             );
             CREATE TABLE IF NOT EXISTS sync_attachment_manifests (
                 attachment_id TEXT NOT NULL PRIMARY KEY,
                 owner_entity_type TEXT NOT NULL,
                 owner_entity_id TEXT NOT NULL,
                 encrypted_file_name TEXT NOT NULL,
                 ciphertext_hash TEXT NOT NULL,
                 size_bytes INTEGER NOT NULL,
                 key_epoch INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS sync_attachment_manifests_owner
                 ON sync_attachment_manifests (owner_entity_type, owner_entity_id);
             CREATE TABLE IF NOT EXISTS sync_conflicts (
                 conflict_id TEXT NOT NULL PRIMARY KEY,
                 entity_type TEXT NOT NULL,
                 entity_id TEXT NOT NULL,
                 local_change_hash TEXT NOT NULL,
                 remote_change_hash TEXT NOT NULL,
                 local_version_json TEXT NOT NULL,
                 remote_version_json TEXT NOT NULL,
                 detected_at_utc TEXT NOT NULL,
                 resolved_at_utc TEXT NOT NULL DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS sync_conflicts_entity
                 ON sync_conflicts (entity_type, entity_id);
             CREATE TABLE IF NOT EXISTS sync_received_operations (
                 mutation_id TEXT NOT NULL PRIMARY KEY REFERENCES sync_operations(mutation_id)
             );
             CREATE TABLE IF NOT EXISTS sync_applied_operations (
                 mutation_id TEXT NOT NULL PRIMARY KEY REFERENCES sync_operations(mutation_id),
                 change_hash TEXT NOT NULL,
                 outcome TEXT NOT NULL CHECK (outcome IN ('applied', 'conflict', 'obsolete')),
                 applied_at_utc TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sync_peer_endpoints (
                 vault_id TEXT NOT NULL,
                 peer_device_id TEXT NOT NULL,
                 address TEXT NOT NULL,
                 PRIMARY KEY (vault_id, peer_device_id)
             );
             CREATE TABLE IF NOT EXISTS sync_exchange_state (
                 vault_id TEXT NOT NULL PRIMARY KEY,
                 last_sync_utc TEXT NOT NULL DEFAULT '',
                 phone_address TEXT NOT NULL DEFAULT '',
                 automatic INTEGER NOT NULL DEFAULT 0 CHECK (automatic IN (0, 1))
             );
             CREATE TABLE IF NOT EXISTS sync_peer_acknowledgements (
                 vault_id TEXT NOT NULL,
                 peer_device_id TEXT NOT NULL,
                 source_device_id TEXT NOT NULL,
                 sequence INTEGER NOT NULL,
                 acknowledged_at_utc TEXT NOT NULL,
                 PRIMARY KEY (vault_id, peer_device_id, source_device_id)
             );
             CREATE TABLE IF NOT EXISTS sync_peer_progress (
                 vault_id TEXT NOT NULL,
                 peer_device_id TEXT NOT NULL,
                 progress_json TEXT NOT NULL,
                 PRIMARY KEY (vault_id, peer_device_id)
             );",
        )?;
        Ok(())
    }

    pub fn save_record_and_operation(
        connection: &mut Connection,
        record: &StoredVaultRecord,
        operation: &ChangeRecord,
        identity: &DeviceIdentity,
    ) -> Result<(), StoreError> {
        Self::save_record_and_operation_with(connection, record, operation, identity, |_| Ok(()))
    }

    pub fn save_record_and_operation_with(
        connection: &mut Connection,
        record: &StoredVaultRecord,
        operation: &ChangeRecord,
        identity: &DeviceIdentity,
        materialize: impl FnOnce(&Transaction<'_>) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        validate_upsert(record, operation, identity)?;
        let transaction = connection.transaction()?;
        validate_next_link(&transaction, operation)?;
        let current_revision: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
                params![record.entity_type, record.entity_id],
                |row| row.get(0),
            )
            .optional()?;
        if current_revision.map(|value| value as u64).unwrap_or(0) != operation.base_revision {
            return Err(StoreError::InvalidOperation("record revision changed"));
        }
        materialize(&transaction)?;
        transaction.execute(
            "INSERT INTO vault_records (
                 entity_type, entity_id, payload_ciphertext, revision, record_version_json
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(entity_type, entity_id) DO UPDATE SET
                 payload_ciphertext = excluded.payload_ciphertext,
                 revision = excluded.revision,
                 record_version_json = excluded.record_version_json",
            params![
                record.entity_type,
                record.entity_id,
                record.payload_ciphertext,
                to_i64(record.revision)?,
                record.record_version_json,
            ],
        )?;
        insert_operation_and_head(&transaction, operation)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_record_and_operation(
        connection: &mut Connection,
        operation: &ChangeRecord,
        identity: &DeviceIdentity,
    ) -> Result<(), StoreError> {
        Self::delete_record_and_operation_with(connection, operation, identity, |_| Ok(()))
    }

    pub fn delete_record_and_operation_with(
        connection: &mut Connection,
        operation: &ChangeRecord,
        identity: &DeviceIdentity,
        materialize: impl FnOnce(&Transaction<'_>) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if operation.kind != ChangeKind::Delete {
            return Err(StoreError::InvalidOperation("operation is not a delete"));
        }
        validate_signed_operation(operation, identity)?;
        let transaction = connection.transaction()?;
        validate_next_link(&transaction, operation)?;
        let revision: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
                params![operation.entity_type, operation.entity_id],
                |row| row.get(0),
            )
            .optional()?;
        if revision.map(|value| value as u64) != Some(operation.base_revision) {
            return Err(StoreError::InvalidOperation("record revision changed"));
        }
        materialize(&transaction)?;
        let deleted = transaction.execute(
            "DELETE FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
            params![operation.entity_type, operation.entity_id],
        )?;
        if deleted != 1 {
            return Err(StoreError::InvalidOperation("record to delete is missing"));
        }
        insert_operation_and_head(&transaction, operation)?;
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
                serde_json::to_string(&operation.record_version)?,
                operation.occurred_at_utc,
                operation.hash,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record(
        connection: &Connection,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<Option<StoredVaultRecord>, StoreError> {
        connection
            .query_row(
                "SELECT entity_type, entity_id, payload_ciphertext, revision, record_version_json
                 FROM vault_records WHERE entity_type = ?1 AND entity_id = ?2",
                params![entity_type, entity_id],
                |row| {
                    let revision: i64 = row.get(3)?;
                    Ok(StoredVaultRecord {
                        entity_type: row.get(0)?,
                        entity_id: row.get(1)?,
                        payload_ciphertext: row.get(2)?,
                        revision: revision as u64,
                        record_version_json: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn operation_count(connection: &Connection) -> Result<u64, StoreError> {
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM sync_operations", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

fn validate_next_link(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
) -> Result<(), StoreError> {
    let head: Option<(i64, String)> = transaction
        .query_row(
            "SELECT sequence, hash FROM sync_device_heads WHERE vault_id = ?1 AND device_id = ?2",
            params![operation.vault_id, operation.device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (sequence, hash) = head
        .map(|(sequence, hash)| (sequence as u64, hash))
        .unwrap_or((0, GENESIS_HASH.to_owned()));
    let latest_operation: Option<(i64, String)> = transaction.query_row(
        "SELECT sequence, hash FROM sync_operations WHERE vault_id = ?1 AND device_id = ?2 ORDER BY sequence DESC LIMIT 1",
        params![operation.vault_id, operation.device_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    if latest_operation.map(|(latest_sequence, latest_hash)| (latest_sequence as u64, latest_hash))
        != (if sequence == 0 {
            None
        } else {
            Some((sequence, hash.clone()))
        })
    {
        return Err(StoreError::InvalidOperation(
            "local change head does not match history",
        ));
    }
    if sequence.checked_add(1) != Some(operation.sequence) || operation.previous_hash != hash {
        return Err(StoreError::InvalidOperation("broken local change chain"));
    }
    Ok(())
}

fn validate_upsert(
    record: &StoredVaultRecord,
    operation: &ChangeRecord,
    identity: &DeviceIdentity,
) -> Result<(), StoreError> {
    if operation.kind != ChangeKind::Upsert {
        return Err(StoreError::InvalidOperation("operation is not an upsert"));
    }
    if operation.entity_type != record.entity_type || operation.entity_id != record.entity_id {
        return Err(StoreError::InvalidOperation(
            "operation targets another record",
        ));
    }
    if operation.base_revision.checked_add(1) != Some(record.revision) {
        return Err(StoreError::InvalidOperation(
            "record revision does not match operation",
        ));
    }
    let stored_version = serde_json::from_str(&record.record_version_json)
        .map_err(|_| StoreError::InvalidOperation("stored record version is invalid"))?;
    if operation.record_version != stored_version {
        return Err(StoreError::InvalidOperation(
            "record version does not match operation",
        ));
    }
    validate_signed_operation(operation, identity)
}

fn validate_signed_operation(
    operation: &ChangeRecord,
    identity: &DeviceIdentity,
) -> Result<(), StoreError> {
    if operation.format_version != SYNC_FORMAT_VERSION {
        return Err(StoreError::InvalidOperation("unsupported format"));
    }
    if operation.hash != operation.compute_hash() {
        return Err(StoreError::InvalidOperation("operation hash is invalid"));
    }
    operation
        .record_version
        .validate()
        .map_err(|_| StoreError::InvalidOperation("record version is invalid"))?;
    if operation.device_id != identity.device_id {
        return Err(StoreError::InvalidOperation(
            "operation author is not this device",
        ));
    }
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&operation.device_signature)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StoreError::InvalidOperation("device signature is invalid"))?;
    if !verify_signature(&identity.public_key, &operation.signing_bytes(), &signature) {
        return Err(StoreError::InvalidOperation("device signature is invalid"));
    }
    Ok(())
}

fn insert_operation_and_head(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
) -> Result<(), StoreError> {
    transaction.execute(
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
            to_i64(operation.sequence)?,
            operation.previous_hash,
            operation.entity_type,
            operation.entity_id,
            match operation.kind {
                ChangeKind::Upsert => "upsert",
                ChangeKind::Delete => "delete",
            },
            to_i64(operation.base_revision)?,
            serde_json::to_string(&operation.record_version)?,
            operation.occurred_at_utc,
            operation.payload_ciphertext,
            operation.payload_nonce,
            operation.device_signature,
            operation.hash,
        ],
    )?;
    transaction.execute(
        "INSERT INTO sync_device_heads (vault_id, device_id, sequence, hash)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(vault_id, device_id) DO UPDATE SET
             sequence = excluded.sequence,
             hash = excluded.hash",
        params![
            operation.vault_id,
            operation.device_id,
            to_i64(operation.sequence)?,
            operation.hash,
        ],
    )?;
    Ok(())
}

fn to_i64(value: u64) -> Result<i64, StoreError> {
    value.try_into().map_err(|_| StoreError::IntegerOverflow)
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("sync serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid sync operation: {0}")]
    InvalidOperation(&'static str),
    #[error("sync counter is too large for SQLite")]
    IntegerOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RecordVersion;
    use ed25519_dalek::{Signer, SigningKey};

    fn identity() -> DeviceIdentity {
        DeviceIdentity {
            device_id: "device-a".to_owned(),
            public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        }
    }

    fn operation(
        mutation_id: &str,
        sequence: u64,
        previous_hash: &str,
        entity_id: &str,
    ) -> ChangeRecord {
        let key = SigningKey::from_bytes(&[7; 32]);
        ChangeRecord::create_signed_with(
            "vault-a",
            "device-a",
            sequence,
            previous_hash,
            mutation_id,
            "entry",
            entity_id,
            ChangeKind::Upsert,
            sequence - 1,
            RecordVersion::from_entries([("device-a", sequence)]),
            "2026-09-21T12:00:00Z",
            format!("ciphertext-{mutation_id}"),
            "nonce-test-only",
            |bytes| Ok::<_, ()>(key.sign(bytes).to_bytes()),
        )
        .expect("test signing must succeed")
    }

    fn record(entity_id: &str, payload: &str, revision: u64) -> StoredVaultRecord {
        StoredVaultRecord {
            entity_type: "entry".to_owned(),
            entity_id: entity_id.to_owned(),
            payload_ciphertext: payload.to_owned(),
            revision,
            record_version_json: format!("{{\"counters\":{{\"device-a\":{revision}}}}}"),
        }
    }

    fn delete_operation(mutation_id: &str, previous_hash: &str) -> ChangeRecord {
        let key = SigningKey::from_bytes(&[7; 32]);
        ChangeRecord::create_signed_with(
            "vault-a",
            "device-a",
            2,
            previous_hash,
            mutation_id,
            "entry",
            "entry-a",
            ChangeKind::Delete,
            1,
            RecordVersion::from_entries([("device-a", 2)]),
            "2026-09-21T12:01:00Z",
            "encrypted-delete",
            "nonce-test-only",
            |bytes| Ok::<_, ()>(key.sign(bytes).to_bytes()),
        )
        .expect("test signing must succeed")
    }

    #[test]
    fn commits_record_operation_and_head_together() {
        let mut connection = Connection::open_in_memory().expect("in-memory SQLite must open");
        ChangeStore::initialize(&connection).expect("schema must initialize");
        let record = record("entry-a", "ciphertext-1", 1);
        let operation = operation("mutation-1", 1, GENESIS_HASH, "entry-a");

        ChangeStore::save_record_and_operation(&mut connection, &record, &operation, &identity())
            .expect("transaction must commit");

        assert_eq!(
            ChangeStore::record(&connection, "entry", "entry-a").expect("record query"),
            Some(record)
        );
        assert_eq!(
            ChangeStore::operation_count(&connection).expect("operation count"),
            1
        );
    }

    #[test]
    fn rejects_head_that_no_longer_matches_operation_history() {
        let mut connection = Connection::open_in_memory().unwrap();
        ChangeStore::initialize(&connection).unwrap();
        let first = operation("mutation-1", 1, GENESIS_HASH, "entry-a");
        ChangeStore::save_record_and_operation(
            &mut connection,
            &record("entry-a", "ciphertext-1", 1),
            &first,
            &identity(),
        )
        .unwrap();
        connection
            .execute("UPDATE sync_device_heads SET sequence = 99", [])
            .unwrap();
        let forged_next = operation("mutation-100", 100, &first.hash, "entry-b");

        assert!(matches!(
            ChangeStore::save_record_and_operation(
                &mut connection,
                &record("entry-b", "ciphertext-100", 100),
                &forged_next,
                &identity(),
            ),
            Err(StoreError::InvalidOperation(
                "local change head does not match history"
            ))
        ));
        assert_eq!(ChangeStore::operation_count(&connection).unwrap(), 1);
    }

    #[test]
    fn rolls_back_record_when_operation_sequence_conflicts() {
        let mut connection = Connection::open_in_memory().expect("in-memory SQLite must open");
        ChangeStore::initialize(&connection).expect("schema must initialize");
        let original = record("entry-a", "ciphertext-original", 1);
        ChangeStore::save_record_and_operation(
            &mut connection,
            &original,
            &operation("mutation-1", 1, GENESIS_HASH, "entry-a"),
            &identity(),
        )
        .expect("first transaction must commit");

        let changed = record("entry-a", "ciphertext-must-rollback", 1);
        let result = ChangeStore::save_record_and_operation(
            &mut connection,
            &changed,
            &operation("mutation-2", 1, GENESIS_HASH, "entry-a"),
            &identity(),
        );

        assert!(matches!(
            result,
            Err(StoreError::InvalidOperation("broken local change chain"))
        ));
        assert_eq!(
            ChangeStore::record(&connection, "entry", "entry-a").expect("record query"),
            Some(original)
        );
        assert_eq!(
            ChangeStore::operation_count(&connection).expect("operation count"),
            1
        );
    }

    #[test]
    fn rejects_forged_signature_without_changing_record() {
        let mut connection = Connection::open_in_memory().expect("in-memory SQLite must open");
        ChangeStore::initialize(&connection).expect("schema must initialize");
        let mut forged = operation("mutation-1", 1, GENESIS_HASH, "entry-a");
        forged.device_signature = URL_SAFE_NO_PAD.encode([0; 64]);
        forged.hash = forged.compute_hash();

        let result = ChangeStore::save_record_and_operation(
            &mut connection,
            &record("entry-a", "ciphertext-1", 1),
            &forged,
            &identity(),
        );

        assert!(matches!(
            result,
            Err(StoreError::InvalidOperation("device signature is invalid"))
        ));
        assert_eq!(
            ChangeStore::operation_count(&connection).expect("operation count"),
            0
        );
        assert!(
            ChangeStore::record(&connection, "entry", "entry-a")
                .expect("record query")
                .is_none()
        );
    }

    #[test]
    fn commits_only_the_next_signed_link() {
        let mut connection = Connection::open_in_memory().expect("in-memory SQLite must open");
        ChangeStore::initialize(&connection).expect("schema must initialize");
        let first = operation("mutation-1", 1, GENESIS_HASH, "entry-a");
        ChangeStore::save_record_and_operation(
            &mut connection,
            &record("entry-a", "ciphertext-1", 1),
            &first,
            &identity(),
        )
        .expect("first operation must commit");
        let broken = operation("mutation-2", 2, GENESIS_HASH, "entry-a");
        assert!(matches!(
            ChangeStore::save_record_and_operation(
                &mut connection,
                &record("entry-a", "ciphertext-2", 2),
                &broken,
                &identity(),
            ),
            Err(StoreError::InvalidOperation("broken local change chain"))
        ));
        let second = operation("mutation-2", 2, &first.hash, "entry-a");
        ChangeStore::save_record_and_operation(
            &mut connection,
            &record("entry-a", "ciphertext-2", 2),
            &second,
            &identity(),
        )
        .expect("next signed operation must commit");
        assert_eq!(
            ChangeStore::operation_count(&connection).expect("operation count"),
            2
        );
    }

    #[test]
    fn delete_keeps_a_tombstone_and_rolls_back_on_operation_failure() {
        let mut connection = Connection::open_in_memory().expect("in-memory SQLite must open");
        ChangeStore::initialize(&connection).expect("schema must initialize");
        let first = operation("mutation-1", 1, GENESIS_HASH, "entry-a");
        let record = record("entry-a", "ciphertext-1", 1);
        ChangeStore::save_record_and_operation(&mut connection, &record, &first, &identity())
            .expect("first operation must commit");

        let duplicate = delete_operation("mutation-1", &first.hash);
        assert!(matches!(
            ChangeStore::delete_record_and_operation(&mut connection, &duplicate, &identity()),
            Err(StoreError::Sqlite(_))
        ));
        assert_eq!(
            ChangeStore::record(&connection, "entry", "entry-a").unwrap(),
            Some(record)
        );

        let deletion = delete_operation("mutation-2", &first.hash);
        ChangeStore::delete_record_and_operation(&mut connection, &deletion, &identity())
            .expect("delete and tombstone must commit");
        assert!(
            ChangeStore::record(&connection, "entry", "entry-a")
                .unwrap()
                .is_none()
        );
        let hash: String = connection.query_row(
            "SELECT change_hash FROM sync_tombstones WHERE entity_type = 'entry' AND entity_id = 'entry-a'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(hash, deletion.hash);
        assert_eq!(ChangeStore::operation_count(&connection).unwrap(), 2);
    }
}
