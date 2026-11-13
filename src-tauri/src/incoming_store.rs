//! Atomically persists an already verified remote operation batch.
//!
//! Membership, transport authentication, payload decryption, and materializing vault
//! records remain the responsibility of their respective callers.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use thiserror::Error;

use crate::{
    incoming::VerifiedBatch,
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
};

pub struct IncomingStore;

impl IncomingStore {
    /// Writes all operations and advances the stream head in one SQLite transaction.
    /// The caller advances its in-memory verifier only after this returns `Ok(())`.
    pub fn persist_batch(
        connection: &mut Connection,
        batch: &VerifiedBatch,
    ) -> Result<(), IncomingStoreError> {
        let records = batch.records();
        let first = records.first().ok_or(IncomingStoreError::InvalidBatch)?;
        let last = records.last().ok_or(IncomingStoreError::InvalidBatch)?;
        let start_sequence = first
            .sequence
            .checked_sub(1)
            .ok_or(IncomingStoreError::InvalidBatch)?;

        let transaction = connection.transaction()?;
        transaction.execute_batch("CREATE TABLE IF NOT EXISTS sync_received_operations (
            mutation_id TEXT NOT NULL PRIMARY KEY REFERENCES sync_operations(mutation_id)
        )")?;
        let current_head = read_head(&transaction, &first.vault_id, &first.device_id)?
            .unwrap_or((0, GENESIS_HASH.to_owned()));
        if current_head != (start_sequence, first.previous_hash.clone()) {
            return Err(IncomingStoreError::HeadMismatch);
        }
        validate_stored_history(
            &transaction,
            &first.vault_id,
            &first.device_id,
            current_head.0,
            &current_head.1,
        )?;

        let mut expected_sequence = start_sequence;
        let mut expected_previous = first.previous_hash.as_str();
        for operation in records {
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(IncomingStoreError::IntegerOverflow)?;
            if operation.vault_id != first.vault_id
                || operation.device_id != first.device_id
                || operation.sequence != expected_sequence
                || operation.previous_hash != expected_previous
            {
                return Err(IncomingStoreError::InvalidBatch);
            }
            insert_operation(&transaction, operation)?;
            transaction.execute("INSERT INTO sync_received_operations (mutation_id) VALUES (?1)", [&operation.mutation_id])?;
            expected_previous = &operation.hash;
        }

        transaction.execute(
            "INSERT INTO sync_device_heads (vault_id, device_id, sequence, hash)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(vault_id, device_id) DO UPDATE SET
                 sequence = excluded.sequence,
                 hash = excluded.hash",
            params![
                first.vault_id,
                first.device_id,
                to_i64(last.sequence)?,
                last.hash,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn read_head(
    transaction: &Transaction<'_>,
    vault_id: &str,
    device_id: &str,
) -> Result<Option<(u64, String)>, IncomingStoreError> {
    transaction
        .query_row(
            "SELECT sequence, hash FROM sync_device_heads WHERE vault_id = ?1 AND device_id = ?2",
            params![vault_id, device_id],
            |row| {
                let sequence: i64 = row.get(0)?;
                let hash: String = row.get(1)?;
                Ok((sequence, hash))
            },
        )
        .optional()?
        .map(|(sequence, hash)| {
            u64::try_from(sequence)
                .map(|sequence| (sequence, hash))
                .map_err(|_| IncomingStoreError::CorruptHistory)
        })
        .transpose()
}

fn validate_stored_history(
    transaction: &Transaction<'_>,
    vault_id: &str,
    device_id: &str,
    head_sequence: u64,
    head_hash: &str,
) -> Result<(), IncomingStoreError> {
    let latest: Option<(i64, String)> = transaction
        .query_row(
            "SELECT sequence, hash FROM sync_operations
             WHERE vault_id = ?1 AND device_id = ?2
             ORDER BY sequence DESC LIMIT 1",
            params![vault_id, device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let latest = latest
        .map(|(sequence, hash)| {
            u64::try_from(sequence)
                .map(|sequence| (sequence, hash))
                .map_err(|_| IncomingStoreError::CorruptHistory)
        })
        .transpose()?;
    let expected = if head_sequence == 0 {
        None
    } else {
        Some((head_sequence, head_hash.to_owned()))
    };
    if latest != expected {
        return Err(IncomingStoreError::CorruptHistory);
    }
    Ok(())
}

fn insert_operation(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
) -> Result<(), IncomingStoreError> {
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
    Ok(())
}

fn to_i64(value: u64) -> Result<i64, IncomingStoreError> {
    value
        .try_into()
        .map_err(|_| IncomingStoreError::IntegerOverflow)
}

#[derive(Debug, Error)]
pub enum IncomingStoreError {
    #[error("encrypted database operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("incoming operation serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("verified incoming batch is empty or inconsistent")]
    InvalidBatch,
    #[error("stored device head does not match the incoming batch")]
    HeadMismatch,
    #[error("stored operation history does not match its device head")]
    CorruptHistory,
    #[error("incoming sync counter is too large for SQLite")]
    IntegerOverflow,
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use rusqlite::Connection;

    use crate::{
        change_store::ChangeStore,
        incoming::{IncomingVerifier, VerifiedBatch},
        protocol::RecordVersion,
        sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
    };

    use super::{IncomingStore, IncomingStoreError};

    fn open_store() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        ChangeStore::initialize(&connection).unwrap();
        connection
    }

    fn make_batch() -> (IncomingVerifier, VerifiedBatch) {
        let signer = SigningKey::from_bytes(&[31; 32]);
        let verifier = IncomingVerifier::new(
            "vault-a",
            "device-b",
            signer.verifying_key().to_bytes(),
            0,
            GENESIS_HASH,
        )
        .unwrap();
        let first = signed(&signer, 1, GENESIS_HASH, "mutation-1");
        let second = signed(&signer, 2, &first.hash, "mutation-2");
        let batch = verifier.verify_batch(vec![first, second]).unwrap();
        (verifier, batch)
    }

    fn signed(
        signer: &SigningKey,
        sequence: u64,
        previous_hash: &str,
        mutation_id: &str,
    ) -> ChangeRecord {
        ChangeRecord::create_signed_with(
            "vault-a",
            "device-b",
            sequence,
            previous_hash,
            mutation_id,
            "entry",
            format!("entry-{sequence}"),
            ChangeKind::Upsert,
            sequence - 1,
            RecordVersion::from_entries([("device-b", sequence)]),
            "2026-09-26T12:00:00Z",
            URL_SAFE_NO_PAD.encode([8_u8; 16]),
            URL_SAFE_NO_PAD.encode([9_u8; 12]),
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()),
        )
        .unwrap()
    }

    fn stored_counts(connection: &Connection) -> (i64, i64) {
        let operations = connection
            .query_row("SELECT COUNT(*) FROM sync_operations", [], |row| row.get(0))
            .unwrap();
        let heads = connection
            .query_row("SELECT COUNT(*) FROM sync_device_heads", [], |row| {
                row.get(0)
            })
            .unwrap();
        (operations, heads)
    }

    #[test]
    fn persists_the_batch_before_the_verifier_cursor_advances() {
        let mut connection = open_store();
        let (mut verifier, batch) = make_batch();

        IncomingStore::persist_batch(&mut connection, &batch).unwrap();
        assert_eq!(stored_counts(&connection), (2, 1));
        assert_eq!(verifier.head(), (0, GENESIS_HASH));

        verifier.commit(&batch).unwrap();
        assert_eq!(
            verifier.head(),
            (2, batch.records().last().unwrap().hash.as_str())
        );
    }

    #[test]
    fn second_insert_failure_rolls_back_operations_and_head() {
        let mut connection = open_store();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_second_incoming_operation
                 BEFORE INSERT ON sync_operations WHEN NEW.sequence = 2
                 BEGIN SELECT RAISE(ABORT, 'test rejection'); END;",
            )
            .unwrap();
        let (verifier, batch) = make_batch();

        assert!(matches!(
            IncomingStore::persist_batch(&mut connection, &batch),
            Err(IncomingStoreError::Sqlite(_))
        ));
        assert_eq!(stored_counts(&connection), (0, 0));
        assert_eq!(verifier.head(), (0, GENESIS_HASH));
    }

    #[test]
    fn rejects_a_database_head_that_does_not_match_the_batch_start() {
        let mut connection = open_store();
        connection
            .execute(
                "INSERT INTO sync_device_heads (vault_id, device_id, sequence, hash)
                 VALUES ('vault-a', 'device-b', 1, ?1)",
                ["a".repeat(64)],
            )
            .unwrap();
        let (_, batch) = make_batch();

        assert!(matches!(
            IncomingStore::persist_batch(&mut connection, &batch),
            Err(IncomingStoreError::HeadMismatch)
        ));
        assert_eq!(stored_counts(&connection), (0, 1));
    }
}
