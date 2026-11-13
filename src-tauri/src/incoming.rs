//! Validates Android-compatible incoming sync operations before durable staging.
//!
//! This module verifies signatures and per-device hash-chain continuity. It does not
//! authenticate a transport, authorize membership, decrypt payloads, or persist data.

use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;

use crate::{
    identity::verify_signature,
    sync::{ChangeRecord, SYNC_FORMAT_VERSION},
};

pub const MAX_INCOMING_BATCH: usize = 100;
const MAX_CIPHERTEXT_BASE64: usize = 1_500_000;
const MAX_TEXT_FIELD: usize = 4096;

/// A verifier for one authenticated remote device's operation stream.
pub struct IncomingVerifier {
    vault_id: String,
    device_id: String,
    public_key: [u8; 32],
    sequence: u64,
    hash: String,
}

/// A fully checked batch. Call `commit` only after the caller durably stores every record.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedBatch {
    start_sequence: u64,
    start_hash: String,
    records: Vec<ChangeRecord>,
    end_sequence: u64,
    end_hash: String,
}

impl VerifiedBatch {
    pub fn records(&self) -> &[ChangeRecord] {
        &self.records
    }
}

impl IncomingVerifier {
    pub fn new(
        vault_id: impl Into<String>,
        device_id: impl Into<String>,
        public_key: [u8; 32],
        sequence: u64,
        hash: impl Into<String>,
    ) -> Result<Self, IncomingError> {
        let vault_id = vault_id.into();
        let device_id = device_id.into();
        let hash = hash.into();
        if vault_id.trim().is_empty() || device_id.trim().is_empty() {
            return Err(IncomingError::InvalidIdentity);
        }
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(IncomingError::InvalidHead);
        }
        if sequence == 0 && hash != crate::sync::GENESIS_HASH {
            return Err(IncomingError::InvalidHead);
        }
        Ok(Self {
            vault_id,
            device_id,
            public_key,
            sequence,
            hash,
        })
    }

    /// Checks a complete bounded batch without advancing this verifier's cursor.
    pub fn verify_batch(&self, records: Vec<ChangeRecord>) -> Result<VerifiedBatch, IncomingError> {
        if records.is_empty() || records.len() > MAX_INCOMING_BATCH {
            return Err(IncomingError::InvalidBatchSize);
        }

        let mut expected_sequence = self.sequence;
        let mut previous_hash = self.hash.clone();
        let mut mutation_ids = HashSet::with_capacity(records.len());

        for record in &records {
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(IncomingError::SequenceOverflow)?;
            validate_record(
                record,
                &self.vault_id,
                &self.device_id,
                &self.public_key,
                expected_sequence,
                &previous_hash,
            )?;
            if !mutation_ids.insert(record.mutation_id.as_str()) {
                return Err(IncomingError::DuplicateMutation);
            }
            previous_hash.clone_from(&record.hash);
        }

        Ok(VerifiedBatch {
            start_sequence: self.sequence,
            start_hash: self.hash.clone(),
            records,
            end_sequence: expected_sequence,
            end_hash: previous_hash,
        })
    }

    /// Advances the cursor after the verified records have been committed durably.
    pub fn commit(&mut self, batch: &VerifiedBatch) -> Result<(), IncomingError> {
        if self.sequence != batch.start_sequence || self.hash != batch.start_hash {
            return Err(IncomingError::StaleBatch);
        }
        self.sequence = batch.end_sequence;
        self.hash.clone_from(&batch.end_hash);
        Ok(())
    }

    pub fn head(&self) -> (u64, &str) {
        (self.sequence, &self.hash)
    }
}

fn validate_record(
    record: &ChangeRecord,
    vault_id: &str,
    device_id: &str,
    public_key: &[u8; 32],
    expected_sequence: u64,
    previous_hash: &str,
) -> Result<(), IncomingError> {
    if record.format_version != SYNC_FORMAT_VERSION {
        return Err(IncomingError::InvalidRecord("unsupported format"));
    }
    if record.vault_id != vault_id || record.device_id != device_id {
        return Err(IncomingError::WrongStream);
    }
    if record.sequence != expected_sequence {
        return Err(IncomingError::SequenceGap {
            expected: expected_sequence,
            actual: record.sequence,
        });
    }
    if record.previous_hash != previous_hash {
        return Err(IncomingError::BrokenLink);
    }
    if record.hash.len() != 64
        || !record.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        || record.hash != record.compute_hash()
    {
        return Err(IncomingError::InvalidRecord("hash mismatch"));
    }
    if record.mutation_id.trim().is_empty()
        || record.entity_type.trim().is_empty()
        || record.entity_id.trim().is_empty()
        || record.occurred_at_utc.trim().is_empty()
        || record.mutation_id.len() > MAX_TEXT_FIELD
        || record.entity_type.len() > MAX_TEXT_FIELD
        || record.entity_id.len() > MAX_TEXT_FIELD
        || record.occurred_at_utc.len() > MAX_TEXT_FIELD
    {
        return Err(IncomingError::InvalidRecord("invalid text field"));
    }
    record
        .record_version
        .validate()
        .map_err(|_| IncomingError::InvalidRecord("invalid record version"))?;

    if record.payload_ciphertext.len() > MAX_CIPHERTEXT_BASE64 {
        return Err(IncomingError::InvalidRecord("invalid ciphertext size"));
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&record.payload_ciphertext)
        .map_err(|_| IncomingError::InvalidRecord("invalid ciphertext encoding"))?;
    if ciphertext.len() < 16 {
        return Err(IncomingError::InvalidRecord("invalid ciphertext size"));
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&record.payload_nonce)
        .map_err(|_| IncomingError::InvalidRecord("invalid nonce encoding"))?;
    if nonce.len() != 12 {
        return Err(IncomingError::InvalidRecord("invalid nonce size"));
    }
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&record.device_signature)
        .map_err(|_| IncomingError::InvalidRecord("invalid signature encoding"))?
        .try_into()
        .map_err(|_| IncomingError::InvalidRecord("invalid signature size"))?;
    if !verify_signature(public_key, &record.signing_bytes(), &signature) {
        return Err(IncomingError::InvalidSignature);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IncomingError {
    #[error("incoming batch size is invalid")]
    InvalidBatchSize,
    #[error("incoming stream identity is invalid")]
    InvalidIdentity,
    #[error("incoming stream head is invalid")]
    InvalidHead,
    #[error("incoming operation belongs to a different stream")]
    WrongStream,
    #[error("expected sequence {expected}, found {actual}")]
    SequenceGap { expected: u64, actual: u64 },
    #[error("incoming operation does not extend the known hash chain")]
    BrokenLink,
    #[error("incoming operation is invalid: {0}")]
    InvalidRecord(&'static str),
    #[error("incoming operation signature is invalid")]
    InvalidSignature,
    #[error("incoming batch repeats a mutation id")]
    DuplicateMutation,
    #[error("incoming sequence counter overflowed")]
    SequenceOverflow,
    #[error("verified batch was checked against a stale stream head")]
    StaleBatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::RecordVersion,
        sync::{ChangeKind, GENESIS_HASH},
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(sequence: u64, previous_hash: &str, mutation_id: &str) -> ChangeRecord {
        let key = SigningKey::from_bytes(&[19; 32]);
        ChangeRecord::create_signed_with(
            "vault-a",
            "device-a",
            sequence,
            previous_hash,
            mutation_id,
            "entry",
            format!("entry-{sequence}"),
            ChangeKind::Upsert,
            sequence - 1,
            RecordVersion::from_entries([("device-a", sequence)]),
            "2026-09-26T12:00:00Z",
            URL_SAFE_NO_PAD.encode([8_u8; 16]),
            URL_SAFE_NO_PAD.encode([9_u8; 12]),
            |bytes| Ok::<_, ()>(key.sign(bytes).to_bytes()),
        )
        .unwrap()
    }

    fn verifier() -> IncomingVerifier {
        let key = SigningKey::from_bytes(&[19; 32]);
        IncomingVerifier::new(
            "vault-a",
            "device-a",
            key.verifying_key().to_bytes(),
            0,
            GENESIS_HASH,
        )
        .unwrap()
    }

    #[test]
    fn verifies_then_commits_a_signed_android_compatible_chain() {
        let mut verifier = verifier();
        let first = signed(1, GENESIS_HASH, "mutation-1");
        let second = signed(2, &first.hash, "mutation-2");
        let batch = verifier.verify_batch(vec![first, second]).unwrap();

        assert_eq!(verifier.head(), (0, GENESIS_HASH));
        assert_eq!(batch.records().len(), 2);
        verifier.commit(&batch).unwrap();
        assert_eq!(verifier.head(), (2, batch.end_hash.as_str()));
    }

    #[test]
    fn rejects_bad_signature_and_leaves_head_unchanged() {
        let verifier = verifier();
        let mut record = signed(1, GENESIS_HASH, "mutation-1");
        record.device_signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
        record.hash = record.compute_hash();

        assert_eq!(
            verifier.verify_batch(vec![record]),
            Err(IncomingError::InvalidSignature)
        );
        assert_eq!(verifier.head(), (0, GENESIS_HASH));
    }

    #[test]
    fn rejects_a_bad_later_record_without_staging_the_batch() {
        let verifier = verifier();
        let first = signed(1, GENESIS_HASH, "mutation-1");
        let mut second = signed(2, &first.hash, "mutation-2");
        second.previous_hash = "f".repeat(64);
        second.hash = second.compute_hash();

        assert_eq!(
            verifier.verify_batch(vec![first, second]),
            Err(IncomingError::BrokenLink)
        );
    }

    #[test]
    fn rejects_stale_commit_and_out_of_bound_batches() {
        let mut verifier = verifier();
        let batch_a = verifier
            .verify_batch(vec![signed(1, GENESIS_HASH, "mutation-1")])
            .unwrap();
        let batch_b = verifier
            .verify_batch(vec![signed(1, GENESIS_HASH, "mutation-1")])
            .unwrap();
        verifier.commit(&batch_a).unwrap();
        assert_eq!(verifier.commit(&batch_b), Err(IncomingError::StaleBatch));
        assert_eq!(
            verifier.verify_batch(vec![
                signed(2, &batch_a.end_hash, "mutation-2");
                MAX_INCOMING_BATCH + 1
            ]),
            Err(IncomingError::InvalidBatchSize)
        );
    }
}
