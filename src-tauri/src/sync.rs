use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::protocol::{ProtocolError, RecordVersion};

pub const SYNC_FORMAT_VERSION: u16 = 1;
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ChangeKind {
    Upsert,
    Delete,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRecord {
    pub format_version: u16,
    pub vault_id: String,
    pub device_id: String,
    pub sequence: u64,
    pub previous_hash: String,
    pub mutation_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub kind: ChangeKind,
    pub base_revision: u64,
    pub record_version: RecordVersion,
    pub occurred_at_utc: String,
    pub payload_ciphertext: String,
    pub payload_nonce: String,
    pub device_signature: String,
    pub hash: String,
}

impl ChangeRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        vault_id: impl Into<String>,
        device_id: impl Into<String>,
        sequence: u64,
        previous_hash: impl Into<String>,
        mutation_id: impl Into<String>,
        entity_type: impl Into<String>,
        entity_id: impl Into<String>,
        kind: ChangeKind,
        base_revision: u64,
        record_version: RecordVersion,
        occurred_at_utc: impl Into<String>,
        payload_ciphertext: impl Into<String>,
        payload_nonce: impl Into<String>,
        device_signature: impl Into<String>,
    ) -> Self {
        let mut record = Self {
            format_version: SYNC_FORMAT_VERSION,
            vault_id: vault_id.into(),
            device_id: device_id.into(),
            sequence,
            previous_hash: previous_hash.into(),
            mutation_id: mutation_id.into(),
            entity_type: entity_type.into(),
            entity_id: entity_id.into(),
            kind,
            base_revision,
            record_version,
            occurred_at_utc: occurred_at_utc.into(),
            payload_ciphertext: payload_ciphertext.into(),
            payload_nonce: payload_nonce.into(),
            device_signature: device_signature.into(),
            hash: String::new(),
        };
        record.hash = record.compute_hash();
        record
    }

    pub fn compute_hash(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes(true)))
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        self.canonical_bytes(false)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_signed_with<E>(
        vault_id: impl Into<String>,
        device_id: impl Into<String>,
        sequence: u64,
        previous_hash: impl Into<String>,
        mutation_id: impl Into<String>,
        entity_type: impl Into<String>,
        entity_id: impl Into<String>,
        kind: ChangeKind,
        base_revision: u64,
        record_version: RecordVersion,
        occurred_at_utc: impl Into<String>,
        payload_ciphertext: impl Into<String>,
        payload_nonce: impl Into<String>,
        signer: impl FnOnce(&[u8]) -> Result<[u8; 64], E>,
    ) -> Result<Self, E> {
        let mut record = Self {
            format_version: SYNC_FORMAT_VERSION,
            vault_id: vault_id.into(),
            device_id: device_id.into(),
            sequence,
            previous_hash: previous_hash.into(),
            mutation_id: mutation_id.into(),
            entity_type: entity_type.into(),
            entity_id: entity_id.into(),
            kind,
            base_revision,
            record_version,
            occurred_at_utc: occurred_at_utc.into(),
            payload_ciphertext: payload_ciphertext.into(),
            payload_nonce: payload_nonce.into(),
            device_signature: String::new(),
            hash: String::new(),
        };
        record.device_signature = URL_SAFE_NO_PAD.encode(signer(&record.signing_bytes())?);
        record.hash = record.compute_hash();
        Ok(record)
    }

    fn canonical_bytes(&self, include_signature: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_field(&mut bytes, &self.format_version.to_be_bytes());
        append_field(&mut bytes, self.vault_id.as_bytes());
        append_field(&mut bytes, self.device_id.as_bytes());
        append_field(&mut bytes, &self.sequence.to_be_bytes());
        append_field(&mut bytes, self.previous_hash.as_bytes());
        append_field(&mut bytes, self.mutation_id.as_bytes());
        append_field(&mut bytes, self.entity_type.as_bytes());
        append_field(&mut bytes, self.entity_id.as_bytes());
        append_field(
            &mut bytes,
            match self.kind {
                ChangeKind::Upsert => b"upsert",
                ChangeKind::Delete => b"delete",
            },
        );
        append_field(&mut bytes, &self.base_revision.to_be_bytes());
        append_field(
            &mut bytes,
            &(self.record_version.counters().len() as u64).to_be_bytes(),
        );
        for (device_id, counter) in self.record_version.counters() {
            append_field(&mut bytes, device_id.as_bytes());
            append_field(&mut bytes, &counter.to_be_bytes());
        }
        append_field(&mut bytes, self.occurred_at_utc.as_bytes());
        append_field(&mut bytes, self.payload_ciphertext.as_bytes());
        append_field(&mut bytes, self.payload_nonce.as_bytes());
        if include_signature {
            append_field(&mut bytes, self.device_signature.as_bytes());
        }
        bytes
    }
}

fn append_field(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("unsupported sync format at sequence {sequence}")]
    UnsupportedFormat { sequence: u64 },
    #[error("expected sequence {expected}, found {actual}")]
    SequenceGap { expected: u64, actual: u64 },
    #[error("previous hash does not match at sequence {sequence}")]
    BrokenLink { sequence: u64 },
    #[error("record contents do not match its hash at sequence {sequence}")]
    ContentChanged { sequence: u64 },
    #[error("invalid record version at sequence {sequence}: {reason}")]
    InvalidRecordVersion {
        sequence: u64,
        reason: ProtocolError,
    },
}

pub fn validate_chain(records: &[ChangeRecord]) -> Result<(), ChainError> {
    let mut expected_previous = GENESIS_HASH;

    for (expected_sequence, record) in (1_u64..).zip(records) {
        if record.format_version != SYNC_FORMAT_VERSION {
            return Err(ChainError::UnsupportedFormat {
                sequence: record.sequence,
            });
        }
        if record.sequence != expected_sequence {
            return Err(ChainError::SequenceGap {
                expected: expected_sequence,
                actual: record.sequence,
            });
        }
        if record.previous_hash != expected_previous {
            return Err(ChainError::BrokenLink {
                sequence: record.sequence,
            });
        }
        if let Err(reason) = record.record_version.validate() {
            return Err(ChainError::InvalidRecordVersion {
                sequence: record.sequence,
                reason,
            });
        }
        if record.hash != record.compute_hash() {
            return Err(ChainError::ContentChanged {
                sequence: record.sequence,
            });
        }

        expected_previous = &record.hash;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::verify_signature;
    use ed25519_dalek::{Signer, SigningKey};

    fn record(sequence: u64, previous_hash: &str, entity_id: &str) -> ChangeRecord {
        ChangeRecord::create(
            "vault-a",
            "device-a",
            sequence,
            previous_hash,
            format!("mutation-{sequence}"),
            "login",
            entity_id,
            ChangeKind::Upsert,
            sequence - 1,
            RecordVersion::from_entries([("device-a", sequence)]),
            "2026-09-21T12:00:00Z",
            "ciphertext-placeholder",
            "nonce-placeholder",
            "signature-placeholder",
        )
    }

    #[test]
    fn accepts_an_ordered_chain() {
        let first = record(1, GENESIS_HASH, "login-a");
        let second = record(2, &first.hash, "login-b");

        assert_eq!(validate_chain(&[first, second]), Ok(()));
    }

    #[test]
    fn rejects_changed_content() {
        let mut first = record(1, GENESIS_HASH, "login-a");
        first.entity_id = "login-tampered".to_owned();

        assert_eq!(
            validate_chain(&[first]),
            Err(ChainError::ContentChanged { sequence: 1 })
        );
    }

    #[test]
    fn rejects_a_missing_record() {
        let first = record(1, GENESIS_HASH, "login-a");
        let third = record(3, &first.hash, "login-c");

        assert_eq!(
            validate_chain(&[first, third]),
            Err(ChainError::SequenceGap {
                expected: 2,
                actual: 3,
            })
        );
    }

    #[test]
    fn deletion_is_a_first_class_change() {
        let deletion = ChangeRecord::create(
            "vault-a",
            "device-a",
            1,
            GENESIS_HASH,
            "mutation-1",
            "login",
            "login-a",
            ChangeKind::Delete,
            4,
            RecordVersion::from_entries([("device-a", 5)]),
            "2026-09-21T12:00:00Z",
            "encrypted-tombstone",
            "nonce-placeholder",
            "signature-placeholder",
        );

        assert_eq!(deletion.kind, ChangeKind::Delete);
        assert_eq!(validate_chain(&[deletion]), Ok(()));
    }

    #[test]
    fn rejects_an_empty_record_version() {
        let mut first = record(1, GENESIS_HASH, "login-a");
        first.record_version = RecordVersion::default();
        first.hash = first.compute_hash();

        assert_eq!(
            validate_chain(&[first]),
            Err(ChainError::InvalidRecordVersion {
                sequence: 1,
                reason: ProtocolError::EmptyRecordVersion,
            })
        );
    }

    #[test]
    fn signs_canonical_operation_bytes() {
        let seed = std::array::from_fn(|index| index as u8);
        let signing_key = SigningKey::from_bytes(&seed);
        let record = ChangeRecord::create_signed_with(
            "vault-a",
            "device-a",
            1,
            GENESIS_HASH,
            "mutation-a",
            "entry",
            "entry-a",
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([("device-a", 1)]),
            "2026-09-22T12:00:00Z",
            "ciphertext",
            "nonce",
            |message| Ok::<_, ()>(signing_key.sign(message).to_bytes()),
        )
        .expect("signing must succeed");
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&record.device_signature)
            .expect("signature must be base64url")
            .try_into()
            .expect("signature must be 64 bytes");
        assert_eq!(
            record.device_signature,
            "op50N3zIarrPOcIDnVStIIufMEMpoDsSvhyVvoBmhm3Xt6MKstl08Ka4o1ETreGaWl3cbeTD8iVREtgvyoqlBg",
        );
        assert_eq!(
            record.hash,
            "e01a1d9910027109f4a8745691c9fcf691a1a786c6823dadf0d9f9588184aac8",
        );

        assert!(verify_signature(
            &signing_key.verifying_key().to_bytes(),
            &record.signing_bytes(),
            &signature,
        ));
        let mut changed = record.clone();
        changed.entity_id = "changed".to_owned();
        assert!(!verify_signature(
            &signing_key.verifying_key().to_bytes(),
            &changed.signing_bytes(),
            &signature,
        ));
    }
}
