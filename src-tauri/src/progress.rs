use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::sync::GENESIS_HASH;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncProgress {
    pub received: BTreeMap<String, (u64, String)>,
    pub applied: BTreeMap<String, (u64, String)>,
}

impl SyncProgress {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProgressError> {
        if !(1..=100_000).contains(&bytes.len()) {
            return Err(ProgressError::InvalidSize);
        }
        let progress: Self = serde_json::from_slice(bytes)?;
        progress.validate()?;
        Ok(progress)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProgressError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self)?;
        if encoded.len() > 100_000 {
            return Err(ProgressError::InvalidSize);
        }
        Ok(encoded)
    }

    pub fn validate(&self) -> Result<(), ProgressError> {
        if self.received.len() > 256 || self.applied.len() > 256 {
            return Err(ProgressError::InvalidHead);
        }
        for (device_id, (sequence, hash)) in self.received.iter().chain(self.applied.iter()) {
            if device_id.trim().is_empty()
                || device_id.chars().count() > 128
                || *sequence > i64::MAX as u64
                || hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || *sequence == 0 && hash != GENESIS_HASH
            {
                return Err(ProgressError::InvalidHead);
            }
        }
        for (device_id, (applied_sequence, applied_hash)) in &self.applied {
            let Some((received_sequence, received_hash)) = self.received.get(device_id) else {
                return Err(ProgressError::AppliedExceedsReceived);
            };
            if applied_sequence > received_sequence
                || applied_sequence == received_sequence && applied_hash != received_hash
            {
                return Err(ProgressError::AppliedExceedsReceived);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ProgressError {
    #[error("invalid sync progress size")]
    InvalidSize,
    #[error("invalid sync chain head")]
    InvalidHead,
    #[error("applied progress exceeds received progress")]
    AppliedExceedsReceived,
    #[error("invalid sync progress JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_android_progress_encoding() {
        let progress = SyncProgress {
            received: BTreeMap::from([
                ("phone".to_owned(), (2, "a".repeat(64))),
                ("windows".to_owned(), (0, GENESIS_HASH.to_owned())),
            ]),
            applied: BTreeMap::from([("phone".to_owned(), (1, "b".repeat(64)))]),
        };
        let expected = format!(
            "{{\"received\":{{\"phone\":[2,\"{}\"],\"windows\":[0,\"{}\"]}},\"applied\":{{\"phone\":[1,\"{}\"]}}}}",
            "a".repeat(64),
            GENESIS_HASH,
            "b".repeat(64),
        );
        assert_eq!(progress.encode().unwrap(), expected.as_bytes());
        assert_eq!(SyncProgress::parse(expected.as_bytes()).unwrap(), progress);
    }

    #[test]
    fn rejects_applied_head_past_received_head() {
        let progress = SyncProgress {
            received: BTreeMap::from([("phone".to_owned(), (1, "a".repeat(64)))]),
            applied: BTreeMap::from([("phone".to_owned(), (2, "b".repeat(64)))]),
        };
        assert!(matches!(
            progress.validate(),
            Err(ProgressError::AppliedExceedsReceived)
        ));
    }
}
