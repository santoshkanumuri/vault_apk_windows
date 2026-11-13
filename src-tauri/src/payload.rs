use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::sync::ChangeRecord;

const MAX_PLAINTEXT: usize = 1_048_576;
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 16;
const KEY_LABEL: &[u8] = b"nuvori-sync-payload-key-v1";

pub struct EncryptedPayload {
    pub ciphertext: String,
    pub nonce: String,
}

pub fn encrypt(
    content_key: &[u8],
    entity_type: &str,
    vault_id: &str,
    mutation_id: &str,
    entity_id: &str,
    plaintext: &[u8],
) -> Result<EncryptedPayload, PayloadError> {
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|error| PayloadError::Random(error.to_string()))?;
    encrypt_with_nonce(
        content_key,
        entity_type,
        vault_id,
        mutation_id,
        entity_id,
        plaintext,
        nonce,
    )
}

pub fn decrypt(content_key: &[u8], change: &ChangeRecord) -> Result<Vec<u8>, PayloadError> {
    if change.payload_ciphertext.len() > 1_500_000 {
        return Err(PayloadError::InvalidPayload);
    }
    let ciphertext = URL_SAFE_NO_PAD.decode(&change.payload_ciphertext)?;
    let nonce: [u8; 12] = URL_SAFE_NO_PAD
        .decode(&change.payload_nonce)?
        .try_into()
        .map_err(|_| PayloadError::InvalidPayload)?;
    if !(16..=MAX_CIPHERTEXT).contains(&ciphertext.len()) {
        return Err(PayloadError::InvalidPayload);
    }
    let key = derive_key(content_key)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).expect("32-byte key");
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: aad(
                    &change.entity_type,
                    &change.vault_id,
                    &change.mutation_id,
                    &change.entity_id,
                )
                .as_bytes(),
            },
        )
        .map_err(|_| PayloadError::AuthenticationFailed)
}

fn encrypt_with_nonce(
    content_key: &[u8],
    entity_type: &str,
    vault_id: &str,
    mutation_id: &str,
    entity_id: &str,
    plaintext: &[u8],
    nonce: [u8; 12],
) -> Result<EncryptedPayload, PayloadError> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(PayloadError::InvalidPayload);
    }
    let key = derive_key(content_key)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).expect("32-byte key");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: aad(entity_type, vault_id, mutation_id, entity_id).as_bytes(),
            },
        )
        .map_err(|_| PayloadError::AuthenticationFailed)?;
    Ok(EncryptedPayload {
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
    })
}

fn derive_key(content_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, PayloadError> {
    if content_key.len() != 32 {
        return Err(PayloadError::InvalidContentKey);
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(content_key).expect("32-byte key");
    mac.update(KEY_LABEL);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn aad(entity_type: &str, vault_id: &str, mutation_id: &str, entity_id: &str) -> String {
    format!("nuvori-sync-{entity_type}-v1:{vault_id}:{mutation_id}:{entity_id}")
}

#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("content key must be 32 bytes")]
    InvalidContentKey,
    #[error("invalid sync payload size or nonce")]
    InvalidPayload,
    #[error("sync payload authentication failed")]
    AuthenticationFailed,
    #[error("sync payload encoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("secure random generation failed: {0}")]
    Random(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::RecordVersion,
        sync::{ChangeKind, GENESIS_HASH},
    };

    fn change(payload: EncryptedPayload) -> ChangeRecord {
        ChangeRecord::create(
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
            payload.ciphertext,
            payload.nonce,
            "test-signature",
        )
    }

    #[test]
    fn matches_android_payload_format_and_binds_record_identity() {
        let key: Vec<u8> = (0..32).collect();
        let encrypted = encrypt_with_nonce(
            &key,
            "entry",
            "vault-a",
            "mutation-a",
            "entry-a",
            br#"{"deleted":true}"#,
            (0..12).collect::<Vec<_>>().try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(encrypted.nonce, "AAECAwQFBgcICQoL");
        assert_eq!(
            encrypted.ciphertext,
            "LWKXFqeXgeG1ZfM7H4dtiB0qQdbDdDeINRqisF0MXKk"
        );
        let operation = change(encrypted);
        assert_eq!(decrypt(&key, &operation).unwrap(), br#"{"deleted":true}"#);
        let mut changed = operation.clone();
        changed.entity_id = "another-entry".to_owned();
        assert!(matches!(
            decrypt(&key, &changed),
            Err(PayloadError::AuthenticationFailed)
        ));
    }
}
