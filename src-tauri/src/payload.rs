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

/// Encrypts a change this PC writes. After a key rotation it uses the newest content key that
/// `vault.db` holds (`epoch_keys::write_key_in`), read for every write, so nothing in memory (a
/// keyring another vault instance cleared, C1 of the review) can make it write with K(1).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_in(
    db: &rusqlite::Connection,
    content_key: &[u8],
    entity_type: &str,
    vault_id: &str,
    mutation_id: &str,
    entity_id: &str,
    plaintext: &[u8],
) -> Result<EncryptedPayload, PayloadError> {
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|error| PayloadError::Random(error.to_string()))?;
    if let Some((epoch, key)) = crate::epoch_keys::write_key_in(db, vault_id).map_err(|error| PayloadError::Storage(error.to_string()))? {
        return encrypt_epoch(&*key, epoch, entity_type, vault_id, mutation_id, entity_id, plaintext, nonce);
    }
    encrypt_with_nonce(content_key, entity_type, vault_id, mutation_id, entity_id, plaintext, nonce)
}

/// Epoch-1 encryption for tests that build changes without a vault.
#[cfg(test)]
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

/// Epoch N >= 2: nonce field `e<N>.<nonce>` and AAD v2 (`nuvori-sync-<type>-v2:<vault>:<N>:<mutation>:<entity>`).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_epoch(
    content_key: &[u8],
    epoch: u64,
    entity_type: &str,
    vault_id: &str,
    mutation_id: &str,
    entity_id: &str,
    plaintext: &[u8],
    nonce: [u8; 12],
) -> Result<EncryptedPayload, PayloadError> {
    if epoch <= 1 {
        return encrypt_with_nonce(content_key, entity_type, vault_id, mutation_id, entity_id, plaintext, nonce);
    }
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(PayloadError::InvalidPayload);
    }
    let key = derive_key(content_key)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).expect("32-byte key");
    let aad = crate::epoch_keys::aad(entity_type, vault_id, epoch, mutation_id, entity_id);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
        .map_err(|_| PayloadError::AuthenticationFailed)?;
    Ok(EncryptedPayload { ciphertext: URL_SAFE_NO_PAD.encode(ciphertext), nonce: crate::epoch_keys::nonce_field(epoch, &nonce) })
}

/// The content key a change of `epoch` needs: `content_key` for epoch 1, else the keyring's.
pub fn key_for(content_key: &[u8], vault_id: &str, epoch: u64) -> Result<Zeroizing<Vec<u8>>, PayloadError> {
    if epoch <= 1 {
        return Ok(Zeroizing::new(content_key.to_vec()));
    }
    crate::epoch_keys::content_key(vault_id, epoch)
        .map(|key| Zeroizing::new(key.to_vec()))
        .ok_or(PayloadError::MissingEpochKey(epoch))
}

pub fn decrypt(content_key: &[u8], change: &ChangeRecord) -> Result<Vec<u8>, PayloadError> {
    if change.payload_ciphertext.len() > 1_500_000 {
        return Err(PayloadError::InvalidPayload);
    }
    let ciphertext = URL_SAFE_NO_PAD.decode(&change.payload_ciphertext)?;
    // `e<N>.` marks a change of a rotated epoch (`epoch_keys.rs`); it waits until this PC holds K(N).
    let epoch = crate::epoch_keys::epoch_of(&change.payload_nonce).ok_or(PayloadError::InvalidPayload)?;
    let nonce: [u8; 12] = crate::epoch_keys::nonce_bytes(&change.payload_nonce).ok_or(PayloadError::InvalidPayload)?;
    if !(16..=MAX_CIPHERTEXT).contains(&ciphertext.len()) {
        return Err(PayloadError::InvalidPayload);
    }
    let epoch_key = key_for(content_key, &change.vault_id, epoch)?;
    let key = derive_key(&epoch_key)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).expect("32-byte key");
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: crate::epoch_keys::aad(
                    &change.entity_type,
                    &change.vault_id,
                    epoch,
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
    #[error("sync keys unavailable: {0}")]
    Storage(String),
    /// A change of a rotated epoch whose key package has not arrived: it waits, it is not set aside.
    #[error("waiting for the sync keys of epoch {0}")]
    MissingEpochKey(u64),
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

    #[test]
    fn a_change_of_a_rotated_epoch_opens_with_its_key_and_waits_without_it() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!("../fixtures/epoch-keys-v1.json")).unwrap();
        let vault = vectors["vaultId"].as_str().unwrap();
        let k1 = hex::decode(vectors["epoch1ContentKeyHex"].as_str().unwrap()).unwrap();
        let k2: [u8; 32] = hex::decode(vectors["contentKeyHex"].as_str().unwrap()).unwrap().try_into().unwrap();
        for payload in vectors["payloads"].as_array().unwrap() {
            let operation = ChangeRecord::create(vault, "dev-pc", 1, GENESIS_HASH, payload["mutationId"].as_str().unwrap(),
                "entry", payload["entityId"].as_str().unwrap(), ChangeKind::Upsert, 0,
                RecordVersion::from_entries([("dev-pc", 1)]), "2026-11-23T00:00:00Z",
                payload["payloadCiphertext"].as_str().unwrap(), payload["payloadNonce"].as_str().unwrap(), "sig");
            if payload["epoch"] == 2 {
                assert!(matches!(decrypt(&k1, &operation), Err(PayloadError::MissingEpochKey(2))));
                crate::epoch_keys::install(vault, 2, &k2, &[9; 32]);
            }
            assert_eq!(decrypt(&k1, &operation).unwrap(), payload["plaintext"].as_str().unwrap().as_bytes());
        }
        // Writing reads the keys from the vault: K(2) there means epoch 2, whatever is in memory.
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(crate::epoch_keys::SCHEMA).unwrap();
        assert!(encrypt_in(&db, &k1, "entry", vault, "m", "e", b"hello").unwrap().nonce.len() == 16);
        db.execute("INSERT INTO sync_epoch_keys (vault_id, epoch, content_key, transport_secret) VALUES (?1, 2, ?2, ?3)",
            rusqlite::params![vault, &k2[..], &[9u8; 32][..]]).unwrap();
        crate::epoch_keys::forget(vault);
        let sealed = encrypt_in(&db, &k1, "entry", vault, "m", "e", b"hello").unwrap();
        assert!(sealed.nonce.starts_with("e2."));
    }
}
