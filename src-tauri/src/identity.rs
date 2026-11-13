use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    },
    core::w,
};
use zeroize::Zeroize;

pub const DEVICE_IDENTITY_FORMAT_VERSION: u16 = 1;
pub const DEVICE_IDENTITY_ALGORITHM: &str = "Ed25519";
const PRIVATE_SEED_BYTES: usize = 32;
const DPAPI_ENTROPY_PREFIX: &str = "nuvori-device-identity-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub public_key: [u8; 32],
}

impl DeviceIdentity {
    pub fn public_key_base64_url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key)
    }
}

pub struct DeviceIdentityStore {
    path: PathBuf,
}

impl DeviceIdentityStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn get_or_create(&self) -> Result<DeviceIdentity, IdentityError> {
        if self.path.exists() {
            return self.load_material().map(|(identity, _)| identity);
        }

        let mut private_seed = [0_u8; PRIVATE_SEED_BYTES];
        getrandom::fill(&mut private_seed)
            .map_err(|error| IdentityError::Random(error.to_string()))?;
        let result = self.create_from_seed(&private_seed);
        private_seed.zeroize();
        result
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], IdentityError> {
        let (_, mut private_seed) = self.load_material()?;
        let signature = SigningKey::from_bytes(&private_seed)
            .sign(message)
            .to_bytes();
        private_seed.zeroize();
        Ok(signature)
    }

    pub fn delete(&self) -> Result<(), IdentityError> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    fn create_from_seed(&self, private_seed: &[u8; 32]) -> Result<DeviceIdentity, IdentityError> {
        let signing_key = SigningKey::from_bytes(private_seed);
        let identity = DeviceIdentity {
            device_id: Uuid::new_v4().to_string(),
            public_key: signing_key.verifying_key().to_bytes(),
        };
        let stored = StoredIdentity {
            format_version: DEVICE_IDENTITY_FORMAT_VERSION,
            algorithm: DEVICE_IDENTITY_ALGORITHM.to_owned(),
            device_id: identity.device_id.clone(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key),
            protected_seed: URL_SAFE_NO_PAD
                .encode(protect_for_current_user(private_seed, &identity.device_id)?),
        };
        write_json_atomically(&self.path, &stored)?;
        Ok(identity)
    }

    fn load_material(&self) -> Result<(DeviceIdentity, [u8; 32]), IdentityError> {
        let stored: StoredIdentity = serde_json::from_slice(&fs::read(&self.path)?)?;
        if stored.format_version != DEVICE_IDENTITY_FORMAT_VERSION {
            return Err(IdentityError::UnsupportedFormat(stored.format_version));
        }
        if stored.algorithm != DEVICE_IDENTITY_ALGORITHM {
            return Err(IdentityError::UnsupportedAlgorithm(stored.algorithm));
        }
        Uuid::parse_str(&stored.device_id).map_err(|_| IdentityError::InvalidDeviceId)?;

        let public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(stored.public_key)?
            .try_into()
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let protected_seed = URL_SAFE_NO_PAD.decode(stored.protected_seed)?;
        let mut unprotected = unprotect_for_current_user(&protected_seed, &stored.device_id)?;
        if unprotected.len() != PRIVATE_SEED_BYTES {
            unprotected.zeroize();
            return Err(IdentityError::InvalidPrivateSeed);
        }
        let mut private_seed = [0_u8; PRIVATE_SEED_BYTES];
        private_seed.copy_from_slice(&unprotected);
        unprotected.zeroize();

        let derived_public_key = SigningKey::from_bytes(&private_seed)
            .verifying_key()
            .to_bytes();
        if public_key != derived_public_key {
            private_seed.zeroize();
            return Err(IdentityError::InconsistentIdentity);
        }

        Ok((
            DeviceIdentity {
                device_id: stored.device_id,
                public_key,
            },
            private_seed,
        ))
    }
}

pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    verifying_key
        .verify(message, &Signature::from_bytes(signature))
        .is_ok()
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredIdentity {
    format_version: u16,
    algorithm: String,
    device_id: String,
    public_key: String,
    protected_seed: String,
}

fn protect_for_current_user(value: &[u8], device_id: &str) -> Result<Vec<u8>, IdentityError> {
    let input = blob(value)?;
    let entropy_bytes = dpapi_entropy(device_id);
    let entropy = blob(&entropy_bytes)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &input,
            w!("Nuvori device identity"),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )?;
        copy_and_free(output, false)
    }
}

fn unprotect_for_current_user(value: &[u8], device_id: &str) -> Result<Vec<u8>, IdentityError> {
    let input = blob(value)?;
    let entropy_bytes = dpapi_entropy(device_id);
    let entropy = blob(&entropy_bytes)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )?;
        copy_and_free(output, true)
    }
}

fn dpapi_entropy(device_id: &str) -> Vec<u8> {
    format!("{DPAPI_ENTROPY_PREFIX}:{device_id}").into_bytes()
}

fn blob(value: &[u8]) -> Result<CRYPT_INTEGER_BLOB, IdentityError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: value
            .len()
            .try_into()
            .map_err(|_| IdentityError::ValueTooLarge)?,
        pbData: value.as_ptr().cast_mut(),
    })
}

unsafe fn copy_and_free(
    output: CRYPT_INTEGER_BLOB,
    clear_before_free: bool,
) -> Result<Vec<u8>, IdentityError> {
    if output.pbData.is_null() {
        return Err(IdentityError::EmptyDpapiOutput);
    }
    let output_len: usize = output
        .cbData
        .try_into()
        .map_err(|_| IdentityError::ValueTooLarge)?;
    let copied = unsafe { std::slice::from_raw_parts(output.pbData, output_len) }.to_vec();
    if clear_before_free {
        unsafe { output.pbData.write_bytes(0, output_len) };
    }
    let remaining = unsafe { LocalFree(Some(HLOCAL(output.pbData.cast()))) };
    if !remaining.0.is_null() {
        return Err(IdentityError::DpapiMemoryRelease);
    }
    Ok(copied)
}

fn write_json_atomically(path: &Path, value: &StoredIdentity) -> Result<(), IdentityError> {
    let parent = path.parent().ok_or(IdentityError::MissingParentDirectory)?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!("device-identity-{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec(value)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity storage failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("identity base64 failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("secure random generation failed: {0}")]
    Random(String),
    #[error("Windows DPAPI failed: {0}")]
    Dpapi(#[from] windows::core::Error),
    #[error("unsupported device identity format {0}")]
    UnsupportedFormat(u16),
    #[error("unsupported device identity algorithm {0}")]
    UnsupportedAlgorithm(String),
    #[error("device ID is invalid")]
    InvalidDeviceId,
    #[error("device public key is invalid")]
    InvalidPublicKey,
    #[error("device private seed is invalid")]
    InvalidPrivateSeed,
    #[error("device public key does not match its private seed")]
    InconsistentIdentity,
    #[error("identity path has no parent directory")]
    MissingParentDirectory,
    #[error("value is too large for Windows DPAPI")]
    ValueTooLarge,
    #[error("Windows DPAPI returned no data")]
    EmptyDpapiOutput,
    #[error("Windows DPAPI memory could not be released")]
    DpapiMemoryRelease,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct IdentityFixture {
        format_version: u16,
        algorithm: String,
        private_seed_hex: String,
        public_key_hex: String,
        message_hex: String,
        signature_hex: String,
    }

    #[test]
    fn matches_rfc_8032_test_vector() {
        let fixture: IdentityFixture =
            serde_json::from_str(include_str!("../fixtures/device-identity-v1.json"))
                .expect("fixture must deserialize");
        assert_eq!(fixture.format_version, DEVICE_IDENTITY_FORMAT_VERSION);
        assert_eq!(fixture.algorithm, DEVICE_IDENTITY_ALGORITHM);

        let private_seed: [u8; 32] = hex::decode(fixture.private_seed_hex)
            .expect("valid seed hex")
            .try_into()
            .expect("32-byte seed");
        let expected_public_key: [u8; 32] = hex::decode(fixture.public_key_hex)
            .expect("valid public key hex")
            .try_into()
            .expect("32-byte public key");
        let message = hex::decode(fixture.message_hex).expect("valid message hex");
        let expected_signature: [u8; 64] = hex::decode(fixture.signature_hex)
            .expect("valid signature hex")
            .try_into()
            .expect("64-byte signature");

        let signing_key = SigningKey::from_bytes(&private_seed);
        assert_eq!(signing_key.verifying_key().to_bytes(), expected_public_key);
        assert_eq!(signing_key.sign(&message).to_bytes(), expected_signature);
        assert!(verify_signature(
            &expected_public_key,
            &message,
            &expected_signature
        ));
    }

    #[test]
    fn persists_with_dpapi_and_reloads_the_same_identity() {
        let directory = std::env::temp_dir().join(format!("nuvori-identity-{}", Uuid::new_v4()));
        let path = directory.join("device-identity-v1.json");
        let store = DeviceIdentityStore::new(&path);

        let created = store.get_or_create().expect("identity must be created");
        let loaded = store.get_or_create().expect("identity must reload");
        let message = b"device-possession-test";
        let signature = store.sign(message).expect("message must be signed");

        assert_eq!(created, loaded);
        assert!(verify_signature(&loaded.public_key, message, &signature));

        let mut stored: StoredIdentity =
            serde_json::from_slice(&fs::read(&path).expect("identity file must be readable"))
                .expect("identity JSON must parse");
        stored.device_id = Uuid::new_v4().to_string();
        fs::write(
            &path,
            serde_json::to_vec(&stored).expect("identity JSON must encode"),
        )
        .expect("tampered identity must be written");
        assert!(matches!(
            store.get_or_create(),
            Err(IdentityError::Dpapi(_))
        ));

        store.delete().expect("identity file must be removed");
        fs::remove_dir(&directory).expect("test directory must be removed");
    }
}
