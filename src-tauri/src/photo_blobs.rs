//! Shared encrypted photo blobs, byte-compatible with Android `PhotoSyncBlobs.kt`.
//!
//! A blob is `nonce(12) || AES-256-GCM(photo bytes)` keyed by
//! `HMAC-SHA256(content key, "nuvori-photo-blob-v1")` with AAD
//! `nuvori-photo-blob-v1:{vaultId}:{photoId}`. Its name is the lowercase hex SHA-256 of the
//! whole blob. Blobs hold only ciphertext under the shared content key, so they live as files
//! next to the vault and are written and read without holding the vault mutex.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Android `PhotoSyncBlobs.MAX_PHOTO_BYTES`; a blob adds a 12-byte nonce and a 16-byte tag.
pub const MAX_PHOTO_BYTES: u64 = 128 * 1024 * 1024;
pub const MIN_BLOB_BYTES: u64 = 28;
pub const MAX_BLOB_BYTES: u64 = MAX_PHOTO_BYTES + 28;
/// Android sends and accepts chunks of at most 64 KiB.
pub const CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum BlobError {
    #[error("photo blob storage failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("photo blob reference is invalid")]
    InvalidReference,
    #[error("photo data failed verification")]
    Verification,
    #[error("photo is too large to sync")]
    TooLarge,
}

pub fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn valid_size(size: u64) -> bool {
    (MIN_BLOB_BYTES..=MAX_BLOB_BYTES).contains(&size)
}

#[derive(Clone, Debug)]
pub struct PhotoBlobs {
    directory: PathBuf,
}

impl PhotoBlobs {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn complete(&self, hash: &str) -> Result<PathBuf, BlobError> {
        if !valid_hash(hash) {
            return Err(BlobError::InvalidReference);
        }
        Ok(self.directory.join(hash))
    }

    fn partial(&self, hash: &str) -> Result<PathBuf, BlobError> {
        if !valid_hash(hash) {
            return Err(BlobError::InvalidReference);
        }
        Ok(self.directory.join(format!("{hash}.part")))
    }

    /// Encrypts photo bytes into a new blob and returns `(hash, size)`.
    pub fn create(
        &self,
        content_key: &[u8],
        vault_id: &str,
        photo_id: &str,
        plaintext: &[u8],
    ) -> Result<(String, u64), BlobError> {
        if plaintext.len() as u64 > MAX_PHOTO_BYTES || content_key.len() != 32 {
            return Err(BlobError::TooLarge);
        }
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| BlobError::InvalidReference)?;
        let key = blob_key(content_key);
        let ciphertext = Aes256Gcm::new_from_slice(&*key)
            .expect("32-byte key")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: plaintext, aad: aad(vault_id, photo_id).as_bytes() },
            )
            .map_err(|_| BlobError::Verification)?;
        let mut blob = Vec::with_capacity(12 + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        let hash = hex::encode(Sha256::digest(&blob));
        fs::create_dir_all(&self.directory)?;
        let target = self.complete(&hash)?;
        if self.size(&hash)?.is_none() {
            let staged = self.directory.join(format!("stage-{}.tmp", uuid::Uuid::new_v4()));
            fs::write(&staged, &blob)?;
            fs::rename(&staged, &target)?;
        }
        Ok((hash, blob.len() as u64))
    }

    /// Size of a complete blob whose content matches its hash, else `None`.
    pub fn size(&self, hash: &str) -> Result<Option<u64>, BlobError> {
        let path = self.complete(hash)?;
        let Ok(metadata) = fs::metadata(&path) else {
            return Ok(None);
        };
        if !metadata.is_file() || !valid_size(metadata.len()) || digest(&path)? != hash {
            return Ok(None);
        }
        Ok(Some(metadata.len()))
    }

    pub fn has(&self, hash: &str, size: u64) -> bool {
        valid_size(size) && matches!(self.size(hash), Ok(Some(found)) if found == size)
    }

    /// Bytes already received for an interrupted transfer; resets an oversized partial.
    pub fn partial_size(&self, hash: &str) -> Result<u64, BlobError> {
        let path = self.partial(hash)?;
        let length = fs::metadata(&path).map_or(0, |metadata| metadata.len());
        if length > MAX_BLOB_BYTES {
            fs::remove_file(&path)?;
            return Ok(0);
        }
        Ok(length)
    }

    pub fn discard_partial(&self, hash: &str) -> Result<(), BlobError> {
        let path = self.partial(hash)?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Appends one received chunk. `offset` must equal the bytes already stored.
    pub fn append(&self, hash: &str, offset: u64, chunk: &[u8]) -> Result<(), BlobError> {
        fs::create_dir_all(&self.directory)?;
        let path = self.partial(hash)?;
        if self.partial_size(hash)? != offset || offset + chunk.len() as u64 > MAX_BLOB_BYTES {
            return Err(BlobError::InvalidReference);
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(chunk)?;
        Ok(())
    }

    /// Verifies a fully received partial against its hash and makes it a complete blob.
    pub fn finish(&self, hash: &str, size: u64) -> Result<(), BlobError> {
        let path = self.partial(hash)?;
        OpenOptions::new().write(true).open(&path)?.sync_all()?;
        if self.partial_size(hash)? != size || digest(&path)? != hash {
            let _ = fs::remove_file(&path);
            return Err(BlobError::Verification);
        }
        let target = self.complete(hash)?;
        if self.size(hash)?.is_some() {
            fs::remove_file(&path)?;
        } else {
            fs::rename(&path, &target)?;
        }
        Ok(())
    }

    /// Opens a complete blob for sending from `offset`.
    pub fn open_at(&self, hash: &str, offset: u64) -> Result<File, BlobError> {
        let mut file = File::open(self.complete(hash)?)?;
        std::io::copy(&mut (&mut file).take(offset), &mut std::io::sink())?;
        Ok(file)
    }

    /// Decrypts a complete blob into the photo bytes.
    pub fn decrypt(
        &self,
        content_key: &[u8],
        vault_id: &str,
        photo_id: &str,
        hash: &str,
        size: u64,
    ) -> Result<Zeroizing<Vec<u8>>, BlobError> {
        if !self.has(hash, size) || content_key.len() != 32 {
            return Err(BlobError::InvalidReference);
        }
        let blob = fs::read(self.complete(hash)?)?;
        let key = blob_key(content_key);
        let plaintext = Aes256Gcm::new_from_slice(&*key)
            .expect("32-byte key")
            .decrypt(
                Nonce::from_slice(&blob[..12]),
                Payload { msg: &blob[12..], aad: aad(vault_id, photo_id).as_bytes() },
            )
            .map_err(|_| BlobError::Verification)?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Removes complete blobs not in `keep`, partials not in `pending`, and stale staging files.
    pub fn prune(&self, keep: &HashSet<String>, pending: &HashSet<String>) -> Result<usize, BlobError> {
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return Ok(0);
        };
        let stale = SystemTime::now() - Duration::from_secs(24 * 60 * 60);
        let mut removed = 0;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let remove = if let Some(hash) = name.strip_suffix(".part") {
                valid_hash(hash) && !pending.contains(hash)
            } else if valid_hash(&name) {
                !keep.contains(&name) && !pending.contains(&name)
            } else {
                name.starts_with("stage-")
                    && entry.metadata().and_then(|m| m.modified()).is_ok_and(|time| time < stale)
            };
            if remove && path.is_file() {
                fs::remove_file(path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn remove_all(&self) -> Result<(), BlobError> {
        if self.directory.exists() {
            fs::remove_dir_all(&self.directory)?;
        }
        Ok(())
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

fn blob_key(content_key: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(content_key).expect("HMAC accepts any key");
    mac.update(b"nuvori-photo-blob-v1");
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn aad(vault_id: &str, photo_id: &str) -> String {
    format!("nuvori-photo-blob-v1:{vault_id}:{photo_id}")
}

fn digest(path: &Path) -> Result<String, BlobError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Image type from magic bytes; Android stores JPEG, PNG, WebP or GIF photos.
pub fn sniff_mime(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        "image/jpeg"
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        "image/webp"
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        "image/gif"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PhotoBlobs {
        PhotoBlobs::new(std::env::temp_dir().join(format!("nuvori-blobs-{}", uuid::Uuid::new_v4())))
    }

    #[test]
    fn blob_round_trips_and_is_bound_to_vault_and_photo() {
        let blobs = temp();
        let (hash, size) = blobs.create(&[4; 32], "vault-a", "photo-a", b"\x89PNG\r\n\x1a\npixels").unwrap();
        assert_eq!(size, 12 + 16 + 14);
        assert!(blobs.has(&hash, size));
        assert_eq!(&*blobs.decrypt(&[4; 32], "vault-a", "photo-a", &hash, size).unwrap(), b"\x89PNG\r\n\x1a\npixels");
        assert!(blobs.decrypt(&[4; 32], "vault-a", "photo-b", &hash, size).is_err());
        assert!(blobs.decrypt(&[5; 32], "vault-a", "photo-a", &hash, size).is_err());
        blobs.remove_all().unwrap();
    }

    #[test]
    fn partial_transfers_resume_and_verify_before_completion() {
        let source = temp();
        let (hash, size) = source.create(&[4; 32], "v", "p", &vec![7u8; 150_000]).unwrap();
        let mut bytes = Vec::new();
        source.open_at(&hash, 0).unwrap().read_to_end(&mut bytes).unwrap();
        let target = temp();
        target.append(&hash, 0, &bytes[..CHUNK_BYTES]).unwrap();
        assert!(target.append(&hash, 0, &bytes[..10]).is_err(), "offset must match stored bytes");
        assert_eq!(target.partial_size(&hash).unwrap(), CHUNK_BYTES as u64);
        target.append(&hash, CHUNK_BYTES as u64, &bytes[CHUNK_BYTES..]).unwrap();
        target.finish(&hash, size).unwrap();
        assert!(target.has(&hash, size));
        let mut corrupt = bytes.clone();
        corrupt[40] ^= 1;
        let fake = hex::encode(Sha256::digest(&bytes[..100]));
        target.append(&fake, 0, &corrupt).unwrap();
        assert!(matches!(target.finish(&fake, corrupt.len() as u64), Err(BlobError::Verification)));
        assert_eq!(target.partial_size(&fake).unwrap(), 0);
        let mut tail = Vec::new();
        source.open_at(&hash, 100).unwrap().read_to_end(&mut tail).unwrap();
        assert_eq!(tail, bytes[100..]);
        let keep = HashSet::new();
        target.append(&fake, 0, b"abc").unwrap();
        assert_eq!(target.prune(&keep, &HashSet::new()).unwrap(), 2);
        assert!(!target.has(&hash, size));
        source.remove_all().unwrap();
        target.remove_all().unwrap();
    }

    #[test]
    fn rejects_invalid_hashes_and_sizes() {
        let blobs = temp();
        assert!(blobs.partial_size("../escape").is_err());
        assert!(!valid_size(27) && !valid_size(MAX_BLOB_BYTES + 1) && valid_size(MAX_BLOB_BYTES));
        assert!(!valid_hash(&"A".repeat(64)) && valid_hash(&"a".repeat(64)));
        assert_eq!(sniff_mime(b"\xff\xd8\xff\xe0"), "image/jpeg");
        assert_eq!(sniff_mime(b"????"), "application/octet-stream");
    }
}
