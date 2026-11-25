//! Encrypted backup files (`.pvault`) in the format of Nuvori for Android (`BackupCipher` and
//! `VaultBackupManager` in the Android repository), so that a backup made on this PC restores on
//! a phone.
//!
//! ```text
//! "PVLT0002" | Argon2id memory KiB, passes, lanes (3 x u32, big-endian) | salt (16) | nonce (12)
//!            | wrapped keyset length (u32, big-endian) | wrapped keyset | streaming body
//! ```
//!
//! The wrapped keyset is a Tink keyset of one `AES128_GCM_HKDF_1MB` streaming key, sealed with
//! AES-256-GCM under Argon2id(master password, salt) with the vault's own Argon2id settings, so a
//! guess at a copied backup costs as much as a guess at the vault. The associated data is the
//! magic and the settings, so a changed setting does not go unnoticed. The body is Tink's
//! streaming AEAD (AES-128-GCM with an HKDF-SHA256 key per file, 1 MiB segments, associated data
//! `private-vault-backup-v1`) over a ZIP archive: `vault.json` (the vault as Android's
//! `VaultBackupManager.serialize` writes it, version 9) and one `photos/<id>` member per photo.
//!
//! Only the writer is used outside tests. The tests read the files back and open a backup that
//! Nuvori for Android made with Tink itself (`tests/fixtures/android-backup.pvault`).

use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
};

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce,
    aead::{Aead, AeadInPlace, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// The file name extension, as on Android.
pub const EXTENSION: &str = "pvault";

const MAGIC: &[u8; 8] = b"PVLT0002";
const ASSOCIATED_DATA: &[u8] = b"private-vault-backup-v1";
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
#[cfg(test)]
const MAX_WRAPPED_KEY: usize = 128 * 1024;

// Tink `AES128_GCM_HKDF_1MB`: 16-byte key material and derived AES-128 key, HKDF-SHA256, 1 MiB
// ciphertext segments with a 16-byte tag. A stream starts with its header length, a salt for HKDF
// and a 7-byte nonce prefix; a segment's nonce is the prefix, the segment number (u32,
// big-endian) and 1 for the last segment or 0 for any other.
const KEY_BYTES: usize = 16;
const SEGMENT_BYTES: usize = 1 << 20;
const TAG_BYTES: usize = 16;
const NONCE_PREFIX_BYTES: usize = 7;
const STREAM_HEADER_BYTES: usize = 1 + KEY_BYTES + NONCE_PREFIX_BYTES;
const PLAIN_SEGMENT_BYTES: usize = SEGMENT_BYTES - TAG_BYTES;
const FIRST_PLAIN_SEGMENT_BYTES: usize = PLAIN_SEGMENT_BYTES - STREAM_HEADER_BYTES;
const TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";
const HASH_SHA256: u64 = 3;
const KEY_MATERIAL_SYMMETRIC: u64 = 1;
const STATUS_ENABLED: u64 = 1;
const OUTPUT_PREFIX_RAW: u64 = 3;

/// The most `vault.json` may hold, as on Android.
const MAX_METADATA: usize = 16 * 1024 * 1024;
/// The entry types a backup holds, as Android's `EntryType`.
const ENTRY_TYPES: [&str; 6] = ["CARD", "QUESTION", "PASSWORD", "NOTE", "AUTHENTICATOR", "AUTOFILL"];

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("The vault's key settings can't be used for a backup")]
    InvalidSettings,
    #[error("Couldn't encrypt the backup")]
    Encryption,
    #[error("Couldn't get secure random data")]
    Random,
    #[error("The vault is too large for one backup file")]
    TooLarge,
    #[error("An item couldn't be added to the backup")]
    InvalidItem,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[cfg(test)]
    #[error("This isn't a Nuvori backup, or a newer Nuvori made it")]
    Unsupported,
    #[cfg(test)]
    #[error("Wrong password, or the backup is damaged")]
    WrongPasswordOrDamaged,
}

/// Argon2id settings: Android's `KdfParams`, and the vault's own (`vault.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Kdf {
    pub const LEGACY: Self = Self { memory_kib: 65_536, iterations: 3, parallelism: 1 };
    const MAX_ITERATIONS: u32 = 64;

    /// The settings Android opens: 64 MiB, 3 to 64 passes, one lane. Anything else is refused
    /// before a key is derived, so an edited file cannot make the derivation run for minutes.
    pub fn valid(&self) -> bool {
        self.memory_kib == Self::LEGACY.memory_kib
            && (Self::LEGACY.iterations..=Self::MAX_ITERATIONS).contains(&self.iterations)
            && self.parallelism == Self::LEGACY.parallelism
    }

    fn prefix(&self) -> Vec<u8> {
        let mut prefix = MAGIC.to_vec();
        for value in [self.memory_kib, self.iterations, self.parallelism] {
            prefix.extend_from_slice(&value.to_be_bytes());
        }
        prefix
    }
}

/// One backup key: the file header, which holds the wrapped keyset, and the key material.
pub struct BackupKey {
    header: Vec<u8>,
    material: Zeroizing<[u8; KEY_BYTES]>,
}

impl BackupKey {
    /// A new key wrapped with `password` under `kdf`. Slow on purpose (one Argon2id run): call it
    /// off the UI thread. A new key for every file, as Android's manual export makes.
    pub fn new(password: &str, kdf: Kdf) -> Result<Self, BackupError> {
        if !kdf.valid() {
            return Err(BackupError::InvalidSettings);
        }
        let material = Zeroizing::new(random::<KEY_BYTES>()?);
        let key_id = loop {
            let id = u32::from_be_bytes(random()?);
            if id != 0 {
                break id;
            }
        };
        let keyset = keyset_bytes(&material, key_id);
        let header = wrap_keyset(&keyset, password, kdf)?;
        Ok(Self { header, material })
    }
}

/// `prefix | salt | nonce | length | AES-256-GCM(Argon2id(password, salt), keyset, aad = prefix)`.
fn wrap_keyset(keyset: &[u8], password: &str, kdf: Kdf) -> Result<Vec<u8>, BackupError> {
    let prefix = kdf.prefix();
    let salt: [u8; SALT_BYTES] = random()?;
    let nonce: [u8; NONCE_BYTES] = random()?;
    let wrapping_key = derive(password, &salt, kdf)?;
    let wrapped = Aes256Gcm::new_from_slice(&*wrapping_key)
        .map_err(|_| BackupError::Encryption)?
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: keyset, aad: &prefix })
        .map_err(|_| BackupError::Encryption)?;
    let length = u32::try_from(wrapped.len()).map_err(|_| BackupError::Encryption)?;
    let mut header = prefix;
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&length.to_be_bytes());
    header.extend_from_slice(&wrapped);
    Ok(header)
}

/// Argon2id with the password's UTF-8 bytes, as `PasswordCrypto.derive` on Android and the vault
/// key derivation on this PC.
fn derive(password: &str, salt: &[u8; SALT_BYTES], kdf: Kdf) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| BackupError::InvalidSettings)?;
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|_| BackupError::InvalidSettings)?;
    Ok(key)
}

fn random<const N: usize>() -> Result<[u8; N], BackupError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| BackupError::Random)?;
    Ok(bytes)
}

// Protocol buffers, as much as a Tink keyset needs: varints and length-delimited fields.

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn put_number(out: &mut Vec<u8>, field: u64, value: u64) {
    put_varint(out, field << 3);
    put_varint(out, value);
}

fn put_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    put_varint(out, field << 3 | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// A secret buffer that never grows, so no copy of the key is left behind by a reallocation.
fn secret_buffer() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(256))
}

/// The serialized `google.crypto.tink.Keyset` that `KeysetHandle.generateNew` makes for
/// `AES128_GCM_HKDF_1MB`: one enabled raw key, the primary.
fn keyset_bytes(material: &[u8; KEY_BYTES], key_id: u32) -> Zeroizing<Vec<u8>> {
    // AesGcmHkdfStreamingParams: ciphertext_segment_size, derived_key_size, hkdf_hash_type.
    let mut params = Vec::new();
    put_number(&mut params, 1, SEGMENT_BYTES as u64);
    put_number(&mut params, 2, KEY_BYTES as u64);
    put_number(&mut params, 3, HASH_SHA256);
    // AesGcmHkdfStreamingKey: version 0 (left out, as protobuf does), params, key_value.
    let mut key = secret_buffer();
    put_bytes(&mut key, 2, &params);
    put_bytes(&mut key, 3, material);
    // KeyData: type_url, value, key_material_type.
    let mut key_data = secret_buffer();
    put_bytes(&mut key_data, 1, TYPE_URL.as_bytes());
    put_bytes(&mut key_data, 2, &key);
    put_number(&mut key_data, 3, KEY_MATERIAL_SYMMETRIC);
    // Keyset.Key: key_data, status, key_id, output_prefix_type.
    let mut entry = secret_buffer();
    put_bytes(&mut entry, 1, &key_data);
    put_number(&mut entry, 2, STATUS_ENABLED);
    put_number(&mut entry, 3, u64::from(key_id));
    put_number(&mut entry, 4, OUTPUT_PREFIX_RAW);
    // Keyset: primary_key_id, key.
    let mut keyset = secret_buffer();
    put_number(&mut keyset, 1, u64::from(key_id));
    put_bytes(&mut keyset, 2, &entry);
    keyset
}

/// HKDF-SHA256 (RFC 5869), the first 16 bytes: Tink's key for one stream.
fn hkdf_key(material: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC takes any key length");
    extract.update(material);
    let pseudo_random_key: Zeroizing<[u8; 32]> = Zeroizing::new(extract.finalize().into_bytes().into());
    let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&*pseudo_random_key).expect("HMAC takes any key length");
    expand.update(info);
    expand.update(&[1]);
    let block: Zeroizing<[u8; 32]> = Zeroizing::new(expand.finalize().into_bytes().into());
    let mut key = Zeroizing::new([0; KEY_BYTES]);
    key.copy_from_slice(&block[..KEY_BYTES]);
    key
}

fn segment_nonce(prefix: &[u8; NONCE_PREFIX_BYTES], segment: u32, last: bool) -> [u8; NONCE_BYTES] {
    let mut nonce = [0; NONCE_BYTES];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_BYTES..NONCE_BYTES - 1].copy_from_slice(&segment.to_be_bytes());
    nonce[NONCE_BYTES - 1] = u8::from(last);
    nonce
}

/// Writes the file header, then encrypts what is written to it as Tink's streaming AEAD does.
/// [`EncryptingWriter::finish`] seals the last segment: a file without it does not open.
///
/// Like Tink's encrypting stream, a full segment is sealed only once more data comes, so the last
/// segment is never empty unless the whole body is.
pub struct EncryptingWriter<W: Write> {
    out: W,
    cipher: Aes128Gcm,
    nonce_prefix: [u8; NONCE_PREFIX_BYTES],
    segment: u32,
    /// The current segment's plaintext. Encrypted in place, so no plaintext stays in it.
    buffer: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl<W: Write> EncryptingWriter<W> {
    pub fn new(mut out: W, key: &BackupKey) -> Result<Self, BackupError> {
        let salt: [u8; KEY_BYTES] = random()?;
        let nonce_prefix: [u8; NONCE_PREFIX_BYTES] = random()?;
        let stream_key = hkdf_key(&*key.material, &salt, ASSOCIATED_DATA);
        let cipher = Aes128Gcm::new_from_slice(&*stream_key).map_err(|_| BackupError::Encryption)?;
        out.write_all(&key.header)?;
        out.write_all(&[STREAM_HEADER_BYTES as u8])?;
        out.write_all(&salt)?;
        out.write_all(&nonce_prefix)?;
        Ok(Self {
            out,
            cipher,
            nonce_prefix,
            segment: 0,
            buffer: Zeroizing::new(Vec::with_capacity(PLAIN_SEGMENT_BYTES)),
            limit: FIRST_PLAIN_SEGMENT_BYTES,
        })
    }

    fn seal_segment(&mut self, last: bool) -> io::Result<()> {
        let nonce = segment_nonce(&self.nonce_prefix, self.segment, last);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", self.buffer.as_mut_slice())
            .map_err(|_| io::Error::other("Couldn't encrypt the backup"))?;
        self.out.write_all(&self.buffer)?;
        self.out.write_all(&tag)?;
        self.buffer.clear();
        self.segment = self.segment.checked_add(1).ok_or_else(|| io::Error::other("The backup is too large"))?;
        self.limit = PLAIN_SEGMENT_BYTES;
        Ok(())
    }

    /// Seals the last segment and returns the output.
    pub fn finish(mut self) -> io::Result<W> {
        self.seal_segment(true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for EncryptingWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.buffer.len() == self.limit {
            self.seal_segment(false)?;
        }
        let taken = data.len().min(self.limit - self.buffer.len());
        self.buffer.extend_from_slice(&data[..taken]);
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 { crc >> 1 ^ 0xEDB8_8320 } else { crc >> 1 };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
};

/// CRC-32 (ISO-HDLC), the checksum of a ZIP member.
fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |crc, &byte| CRC_TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ crc >> 8)
}

/// A ZIP archive of stored (uncompressed) members, as `java.util.zip.ZipInputStream` reads them on
/// Android: every local header carries the checksum and sizes, so there are no data descriptors.
/// Without ZIP64, so up to 65,535 members and 4 GiB; a larger vault is refused.
pub struct ZipWriter<W: Write> {
    out: W,
    offset: u64,
    central: Vec<u8>,
    count: u16,
}

/// 1980-01-01 00:00, the earliest MS-DOS date. Members carry no time of their own.
const DOS_TIME: u16 = 0;
const DOS_DATE: u16 = 1 << 5 | 1;
/// Bit 11: the name is UTF-8.
const UTF8_NAMES: u16 = 1 << 11;

impl<W: Write> ZipWriter<W> {
    pub fn new(out: W) -> Self {
        Self { out, offset: 0, central: Vec::new(), count: 0 }
    }

    pub fn add(&mut self, name: &str, data: &[u8]) -> Result<(), BackupError> {
        let size = u32::try_from(data.len()).map_err(|_| BackupError::TooLarge)?;
        let offset = u32::try_from(self.offset).map_err(|_| BackupError::TooLarge)?;
        let name_length = u16::try_from(name.len()).map_err(|_| BackupError::InvalidItem)?;
        let count = self.count.checked_add(1).ok_or(BackupError::TooLarge)?;
        let crc = crc32(data);
        let mut local = Vec::with_capacity(30 + name.len());
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        for value in [10u16, UTF8_NAMES, 0, DOS_TIME, DOS_DATE] {
            local.extend_from_slice(&value.to_le_bytes());
        }
        for value in [crc, size, size] {
            local.extend_from_slice(&value.to_le_bytes());
        }
        local.extend_from_slice(&name_length.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name.as_bytes());
        self.out.write_all(&local)?;
        self.out.write_all(data)?;
        self.offset += (local.len() + data.len()) as u64;

        self.central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        for value in [20u16, 10, UTF8_NAMES, 0, DOS_TIME, DOS_DATE] {
            self.central.extend_from_slice(&value.to_le_bytes());
        }
        for value in [crc, size, size] {
            self.central.extend_from_slice(&value.to_le_bytes());
        }
        for value in [name_length, 0, 0, 0, 0] {
            self.central.extend_from_slice(&value.to_le_bytes());
        }
        self.central.extend_from_slice(&0u32.to_le_bytes());
        self.central.extend_from_slice(&offset.to_le_bytes());
        self.central.extend_from_slice(name.as_bytes());
        self.count = count;
        Ok(())
    }

    /// Writes the central directory and returns the output.
    pub fn finish(mut self) -> Result<W, BackupError> {
        let directory_offset = u32::try_from(self.offset).map_err(|_| BackupError::TooLarge)?;
        let directory_size = u32::try_from(self.central.len()).map_err(|_| BackupError::TooLarge)?;
        directory_offset.checked_add(directory_size).ok_or(BackupError::TooLarge)?;
        self.out.write_all(&self.central)?;
        let mut end = Vec::with_capacity(22);
        end.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        for value in [0u16, 0, self.count, self.count] {
            end.extend_from_slice(&value.to_le_bytes());
        }
        end.extend_from_slice(&directory_size.to_le_bytes());
        end.extend_from_slice(&directory_offset.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        self.out.write_all(&end)?;
        Ok(self.out)
    }
}

/// A folder (Android's `VaultGroup`).
pub struct Group {
    pub id: String,
    pub name: String,
    pub notes: String,
    /// "" for a plain folder, or the one entry type a typed folder holds.
    pub folder_type: String,
}

/// A photo's details in `vault.json`; its bytes go in `photos/<id>`.
pub struct Photo {
    pub id: String,
    pub entry_id: String,
    pub is_cover: bool,
    pub added_at: i64,
}

/// What a backup holds. `entries` are stored items and notes as Android's `VaultEntry` JSON.
pub struct Contents {
    pub vault_id: String,
    pub entries: Vec<Value>,
    pub groups: Vec<Group>,
    /// (entry ID, folder ID).
    pub links: Vec<(String, String)>,
    pub photos: Vec<Photo>,
    pub passkeys: Vec<Value>,
    /// The accent and surface IDs (appearance.rs), when set.
    pub appearance: Option<(String, String)>,
}

/// `vault.json` and the photos it lists, in the order their members go in the archive.
pub struct Metadata {
    pub json: Zeroizing<Vec<u8>>,
    pub photo_ids: Vec<String>,
}

/// A photo ID that Android's restore accepts as a member name (`photos/<id>`).
fn valid_photo_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// `vault.json`, version 9, with the fields Android's `VaultBackupManager.parse` reads.
///
/// Android refuses a whole backup when one reference in it is broken, so references that point
/// nowhere are left out rather than written: a folder link to a missing item or folder, a link
/// that puts an item in a typed folder of another type or in a second typed folder, a photo of a
/// missing item, and an authenticator link (`linkedAuthenticatorId`) from anything but a login to
/// anything but an authenticator in the backup. Device settings (theme, lock timers, NFC) are not
/// written: they belong to this PC, and a phone that restores the file keeps its defaults.
pub fn metadata(contents: &Contents) -> Result<Metadata, BackupError> {
    if contents.vault_id.trim().is_empty() {
        return Err(BackupError::InvalidItem);
    }
    let mut types = HashMap::new();
    for entry in &contents.entries {
        let (Some(id), Some(entry_type)) = (entry["id"].as_str(), entry["type"].as_str()) else {
            return Err(BackupError::InvalidItem);
        };
        if id.is_empty() || !ENTRY_TYPES.contains(&entry_type) || types.insert(id, entry_type).is_some() {
            return Err(BackupError::InvalidItem);
        }
    }
    let mut folders = HashMap::new();
    for group in &contents.groups {
        if group.id.is_empty()
            || !(group.folder_type.is_empty() || ENTRY_TYPES.contains(&group.folder_type.as_str()))
            || folders.insert(group.id.as_str(), group.folder_type.as_str()).is_some()
        {
            return Err(BackupError::InvalidItem);
        }
    }

    let entries = contents
        .entries
        .iter()
        .map(|entry| {
            let mut entry: Map<String, Value> = entry.as_object().cloned().ok_or(BackupError::InvalidItem)?;
            // Kept on this PC beside the stored item; a backup has its own links.
            entry.remove("groupIds");
            let linked = entry.get("linkedAuthenticatorId").and_then(Value::as_str).unwrap_or_default();
            if !linked.is_empty()
                && (entry.get("type").and_then(Value::as_str) != Some("PASSWORD")
                    || types.get(linked) != Some(&"AUTHENTICATOR"))
            {
                entry.insert("linkedAuthenticatorId".into(), "".into());
            }
            Ok(Value::Object(entry))
        })
        .collect::<Result<Vec<_>, BackupError>>()?;

    let mut seen = HashSet::new();
    let mut typed_folder = HashSet::new();
    let links: Vec<Value> = contents
        .links
        .iter()
        .filter(|(entry_id, group_id)| {
            let (Some(entry_type), Some(folder_type)) = (types.get(entry_id.as_str()), folders.get(group_id.as_str())) else {
                return false;
            };
            if !folder_type.is_empty() && (folder_type != entry_type || typed_folder.contains(entry_id.as_str())) {
                return false;
            }
            if !seen.insert((entry_id.as_str(), group_id.as_str())) {
                return false;
            }
            if !folder_type.is_empty() {
                typed_folder.insert(entry_id.as_str());
            }
            true
        })
        .map(|(entry_id, group_id)| json!({"entryId": entry_id, "groupId": group_id}))
        .collect();

    let mut photo_ids = Vec::new();
    let mut photos = Vec::new();
    for photo in &contents.photos {
        if !types.contains_key(photo.entry_id.as_str()) {
            continue;
        }
        if !valid_photo_id(&photo.id) || photo_ids.contains(&photo.id) || photo.added_at < 0 {
            return Err(BackupError::InvalidItem);
        }
        photo_ids.push(photo.id.clone());
        photos.push(json!({"id": photo.id, "entryId": photo.entry_id, "isCover": photo.is_cover, "addedAt": photo.added_at}));
    }

    let groups: Vec<Value> = contents
        .groups
        .iter()
        .map(|group| json!({"id": group.id, "name": group.name, "notes": group.notes, "folderType": group.folder_type}))
        .collect();
    let mut root = json!({
        "version": 9,
        "vaultId": contents.vault_id,
        "entries": entries,
        "groups": groups,
        "links": links,
        "photos": photos,
        "passkeys": contents.passkeys,
    });
    if let Some((accent, surface)) = &contents.appearance {
        root["appearanceAccent"] = accent.as_str().into();
        root["appearanceSurface"] = surface.as_str().into();
    }
    let json = Zeroizing::new(serde_json::to_vec(&root).map_err(|_| BackupError::InvalidItem)?);
    drop(root);
    if json.len() > MAX_METADATA {
        return Err(BackupError::TooLarge);
    }
    Ok(Metadata { json, photo_ids })
}

/// Writes a whole backup to `out`: the header, then the archive of `vault.json` and each photo
/// that `photo` returns, encrypted. Returns `out` once the last segment is sealed.
pub fn write<W: Write, E: From<BackupError>>(
    out: W,
    key: &BackupKey,
    metadata: &Metadata,
    mut photo: impl FnMut(&str) -> Result<Zeroizing<Vec<u8>>, E>,
) -> Result<W, E> {
    let mut zip = ZipWriter::new(EncryptingWriter::new(out, key)?);
    zip.add("vault.json", &metadata.json)?;
    for id in &metadata.photo_ids {
        let bytes = photo(id)?;
        zip.add(&format!("photos/{id}"), &bytes)?;
    }
    Ok(zip.finish()?.finish().map_err(BackupError::from)?)
}

#[cfg(test)]
pub(crate) mod read {
    //! Opens a `.pvault`, for the tests: what Android's `BackupCipher.decrypt` does.

    use std::io::{self, Read};

    use super::*;

    const MAGIC_V1: &[u8; 8] = b"PVLT0001";

    pub struct DecryptingReader<R: Read> {
        input: R,
        cipher: Aes128Gcm,
        nonce_prefix: [u8; NONCE_PREFIX_BYTES],
        segment: u32,
        plain: Zeroizing<Vec<u8>>,
        position: usize,
        lookahead: Option<u8>,
        finished: bool,
    }

    fn read_array<const N: usize>(input: &mut impl Read) -> io::Result<[u8; N]> {
        let mut bytes = [0; N];
        input.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    /// Reads the header, opens the keyset with `password`, and returns the decrypted body.
    pub fn open<R: Read>(mut input: R, password: &str) -> Result<DecryptingReader<R>, BackupError> {
        let magic: [u8; 8] = read_array(&mut input)?;
        let (prefix, kdf) = if &magic == MAGIC_V1 {
            (magic.to_vec(), Kdf::LEGACY)
        } else if &magic == MAGIC {
            let settings: [u8; 12] = read_array(&mut input)?;
            let value = |at: usize| u32::from_be_bytes(settings[at..at + 4].try_into().expect("4 bytes"));
            let kdf = Kdf { memory_kib: value(0), iterations: value(4), parallelism: value(8) };
            if !kdf.valid() {
                return Err(BackupError::Unsupported);
            }
            ([&magic[..], &settings[..]].concat(), kdf)
        } else {
            return Err(BackupError::Unsupported);
        };
        let salt: [u8; SALT_BYTES] = read_array(&mut input)?;
        let nonce: [u8; NONCE_BYTES] = read_array(&mut input)?;
        let length = u32::from_be_bytes(read_array(&mut input)?) as usize;
        if !(1..=MAX_WRAPPED_KEY).contains(&length) {
            return Err(BackupError::Unsupported);
        }
        let mut wrapped = vec![0; length];
        input.read_exact(&mut wrapped)?;
        let wrapping_key = derive(password, &salt, kdf)?;
        let keyset = Zeroizing::new(
            Aes256Gcm::new_from_slice(&*wrapping_key)
                .expect("32-byte key")
                .decrypt(Nonce::from_slice(&nonce), Payload { msg: &wrapped, aad: &prefix })
                .map_err(|_| BackupError::WrongPasswordOrDamaged)?,
        );
        let material = key_material(&keyset).ok_or(BackupError::Unsupported)?;
        let header: [u8; STREAM_HEADER_BYTES] = read_array(&mut input)?;
        if usize::from(header[0]) != STREAM_HEADER_BYTES {
            return Err(BackupError::WrongPasswordOrDamaged);
        }
        let stream_key = hkdf_key(&*material, &header[1..1 + KEY_BYTES], ASSOCIATED_DATA);
        Ok(DecryptingReader {
            input,
            cipher: Aes128Gcm::new_from_slice(&*stream_key).expect("16-byte key"),
            nonce_prefix: header[1 + KEY_BYTES..].try_into().expect("7 bytes"),
            segment: 0,
            plain: Zeroizing::new(Vec::new()),
            position: 0,
            lookahead: None,
            finished: false,
        })
    }

    enum Field<'a> {
        Number(u64),
        Bytes(&'a [u8]),
    }

    fn varint(bytes: &mut &[u8]) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = bytes.split_first()?;
            *bytes = rest;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    /// The fields of one message: varints and length-delimited only, as a keyset has.
    fn fields(mut bytes: &[u8]) -> Option<Vec<(u64, Field<'_>)>> {
        let mut fields = Vec::new();
        while !bytes.is_empty() {
            let tag = varint(&mut bytes)?;
            let field = match tag & 7 {
                0 => Field::Number(varint(&mut bytes)?),
                2 => {
                    let length = usize::try_from(varint(&mut bytes)?).ok()?;
                    if length > bytes.len() {
                        return None;
                    }
                    let (value, rest) = bytes.split_at(length);
                    bytes = rest;
                    Field::Bytes(value)
                }
                _ => return None,
            };
            fields.push((tag >> 3, field));
        }
        Some(fields)
    }

    fn number(fields: &[(u64, Field<'_>)], wanted: u64) -> u64 {
        fields.iter().rev().find_map(|(field, value)| match value {
            Field::Number(number) if *field == wanted => Some(*number),
            _ => None,
        }).unwrap_or(0)
    }

    fn bytes<'a>(fields: &[(u64, Field<'a>)], wanted: u64) -> &'a [u8] {
        fields.iter().rev().find_map(|(field, value)| match value {
            Field::Bytes(bytes) if *field == wanted => Some(*bytes),
            _ => None,
        }).unwrap_or_default()
    }

    /// The key material of the keyset's primary key, when it is the one key type and size this
    /// format uses (`AES128_GCM_HKDF_1MB`).
    pub(crate) fn key_material(keyset: &[u8]) -> Option<Zeroizing<[u8; KEY_BYTES]>> {
        let keyset = fields(keyset)?;
        let primary = number(&keyset, 1);
        let entry = keyset.iter().find_map(|(field, value)| match value {
            Field::Bytes(bytes) if *field == 2 => fields(bytes).filter(|key| number(key, 3) == primary),
            _ => None,
        })?;
        if number(&entry, 2) != STATUS_ENABLED || number(&entry, 4) != OUTPUT_PREFIX_RAW {
            return None;
        }
        let key_data = fields(bytes(&entry, 1))?;
        if bytes(&key_data, 1) != TYPE_URL.as_bytes() || number(&key_data, 3) != KEY_MATERIAL_SYMMETRIC {
            return None;
        }
        let key = fields(bytes(&key_data, 2))?;
        let params = fields(bytes(&key, 2))?;
        if number(&key, 1) != 0
            || number(&params, 1) != SEGMENT_BYTES as u64
            || number(&params, 2) != KEY_BYTES as u64
            || number(&params, 3) != HASH_SHA256
        {
            return None;
        }
        let material: [u8; KEY_BYTES] = bytes(&key, 3).try_into().ok()?;
        Some(Zeroizing::new(material))
    }

    fn damaged() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, "The backup is damaged")
    }

    impl<R: Read> DecryptingReader<R> {
        fn next_segment(&mut self) -> io::Result<()> {
            let size = if self.segment == 0 { SEGMENT_BYTES - STREAM_HEADER_BYTES } else { SEGMENT_BYTES };
            let mut segment = Zeroizing::new(Vec::with_capacity(size));
            segment.extend(self.lookahead.take());
            let mut chunk = [0; 8192];
            while segment.len() < size {
                let wanted = chunk.len().min(size - segment.len());
                match self.input.read(&mut chunk[..wanted])? {
                    0 => break,
                    count => segment.extend_from_slice(&chunk[..count]),
                }
            }
            let mut next = [0];
            let last = segment.len() < size || self.input.read(&mut next)? == 0;
            if !last {
                self.lookahead = Some(next[0]);
            }
            if segment.len() < TAG_BYTES {
                return Err(damaged());
            }
            let tag_at = segment.len() - TAG_BYTES;
            let (body, tag) = segment.split_at_mut(tag_at);
            let nonce = segment_nonce(&self.nonce_prefix, self.segment, last);
            self.cipher
                .decrypt_in_place_detached(Nonce::from_slice(&nonce), b"", body, (&*tag).into())
                .map_err(|_| damaged())?;
            let plain_length = body.len();
            segment.truncate(plain_length);
            self.plain = segment;
            self.position = 0;
            self.segment = self.segment.checked_add(1).ok_or_else(damaged)?;
            self.finished = last;
            Ok(())
        }
    }

    impl<R: Read> Read for DecryptingReader<R> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            while self.position == self.plain.len() {
                if self.finished {
                    return Ok(0);
                }
                self.next_segment()?;
            }
            let count = out.len().min(self.plain.len() - self.position);
            out[..count].copy_from_slice(&self.plain[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        }
    }

    /// The members of a stored-only ZIP archive that [`ZipWriter`] wrote, by name.
    pub fn stored_members(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut members = Vec::new();
        let mut at = 0;
        let u16_at = |at: usize| u16::from_le_bytes(archive[at..at + 2].try_into().unwrap()) as usize;
        let u32_at = |at: usize| u32::from_le_bytes(archive[at..at + 4].try_into().unwrap());
        while u32_at(at) == 0x0403_4b50 {
            assert_eq!(u16_at(at + 8), 0, "stored");
            let size = u32_at(at + 18) as usize;
            assert_eq!(size, u32_at(at + 22) as usize);
            let name_length = u16_at(at + 26);
            let data_at = at + 30 + name_length + u16_at(at + 28);
            let name = String::from_utf8(archive[at + 30..at + 30 + name_length].to_vec()).unwrap();
            let data = archive[data_at..data_at + size].to_vec();
            assert_eq!(crc32(&data), u32_at(at + 14), "{name}");
            members.push((name, data));
            at = data_at + size;
        }
        members
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::{read::*, *};

    const PASSWORD: &str = "correct horse battery staple";

    fn key() -> BackupKey {
        BackupKey::new(PASSWORD, Kdf::LEGACY).unwrap()
    }

    fn encrypt(plain: &[u8], chunk: usize) -> Vec<u8> {
        let mut writer = EncryptingWriter::new(Vec::new(), &key()).unwrap();
        for part in plain.chunks(chunk.max(1)) {
            writer.write_all(part).unwrap();
        }
        writer.finish().unwrap()
    }

    fn decrypt(file: &[u8], password: &str) -> Result<Vec<u8>, BackupError> {
        let mut body = Vec::new();
        open(file, password)?.read_to_end(&mut body)?;
        Ok(body)
    }

    fn pattern(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index * 31 % 251) as u8).collect()
    }

    /// Header, wrapped keyset and stream header, before the first segment.
    fn body_offset(file: &[u8]) -> usize {
        let wrapped = u32::from_be_bytes(file[48..52].try_into().unwrap()) as usize;
        52 + wrapped + STREAM_HEADER_BYTES
    }

    #[test]
    fn hkdf_matches_rfc_5869() {
        // RFC 5869, test case 1 (SHA-256), the first 16 bytes of the output.
        let key = hkdf_key(&[0x0b; 22], &(0..=0x0c).collect::<Vec<u8>>(), &(0xf0..=0xf9).collect::<Vec<u8>>());
        assert_eq!(key.as_slice(), [0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a]);
    }

    #[test]
    fn crc32_matches_the_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn the_header_is_androids_format_two() {
        let file = encrypt(b"body", 7);
        assert_eq!(&file[..8], b"PVLT0002");
        assert_eq!(&file[8..20], &[0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1]);
        // Salt and nonce, then the wrapped keyset: AES-GCM adds its 16-byte tag.
        let wrapped = u32::from_be_bytes(file[48..52].try_into().unwrap()) as usize;
        assert!((100..200).contains(&wrapped), "{wrapped}");
        assert_eq!(file[52 + wrapped], STREAM_HEADER_BYTES as u8);
    }

    /// A keyset like [`keyset_bytes`], with one setting changed.
    fn keyset_with(segment: u64, hash: u64, status: u64, prefix: u64, primary: u32) -> Vec<u8> {
        let mut params = Vec::new();
        put_number(&mut params, 1, segment);
        put_number(&mut params, 2, KEY_BYTES as u64);
        put_number(&mut params, 3, hash);
        let mut key = Vec::new();
        put_bytes(&mut key, 2, &params);
        put_bytes(&mut key, 3, &[7; KEY_BYTES]);
        let mut key_data = Vec::new();
        put_bytes(&mut key_data, 1, TYPE_URL.as_bytes());
        put_bytes(&mut key_data, 2, &key);
        put_number(&mut key_data, 3, KEY_MATERIAL_SYMMETRIC);
        let mut entry = Vec::new();
        put_bytes(&mut entry, 1, &key_data);
        put_number(&mut entry, 2, status);
        put_number(&mut entry, 3, 42);
        put_number(&mut entry, 4, prefix);
        let mut keyset = Vec::new();
        put_number(&mut keyset, 1, u64::from(primary));
        put_bytes(&mut keyset, 2, &entry);
        keyset
    }

    #[test]
    fn the_keyset_is_one_raw_streaming_key() {
        let keyset = keyset_bytes(&[7; KEY_BYTES], 42);
        assert_eq!(*key_material(&keyset).unwrap(), [7; KEY_BYTES]);
        assert_eq!(keyset.as_slice(), keyset_with(SEGMENT_BYTES as u64, HASH_SHA256, STATUS_ENABLED, OUTPUT_PREFIX_RAW, 42));
        // Anything else is refused: another segment size or hash, a key that is off or not raw, or
        // a primary key that is not in the keyset.
        for other in [
            keyset_with(4096, HASH_SHA256, STATUS_ENABLED, OUTPUT_PREFIX_RAW, 42),
            keyset_with(SEGMENT_BYTES as u64, 1, STATUS_ENABLED, OUTPUT_PREFIX_RAW, 42),
            keyset_with(SEGMENT_BYTES as u64, HASH_SHA256, 2, OUTPUT_PREFIX_RAW, 42),
            keyset_with(SEGMENT_BYTES as u64, HASH_SHA256, STATUS_ENABLED, 1, 42),
            keyset_with(SEGMENT_BYTES as u64, HASH_SHA256, STATUS_ENABLED, OUTPUT_PREFIX_RAW, 43),
        ] {
            assert!(key_material(&other).is_none());
        }
    }

    #[test]
    fn a_body_of_any_size_opens_again() {
        for length in [
            0,
            1,
            FIRST_PLAIN_SEGMENT_BYTES - 1,
            FIRST_PLAIN_SEGMENT_BYTES,
            FIRST_PLAIN_SEGMENT_BYTES + 1,
            FIRST_PLAIN_SEGMENT_BYTES + PLAIN_SEGMENT_BYTES,
            FIRST_PLAIN_SEGMENT_BYTES + PLAIN_SEGMENT_BYTES + 1,
            3 * SEGMENT_BYTES + 12_345,
        ] {
            let plain = pattern(length);
            for chunk in [1_000_003, 65_536, 4_093] {
                let file = encrypt(&plain, chunk);
                // As Tink: one tag per segment, and the last segment is empty only for an empty body.
                let segments = if length <= FIRST_PLAIN_SEGMENT_BYTES { 1 } else {
                    1 + (length - FIRST_PLAIN_SEGMENT_BYTES).div_ceil(PLAIN_SEGMENT_BYTES)
                };
                assert_eq!(file.len(), body_offset(&file) + length + segments * TAG_BYTES, "{length}");
                assert_eq!(decrypt(&file, PASSWORD).unwrap(), plain, "{length} in chunks of {chunk}");
            }
        }
    }

    #[test]
    fn a_wrong_password_or_a_changed_file_does_not_open() {
        let plain = pattern(FIRST_PLAIN_SEGMENT_BYTES + 5_000);
        let file = encrypt(&plain, 10_000);
        assert!(matches!(decrypt(&file, "another password here"), Err(BackupError::WrongPasswordOrDamaged)));
        // Settings Android would also accept, but not the ones the keyset was sealed with.
        let mut settings = file.clone();
        settings[15] = 4;
        assert!(matches!(decrypt(&settings, PASSWORD), Err(BackupError::WrongPasswordOrDamaged)));
        // Settings outside the limits are refused before any key derivation.
        let mut heavy = file.clone();
        heavy[9] = 0x10;
        assert!(matches!(decrypt(&heavy, PASSWORD), Err(BackupError::Unsupported)));
        let body = body_offset(&file);
        for at in [body, body + FIRST_PLAIN_SEGMENT_BYTES + 3, file.len() - 1] {
            let mut changed = file.clone();
            changed[at] ^= 1;
            assert!(decrypt(&changed, PASSWORD).is_err(), "{at}");
        }
        // Cut after the first segment: that segment was not sealed as the last.
        let first = body + FIRST_PLAIN_SEGMENT_BYTES + TAG_BYTES;
        assert!(decrypt(&file[..first], PASSWORD).is_err());
        assert!(decrypt(&file[..file.len() - 1], PASSWORD).is_err());
        let mut longer = file.clone();
        longer.extend_from_slice(&[0; TAG_BYTES + 4]);
        assert!(decrypt(&longer, PASSWORD).is_err());
        assert_eq!(decrypt(&file, PASSWORD).unwrap(), plain);
    }

    #[test]
    fn settings_outside_androids_limits_are_refused() {
        for kdf in [
            Kdf { memory_kib: 1 << 20, ..Kdf::LEGACY },
            Kdf { iterations: 2, ..Kdf::LEGACY },
            Kdf { iterations: 65, ..Kdf::LEGACY },
            Kdf { parallelism: 4, ..Kdf::LEGACY },
        ] {
            assert!(matches!(BackupKey::new(PASSWORD, kdf), Err(BackupError::InvalidSettings)), "{kdf:?}");
        }
        assert!(Kdf { iterations: 64, ..Kdf::LEGACY }.valid());
    }

    #[test]
    fn each_file_has_its_own_salts() {
        let one = encrypt(b"same", 4);
        let two = encrypt(b"same", 4);
        assert_ne!(one[20..48], two[20..48]);
        assert_ne!(one[body_offset(&one) - STREAM_HEADER_BYTES..body_offset(&one)], two[body_offset(&two) - STREAM_HEADER_BYTES..body_offset(&two)]);
    }

    #[test]
    fn the_archive_holds_stored_members_with_their_checksums() {
        let mut zip = ZipWriter::new(Vec::new());
        zip.add("vault.json", b"{\"version\":9}").unwrap();
        zip.add("photos/abc-1", &pattern(70_000)).unwrap();
        zip.add("photos/empty", b"").unwrap();
        let archive = zip.finish().unwrap();
        let members = stored_members(&archive);
        assert_eq!(members.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), ["vault.json", "photos/abc-1", "photos/empty"]);
        assert_eq!(members[1].1, pattern(70_000));
        // The end record counts three members and points at the central directory.
        let end = archive.len() - 22;
        assert_eq!(&archive[end..end + 4], &[0x50, 0x4b, 0x05, 0x06]);
        assert_eq!(u16::from_le_bytes([archive[end + 10], archive[end + 11]]), 3);
        let directory = u32::from_le_bytes(archive[end + 16..end + 20].try_into().unwrap()) as usize;
        assert_eq!(&archive[directory..directory + 4], &[0x50, 0x4b, 0x01, 0x02]);
    }

    fn entry(id: &str, entry_type: &str) -> Value {
        json!({
            "id": id, "type": entry_type, "title": id, "primaryValue": "", "secondaryValue": "secret",
            "tertiaryValue": "", "fourthValue": "", "cardKind": "CREDIT", "network": "", "totpAlgorithm": "SHA1",
            "totpDigits": 6, "totpPeriod": 30, "linkedApps": "", "autofillSignatures": "", "autofillOrigins": "",
            "linkedAuthenticatorId": "", "notes": "", "color": 0xFF08704A_u64, "tags": "", "favorite": false,
            "lastOpenedAt": 0, "sortOrder": 1, "createdAt": 1, "updatedAt": 2,
        })
    }

    fn group(id: &str, folder_type: &str) -> Group {
        Group { id: id.into(), name: id.into(), notes: String::new(), folder_type: folder_type.into() }
    }

    fn contents() -> Contents {
        let mut login = entry("login", "PASSWORD");
        login["linkedAuthenticatorId"] = "code".into();
        login["groupIds"] = json!(["work"]);
        let mut card = entry("card", "CARD");
        card["linkedAuthenticatorId"] = "code".into();
        let mut stale = entry("stale", "PASSWORD");
        stale["linkedAuthenticatorId"] = "deleted-code".into();
        Contents {
            vault_id: "vault-1".into(),
            entries: vec![login, card, stale, entry("code", "AUTHENTICATOR"), entry("note", "NOTE")],
            groups: vec![group("work", ""), group("logins", "PASSWORD"), group("more-logins", "PASSWORD"), group("cards", "CARD")],
            links: vec![
                ("login".into(), "work".into()),
                ("login".into(), "logins".into()),
                ("login".into(), "more-logins".into()),
                ("login".into(), "cards".into()),
                ("login".into(), "work".into()),
                ("gone".into(), "work".into()),
                ("note".into(), "missing-folder".into()),
                ("card".into(), "cards".into()),
            ],
            photos: vec![
                Photo { id: "p-1".into(), entry_id: "card".into(), is_cover: true, added_at: 5 },
                Photo { id: "p-2".into(), entry_id: "gone".into(), is_cover: false, added_at: 6 },
            ],
            passkeys: vec![json!({"id": "pk", "rpId": "example.com"})],
            appearance: Some(("blue".into(), "slate".into())),
        }
    }

    #[test]
    fn vault_json_is_androids_version_nine_without_broken_references() {
        let metadata = metadata(&contents()).unwrap();
        let root: Value = serde_json::from_slice(&metadata.json).unwrap();
        assert_eq!((root["version"].as_i64(), root["vaultId"].as_str()), (Some(9), Some("vault-1")));
        assert_eq!((root["appearanceAccent"].as_str(), root["appearanceSurface"].as_str()), (Some("blue"), Some("slate")));
        for setting in ["lightMode", "nfcEnabled", "backgroundTimeoutMs", "inactivityTimeoutMs", "masterPasswordIntervalMs"] {
            assert!(root.get(setting).is_none(), "{setting}");
        }
        let entries = root["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0]["linkedAuthenticatorId"], "code", "a login keeps its code");
        assert_eq!(entries[1]["linkedAuthenticatorId"], "", "only a login links a code");
        assert_eq!(entries[2]["linkedAuthenticatorId"], "", "a deleted code is not linked");
        assert_eq!(entries[0]["secondaryValue"], "secret");
        assert!(entries[0].get("groupIds").is_none());
        assert_eq!(root["links"], json!([
            {"entryId": "login", "groupId": "work"},
            {"entryId": "login", "groupId": "logins"},
            {"entryId": "card", "groupId": "cards"},
        ]));
        assert_eq!(root["photos"], json!([{"id": "p-1", "entryId": "card", "isCover": true, "addedAt": 5}]));
        assert_eq!(metadata.photo_ids, ["p-1"]);
        assert_eq!(root["groups"][1], json!({"id": "logins", "name": "logins", "notes": "", "folderType": "PASSWORD"}));
        assert_eq!(root["passkeys"], json!([{"id": "pk", "rpId": "example.com"}]));
    }

    #[test]
    fn items_android_cannot_restore_are_refused() {
        let mut duplicate = contents();
        duplicate.entries.push(entry("login", "CARD"));
        assert!(matches!(metadata(&duplicate), Err(BackupError::InvalidItem)));
        let mut unknown = contents();
        unknown.entries.push(entry("x", "WIFI"));
        assert!(matches!(metadata(&unknown), Err(BackupError::InvalidItem)));
        let mut photo = contents();
        photo.photos[0].id = "../vault.json".into();
        assert!(matches!(metadata(&photo), Err(BackupError::InvalidItem)));
        let mut folder = contents();
        folder.groups.push(group("odd", "WIFI"));
        assert!(matches!(metadata(&folder), Err(BackupError::InvalidItem)));
        let mut no_vault = contents();
        no_vault.vault_id = " ".into();
        assert!(matches!(metadata(&no_vault), Err(BackupError::InvalidItem)));
    }

    #[test]
    fn a_whole_backup_opens_with_its_members() {
        let metadata = metadata(&contents()).unwrap();
        let photo = pattern(2 * SEGMENT_BYTES);
        let file = write(Vec::new(), &key(), &metadata, |id| {
            assert_eq!(id, "p-1");
            Ok::<_, BackupError>(Zeroizing::new(photo.clone()))
        })
        .unwrap();
        let body = decrypt(&file, PASSWORD).unwrap();
        let members = stored_members(&body);
        assert_eq!(members.len(), 2);
        assert_eq!(members[0], ("vault.json".to_owned(), metadata.json.to_vec()));
        assert_eq!(members[1], ("photos/p-1".to_owned(), photo));
        // Nothing of the vault is readable in the file.
        for plain in [&b"secret"[..], b"vault.json", b"photos/", b"vault-1"] {
            assert!(!file.windows(plain.len()).any(|window| window == plain), "{}", String::from_utf8_lossy(plain));
        }
    }

    #[test]
    fn a_photo_that_cannot_be_read_stops_the_backup() {
        let metadata = metadata(&contents()).unwrap();
        let result = write(Vec::new(), &key(), &metadata, |_| Err::<Zeroizing<Vec<u8>>, _>(BackupError::InvalidItem));
        assert!(matches!(result, Err(BackupError::InvalidItem)));
    }

    #[test]
    fn a_backup_from_android_opens() {
        // Made by Nuvori for Android's own `BackupCipher` with Tink 1.23.0 (format 2, 5 passes),
        // around an archive as `VaultBackupManager.export` writes it (deflated).
        let file = include_bytes!("../fixtures/android-backup-v2.pvault");
        assert_eq!(&file[8..20], &[0, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 1]);
        let body = decrypt(file, "synthetic fixture password").unwrap();
        assert_eq!(body, include_bytes!("../fixtures/android-backup-v2.zip"));
        assert!(matches!(decrypt(file, PASSWORD), Err(BackupError::WrongPasswordOrDamaged)));
    }
}
