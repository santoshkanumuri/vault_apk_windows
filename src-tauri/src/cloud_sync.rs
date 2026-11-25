//! Cloud sync: the user's own cloud drive carries the group's signed changes between devices
//! that are not on the same Wi-Fi. Format `nv1`, shared with Android `CloudSync.kt`
//! (`docs/CLOUD-SYNC.md`, vectors in `fixtures/cloud-sync-v1.json`).
//!
//! The drive is a mailbox, not an authority. Every change is signed by its author and
//! hash-chained, and membership is a signed chain, exactly as in Wi-Fi sync. A file that fails
//! those checks is ignored. The provider can read nothing: change payloads and photo blobs are
//! already encrypted under the group's content key, and each file is sealed again under a key
//! derived from the group's transport secret, so entry IDs, device IDs and times stay private.
//!
//! Files, all in the provider's app-only folder:
//!
//! | Name                                   | Content (after opening the envelope)        |
//! |----------------------------------------|---------------------------------------------|
//! | `nv1.<group>.m.<count>.<head16>`       | JSON array of membership events             |
//! | `nv1.<group>.o.<device>.<first>.<last>`| JSON array of changes by one author         |
//! | `nv1.<group>.p.<device>`               | `{deviceId, updatedAt, progress}`           |
//! | `nv1.<group>.b.<sha256>`               | a photo blob as stored (no envelope)        |
//! | `nv1.<group>.l.<device>`               | `{request, signature}`: a signed leave request |
//!
//! - cloud key = HMAC-SHA256(transport secret, `nuvori-cloud-v1:<vaultId>`)
//! - `<group>` = first 8 bytes, hex, of HMAC-SHA256(cloud key, `tag`)
//! - `<device>` = first 8 bytes, hex, of HMAC-SHA256(cloud key, `device:<deviceId>`)
//! - envelope = `NVC1` || nonce(12) || AES-256-GCM(cloud key, plaintext, AAD = file name)
//! - `<count>` is 10 digits, `<first>` and `<last>` are 12 digits, zero padded
//!
//! A file is written once and never changed, except the progress file. Any device may upload
//! any author's changes that the drive lacks, so a device that never connects to the drive
//! still reaches it through one that does. Two devices that upload the same range only make a
//! harmless duplicate.

use super::*;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::Digest;

const ENVELOPE_MAGIC: &[u8; 4] = b"NVC1";
/// One uploaded file of changes holds at most this many.
const UPLOAD_OPERATIONS: usize = 256;
const UPLOAD_BYTES: usize = 2 * 1024 * 1024;
/// A downloaded file of changes may be this large; a larger one is ignored.
const DOWNLOAD_OPERATIONS: usize = 1024;
const DOWNLOAD_BYTES: u64 = 16 * 1024 * 1024;
const MEMBERSHIP_BYTES: u64 = 1_000_000 + 64;
const PROGRESS_BYTES: u64 = 200_000;
/// Work bounds for one pass; the next pass continues.
const UPLOAD_FILES_PER_PASS: usize = 64;
const PHOTOS_PER_PASS: usize = 32;
/// Blobs under a rotated prefix are sealed in memory; larger ones travel over Wi-Fi only.
const SEALED_BLOB_BYTES: u64 = 32 * 1024 * 1024;
/// "NVC1", nonce and tag around a sealed blob.
const BLOB_ENVELOPE: u64 = 4 + 12 + 16;
/// A relisting starts this long before the newest file seen, to cover provider clock skew.
const LIST_OVERLAP: time::Duration = time::Duration::minutes(10);

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS cloud_sync_files (
        vault_id TEXT NOT NULL, file_id TEXT NOT NULL, name TEXT NOT NULL,
        size INTEGER NOT NULL, modified TEXT NOT NULL, PRIMARY KEY (vault_id, file_id));
    CREATE TABLE IF NOT EXISTS cloud_sync_compaction (
        vault_id TEXT NOT NULL PRIMARY KEY, drive_compacted_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS cloud_sync_state (
        vault_id TEXT NOT NULL PRIMARY KEY, cursor TEXT NOT NULL DEFAULT '',
        last_sync_utc TEXT NOT NULL DEFAULT '', progress_digest TEXT NOT NULL DEFAULT '');";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloudError {
    /// The saved sign-in no longer works; the user must connect again.
    Auth,
    Offline,
    /// The drive is full.
    Quota,
    NotFound,
    /// The provider asked to slow down.
    Busy,
    Other(String),
}

impl CloudError {
    /// A fixed sentence for the UI. It never contains file names or account data.
    pub fn message(&self) -> String {
        match self {
            Self::Auth => AUTH_NEEDED.into(),
            Self::Offline => "Can't reach Google Drive. Check the internet connection.".into(),
            Self::Quota => "Your Google Drive is full. Free some space, then sync again.".into(),
            Self::NotFound => "A sync file is gone from Google Drive. Sync will check again.".into(),
            Self::Busy => "Google Drive is busy. Sync will retry soon.".into(),
            Self::Other(_) => "Google Drive sync failed. Sync will retry.".into(),
        }
    }
}

pub const AUTH_NEEDED: &str = "Google Drive needs you to sign in again.";

type Cloud<T> = std::result::Result<T, CloudError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudFile {
    pub id: String,
    pub name: String,
    pub size: u64,
    /// RFC 3339 in UTC, as the provider reports it.
    pub modified: String,
}

/// The few drive operations cloud sync needs. `google_drive.rs` implements it for Google Drive.
pub trait CloudStore {
    /// Files in the app folder, all of them or only those changed after `modified_after`.
    fn list(&mut self, modified_after: Option<&str>) -> Cloud<Vec<CloudFile>>;
    /// Streams a file to `sink`; fails with `Other` when it is larger than `max_bytes`.
    fn download(&mut self, id: &str, max_bytes: u64, sink: &mut dyn FnMut(&[u8]) -> Cloud<()>) -> Cloud<()>;
    fn upload(&mut self, name: &str, size: u64, content: &mut dyn Read) -> Cloud<CloudFile>;
    fn replace(&mut self, id: &str, content: &[u8]) -> Cloud<CloudFile>;
    /// Drive cleanup only (`compaction.rs` `drive`). A file already gone is `NotFound`.
    fn delete(&mut self, _id: &str) -> Cloud<()> {
        Err(CloudError::Other("delete unsupported".into()))
    }
}

fn download_bytes(store: &mut dyn CloudStore, id: &str, max_bytes: u64) -> Cloud<Vec<u8>> {
    let mut bytes = Vec::new();
    store.download(id, max_bytes, &mut |chunk| {
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(bytes)
}

fn upload_bytes(store: &mut dyn CloudStore, name: &str, bytes: &[u8]) -> Cloud<CloudFile> {
    store.upload(name, bytes.len() as u64, &mut &bytes[..])
}

/// What a file name in the app folder means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloudName {
    Membership { count: u64, head: String },
    Operations { device: String, first: u64, last: u64 },
    Progress { device: String },
    Blob { hash: String },
    Leave { device: String },
    /// `e.<epoch>.<recipient>`: the signed package set of a new epoch, under the previous prefix (`epoch_keys.rs`).
    Packages { epoch: u64, recipient: String },
    /// `k.<device>`: a device's signed key statement.
    Statement { device: String },
    /// `c.<author>`: a floor marker of drive compaction (`compaction.rs` `drive`).
    Floor { author: String },
}

fn hex_field(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn number_field(text: &str, length: usize) -> Option<u64> {
    (text.len() == length && text.bytes().all(|byte| byte.is_ascii_digit())).then(|| text.parse().ok()).flatten()
}

/// Names and the envelope for one sync group.
pub struct CloudKeys {
    key: Zeroizing<[u8; 32]>,
    tag: String,
}

impl CloudKeys {
    pub fn derive(transport_secret: &[u8], vault_id: &str) -> Option<Self> {
        if transport_secret.len() != 32 {
            return None;
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(transport_secret).ok()?;
        mac.update(format!("nuvori-cloud-v1:{vault_id}").as_bytes());
        let key = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        let mut keys = Self { key, tag: String::new() };
        keys.tag = keys.short_mac("tag");
        Some(keys)
    }

    fn short_mac(&self, label: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.key).expect("32-byte key");
        mac.update(label.as_bytes());
        hex::encode(&mac.finalize().into_bytes()[..8])
    }

    pub fn device_tag(&self, device_id: &str) -> String {
        self.short_mac(&format!("device:{device_id}"))
    }

    pub fn prefix(&self) -> String {
        format!("nv1.{}.", self.tag)
    }

    pub fn membership_name(&self, count: u64, head: &str) -> String {
        format!("{}m.{count:010}.{}", self.prefix(), &head[..16.min(head.len())])
    }

    pub fn operations_name(&self, device_id: &str, first: u64, last: u64) -> String {
        format!("{}o.{}.{first:012}.{last:012}", self.prefix(), self.device_tag(device_id))
    }

    pub fn progress_name(&self, device_id: &str) -> String {
        format!("{}p.{}", self.prefix(), self.device_tag(device_id))
    }

    pub fn blob_name(&self, hash: &str) -> String {
        format!("{}b.{hash}", self.prefix())
    }

    pub fn leave_name(&self, device_id: &str) -> String {
        format!("{}l.{}", self.prefix(), self.device_tag(device_id))
    }

    /// The managing phone writes these (`EpochKeyRotation`); this PC only reads them.
    #[allow(dead_code)]
    pub fn package_name(&self, epoch: u64, recipient: &str) -> String {
        format!("{}e.{epoch}.{}", self.prefix(), self.device_tag(recipient))
    }

    pub fn statement_name(&self, device_id: &str) -> String {
        format!("{}k.{}", self.prefix(), self.device_tag(device_id))
    }

    pub fn floor_name(&self, author: &str) -> String {
        format!("{}c.{}", self.prefix(), self.device_tag(author))
    }

    /// `None` for a file of another group or with a name this version does not know.
    pub fn parse(&self, name: &str) -> Option<CloudName> {
        let parts: Vec<&str> = name.strip_prefix(&self.prefix())?.split('.').collect();
        match parts.as_slice() {
            ["m", count, head] if hex_field(head, 16) => {
                Some(CloudName::Membership { count: number_field(count, 10).filter(|count| *count > 0)?, head: (*head).into() })
            }
            ["o", device, first, last] if hex_field(device, 16) => {
                let (first, last) = (number_field(first, 12)?, number_field(last, 12)?);
                (first >= 1 && last >= first).then(|| CloudName::Operations { device: (*device).into(), first, last })
            }
            ["p", device] if hex_field(device, 16) => Some(CloudName::Progress { device: (*device).into() }),
            ["b", hash] if photo_blobs::valid_hash(hash) => Some(CloudName::Blob { hash: (*hash).into() }),
            ["l", device] if hex_field(device, 16) => Some(CloudName::Leave { device: (*device).into() }),
            ["e", epoch, recipient] if hex_field(recipient, 16) && !epoch.is_empty() && epoch.len() <= 10
                && !epoch.starts_with('0') && epoch.bytes().all(|byte| byte.is_ascii_digit()) => {
                let epoch: u64 = epoch.parse().ok()?;
                (epoch >= 2).then(|| CloudName::Packages { epoch, recipient: (*recipient).into() })
            }
            ["k", device] if hex_field(device, 16) => Some(CloudName::Statement { device: (*device).into() }),
            ["c", author] if hex_field(author, 16) => Some(CloudName::Floor { author: (*author).into() }),
            _ => None,
        }
    }

    pub fn seal(&self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(storage_error)?;
        self.seal_with_nonce(name, plaintext, &nonce)
    }

    fn seal_with_nonce(&self, name: &str, plaintext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let ciphertext = Aes256Gcm::new_from_slice(&*self.key)
            .expect("32-byte key")
            .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: name.as_bytes() })
            .map_err(|_| storage_error("cloud envelope"))?;
        Ok([ENVELOPE_MAGIC.as_slice(), nonce, &ciphertext].concat())
    }

    /// `None` when the bytes were not sealed by this group under this file name.
    pub fn open(&self, name: &str, sealed: &[u8]) -> Option<Vec<u8>> {
        let body = sealed.strip_prefix(ENVELOPE_MAGIC.as_slice()).filter(|body| body.len() >= 12 + 16)?;
        Aes256Gcm::new_from_slice(&*self.key)
            .expect("32-byte key")
            .decrypt(Nonce::from_slice(&body[..12]), Payload { msg: &body[12..], aad: name.as_bytes() })
            .ok()
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// The time to list from: a little before the newest file already seen.
fn relist_from(cursor: &str) -> Option<String> {
    let newest = time::OffsetDateTime::parse(cursor, &time::format_description::well_known::Rfc3339).ok()?;
    (newest - LIST_OVERLAP).format(&time::format_description::well_known::Rfc3339).ok()
}

struct Context {
    vault_id: String,
    events: Vec<MembershipEvent>,
    keys: CloudKeys,
    content_key: Zeroizing<Vec<u8>>,
    local: crate::identity::DeviceIdentity,
    blobs: PhotoBlobs,
    files: Vec<CloudFile>,
    cursor: String,
    progress_digest: String,
    revision: u64,
    /// "Mark as lost" on this PC (`merge_join.rs`).
    freeze: Option<crate::merge_join::LostFreeze>,
    /// The keys of every prefix this PC holds a secret for, newest first (`keys` is the first), with
    /// the epoch of each prefix (1 for the root): new files go to the newest, files under every one
    /// are read (`epoch_keys.rs`).
    ring: Vec<(u64, CloudKeys)>,
    /// The epoch of the prefix new files go to.
    keys_epoch: u64,
    /// The group's root transport secret, to rebuild the ring when new keys arrive in a pass.
    root: Zeroizing<Vec<u8>>,
}

impl Context {
    fn keys_for(&self, name: &str) -> Option<&CloudKeys> {
        self.ring.iter().find(|(_, keys)| name.starts_with(&keys.prefix())).map(|(_, keys)| keys)
    }

    fn epoch_for(&self, name: &str) -> Option<u64> {
        self.ring.iter().find(|(_, keys)| name.starts_with(&keys.prefix())).map(|(epoch, _)| *epoch)
    }

    /// The newest prefix and the ring for `epoch`, from the random secrets in `vault.db` (never from
    /// memory, C1): no file ever goes under an older prefix than the newest this PC holds a secret for.
    fn rebuild(&mut self, epoch: u64, random: &BTreeMap<u64, Zeroizing<[u8; 32]>>) -> Result<()> {
        let (keys_epoch, drive) = crate::epoch_keys::drive_secret(&self.root, epoch, random);
        self.keys = CloudKeys::derive(&drive, &self.vault_id).ok_or("Invalid sync keys")?;
        self.keys_epoch = keys_epoch;
        let mut ring = vec![(keys_epoch, CloudKeys::derive(&drive, &self.vault_id).ok_or("Invalid sync keys")?)];
        let older = random.iter().rev().map(|(epoch, secret)| (*epoch, secret.to_vec())).chain(std::iter::once((1, self.root.to_vec())));
        for (epoch, secret) in older {
            if let Some(keys) = CloudKeys::derive(&secret, &self.vault_id)
                && !ring.iter().any(|(_, known)| known.prefix() == keys.prefix())
            {
                ring.push((epoch, keys));
            }
        }
        self.ring = ring;
        Ok(())
    }

    fn parse(&self, name: &str) -> Option<CloudName> {
        self.keys_for(name)?.parse(name)
    }

    fn open(&self, name: &str, sealed: &[u8]) -> Option<Vec<u8>> {
        self.keys_for(name)?.open(name, sealed)
    }
}

/// A drive progress report signed by its device's identity (H2 of the key-rotation review), as
/// Android `DriveProgress`; vectors `progressFile` in `fixtures/epoch-keys-v1.json`.
pub(crate) mod drive_progress {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};

    use crate::progress::SyncProgress;

    pub fn signing_bytes(vault_id: &str, device_id: &str, prefix_epoch: u64, updated_at: i64, key_epoch: u64,
        progress_text: &str, features: &[String]) -> Vec<u8> {
        let mut sorted = features.to_vec();
        sorted.sort();
        format!("nuvori-drive-progress-v1\n{vault_id}\n{device_id}\n{prefix_epoch}\n{updated_at}\n{key_epoch}\n{}\n{}",
            hex::encode(Sha256::digest(progress_text.as_bytes())), sorted.join(",")).into_bytes()
    }

    /// The body: `progress` (an object, for older builds), `progressText` (what is signed), and the signature.
    #[allow(clippy::too_many_arguments)]
    pub fn body(vault_id: &str, device_id: &str, prefix_epoch: u64, updated_at: i64, key_epoch: u64, progress_text: &str,
        features: &[&str], sign: impl FnOnce(&[u8]) -> Option<[u8; 64]>) -> Result<serde_json::Value, String> {
        let features: Vec<String> = features.iter().map(|feature| (*feature).to_owned()).collect();
        let mut body = serde_json::json!({
            "deviceId": device_id,
            "updatedAt": updated_at,
            "keyEpoch": key_epoch,
            "prefixEpoch": prefix_epoch,
            "progress": serde_json::from_str::<serde_json::Value>(progress_text).map_err(|error| error.to_string())?,
            "progressText": progress_text,
            // Older builds ignore these keys. A member that syncs only through the drive learns the features here.
            "features": features,
        });
        if let Some(signature) = sign(&signing_bytes(vault_id, device_id, prefix_epoch, updated_at, key_epoch, progress_text, &features)) {
            body["signature"] = URL_SAFE_NO_PAD.encode(signature).into();
        }
        Ok(body)
    }

    /// The progress and features when `device_id` (identity `public_key`) signed the report for this
    /// group under the prefix of `prefix_epoch`; otherwise `None`.
    pub fn verify(body: &serde_json::Value, vault_id: &str, device_id: &str, public_key: &[u8; 32], prefix_epoch: u64)
        -> Option<(SyncProgress, Option<Vec<String>>)> {
        if body["deviceId"].as_str() != Some(device_id) || body["prefixEpoch"].as_u64() != Some(prefix_epoch) {
            return None;
        }
        let text = body["progressText"].as_str()?;
        let features = super::peer_features(body);
        let signature: [u8; 64] = URL_SAFE_NO_PAD.decode(body["signature"].as_str()?).ok()?.try_into().ok()?;
        let bytes = signing_bytes(vault_id, device_id, prefix_epoch, body["updatedAt"].as_i64()?, body["keyEpoch"].as_u64()?, text,
            features.as_deref().unwrap_or_default());
        VerifyingKey::from_bytes(public_key).ok()?.verify(&bytes, &Signature::from_bytes(&signature)).ok()?;
        Some((SyncProgress::parse(text.as_bytes()).ok()?, features))
    }
}

/// This build's features, sorted, for the drive progress file.
fn sorted_features() -> Vec<&'static str> {
    let mut features = crate::protocol::SYNC_FEATURES.to_vec();
    features.sort_unstable();
    features
}

/// The `features` of a drive progress file: at most 32 strings of 1 to 64 characters. `None` when
/// the key is missing (an older build) or malformed; the stored features then stay as they are.
fn peer_features(body: &serde_json::Value) -> Option<Vec<String>> {
    let list = body.get("features")?.as_array()?;
    if list.len() > 32 {
        return None;
    }
    list.iter()
        .map(|item| item.as_str().filter(|text| !text.is_empty() && text.chars().count() <= 64).map(str::to_owned))
        .collect()
}

fn load(state: &ManagedState) -> Result<Context> {
    let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
    let identity_store = app.store.identity_store();
    let local = identity_store.get_or_create().map_err(|_| "Device identity unavailable")?;
    let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
    let _ = vault.publish_unsynced_photos();
    // A waiting appearance choice is written now if the gate is open, and uploaded in this pass.
    // Drive files carry no handshake, so a Drive pass never records peer features: the gate opens
    // only from what members announced over Wi-Fi. Uploads are a broadcast mailbox and cannot be
    // filtered per reader; the gate is what keeps appearance changes away from older builds.
    crate::appearance::flush_installed(vault, &identity_store);
    crate::site_icon_sync::flush_installed(vault, &identity_store);
    crate::sign_in_sync::flush_installed(vault, &identity_store);
    let revision = u64::from(vault.local_change_count().map_err(storage_error)?);
    let blobs = vault.photo_blobs();
    let db = vault.connection();
    let (vault_id, transport, content): (String, Vec<u8>, Vec<u8>) = db
        .query_row("SELECT vault_id, transport_secret, content_key FROM sync_group_state", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|_| "Pair this PC with your phone first")?;
    let (transport, content_key) = (Zeroizing::new(transport), Zeroizing::new(content));
    // One prefix per rotated epoch: the newest random transport secret at or below the current epoch.
    let epoch = membership::verify(&read_membership(db, &vault_id)?).map(|verified| verified.key_epoch).unwrap_or(1);
    let random = crate::epoch_keys::random_secrets_in(db, &vault_id).map_err(storage_error)?;
    let keys = CloudKeys::derive(&transport, &vault_id).ok_or("Invalid sync keys")?;
    if content_key.len() != 32 {
        return Err("Invalid sync keys".into());
    }
    db.execute_batch(SCHEMA).map_err(storage_error)?;
    let files = db
        .prepare("SELECT file_id, name, size, modified FROM cloud_sync_files WHERE vault_id = ?1")
        .map_err(storage_error)?
        .query_map([&vault_id], |row| {
            Ok(CloudFile { id: row.get(0)?, name: row.get(1)?, size: counter(row, 2)?, modified: row.get(3)? })
        })
        .map_err(storage_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    let (cursor, progress_digest) = db
        .query_row("SELECT cursor, progress_digest FROM cloud_sync_state WHERE vault_id = ?1", [&vault_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()
        .map_err(storage_error)?
        .unwrap_or_default();
    let freeze = crate::merge_join::lost_freeze(db, &vault_id).map_err(storage_error)?;
    let mut context = Context { events: read_membership(db, &vault_id)?, vault_id, keys, content_key, local, blobs, files, cursor,
        progress_digest, revision, freeze, ring: Vec::new(), keys_epoch: 1, root: transport };
    context.rebuild(epoch, &random)?;
    Ok(context)
}

/// Saves the file list and where the next listing starts. `last_sync` is set when a pass ends well.
/// Only rows that differ are written: the folder only grows, and a pass runs every 15 seconds by
/// default, so rewriting every row rewrote megabytes of the vault each time.
fn save(state: &ManagedState, context: &Context, finished: bool) -> Result<()> {
    let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
    let vault = app.unlocked.as_mut().ok_or("Vault locked. Unlock and retry sync.")?;
    let tx = vault.connection().transaction().map_err(storage_error)?;
    let stored: std::collections::HashMap<String, CloudFile> = tx
        .prepare("SELECT file_id, name, size, modified FROM cloud_sync_files WHERE vault_id = ?1")
        .map_err(storage_error)?
        .query_map([&context.vault_id], |row| {
            Ok(CloudFile { id: row.get(0)?, name: row.get(1)?, size: counter(row, 2)?, modified: row.get(3)? })
        })
        .map_err(storage_error)?
        .map(|file| file.map(|file| (file.id.clone(), file)))
        .collect::<std::result::Result<_, _>>()
        .map_err(storage_error)?;
    let kept: std::collections::HashSet<&str> = context.files.iter().map(|file| file.id.as_str()).collect();
    for id in stored.keys().filter(|id| !kept.contains(id.as_str())) {
        tx.execute("DELETE FROM cloud_sync_files WHERE vault_id = ?1 AND file_id = ?2", params![context.vault_id, id])
            .map_err(storage_error)?;
    }
    for file in context.files.iter().filter(|file| stored.get(&file.id) != Some(*file)) {
        tx.execute(
            "INSERT OR REPLACE INTO cloud_sync_files (vault_id, file_id, name, size, modified) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![context.vault_id, file.id, file.name, integer(file.size)?, file.modified],
        )
        .map_err(storage_error)?;
    }
    tx.execute(
        "INSERT INTO cloud_sync_state (vault_id, cursor, progress_digest) VALUES (?1, ?2, ?3)
         ON CONFLICT(vault_id) DO UPDATE SET cursor = excluded.cursor, progress_digest = excluded.progress_digest",
        params![context.vault_id, context.cursor, context.progress_digest],
    )
    .map_err(storage_error)?;
    if finished {
        tx.execute("UPDATE cloud_sync_state SET last_sync_utc = ?2 WHERE vault_id = ?1", params![context.vault_id, now_rfc3339()])
            .map_err(storage_error)?;
    }
    tx.commit().map_err(storage_error)
}

/// RFC 3339 time of the last finished cloud pass for the current group, or empty.
pub(crate) fn last_sync(db: &Connection) -> String {
    db.query_row(
        "SELECT last_sync_utc FROM cloud_sync_state WHERE vault_id = (SELECT vault_id FROM local_sync_settings WHERE id = 1)",
        [],
        |row| row.get(0),
    )
    .unwrap_or_default()
}

/// Forgets the cached file list, so the next pass lists the whole folder (after a new sign-in).
pub(crate) fn forget(db: &Connection) -> Result<()> {
    db.execute_batch(SCHEMA).map_err(storage_error)?;
    db.execute_batch("DELETE FROM cloud_sync_files; DELETE FROM cloud_sync_state;").map_err(storage_error)
}

/// The body of a leave file: the same signed request as the Wi-Fi `leave1` frame, as
/// `{"request": {...}, "signature": "<base64url>"}`. Byte for byte the same as Android `CloudLeave`.
pub(crate) fn leave_body(request: &crate::membership_exit::LeaveRequest, signature: &[u8; 64]) -> Vec<u8> {
    // Written by hand: `serde_json` would sort the request's keys, and both apps write them in
    // declaration order (vaultId, deviceId, membershipHead, keyEpoch, createdAt).
    [b"{\"request\":".as_slice(), &request.json(), b",\"signature\":\"", URL_SAFE_NO_PAD.encode(signature).as_bytes(), b"\"}"].concat()
}

/// A leave request waiting for upload to Google Drive. Sealed while this PC still held the group
/// keys; the managing phone answers it as it answers one over Wi-Fi.
const PENDING_LEAVE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS cloud_pending_leave (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), name TEXT NOT NULL, sealed BLOB NOT NULL,
    created_at INTEGER NOT NULL, attempted_at INTEGER NOT NULL DEFAULT 0)";
/// Retry an upload at most this often, for at most as long as a Wi-Fi leave request.
const LEAVE_UPLOAD_RETRY_MILLIS: i64 = 5 * 60 * 1000;
const LEAVE_UPLOAD_MAX_AGE_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Before this PC leaves: seals the leave request for Google Drive when it is connected. Returns
/// false (and stores nothing) without a Google Drive sign-in.
pub(crate) fn save_pending_leave(db: &Connection, transport_secret: &[u8], vault_id: &str,
    request: &crate::membership_exit::LeaveRequest, signature: &[u8; 64]) -> Result<bool> {
    if account(db).is_none() { return Ok(false); }
    let keys = CloudKeys::derive(transport_secret, vault_id).ok_or("Invalid sync keys")?;
    let name = keys.leave_name(&request.device_id);
    let sealed = keys.seal(&name, &leave_body(request, signature))?;
    db.execute_batch(PENDING_LEAVE_SCHEMA).map_err(storage_error)?;
    db.execute("INSERT OR REPLACE INTO cloud_pending_leave (id, name, sealed, created_at, attempted_at) VALUES (1, ?1, ?2, ?3, 0)",
        params![name, sealed, request.created_at]).map_err(storage_error)?;
    Ok(true)
}

/// The leave file to upload now, with the account to upload it with. `None` when there is none,
/// when the last try was less than 5 minutes ago, or after 30 days (then it is dropped).
pub(crate) fn pending_leave_upload(db: &Connection, now: i64) -> Option<(String, Vec<u8>, Account)> {
    db.execute_batch(PENDING_LEAVE_SCHEMA).ok()?;
    let (name, sealed, created, attempted): (String, Vec<u8>, i64, i64) = db.query_row(
        "SELECT name, sealed, created_at, attempted_at FROM cloud_pending_leave WHERE id = 1", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).ok()?;
    if now - created > LEAVE_UPLOAD_MAX_AGE_MILLIS {
        let _ = db.execute("DELETE FROM cloud_pending_leave", []);
        return None;
    }
    if now - attempted < LEAVE_UPLOAD_RETRY_MILLIS { return None; }
    let _ = db.execute("UPDATE cloud_pending_leave SET attempted_at = ?1 WHERE id = 1", [now]);
    Some((name, sealed, account(db)?))
}

pub(crate) fn finish_pending_leave(db: &Connection) {
    let _ = db.execute_batch(PENDING_LEAVE_SCHEMA);
    let _ = db.execute("DELETE FROM cloud_pending_leave", []);
}

/// Uploads one sealed file; the leave request uses it.
pub(crate) fn upload_sealed(store: &mut dyn CloudStore, name: &str, sealed: &[u8]) -> Cloud<CloudFile> {
    upload_bytes(store, name, sealed)
}

/// The cloud account this PC is signed in to. The token lives in the encrypted vault database,
/// so it is readable only while the vault is unlocked.
pub(crate) struct Account {
    pub account: String,
    pub refresh_token: Zeroizing<String>,
}

const ACCOUNT_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS cloud_sync_account (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), provider TEXT NOT NULL, account TEXT NOT NULL,
    refresh_token TEXT NOT NULL, connected_at_utc TEXT NOT NULL)";

pub(crate) fn account(db: &Connection) -> Option<Account> {
    db.execute_batch(ACCOUNT_SCHEMA).ok()?;
    db.query_row("SELECT account, refresh_token FROM cloud_sync_account WHERE id = 1 AND provider = 'google-drive'", [], |row| {
        Ok(Account { account: row.get(0)?, refresh_token: Zeroizing::new(row.get(1)?) })
    })
    .ok()
}

pub(crate) fn save_account(db: &Connection, account: &str, refresh_token: &str) -> Result<()> {
    db.execute_batch(ACCOUNT_SCHEMA).map_err(storage_error)?;
    db.execute(
        "INSERT OR REPLACE INTO cloud_sync_account (id, provider, account, refresh_token, connected_at_utc) VALUES (1, 'google-drive', ?1, ?2, ?3)",
        params![account, refresh_token, now_rfc3339()],
    )
    .map_err(storage_error)?;
    forget(db)
}

/// Removes the sign-in from this PC and returns it, so the caller can end it at the provider.
pub(crate) fn remove_account(db: &Connection) -> Result<Option<Account>> {
    let saved = account(db);
    db.execute("DELETE FROM cloud_sync_account", []).map_err(storage_error)?;
    forget(db)?;
    Ok(saved)
}

fn remember(context: &mut Context, file: CloudFile) {
    context.files.retain(|known| known.id != file.id);
    if file.modified > context.cursor {
        context.cursor = file.modified.clone();
    }
    context.files.push(file);
}

/// One cloud pass: list, take the newer membership, download changes this PC lacks, upload
/// changes the drive lacks, move photo blobs, publish progress. No vault lock is held during a
/// network call. `full` lists the whole folder instead of only files changed since the last pass.
pub(crate) fn run(state: &ManagedState, store: &mut dyn CloudStore, tracker: &SyncTracker, full: bool) -> Result<SyncReport> {
    let mut context = load(state)?;
    let mut membership = membership::verify(&context.events).map_err(|_| "Invalid signed membership")?;
    require_member(&membership, &context.local.device_id, &context.local.public_key).map_err(|_| REMOVED)?;
    let cloud = |error: CloudError| error.message();
    tracker.set_phase(Phase::Connecting);

    // 1. List.
    let since = (!full && !context.files.is_empty()).then(|| relist_from(&context.cursor)).flatten();

    let mut listed: Vec<CloudFile> = store
        .list(since.as_deref())
        .map_err(cloud)?
        .into_iter()
        .filter(|file| context.parse(&file.name).is_some())
        .collect();
    if since.is_none() {
        context.files.clear();
    }
    for file in &listed {
        remember(&mut context, file.clone());
    }
    save(state, &context, false)?;
    let parsed = |context: &Context| -> Vec<(CloudFile, CloudName)> {
        context.files.iter().filter_map(|file| Some((file.clone(), context.parse(&file.name)?))).collect()
    };

    // 2. Membership: take a longer signed history, or publish ours when it is the longest.
    let mut histories: Vec<(u64, CloudFile)> = parsed(&context)
        .into_iter()
        .filter_map(|(file, name)| match name {
            CloudName::Membership { count, .. } => Some((count, file)),
            _ => None,
        })
        .collect();
    histories.sort_by(|left, right| right.0.cmp(&left.0));
    let mut published = histories.iter().any(|(count, _)| *count == context.events.len() as u64);
    for (_, file) in histories.iter().filter(|(count, _)| *count > context.events.len() as u64).take(3) {
        let Some(remote) = download_bytes(store, &file.id, MEMBERSHIP_BYTES)
            .ok()
            .and_then(|sealed| context.open(&file.name, &sealed))
            .and_then(|plain| serde_json::from_slice::<Vec<MembershipEvent>>(&plain).ok())
        else {
            continue;
        };
        let remote = crate::merge_join::cap(context.freeze.as_ref(), remote);
        let Ok(accepted) = merge_membership(&context.events, &remote) else { continue };
        if remote.len() <= context.events.len() {
            continue;
        }
        if !accepted.members.get(&context.local.device_id).is_some_and(|member| member.active) {
            // A signed removal of this PC: leave the group, as a Wi-Fi removal notice does.
            return Err(adopt_history(state, &context.events, &remote, &context.local.device_id));
        }
        with_vault(state, &context.vault_id, &membership.head, |vault| {
            persist_membership(vault.connection(), &context.vault_id, &context.events, &remote, &accepted)
        })?;
        context.events = remote;
        membership = accepted;
        published = true;
        break;
    }
    let mut report = SyncReport { local_revision_at_start: context.revision, ..Default::default() };
    let mut complete = true;
    // 2b. Key rotation (`epoch_keys.rs`): publish this PC's signed key statement; read the others'
    // and the sealed package sets addressed to this PC, under any prefix it holds.
    let statement_name = context.keys.statement_name(&context.local.device_id);
    if !context.files.iter().any(|file| file.name == statement_name) {
        let statement = {
            let app = state.lock().map_err(|_| "Vault state unavailable")?;
            app.store.identity_store().key_statement(&context.vault_id).ok()
        };
        if let Some(statement) = statement {
            let sealed = context.keys.seal(&statement_name, &serde_json::to_vec(&statement).map_err(storage_error)?)?;
            let file = upload_bytes(store, &statement_name, &sealed).map_err(cloud)?;
            remember(&mut context, file);
        }
    }
    let mut statements = Vec::new();
    let mut sets = Vec::new();
    for (file, name) in parsed(&context) {
        let own = context.keys_for(&file.name).map(|keys| keys.device_tag(&context.local.device_id));
        let wanted = match &name {
            CloudName::Statement { device } => own.as_ref() != Some(device),
            CloudName::Packages { recipient, .. } => own.as_ref() == Some(recipient),
            _ => false,
        };
        if !wanted {
            continue;
        }
        let Some(plain) = download_bytes(store, &file.id, PROGRESS_BYTES).ok().and_then(|sealed| context.open(&file.name, &sealed)) else {
            continue;
        };
        match name {
            CloudName::Statement { .. } => statements.extend(serde_json::from_slice::<crate::epoch_keys::KeyStatement>(&plain).ok()),
            _ => sets.extend(serde_json::from_slice::<crate::epoch_keys::PackageSet>(&plain).ok()),
        }
    }
    if !statements.is_empty() || !sets.is_empty() {
        let private = {
            let app = state.lock().map_err(|_| "Vault state unavailable")?;
            app.store.identity_store().x25519_private().map_err(storage_error)?
        };
        let local_id = context.local.device_id.clone();
        let opened = with_vault(state, &context.vault_id, &membership.head, |vault| {
            let db = vault.connection();
            for statement in &statements {
                crate::epoch_keys::accept_statement(db, &membership, statement).map_err(storage_error)?;
            }
            crate::epoch_keys::accept_packages(db, &context.events, &membership, &local_id, &private, &sets).map_err(storage_error)
        })?;
        // New keys apply in this same pass (M1): the newest prefix from now on, and the folder listed
        // again whole, because files under that prefix could not be read when it was listed.
        if opened > 0 {
            complete = false;
            let random = with_vault(state, &context.vault_id, &membership.head, |vault| {
                crate::epoch_keys::random_secrets_in(vault.connection(), &context.vault_id).map_err(storage_error)
            })?;
            context.rebuild(membership.key_epoch, &random)?;
            let again: Vec<CloudFile> = store.list(None).map_err(cloud)?.into_iter().filter(|file| context.parse(&file.name).is_some()).collect();
            context.files.clear();
            for file in &again {
                remember(&mut context, file.clone());
            }
            listed = again;
        }
    }
    // Waiting for a package (H1): this pass only reads. Nothing goes under the old prefix, which the
    // removed device can read, until the new keys arrive.
    let stranded = with_vault(state, &context.vault_id, &membership.head, |vault| {
        crate::epoch_keys::stranded(vault.connection(), &context.events, &membership, &context.local.device_id).map_err(storage_error)
    })?;
    report.waiting_for_keys = stranded;
    if !published && !stranded
        && !context.files.iter().any(|file| file.name == context.keys.membership_name(context.events.len() as u64, &membership.head))
    {
        let name = context.keys.membership_name(context.events.len() as u64, &membership.head);
        let sealed = context.keys.seal(&name, &serde_json::to_vec(&context.events).map_err(storage_error)?)?;
        let file = upload_bytes(store, &name, &sealed).map_err(cloud)?;
        remember(&mut context, file);
    }
    let authors: BTreeMap<String, String> = context.ring.iter()
        .flat_map(|(_, keys)| membership.members.keys().map(|device| (keys.device_tag(device), device.clone())))
        .collect();
    // Per author: the files that hold its changes.
    let mut segments: BTreeMap<String, Vec<(u64, u64, CloudFile)>> = BTreeMap::new();
    for (file, name) in parsed(&context) {
        if let CloudName::Operations { device, first, last } = name
            && let Some(author) = authors.get(&device)
        {
            segments.entry(author.clone()).or_default().push((first, last, file));
        }
    }

    // 3. Download what this PC lacks. Every change passes the same checks as over Wi-Fi.
    tracker.set_phase(Phase::Receiving);
    let mut unusable = std::collections::BTreeSet::new();
    for (author, files) in &segments {
        if *author == context.local.device_id {
            continue;
        }
        loop {
            let head = with_vault(state, &context.vault_id, &membership.head, |vault| {
                initialize_received(vault.connection())?;
                Ok(progress(vault.connection(), &context.vault_id)?.received.get(author).map_or(0, |head| head.0))
            })?;
            let Some((first, last, file)) = files
                .iter()
                .filter(|(first, last, file)| *first <= head + 1 && *last > head && !unusable.contains(&file.id))
                .max_by_key(|(_, last, _)| *last)
            else {
                break;
            };
            let (first, last) = (*first, *last);
            let sealed = match download_bytes(store, &file.id, DOWNLOAD_BYTES) {
                Ok(sealed) => sealed,
                // The file list is stale (a file was removed): list everything on the next pass.
                Err(CloudError::NotFound) => {
                    context.files.retain(|known| known.id != file.id);
                    unusable.insert(file.id.clone());
                    complete = false;
                    continue;
                }
                Err(error) => return Err(cloud(error)),
            };
            let operations = context
                .open(&file.name, &sealed)
                .and_then(|plain| serde_json::from_slice::<Vec<serde_json::Value>>(&plain).ok())
                .filter(|operations| operations.len() as u64 == last - first + 1 && operations.len() <= DOWNLOAD_OPERATIONS);
            let Some(operations) = operations else {
                unusable.insert(file.id.clone());
                continue;
            };
            tracker.incoming_announced(last - head);
            let mut stored = 0usize;
            for (index, value) in operations.iter().enumerate() {
                let sequence = first + index as u64;
                if sequence <= head {
                    continue;
                }
                let operation = serde_json::to_vec(value).map_err(storage_error).and_then(|bytes| operation_from_wire(&bytes));
                let valid = operation.as_ref().is_ok_and(|operation| operation.device_id == *author && operation.sequence == sequence);
                if !valid || store_received(state, &membership, operation.as_ref().expect("checked")).is_err() {
                    // Changes before this one are verified and kept; the rest of the file is not used.
                    unusable.insert(file.id.clone());
                    break;
                }
                stored += 1;
                tracker.received_one();
            }
            report.received += stored;
            if stored == 0 {
                unusable.insert(file.id.clone());
            }
        }
    }
    if report.received > 0 {
        tracker.set_phase(Phase::Applying);
        with_vault(state, &context.vault_id, &membership.head, |vault| apply_waiting(vault, &context.vault_id, &context.content_key))?;
    }

    // Floor markers (`compaction.rs` `drive`), counted only at or below this PC's own floor(A).
    let own_floors = with_vault(state, &context.vault_id, &membership.head, |vault| {
        crate::compaction::own_floors(vault.connection(), &context.vault_id, &context.local.device_id, &membership).map_err(storage_error)
    })?;
    let mut markers: BTreeMap<String, u64> = BTreeMap::new();
    for (file, name) in parsed(&context) {
        let CloudName::Floor { author } = name else { continue };
        let Some(author) = authors.get(&author) else { continue };
        let Some(marker) = download_bytes(store, &file.id, 4_096).ok()
            .and_then(|sealed| context.open(&file.name, &sealed))
            .and_then(|plain| serde_json::from_slice::<crate::compaction::drive::Marker>(&plain).ok())
            .filter(|marker| marker.author == *author && membership.members.contains_key(&marker.writer))
        else {
            continue;
        };
        let entry = markers.entry(author.clone()).or_default();
        *entry = (*entry).max(marker.floor);
    }
    let counted: BTreeMap<String, u64> = markers.iter()
        .map(|(author, floor)| (author.clone(), crate::compaction::drive::counted_floor(Some(*floor), own_floors.get(author).copied().unwrap_or(0))))
        .collect();

    // 4. Upload what the drive lacks, for every author this PC holds changes of.
    tracker.set_phase(Phase::Sending);
    let local_authors: Vec<String> = with_vault(state, &context.vault_id, &membership.head, |vault| {
        vault
            .connection()
            .prepare("SELECT DISTINCT device_id FROM sync_operations WHERE vault_id = ?1 ORDER BY device_id")
            .map_err(storage_error)?
            .query_map([&context.vault_id], |row| row.get(0))
            .map_err(storage_error)?
            .collect::<std::result::Result<_, _>>()
            .map_err(storage_error)
    })?;
    let mut uploaded_files = 0usize;
    'authors: for author in local_authors.into_iter().filter(|_| !stranded) {
        let limit = match membership.members.get(&author) {
            Some(member) if member.active => u64::MAX,
            Some(member) => match &member.removal_cutoff {
                Some(cutoff) => cutoff.0,
                None => continue,
            },
            None => continue,
        };
        let ranges: Vec<(u64, u64)> =
            segments.get(&author).map(|files| files.iter().map(|(first, last, _)| (*first, *last)).collect()).unwrap_or_default();
        // Coverage starts after a floor marker this PC counts: a deleted range is never uploaded again.
        let mut covered = crate::compaction::drive::coverage(&ranges, counted.get(&author).copied().unwrap_or(0));
        loop {
            let (pending, remaining) = with_vault(state, &context.vault_id, &membership.head, |vault| {
                pending_operations(
                    vault.connection(),
                    &context.vault_id,
                    &BTreeMap::from([(author.clone(), (covered, String::new()))]),
                    UPLOAD_OPERATIONS,
                    UPLOAD_BYTES,
                    &|device| (device == author).then_some(limit),
                )
            })?;
            let (Some(first), Some(last)) = (pending.first(), pending.last()) else { break };
            if uploaded_files >= UPLOAD_FILES_PER_PASS {
                complete = false;
                break 'authors;
            }
            tracker.outgoing_remaining(remaining as u64);
            let (first, last) = (first.0.sequence, last.0.sequence);
            let mut plain = Vec::with_capacity(pending.iter().map(|(_, wire)| wire.len() + 1).sum::<usize>() + 2);
            plain.push(b'[');
            for (index, (_, wire)) in pending.iter().enumerate() {
                if index > 0 {
                    plain.push(b',');
                }
                plain.extend_from_slice(wire);
            }
            plain.push(b']');
            let name = context.keys.operations_name(&author, first, last);
            let file = upload_bytes(store, &name, &context.keys.seal(&name, &plain)?).map_err(cloud)?;
            remember(&mut context, file);
            uploaded_files += 1;
            covered = last;
            report.sent += pending.len();
            for _ in &pending {
                tracker.sent_one();
            }
        }
    }

    // 5. Photo blobs. A blob is already ciphertext and its name is its hash, so it needs no envelope.
    let cloud_blobs: BTreeMap<String, CloudFile> = parsed(&context)
        .into_iter()
        .filter_map(|(file, name)| match name {
            CloudName::Blob { hash } => Some((hash, file)),
            _ => None,
        })
        .collect();
    let (wanted, held) = with_vault(state, &context.vault_id, &membership.head, |vault| {
        let wanted = vault.waiting_photo_blobs().map_err(storage_error)?;
        let held: Vec<(String, u64)> = vault
            .connection()
            .prepare("SELECT DISTINCT ciphertext_hash, size_bytes FROM sync_attachment_manifests")
            .map_err(storage_error)?
            .query_map([], |row| Ok((row.get(0)?, counter(row, 1)?)))
            .map_err(storage_error)?
            .collect::<std::result::Result<_, _>>()
            .map_err(storage_error)?;
        Ok((wanted, held))
    })?;
    let blobs = context.blobs.clone();
    // Under a rotated prefix a blob is sealed like every other file (a removed device holds the keys
    // of older epochs, so a raw blob there could be one it reads); under the root prefix it is raw.
    let sealed_size = |file: &CloudFile, size: u64| if context.epoch_for(&file.name).unwrap_or(1) >= 2 { size + BLOB_ENVELOPE } else { size };
    let missing: Vec<(String, u64, CloudFile)> = wanted
        .into_iter()
        .filter(|(hash, size)| !blobs.has(hash, *size))
        .filter_map(|(hash, size)| cloud_blobs.get(&hash).filter(|file| file.size == sealed_size(file, size)).map(|file| (hash, size, file.clone())))
        .collect();
    complete &= missing.len() <= PHOTOS_PER_PASS;
    if !missing.is_empty() {
        tracker.set_phase(Phase::Receiving);
    }
    for (hash, size, file) in missing.into_iter().take(PHOTOS_PER_PASS) {
        tracker.photo_expected(size);
        blobs.discard_partial(&hash).map_err(storage_error)?;
        let mut position = 0u64;
        if context.epoch_for(&file.name).unwrap_or(1) >= 2 {
            let plain = download_bytes(store, &file.id, size + BLOB_ENVELOPE).ok().and_then(|sealed| context.open(&file.name, &sealed));
            let stored = plain.filter(|plain| plain.len() as u64 == size).is_some_and(|plain| {
                plain.chunks(photo_blobs::CHUNK_BYTES).all(|chunk| {
                    let written = blobs.append(&hash, position, chunk).is_ok();
                    position += chunk.len() as u64;
                    written
                }) && blobs.finish(&hash, size).is_ok()
            });
            if stored {
                tracker.photo_moved(size);
                report.photos_received += 1;
            } else {
                let _ = blobs.discard_partial(&hash);
            }
            continue;
        }
        let downloaded = store.download(&file.id, size, &mut |bytes| {
            for chunk in bytes.chunks(photo_blobs::CHUNK_BYTES) {
                blobs.append(&hash, position, chunk).map_err(|error| CloudError::Other(error.to_string()))?;
                position += chunk.len() as u64;
                tracker.photo_moved(chunk.len() as u64);
            }
            Ok(())
        });
        match downloaded {
            Ok(()) if blobs.finish(&hash, size).is_ok() => report.photos_received += 1,
            Ok(()) | Err(CloudError::Other(_)) | Err(CloudError::NotFound) => {
                let _ = blobs.discard_partial(&hash);
            }
            Err(error) => return Err(cloud(error)),
        }
    }
    let seal_blobs = context.keys_epoch >= 2;
    let to_upload: Vec<(String, u64)> = held
        .into_iter()
        .filter(|_| !stranded)
        .filter(|(hash, size)| photo_blobs::valid_hash(hash) && !cloud_blobs.contains_key(hash) && blobs.has(hash, *size))
        // A blob too large to seal in memory travels over Wi-Fi only.
        .filter(|(_, size)| !seal_blobs || *size <= SEALED_BLOB_BYTES)
        .collect();
    complete &= to_upload.len() <= PHOTOS_PER_PASS;
    if !to_upload.is_empty() {
        tracker.set_phase(Phase::Sending);
    }
    for (hash, size) in to_upload.into_iter().take(PHOTOS_PER_PASS) {
        tracker.photo_expected(size);
        let mut file = blobs.open_at(&hash, 0).map_err(storage_error)?;
        let name = context.keys.blob_name(&hash);
        let uploaded = if seal_blobs {
            let mut plain = Zeroizing::new(Vec::with_capacity(size as usize));
            file.read_to_end(&mut plain).map_err(storage_error)?;
            upload_bytes(store, &name, &context.keys.seal(&name, &plain)?).map_err(cloud)?
        } else {
            store.upload(&name, size, &mut file).map_err(cloud)?
        };
        tracker.photo_moved(size);
        remember(&mut context, uploaded);
        report.photos_sent += 1;
    }

    // 6. Progress: tell the other devices what this PC has, and read what they have.
    tracker.set_phase(Phase::Applying);
    let own_progress = with_vault(state, &context.vault_id, &membership.head, |vault| {
        apply_waiting(vault, &context.vault_id, &context.content_key)?;
        progress(vault.connection(), &context.vault_id)?.encode().map_err(storage_error)
    })?;
    // The features are part of the digest, so an update that adds one rewrites the file at once.
    let digest = hex::encode(Sha256::digest([own_progress.as_slice(), format!("|{}|", context.keys_epoch).as_bytes(),
        crate::protocol::SYNC_FEATURES.join(",").as_bytes()].concat()));
    let own_name = context.keys.progress_name(&context.local.device_id);
    let own_file = context.files.iter().find(|file| file.name == own_name).cloned();
    if !stranded && (digest != context.progress_digest || own_file.is_none()) {
        // Signed by this PC's identity (H2): only a signed report counts for what may be deleted.
        let key_epoch = with_vault(state, &context.vault_id, &membership.head, |vault| {
            Ok(crate::epoch_keys::stored_keys(vault.connection(), &context.vault_id).map_err(storage_error)?.keys().next_back().copied().unwrap_or(1))
        })?;
        let identity = state.lock().map_err(|_| "Vault state unavailable")?.store.identity_store();
        let text = String::from_utf8(own_progress.clone()).map_err(storage_error)?;
        let body = drive_progress::body(&context.vault_id, &context.local.device_id, context.keys_epoch,
            crate::activity::now_millis() as i64, key_epoch, &text, &sorted_features(), |bytes| identity.sign(bytes).ok())?;
        let sealed = context.keys.seal(&own_name, &serde_json::to_vec(&body).map_err(storage_error)?)?;
        let file = match own_file {
            Some(file) => match store.replace(&file.id, &sealed) {
                Err(CloudError::NotFound) => upload_bytes(store, &own_name, &sealed),
                other => other,
            },
            None => upload_bytes(store, &own_name, &sealed),
        }
        .map_err(cloud)?;
        remember(&mut context, file);
        context.progress_digest = digest;
    }
    for file in &listed {
        let Some(CloudName::Progress { device }) = context.parse(&file.name) else { continue };
        let Some(peer) = authors.get(&device).filter(|peer| **peer != context.local.device_id) else { continue };
        let Some(member) = membership.members.get(peer).filter(|member| member.active) else {
            continue;
        };
        let Some(body) = download_bytes(store, &file.id, PROGRESS_BYTES)
            .ok()
            .and_then(|sealed| context.open(&file.name, &sealed))
            .and_then(|plain| serde_json::from_slice::<serde_json::Value>(&plain).ok())
            .filter(|body| body["deviceId"].as_str() == Some(peer.as_str()))
        else {
            continue;
        };
        // Progress and features count only when the peer signed the report for the newest prefix (H2):
        // they decide what may be deleted and which gates open. Unsigned (an older build) or from an
        // older prefix, it is unknown progress: nothing more is deleted because of it.
        let seen_at = body["updatedAt"].as_i64().unwrap_or(0).min(crate::activity::now_millis() as i64);
        let signed = (context.epoch_for(&file.name) == Some(context.keys_epoch))
            .then(|| drive_progress::verify(&body, &context.vault_id, peer, &member.public_key, context.keys_epoch))
            .flatten();
        // Only a signed report proves the member synced: an unsigned one may come from a removed device
        // that still holds an old key, so it never makes a member look seen or up to date (Sync page).
        let Some((peer_progress, features)) = &signed else { continue };
        // A report older than one this PC got over Wi-Fi is refused there and simply skipped here.
        let _ = with_vault(state, &context.vault_id, &membership.head, |vault| {
            let db = vault.connection();
            if seen_at > 0 {
                crate::membership_exit::record_peer_seen(db, peer, seen_at).map_err(storage_error)?;
            }
            if let Some(features) = features {
                crate::appearance::record_peer_features(db, &context.vault_id, peer, features).map_err(storage_error)?;
            }
            validate_peer_progress(db, &context.vault_id, &context.local.device_id, peer, peer_progress, false)
        });
    }

    // 7. Drive cleanup (`compaction.rs` `drive`): once a day, after a complete pass, and only when
    // every active member reads floor markers. An offline member pins floor(A); a removed one does not.
    let gate = with_vault(state, &context.vault_id, &membership.head, |vault| {
        let db = vault.connection();
        let due = db.query_row("SELECT drive_compacted_at FROM cloud_sync_compaction WHERE vault_id = ?1", [&context.vault_id], |row| row.get::<_, i64>(0))
            .optional().map_err(storage_error)?
            .is_none_or(|at| !(0..crate::compaction::drive::INTERVAL_MS).contains(&(crate::activity::now_millis() as i64 - at)));
        Ok(due && crate::appearance::gate_open_for(db, &membership, &context.local.device_id, crate::compaction::drive::FEATURE))
    })?;
    if complete && gate && !stranded {
        let mut deletes = 0;
        for (author, files) in &segments {
            if deletes >= crate::compaction::drive::MAX_DELETES {
                break;
            }
            let Some(floor) = own_floors.get(author).copied() else { continue };
            let ranges: Vec<(u64, u64)> = files.iter().map(|(first, last, _)| (*first, *last)).collect();
            let (new_floor, gone) = crate::compaction::drive::cleanup(&ranges, counted.get(author).copied().unwrap_or(0), floor);
            if gone.is_empty() {
                continue;
            }
            // The marker first: a stop before the deletes leaves extra files, never a gap.
            let name = context.keys.floor_name(author);
            let marker = crate::compaction::drive::Marker { author: author.clone(), floor: new_floor, hash: String::new(),
                writer: context.local.device_id.clone(), at: crate::activity::now_millis() as i64 };
            let sealed = context.keys.seal(&name, &serde_json::to_vec(&marker).map_err(storage_error)?)?;
            let existing = context.files.iter().find(|file| file.name == name).map(|file| file.id.clone());
            let file = match existing {
                Some(id) => store.replace(&id, &sealed).or_else(|_| upload_bytes(store, &name, &sealed)).map_err(cloud)?,
                None => upload_bytes(store, &name, &sealed).map_err(cloud)?,
            };
            remember(&mut context, file);
            for (first, last) in gone {
                for (_, _, file) in files.iter().filter(|(f, l, _)| *f == first && *l == last) {
                    if deletes >= crate::compaction::drive::MAX_DELETES {
                        break;
                    }
                    match store.delete(&file.id) {
                        Ok(()) | Err(CloudError::NotFound) => {}
                        Err(error) => return Err(cloud(error)),
                    }
                    context.files.retain(|known| known.id != file.id);
                    deletes += 1;
                }
            }
        }
        with_vault(state, &context.vault_id, &membership.head, |vault| {
            vault.connection().execute(
                "INSERT INTO cloud_sync_compaction (vault_id, drive_compacted_at) VALUES (?1, ?2)
                 ON CONFLICT(vault_id) DO UPDATE SET drive_compacted_at = excluded.drive_compacted_at",
                params![context.vault_id, crate::activity::now_millis() as i64],
            ).map_err(storage_error)?;
            Ok(())
        })?;
    }

    with_vault(state, &context.vault_id, &membership.head, |vault| {
        let db = vault.connection();
        report.waiting_to_apply = waiting(db, &context.vault_id)?.len();
        report.conflicts = db
            .query_row("SELECT count(*) FROM sync_conflicts WHERE resolved_at_utc = ''", [], |row| row.get::<_, u32>(0))
            .map_err(storage_error)? as usize;
        Ok(())
    })?;
    save(state, &context, complete)?;
    Ok(report)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests::{Synthetic, login_entry, phone_change, phone_op, remove_event, signed_member, stage, synthetic_vault};
    use super::*;
    use crate::{identity::DeviceIdentity, protocol::RecordVersion};
    use ed25519_dalek::SigningKey;
    use std::sync::{Arc, Mutex};

    /// A drive in memory, shared by the devices of a test.
    #[derive(Clone, Default)]
    pub(crate) struct MemoryDrive {
        files: Arc<Mutex<Vec<(CloudFile, Vec<u8>)>>>,
        clock: Arc<Mutex<i64>>,
        pub(crate) listings: Arc<Mutex<Vec<Option<String>>>>,
    }

    impl MemoryDrive {
        fn stamp(&self) -> String {
            let mut clock = self.clock.lock().unwrap();
            *clock += 3600;
            (time::OffsetDateTime::from_unix_timestamp(1_790_000_000 + *clock).unwrap())
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        }

        pub(crate) fn names(&self) -> Vec<String> {
            self.files.lock().unwrap().iter().map(|(file, _)| file.name.clone()).collect()
        }

        fn put(&self, name: &str, bytes: Vec<u8>) -> CloudFile {
            let file = CloudFile { id: uuid::Uuid::new_v4().to_string(), name: name.into(), size: bytes.len() as u64, modified: self.stamp() };
            self.files.lock().unwrap().push((file.clone(), bytes));
            file
        }
    }

    impl CloudStore for MemoryDrive {
        fn list(&mut self, modified_after: Option<&str>) -> Cloud<Vec<CloudFile>> {
            self.listings.lock().unwrap().push(modified_after.map(str::to_owned));
            Ok(self.files.lock().unwrap().iter().map(|(file, _)| file.clone())
                .filter(|file| modified_after.is_none_or(|after| file.modified.as_str() > after)).collect())
        }

        fn download(&mut self, id: &str, max_bytes: u64, sink: &mut dyn FnMut(&[u8]) -> Cloud<()>) -> Cloud<()> {
            let bytes = self.files.lock().unwrap().iter().find(|(file, _)| file.id == id).map(|(_, bytes)| bytes.clone())
                .ok_or(CloudError::NotFound)?;
            if bytes.len() as u64 > max_bytes {
                return Err(CloudError::Other("too large".into()));
            }
            bytes.chunks(100_000).try_for_each(|chunk| sink(chunk))
        }

        fn upload(&mut self, name: &str, size: u64, content: &mut dyn Read) -> Cloud<CloudFile> {
            let mut bytes = Vec::new();
            content.read_to_end(&mut bytes).map_err(|error| CloudError::Other(error.to_string()))?;
            assert_eq!(bytes.len() as u64, size);
            Ok(self.put(name, bytes))
        }

        fn replace(&mut self, id: &str, content: &[u8]) -> Cloud<CloudFile> {
            let stamp = self.stamp();
            let mut files = self.files.lock().unwrap();
            let (file, bytes) = files.iter_mut().find(|(file, _)| file.id == id).ok_or(CloudError::NotFound)?;
            *bytes = content.to_vec();
            file.size = content.len() as u64;
            file.modified = stamp;
            Ok(file.clone())
        }

        fn delete(&mut self, id: &str) -> Cloud<()> {
            let mut files = self.files.lock().unwrap();
            let before = files.len();
            files.retain(|(file, _)| file.id != id);
            if files.len() == before { Err(CloudError::NotFound) } else { Ok(()) }
        }
    }

    fn pass(device: &Synthetic, drive: &MemoryDrive) -> SyncReport {
        run(&device.state, &mut drive.clone(), &SyncTracker::default(), false).unwrap()
    }

    /// Two PCs and a phone in one group, as in the Wi-Fi test.
    fn group() -> (Synthetic, Synthetic, Vec<MembershipEvent>) {
        let (mut a, mut b) = (synthetic_vault(1), synthetic_vault(1));
        let phone = DeviceIdentity { device_id: "phone".into(), public_key: SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes() };
        let mut history = vec![signed_member(None, &phone)];
        for device in [&a.local, &b.local] {
            history.push(signed_member(history.last(), device));
        }
        for device in [&mut a, &mut b] {
            let mut app = device.state.lock().unwrap();
            let db = app.unlocked.as_mut().unwrap().connection();
            db.execute("DELETE FROM sync_membership_events", []).unwrap();
            let verified = membership::verify(&history).unwrap();
            persist_membership(db, "vault-a", &[], &history, &verified).unwrap();
            device.membership = verified;
        }
        (a, b, history)
    }

    fn notes(device: &Synthetic) -> Vec<String> {
        let mut app = device.state.lock().unwrap();
        let mut titles: Vec<String> = app.unlocked.as_mut().unwrap().list_notes().unwrap().into_iter().map(|note| note.title).collect();
        titles.sort();
        titles
    }

    fn cleanup(devices: impl IntoIterator<Item = Synthetic>) {
        for device in devices {
            drop(device.state);
            std::fs::remove_dir_all(device.directory).unwrap();
        }
    }

    #[test]
    fn a_leaving_pc_keeps_a_sealed_leave_file_until_it_is_uploaded() {
        let db = Connection::open_in_memory().unwrap();
        let secret = [4u8; 32];
        let request = crate::membership_exit::LeaveRequest {
            vault_id: "vault-a".into(), device_id: "pc".into(), membership_head: "ab".repeat(32), key_epoch: 1,
            created_at: 1_767_225_600_000,
        };
        // Without a Google Drive sign-in nothing is stored.
        assert!(!save_pending_leave(&db, &secret, "vault-a", &request, &[7u8; 64]).unwrap());
        save_account(&db, "person@example.com", "refresh").unwrap();
        assert!(save_pending_leave(&db, &secret, "vault-a", &request, &[7u8; 64]).unwrap());
        let now = request.created_at + 1_000;
        let (name, sealed, account) = pending_leave_upload(&db, now).unwrap();
        let keys = CloudKeys::derive(&secret, "vault-a").unwrap();
        assert_eq!(name, keys.leave_name("pc"));
        assert_eq!(keys.open(&name, &sealed).unwrap(), leave_body(&request, &[7u8; 64]));
        assert_eq!(account.account, "person@example.com");
        // A failed upload is retried after 5 minutes, and given up after 30 days.
        assert!(pending_leave_upload(&db, now + 60_000).is_none());
        assert!(pending_leave_upload(&db, now + LEAVE_UPLOAD_RETRY_MILLIS).is_some());
        assert!(pending_leave_upload(&db, request.created_at + LEAVE_UPLOAD_MAX_AGE_MILLIS + 1).is_none());
        assert!(pending_leave_upload(&db, now + 2 * LEAVE_UPLOAD_RETRY_MILLIS).is_none(), "dropped after 30 days");
        save_pending_leave(&db, &secret, "vault-a", &request, &[7u8; 64]).unwrap();
        finish_pending_leave(&db);
        assert!(pending_leave_upload(&db, now + 3 * LEAVE_UPLOAD_RETRY_MILLIS).is_none(), "gone after the upload");
    }

    #[test]
    fn names_and_envelope_match_the_shared_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!("../fixtures/cloud-sync-v1.json")).unwrap();
        let secret = hex::decode(vectors["transportSecretHex"].as_str().unwrap()).unwrap();
        let keys = CloudKeys::derive(&secret, vectors["vaultId"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(&*keys.key), vectors["cloudKeyHex"]);
        assert_eq!(keys.prefix(), vectors["prefix"]);
        let device = vectors["deviceId"].as_str().unwrap();
        assert_eq!(keys.device_tag(device), vectors["deviceTag"]);
        assert_eq!(keys.membership_name(3, &"ab".repeat(32)), vectors["membershipName"]);
        assert_eq!(keys.operations_name(device, 7, 42), vectors["operationsName"]);
        assert_eq!(keys.progress_name(device), vectors["progressName"]);
        assert_eq!(keys.blob_name(&"cd".repeat(32)), vectors["blobName"]);
        assert_eq!(keys.leave_name(device), vectors["leaveName"]);
        // A leave file body is byte for byte the same on Windows and Android.
        let request = crate::membership_exit::LeaveRequest {
            vault_id: vectors["vaultId"].as_str().unwrap().into(), device_id: device.into(),
            membership_head: "ab".repeat(32), key_epoch: 1, created_at: 1_767_225_600_000,
        };
        assert_eq!(String::from_utf8(leave_body(&request, &[7u8; 64])).unwrap(), vectors["leaveBody"].as_str().unwrap());
        let name = vectors["operationsName"].as_str().unwrap();
        let plain = vectors["plaintext"].as_str().unwrap().as_bytes();
        let nonce: [u8; 12] = hex::decode(vectors["nonceHex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let sealed = keys.seal_with_nonce(name, plain, &nonce).unwrap();
        assert_eq!(hex::encode(&sealed), vectors["sealedHex"]);
        assert_eq!(keys.open(name, &sealed).unwrap(), plain);
        assert!(keys.open(vectors["progressName"].as_str().unwrap(), &sealed).is_none(), "the name is bound to the content");
        assert!(CloudKeys::derive(&[9; 32], "vault-a").unwrap().open(name, &sealed).is_none(), "another group cannot open it");
    }

    #[test]
    fn names_parse_back_and_foreign_names_are_ignored() {
        let keys = CloudKeys::derive(&[5; 32], "vault-a").unwrap();
        let tag = keys.device_tag("phone");
        assert_eq!(keys.parse(&keys.operations_name("phone", 1, 256)), Some(CloudName::Operations { device: tag.clone(), first: 1, last: 256 }));
        assert_eq!(keys.parse(&keys.membership_name(4, &"ab".repeat(32))), Some(CloudName::Membership { count: 4, head: "ab".repeat(8) }));
        assert_eq!(keys.parse(&keys.progress_name("phone")), Some(CloudName::Progress { device: tag.clone() }));
        assert_eq!(keys.parse(&keys.leave_name("phone")), Some(CloudName::Leave { device: tag.clone() }));
        assert_eq!(keys.parse(&keys.blob_name(&"cd".repeat(32))), Some(CloudName::Blob { hash: "cd".repeat(32) }));
        let prefix = keys.prefix();
        for name in [
            "notes.txt".to_owned(),
            format!("nv1.{}.o.{tag}.000000000001.000000000002", "0".repeat(16)),
            format!("{prefix}o.{tag}.000000000005.000000000002"),
            format!("{prefix}o.{tag}.000000000000.000000000002"),
            format!("{prefix}o.{tag}.1.2"),
            format!("{prefix}m.0000000000.{}", "ab".repeat(8)),
            format!("{prefix}b.{}", "CD".repeat(32)),
            format!("{prefix}x.{tag}"),
        ] {
            assert_eq!(keys.parse(&name), None, "{name}");
        }
        assert_eq!(crate::compaction::drive::coverage(&[(1, 10), (11, 20), (5, 12)], 0), 20);
        assert_eq!(crate::compaction::drive::coverage(&[(1, 10), (12, 20)], 0), 10, "a gap stops the coverage");
        assert_eq!(crate::compaction::drive::coverage(&[(2, 10)], 0), 0);
    }

    #[test]
    fn two_pcs_sync_changes_and_photos_through_the_drive() {
        let (a, b, _) = group();
        let drive = MemoryDrive::default();
        stage(&a, &[phone_change()]);
        let image = [b"\x89PNG\r\n\x1a\n".as_slice(), &vec![7u8; 100_000]].concat();
        let entry_id = {
            let mut app = a.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            let entry = vault.save_entry(serde_json::json!({"type": "CARD", "title": "From PC A", "primaryValue": "4111"})).unwrap();
            let id = entry["id"].as_str().unwrap().to_owned();
            vault.add_entry_photo(&id, "image/png", &base64::engine::general_purpose::STANDARD.encode(&image)).unwrap();
            id
        };
        let first = pass(&a, &drive);
        // PC A's note, entry and photo change, and the phone's folder that A relays.
        assert_eq!((first.sent, first.received, first.photos_sent), (4, 0, 1));
        let second = pass(&b, &drive);
        assert_eq!((second.sent, second.received, second.photos_received), (1, 4, 1));
        {
            let mut app = b.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            assert_eq!(vault.list_notes().unwrap().len(), 2);
            assert_eq!(vault.connection().query_row("SELECT name FROM local_groups WHERE id = 'phone-folder'", [], |row| row.get::<_, String>(0)).unwrap(), "Phone notes");
            assert_eq!(vault.list_entry_photos(&entry_id).unwrap().len(), 1);
        }
        let third = pass(&a, &drive);
        assert_eq!((third.sent, third.received), (0, 1));
        assert_eq!(notes(&a), notes(&b));
        // Nothing new: nothing moves, and the listing only asks for files changed since.
        for device in [&a, &b] {
            let idle = pass(device, &drive);
            assert_eq!((idle.sent, idle.received, idle.photos_sent, idle.photos_received), (0, 0, 0, 0));
        }
        assert!(drive.listings.lock().unwrap().last().unwrap().is_some());
        // The provider sees only opaque names and sealed bytes.
        let keys = CloudKeys::derive(&[5; 32], "vault-a").unwrap();
        for (file, bytes) in drive.files.lock().unwrap().iter() {
            assert!(keys.parse(&file.name).is_some(), "{}", file.name);
            for secret in ["vault-a", "phone", "From PC A", "Note 0", a.local.device_id.as_str()] {
                assert!(!file.name.contains(secret));
                assert!(!String::from_utf8_lossy(bytes).contains(secret), "{secret} is readable in {}", file.name);
            }
        }
        // A later edit on B reaches A, and each PC knows what the other has received.
        b.state.lock().unwrap().unlocked.as_mut().unwrap().save_note(None, "Written on B", "Body", Some(vec![])).unwrap();
        assert_eq!(pass(&b, &drive).sent, 1);
        assert_eq!(pass(&a, &drive).received, 1);
        assert!(notes(&a).contains(&"Written on B".to_owned()));
        pass(&b, &drive);
        let known: String = b.state.lock().unwrap().unlocked.as_mut().unwrap().connection()
            .query_row("SELECT progress_json FROM sync_peer_progress WHERE peer_device_id = ?1", [&a.local.device_id], |row| row.get(0)).unwrap();
        assert!(known.contains(&b.local.device_id), "B read A's progress report from the drive");
        cleanup([a, b]);
    }

    #[test]
    fn the_saved_file_list_changes_only_where_the_drive_changed() {
        let (a, b, _) = group();
        let drive = MemoryDrive::default();
        stage(&a, &[phone_change()]);
        pass(&a, &drive);
        // Counts every row written to or removed from the saved list (a TEMP trigger on this connection).
        let sql = |device: &Synthetic, statement: &str| -> i64 {
            let mut app = device.state.lock().unwrap();
            let db = app.unlocked.as_mut().unwrap().connection();
            db.query_row(statement, [], |row| row.get(0)).unwrap()
        };
        {
            let mut app = a.state.lock().unwrap();
            app.unlocked.as_mut().unwrap().connection().execute_batch(
                "CREATE TEMP TABLE list_writes (n INTEGER NOT NULL); INSERT INTO list_writes VALUES (0);
                 CREATE TEMP TRIGGER list_insert AFTER INSERT ON cloud_sync_files BEGIN UPDATE list_writes SET n = n + 1; END;
                 CREATE TEMP TRIGGER list_delete AFTER DELETE ON cloud_sync_files BEGIN UPDATE list_writes SET n = n + 1; END;").unwrap();
        }
        let remembered = sql(&a, "SELECT count(*) FROM cloud_sync_files");
        assert_eq!(remembered as usize, drive.names().len(), "every file of the group is remembered");
        // An idle pass writes no row of the list.
        assert_eq!(pass(&a, &drive).sent, 0);
        assert_eq!(sql(&a, "SELECT n FROM list_writes"), 0, "an idle pass rewrote the saved file list");
        // A file gone from the drive is forgotten on a full listing, with a few writes, not one per file.
        let gone = drive.files.lock().unwrap().iter().find(|(file, _)| file.name.contains(".o.")).unwrap().0.id.clone();
        drive.files.lock().unwrap().retain(|(file, _)| file.id != gone);
        run(&a.state, &mut drive.clone(), &SyncTracker::default(), true).unwrap();
        assert_eq!(sql(&a, &format!("SELECT count(*) FROM cloud_sync_files WHERE file_id = '{gone}'")), 0);
        assert_eq!(sql(&a, "SELECT count(*) FROM cloud_sync_files") as usize, drive.names().len());
        assert!(sql(&a, "SELECT n FROM list_writes") < remembered, "the full pass rewrote every row");
        cleanup([a, b]);
    }

    #[test]
    fn forged_reordered_and_foreign_files_change_nothing() {
        let (a, b, _) = group();
        let drive = MemoryDrive::default();
        let keys = CloudKeys::derive(&[5; 32], "vault-a").unwrap();
        // A change signed by someone who is not the phone, under the phone's name.
        let forged = {
            let signer = SigningKey::from_bytes(&[99; 32]);
            let mut change = phone_change();
            use ed25519_dalek::Signer;
            change.device_signature = URL_SAFE_NO_PAD.encode(signer.sign(b"not the phone").to_bytes());
            change
        };
        let name = keys.operations_name("phone", 1, 1);
        let body = [b"[".as_slice(), &operation_wire(&forged).unwrap(), b"]"].concat();
        drive.put(&name, keys.seal(&name, &body).unwrap());
        // A real file under the wrong name, a file of another group, garbage, and a gap.
        let real = [b"[".as_slice(), &operation_wire(&phone_change()).unwrap(), b"]"].concat();
        let wrong = keys.operations_name("phone", 1, 2);
        drive.put(&wrong, keys.seal(&name, &real).unwrap());
        let other = CloudKeys::derive(&[6; 32], "vault-a").unwrap();
        drive.put(&other.operations_name("phone", 1, 1), other.seal(&other.operations_name("phone", 1, 1), &real).unwrap());
        drive.put(&keys.operations_name("phone", 1, 1), b"NVC1 garbage that is long enough to look sealed".to_vec());
        let later = keys.operations_name("phone", 5, 5);
        drive.put(&later, keys.seal(&later, &real).unwrap());
        let report = pass(&b, &drive);
        assert_eq!(report.received, 0);
        assert_eq!(b.state.lock().unwrap().unlocked.as_mut().unwrap().connection()
            .query_row("SELECT count(*) FROM sync_operations WHERE device_id = 'phone'", [], |row| row.get::<_, u32>(0)).unwrap(), 0);
        // The real file then arrives and is accepted next to the bad ones.
        drive.put(&name, keys.seal(&name, &real).unwrap());
        assert_eq!(run(&b.state, &mut drive.clone(), &SyncTracker::default(), true).unwrap().received, 1);
        cleanup([a, b]);
    }

    #[test]
    fn drive_cleanup_waits_for_every_active_member_and_nothing_is_uploaded_again() {
        let (a, b, _) = group();
        let drive = MemoryDrive::default();
        let mut previous = GENESIS_HASH.to_owned();
        let mut chain = Vec::new();
        for sequence in 1..=300u64 {
            let id = format!("login-{sequence}");
            let change = phone_op(sequence, &previous, "entry", &id, RecordVersion::from_entries([("phone", 1)]), 0,
                serde_json::json!({"entry": login_entry(&id, &format!("Login {sequence}")), "groupIds": []}));
            previous = change.hash.clone();
            chain.push(change);
        }
        let apply = |device: &Synthetic| {
            let mut app = device.state.lock().unwrap();
            apply_waiting(app.unlocked.as_mut().unwrap(), "vault-a", &[4u8; 32]).unwrap();
        };
        stage(&a, &chain);
        apply(&a);
        pass(&a, &drive);
        let keys = CloudKeys::derive(&[5; 32], "vault-a").unwrap();
        let phone_files = || drive.names().iter().filter(|name| matches!(keys.parse(name),
            Some(CloudName::Operations { device, .. }) if device == keys.device_tag("phone"))).count();
        assert_eq!(phone_files(), 2);
        let head = (300u64, previous.clone());
        let report = |db: &Connection, peer: &str, applied: bool| {
            let heads: BTreeMap<String, (u64, String)> = if applied { BTreeMap::from([("phone".to_owned(), head.clone())]) } else { BTreeMap::new() };
            let progress = crate::progress::SyncProgress { received: heads.clone(), applied: heads };
            db.execute("CREATE TABLE IF NOT EXISTS sync_peer_progress (vault_id TEXT NOT NULL, peer_device_id TEXT NOT NULL, progress_json TEXT NOT NULL, PRIMARY KEY (vault_id, peer_device_id))", []).unwrap();
            db.execute("INSERT OR REPLACE INTO sync_peer_progress VALUES ('vault-a', ?1, ?2)",
                params![peer, String::from_utf8(progress.encode().unwrap()).unwrap()]).unwrap();
        };
        let features = vec![crate::compaction::drive::FEATURE.to_owned()];
        let b_id = b.local.device_id.clone();
        let reset = |device: &Synthetic| device.state.lock().unwrap().unlocked.as_mut().unwrap().connection()
            .execute("DELETE FROM cloud_sync_compaction", []).unwrap();
        // Everyone announced the feature, but the PC `b` applied nothing (it is offline): nothing goes.
        {
            let mut app = a.state.lock().unwrap();
            let db = app.unlocked.as_mut().unwrap().connection();
            for peer in ["phone", b_id.as_str()] {
                crate::appearance::record_peer_features(db, "vault-a", peer, &features).unwrap();
            }
            report(db, "phone", true);
            report(db, &b_id, false);
        }
        pass(&a, &drive);
        assert_eq!(phone_files(), 2, "an offline member holds the cleanup back");
        // `b` catches up: the files go, after the marker.
        reset(&a);
        report(a.state.lock().unwrap().unlocked.as_mut().unwrap().connection(), &b_id, true);
        pass(&a, &drive);
        assert_eq!(phone_files(), 0);
        assert!(drive.names().contains(&keys.floor_name("phone")));
        // `b` counts the marker and uploads nothing again.
        stage(&b, &chain);
        apply(&b);
        report(b.state.lock().unwrap().unlocked.as_mut().unwrap().connection(), "phone", true);
        report(b.state.lock().unwrap().unlocked.as_mut().unwrap().connection(), &a.local.device_id, true);
        // Only its own note goes up: none of the phone's deleted range.
        assert_eq!(pass(&b, &drive).sent, 1);
        assert_eq!(phone_files(), 0);
        cleanup([a, b]);
    }

    #[test]
    fn a_long_history_uploads_in_bounded_files_and_downloads_in_order() {
        let (a, b, _) = group();
        let drive = MemoryDrive::default();
        let mut previous = GENESIS_HASH.to_owned();
        let mut chain = Vec::new();
        for sequence in 1..=300u64 {
            let id = format!("login-{sequence}");
            let change = phone_op(sequence, &previous, "entry", &id, RecordVersion::from_entries([("phone", 1)]), 0,
                serde_json::json!({"entry": login_entry(&id, &format!("Login {sequence}")), "groupIds": []}));
            previous = change.hash.clone();
            chain.push(change);
        }
        stage(&a, &chain);
        assert_eq!(pass(&a, &drive).sent, 301);
        let keys = CloudKeys::derive(&[5; 32], "vault-a").unwrap();
        let mut ranges: Vec<(u64, u64)> = drive.names().iter().filter_map(|name| match keys.parse(name)? {
            CloudName::Operations { device, first, last } if device == keys.device_tag("phone") => Some((first, last)),
            _ => None,
        }).collect();
        ranges.sort_unstable();
        assert_eq!(ranges, [(1, 256), (257, 300)]);
        assert_eq!(pass(&b, &drive).received, 301);
        assert_eq!(b.state.lock().unwrap().unlocked.as_mut().unwrap().list_entries().unwrap().len(), 300);
        cleanup([a, b]);
    }

    #[test]
    fn a_signed_removal_on_the_drive_makes_this_pc_leave() {
        let (a, b, history) = group();
        let drive = MemoryDrive::default();
        pass(&a, &drive);
        let keys = CloudKeys::derive(&[5; 32], "vault-a").unwrap();
        // A forged removal of B is not adopted.
        let mut forged = history.clone();
        forged.push(remove_event(history.last().unwrap(), &b.local.device_id, false));
        let name = keys.membership_name(forged.len() as u64, &forged.last().unwrap().hash);
        drive.put(&name, keys.seal(&name, &serde_json::to_vec(&forged).unwrap()).unwrap());
        pass(&b, &drive);
        assert!(b.state.lock().unwrap().unlocked.as_ref().unwrap().is_enrolled().unwrap());
        // The phone's signed removal is.
        let mut removed = history.clone();
        removed.push(remove_event(history.last().unwrap(), &b.local.device_id, true));
        let name = keys.membership_name(removed.len() as u64, &removed.last().unwrap().hash);
        drive.put(&name, keys.seal(&name, &serde_json::to_vec(&removed).unwrap()).unwrap());
        let error = run(&b.state, &mut drive.clone(), &SyncTracker::default(), true).unwrap_err();
        assert_eq!(error, REMOVED_NOTICE);
        assert!(!b.state.lock().unwrap().unlocked.as_ref().unwrap().is_enrolled().unwrap());
        assert_eq!(notes(&b), ["Note 0", "Note 0"], "the PC keeps its own note and the one it received");
        // PC A adopts the same history and goes on.
        assert_eq!(pass(&a, &drive).received, 0);
        assert_eq!(a.state.lock().unwrap().unlocked.as_ref().unwrap().stored_membership().unwrap().len(), removed.len());
        cleanup([a, b]);
    }

    #[test]
    fn drive_progress_matches_the_shared_vector() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!("../fixtures/epoch-keys-v1.json")).unwrap();
        let file = &vectors["progressFile"];
        let vault = vectors["vaultId"].as_str().unwrap();
        let text = file["progressText"].as_str().unwrap();
        let features: Vec<String> = file["features"].as_array().unwrap().iter().map(|f| f.as_str().unwrap().to_owned()).collect();
        let at = file["updatedAt"].as_i64().unwrap();
        assert_eq!(hex::encode(drive_progress::signing_bytes(vault, "dev-pc", 2, at, 2, text, &features)), file["signingHex"]);
        let seed: [u8; 32] = hex::decode(vectors["devices"]["dev-pc"]["ed25519Seed"].as_str().unwrap()).unwrap().try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);
        let refs: Vec<&str> = features.iter().map(String::as_str).collect();
        let body = drive_progress::body(vault, "dev-pc", 2, at, 2, text, &refs, |m| Some(ed25519_dalek::Signer::sign(&key, m).to_bytes())).unwrap();
        assert_eq!(body["signature"], file["signature"]);
        let public = key.verifying_key().to_bytes();
        assert_eq!(drive_progress::verify(&body, vault, "dev-pc", &public, 2).unwrap().0.applied.get("dev-pc").map(|head| head.0), Some(3));
        assert!(drive_progress::verify(&body, vault, "dev-pc", &public, 1).is_none(), "another prefix");
        assert!(drive_progress::verify(&body, "other", "dev-pc", &public, 2).is_none(), "another vault");
        let mut changed = body.clone();
        changed["progressText"] = text.replace("[1,", "[3,").into();
        assert!(drive_progress::verify(&changed, vault, "dev-pc", &public, 2).is_none(), "a changed report");
        let mut unsigned = body.clone();
        unsigned.as_object_mut().unwrap().remove("signature");
        assert!(drive_progress::verify(&unsigned, vault, "dev-pc", &public, 2).is_none(), "unsigned (an older build)");
        // A photo blob under a rotated prefix is sealed like every other file.
        let blob = &vectors["blobFile"];
        let keys = CloudKeys::derive(&hex::decode(vectors["transportSecretHex"].as_str().unwrap()).unwrap(), vault).unwrap();
        let sealed = hex::decode(blob["sealedHex"].as_str().unwrap()).unwrap();
        assert_eq!(keys.open(blob["name"].as_str().unwrap(), &sealed).unwrap(), hex::decode(blob["blobHex"].as_str().unwrap()).unwrap());
        assert_eq!(sealed.len() as u64, hex::decode(blob["blobHex"].as_str().unwrap()).unwrap().len() as u64 + BLOB_ENVELOPE);
    }

    /// End to end on a drive in memory (H1, H2, M1): the phone removes PC B with new keys and seals a
    /// package for PC A. B, removed but holding the root key and a Google sign-in, withholds A's `e.`
    /// file and forges progress. A learns the REMOVE, sends nothing while it waits, takes its package
    /// once the file is there, and from then on writes only under the new prefix, which B can't open.
    #[test]
    fn a_removed_pc_that_tampers_with_drive_files_cant_strand_or_read_a_survivor() {
        use crate::epoch_keys::{KeyStatement, PackageSet, seal_package_with, x25519_private, x25519_public};
        use ed25519_dalek::Signer;
        let (a, b, history) = group();
        let drive = MemoryDrive::default();
        pass(&a, &drive);
        let root = CloudKeys::derive(&[5; 32], "vault-a").unwrap();
        let phone = SigningKey::from_bytes(&[17; 32]);
        let phone_x = x25519_private(&[17; 32]);
        let phone_statement = KeyStatement::create("vault-a", "phone", &x25519_public(&phone_x), |m| Some(phone.sign(m).to_bytes())).unwrap();
        let name = root.statement_name("phone");
        drive.put(&name, root.seal(&name, &serde_json::to_vec(&phone_statement).unwrap()).unwrap());
        let mut removed = history.clone();
        removed.push(remove_event(history.last().unwrap(), &b.local.device_id, true));
        let name = root.membership_name(removed.len() as u64, &removed.last().unwrap().hash);
        drive.put(&name, root.seal(&name, &serde_json::to_vec(&removed).unwrap()).unwrap());
        // B forges an unsigned progress report of the phone under the old prefix (it would raise floors).
        let forged = serde_json::json!({"deviceId": "phone", "updatedAt": 1, "progress": {"received": {"phone": [900, "ab".repeat(32)]},
            "applied": {"phone": [900, "ab".repeat(32)]}}, "features": ["history-compaction-v1"]});
        let name = root.progress_name("phone");
        drive.put(&name, root.seal(&name, &serde_json::to_vec(&forged).unwrap()).unwrap());
        // A writes a change while the package is withheld: it waits and sends nothing.
        a.state.lock().unwrap().unlocked.as_mut().unwrap().save_note(None, "While waiting", "Secret", None).unwrap();
        let before = drive.names().len();
        let report = run(&a.state, &mut drive.clone(), &SyncTracker::default(), true).unwrap();
        assert!(report.waiting_for_keys);
        assert_eq!(report.sent, 0);
        let a_tag = root.device_tag(&a.local.device_id);
        assert!(drive.names()[before..].iter().all(|name| !matches!(root.parse(name),
            Some(CloudName::Operations { ref device, .. } | CloudName::Progress { ref device }) if *device == a_tag)), "{:?}", &drive.names()[before..]);
        let peer_rows = |device: &Synthetic| -> i64 { device.state.lock().unwrap().unlocked.as_mut().unwrap().connection()
            .query_row("SELECT count(*) FROM sync_peer_progress WHERE peer_device_id = 'phone'", [], |row| row.get(0)).unwrap_or(0) };
        assert_eq!(peer_rows(&a), 0, "unsigned progress is unknown progress");
        // The phone uploads the package (again): A opens it and uploads under the new prefix only.
        let statement = a.state.lock().unwrap().store.identity_store().key_statement("vault-a").unwrap();
        let (s2, p2) = ([0x5C; 32], [0x6D; 32]);
        let sealed = seal_package_with("vault-a", 2, &a.local.device_id, &statement.public_key().unwrap(), &s2, &p2, &[0x41; 32], &[0x51; 12]);
        let mut set = PackageSet { vault_id: "vault-a".into(), epoch: 2, remove_hash: removed.last().unwrap().hash.clone(),
            packages: BTreeMap::from([(a.local.device_id.clone(), URL_SAFE_NO_PAD.encode(&sealed))]), signature: String::new() };
        set.signature = URL_SAFE_NO_PAD.encode(phone.sign(&set.signing_bytes()).to_bytes());
        let name = root.package_name(2, &a.local.device_id);
        drive.put(&name, root.seal(&name, &serde_json::to_vec(&set).unwrap()).unwrap());
        let before = drive.names().len();
        let report = pass(&a, &drive);
        assert!(!report.waiting_for_keys);
        assert!(report.sent >= 1);
        let new = CloudKeys::derive(&s2, "vault-a").unwrap();
        let after = drive.names()[before..].to_vec();
        assert!(after.iter().all(|name| root.parse(name).is_none()), "nothing new under the old prefix: {after:?}");
        assert!(after.iter().any(|name| matches!(new.parse(name), Some(CloudName::Operations { .. }))));
        assert!(after.iter().any(|name| matches!(new.parse(name), Some(CloudName::Progress { .. }))));
        cleanup([a, b]);
    }
}
