//! New sync keys when the managing phone removes a device (feature `epoch-keys-v1`). Android
//! `EpochKeys.kt` / `EpochKeyRotation.kt`; shared vectors `fixtures/epoch-keys-v1.json` (card_app
//! `scripts/sync-vectors/epoch_keys.py`). Security notes: protocol-upgrade-design.md, section 11.
//!
//! This PC never makes packages (only the managing phone rotates). It publishes a key statement,
//! opens the package sealed to it, keeps and relays package sets, writes changes with the newest
//! content key it holds, and reads changes of every epoch it holds a key for. A package holds the
//! transport secret S(N) and a package key P(N); the content key is K(N) = HKDF(P(N), salt = K(1))
//! (`content_key`), so it needs the vault's K(1) too. Writing reads the keys from `vault.db` each
//! time (`write_key_in`, `random_secrets_in`); the in-memory keyring serves reads only, and belongs
//! to the unlocked vault that loaded it (`KeyringOwner`). X25519 is
//! `curve25519-dalek` (already in Cargo.lock through `ed25519-dalek`); HKDF-SHA256 is RFC 5869 on
//! the `hmac` crate.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, atomic::{AtomicU64, Ordering}},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::membership::{MembershipAction, MembershipEvent, VerifiedMembership};

pub const FEATURE: &str = "epoch-keys-v1";
const FRAME_PREFIX: &[u8] = b"keys1";
/// Sets per `keys1` frame, as Android `EpochKeyRotation.MAX_SETS`; the frame also stays under `MAX_FRAME_BYTES`.
pub const MAX_SETS: usize = 64;
const MAX_FRAME_BYTES: usize = 200 * 1024;

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sync_epoch_keys (
    vault_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    content_key BLOB NOT NULL CHECK (length(content_key) = 32),
    transport_secret BLOB NOT NULL CHECK (length(transport_secret) = 32),
    PRIMARY KEY (vault_id, epoch)
);
CREATE TABLE IF NOT EXISTS sync_key_packages (
    vault_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    set_json TEXT NOT NULL,
    PRIMARY KEY (vault_id, epoch)
);
CREATE TABLE IF NOT EXISTS sync_key_statements (
    vault_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    PRIMARY KEY (vault_id, device_id)
);";

/// RFC 5869 HKDF-SHA256 with a 32-byte output. An empty salt is 32 zero bytes.
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let zeros = [0u8; 32];
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(if salt.is_empty() { &zeros } else { salt }).expect("any key length");
    extract.update(ikm);
    let prk: Zeroizing<[u8; 32]> = Zeroizing::new(extract.finalize().into_bytes().into());
    let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&*prk).expect("any key length");
    expand.update(info);
    expand.update(&[1]);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&expand.finalize().into_bytes());
    out
}

pub fn x25519_private(ed25519_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(ed25519_seed, &[], b"nuvori-device-x25519-v1")
}

pub fn x25519_public(private: &[u8; 32]) -> [u8; 32] {
    // `mul_base_clamped` takes the scalar by value: the copy here is wiped after use.
    let mut scalar = *private;
    let public = MontgomeryPoint::mul_base_clamped(scalar).to_bytes();
    scalar.zeroize();
    public
}

/// X25519(private, point), wiping the scalar copy the call takes.
fn shared_secret(point: &[u8; 32], private: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut scalar = *private;
    let shared = Zeroizing::new(MontgomeryPoint(*point).mul_clamped(scalar).to_bytes());
    scalar.zeroize();
    shared
}

/// A usable X25519 public key: not a low-order point, which gives an all-zero secret with any scalar.
pub fn valid_point(point: &[u8; 32]) -> bool {
    *shared_secret(point, &[0x5A; 32]) != [0u8; 32]
}

/// K(N) from the package key P(N) and the group's epoch-1 content key K(1), as Android `EpochKeys.contentKey`.
pub fn content_key_from(epoch1: &[u8; 32], vault_id: &str, epoch: u64, package_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(package_key, epoch1, format!("nuvori-epoch-content-v1:{vault_id}:{epoch}").as_bytes())
}

fn wrap_key(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32], vault_id: &str, epoch: u64, device_id: &str) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    hkdf(shared, &salt, format!("nuvori-epoch-key-v1:{vault_id}:{epoch}:{device_id}").as_bytes())
}

/// (S, P) from a package sealed to this device; `None` when it is not for it or was changed.
pub fn open_package(vault_id: &str, epoch: u64, device_id: &str, private: &[u8; 32], sealed: &[u8])
    -> Option<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    if sealed.len() != 32 + 12 + 64 + 16 {
        return None;
    }
    let ephemeral: [u8; 32] = sealed[..32].try_into().ok()?;
    let shared = shared_secret(&ephemeral, private);
    if *shared == [0u8; 32] {
        return None;
    }
    let key = wrap_key(&shared, &ephemeral, &x25519_public(private), vault_id, epoch, device_id);
    let cipher = Aes256Gcm::new_from_slice(&*key).ok()?;
    let plain = Zeroizing::new(cipher.decrypt(Nonce::from_slice(&sealed[32..44]), Payload {
        msg: &sealed[44..],
        aad: format!("{vault_id}:{epoch}:{device_id}").as_bytes(),
    }).ok()?);
    let mut secret = Zeroizing::new([0u8; 32]);
    let mut content = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&plain[..32]);
    content.copy_from_slice(&plain[32..64]);
    Some((secret, content))
}

/// Seals (S, K) to a device, as the managing phone does. Tests only: this PC never rotates.
#[cfg(test)]
pub fn seal_package_with(vault_id: &str, epoch: u64, device_id: &str, recipient: &[u8; 32], secret: &[u8; 32],
    content: &[u8; 32], ephemeral: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let public = x25519_public(ephemeral);
    let shared = shared_secret(recipient, ephemeral);
    let key = wrap_key(&shared, &public, recipient, vault_id, epoch, device_id);
    let mut plain = secret.to_vec();
    plain.extend_from_slice(content);
    let sealed = Aes256Gcm::new_from_slice(&*key).unwrap()
        .encrypt(Nonce::from_slice(nonce), Payload { msg: &plain, aad: format!("{vault_id}:{epoch}:{device_id}").as_bytes() })
        .unwrap();
    [public.as_slice(), nonce.as_slice(), sealed.as_slice()].concat()
}

/// A device's X25519 key for one group, signed by its Ed25519 identity.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyStatement {
    pub vault_id: String,
    pub device_id: String,
    pub x25519: String,
    pub signature: String,
}

impl KeyStatement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("nuvori-device-key-v1\n{}\n{}\n{}", self.vault_id, self.device_id, self.x25519).into_bytes()
    }

    /// The X25519 key: canonical base64url (the decoder refuses padding and stray bits), 32 bytes,
    /// and not a low-order point (`valid_point`), so a bad statement can't break a rotation.
    pub fn public_key(&self) -> Option<[u8; 32]> {
        let key: [u8; 32] = URL_SAFE_NO_PAD.decode(&self.x25519).ok()?.try_into().ok()?;
        valid_point(&key).then_some(key)
    }

    pub fn valid(&self, vault_id: &str, identity_key: &[u8; 32]) -> bool {
        self.vault_id == vault_id && !self.device_id.is_empty() && self.public_key().is_some()
            && verify(identity_key, &self.signing_bytes(), &self.signature)
    }

    pub fn create(vault_id: &str, device_id: &str, x25519: &[u8; 32], signer: impl FnOnce(&[u8]) -> Option<[u8; 64]>) -> Option<Self> {
        let mut statement = Self { vault_id: vault_id.to_owned(), device_id: device_id.to_owned(),
            x25519: URL_SAFE_NO_PAD.encode(x25519), signature: String::new() };
        statement.signature = URL_SAFE_NO_PAD.encode(signer(&statement.signing_bytes())?);
        Some(statement)
    }
}

/// The packages of one epoch, signed by the managing phone and bound to the REMOVE that started it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageSet {
    pub vault_id: String,
    pub epoch: u64,
    pub remove_hash: String,
    pub packages: BTreeMap<String, String>,
    pub signature: String,
}

impl PackageSet {
    /// Device IDs in UTF-8 byte order: `BTreeMap<String, _>` iterates in that order.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut text = format!("nuvori-epoch-keys-v1\n{}\n{}\n{}\n", self.vault_id, self.epoch, self.remove_hash);
        for (device, sealed) in &self.packages {
            let digest = Sha256::digest(URL_SAFE_NO_PAD.decode(sealed).unwrap_or_default());
            text.push_str(&format!("{device}:{}\n", hex::encode(digest)));
        }
        text.into_bytes()
    }

    /// An empty set is the manager's signed marker that this REMOVE made no new keys.
    pub fn valid(&self, vault_id: &str, manager_key: &[u8; 32], remove_hash: &str) -> bool {
        self.vault_id == vault_id && self.epoch >= 2 && self.remove_hash == remove_hash
            && self.packages.len() <= crate::membership::MAX_ACTIVE_DEVICES
            && self.packages.iter().all(|(device, sealed)| !device.is_empty()
                && URL_SAFE_NO_PAD.decode(sealed).is_ok_and(|bytes| bytes.len() == 124))
            && verify(manager_key, &self.signing_bytes(), &self.signature)
    }

    /// Signed by the issuer of the REMOVE that started its epoch, in this group's verified history.
    pub fn valid_in(&self, events: &[MembershipEvent], verified: &VerifiedMembership) -> bool {
        let Some(remove) = events.iter().find(|event| event.action == MembershipAction::Remove && event.key_epoch == self.epoch) else {
            return false;
        };
        verified.members.get(&remove.issuer_device_id)
            .is_some_and(|issuer| self.valid(&verified.vault_id, &issuer.public_key, &remove.hash))
    }
}

fn verify(public_key: &[u8; 32], message: &[u8], signature: &str) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else { return false };
    let Some(signature) = URL_SAFE_NO_PAD.decode(signature).ok().and_then(|bytes| <[u8; 64]>::try_from(bytes).ok()) else {
        return false;
    };
    key.verify(message, &Signature::from_bytes(&signature)).is_ok()
}

/// The epoch of a change's payload nonce: 1 for a bare nonce, N for `e<N>.`; `None` when invalid.
pub fn epoch_of(nonce: &str) -> Option<u64> {
    // A bare base64url nonce has no '.', but may start with 'e': only a '.' marks the epoch form.
    let Some(rest) = nonce.strip_prefix('e').filter(|_| nonce.contains('.')) else {
        return (URL_SAFE_NO_PAD.decode(nonce).ok()?.len() == 12).then_some(1);
    };
    let (digits, encoded) = rest.split_once('.')?;
    if digits.is_empty() || digits.len() > 10 || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let epoch: u64 = digits.parse().ok()?;
    ((2..=i32::MAX as u64).contains(&epoch) && URL_SAFE_NO_PAD.decode(encoded).ok()?.len() == 12).then_some(epoch)
}

pub fn nonce_bytes(nonce: &str) -> Option<[u8; 12]> {
    epoch_of(nonce)?;
    URL_SAFE_NO_PAD.decode(nonce.rsplit('.').next()?).ok()?.try_into().ok()
}

pub fn nonce_field(epoch: u64, nonce: &[u8; 12]) -> String {
    let text = URL_SAFE_NO_PAD.encode(nonce);
    if epoch <= 1 { text } else { format!("e{epoch}.{text}") }
}

pub fn aad(entity_type: &str, vault_id: &str, epoch: u64, mutation_id: &str, entity_id: &str) -> String {
    if epoch <= 1 {
        format!("nuvori-sync-{entity_type}-v1:{vault_id}:{mutation_id}:{entity_id}")
    } else {
        format!("nuvori-sync-{entity_type}-v2:{vault_id}:{epoch}:{mutation_id}:{entity_id}")
    }
}

/// The transport secret of `epoch`: its own random one, else HMAC-derived from the newest random one
/// below it (from the root when the group never rotated, as before).
pub fn transport_secret(root: &[u8], vault_id: &str, epoch: u64, random: &BTreeMap<u64, Zeroizing<[u8; 32]>>) -> Option<Zeroizing<Vec<u8>>> {
    if root.len() != 32 || epoch == 0 {
        return None;
    }
    if let Some(secret) = random.get(&epoch) {
        return Some(Zeroizing::new(secret.to_vec()));
    }
    if epoch == 1 {
        return Some(Zeroizing::new(root.to_vec()));
    }
    let base: &[u8] = random.range(..epoch).next_back().map_or(root, |(_, secret)| &secret[..]);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(base).ok()?;
    mac.update(format!("nuvori-transport-epoch-v1:{vault_id}:{epoch}").as_bytes());
    Some(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

/// The secret the Google Drive key of `epoch` comes from: the newest random one at or below it, else the root.
pub fn drive_secret(root: &[u8], epoch: u64, random: &BTreeMap<u64, Zeroizing<[u8; 32]>>) -> (u64, Zeroizing<Vec<u8>>) {
    match random.range(..=epoch).next_back() {
        Some((epoch, secret)) => (*epoch, Zeroizing::new(secret.to_vec())),
        None => (1, Zeroizing::new(root.to_vec())),
    }
}

type EpochSecrets = BTreeMap<u64, (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)>;

/// The keys of later epochs of one group held in memory for reading changes: (content key,
/// transport secret), and the unlocked vaults that loaded them.
#[derive(Default)]
struct Group {
    owners: BTreeSet<u64>,
    keys: EpochSecrets,
}

/// Filled from `sync_epoch_keys` at unlock and when a package opens. Only reads use it: writing,
/// the Drive prefix and the Wi-Fi secret read `vault.db` (`write_key_in`, `random_secrets_in`), so
/// an empty keyring can make a change wait but never makes this PC write with an older key.
static KEYRING: Mutex<BTreeMap<String, Group>> = Mutex::new(BTreeMap::new());
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// One unlocked vault's claim on the keyring (C1 of the key-rotation review). A second vault
/// instance (for example one opened to check the master password) has its own claim, so dropping
/// it can't empty the keyring of the vault that stays unlocked.
pub struct KeyringOwner {
    token: u64,
    vault_id: Mutex<Option<String>>,
}

impl KeyringOwner {
    pub fn new() -> Self {
        Self { token: NEXT_OWNER.fetch_add(1, Ordering::Relaxed), vault_id: Mutex::new(None) }
    }

    /// Releases this owner's claim on `vault_id` (the group it unlocked, or the one it is in now).
    pub fn release(&self, vault_id: &str) {
        if let Ok(mut ring) = KEYRING.lock() {
            release_in(&mut ring, self.token, vault_id);
        }
        if let Ok(mut held) = self.vault_id.lock()
            && held.as_deref() == Some(vault_id)
        {
            *held = None;
        }
    }
}

impl Default for KeyringOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for KeyringOwner {
    fn drop(&mut self) {
        let held = self.vault_id.lock().ok().and_then(|mut held| held.take());
        if let (Some(vault_id), Ok(mut ring)) = (held, KEYRING.lock()) {
            release_in(&mut ring, self.token, &vault_id);
        }
    }
}

/// A group whose last owner let go leaves memory with its keys.
fn release_in(ring: &mut BTreeMap<String, Group>, token: u64, vault_id: &str) {
    if let Some(group) = ring.get_mut(vault_id) {
        group.owners.remove(&token);
        if group.owners.is_empty() {
            ring.remove(vault_id);
        }
    }
}

pub fn install(vault_id: &str, epoch: u64, content: &[u8; 32], secret: &[u8; 32]) {
    if let Ok(mut ring) = KEYRING.lock() {
        ring.entry(vault_id.to_owned()).or_default().keys.insert(epoch, (Zeroizing::new(*content), Zeroizing::new(*secret)));
    }
}

/// The content key of `epoch` for reading a change; `None` waits (`PayloadError::MissingEpochKey`).
pub fn content_key(vault_id: &str, epoch: u64) -> Option<Zeroizing<[u8; 32]>> {
    KEYRING.lock().ok()?.get(vault_id)?.keys.get(&epoch).map(|(key, _)| key.clone())
}

/// Drops a group's keys at once (this PC leaves the group).
pub fn forget(vault_id: &str) {
    if let Ok(mut ring) = KEYRING.lock() {
        ring.remove(vault_id);
    }
}

/// The stored keys of `vault_id` (`sync_epoch_keys`): (content key, transport secret) by epoch.
pub fn stored_keys(db: &Connection, vault_id: &str) -> rusqlite::Result<EpochSecrets> {
    db.execute_batch(SCHEMA)?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = db
        .prepare("SELECT epoch, content_key, transport_secret FROM sync_epoch_keys WHERE vault_id = ?1")?
        .query_map([vault_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut keys = EpochSecrets::new();
    for (epoch, content, secret) in rows {
        let (content, secret) = (Zeroizing::new(content), Zeroizing::new(secret));
        let (Ok(content), Ok(secret)) = (<[u8; 32]>::try_from(&content[..]), <[u8; 32]>::try_from(&secret[..])) else {
            return Err(rusqlite::Error::InvalidColumnType(1, "content_key".into(), rusqlite::types::Type::Blob));
        };
        keys.insert(u64::try_from(epoch).unwrap_or(0), (Zeroizing::new(content), Zeroizing::new(secret)));
    }
    Ok(keys)
}

/// The newest epoch >= 2 whose content key `vault.db` holds for `vault_id`: what this PC writes with.
/// Read for every write, never from memory: nothing can make this PC fall back to K(1).
pub fn write_key_in(db: &Connection, vault_id: &str) -> rusqlite::Result<Option<(u64, Zeroizing<[u8; 32]>)>> {
    Ok(stored_keys(db, vault_id)?.into_iter().next_back().map(|(epoch, (key, _))| (epoch, key)))
}

/// The random transport secrets of rotated epochs, from `vault.db`.
pub fn random_secrets_in(db: &Connection, vault_id: &str) -> rusqlite::Result<BTreeMap<u64, Zeroizing<[u8; 32]>>> {
    Ok(stored_keys(db, vault_id)?.into_iter().map(|(epoch, (_, secret))| (epoch, secret)).collect())
}

/// At unlock: the stored keys of the current group into the keyring, claimed by `owner`. An error
/// is fatal for the unlock (the caller must not run without the keys it holds).
pub fn load(db: &Connection, owner: &KeyringOwner) -> rusqlite::Result<()> {
    db.execute_batch(SCHEMA)?;
    let vault_id = db.query_row("SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get::<_, String>(0)).optional()?;
    let keys = match &vault_id {
        Some(vault_id) => stored_keys(db, vault_id)?,
        None => EpochSecrets::new(),
    };
    let mut ring = KEYRING.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
    let mut held = owner.vault_id.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
    if let Some(previous) = held.take().filter(|previous| Some(previous) != vault_id.as_ref()) {
        release_in(&mut ring, owner.token, &previous);
    }
    let Some(vault_id) = vault_id else { return Ok(()) };
    let group = ring.entry(vault_id.clone()).or_default();
    group.owners.insert(owner.token);
    group.keys.extend(keys);
    *held = Some(vault_id);
    Ok(())
}

/// The newest epoch whose keys this PC must hold before it sends anything (H1 of the review), as
/// Android `EpochKeyRotation.awaitedEpoch`: a REMOVE after this PC joined whose valid set holds a
/// package for it, or for which no set is known yet while its issuer is a build that rotates (its
/// valid key statement is stored here). A set without this PC's package (a marker) ends the wait.
pub fn awaited_epoch(events: &[MembershipEvent], verified: &VerifiedMembership, local_device_id: &str,
    sets: &[PackageSet], statements: &[KeyStatement]) -> Option<u64> {
    let joined = events.iter().rposition(|event| event.subject_device_id == local_device_id
        && matches!(event.action, MembershipAction::Add | MembershipAction::Genesis))?;
    events.iter().enumerate()
        .filter(|(index, event)| *index > joined && event.action == MembershipAction::Remove && event.key_epoch >= 2
            && event.subject_device_id != local_device_id)
        .filter(|(_, remove)| match sets.iter().find(|set| set.epoch == remove.key_epoch && set.valid_in(events, verified)) {
            Some(set) => set.packages.contains_key(local_device_id),
            None => verified.members.get(&remove.issuer_device_id).is_some_and(|issuer| statements.iter()
                .any(|statement| statement.device_id == remove.issuer_device_id && statement.valid(&verified.vault_id, &issuer.public_key))),
        })
        .map(|(_, remove)| remove.key_epoch)
        .max()
}

/// True while this PC knows a REMOVE that made (or may have made) new keys but holds no package
/// for it: it then sends nothing over Wi-Fi or Google Drive until the keys arrive, so nothing it
/// writes meanwhile reaches the removed device, which holds every older key and prefix.
pub fn stranded(db: &Connection, events: &[MembershipEvent], verified: &VerifiedMembership, local_device_id: &str) -> rusqlite::Result<bool> {
    let Some(awaited) = awaited_epoch(events, verified, local_device_id, &package_sets(db, &verified.vault_id)?,
        &statements(db, &verified.vault_id)?) else { return Ok(false) };
    let newest = stored_keys(db, &verified.vault_id)?.keys().next_back().copied().unwrap_or(1);
    Ok(awaited > newest)
}

pub fn statements(db: &Connection, vault_id: &str) -> rusqlite::Result<Vec<KeyStatement>> {
    db.execute_batch(SCHEMA)?;
    let rows: Vec<String> = db
        .prepare("SELECT statement_json FROM sync_key_statements WHERE vault_id = ?1 ORDER BY device_id")?
        .query_map([vault_id], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows.iter().filter_map(|json| serde_json::from_str(json).ok()).collect())
}

pub fn package_sets(db: &Connection, vault_id: &str) -> rusqlite::Result<Vec<PackageSet>> {
    db.execute_batch(SCHEMA)?;
    let rows: Vec<String> = db
        .prepare("SELECT set_json FROM sync_key_packages WHERE vault_id = ?1 ORDER BY epoch")?
        .query_map([vault_id], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows.iter().filter_map(|json| serde_json::from_str(json).ok()).collect())
}

/// Keeps a member's statement when its signed identity key signed it for this group.
pub fn accept_statement(db: &Connection, verified: &VerifiedMembership, statement: &KeyStatement) -> rusqlite::Result<bool> {
    let Some(member) = verified.members.get(&statement.device_id).filter(|member| member.active) else { return Ok(false) };
    if !statement.valid(&verified.vault_id, &member.public_key) {
        return Ok(false);
    }
    db.execute_batch(SCHEMA)?;
    db.execute(
        "INSERT OR REPLACE INTO sync_key_statements (vault_id, device_id, statement_json) VALUES (?1, ?2, ?3)",
        params![verified.vault_id, statement.device_id, serde_json::to_string(statement).unwrap_or_default()],
    )?;
    Ok(true)
}

/// Keeps each valid set (never replacing one already kept), opens this PC's package and stores its
/// keys (also into the keyring). K(N) is derived from the package key and the vault's K(1)
/// (`content_key_from`). Returns the number of epochs whose keys this PC got now.
pub fn accept_packages(db: &Connection, events: &[MembershipEvent], verified: &VerifiedMembership, local_device_id: &str,
    private: &[u8; 32], sets: &[PackageSet]) -> rusqlite::Result<usize> {
    db.execute_batch(SCHEMA)?;
    let epoch1: Zeroizing<Vec<u8>> = Zeroizing::new(db.query_row(
        "SELECT content_key FROM sync_group_state WHERE vault_id = ?1", [&verified.vault_id], |row| row.get(0))?);
    let Ok(epoch1) = <[u8; 32]>::try_from(&epoch1[..]).map(Zeroizing::new) else {
        return Err(rusqlite::Error::InvalidColumnType(0, "content_key".into(), rusqlite::types::Type::Blob));
    };
    let mut opened = 0;
    for set in sets.iter().take(MAX_SETS) {
        if !set.valid_in(events, verified) {
            continue;
        }
        db.execute(
            "INSERT OR IGNORE INTO sync_key_packages (vault_id, epoch, set_json) VALUES (?1, ?2, ?3)",
            params![verified.vault_id, set.epoch as i64, serde_json::to_string(set).unwrap_or_default()],
        )?;
        let held: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_epoch_keys WHERE vault_id = ?1 AND epoch = ?2)",
            params![verified.vault_id, set.epoch as i64], |row| row.get(0))?;
        if held {
            continue;
        }
        let Some(sealed) = set.packages.get(local_device_id).and_then(|text| URL_SAFE_NO_PAD.decode(text).ok()) else { continue };
        let Some((secret, package_key)) = open_package(&verified.vault_id, set.epoch, local_device_id, private, &sealed) else { continue };
        let content = content_key_from(&epoch1, &verified.vault_id, set.epoch, &package_key);
        db.execute(
            "INSERT OR REPLACE INTO sync_epoch_keys (vault_id, epoch, content_key, transport_secret) VALUES (?1, ?2, ?3, ?4)",
            params![verified.vault_id, set.epoch as i64, &content[..], &secret[..]],
        )?;
        install(&verified.vault_id, set.epoch, &content, &secret);
        opened += 1;
    }
    Ok(opened)
}

/// `keys1{"statement": …, "packages": […]}`, the same frame as Android: sets oldest first (a
/// survivor many epochs behind needs those first), at most `MAX_SETS` and `MAX_FRAME_BYTES`.
pub fn encode_frame(statement: Option<&KeyStatement>, sets: &[PackageSet]) -> Vec<u8> {
    let mut ordered: Vec<&PackageSet> = sets.iter().collect();
    ordered.sort_by_key(|set| set.epoch);
    let mut bytes = 0;
    let mut kept = Vec::new();
    for set in ordered.into_iter().take(MAX_SETS) {
        let value = serde_json::to_value(set).unwrap_or_default();
        bytes += value.to_string().len() + 1;
        if bytes > MAX_FRAME_BYTES {
            break;
        }
        kept.push(value);
    }
    let mut body = serde_json::json!({"packages": kept});
    if let Some(statement) = statement {
        body["statement"] = serde_json::to_value(statement).unwrap_or_default();
    }
    [FRAME_PREFIX, body.to_string().as_bytes()].concat()
}

pub fn parse_frame(bytes: &[u8]) -> Option<(Option<KeyStatement>, Vec<PackageSet>)> {
    if bytes.len() > 256 * 1024 {
        return None;
    }
    let body: serde_json::Value = serde_json::from_slice(bytes.strip_prefix(FRAME_PREFIX)?).ok()?;
    let statement = serde_json::from_value(body["statement"].clone()).ok();
    let sets = body["packages"].as_array().map(|sets| {
        sets.iter().take(MAX_SETS).filter_map(|set| serde_json::from_value(set.clone()).ok()).collect()
    }).unwrap_or_default();
    Some((statement, sets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../fixtures/epoch-keys-v1.json")).unwrap()
    }

    fn bytes32(text: &str) -> [u8; 32] {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    #[test]
    fn device_keys_and_statements_match_the_vectors() {
        let vectors = vectors();
        assert_eq!(vectors["feature"], FEATURE);
        assert!(crate::protocol::SYNC_FEATURES.contains(&FEATURE));
        let vault = vectors["vaultId"].as_str().unwrap();
        for id in ["dev-pc", "dev-tablet", "dev-removed"] {
            let device = &vectors["devices"][id];
            let seed = bytes32(device["ed25519Seed"].as_str().unwrap());
            let private = x25519_private(&seed);
            assert_eq!(hex::encode(*private), device["x25519Private"]);
            assert_eq!(URL_SAFE_NO_PAD.encode(x25519_public(&private)), device["x25519"]);
            let key = SigningKey::from_bytes(&seed);
            let statement = KeyStatement::create(vault, id, &x25519_public(&private), |m| Some(key.sign(m).to_bytes())).unwrap();
            assert_eq!(hex::encode(statement.signing_bytes()), device["statementHex"]);
            assert_eq!(statement.signature, device["signature"]);
            assert!(statement.valid(vault, &key.verifying_key().to_bytes()));
            assert!(!statement.valid("other", &key.verifying_key().to_bytes()));
            assert!(!statement.valid(vault, &SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()));
        }
    }

    #[test]
    fn only_the_right_survivor_opens_its_package() {
        let vectors = vectors();
        let vault = vectors["vaultId"].as_str().unwrap();
        let secret = bytes32(vectors["transportSecretHex"].as_str().unwrap());
        let content = bytes32(vectors["packageKeyHex"].as_str().unwrap());
        let private = |id: &str| bytes32(vectors["devices"][id]["x25519Private"].as_str().unwrap());
        for (index, id) in ["dev-pc", "dev-tablet"].iter().enumerate() {
            let sealed = URL_SAFE_NO_PAD.decode(vectors["packages"][*id].as_str().unwrap()).unwrap();
            let (s, k) = open_package(vault, 2, id, &private(id), &sealed).unwrap();
            assert_eq!((*s, *k), (secret, content));
            let recipient: [u8; 32] = URL_SAFE_NO_PAD.decode(vectors["devices"][*id]["x25519"].as_str().unwrap()).unwrap().try_into().unwrap();
            let again = seal_package_with(vault, 2, id, &recipient, &secret, &content, &[0x40 + index as u8; 32], &[0x50 + index as u8; 12]);
            assert_eq!(again, sealed);
        }
        let pc = URL_SAFE_NO_PAD.decode(vectors["packages"]["dev-pc"].as_str().unwrap()).unwrap();
        assert!(open_package(vault, 2, "dev-pc", &private("dev-removed"), &pc).is_none(), "the removed device");
        assert!(open_package(vault, 2, "dev-tablet", &private("dev-tablet"), &pc).is_none(), "another survivor");
        assert!(open_package(vault, 3, "dev-pc", &private("dev-pc"), &pc).is_none(), "another epoch");
        let tampered = URL_SAFE_NO_PAD.decode(vectors["tamperedPackage"]["package"].as_str().unwrap()).unwrap();
        assert!(open_package(vault, 2, "dev-pc", &private("dev-pc"), &tampered).is_none(), "a changed package");
    }

    /// H3: the package gives S(N) and P(N); K(N) also needs the vault's K(1).
    #[test]
    fn the_content_key_needs_the_package_key_and_the_vaults_epoch_one_key() {
        let vectors = vectors();
        let vault = vectors["vaultId"].as_str().unwrap();
        let k1 = bytes32(vectors["epoch1ContentKeyHex"].as_str().unwrap());
        let p2 = bytes32(vectors["packageKeyHex"].as_str().unwrap());
        assert_eq!(hex::encode(*content_key_from(&k1, vault, 2, &p2)), vectors["contentKeyHex"]);
        assert_ne!(hex::encode(p2), vectors["contentKeyHex"].as_str().unwrap());
        assert_ne!(*content_key_from(&[0; 32], vault, 2, &p2), *content_key_from(&k1, vault, 2, &p2));
        assert_ne!(*content_key_from(&k1, vault, 3, &p2), *content_key_from(&k1, vault, 2, &p2));
    }

    /// L3: only canonical base64url (no padding, no stray bits) is read; Android decodes as strictly.
    #[test]
    fn non_canonical_base64_url_is_refused() {
        let vectors = vectors();
        let case = &vectors["nonCanonicalPackage"];
        assert!(URL_SAFE_NO_PAD.decode(case["canonical"].as_str().unwrap()).is_ok());
        assert!(URL_SAFE_NO_PAD.decode(case["lenient"].as_str().unwrap()).is_err());
        let packages: BTreeMap<String, String> = vectors["packages"].as_object().unwrap().iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned())).collect();
        let manager: [u8; 32] = URL_SAFE_NO_PAD.decode(vectors["managerPublic"].as_str().unwrap()).unwrap().try_into().unwrap();
        let remove = vectors["removeEventHash"].as_str().unwrap();
        let mut set = PackageSet { vault_id: vault_of(&vectors), epoch: 2, remove_hash: remove.into(), packages,
            signature: vectors["setSignature"].as_str().unwrap().into() };
        assert!(set.valid(&vault_of(&vectors), &manager, remove));
        set.packages.insert("dev-pc".into(), case["lenient"].as_str().unwrap().into());
        assert!(!set.valid(&vault_of(&vectors), &manager, remove));
    }

    fn vault_of(vectors: &Value) -> String {
        vectors["vaultId"].as_str().unwrap().to_owned()
    }

    /// L2: a low-order statement key is not a valid statement, so it can't make a rotation fail.
    #[test]
    fn a_low_order_statement_key_is_refused() {
        let key = SigningKey::from_bytes(&[12; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        for point in [[0u8; 32], one, bytes32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")] {
            assert!(!valid_point(&point));
            let statement = KeyStatement::create("v", "d", &point, |m| Some(key.sign(m).to_bytes())).unwrap();
            assert!(statement.public_key().is_none());
            assert!(!statement.valid("v", &key.verifying_key().to_bytes()));
        }
    }

    /// An empty set is the manager's signed marker that a REMOVE made no new keys.
    #[test]
    fn an_empty_set_is_a_signed_marker() {
        let vectors = vectors();
        let marker = &vectors["markerSet"];
        let set = PackageSet { vault_id: vault_of(&vectors), epoch: 3, remove_hash: marker["removeHash"].as_str().unwrap().into(),
            packages: BTreeMap::new(), signature: marker["signature"].as_str().unwrap().into() };
        assert_eq!(hex::encode(set.signing_bytes()), marker["setStatementHex"]);
        let manager: [u8; 32] = URL_SAFE_NO_PAD.decode(vectors["managerPublic"].as_str().unwrap()).unwrap().try_into().unwrap();
        assert!(set.valid(&vault_of(&vectors), &manager, marker["removeHash"].as_str().unwrap()));
        assert!(!set.valid(&vault_of(&vectors), &manager, &"ab".repeat(32)));
    }

    /// I3: the `e.` file body of the vectors is a whole package set, which this PC parses and checks.
    #[test]
    fn the_package_file_vector_is_a_whole_set() {
        let vectors = vectors();
        let file = &vectors["packageFile"];
        let set: PackageSet = serde_json::from_str(file["bodyJson"].as_str().unwrap()).unwrap();
        let manager: [u8; 32] = URL_SAFE_NO_PAD.decode(vectors["managerPublic"].as_str().unwrap()).unwrap().try_into().unwrap();
        assert!(set.valid(&vault_of(&vectors), &manager, vectors["removeEventHash"].as_str().unwrap()));
        let root = hex::decode(vectors["rootTransportSecretHex"].as_str().unwrap()).unwrap();
        let keys = crate::lan_sync::cloud::CloudKeys::derive(&root, &vault_of(&vectors)).unwrap();
        let name = file["name"].as_str().unwrap();
        let sealed = hex::decode(file["sealedHex"].as_str().unwrap()).unwrap();
        assert_eq!(keys.open(name, &sealed).unwrap(), file["bodyJson"].as_str().unwrap().as_bytes());
    }

    /// C1: the keyring belongs to the unlocked vault that loaded it; another instance letting go
    /// does not empty it, and writing reads the keys from the vault, never from memory.
    #[test]
    fn another_vault_instance_cannot_clear_the_keyring_and_writes_never_fall_back() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE local_sync_settings (id INTEGER PRIMARY KEY, vault_id TEXT NOT NULL);
            INSERT INTO local_sync_settings VALUES (1, 'vault-c1');").unwrap();
        db.execute_batch(SCHEMA).unwrap();
        db.execute("INSERT INTO sync_epoch_keys VALUES ('vault-c1', 2, ?1, ?2)", params![&[7u8; 32][..], &[8u8; 32][..]]).unwrap();
        let unlocked = KeyringOwner::new();
        load(&db, &unlocked).unwrap();
        // A second instance (a password check, a Windows Hello setup) loads and goes away.
        let checking = KeyringOwner::new();
        load(&db, &checking).unwrap();
        drop(checking);
        assert_eq!(*content_key("vault-c1", 2).unwrap(), [7; 32]);
        // Even with the memory cleared, the write key and the Drive/Wi-Fi secrets come from the vault.
        forget("vault-c1");
        assert_eq!(write_key_in(&db, "vault-c1").unwrap().map(|(epoch, key)| (epoch, *key)), Some((2, [7; 32])));
        assert_eq!(random_secrets_in(&db, "vault-c1").unwrap().get(&2).map(|secret| **secret), Some([8; 32]));
        let payload = crate::payload::encrypt_in(&db, &[1; 32], "entry", "vault-c1", "m", "e", b"{}").unwrap();
        assert!(payload.nonce.starts_with("e2."));
        // The last owner releases the keys from memory.
        load(&db, &unlocked).unwrap();
        drop(unlocked);
        assert!(content_key("vault-c1", 2).is_none());
    }

    /// H1: a REMOVE whose issuer rotates (its statement is known) is awaited until this PC holds its
    /// keys; a marker or the package ends the wait; an older issuer (no statement) is not awaited.
    #[test]
    fn a_survivor_waits_for_a_rotated_epoch_until_its_package_or_a_marker_arrives() {
        let phone = SigningKey::from_bytes(&[17; 32]);
        let pc = SigningKey::from_bytes(&[12; 32]);
        let vault = "vault-wait";
        let sign = |mut event: MembershipEvent| {
            let bytes = event.signing_bytes().unwrap();
            event.signature = URL_SAFE_NO_PAD.encode(phone.sign(&bytes).to_bytes());
            let mut digest = Sha256::new();
            digest.update(&bytes);
            digest.update(event.signature.as_bytes());
            event.hash = hex::encode(digest.finalize());
            event
        };
        let event = |sequence: u64, previous: &str, action: MembershipAction, subject: &str, key: String, epoch: u64| MembershipEvent {
            vault_id: vault.into(), sequence, format_version: 1, previous_hash: previous.into(), action,
            issuer_device_id: "phone".into(), subject_device_id: subject.into(), subject_public_key: key, key_epoch: epoch,
            signature: String::new(), hash: String::new() };
        let genesis = sign(event(1, crate::sync::GENESIS_HASH, MembershipAction::Genesis, "phone", URL_SAFE_NO_PAD.encode(phone.verifying_key().to_bytes()), 1));
        let add_pc = sign(event(2, &genesis.hash, MembershipAction::Add, "pc", URL_SAFE_NO_PAD.encode(pc.verifying_key().to_bytes()), 1));
        let add_old = sign(event(3, &add_pc.hash, MembershipAction::Add, "old", URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[55; 32]).verifying_key().to_bytes()), 1));
        let remove = sign(event(4, &add_old.hash, MembershipAction::Remove, "old", String::new(), 2));
        let events = vec![genesis, add_pc, add_old, remove.clone()];
        let verified = crate::membership::verify(&events).unwrap();
        let phone_x = x25519_private(&[17; 32]);
        let statement = KeyStatement::create(vault, "phone", &x25519_public(&phone_x), |m| Some(phone.sign(m).to_bytes())).unwrap();
        // An older phone (no statement): nothing is awaited.
        assert_eq!(awaited_epoch(&events, &verified, "pc", &[], &[]), None);
        // A phone that rotates: epoch 2 is awaited until a set arrives.
        assert_eq!(awaited_epoch(&events, &verified, "pc", &[], std::slice::from_ref(&statement)), Some(2));
        let mut marker = PackageSet { vault_id: vault.into(), epoch: 2, remove_hash: remove.hash.clone(), packages: BTreeMap::new(), signature: String::new() };
        marker.signature = URL_SAFE_NO_PAD.encode(phone.sign(&marker.signing_bytes()).to_bytes());
        assert_eq!(awaited_epoch(&events, &verified, "pc", std::slice::from_ref(&marker), std::slice::from_ref(&statement)), None);
        let mut set = marker.clone();
        set.packages.insert("pc".into(), URL_SAFE_NO_PAD.encode([1u8; 124]));
        set.signature = URL_SAFE_NO_PAD.encode(phone.sign(&set.signing_bytes()).to_bytes());
        assert_eq!(awaited_epoch(&events, &verified, "pc", std::slice::from_ref(&set), &[]), Some(2));
        // A marker signed by another device is no marker.
        let mut forged = marker.clone();
        forged.signature = URL_SAFE_NO_PAD.encode(pc.sign(&forged.signing_bytes()).to_bytes());
        assert_eq!(awaited_epoch(&events, &verified, "pc", &[forged], std::slice::from_ref(&statement)), Some(2));
        // The stored form: stranded until the vault holds a key of epoch 2.
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        db.execute("INSERT INTO sync_key_statements VALUES (?1, 'phone', ?2)", params![vault, serde_json::to_string(&statement).unwrap()]).unwrap();
        assert!(stranded(&db, &events, &verified, "pc").unwrap());
        db.execute("INSERT INTO sync_epoch_keys VALUES (?1, 2, ?2, ?3)", params![vault, &[7u8; 32][..], &[8u8; 32][..]]).unwrap();
        assert!(!stranded(&db, &events, &verified, "pc").unwrap());
    }

    #[test]
    fn the_package_set_is_signed_by_the_manager_and_bound_to_the_remove() {
        let vectors = vectors();
        let vault = vectors["vaultId"].as_str().unwrap();
        let packages: BTreeMap<String, String> = vectors["packages"].as_object().unwrap().iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned())).collect();
        let remove = vectors["removeEventHash"].as_str().unwrap();
        let set = PackageSet { vault_id: vault.into(), epoch: 2, remove_hash: remove.into(), packages,
            signature: vectors["setSignature"].as_str().unwrap().into() };
        assert_eq!(hex::encode(set.signing_bytes()), vectors["setStatementHex"]);
        let manager: [u8; 32] = URL_SAFE_NO_PAD.decode(vectors["managerPublic"].as_str().unwrap()).unwrap().try_into().unwrap();
        assert!(set.valid(vault, &manager, remove));
        assert!(!set.valid(vault, &manager, &"ab".repeat(32)));
        assert!(!set.valid("other", &manager, remove));
        let mut fewer = set.clone();
        fewer.packages.remove("dev-tablet");
        assert!(!fewer.valid(vault, &manager, remove));
        assert_eq!(MAX_SETS, 64);
        let (statement, sets) = parse_frame(&encode_frame(None, &[set.clone()])).unwrap();
        assert_eq!((statement, sets), (None, vec![set]));
    }

    #[test]
    fn payload_nonces_carry_the_epoch_and_secrets_follow_the_newest_random_one() {
        let vectors = vectors();
        let vault = vectors["vaultId"].as_str().unwrap();
        for case in vectors["nonces"].as_array().unwrap() {
            let epoch = epoch_of(case["field"].as_str().unwrap());
            if case["valid"].as_bool().unwrap() {
                assert_eq!(epoch, case["epoch"].as_u64(), "{case}");
            } else {
                assert_eq!(epoch, None, "{case}");
            }
        }
        for payload in vectors["payloads"].as_array().unwrap() {
            let epoch = payload["epoch"].as_u64().unwrap();
            let nonce = nonce_bytes(payload["payloadNonce"].as_str().unwrap()).unwrap();
            assert_eq!(nonce_field(epoch, &nonce), payload["payloadNonce"]);
            assert_eq!(aad("entry", vault, epoch, payload["mutationId"].as_str().unwrap(), payload["entityId"].as_str().unwrap()), payload["aad"]);
        }
        let root = bytes32(vectors["rootTransportSecretHex"].as_str().unwrap());
        let s2 = bytes32(vectors["transportSecretHex"].as_str().unwrap());
        let none = BTreeMap::new();
        let rotated = BTreeMap::from([(2u64, Zeroizing::new(s2))]);
        assert_eq!(hex::encode(&*transport_secret(&root, vault, 2, &none).unwrap()), vectors["epoch2DerivedTransportHex"]);
        assert_eq!(*transport_secret(&root, vault, 2, &rotated).unwrap(), s2.to_vec());
        assert_eq!(hex::encode(&*transport_secret(&root, vault, 3, &rotated).unwrap()), vectors["epoch3AfterRotationTransportHex"]);
        for cloud in vectors["cloud"].as_array().unwrap() {
            let (_, secret) = drive_secret(&root, cloud["epoch"].as_u64().unwrap(), &rotated);
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret).unwrap();
            mac.update(format!("nuvori-cloud-v1:{vault}").as_bytes());
            assert_eq!(hex::encode(mac.finalize().into_bytes()), cloud["cloudKeyHex"]);
        }
    }
}
