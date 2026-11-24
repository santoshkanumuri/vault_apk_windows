use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    browser,
    change_store::{ChangeStore, StoreError, StoredVaultRecord},
    hello,
    identity::{DeviceIdentityStore, IdentityError},
    passkeys::{PasskeyError, VaultPasskey},
    payload::{self, PayloadError},
    photo_blobs::PhotoBlobs,
    protocol::RecordVersion,
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
};

/// What a forced leave kept of the received changes that had not applied (see
/// `UnlockedVault::leave_after_removal`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RemovalKept {
    /// Entries and notes kept in Recently deleted.
    pub kept_entries: usize,
    /// Folder, passkey and photo changes that could not be kept on this PC.
    pub other_changes: usize,
}

impl RemovalKept {
    /// The sentence for the person, or `None` when nothing was waiting. Same words as Android.
    pub(crate) fn message(&self) -> Option<String> {
        let kept = match self.kept_entries {
            0 => String::new(),
            1 => "1 item that had not finished syncing is in Recently deleted. Restore it there within 30 days.".to_owned(),
            count => format!("{count} items that had not finished syncing are in Recently deleted. Restore them there within 30 days."),
        };
        let other = match self.other_changes {
            0 => String::new(),
            1 => "1 other change (folders, passkeys or photos) could not be kept here. The devices that made them still have them.".to_owned(),
            count => format!("{count} other changes (folders, passkeys or photos) could not be kept here. The devices that made them still have them."),
        };
        let text = [kept, other].into_iter().filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" ");
        (!text.is_empty()).then_some(text)
    }
}

/// Format 2 stores the Argon2id settings in the file. Format 1 (Windows 2.2.9 and earlier) always used
/// [`KdfParams::LEGACY`]; the next unlock with the master password saves it again in format 2.
const BOOTSTRAP_VERSION: u16 = 2;
const LEGACY_BOOTSTRAP_VERSION: u16 = 1;
const MIN_PASSWORD_LENGTH: usize = 12;
const BOOTSTRAP_FILE: &str = "vault-key-v1.json";
const DATABASE_FILE: &str = "vault.db";
const HELLO_FILE: &str = "hello-unlock-v1.bin";
const PHOTO_BLOB_DIRECTORY: &str = "photo-blobs";

pub struct VaultStore {
    directory: PathBuf,
}

pub struct UnlockedVault {
    connection: Connection,
    key: [u8; 32],
    identity_store: DeviceIdentityStore,
    blobs: PhotoBlobs,
    /// This instance's claim on the in-memory keys of rotated epochs (`epoch_keys::KeyringOwner`).
    keyring: crate::epoch_keys::KeyringOwner,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalNote {
    pub id: String,
    pub title: String,
    pub body: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub group_ids: Vec<String>,
    /// Rich note formatting (docs/RICH-NOTES-PLAN.md), kept in the entry's `fourthValue`; empty for plain notes.
    #[serde(default)]
    pub rich: String,
}

/// Rich note JSON is at most 512 KiB, and with the text it must fit one sync payload.
const MAX_RICH_NOTE_BYTES: usize = 512 * 1024;
const MAX_NOTE_PAYLOAD_BYTES: usize = 1_000_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalGroup {
    pub id: String,
    pub name: String,
    pub notes: String,
    pub folder_type: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeySummary {
    pub id: String,
    pub rp_id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryPhoto {
    pub id: String,
    pub mime_type: String,
    pub data_url: String,
    /// Android's cover flag (`VaultPhoto.isCover`).
    pub is_cover: bool,
    /// Unix milliseconds (`VaultPhoto.addedAt`); 0 for photos saved before schema version 1.
    pub added_at: i64,
}

impl VaultStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub(crate) fn identity_store(&self) -> DeviceIdentityStore {
        DeviceIdentityStore::new(self.directory.join("device-identity-v1.json"))
    }

    pub fn is_initialized(&self) -> bool {
        self.directory.join(BOOTSTRAP_FILE).exists()
    }

    pub fn hello_enabled(&self) -> bool {
        self.is_initialized() && self.directory.join(HELLO_FILE).exists()
    }

    /// The saved Windows Hello unlock, as `hello::seal` made it (or a legacy DPAPI-only file).
    pub fn hello_file(&self) -> Result<Vec<u8>, VaultError> {
        Ok(fs::read(self.directory.join(HELLO_FILE))?)
    }

    /// Saves a Windows Hello unlock made by `hello::seal`.
    pub fn enable_hello(&self, sealed: &[u8]) -> Result<(), VaultError> {
        if hello::is_legacy(sealed) {
            return Err(VaultError::Hello(
                "Windows Hello could not protect the vault key".to_owned(),
            ));
        }
        fs::write(self.directory.join(HELLO_FILE), sealed)?;
        Ok(())
    }

    pub fn disable_hello(&self) -> Result<(), VaultError> {
        let path = self.directory.join(HELLO_FILE);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Opens the vault with a key that `hello::unseal` (or the legacy reader) returned.
    pub fn unlock_hello(&self, key: &[u8; 32]) -> Result<UnlockedVault, VaultError> {
        self.open_with_key(key)
    }

    /// Checks the master password without opening a second `UnlockedVault`: one more instance would
    /// run unlock side effects and, before the keyring had owners, its drop emptied the keyring of
    /// the vault that stays unlocked (C1 of the key-rotation review).
    pub fn verify_password(&self, password: &str) -> Result<(), VaultError> {
        let (key, ..) = self.unwrap_key(password)?;
        let connection = open_database(&self.directory.join(DATABASE_FILE), &key, false)?;
        connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))?;
        Ok(())
    }

    /// When the vault was last changed, in Unix milliseconds: the newest write time of its
    /// database and key files. Reads file times only, never the files.
    pub fn last_used_millis(&self) -> Option<i64> {
        [DATABASE_FILE, "vault.db-wal", BOOTSTRAP_FILE]
            .into_iter()
            .filter_map(|name| fs::metadata(self.directory.join(name)).and_then(|metadata| metadata.modified()).ok())
            .map(crate::install_marker::millis)
            .max()
    }

    /// "Start fresh on this PC": deletes the same files as the password-checked reset, without the
    /// password. Only for a locked vault: the caller makes sure this process has it closed, and
    /// this refuses when any other process still has the database open. Nothing is read from
    /// the vault and nothing is sent to other devices.
    pub fn start_fresh(&self) -> Result<(), VaultError> {
        self.ensure_database_closed()?;
        self.reset_files()
    }

    /// Opens the database files with no sharing, which Windows refuses while any other handle to
    /// them is open (SQLite never shares delete access). Opens them for reading and reads nothing.
    fn ensure_database_closed(&self) -> Result<(), VaultError> {
        use std::os::windows::fs::OpenOptionsExt;
        const ERROR_SHARING_VIOLATION: i32 = 32;
        const ERROR_LOCK_VIOLATION: i32 = 33;
        for name in [DATABASE_FILE, "vault.db-wal"] {
            match fs::OpenOptions::new().read(true).share_mode(0).open(self.directory.join(name)) {
                Ok(file) => drop(file),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) if matches!(error.raw_os_error(), Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)) => {
                    return Err(VaultError::InUse);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub fn reset_files(&self) -> Result<(), VaultError> {
        for name in [
            DATABASE_FILE,
            "vault.db-wal",
            "vault.db-shm",
            "vault.db-journal",
            "device-identity-v1.json",
            HELLO_FILE,
            BOOTSTRAP_FILE,
        ] {
            let path = self.directory.join(name);
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        {
            let blobs = self.directory.join(PHOTO_BLOB_DIRECTORY);
            if blobs.exists() {
                fs::remove_dir_all(blobs)?;
            }
        }
        Ok(())
    }

    pub fn create(&self, password: &str) -> Result<UnlockedVault, VaultError> {
        if password.chars().count() < MIN_PASSWORD_LENGTH {
            return Err(VaultError::PasswordTooShort);
        }
        fs::create_dir_all(&self.directory)?;
        let bootstrap_path = self.directory.join(BOOTSTRAP_FILE);
        let database_path = self.directory.join(DATABASE_FILE);
        if bootstrap_path.exists() || database_path.exists() {
            return Err(VaultError::AlreadyInitialized);
        }

        let vault_key = Zeroizing::new(random_array()?);
        let bootstrap = wrap_vault_key(&vault_key, password, KdfParams::calibrated()?)?;

        let connection = match open_database(&database_path, &vault_key, true) {
            Ok(connection) => connection,
            Err(error) => {
                let _ = fs::remove_file(&database_path);
                return Err(error);
            }
        };
        if let Err(error) = ChangeStore::initialize(&connection) {
            drop(connection);
            let _ = fs::remove_file(&database_path);
            return Err(error.into());
        }
        if let Err(error) = initialize_notes(&connection) {
            drop(connection);
            let _ = fs::remove_file(&database_path);
            return Err(error);
        }
        if let Err(error) = initialize_local_sync_settings(&connection) {
            drop(connection);
            let _ = fs::remove_file(&database_path);
            return Err(error);
        }
        if let Err(error) = write_new_bootstrap(&bootstrap_path, &bootstrap) {
            drop(connection);
            let _ = fs::remove_file(&database_path);
            return Err(error);
        }
        Ok(UnlockedVault {
            connection,
            key: *vault_key,
            identity_store: DeviceIdentityStore::new(
                self.directory.join("device-identity-v1.json"),
            ),
            blobs: PhotoBlobs::new(self.directory.join(PHOTO_BLOB_DIRECTORY)),
            keyring: crate::epoch_keys::KeyringOwner::new(),
        })
    }

    pub fn unlock(&self, password: &str) -> Result<UnlockedVault, VaultError> {
        let (key, bootstrap, elapsed, params) = self.unwrap_key(password)?;
        let bootstrap_path = self.directory.join(BOOTSTRAP_FILE);
        let vault = self.open_with_key(&key)?;
        if bootstrap.format_version == LEGACY_BOOTSTRAP_VERSION {
            // The key opened the database, so save it again with settings timed on this PC. The
            // Argon2id run above already measured this PC, so no extra benchmark runs. A failure
            // keeps the old file, and the vault still opens.
            let upgraded = wrap_vault_key(&key, password, KdfParams::for_measured(elapsed, params.iterations))
                .and_then(|bootstrap| write_new_bootstrap(&bootstrap_path, &bootstrap));
            if let Err(error) = upgraded {
                crate::activity::diagnostic(crate::activity::Category::Vault, "Could not strengthen the vault key file", error);
            }
        }
        Ok(vault)
    }

    /// The vault key the master password unwraps, with what `unlock` needs to upgrade the key file.
    #[allow(clippy::type_complexity)]
    fn unwrap_key(&self, password: &str) -> Result<(Zeroizing<[u8; 32]>, VaultBootstrap, std::time::Duration, KdfParams), VaultError> {
        let bootstrap_path = self.directory.join(BOOTSTRAP_FILE);
        let bootstrap: VaultBootstrap = serde_json::from_slice(&fs::read(&bootstrap_path)?)?;
        let params = bootstrap.kdf_params()?;
        let salt: [u8; 16] = decode_array(&bootstrap.salt)?;
        let nonce: [u8; 12] = decode_array(&bootstrap.nonce)?;
        let wrapped = URL_SAFE_NO_PAD.decode(&bootstrap.wrapped_key)?;
        let started = std::time::Instant::now();
        let wrapping_key = Zeroizing::new(derive(password, &salt, params)?);
        let elapsed = started.elapsed();
        let unwrapped = Aes256Gcm::new_from_slice(&*wrapping_key)
            .expect("32-byte key")
            .decrypt(Nonce::from_slice(&nonce), wrapped.as_ref())
            .map_err(|_| VaultError::WrongPasswordOrCorruptKey);
        let mut unwrapped = unwrapped?;
        let key: Zeroizing<[u8; 32]> = match unwrapped.as_slice().try_into() {
            Ok(key) => Zeroizing::new(key),
            Err(_) => {
                unwrapped.zeroize();
                return Err(VaultError::InvalidVaultKey);
            }
        };
        unwrapped.zeroize();
        Ok((key, bootstrap, elapsed, params))
    }

    fn open_with_key(&self, key: &[u8; 32]) -> Result<UnlockedVault, VaultError> {
        let connection = open_database(&self.directory.join(DATABASE_FILE), key, false)?;
        // Vaults created by older builds lack sync tables added since; every statement here is
        // CREATE IF NOT EXISTS, so running it on each unlock only fills those gaps.
        ChangeStore::initialize(&connection)?;
        initialize_notes(&connection)?;
        initialize_local_sync_settings(&connection)?;
        let mut vault = UnlockedVault {
            connection,
            key: *key,
            identity_store: DeviceIdentityStore::new(
                self.directory.join("device-identity-v1.json"),
            ),
            blobs: PhotoBlobs::new(self.directory.join(PHOTO_BLOB_DIRECTORY)),
            keyring: crate::epoch_keys::KeyringOwner::new(),
        };
        vault.replace_retired_identity()?;
        vault.backfill_independent_history()?;
        // Keys of rotated epochs into memory while unlocked, for reading changes (`epoch_keys.rs`);
        // this vault's drop releases its claim. Without them the vault does not open.
        crate::epoch_keys::load(&vault.connection, &vault.keyring)?;
        // Local housekeeping only; a failure here must not block unlocking.
        let _ = now_millis().map(|now| crate::local_recovery::purge(&vault.connection, now));
        let _ = crate::site_icons::purge(&vault.connection, crate::site_icons::enabled());
        let _ = vault.sweep_orphan_photos();
        let _ = vault.publish_unsynced_photos();
        Ok(vault)
    }
}

impl UnlockedVault {
    /// This PC's device ID, when it has an identity (never creates one).
    pub(crate) fn local_device_id(&self) -> Option<String> {
        self.identity_store.exists().then(|| self.identity_store.get_or_create().ok()).flatten().map(|identity| identity.device_id)
    }

    pub fn key_for_hello(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn connection(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub fn note_count(&self) -> Result<u32, VaultError> {
        Ok(self
            .connection
            .query_row("SELECT count(*) FROM local_notes", [], |row| row.get(0))?)
    }

    pub fn is_enrolled(&self) -> Result<bool, VaultError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_group_state)",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn stop_sharing(&mut self) -> Result<(), VaultError> {
        self.leave_locally(true)
    }

    /// Leaves the group on this PC only: keeps every item, drops sync state, and starts an
    /// independent history under a new vault ID. `require_resolved` keeps open conflicts from
    /// being discarded by a user's own leave; a verified removal leaves regardless.
    fn leave_locally(&mut self, require_resolved: bool) -> Result<(), VaultError> {
        if !self.is_enrolled()? {
            return Err(VaultError::NotSharing);
        }
        let unresolved: i64 = self.connection.query_row(
            "SELECT count(*) FROM sync_conflicts WHERE resolved_at_utc = ''",
            [],
            |row| row.get(0),
        )?;
        if require_resolved && unresolved != 0 {
            return Err(VaultError::PendingConflicts);
        }
        let transaction = self.connection.transaction()?;
        // What this PC keeps of the group: each item's version, for a later merge join (`merge_join.rs`).
        let old_vault: String = transaction.query_row("SELECT vault_id FROM sync_group_state", [], |row| row.get(0))?;
        let versions = crate::merge_join::current_versions(&transaction)?;
        let digests = crate::migration_inventory::read(&transaction).map(|inventory| crate::snapshot_import::inventory_digests(&inventory))
            .unwrap_or_default();
        crate::merge_join::save_lineage(&transaction, &old_vault, &versions, &digests)?;
        crate::merge_join::clear_lost(&transaction)?;
        // The keys of the group's rotated epochs go with it (`epoch_keys.rs`).
        transaction.execute_batch(crate::epoch_keys::SCHEMA)?;
        transaction.execute_batch("DELETE FROM sync_epoch_keys; DELETE FROM sync_key_packages; DELETE FROM sync_key_statements;")?;
        crate::epoch_keys::forget(&old_vault);
        for table in [
            "sync_received_operations",
            "sync_applied_operations",
            "sync_exchange_state",
            "sync_peer_endpoints",
            "sync_peer_acknowledgements",
            "sync_peer_progress",
            "sync_conflicts",
            "sync_attachment_manifests",
            "sync_tombstones",
            "sync_device_heads",
            "sync_operations",
            "vault_records",
            "sync_memberships",
            "sync_membership_events",
            "sync_group_state",
        ] {
            transaction.execute(&format!("DELETE FROM {table}"), [])?;
        }
        transaction.execute(
            "UPDATE local_sync_settings SET vault_id = ?1 WHERE id = 1",
            [Uuid::new_v4().to_string()],
        )?;
        // The group keeps this identity as a member (or as removed) forever, and a device ID or
        // key that was ever in a group can't be added to it again. So this PC gets a new identity
        // (below) and can pair again later as a new device.
        if self.identity_store.exists() {
            let device_id = self.identity_store.get_or_create()?.device_id;
            crate::membership_exit::retire_identity(&transaction, &device_id, now_millis()?)?;
        }
        transaction.commit()?;
        // Shared photo blobs are encrypted with the group's content key, which is gone now.
        let _ = self.blobs.remove_all();
        // Before the independent history is signed, so it is signed by the new identity.
        self.replace_retired_identity()?;
        self.backfill_independent_history()
    }

    /// Replaces this PC's identity when a leave retired it (`membership_exit::retire_identity`).
    /// Runs right after the leave and again on unlock, in case the app stopped in between.
    fn replace_retired_identity(&mut self) -> Result<(), VaultError> {
        if !self.identity_store.exists() || self.is_enrolled()? {
            return Ok(());
        }
        let device_id = self.identity_store.get_or_create()?.device_id;
        if crate::membership_exit::is_retired(&self.connection, &device_id)? {
            self.identity_store.rotate()?;
        }
        Ok(())
    }

    pub fn paired_device_count(&self) -> Result<u32, VaultError> {
        if !self.is_enrolled()? || !self.identity_store.exists() {
            return Ok(0);
        }
        let local_device = self.identity_store.get_or_create()?.device_id;
        let mut statement = self.connection.prepare(
            "SELECT member_json FROM sync_memberships
             WHERE vault_id = (SELECT vault_id FROM local_sync_settings WHERE id = 1)",
        )?;
        let members = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut count = 0_u32;
        for member in members {
            let value: serde_json::Value = serde_json::from_str(&member?)?;
            if value["status"] == "ACTIVE" && value["deviceId"] != local_device {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    /// A number that changes when a change is stored or applied or the membership grows. The sync
    /// loop reads it every 2 seconds with the vault locked for other callers, so it reads the largest
    /// rowid of each table (one index step) instead of counting rows (a full scan: about 48 ms with
    /// 44,000 changes in a debug build). These tables only ever lose every row at once.
    pub fn change_revision(&self) -> Result<u64, VaultError> {
        let revision: i64 = self.connection.query_row(
            "SELECT (SELECT ifnull(max(rowid), 0) FROM sync_operations) + (SELECT ifnull(max(rowid), 0) FROM sync_applied_operations)
                  + (SELECT ifnull(max(rowid), 0) FROM sync_membership_events)",
            [],
            |row| row.get(0),
        )?;
        Ok(revision as u64)
    }

    pub fn local_change_count(&self) -> Result<u32, VaultError> {
        if !self.identity_store.exists() {
            return Ok(0);
        }
        let device_id = self.identity_store.get_or_create()?.device_id;
        // This device's newest sequence: the number of changes it wrote, also after history
        // compaction deleted older ones (a count of rows would shrink).
        let count: i64 = self.connection.query_row(
            "SELECT ifnull(max(sequence), 0) FROM sync_operations
             WHERE vault_id = (SELECT vault_id FROM local_sync_settings WHERE id = 1)
               AND device_id = ?1",
            [&device_id],
            |row| row.get(0),
        )?;
        Ok((count as u64).min(u32::MAX as u64) as u32)
    }

    pub fn entry_counts(&self) -> Result<BTreeMap<String, u32>, VaultError> {
        let mut statement = self
            .connection
            .prepare("SELECT type, count(*) FROM local_entries GROUP BY type")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;
        Ok(rows.collect::<Result<BTreeMap<_, _>, _>>()?)
    }

    pub fn list_notes(&self) -> Result<Vec<LocalNote>, VaultError> {
        let mut statement = self.connection.prepare(
            "SELECT n.id, n.title, n.body, n.created_at, n.updated_at, d.data_json
             FROM local_notes n LEFT JOIN local_note_details d ON d.id = n.id
             ORDER BY n.updated_at DESC, n.id",
        )?;
        let notes = statement.query_map([], |row| {
            Ok(LocalNote {
                id: row.get(0)?,
                title: row.get(1)?,
                body: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                group_ids: Vec::new(),
                rich: rich_from_details(row.get::<_, Option<String>>(5)?.as_deref()),
            })
        })?;
        let mut notes = notes.collect::<Result<Vec<_>, _>>()?;
        for note in &mut notes {
            note.group_ids = self.group_ids(&note.id)?;
        }
        Ok(notes)
    }

    pub fn save_note(
        &mut self,
        id: Option<&str>,
        title: &str,
        body: &str,
        group_ids: Option<Vec<String>>,
    ) -> Result<LocalNote, VaultError> {
        self.save_rich_note(id, title, body, None, group_ids)
    }

    /// Saves a note. `rich` is its formatting JSON ("" for a plain note); `None` keeps what the note had,
    /// and readers fall back to the text when it no longer matches.
    pub fn save_rich_note(
        &mut self,
        id: Option<&str>,
        title: &str,
        body: &str,
        rich: Option<&str>,
        group_ids: Option<Vec<String>>,
    ) -> Result<LocalNote, VaultError> {
        let title = title.trim();
        let body = body.trim();
        if title.is_empty() || body.is_empty() || title.len() > 500 || body.len() > 1_048_576 {
            return Err(VaultError::InvalidNote);
        }
        let rich = match (rich, id) {
            (Some(rich), _) => rich.to_owned(),
            (None, Some(id)) => {
                let details: Option<String> = self
                    .connection
                    .query_row("SELECT data_json FROM local_note_details WHERE id = ?1", [id], |row| row.get(0))
                    .optional()?;
                rich_from_details(details.as_deref())
            }
            (None, None) => String::new(),
        };
        if rich.len() > MAX_RICH_NOTE_BYTES
            || body.len() + rich.len() > MAX_NOTE_PAYLOAD_BYTES
            || !(rich.is_empty() || serde_json::from_str::<serde_json::Value>(&rich).is_ok_and(|value| value.is_object()))
        {
            return Err(VaultError::InvalidNote);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| VaultError::Clock)?
            .as_millis() as i64;
        let group_ids = match (id, group_ids) {
            (_, Some(group_ids)) => group_ids,
            (Some(id), None) => self.group_ids(id)?,
            (None, None) => Vec::new(),
        };
        if group_ids.len() > 100
            || group_ids.iter().collect::<BTreeSet<_>>().len() != group_ids.len()
        {
            return Err(VaultError::InvalidNote);
        }
        for group_id in &group_ids {
            let folder_type: Option<String> = self
                .connection
                .query_row(
                    "SELECT folder_type FROM local_groups WHERE id = ?1",
                    [group_id],
                    |row| row.get(0),
                )
                .optional()?;
            if !folder_type
                .is_some_and(|folder_type| folder_type.is_empty() || folder_type == "NOTE")
            {
                return Err(VaultError::InvalidNote);
            }
        }
        let note = if let Some(id) = id {
            let created_at = self
                .connection
                .query_row(
                    "SELECT created_at FROM local_notes WHERE id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(VaultError::NoteNotFound)?;
            LocalNote {
                id: id.to_owned(),
                title: title.to_owned(),
                body: body.to_owned(),
                created_at,
                updated_at: now,
                group_ids: group_ids.clone(),
                rich: rich.clone(),
            }
        } else {
            LocalNote {
                id: Uuid::new_v4().to_string(),
                title: title.to_owned(),
                body: body.to_owned(),
                created_at: now,
                updated_at: now,
                group_ids: group_ids.clone(),
                rich: rich.clone(),
            }
        };
        self.write_note_change(&note, ChangeKind::Upsert, |transaction| {
            transaction.execute(
                "INSERT INTO local_notes (id, title, body, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET title = excluded.title, body = excluded.body, updated_at = excluded.updated_at",
                params![note.id, note.title, note.body, note.created_at, note.updated_at],
            )?;
            transaction.execute("DELETE FROM entry_groups WHERE entry_id = ?1", [&note.id])?;
            for group_id in &group_ids {
                transaction.execute("INSERT INTO entry_groups (entry_id, group_id) VALUES (?1, ?2)",
                    params![note.id, group_id])?;
            }
            Ok(())
        })?;
        Ok(note)
    }

    pub fn delete_note(&mut self, id: &str) -> Result<(), VaultError> {
        let note = self
            .connection
            .query_row(
                "SELECT id, title, body, created_at, updated_at FROM local_notes WHERE id = ?1",
                [id],
                |row| {
                    Ok(LocalNote {
                        id: row.get(0)?,
                        title: row.get(1)?,
                        body: row.get(2)?,
                        created_at: row.get(3)?,
                        updated_at: row.get(4)?,
                        group_ids: Vec::new(),
                        rich: String::new(),
                    })
                },
            )
            .optional()?
            .ok_or(VaultError::NoteNotFound)?;
        self.write_note_change(&note, ChangeKind::Delete, |transaction| {
            crate::local_recovery::keep_deleted(transaction, id, now_millis().unwrap_or_default(), false)?;
            transaction.execute("DELETE FROM local_notes WHERE id = ?1", [id])?;
            transaction.execute("DELETE FROM entry_groups WHERE entry_id = ?1", [id])?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn list_entries(&self) -> Result<Vec<serde_json::Value>, VaultError> {
        let mut statement = self
            .connection
            .prepare("SELECT data_json FROM local_entries ORDER BY updated_at DESC, id")?;
        let entries = statement.query_map([], |row| row.get::<_, String>(0))?;
        entries
            .map(|entry| {
                let mut value: serde_json::Value = serde_json::from_str(&entry?)?;
                value["groupIds"] = serde_json::to_value(
                    self.group_ids(value["id"].as_str().ok_or(VaultError::InvalidEntry)?)?,
                )?;
                Ok(value)
            })
            .collect()
    }

    pub fn list_entry_photos(&self, entry_id: &str) -> Result<Vec<EntryPhoto>, VaultError> {
        self.require_entry(entry_id)?;
        let mut statement = self.connection.prepare(
            "SELECT id, mime_type, data, is_cover, added_at FROM local_entry_photos
             WHERE entry_id = ?1 ORDER BY is_cover DESC, added_at, id",
        )?;
        let rows = statement.query_map([entry_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (id, mime_type, data, is_cover, added_at) = row?;
            Ok(EntryPhoto {
                id,
                data_url: format!(
                    "data:{mime_type};base64,{}",
                    base64::engine::general_purpose::STANDARD.encode(data)
                ),
                mime_type,
                is_cover,
                added_at,
            })
        })
        .collect()
    }

    pub fn add_entry_photo(
        &mut self,
        entry_id: &str,
        mime_type: &str,
        encoded: &str,
    ) -> Result<(), VaultError> {
        self.require_entry(entry_id)?;
        if !matches!(
            mime_type,
            "image/jpeg" | "image/png" | "image/webp" | "image/gif"
        ) || encoded.len() > 14_000_000
        {
            return Err(VaultError::InvalidPhoto);
        }
        let data = URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))?;
        if data.is_empty() || data.len() > 10_000_000 {
            return Err(VaultError::InvalidPhoto);
        }
        let valid_image = match mime_type {
            "image/jpeg" => data.starts_with(&[0xff, 0xd8, 0xff]),
            "image/png" => data.starts_with(b"\x89PNG\r\n\x1a\n"),
            "image/webp" => data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP"),
            "image/gif" => data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a"),
            _ => false,
        };
        if !valid_image {
            return Err(VaultError::InvalidPhoto);
        }
        let count: u32 = self.connection.query_row(
            "SELECT count(*) FROM local_entry_photos WHERE entry_id = ?1",
            [entry_id],
            |row| row.get(0),
        )?;
        if count >= 20 {
            return Err(VaultError::InvalidPhoto);
        }
        let has_cover: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM local_entry_photos WHERE entry_id = ?1 AND is_cover = 1)",
            [entry_id],
            |row| row.get(0),
        )?;
        let photo_id = Uuid::new_v4().to_string();
        let added_at = now_millis()?;
        if !self.is_enrolled()? {
            self.connection.execute(
                "INSERT INTO local_entry_photos (id, entry_id, mime_type, data, is_cover, added_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![photo_id, entry_id, mime_type, data, !has_cover, added_at],
            )?;
            return Ok(());
        }
        // In a sync group a photo travels like Android's: a signed change plus a shared blob.
        let (hash, size, epoch) = self.create_photo_blob(&photo_id, &data)?;
        let payload = photo_payload(&photo_id, entry_id, !has_cover, added_at, &hash, size, epoch);
        let (entry_id, mime_type) = (entry_id.to_owned(), mime_type.to_owned());
        self.write_change("photo", &photo_id.clone(), ChangeKind::Upsert, payload, move |transaction| {
            transaction.execute(
                "INSERT INTO local_entry_photos (id, entry_id, mime_type, data, is_cover, added_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![photo_id, entry_id, mime_type, data, !has_cover, added_at],
            )?;
            insert_manifest(transaction, &photo_id, &entry_id, &hash, size)?;
            Ok(())
        })
    }

    pub fn delete_entry_photo(&mut self, photo_id: &str) -> Result<(), VaultError> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM local_entry_photos WHERE id = ?1)",
            [photo_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(VaultError::PhotoNotFound);
        }
        if ChangeStore::record(&self.connection, "photo", photo_id)?.is_some() {
            let id = photo_id.to_owned();
            return self.write_change("photo", photo_id, ChangeKind::Delete, serde_json::json!({"deleted": true}), move |transaction| {
                transaction.execute("DELETE FROM local_entry_photos WHERE id = ?1", [&id])?;
                transaction.execute("DELETE FROM sync_attachment_manifests WHERE attachment_id = ?1", [&id])?;
                Ok(())
            });
        }
        self.connection
            .execute("DELETE FROM local_entry_photos WHERE id = ?1", [photo_id])?;
        Ok(())
    }

    fn membership_events(&self) -> Result<Vec<crate::membership::MembershipEvent>, VaultError> {
        let rows: Vec<String> = self
            .connection
            .prepare(
                "SELECT event_json FROM sync_membership_events
                 WHERE vault_id = (SELECT vault_id FROM local_sync_settings WHERE id = 1) ORDER BY sequence",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        rows.iter().map(|json| Ok(serde_json::from_str(json)?)).collect()
    }

    fn member_name(&self, device_id: &str) -> Option<String> {
        let json: Option<String> = self
            .connection
            .query_row("SELECT member_json FROM sync_memberships WHERE device_id = ?1", [device_id], |row| row.get(0))
            .optional()
            .ok()
            .flatten();
        json.and_then(|json| serde_json::from_str::<crate::snapshot::SnapshotMember>(&json).ok())
            .map(|member| member.display_name)
            .filter(|name| !name.trim().is_empty())
    }

    /// "Mark as lost": the managing phone is gone. This PC keeps the group's membership as it is and
    /// takes no new changes from that phone. It keeps syncing with the other devices, and it may
    /// pair with a new managing phone, keeping its items (`merge_join.rs`). Local only.
    pub fn mark_manager_lost(&mut self) -> Result<(), VaultError> {
        if !self.is_enrolled()? {
            return Err(VaultError::NotSharing);
        }
        let events = self.membership_events()?;
        let verified = crate::membership::verify(&events).map_err(|_| VaultError::NotSharing)?;
        let local = self.identity_store.get_or_create()?;
        if verified.manager_device_id == local.device_id {
            return Err(VaultError::ManagingDevice);
        }
        crate::merge_join::mark_lost(&self.connection, &verified.vault_id, &local.device_id, &events, now_millis()?)
            .map_err(|_| VaultError::NotSharing)?;
        Ok(())
    }

    /// The managing phone was not lost after all: the freeze ends. Nothing else changed.
    pub fn undo_manager_lost(&mut self) -> Result<(), VaultError> {
        crate::merge_join::clear_lost(&self.connection)?;
        Ok(())
    }

    /// True after "Mark as lost" for the current group: pairing with a new managing phone is allowed.
    pub fn manager_lost(&self) -> Result<bool, VaultError> {
        let vault_id: String = self
            .connection
            .query_row("SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get(0))
            .optional()?
            .unwrap_or_default();
        Ok(crate::merge_join::lost_freeze(&self.connection, &vault_id)?.is_some())
    }

    /// SPEC3 `membership_status`. Display names only; no keys or secrets.
    pub fn membership_status(&self) -> Result<crate::membership_exit::MembershipStatus, VaultError> {
        use crate::membership_exit::{self as exit, MemberRow, MembershipStatus};
        let local_device_id = if self.identity_store.exists() {
            self.identity_store.get_or_create()?.device_id
        } else {
            String::new()
        };
        let mut status = MembershipStatus {
            local_device_id: local_device_id.clone(),
            removed_notice: exit::removed_notice(&self.connection)?,
            pending_leave: exit::pending_leave(&self.connection, now_millis()?)?.is_some(),
            ..Default::default()
        };
        if !self.is_enrolled()? {
            return Ok(status);
        }
        let Ok(verified) = crate::membership::verify(&self.membership_events()?) else {
            return Ok(status);
        };
        status.manager_name = self.member_name(&verified.manager_device_id).unwrap_or_else(|| "Managing device".to_owned());
        status.manager_lost = crate::merge_join::lost_freeze(&self.connection, &verified.vault_id)?
            .is_some_and(|freeze| freeze.device_id == verified.manager_device_id);
        let names: std::collections::BTreeMap<String, String> = verified.members.keys()
            .filter_map(|id| self.member_name(id).map(|name| (id.clone(), name))).collect();
        status.cleanup_hint = crate::compaction::cleanup_suggestion(&self.connection, &verified.vault_id, &local_device_id,
            &verified, &names, now_millis()?).ok().flatten();
        status.manager_device_id = verified.manager_device_id.clone();
        status.leave_address = self.leave_addresses(&verified)?.into_iter().next().unwrap_or_default();
        status.pending_transfer_to = verified.pending_transfer.clone().unwrap_or_default();
        status.transfer_accepted = verified.transfer_accepted;
        let local_progress = crate::lan_sync::progress(&self.connection, &verified.vault_id).ok();
        let reported: std::collections::BTreeMap<String, crate::progress::SyncProgress> = self
            .connection
            .prepare("SELECT peer_device_id, progress_json FROM sync_peer_progress WHERE vault_id = ?1")
            .and_then(|mut query| {
                query
                    .query_map([&verified.vault_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(peer, json)| Some((peer, crate::progress::SyncProgress::parse(json.as_bytes()).ok()?)))
            .collect();
        for member in verified.members.values() {
            let is_this_device = member.device_id == local_device_id;
            let is_manager = member.device_id == verified.manager_device_id;
            let name = self.member_name(&member.device_id).unwrap_or_else(|| {
                if is_this_device { "This PC".to_owned() } else { "Paired device".to_owned() }
            });
            let platform = if is_this_device || name.starts_with("Windows") {
                "windows"
            } else if is_manager || name.starts_with("Android") {
                "android"
            } else {
                "unknown"
            };
            status.devices.push(MemberRow {
                device_id: member.device_id.clone(),
                name,
                platform,
                status: if member.active { "active" } else { "removed" },
                is_manager,
                is_this_device,
                last_seen: if is_this_device { 0 } else { exit::peer_seen(&self.connection, &member.device_id)? },
                counts: match (&local_progress, is_this_device || !member.active) {
                    (Some(local), false) => exit::peer_counts(&local_device_id, &member.device_id, local, reported.get(&member.device_id)),
                    _ => exit::PeerCounts::default(),
                },
            });
        }
        Ok(status)
    }

    /// Leaves now and queues a signed `leave1` request for the managing phone (SPEC3 B).
    /// The request is signed with this device's identity before the local vault ID changes.
    pub fn leave_group(&mut self, keep_items: bool) -> Result<(), VaultError> {
        use crate::membership_exit::{self as exit, LeaveRequest, PendingLeave};
        if !self.is_enrolled()? {
            return Err(VaultError::NotSharing);
        }
        let verified = crate::membership::verify(&self.membership_events()?).map_err(|_| VaultError::NotSharing)?;
        let identity = self.identity_store.get_or_create()?;
        if verified.manager_device_id == identity.device_id {
            return Err(VaultError::ManagingDevice);
        }
        let secret: Vec<u8> = self.connection.query_row(
            "SELECT transport_secret FROM sync_group_state WHERE vault_id = ?1",
            [&verified.vault_id],
            |row| row.get(0),
        )?;
        // Read before the local leave deletes the saved routes.
        let address = self.leave_addresses(&verified)?.join(",");
        // The leave proof uses the transport secret of the current key epoch.
        let random = crate::epoch_keys::random_secrets_in(&self.connection, &verified.vault_id)?;
        let secret = crate::membership_exit::transport_epoch_secret(&secret, &verified.vault_id, verified.key_epoch, &random)
            .ok_or(VaultError::InvalidVaultKey)?
            .to_vec();
        let request = LeaveRequest {
            vault_id: verified.vault_id.clone(),
            device_id: identity.device_id.clone(),
            membership_head: verified.head.clone(),
            key_epoch: verified.key_epoch,
            created_at: now_millis()?,
        };
        let signature = self.identity_store.sign(&request.signing_bytes())?;
        // With Google Drive connected, the request also goes to Drive, sealed with the group's
        // cloud key while this PC still holds it. The managing phone finds it from anywhere.
        let root: Vec<u8> = self.connection.query_row(
            "SELECT transport_secret FROM sync_group_state WHERE vault_id = ?1", [&verified.vault_id], |row| row.get(0))?;
        let _ = crate::lan_sync::cloud::save_pending_leave(&self.connection, &Zeroizing::new(root), &verified.vault_id,
            &request, &signature);
        // Saved before the local leave, so a stop right after it still sends the request later.
        // A leave that fails withdraws it.
        exit::store_pending_leave(&self.connection, &PendingLeave {
            request,
            signature,
            transport_secret: Zeroizing::new(secret),
            address,
        })?;
        if let Err(error) = self.leave_locally(true) {
            let _ = exit::clear_pending_leave(&self.connection);
            crate::lan_sync::cloud::finish_pending_leave(&self.connection);
            return Err(error);
        }
        if !keep_items {
            self.clear_local_items()?;
        }
        Ok(())
    }

    /// Empties this vault after leaving so it can join another group with nothing to merge.
    /// The master password, Windows Hello and pending leave notice stay. The device identity is
    /// already a new one (`leave_locally`).
    /// Only for a vault that is no longer enrolled: other devices never see these deletions.
    fn clear_local_items(&mut self) -> Result<(), VaultError> {
        if self.is_enrolled()? {
            return Err(VaultError::InvalidEntry);
        }
        let transaction = self.connection.transaction()?;
        for table in [
            "entry_groups",
            "local_entry_photos",
            "local_entries",
            "local_note_details",
            "local_notes",
            "local_groups",
            "local_passkeys",
            "sync_conflicts",
            "sync_attachment_manifests",
            "sync_tombstones",
            "sync_device_heads",
            "sync_operations",
            "vault_records",
        ] {
            transaction.execute(&format!("DELETE FROM {table}"), [])?;
        }
        transaction.commit()?;
        let _ = self.blobs.remove_all();
        Ok(())
    }

    /// Applies a verified removal notice: leave locally even with open conflicts, keep items,
    /// and remember who removed this PC.
    ///
    /// Received changes that have not applied yet would be lost with the group's key, so first
    /// they are applied where possible, and the newest unapplied version of each entry or note goes
    /// to Recently deleted (`keep_unapplied`). When that can't be saved, this returns the error and
    /// the PC stays in the group; the next removal notice tries again.
    pub(crate) fn leave_after_removal(&mut self, by: &str, at: i64) -> Result<RemovalKept, VaultError> {
        let kept = self.keep_unapplied(at)?;
        self.leave_locally(false)?;
        crate::membership_exit::record_removed(&self.connection, by, at)?;
        crate::membership_exit::clear_pending_leave(&self.connection)?;
        if let Some(message) = kept.message() {
            crate::activity::log(crate::activity::Level::Warning, crate::activity::Category::Sync, message);
        }
        Ok(kept)
    }

    /// Received changes stored here but not applied, in each author's chain order.
    fn unapplied_received(&self) -> Result<Vec<ChangeRecord>, VaultError> {
        let mut query = self.connection.prepare(
            "SELECT o.format_version, o.vault_id, o.device_id, o.sequence, o.previous_hash, o.mutation_id, o.entity_type,
                    o.entity_id, o.kind, o.base_revision, o.record_version_json, o.occurred_at_utc, o.payload_ciphertext,
                    o.payload_nonce, o.device_signature, o.hash
             FROM sync_received_operations r CROSS JOIN sync_operations o ON o.mutation_id = r.mutation_id
             WHERE NOT EXISTS (SELECT 1 FROM sync_applied_operations a WHERE a.mutation_id = r.mutation_id)
               AND o.vault_id = (SELECT vault_id FROM local_sync_settings WHERE id = 1)
             ORDER BY o.device_id, o.sequence",
        )?;
        let rows = query.query_map([], |row| {
            let number = |index: usize| -> rusqlite::Result<u64> {
                let value: i64 = row.get(index)?;
                u64::try_from(value).map_err(|error| rusqlite::Error::FromSqlConversionFailure(
                    index, rusqlite::types::Type::Integer, Box::new(error)))
            };
            let kind: String = row.get(8)?;
            let version: String = row.get(10)?;
            Ok((ChangeRecord {
                format_version: row.get(0)?,
                vault_id: row.get(1)?,
                device_id: row.get(2)?,
                sequence: number(3)?,
                previous_hash: row.get(4)?,
                mutation_id: row.get(5)?,
                entity_type: row.get(6)?,
                entity_id: row.get(7)?,
                kind: if kind == "upsert" { ChangeKind::Upsert } else { ChangeKind::Delete },
                base_revision: number(9)?,
                record_version: RecordVersion::default(),
                occurred_at_utc: row.get(11)?,
                payload_ciphertext: row.get(12)?,
                payload_nonce: row.get(13)?,
                device_signature: row.get(14)?,
                hash: row.get(15)?,
            }, version))
        })?;
        let mut operations = Vec::new();
        for row in rows {
            let (mut operation, version) = row?;
            operation.record_version = serde_json::from_str(&version)?;
            operations.push(operation);
        }
        Ok(operations)
    }

    /// Before a forced leave (the Android counterpart is `LockedSyncStore.archiveUnapplied`):
    /// applies what it can, then keeps the newest unapplied version of each entry or note in
    /// Recently deleted, unless this PC already holds the same content. Other unapplied changes
    /// with data (folders, passkeys, photos) can't be kept there; they are counted. Their authors
    /// still hold them, and deletes need nothing.
    fn keep_unapplied(&mut self, now: i64) -> Result<RemovalKept, VaultError> {
        let Some(key) = self.sync_content_key()? else {
            return Ok(RemovalKept::default());
        };
        // Apply what can apply now. Each change applies in its own transaction; one that fails
        // (it waits for something, or can't be read) is left for the archive below.
        let blobs = self.blobs.clone();
        loop {
            let mut advanced = false;
            for operation in self.unapplied_received()? {
                if crate::incoming_apply::IncomingApply::apply_with_blobs(&mut self.connection, &operation, &*key, Some(&blobs)).is_ok() {
                    advanced = true;
                }
            }
            if !advanced {
                break;
            }
        }
        let remaining = self.unapplied_received()?;
        let other_changes = remaining.iter()
            .filter(|operation| operation.kind == ChangeKind::Upsert
                && matches!(operation.entity_type.as_str(), "group" | "passkey" | "photo" | "photo_cover"))
            .count();
        // The newest version of each entry, by change time, then author and sequence.
        let mut newest: BTreeMap<String, &ChangeRecord> = BTreeMap::new();
        for operation in remaining.iter().filter(|o| o.entity_type == "entry" && o.kind == ChangeKind::Upsert) {
            let order = |o: &ChangeRecord| (o.occurred_at_utc.clone(), o.device_id.clone(), o.sequence);
            if newest.get(&operation.entity_id).map_or(true, |known| order(operation) > order(known)) {
                newest.insert(operation.entity_id.clone(), operation);
            }
        }
        let mut copies = Vec::new();
        for operation in newest.values() {
            let Ok(plaintext) = payload::decrypt(&*key, operation) else { continue };
            let plaintext = Zeroizing::new(plaintext);
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&plaintext) else { continue };
            let entry = &value["entry"];
            let (Some(item_type), Some(title)) = (entry["type"].as_str(), entry["title"].as_str()) else { continue };
            let group_ids: Vec<String> = value["groupIds"].as_array().map(|ids| {
                ids.iter().filter_map(|id| id.as_str().map(str::to_owned)).collect()
            }).unwrap_or_default();
            let (kind, data) = if item_type == "NOTE" {
                ("note", serde_json::json!({"title": title, "body": entry["notes"].as_str().unwrap_or_default()}))
            } else {
                ("entry", entry.clone())
            };
            if self.holds_same(&operation.entity_id, kind, &data)? {
                continue;
            }
            copies.push((format!("unapplied-{}", operation.hash), operation.entity_id.clone(), kind, item_type.to_owned(),
                title.to_owned(), data, group_ids));
        }
        let transaction = self.connection.transaction()?;
        for (trash_id, item_id, kind, item_type, title, data, group_ids) in &copies {
            crate::local_recovery::keep_removal_copy(&transaction, trash_id, item_id, kind, item_type, title, data,
                group_ids, now)?;
        }
        transaction.commit()?;
        Ok(RemovalKept { kept_entries: copies.len(), other_changes })
    }

    /// True when this PC holds the item `id` with exactly this content.
    fn holds_same(&self, id: &str, kind: &str, data: &serde_json::Value) -> Result<bool, VaultError> {
        if kind == "note" {
            let note: Option<(String, String)> = self.connection
                .query_row("SELECT title, body FROM local_notes WHERE id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()?;
            return Ok(note.is_some_and(|(title, body)| data["title"] == title.as_str() && data["body"] == body.as_str()));
        }
        let stored: Option<String> = self.connection
            .query_row("SELECT data_json FROM local_entries WHERE id = ?1", [id], |row| row.get(0))
            .optional()?;
        Ok(stored.and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok()).as_ref() == Some(data))
    }

    pub(crate) fn stored_membership(&self) -> Result<Vec<crate::membership::MembershipEvent>, VaultError> {
        self.membership_events()
    }

    pub(crate) fn display_name_of(&self, device_id: &str) -> Option<String> {
        self.member_name(device_id)
    }

    pub fn dismiss_removed_notice(&self) -> Result<(), VaultError> {
        crate::membership_exit::dismiss_removed(&self.connection)?;
        Ok(())
    }

    /// Where a leave request goes, in order: the typed phone address, the managing device's last
    /// confirmed route, then the other paired devices' routes (a device that is not the manager
    /// answers `notmanager1`). Android retries on discovered and saved addresses the same way.
    fn leave_addresses(&self, verified: &crate::membership::VerifiedMembership) -> Result<Vec<String>, VaultError> {
        let typed: String = self
            .connection
            .query_row("SELECT phone_address FROM sync_exchange_state WHERE vault_id = ?1", [&verified.vault_id], |row| row.get(0))
            .optional()?
            .unwrap_or_default();
        let saved: Vec<(String, String)> = self
            .connection
            .prepare("SELECT peer_device_id, address FROM sync_peer_endpoints WHERE vault_id = ?1 ORDER BY peer_device_id")?
            .query_map([&verified.vault_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut addresses: Vec<String> = Vec::new();
        let manager = saved.iter().filter(|(peer, _)| *peer == verified.manager_device_id);
        let others = saved.iter().filter(|(peer, _)| *peer != verified.manager_device_id);
        for address in std::iter::once(&typed).chain(manager.chain(others).map(|(_, address)| address)) {
            let address = address.trim();
            if !address.is_empty() && !address.contains(',') && !addresses.iter().any(|known| known == address) {
                addresses.push(address.to_owned());
            }
        }
        addresses.truncate(8);
        Ok(addresses)
    }

    pub(crate) fn pending_leave(&self) -> Result<Option<crate::membership_exit::PendingLeave>, VaultError> {
        Ok(crate::membership_exit::pending_leave(&self.connection, now_millis()?)?)
    }

    pub(crate) fn claim_leave_attempt(&self, min_gap_millis: i64) -> Result<bool, VaultError> {
        Ok(crate::membership_exit::claim_leave_attempt(&self.connection, now_millis()?, min_gap_millis)?)
    }

    pub(crate) fn record_peer_seen(&self, device_id: &str) -> Result<(), VaultError> {
        crate::membership_exit::record_peer_seen(&self.connection, device_id, now_millis()?)?;
        Ok(())
    }

    pub(crate) fn finish_pending_leave(&self) -> Result<(), VaultError> {
        crate::membership_exit::clear_pending_leave(&self.connection)?;
        Ok(())
    }

    /// After a join: drops a pending leave request (Wi-Fi and Google Drive copy) that the joined
    /// identity signed itself, so the manager can't remove this PC again when it arrives. A request
    /// from an earlier, retired identity stays and removes that old entry.
    pub(crate) fn forget_own_pending_leave(&self) -> Result<bool, VaultError> {
        if !self.identity_store.exists() {
            return Ok(false);
        }
        let device_id = self.identity_store.get_or_create()?.device_id;
        let cleared = crate::membership_exit::clear_pending_leave_of(&self.connection, &device_id, now_millis()?)?;
        if cleared {
            crate::lan_sync::cloud::finish_pending_leave(&self.connection);
        }
        Ok(cleared)
    }

    pub fn list_conflicts(&self) -> Result<Vec<crate::conflicts::SyncConflict>, crate::conflicts::ConflictError> {
        let Some(key) = self.sync_content_key().map_err(|_| crate::conflicts::ConflictError::Data)? else {
            return Ok(Vec::new());
        };
        crate::conflicts::list(&self.connection, &*key)
    }

    /// Records the chosen side as a signed change by this device (see `conflicts.rs`).
    pub fn resolve_conflict(&mut self, id: &str, keep_remote: bool) -> Result<(), crate::conflicts::ConflictError> {
        use crate::conflicts::ConflictError;
        let key = self.sync_content_key().map_err(|_| ConflictError::Data)?.ok_or(ConflictError::NotFound)?;
        let device = self.identity_store.get_or_create().map_err(|_| ConflictError::Data)?;
        let identity = &self.identity_store;
        crate::conflicts::resolve(&mut self.connection, id, keep_remote, &*key, &device.device_id,
            Some(&self.blobs), |bytes| identity.sign(bytes))?;
        Ok(())
    }

    /// Photo uploads received from another device whose blob has not arrived yet.
    pub fn photos_waiting_for_data(&self) -> Result<usize, VaultError> {
        Ok(self.waiting_photo_blobs()?.into_iter().filter(|(hash, size)| !self.blobs.has(hash, *size)).count())
    }

    pub(crate) fn photo_blobs(&self) -> PhotoBlobs {
        self.blobs.clone()
    }

    /// The shared content key when this vault is in a sync group.
    pub(crate) fn sync_content_key(&self) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
        let key: Option<Vec<u8>> = self
            .connection
            .query_row("SELECT content_key FROM sync_group_state", [], |row| row.get(0))
            .optional()?;
        key.map(|key| key.try_into().map(Zeroizing::new).map_err(|_| VaultError::InvalidVaultKey))
            .transpose()
    }

    /// The blob is sealed with the newest content key (`epoch_keys.rs`); its payload names that epoch.
    fn create_photo_blob(&self, photo_id: &str, data: &[u8]) -> Result<(String, u64, u64), VaultError> {
        let key = self.sync_content_key()?.ok_or(VaultError::NotSharing)?;
        let vault_id: String =
            self.connection
                .query_row("SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get(0))?;
        let (epoch, key) = match crate::epoch_keys::write_key_in(&self.connection, &vault_id)? {
            Some((epoch, newer)) => (epoch, newer),
            None => (1, key),
        };
        let (hash, size) = self.blobs
            .create(&*key, &vault_id, photo_id, data)
            .map_err(|_| VaultError::InvalidPhoto)?;
        Ok((hash, size, epoch))
    }

    /// Publishes photos that have never been part of the signed history (added before pairing or
    /// migrated into the group). Photos that came from another device already have operations.
    pub(crate) fn publish_unsynced_photos(&mut self) -> Result<usize, VaultError> {
        if !self.is_enrolled()? {
            return Ok(0);
        }
        let photos: Vec<(String, String, bool, i64)> = self
            .connection
            .prepare(
                "SELECT p.id, p.entry_id, p.is_cover, p.added_at FROM local_entry_photos p
                 WHERE EXISTS (SELECT 1 FROM local_entries e WHERE e.id = p.entry_id)
                   AND NOT EXISTS (SELECT 1 FROM vault_records r WHERE r.entity_type = 'photo' AND r.entity_id = p.id)
                   AND NOT EXISTS (SELECT 1 FROM sync_operations o WHERE o.entity_type = 'photo' AND o.entity_id = p.id)
                   AND NOT EXISTS (SELECT 1 FROM sync_tombstones t WHERE t.entity_type = 'photo' AND t.entity_id = p.id)
                 ORDER BY p.added_at, p.id",
            )?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let mut published = 0;
        for (photo_id, entry_id, is_cover, added_at) in photos {
            let data: Zeroizing<Vec<u8>> = Zeroizing::new(self.connection.query_row(
                "SELECT data FROM local_entry_photos WHERE id = ?1",
                [&photo_id],
                |row| row.get(0),
            )?);
            let (hash, size, epoch) = self.create_photo_blob(&photo_id, &data)?;
            let added_at = if added_at > 0 { added_at } else { now_millis()? };
            let payload = photo_payload(&photo_id, &entry_id, is_cover, added_at, &hash, size, epoch);
            let (id, owner) = (photo_id.clone(), entry_id.clone());
            self.write_change("photo", &photo_id, ChangeKind::Upsert, payload, move |transaction| {
                transaction.execute("UPDATE local_entry_photos SET added_at = ?2 WHERE id = ?1", params![id, added_at])?;
                insert_manifest(transaction, &id, &owner, &hash, size)
            })?;
            published += 1;
        }
        Ok(published)
    }

    /// Blob references of received photo uploads that are not applied yet.
    pub(crate) fn waiting_photo_blobs(&self) -> Result<Vec<(String, u64)>, VaultError> {
        let Some(key) = self.sync_content_key()? else {
            return Ok(Vec::new());
        };
        let rows: Vec<(String, String, String, String, String, String)> = self
            .connection
            .prepare(
                "SELECT o.vault_id, o.mutation_id, o.entity_id, o.payload_ciphertext, o.payload_nonce, o.hash
                 FROM sync_operations o
                 JOIN sync_received_operations r ON r.mutation_id = o.mutation_id
                 LEFT JOIN sync_applied_operations a ON a.mutation_id = o.mutation_id
                 WHERE a.mutation_id IS NULL AND o.entity_type = 'photo' AND o.kind = 'upsert'
                 ORDER BY o.device_id, o.sequence",
            )?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)))?
            .collect::<Result<_, _>>()?;
        let mut refs = Vec::new();
        for (vault_id, mutation_id, entity_id, ciphertext, nonce, hash) in rows {
            let operation = ChangeRecord::create(
                vault_id, "", 1, GENESIS_HASH, mutation_id, "photo", entity_id, ChangeKind::Upsert, 0,
                RecordVersion::default(), "", ciphertext, nonce, "",
            );
            let _ = hash;
            let Ok(plaintext) = payload::decrypt(&*key, &operation) else { continue };
            let plaintext = Zeroizing::new(plaintext);
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&plaintext) else { continue };
            let (Some(blob), Some(size)) = (value["photo"]["blobHash"].as_str(), value["photo"]["blobSize"].as_u64()) else { continue };
            // The image of a photo whose entry is deleted is never shown here; do not ask for it.
            if crate::incoming_apply::entry_deleted(&self.connection, value["photo"]["entryId"].as_str().unwrap_or_default())? {
                continue;
            }
            if crate::photo_blobs::valid_hash(blob) && crate::photo_blobs::valid_size(size)
                && !refs.iter().any(|(known, _)| known == blob)
            {
                refs.push((blob.to_owned(), size));
            }
        }
        Ok(refs)
    }

    /// Removes photos whose entry is gone, but never while a change for that entry still waits,
    /// then drops manifests and blob files nothing refers to. Local work only.
    pub(crate) fn sweep_orphan_photos(&mut self) -> Result<usize, VaultError> {
        let removed = self.connection.execute(
            "DELETE FROM local_entry_photos
             WHERE NOT EXISTS (SELECT 1 FROM local_entries e WHERE e.id = local_entry_photos.entry_id)
               AND NOT EXISTS (SELECT 1 FROM local_notes n WHERE n.id = local_entry_photos.entry_id)
               AND NOT EXISTS (
                   SELECT 1 FROM sync_operations o
                   JOIN sync_received_operations r ON r.mutation_id = o.mutation_id
                   LEFT JOIN sync_applied_operations a ON a.mutation_id = o.mutation_id
                   WHERE a.mutation_id IS NULL AND o.entity_type = 'entry'
                     AND o.entity_id = local_entry_photos.entry_id)",
            [],
        )?;
        self.connection.execute(
            "DELETE FROM sync_attachment_manifests
             WHERE NOT EXISTS (SELECT 1 FROM local_entry_photos p WHERE p.id = sync_attachment_manifests.attachment_id)",
            [],
        )?;
        let keep: std::collections::HashSet<String> = self
            .connection
            .prepare("SELECT ciphertext_hash FROM sync_attachment_manifests")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        let pending: std::collections::HashSet<String> =
            self.waiting_photo_blobs()?.into_iter().map(|(hash, _)| hash).collect();
        let _ = self.blobs.prune(&keep, &pending);
        Ok(removed)
    }

    fn require_entry(&self, entry_id: &str) -> Result<(), VaultError> {
        self.connection
            .query_row(
                "SELECT 1 FROM local_entries WHERE id = ?1",
                [entry_id],
                |_| Ok(()),
            )
            .optional()?
            .ok_or(VaultError::EntryNotFound)?;
        Ok(())
    }

    fn group_ids(&self, entry_id: &str) -> Result<Vec<String>, VaultError> {
        let mut statement = self
            .connection
            .prepare("SELECT group_id FROM entry_groups WHERE entry_id = ?1 ORDER BY group_id")?;
        Ok(statement
            .query_map([entry_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?)
    }

    pub fn list_groups(&self) -> Result<Vec<LocalGroup>, VaultError> {
        let mut statement = self
            .connection
            .prepare("SELECT id, name, notes, folder_type FROM local_groups ORDER BY name, id")?;
        Ok(statement
            .query_map([], |row| {
                Ok(LocalGroup {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    notes: row.get(2)?,
                    folder_type: row.get(3)?,
                })
            })?
            .collect::<Result<_, _>>()?)
    }

    pub fn save_group(
        &mut self,
        id: Option<&str>,
        name: &str,
        notes: &str,
        folder_type: &str,
    ) -> Result<LocalGroup, VaultError> {
        let name = name.trim();
        let notes = notes.trim();
        if name.is_empty()
            || name.len() > 500
            || notes.len() > 1_048_576
            || !matches!(
                folder_type,
                "" | "CARD" | "PASSWORD" | "QUESTION" | "NOTE" | "AUTHENTICATOR" | "AUTOFILL"
            )
        {
            return Err(VaultError::InvalidGroup);
        }
        let id = if let Some(id) = id {
            if self
                .connection
                .query_row("SELECT 1 FROM local_groups WHERE id = ?1", [id], |_| Ok(()))
                .optional()?
                .is_none()
            {
                return Err(VaultError::GroupNotFound);
            }
            if !folder_type.is_empty() {
                let mismatched: i64 = self.connection.query_row(
                    "SELECT count(*) FROM entry_groups links LEFT JOIN local_entries entries ON entries.id = links.entry_id
                     WHERE links.group_id = ?1 AND COALESCE(entries.type, 'NOTE') != ?2",
                    params![id, folder_type], |row| row.get(0)
                )?;
                if mismatched > 0 {
                    return Err(VaultError::InvalidGroup);
                }
            }
            id.to_owned()
        } else {
            Uuid::new_v4().to_string()
        };
        let group = LocalGroup {
            id: id.clone(),
            name: name.to_owned(),
            notes: notes.to_owned(),
            folder_type: folder_type.to_owned(),
        };
        let payload = serde_json::json!({"group": group});
        self.write_change("group", &id, ChangeKind::Upsert, payload, |transaction| {
            transaction.execute("INSERT INTO local_groups (id, name, notes, folder_type) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(id) DO UPDATE SET name = excluded.name, notes = excluded.notes, folder_type = excluded.folder_type",
                params![id, name, notes, folder_type])?;
            Ok(())
        })?;
        Ok(group)
    }

    pub fn delete_group(&mut self, id: &str) -> Result<(), VaultError> {
        if self
            .connection
            .query_row("SELECT 1 FROM local_groups WHERE id = ?1", [id], |_| Ok(()))
            .optional()?
            .is_none()
        {
            return Err(VaultError::GroupNotFound);
        }
        self.write_change(
            "group",
            id,
            ChangeKind::Delete,
            serde_json::json!({"deleted": true}),
            |transaction| {
                transaction.execute("DELETE FROM entry_groups WHERE group_id = ?1", [id])?;
                transaction.execute("DELETE FROM local_groups WHERE id = ?1", [id])?;
                Ok(())
            },
        )
    }

    pub fn list_passkeys(&self) -> Result<Vec<PasskeySummary>, VaultError> {
        let mut statement = self
            .connection
            .prepare("SELECT data_json FROM local_passkeys ORDER BY rp_id, id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let key: VaultPasskey = serde_json::from_str(&row?)?;
            Ok(PasskeySummary {
                id: key.id,
                rp_id: key.rp_id,
                username: key.username,
                display_name: key.display_name,
                created_at: key.created_at,
            })
        })
        .collect()
    }

    /// Every passkey with its key material, for the Windows passkey provider. Never sent to the UI.
    pub(crate) fn passkey_records(&self) -> Result<Vec<VaultPasskey>, VaultError> {
        let mut statement = self
            .connection
            .prepare("SELECT data_json FROM local_passkeys ORDER BY rp_id, id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    pub fn save_passkey(&mut self, passkey: VaultPasskey) -> Result<(), VaultError> {
        passkey.validate()?;
        if self
            .connection
            .query_row(
                "SELECT 1 FROM local_passkeys WHERE id = ?1",
                [&passkey.id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(VaultError::PasskeyAlreadyExists);
        }
        let id = passkey.id.clone();
        let rp_id = passkey.rp_id.clone();
        let data = serde_json::to_string(&passkey)?;
        self.write_change(
            "passkey",
            &id,
            ChangeKind::Upsert,
            serde_json::json!({"passkey": passkey}),
            |transaction| {
                transaction.execute(
                    "INSERT INTO local_passkeys (id, rp_id, data_json) VALUES (?1, ?2, ?3)",
                    params![id, rp_id, data],
                )?;
                Ok(())
            },
        )
    }

    pub fn delete_passkey(&mut self, id: &str) -> Result<(), VaultError> {
        self.connection
            .query_row("SELECT 1 FROM local_passkeys WHERE id = ?1", [id], |_| {
                Ok(())
            })
            .optional()?
            .ok_or(VaultError::PasskeyNotFound)?;
        self.write_change(
            "passkey",
            id,
            ChangeKind::Delete,
            serde_json::json!({"deleted": true}),
            |transaction| {
                transaction.execute("DELETE FROM local_passkeys WHERE id = ?1", [id])?;
                Ok(())
            },
        )
    }

    pub fn matching_logins(
        &self,
        origin: &str,
    ) -> Result<Vec<(String, String, String)>, VaultError> {
        if browser::canonical_https_origin(origin).is_none() {
            return Ok(Vec::new());
        }
        Ok(self
            .list_entries()?
            .into_iter()
            .filter_map(|entry| {
                if entry["type"] != "PASSWORD"
                    || !browser::login_url_matches_origin(entry["tertiaryValue"].as_str()?, origin)
                {
                    return None;
                }
                Some((
                    entry["id"].as_str()?.to_owned(),
                    entry["title"].as_str()?.to_owned(),
                    entry["primaryValue"].as_str()?.to_owned(),
                ))
            })
            .collect())
    }

    /// Logins saved for the other of a bare site and its "www." name ("related_logins", see
    /// `browser::login_url_same_site`), for listing and filling
    /// only. Saving and updating stay tied to the exact origin (`matching_logins`).
    pub fn related_logins(&self, origin: &str) -> Result<Vec<(String, String, String)>, VaultError> {
        if browser::canonical_https_origin(origin).is_none() {
            return Ok(Vec::new());
        }
        Ok(self
            .list_entries()?
            .into_iter()
            .filter_map(|entry| {
                if entry["type"] != "PASSWORD" || !browser::login_url_same_site(entry["tertiaryValue"].as_str()?, origin) {
                    return None;
                }
                Some((
                    entry["id"].as_str()?.to_owned(),
                    entry["title"].as_str()?.to_owned(),
                    entry["primaryValue"].as_str()?.to_owned(),
                ))
            })
            .collect())
    }

    /// A login the browser may fill on `origin`: saved for that origin or a related page of it.
    pub fn fillable_login(&self, id: &str, origin: &str) -> Result<Option<(String, String)>, VaultError> {
        if let Some(login) = self.selected_login(id, origin)? {
            return Ok(Some(login));
        }
        let related = self.related_logins(origin)?.into_iter().any(|(related, _, _)| related == id);
        if !related {
            return Ok(None);
        }
        let stored: String = self
            .connection
            .query_row("SELECT data_json FROM local_entries WHERE id = ?1 AND type = 'PASSWORD'", [id], |row| row.get(0))?;
        let entry: serde_json::Value = serde_json::from_str(&stored)?;
        Ok(Some((
            entry["primaryValue"].as_str().unwrap_or("").to_owned(),
            entry["secondaryValue"].as_str().unwrap_or("").to_owned(),
        )))
    }

    pub fn selected_login(
        &self,
        id: &str,
        origin: &str,
    ) -> Result<Option<(String, String)>, VaultError> {
        if browser::canonical_https_origin(origin).is_none() {
            return Ok(None);
        }
        let stored: Option<String> = self
            .connection
            .query_row(
                "SELECT data_json FROM local_entries WHERE id = ?1 AND type = 'PASSWORD'",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        let entry: serde_json::Value = serde_json::from_str(&stored)?;
        if !browser::login_url_matches_origin(entry["tertiaryValue"].as_str().unwrap_or(""), origin)
        {
            return Ok(None);
        }
        Ok(Some((
            entry["primaryValue"].as_str().unwrap_or("").to_owned(),
            entry["secondaryValue"].as_str().unwrap_or("").to_owned(),
        )))
    }

    /// "passkey_mark": the ids of the logins that have a passkey for the same account
    /// (`browser::passkey_matches_login`). The app and the browser show a passkey mark on them.
    pub fn logins_with_passkeys(&self) -> Result<std::collections::HashSet<String>, VaultError> {
        let passkeys = self.list_passkeys()?;
        if passkeys.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        Ok(self
            .list_entries()?
            .into_iter()
            .filter_map(|entry| {
                if entry["type"] != "PASSWORD" {
                    return None;
                }
                let username = entry["primaryValue"].as_str().unwrap_or("");
                // The saved website and the origins linked on Android, one per line (as `savedLoginOrigins`).
                let websites: Vec<&str> = std::iter::once(entry["tertiaryValue"].as_str().unwrap_or(""))
                    .chain(entry["autofillOrigins"].as_str().unwrap_or("").lines())
                    .collect();
                passkeys
                    .iter()
                    .any(|passkey| websites.iter().any(|url| browser::passkey_matches_login(&passkey.rp_id, &passkey.username, url, username)))
                    .then(|| entry["id"].as_str().map(str::to_owned))
                    .flatten()
            })
            .collect())
    }

    /// "all_logins": every login as (id, title, username, the host of its saved website or ""),
    /// by title. For the browser's "Search all logins", where the user picks one for any site.
    pub fn all_logins(&self) -> Result<Vec<(String, String, String, String)>, VaultError> {
        let mut logins: Vec<_> = self
            .list_entries()?
            .into_iter()
            .filter_map(|entry| {
                if entry["type"] != "PASSWORD" {
                    return None;
                }
                let site = entry["tertiaryValue"].as_str().map(browser::login_site_label).unwrap_or_default();
                Some((
                    entry["id"].as_str()?.to_owned(),
                    entry["title"].as_str().unwrap_or("").to_owned(),
                    entry["primaryValue"].as_str().unwrap_or("").to_owned(),
                    site,
                ))
            })
            .collect();
        logins.sort_by_cached_key(|(_, title, username, _)| (title.to_lowercase(), username.to_lowercase()));
        Ok(logins)
    }

    /// "all_logins": the username and password of a login the user chose, whatever site it is saved for.
    pub fn any_login(&self, id: &str) -> Result<Option<(String, String)>, VaultError> {
        let stored: Option<String> = self
            .connection
            .query_row("SELECT data_json FROM local_entries WHERE id = ?1 AND type = 'PASSWORD'", [id], |row| row.get(0))
            .optional()?;
        let Some(stored) = stored else { return Ok(None) };
        let entry: serde_json::Value = serde_json::from_str(&stored)?;
        Ok(Some((
            entry["primaryValue"].as_str().unwrap_or("").to_owned(),
            entry["secondaryValue"].as_str().unwrap_or("").to_owned(),
        )))
    }

    /// Saves a login captured in the browser. `username` may be empty for a password-only form.
    /// `title` follows Android `newLoginTitle`: the trimmed request, else the origin without `https://`.
    pub fn save_new_browser_login(
        &mut self,
        origin: &str,
        username: &str,
        password: &str,
        title: Option<&str>,
    ) -> Result<bool, VaultError> {
        if title.is_some_and(|title| !browser::valid_login_title(title)) {
            return Err(VaultError::InvalidEntry);
        }
        if !self.review_browser_login(origin, username, password)? { return Ok(false); }
        let title = browser::new_login_title(title, origin);
        self.save_entry(serde_json::json!({
            "type": "PASSWORD", "title": title, "primaryValue": username,
            "secondaryValue": password, "tertiaryValue": origin
        }))?;
        Ok(true)
    }

    pub fn review_browser_login(&self, origin: &str, username: &str, password: &str) -> Result<bool, VaultError> {
        if browser::canonical_https_origin(origin).as_deref() != Some(origin)
            || !browser::valid_capture_username(username)
            || password.is_empty()
            || password.len() > 4096
        {
            return Err(VaultError::InvalidEntry);
        }
        // Only logins for this origin with exactly this username match; an empty username
        // matches only saved logins whose username is empty too.
        let mut conflict = false;
        for (id, _, saved_username) in self.matching_logins(origin)? {
            if saved_username == username {
                let (_, mut saved_password) = self
                    .selected_login(&id, origin)?
                    .ok_or(VaultError::BrowserLoginConflict)?;
                let unchanged = saved_password == password;
                saved_password.zeroize();
                if unchanged {
                    return Ok(false);
                }
                conflict = true;
            }
        }
        if conflict {
            return Err(VaultError::BrowserLoginConflict);
        }
        Ok(true)
    }

    pub fn update_browser_login(&mut self, origin: &str, id: &str, username: &str, password: &str, expected_hash: &[u8; 32]) -> Result<(), VaultError> {
        use sha2::{Digest, Sha256};
        if !browser::valid_capture_username(username) || password.is_empty() || password.len() > 4096 {
            return Err(VaultError::InvalidEntry);
        }
        let (saved_username, mut saved_password) = self.selected_login(id, origin)?.ok_or(VaultError::BrowserLoginConflict)?;
        let hash: [u8; 32] = Sha256::digest(saved_password.as_bytes()).into();
        saved_password.zeroize();
        if saved_username != username || &hash != expected_hash { return Err(VaultError::BrowserLoginConflict); }
        let mut entry = self.list_entries()?.into_iter().find(|entry| entry["id"].as_str() == Some(id)).ok_or(VaultError::EntryNotFound)?;
        entry["secondaryValue"] = serde_json::Value::String(password.into());
        self.save_entry(entry)?;
        Ok(())
    }

    fn entry_of_type(&self, id: &str, entry_type: &str) -> Result<Option<serde_json::Value>, VaultError> {
        let stored: Option<String> = self
            .connection
            .query_row(
                "SELECT data_json FROM local_entries WHERE id = ?1 AND type = ?2",
                [id, entry_type],
                |row| row.get(0),
            )
            .optional()?;
        stored.map(|stored| serde_json::from_str(&stored).map_err(VaultError::from)).transpose()
    }

    fn entries_of_type(&self, entry_type: &str) -> Result<Vec<serde_json::Value>, VaultError> {
        Ok(self.list_entries()?.into_iter().filter(|entry| entry["type"] == entry_type).collect())
    }

    /// "cards": every card as (id, title, "Visa •••• 1111 · 12/27"). Cards are not tied to a site.
    /// (id, title, "Visa · •••• 1111 · 08/29", color). Never more of the number than its last four digits.
    pub fn browser_cards(&self) -> Result<Vec<(String, String, String, Option<u64>)>, VaultError> {
        Ok(self.entries_of_type("CARD")?.iter().filter_map(|entry| {
            let digits = browser::card_digits(entry["primaryValue"].as_str()?);
            let last4 = digits.get(digits.len().saturating_sub(4)..).unwrap_or("");
            let network = entry["network"].as_str().filter(|network| !network.trim().is_empty())
                .map(str::to_owned).unwrap_or_else(|| browser::card_network(&digits).to_owned());
            let expiry = entry["tertiaryValue"].as_str().unwrap_or("");
            let label = [if network.is_empty() { "Card".to_owned() } else { network }, format!("•••• {last4}"), expiry.to_owned()]
                .into_iter().filter(|part| !part.trim().is_empty()).collect::<Vec<_>>().join(" · ");
            Some((entry["id"].as_str()?.to_owned(), entry["title"].as_str().unwrap_or("").to_owned(), label,
                entry["color"].as_u64().filter(|color| *color <= 0xFFFF_FFFF)))
        }).collect())
    }

    /// One card's fields, including its security code (the caller decides whether to release it).
    pub fn browser_card(&self, id: &str) -> Result<Option<browser::CardDetails>, VaultError> {
        let Some(entry) = self.entry_of_type(id, "CARD")? else { return Ok(None) };
        let text = |field: &str| entry[field].as_str().unwrap_or("").to_owned();
        let number = browser::card_digits(&text("primaryValue"));
        let expiry = browser::normalize_expiry(&text("tertiaryValue")).unwrap_or_default();
        let network = Some(text("network")).filter(|network| !network.trim().is_empty())
            .unwrap_or_else(|| browser::card_network(&number).to_owned());
        Ok(Some(browser::CardDetails {
            name: text("secondaryValue"), expiry, cvv: browser::card_digits(&text("fourthValue")), network, number,
        }))
    }

    /// "profiles": every contact profile as (id, title, "Name · email").
    /// "profiles": (id, title, "name · email · city", the values) for each address.
    pub fn browser_profiles(&self) -> Result<Vec<(String, String, String, browser::ProfileDetails)>, VaultError> {
        Ok(self.entries_of_type("AUTOFILL")?.iter().filter_map(|entry| {
            let profile = profile_of(entry);
            let label = [&profile.name, &profile.email, &profile.city].into_iter()
                .filter(|part| !part.trim().is_empty()).cloned().collect::<Vec<_>>().join(" · ");
            Some((entry["id"].as_str()?.to_owned(), entry["title"].as_str().unwrap_or("").to_owned(), label, profile))
        }).collect())
    }

    pub fn browser_profile(&self, id: &str) -> Result<Option<browser::ProfileDetails>, VaultError> {
        Ok(self.entry_of_type(id, "AUTOFILL")?.map(|entry| profile_of(&entry)))
    }

    /// "codes": authenticator codes as (id, service, account). Without `all`, only codes whose
    /// service names the site, whose site list includes it, or whose account is a login saved for
    /// it. Matches come first either way.
    pub fn browser_codes(&self, origin: &str, all: bool) -> Result<Vec<(String, String, String)>, VaultError> {
        let label = site_label(origin);
        let usernames: Vec<String> = self.matching_logins(origin)?.into_iter()
            .map(|(_, _, username)| username.trim().to_lowercase()).filter(|name| !name.is_empty()).collect();
        let mut codes: Vec<(bool, String, String, String)> = self.entries_of_type("AUTHENTICATOR")?.iter().filter_map(|entry| {
            let title = entry["title"].as_str().unwrap_or("").to_owned();
            let account = entry["primaryValue"].as_str().unwrap_or("").to_owned();
            let service = squash(&title);
            let named = label.as_deref().is_some_and(|label| {
                (label.len() >= 3 && service.contains(label)) || (service.len() >= 4 && label.contains(&service))
            });
            let listed = entry["autofillOrigins"].as_str().unwrap_or("")
                .split([',', ' ', '\n']).any(|site| browser::stored_login_origin(site.trim()).as_deref() == Some(origin));
            let same_account = !account.trim().is_empty() && usernames.contains(&account.trim().to_lowercase());
            let matched = named || listed || same_account;
            (matched || all).then(|| Some((matched, entry["id"].as_str()?.to_owned(), title, account)))?
        }).collect();
        codes.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.2.to_lowercase().cmp(&right.2.to_lowercase())));
        Ok(codes.into_iter().map(|(_, id, title, account)| (id, title, account)).collect())
    }

    /// The current code for one authenticator item.
    pub fn browser_code(&self, id: &str, unix_seconds: u64) -> Result<Option<browser::CodeValue>, VaultError> {
        let Some(entry) = self.entry_of_type(id, "AUTHENTICATOR")? else { return Ok(None) };
        let mut secret = Zeroizing::new(entry["secondaryValue"].as_str().unwrap_or("").to_owned());
        let digits = entry["totpDigits"].as_u64().unwrap_or(6) as u32;
        let period = entry["totpPeriod"].as_u64().unwrap_or(30);
        let algorithm = entry["totpAlgorithm"].as_str().unwrap_or("SHA1");
        let code = crate::totp::code_at(&secret, algorithm, digits, period, unix_seconds);
        secret.zeroize();
        Ok(code.map(|(value, seconds_left)| browser::CodeValue { value, seconds_left }))
    }

    /// "save_details": true when a captured card or address is not in the vault yet. A card
    /// matches by number; an address matches when a saved profile has every captured value.
    pub fn review_browser_details(&self, pending: &browser::PendingDetails) -> Result<bool, VaultError> {
        match (pending.kind, &pending.card, &pending.profile) {
            (browser::ItemKind::Card, Some(card), None) if browser::valid_card_capture(card) => {
                Ok(!self.entries_of_type("CARD")?.iter()
                    .any(|entry| browser::card_digits(entry["primaryValue"].as_str().unwrap_or("")) == card.number))
            }
            (browser::ItemKind::Profile, None, Some(profile)) if browser::valid_profile_capture(profile) => {
                let same = |saved: &str, captured: &str| saved.trim().eq_ignore_ascii_case(captured.trim());
                Ok(!self.entries_of_type("AUTOFILL")?.iter().any(|entry| {
                    let saved = profile_of(entry);
                    saved.fields().iter().zip(profile.fields()).all(|(saved, captured)| captured.trim().is_empty() || same(saved, captured))
                }))
            }
            _ => Err(VaultError::InvalidEntry),
        }
    }

    /// Saves a captured card or address as a new item. Returns false when it is already saved.
    pub fn save_browser_details(&mut self, pending: &browser::PendingDetails, title: Option<&str>) -> Result<bool, VaultError> {
        if title.is_some_and(|title| !browser::valid_login_title(title)) {
            return Err(VaultError::InvalidEntry);
        }
        if !self.review_browser_details(pending)? {
            return Ok(false);
        }
        let requested = title.map(str::trim).filter(|title| !title.is_empty()).map(|title| title.chars().take(200).collect::<String>());
        let draft = if let Some(card) = &pending.card {
            let network = Some(card.network.clone()).filter(|network| !network.is_empty())
                .unwrap_or_else(|| browser::card_network(&card.number).to_owned());
            let last4 = &card.number[card.number.len() - 4..];
            let fallback = format!("{} •••• {last4}", if network.is_empty() { "Card" } else { network.as_str() });
            serde_json::json!({
                "type": "CARD", "title": requested.unwrap_or(fallback), "primaryValue": card.number,
                "secondaryValue": card.name.trim(), "tertiaryValue": card.expiry, "network": network,
            })
        } else if let Some(profile) = &pending.profile {
            let fallback = Some(profile.name.trim()).filter(|name| !name.is_empty()).unwrap_or("Address").to_owned();
            let body = serde_json::to_string(profile)?;
            serde_json::json!({ "type": "AUTOFILL", "title": requested.unwrap_or(fallback), "primaryValue": body })
        } else {
            return Err(VaultError::InvalidEntry);
        };
        self.save_entry(draft)?;
        Ok(true)
    }

    pub fn save_entry(
        &mut self,
        draft: serde_json::Value,
    ) -> Result<serde_json::Value, VaultError> {
        let input = draft.as_object().ok_or(VaultError::InvalidEntry)?;
        let requested_id = match input.get("id") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(id)) if !id.is_empty() => Some(id.as_str()),
            _ => return Err(VaultError::InvalidEntry),
        };
        let now = now_millis()?;
        let mut entry: serde_json::Value = if let Some(id) = requested_id {
            let stored: String = self
                .connection
                .query_row(
                    "SELECT data_json FROM local_entries WHERE id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(VaultError::EntryNotFound)?;
            serde_json::from_str(&stored)?
        } else {
            default_entry(&Uuid::new_v4().to_string(), now)
        };
        if requested_id.is_some()
            && input
                .get("type")
                .is_some_and(|entry_type| entry_type != &entry["type"])
        {
            return Err(VaultError::InvalidEntry);
        }
        for field in [
            "type",
            "title",
            "primaryValue",
            "secondaryValue",
            "tertiaryValue",
            "fourthValue",
            "cardKind",
            "network",
            "totpAlgorithm",
            "totpDigits",
            "totpPeriod",
            "linkedApps",
            "autofillSignatures",
            "autofillOrigins",
            "linkedAuthenticatorId",
            "notes",
            "color",
            "tags",
            "favorite",
            "lastOpenedAt",
            "sortOrder",
        ] {
            if let Some(value) = input.get(field) {
                entry[field] = value.clone();
            }
        }
        entry["updatedAt"] = now.into();
        validate_entry(&entry)?;
        let id = entry["id"]
            .as_str()
            .ok_or(VaultError::InvalidEntry)?
            .to_owned();
        let entry_type = entry["type"]
            .as_str()
            .ok_or(VaultError::InvalidEntry)?
            .to_owned();
        let group_ids: Vec<String> = if let Some(group_ids) = input.get("groupIds") {
            group_ids
                .as_array()
                .ok_or(VaultError::InvalidEntry)?
                .iter()
                .map(|id| {
                    id.as_str()
                        .map(str::to_owned)
                        .ok_or(VaultError::InvalidEntry)
                })
                .collect::<Result<_, _>>()?
        } else if requested_id.is_some() {
            self.group_ids(&id)?
        } else {
            Vec::new()
        };
        if group_ids.len() > 100
            || group_ids.iter().any(|id| id.is_empty())
            || group_ids.iter().collect::<BTreeSet<_>>().len() != group_ids.len()
        {
            return Err(VaultError::InvalidEntry);
        }
        for group_id in &group_ids {
            let folder_type: Option<String> = self
                .connection
                .query_row(
                    "SELECT folder_type FROM local_groups WHERE id = ?1",
                    [group_id],
                    |row| row.get(0),
                )
                .optional()?;
            if !folder_type
                .is_some_and(|folder_type| folder_type.is_empty() || folder_type == entry_type)
            {
                return Err(VaultError::InvalidEntry);
            }
        }
        let json = serde_json::to_string(&entry)?;
        let payload = serde_json::json!({"entry": entry, "groupIds": group_ids});
        let history_entry = entry.clone();
        self.write_change("entry", &id, ChangeKind::Upsert, payload, |transaction| {
            crate::local_recovery::note_entry_write(transaction, &id, &history_entry, now)?;
            transaction.execute(
                "INSERT INTO local_entries (id, type, data_json, updated_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET type = excluded.type, data_json = excluded.data_json, updated_at = excluded.updated_at",
                params![id, entry_type, json, now],
            )?;
            transaction.execute("DELETE FROM entry_groups WHERE entry_id = ?1", [&id])?;
            for group_id in &group_ids {
                transaction.execute("INSERT INTO entry_groups (entry_id, group_id) VALUES (?1, ?2)", params![id, group_id])?;
            }
            Ok(())
        })?;
        entry["groupIds"] = serde_json::to_value(group_ids)?;
        Ok(entry)
    }

    /// The Android entry type of a non-note item, for display-safe activity messages.
    pub fn entry_type(&self, id: &str) -> Result<Option<String>, VaultError> {
        Ok(self
            .connection
            .query_row("SELECT type FROM local_entries WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .optional()?)
    }

    /// Saves a KeePass import (keepass_import.rs) as ordinary new items, so they sync like items
    /// added by hand. A login that already exists with the same website, username and password is
    /// skipped, also when the file holds it twice. Returns the counts actually saved.
    pub fn import_keepass(&mut self, plan: &crate::keepass_import::Plan) -> Result<crate::keepass_import::Summary, VaultError> {
        fn site(url: &str) -> String {
            let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
            rest.split(['/', '?', '#']).next().unwrap_or_default().to_ascii_lowercase()
        }
        let mut summary = plan.summary();
        summary.logins = 0;
        summary.codes = 0;
        summary.notes = 0;
        let mut known: BTreeSet<(String, String, String)> = self.list_entries()?.iter()
            .filter(|entry| entry["type"] == "PASSWORD")
            .map(|entry| (
                site(entry["tertiaryValue"].as_str().unwrap_or_default()),
                entry["primaryValue"].as_str().unwrap_or_default().to_owned(),
                entry["secondaryValue"].as_str().unwrap_or_default().to_owned(),
            ))
            .collect();
        for login in &plan.logins {
            if login.has_password() && !known.insert((site(&login.url), login.username.clone(), login.password.clone())) {
                summary.duplicates += 1;
                continue;
            }
            let mut linked = String::new();
            if let Some(code) = &login.code {
                let usable = crate::totp::code_at(&code.secret, code.algorithm, code.digits, code.period, 0).is_some();
                let saved = usable.then(|| self.save_entry(serde_json::json!({
                    "type": "AUTHENTICATOR", "title": login.title, "primaryValue": login.username,
                    "secondaryValue": code.secret, "totpAlgorithm": code.algorithm,
                    "totpDigits": code.digits, "totpPeriod": code.period, "tags": login.tags,
                })));
                match saved {
                    Some(Ok(entry)) => {
                        linked = entry["id"].as_str().unwrap_or_default().to_owned();
                        summary.codes += 1;
                    }
                    _ => summary.codes_skipped += 1,
                }
            }
            if login.has_password() {
                self.save_entry(serde_json::json!({
                    "type": "PASSWORD", "title": login.title, "primaryValue": login.username,
                    "secondaryValue": login.password, "tertiaryValue": login.url, "notes": login.notes,
                    "tags": login.tags, "linkedAuthenticatorId": linked,
                }))?;
                summary.logins += 1;
            } else if login.code.is_none() {
                self.save_note(None, &login.title, &login.note_body(), None)?;
                summary.notes += 1;
            }
        }
        Ok(summary)
    }

    // Previous passwords and Recently deleted: this PC only (local_recovery.rs).

    pub fn previous_passwords(&self, entry_id: &str) -> Result<Vec<crate::local_recovery::PreviousPassword>, VaultError> {
        Ok(crate::local_recovery::previous_passwords(&self.connection, entry_id)?)
    }

    pub fn clear_previous_passwords(&self, entry_id: &str) -> Result<(), VaultError> {
        Ok(crate::local_recovery::clear_previous_passwords(&self.connection, entry_id)?)
    }

    pub fn trashed_items(&self) -> Result<Vec<crate::local_recovery::TrashedItem>, VaultError> {
        Ok(crate::local_recovery::trashed_items(&self.connection)?)
    }

    /// Restores a trashed item as a new item (new ID), which syncs like any new item. It goes back
    /// into the folders that still exist and still take its type, and keeps its previous passwords.
    /// Returns `{kind, id, type}` of the new item.
    pub fn restore_trashed(&mut self, trash_id: &str) -> Result<serde_json::Value, VaultError> {
        let (item_id, kind, data, group_ids) = crate::local_recovery::trashed(&self.connection, trash_id)?
            .ok_or(VaultError::EntryNotFound)?;
        let item_type = if kind == "note" { "NOTE" } else { data["type"].as_str().ok_or(VaultError::InvalidEntry)? }.to_owned();
        let folders: BTreeMap<String, String> = self.list_groups()?.into_iter().map(|group| (group.id, group.folder_type)).collect();
        let group_ids: Vec<String> = group_ids.into_iter()
            .filter(|id| folders.get(id).is_some_and(|folder_type| folder_type.is_empty() || *folder_type == item_type))
            .collect();
        let restored_id = if kind == "note" {
            let title = data["title"].as_str().ok_or(VaultError::InvalidNote)?;
            let body = data["body"].as_str().ok_or(VaultError::InvalidNote)?;
            self.save_note(None, title, body, Some(group_ids))?.id
        } else {
            let mut draft = data.as_object().cloned().ok_or(VaultError::InvalidEntry)?;
            draft.remove("id");
            draft.insert("groupIds".to_owned(), serde_json::to_value(&group_ids)?);
            let entry = self.save_entry(serde_json::Value::Object(draft))?;
            let new_id = entry["id"].as_str().ok_or(VaultError::InvalidEntry)?.to_owned();
            crate::local_recovery::move_history(&self.connection, &item_id, &new_id)?;
            new_id
        };
        self.connection.execute("DELETE FROM local_trash WHERE id = ?1", [trash_id])?;
        Ok(serde_json::json!({"kind": kind, "id": restored_id, "type": item_type}))
    }

    pub fn forget_trashed(&self, trash_id: &str) -> Result<(), VaultError> {
        if crate::local_recovery::forget(&self.connection, trash_id)? { Ok(()) } else { Err(VaultError::EntryNotFound) }
    }

    pub fn empty_trash(&self) -> Result<(), VaultError> {
        Ok(crate::local_recovery::empty(&self.connection)?)
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<(), VaultError> {
        self.connection
            .query_row(
                "SELECT 1 FROM local_entries WHERE id = ?1",
                [id],
                |_| Ok(()),
            )
            .optional()?
            .ok_or(VaultError::EntryNotFound)?;
        // Published photos get their own delete changes (tombstones), like Android's per-photo
        // delete, so a late photo upload from another device cannot bring one back.
        let published: Vec<String> = self
            .connection
            .prepare(
                "SELECT p.id FROM local_entry_photos p JOIN vault_records r
                   ON r.entity_type = 'photo' AND r.entity_id = p.id WHERE p.entry_id = ?1 ORDER BY p.id",
            )?
            .query_map([id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        for photo_id in published {
            self.delete_entry_photo(&photo_id)?;
        }
        self.write_change(
            "entry",
            id,
            ChangeKind::Delete,
            serde_json::json!({"deleted": true}),
            |transaction| {
                crate::local_recovery::keep_deleted(transaction, id, now_millis().unwrap_or_default(), false)?;
                transaction.execute("DELETE FROM local_entries WHERE id = ?1", [id])?;
                transaction.execute("DELETE FROM local_entry_photos WHERE entry_id = ?1", [id])?;
                transaction.execute("DELETE FROM sync_attachment_manifests WHERE owner_entity_id = ?1", [id])?;
                transaction.execute("DELETE FROM entry_groups WHERE entry_id = ?1", [id])?;
                Ok(())
            },
        )?;
        Ok(())
    }

    fn backfill_independent_history(&mut self) -> Result<(), VaultError> {
        let enrolled: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_group_state)",
            [],
            |row| row.get(0),
        )?;
        if enrolled {
            return Ok(());
        }
        for group in self.list_groups()? {
            if ChangeStore::record(&self.connection, "group", &group.id)?.is_none() {
                let id = group.id.clone();
                self.write_change(
                    "group",
                    &id,
                    ChangeKind::Upsert,
                    serde_json::json!({"group": group}),
                    |_| Ok(()),
                )?;
            }
        }
        for note in self.list_notes()? {
            if ChangeStore::record(&self.connection, "entry", &note.id)?.is_none() {
                self.write_note_change(&note, ChangeKind::Upsert, |_| Ok(()))?;
            }
        }
        for mut entry in self.list_entries()? {
            let id = entry["id"]
                .as_str()
                .ok_or(VaultError::InvalidEntry)?
                .to_owned();
            if ChangeStore::record(&self.connection, "entry", &id)?.is_none() {
                let group_ids = entry
                    .as_object_mut()
                    .ok_or(VaultError::InvalidEntry)?
                    .remove("groupIds")
                    .ok_or(VaultError::InvalidEntry)?;
                self.write_change(
                    "entry",
                    &id,
                    ChangeKind::Upsert,
                    serde_json::json!({"entry": entry, "groupIds": group_ids}),
                    |_| Ok(()),
                )?;
            }
        }
        let passkeys: Vec<String> = self
            .connection
            .prepare("SELECT data_json FROM local_passkeys ORDER BY id")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        for json in passkeys {
            let passkey: VaultPasskey = serde_json::from_str(&json)?;
            if ChangeStore::record(&self.connection, "passkey", &passkey.id)?.is_none() {
                let id = passkey.id.clone();
                self.write_change(
                    "passkey",
                    &id,
                    ChangeKind::Upsert,
                    serde_json::json!({"passkey": passkey}),
                    |_| Ok(()),
                )?;
            }
        }
        Ok(())
    }

    fn write_note_change(
        &mut self,
        note: &LocalNote,
        kind: ChangeKind,
        materialize: impl FnOnce(&Transaction<'_>) -> Result<(), StoreError>,
    ) -> Result<(), VaultError> {
        let payload = if kind == ChangeKind::Upsert {
            let existing: Option<String> = self
                .connection
                .query_row(
                    "SELECT data_json FROM local_note_details WHERE id = ?1",
                    [&note.id],
                    |row| row.get(0),
                )
                .optional()?;
            let mut entry: serde_json::Value = existing
                .map(|value| serde_json::from_str(&value))
                .transpose()?
                .unwrap_or_else(|| note_sync_json(note));
            entry["title"] = note.title.clone().into();
            entry["notes"] = note.body.clone().into();
            entry["fourthValue"] = note.rich.clone().into();
            entry["createdAt"] = note.created_at.into();
            entry["updatedAt"] = note.updated_at.into();
            serde_json::json!({"entry": entry, "groupIds": note.group_ids})
        } else {
            serde_json::json!({"deleted": true})
        };
        let entry_json = if kind == ChangeKind::Upsert {
            Some(serde_json::to_string(&payload["entry"])?)
        } else {
            None
        };
        self.write_change("entry", &note.id, kind, payload, |transaction| {
            materialize(transaction)?;
            if let Some(entry_json) = &entry_json {
                transaction.execute(
                    "INSERT INTO local_note_details (id, data_json) VALUES (?1, ?2)
                     ON CONFLICT(id) DO UPDATE SET data_json = excluded.data_json",
                    params![note.id, entry_json],
                )?;
            } else {
                transaction.execute("DELETE FROM local_note_details WHERE id = ?1", [&note.id])?;
            }
            Ok(())
        })
    }

    fn write_change(
        &mut self,
        entity_type: &str,
        entity_id: &str,
        kind: ChangeKind,
        payload_json: serde_json::Value,
        materialize: impl FnOnce(&Transaction<'_>) -> Result<(), StoreError>,
    ) -> Result<(), VaultError> {
        if !self.identity_store.exists() && ChangeStore::operation_count(&self.connection)? > 0 {
            return Err(VaultError::MissingDeviceIdentity);
        }
        let identity = self.identity_store.get_or_create()?;
        let vault_id: String = self.connection.query_row(
            "SELECT vault_id FROM local_sync_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        let enrolled_key: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT content_key FROM sync_group_state WHERE vault_id = ?1",
                [&vault_id],
                |row| row.get(0),
            )
            .optional()?;
        let content_key = match enrolled_key {
            Some(key) => Zeroizing::new(key.try_into().map_err(|_| VaultError::InvalidVaultKey)?),
            None => {
                let enrolled: bool = self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sync_membership_events)",
                    [],
                    |row| row.get(0),
                )?;
                if enrolled {
                    return Err(VaultError::InvalidVaultKey);
                }
                Zeroizing::new(self.key)
            }
        };
        let head: Option<(i64, String)> = self.connection.query_row(
            "SELECT sequence, hash FROM sync_device_heads WHERE vault_id = ?1 AND device_id = ?2",
            params![vault_id, identity.device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let (sequence, previous_hash) = head
            .map(|(sequence, hash)| (sequence as u64 + 1, hash))
            .unwrap_or((1, GENESIS_HASH.to_owned()));
        let current = ChangeStore::record(&self.connection, entity_type, entity_id)?;
        if kind == ChangeKind::Delete && current.is_none() {
            return Err(VaultError::MissingNoteChange);
        }
        let base_revision = current.as_ref().map_or(0, |record| record.revision);
        let mut counters: BTreeMap<String, u64> = current
            .as_ref()
            .map(|record| serde_json::from_str::<RecordVersion>(&record.record_version_json))
            .transpose()?
            .unwrap_or_default()
            .counters()
            .clone();
        *counters.entry(identity.device_id.clone()).or_default() += 1;
        let version = RecordVersion::new(counters);
        let mutation_id = Uuid::new_v4().to_string();
        let plaintext = serde_json::to_vec(&payload_json)?;
        let encrypted = payload::encrypt_in(
            &self.connection,
            &*content_key,
            entity_type,
            &vault_id,
            &mutation_id,
            entity_id,
            &plaintext,
        )?;
        let occurred_at_utc = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| VaultError::Clock)?;
        let operation = ChangeRecord::create_signed_with(
            &vault_id,
            &identity.device_id,
            sequence,
            previous_hash,
            mutation_id,
            entity_type,
            entity_id,
            kind.clone(),
            base_revision,
            version.clone(),
            occurred_at_utc,
            encrypted.ciphertext,
            encrypted.nonce,
            |message| self.identity_store.sign(message),
        )?;
        if kind == ChangeKind::Upsert {
            let record = StoredVaultRecord {
                entity_type: entity_type.to_owned(),
                entity_id: entity_id.to_owned(),
                payload_ciphertext: operation.payload_ciphertext.clone(),
                revision: base_revision + 1,
                record_version_json: serde_json::to_string(&version)?,
            };
            ChangeStore::save_record_and_operation_with(
                &mut self.connection,
                &record,
                &operation,
                &identity,
                materialize,
            )?;
        } else {
            ChangeStore::delete_record_and_operation_with(
                &mut self.connection,
                &operation,
                &identity,
                materialize,
            )?;
        }
        Ok(())
    }
}

/// Android `LocalPhotoChangeWriter` payload for a photo upsert.
fn photo_payload(id: &str, entry_id: &str, is_cover: bool, added_at: i64, hash: &str, size: u64, epoch: u64) -> serde_json::Value {
    let mut payload = serde_json::json!({"photo": {
        "id": id, "entryId": entry_id, "isCover": is_cover, "addedAt": added_at,
        "blobHash": hash, "blobSize": size
    }});
    // Epoch 1 photos say nothing, as before.
    if epoch > 1 {
        payload["photo"]["keyEpoch"] = epoch.into();
    }
    payload
}

fn insert_manifest(transaction: &Transaction<'_>, photo_id: &str, entry_id: &str, hash: &str, size: u64) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO sync_attachment_manifests (attachment_id, owner_entity_type, owner_entity_id,
             encrypted_file_name, ciphertext_hash, size_bytes, key_epoch)
         VALUES (?1, 'entry', ?2, ?3, ?3, ?4, 1)
         ON CONFLICT(attachment_id) DO UPDATE SET owner_entity_id = excluded.owner_entity_id,
             encrypted_file_name = excluded.encrypted_file_name,
             ciphertext_hash = excluded.ciphertext_hash, size_bytes = excluded.size_bytes",
        params![photo_id, entry_id, hash, size as i64],
    )?;
    Ok(())
}

/// A note's formatting from its stored entry JSON (`fourthValue`), or "" when it has none.
fn rich_from_details(details: Option<&str>) -> String {
    details
        .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
        .and_then(|entry| entry.get("fourthValue").and_then(|value| value.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

pub(crate) fn note_sync_json(note: &LocalNote) -> serde_json::Value {
    serde_json::json!({
        "id": note.id, "type": "NOTE", "title": note.title,
        "primaryValue": "", "secondaryValue": "", "tertiaryValue": "", "fourthValue": note.rich,
        "cardKind": "CREDIT", "network": "", "totpAlgorithm": "SHA1", "totpDigits": 6,
        "totpPeriod": 30, "linkedApps": "", "autofillSignatures": "", "autofillOrigins": "",
        "linkedAuthenticatorId": "", "notes": note.body, "color": 0xFF08704A_u64,
        "tags": "", "favorite": false, "lastOpenedAt": 0, "sortOrder": note.created_at,
        "createdAt": note.created_at, "updatedAt": note.updated_at
    })
}

fn now_millis() -> Result<i64, VaultError> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| VaultError::Clock)?
        .as_millis() as i64)
}

fn default_entry(id: &str, now: i64) -> serde_json::Value {
    serde_json::json!({
        "id": id, "type": "", "title": "", "primaryValue": "", "secondaryValue": "",
        "tertiaryValue": "", "fourthValue": "", "cardKind": "CREDIT", "network": "",
        "totpAlgorithm": "SHA1", "totpDigits": 6, "totpPeriod": 30,
        "linkedApps": "", "autofillSignatures": "", "autofillOrigins": "",
        "linkedAuthenticatorId": "", "notes": "", "color": 0xFF08704A_u64,
        "tags": "", "favorite": false, "lastOpenedAt": 0, "sortOrder": now,
        "createdAt": now, "updatedAt": now
    })
}

fn validate_entry(entry: &serde_json::Value) -> Result<(), VaultError> {
    let entry_type = entry["type"].as_str().ok_or(VaultError::InvalidEntry)?;
    if !matches!(
        entry_type,
        "CARD" | "PASSWORD" | "QUESTION" | "AUTHENTICATOR" | "AUTOFILL"
    ) {
        return Err(VaultError::InvalidEntry);
    }
    for field in [
        "id",
        "title",
        "primaryValue",
        "secondaryValue",
        "tertiaryValue",
        "fourthValue",
        "cardKind",
        "network",
        "totpAlgorithm",
        "linkedApps",
        "autofillSignatures",
        "autofillOrigins",
        "linkedAuthenticatorId",
        "notes",
        "tags",
    ] {
        if entry[field].as_str().is_none() {
            return Err(VaultError::InvalidEntry);
        }
    }
    let title = entry["title"].as_str().ok_or(VaultError::InvalidEntry)?;
    if title.trim().is_empty() || title.len() > 500 {
        return Err(VaultError::InvalidEntry);
    }
    if !matches!(entry["cardKind"].as_str(), Some("CREDIT" | "DEBIT"))
        || !matches!(
            entry["totpAlgorithm"].as_str(),
            Some("SHA1" | "SHA256" | "SHA512")
        )
        || !matches!(entry["totpDigits"].as_u64(), Some(6..=8))
        || !matches!(entry["totpPeriod"].as_u64(), Some(1..=300))
        || entry["favorite"].as_bool().is_none()
        || entry["color"].as_u64().is_none()
        || entry["lastOpenedAt"].as_i64().is_none()
        || entry["sortOrder"].as_i64().is_none()
        || entry["createdAt"].as_i64().is_none()
        || entry["updatedAt"].as_i64().is_none()
    {
        return Err(VaultError::InvalidEntry);
    }
    let primary = entry["primaryValue"]
        .as_str()
        .ok_or(VaultError::InvalidEntry)?;
    let secondary = entry["secondaryValue"]
        .as_str()
        .ok_or(VaultError::InvalidEntry)?;
    let required = match entry_type {
        "CARD" => !primary.trim().is_empty(),
        "PASSWORD" | "AUTHENTICATOR" => !secondary.trim().is_empty(),
        "QUESTION" => !primary.trim().is_empty() && !secondary.trim().is_empty(),
        "AUTOFILL" => serde_json::from_str::<serde_json::Value>(primary)
            .ok()
            .and_then(|profile| profile.as_object().cloned())
            .is_some_and(|profile| {
                [
                    "name",
                    "email",
                    "phone",
                    "address1",
                    "address2",
                    "unit",
                    "city",
                    "state",
                    "postalCode",
                    "country",
                ]
                .iter()
                .any(|field| {
                    profile
                        .get(*field)
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty())
                })
            }),
        _ => false,
    };
    if !required {
        return Err(VaultError::InvalidEntry);
    }
    Ok(())
}

fn initialize_notes(connection: &Connection) -> Result<(), VaultError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS local_notes (
            id TEXT NOT NULL PRIMARY KEY,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS local_entries (
            id TEXT NOT NULL PRIMARY KEY,
            type TEXT NOT NULL,
            data_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS local_note_details (
            id TEXT NOT NULL PRIMARY KEY,
            data_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS local_entry_photos (
            id TEXT NOT NULL PRIMARY KEY,
            entry_id TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            data BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS local_groups (
            id TEXT NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            notes TEXT NOT NULL,
            folder_type TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS entry_groups (
            entry_id TEXT NOT NULL,
            group_id TEXT NOT NULL REFERENCES local_groups(id) ON DELETE CASCADE,
            PRIMARY KEY (entry_id, group_id)
        );
        CREATE TABLE IF NOT EXISTS local_passkeys (
            id TEXT NOT NULL PRIMARY KEY,
            rp_id TEXT NOT NULL,
            data_json TEXT NOT NULL
        );",
    )?;
    crate::local_recovery::initialize(connection)?;
    crate::site_icons::initialize(connection)?;
    crate::sign_ins::initialize(connection)?;
    migrate_local_schema(connection)
}

/// Local schema version in SQLite's `user_version`. Version 1 adds Android's photo cover flag
/// and timestamp so pairing imports keep them. Migrations only add columns with defaults, so
/// an older vault opens unchanged and an older build still reads the tables it knows.
pub(crate) const LOCAL_SCHEMA_VERSION: i64 = 1;

fn migrate_local_schema(connection: &Connection) -> Result<(), VaultError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version >= LOCAL_SCHEMA_VERSION {
        return Ok(());
    }
    let columns: BTreeSet<String> = connection
        .prepare("SELECT name FROM pragma_table_info('local_entry_photos')")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let transaction = connection.unchecked_transaction()?;
    if !columns.contains("is_cover") {
        transaction.execute_batch(
            "ALTER TABLE local_entry_photos ADD COLUMN is_cover INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    if !columns.contains("added_at") {
        transaction.execute_batch(
            "ALTER TABLE local_entry_photos ADD COLUMN added_at INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    transaction.execute_batch(&format!("PRAGMA user_version = {LOCAL_SCHEMA_VERSION};"))?;
    transaction.commit()?;
    Ok(())
}

fn initialize_local_sync_settings(connection: &Connection) -> Result<(), VaultError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS local_sync_settings (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
            vault_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sync_group_state (
            vault_id TEXT NOT NULL PRIMARY KEY,
            content_key BLOB NOT NULL CHECK (length(content_key) = 32),
            transport_secret BLOB NOT NULL CHECK (length(transport_secret) = 32)
        );
        CREATE TABLE IF NOT EXISTS sync_membership_events (
            vault_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            event_json TEXT NOT NULL,
            PRIMARY KEY (vault_id, sequence)
        );
        CREATE TABLE IF NOT EXISTS local_membership_notices (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
            removed_by TEXT NOT NULL DEFAULT '',
            removed_at INTEGER NOT NULL DEFAULT 0,
            leave_request TEXT NOT NULL DEFAULT '',
            leave_signature TEXT NOT NULL DEFAULT '',
            leave_secret BLOB,
            leave_address TEXT NOT NULL DEFAULT '',
            leave_attempted_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sync_memberships (
            vault_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            member_json TEXT NOT NULL,
            PRIMARY KEY (vault_id, device_id)
        );",
    )?;
    connection.execute(
        "INSERT OR IGNORE INTO local_sync_settings (id, vault_id) VALUES (1, ?1)",
        [Uuid::new_v4().to_string()],
    )?;
    Ok(())
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        // Only this vault's claim goes: another unlocked instance keeps its keys (C1).
        if let Ok(vault_id) = self.connection.query_row("SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get::<_, String>(0)) {
            self.keyring.release(&vault_id);
        }
        self.key.zeroize();
    }
}

/// `PRAGMA key = "x'<64 hex digits>'";` in one buffer of exact size, so it never reallocates and
/// leaves no copy of the key text behind. The buffer is wiped when it drops.
fn key_statement(key: &[u8; 32]) -> Zeroizing<String> {
    const PREFIX: &str = "PRAGMA key = \"x'";
    const SUFFIX: &str = "'\";";
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut statement = Zeroizing::new(String::with_capacity(PREFIX.len() + 64 + SUFFIX.len()));
    statement.push_str(PREFIX);
    for byte in key {
        statement.push(DIGITS[usize::from(byte >> 4)] as char);
        statement.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    statement.push_str(SUFFIX);
    statement
}

fn open_database(path: &Path, key: &[u8; 32], create: bool) -> Result<Connection, VaultError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | if create {
            OpenFlags::SQLITE_OPEN_CREATE
        } else {
            OpenFlags::empty()
        };
    let connection = Connection::open_with_flags(path, flags)?;
    // SQLCipher's raw-key form skips a second password KDF. The random key is
    // wrapped with Argon2id and AES-GCM in the bootstrap file.
    connection.execute_batch(&key_statement(key))?;
    connection.query_row("PRAGMA cipher_version", [], |_| Ok(()))?;
    connection.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
    Ok(connection)
}

/// Argon2id settings that turn the master password into the key that wraps the vault key.
///
/// Memory stays at 64 MiB on every device. The number of passes is timed on the device so that
/// one unlock takes about [`KDF_TARGET`], as KeePassXC does, and it never drops below the
/// 2.2.9 setting. An attacker who copies the vault folder pays the same cost for each guess.
/// The Android app uses the same rules (`PasswordCrypto` in the Android repository).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// About one second on the device that saves the file. Tests use the minimum, so that the many
/// test vaults stay fast.
const KDF_TARGET: std::time::Duration =
    std::time::Duration::from_millis(if cfg!(test) { 0 } else { 1_000 });
const KDF_MAX_ITERATIONS: u32 = 64;

impl KdfParams {
    /// The fixed setting of bootstrap format 1, and the lowest setting Nuvori saves.
    const LEGACY: Self = Self { memory_kib: 65_536, iterations: 3, parallelism: 1 };

    /// Settings read from a file stay within these limits, so that a damaged or edited file
    /// cannot make the unlock use gigabytes of memory or run for minutes.
    fn valid(&self) -> bool {
        self.memory_kib == Self::LEGACY.memory_kib
            && (Self::LEGACY.iterations..=KDF_MAX_ITERATIONS).contains(&self.iterations)
            && self.parallelism == Self::LEGACY.parallelism
    }

    /// Passes that fill [`KDF_TARGET`], given the time that `iterations` passes took here.
    fn for_measured(elapsed: std::time::Duration, iterations: u32) -> Self {
        Self::for_measured_within(elapsed, iterations, KDF_TARGET)
    }

    fn for_measured_within(elapsed: std::time::Duration, iterations: u32, target: std::time::Duration) -> Self {
        let per_pass = elapsed.as_secs_f64() / f64::from(iterations.max(1));
        Self { iterations: iterations_for(per_pass, target.as_secs_f64()), ..Self::LEGACY }
    }

    /// Times the legacy setting (3 passes) on this device, the same measurement as the unlock
    /// of a format 1 file. Used when no unlock has measured it yet: a new vault.
    fn calibrated() -> Result<Self, VaultError> {
        Self::calibrated_within(KDF_TARGET)
    }

    fn calibrated_within(target: std::time::Duration) -> Result<Self, VaultError> {
        if target.is_zero() {
            return Ok(Self::LEGACY);
        }
        let salt: [u8; 16] = random_array()?;
        let started = std::time::Instant::now();
        Zeroizing::new(derive("nuvori-kdf-calibration", &salt, Self::LEGACY)?);
        Ok(Self::for_measured_within(started.elapsed(), Self::LEGACY.iterations, target))
    }
}

/// Whole passes for `target` seconds when one pass takes `per_pass` seconds, kept between the
/// legacy minimum and [`KDF_MAX_ITERATIONS`].
fn iterations_for(per_pass: f64, target: f64) -> u32 {
    let wanted = if per_pass > 0.0 { (target / per_pass).round() } else { f64::from(KDF_MAX_ITERATIONS) };
    (wanted.clamp(f64::from(KdfParams::LEGACY.iterations), f64::from(KDF_MAX_ITERATIONS))) as u32
}

/// Wraps `vault_key` with a fresh salt and nonce under `password`, in bootstrap format 2.
fn wrap_vault_key(vault_key: &[u8; 32], password: &str, kdf: KdfParams) -> Result<VaultBootstrap, VaultError> {
    let salt: [u8; 16] = random_array()?;
    let nonce: [u8; 12] = random_array()?;
    let wrapping_key = Zeroizing::new(derive(password, &salt, kdf)?);
    let wrapped = Aes256Gcm::new_from_slice(&*wrapping_key)
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(&nonce), vault_key.as_ref())
        .map_err(|_| VaultError::KeyWrappingFailed)?;
    Ok(VaultBootstrap {
        format_version: BOOTSTRAP_VERSION,
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        wrapped_key: URL_SAFE_NO_PAD.encode(wrapped),
        kdf: Some(kdf),
    })
}

fn derive(password: &str, salt: &[u8; 16], kdf: KdfParams) -> Result<[u8; 32], VaultError> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|error| VaultError::Argon2(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|error| VaultError::Argon2(error.to_string()))?;
    Ok(key)
}

fn random_array<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|error| VaultError::Random(error.to_string()))?;
    Ok(bytes)
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], VaultError> {
    URL_SAFE_NO_PAD
        .decode(encoded)?
        .try_into()
        .map_err(|_| VaultError::InvalidBootstrap)
}

fn write_new_bootstrap(path: &Path, bootstrap: &VaultBootstrap) -> Result<(), VaultError> {
    let temporary = path.with_file_name(format!("vault-key-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(bootstrap)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok::<_, VaultError>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultBootstrap {
    format_version: u16,
    salt: String,
    nonce: String,
    wrapped_key: String,
    /// Format 2 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfParams>,
}

impl VaultBootstrap {
    /// The Argon2id settings this file was saved with. A format from a newer Nuvori is refused
    /// before any key derivation runs.
    fn kdf_params(&self) -> Result<KdfParams, VaultError> {
        match (self.format_version, self.kdf) {
            (LEGACY_BOOTSTRAP_VERSION, None) => Ok(KdfParams::LEGACY),
            (BOOTSTRAP_VERSION, Some(kdf)) if kdf.valid() => Ok(kdf),
            (LEGACY_BOOTSTRAP_VERSION | BOOTSTRAP_VERSION, _) => Err(VaultError::InvalidBootstrap),
            (version, _) => Err(VaultError::UnsupportedBootstrap(version)),
        }
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Windows Hello unlock failed: {0}")]
    Hello(String),
    #[error("vault storage failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("encrypted database failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("vault schema failed: {0}")]
    Store(#[from] StoreError),
    #[error("device identity failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("sync payload failed: {0}")]
    Payload(#[from] PayloadError),
    #[error("passkey is invalid: {0}")]
    Passkey(#[from] PasskeyError),
    #[error("vault metadata failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("vault metadata encoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("password must have at least 12 characters")]
    PasswordTooShort,
    #[error("vault already exists")]
    AlreadyInitialized,
    #[error("unsupported vault key format {0}")]
    UnsupportedBootstrap(u16),
    #[error("vault key metadata is invalid")]
    InvalidBootstrap,
    #[error("wrong password or damaged vault key")]
    WrongPasswordOrCorruptKey,
    #[error("vault key has an invalid length")]
    InvalidVaultKey,
    #[error("vault key wrapping failed")]
    KeyWrappingFailed,
    #[error("password derivation failed: {0}")]
    Argon2(String),
    #[error("secure random generation failed: {0}")]
    Random(String),
    #[error("note title and body are required and must fit the size limit")]
    InvalidNote,
    #[error("note was not found")]
    NoteNotFound,
    #[error("entry fields are invalid")]
    InvalidEntry,
    #[error("photo is invalid or exceeds the size limit")]
    InvalidPhoto,
    #[error("photo was not found")]
    PhotoNotFound,
    #[error("entry was not found")]
    EntryNotFound,
    #[error("a different password is already saved for this website account")]
    BrowserLoginConflict,
    #[error("group fields are invalid")]
    InvalidGroup,
    #[error("group was not found")]
    GroupNotFound,
    #[error("passkey ID already exists")]
    PasskeyAlreadyExists,
    #[error("passkey was not found")]
    PasskeyNotFound,
    #[error("system clock is unavailable")]
    Clock,
    #[error("device identity is missing for an existing change chain")]
    MissingDeviceIdentity,
    #[error("this vault is not sharing with another device")]
    NotSharing,
    #[error("resolve sync conflicts before stopping sharing")]
    PendingConflicts,
    #[error("the managing device cannot leave without transferring its role")]
    ManagingDevice,
    #[error("note has no matching change record")]
    MissingNoteChange,
    #[error("the vault database is open in another program")]
    InUse,
}

/// An "AUTOFILL" item's profile; unknown or missing fields are empty.
fn profile_of(entry: &serde_json::Value) -> browser::ProfileDetails {
    let stored: serde_json::Value = serde_json::from_str(entry["primaryValue"].as_str().unwrap_or("")).unwrap_or_default();
    let text = |field: &str| stored[field].as_str().unwrap_or("").to_owned();
    browser::ProfileDetails {
        name: text("name"), email: text("email"), phone: text("phone"), address1: text("address1"),
        address2: text("address2"), unit: text("unit"), city: text("city"), state: text("state"),
        postal_code: text("postalCode"), country: text("country"),
    }
}

/// Lower-case letters and digits only: "Git Hub!" -> "github".
fn squash(value: &str) -> String {
    value.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect()
}

/// The registrable name of a site: "https://accounts.google.co.uk" -> "google".
fn site_label(origin: &str) -> Option<String> {
    let host = url::Url::parse(origin).ok()?.host_str()?.to_owned();
    let domain = psl::domain_str(&host).unwrap_or(&host);
    let label = squash(domain.split('.').next()?);
    (!label.is_empty()).then_some(label)
}

#[cfg(test)]
mod tests {
    #[test]
    fn browser_cards_profiles_and_codes() {
        let directory = std::env::temp_dir().join(format!("nuvori-browser-items-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        let card = vault.save_entry(serde_json::json!({"type": "CARD", "title": "Travel", "primaryValue": "4111 1111 1111 1111",
            "secondaryValue": "A Person", "tertiaryValue": "7/29", "fourthValue": "123"})).unwrap();
        let card_id = card["id"].as_str().unwrap();
        // A card saved without a color lists the default green, so the extension draws it as in the app.
        assert_eq!(vault.browser_cards().unwrap(), vec![(card_id.to_owned(), "Travel".to_owned(), "Visa · •••• 1111 · 7/29".to_owned(), Some(0xFF08704A))]);
        let details = vault.browser_card(card_id).unwrap().unwrap();
        assert_eq!((details.number.as_str(), details.expiry.as_str(), details.cvv.as_str()), ("4111111111111111", "07/29", "123"));

        vault.save_entry(serde_json::json!({"type": "PASSWORD", "title": "Mail", "primaryValue": "me@example.com",
            "secondaryValue": "pw", "tertiaryValue": "https://mail.example.org"})).unwrap();
        let named = vault.save_entry(serde_json::json!({"type": "AUTHENTICATOR", "title": "GitHub", "primaryValue": "octo",
            "secondaryValue": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})).unwrap();
        let by_account = vault.save_entry(serde_json::json!({"type": "AUTHENTICATOR", "title": "Work mail", "primaryValue": "Me@example.com",
            "secondaryValue": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})).unwrap();
        vault.save_entry(serde_json::json!({"type": "AUTHENTICATOR", "title": "Bank", "primaryValue": "x",
            "secondaryValue": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"})).unwrap();
        let ids = |codes: Vec<(String, String, String)>| codes.into_iter().map(|code| code.0).collect::<Vec<_>>();
        assert_eq!(ids(vault.browser_codes("https://github.com", false).unwrap()), vec![named["id"].as_str().unwrap()]);
        assert_eq!(ids(vault.browser_codes("https://mail.example.org", false).unwrap()), vec![by_account["id"].as_str().unwrap()]);
        let all = vault.browser_codes("https://github.com", true).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0, named["id"].as_str().unwrap(), "matches first");
        let code = vault.browser_code(named["id"].as_str().unwrap(), 59).unwrap().unwrap();
        assert_eq!((code.value.as_str(), code.seconds_left), ("287082", 1));

        let pending = |card: Option<browser::CardDetails>, profile: Option<browser::ProfileDetails>| browser::PendingDetails {
            version: 1, origin: "https://shop.example".into(), created_at: 0,
            kind: if card.is_some() { browser::ItemKind::Card } else { browser::ItemKind::Profile }, card, profile,
        };
        let same_card = pending(Some(browser::CardDetails::with("4111111111111111", "", "")), None);
        assert!(!vault.save_browser_details(&same_card, None).unwrap(), "already saved by number");
        let new_card = pending(Some(browser::CardDetails::with("5500000000000004", "01/30", "")), None);
        assert!(vault.save_browser_details(&new_card, None).unwrap());
        assert!(vault.browser_cards().unwrap().iter().any(|card| card.1 == "Mastercard •••• 0004"));
        let home = browser::ProfileDetails { name: "A Person".into(), city: "Pune".into(), postal_code: "411001".into(), ..Default::default() };
        assert!(vault.review_browser_details(&pending(None, Some(home.clone()))).unwrap());
        assert!(vault.save_browser_details(&pending(None, Some(home.clone())), Some("Home")).unwrap());
        assert!(!vault.save_browser_details(&pending(None, Some(browser::ProfileDetails { city: "pune".into(), ..Default::default() })), None).unwrap());
        let profiles = vault.browser_profiles().unwrap();
        assert_eq!((profiles[0].1.as_str(), profiles[0].2.as_str()), ("Home", "A Person · Pune"));
        assert_eq!(profiles[0].3.postal_code, "411001");
        assert_eq!(vault.browser_profile(&profiles[0].0).unwrap().unwrap().postal_code, "411001");
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    use super::*;
    use crate::identity::verify_signature;

    fn read_bootstrap(directory: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(directory.join(BOOTSTRAP_FILE)).unwrap()).unwrap()
    }

    fn login(vault: &mut UnlockedVault, password: &str, group_ids: &[&str]) -> String {
        let saved = vault.save_entry(serde_json::json!({"type": "PASSWORD", "title": "Mail", "primaryValue": "me@example.com",
            "secondaryValue": password, "tertiaryValue": "https://mail.example.org", "notes": "keep me", "groupIds": group_ids})).unwrap();
        saved["id"].as_str().unwrap().to_owned()
    }

    fn passwords(vault: &UnlockedVault, id: &str) -> Vec<String> {
        vault.previous_passwords(id).unwrap().into_iter().map(|old| old.password).collect()
    }

    #[test]
    fn the_change_revision_moves_with_each_change_and_only_then() {
        let directory = std::env::temp_dir().join(format!("nuvori-revision-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        let start = vault.change_revision().unwrap();
        assert_eq!(vault.change_revision().unwrap(), start, "reading changes nothing");
        login(&mut vault, "first", &[]);
        let saved = vault.change_revision().unwrap();
        assert!(saved > start, "a saved item writes a change");
        assert_eq!(vault.change_revision().unwrap(), saved);
        login(&mut vault, "second", &[]);
        let again = vault.change_revision().unwrap();
        assert!(again > saved);
        // An applied mark and a membership event move it too.
        let mutation: String = vault.connection.query_row("SELECT mutation_id FROM sync_operations LIMIT 1", [], |row| row.get(0)).unwrap();
        vault.connection.execute("INSERT INTO sync_applied_operations (mutation_id, change_hash, outcome, applied_at_utc) VALUES (?1, 'h', 'applied', 'now')", [&mutation]).unwrap();
        let applied = vault.change_revision().unwrap();
        assert!(applied > again);
        vault.connection.execute("INSERT INTO sync_membership_events (vault_id, sequence, event_json) VALUES ('v', 1, '{}')", []).unwrap();
        assert!(vault.change_revision().unwrap() > applied);
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_changed_password_is_kept_newest_first_up_to_ten() {
        let directory = std::env::temp_dir().join(format!("nuvori-history-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        let id = login(&mut vault, "first", &[]);
        assert!(passwords(&vault, &id).is_empty(), "a new login has no history");
        vault.save_entry(serde_json::json!({"id": id, "title": "Mail (renamed)"})).unwrap();
        assert!(passwords(&vault, &id).is_empty(), "a change without a new password adds nothing");
        vault.save_entry(serde_json::json!({"id": id, "secondaryValue": "second"})).unwrap();
        assert_eq!(passwords(&vault, &id), ["first"]);
        for index in 3..=13 {
            vault.save_entry(serde_json::json!({"id": id, "secondaryValue": format!("password {index}")})).unwrap();
        }
        let history = passwords(&vault, &id);
        assert_eq!(history.len(), 10);
        assert_eq!((history[0].as_str(), history[9].as_str()), ("password 12", "password 3"));
        // Cards and codes have no password history.
        let card = vault.save_entry(serde_json::json!({"type": "CARD", "title": "Travel", "primaryValue": "4111 1111 1111 1111"})).unwrap();
        let card_id = card["id"].as_str().unwrap();
        vault.save_entry(serde_json::json!({"id": card_id, "secondaryValue": "A Person"})).unwrap();
        assert!(passwords(&vault, card_id).is_empty());
        vault.clear_previous_passwords(&id).unwrap();
        assert!(passwords(&vault, &id).is_empty());
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_deleted_login_restores_as_a_new_item_with_its_folder_and_history() {
        let directory = std::env::temp_dir().join(format!("nuvori-trash-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        let folder = vault.save_group(None, "Work", "", "PASSWORD").unwrap();
        let id = login(&mut vault, "old secret", &[&folder.id]);
        vault.save_entry(serde_json::json!({"id": id, "secondaryValue": "new secret"})).unwrap();
        vault.delete_entry(&id).unwrap();

        let trash = vault.trashed_items().unwrap();
        assert_eq!(trash.len(), 1);
        assert_eq!((trash[0].title.as_str(), trash[0].item_type.as_str(), trash[0].deleted_elsewhere), ("Mail", "PASSWORD", false));
        assert_eq!(trash[0].expires_at - trash[0].deleted_at, 30 * 24 * 60 * 60 * 1000);
        assert!(vault.list_entries().unwrap().is_empty());

        let restored = vault.restore_trashed(&trash[0].id).unwrap();
        let new_id = restored["id"].as_str().unwrap();
        assert_ne!(new_id, id, "the deleted ID keeps its tombstone; the restored item is new");
        let entries = vault.list_entries().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!((entry["title"].as_str(), entry["secondaryValue"].as_str(), entry["notes"].as_str()), (Some("Mail"), Some("new secret"), Some("keep me")));
        assert_eq!(entry["groupIds"], serde_json::json!([folder.id]));
        assert_eq!(passwords(&vault, new_id), ["old secret"]);
        assert!(vault.trashed_items().unwrap().is_empty());
        // The restore is an ordinary signed change, so it syncs like a new item.
        assert!(ChangeStore::record(&vault.connection, "entry", new_id).unwrap().is_some());
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rich_note_formatting_is_saved_synced_and_kept_by_plain_edits() {
        let directory = std::env::temp_dir().join(format!("nuvori-rich-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        // The "inline marks" fixture from docs/rich-notes/fixtures.json, as the Android app writes it.
        let fixtures: serde_json::Value = serde_json::from_str(include_str!("../../docs/rich-notes/fixtures.json")).unwrap();
        let fixture = &fixtures["fixtures"][0];
        let (plain, rich) = (fixture["plain"].as_str().unwrap(), fixture["encoded"].as_str().unwrap());
        let note = vault.save_rich_note(None, "Formatted", plain, Some(rich), None).unwrap();
        assert_eq!(note.rich, rich);
        let stored = |vault: &mut UnlockedVault| -> serde_json::Value {
            let json: String = vault.connection().query_row("SELECT data_json FROM local_note_details WHERE id = ?1", [&note.id], |row| row.get(0)).unwrap();
            serde_json::from_str(&json).unwrap()
        };
        assert_eq!(stored(&mut vault)["fourthValue"], rich, "the sync entry carries the formatting byte for byte");
        assert_eq!(stored(&mut vault)["notes"], plain);
        assert_eq!(vault.list_notes().unwrap()[0].rich, rich);

        // An edit that sends no formatting keeps it; readers see the text changed and show the text.
        vault.save_note(Some(&note.id), "Formatted", "Edited as plain text", None).unwrap();
        assert_eq!(vault.list_notes().unwrap()[0].rich, rich);
        // Saving it as a plain note clears it.
        vault.save_rich_note(Some(&note.id), "Formatted", "Plain now", Some(""), None).unwrap();
        assert_eq!(vault.list_notes().unwrap()[0].rich, "");
        assert_eq!(stored(&mut vault)["fourthValue"], "");

        for bad in ["not json", "[1,2]", &"x".repeat(MAX_RICH_NOTE_BYTES + 1)] {
            assert!(matches!(vault.save_rich_note(None, "Bad", "Body", Some(bad), None), Err(VaultError::InvalidNote)));
        }
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn notes_go_to_the_trash_and_old_trash_is_purged() {
        let directory = std::env::temp_dir().join(format!("nuvori-trash-notes-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        let note = vault.save_note(None, "Wi-Fi", "router password: synthetic", None).unwrap();
        vault.delete_note(&note.id).unwrap();
        let trash = vault.trashed_items().unwrap();
        assert_eq!((trash[0].kind.as_str(), trash[0].item_type.as_str()), ("note", "NOTE"));
        vault.restore_trashed(&trash[0].id).unwrap();
        let notes = vault.list_notes().unwrap();
        assert_eq!((notes[0].title.as_str(), notes[0].body.as_str()), ("Wi-Fi", "router password: synthetic"));

        // Items older than 30 days are gone after the next unlock, with their previous passwords.
        let id = login(&mut vault, "a", &[]);
        vault.save_entry(serde_json::json!({"id": id, "secondaryValue": "b"})).unwrap();
        vault.delete_entry(&id).unwrap();
        vault.delete_note(&notes[0].id).unwrap();
        let old = now_millis().unwrap() - 31 * 24 * 60 * 60 * 1000;
        vault.connection.execute("UPDATE local_trash SET deleted_at = ?1 WHERE kind = 'entry'", [old]).unwrap();
        drop(vault);
        let vault = store.unlock("synthetic-test-password").unwrap();
        let trash = vault.trashed_items().unwrap();
        assert_eq!(trash.iter().map(|item| item.kind.as_str()).collect::<Vec<_>>(), ["note"]);
        assert!(passwords(&vault, &id).is_empty());

        vault.forget_trashed(&trash[0].id).unwrap();
        assert!(vault.trashed_items().unwrap().is_empty());
        assert!(matches!(vault.forget_trashed("missing"), Err(VaultError::EntryNotFound)));
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_keepass_import_saves_linked_codes_and_notes_and_skips_duplicates() {
        use crate::keepass_import::{Code, Login, Plan};
        let directory = std::env::temp_dir().join(format!("nuvori-keepass-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        login(&mut vault, "already-here", &[]);
        let item = |title: &str, password: &str, url: &str, code: Option<Code>| Login {
            title: title.into(), username: "me@example.com".into(), password: password.into(), url: url.into(),
            notes: "from KeePass".into(), tags: "KeePass: Work".into(), code,
        };
        let plan = Plan { logins: vec![
            item("Mail", "already-here", "https://mail.example.org/other-page", None),
            item("Bank", "synthetic-bank", "https://bank.example", Some(Code { secret: "JBSWY3DPEHPK3PXP".into(), algorithm: "SHA1", digits: 6, period: 30 })),
            item("Bank copy", "synthetic-bank", "https://bank.example/login", None),
            item("Broken code", "synthetic-x", "https://x.example", Some(Code { secret: "JBSWY3DPEHPK3PXP".into(), algorithm: "SHA1", digits: 9, period: 30 })),
            item("Office Wi-Fi", "", "", None),
        ], ..Plan::default() };

        let summary = vault.import_keepass(&plan).unwrap();
        assert_eq!((summary.logins, summary.codes, summary.notes, summary.duplicates, summary.codes_skipped), (2, 1, 1, 2, 1));
        let entries = vault.list_entries().unwrap();
        let bank = entries.iter().find(|entry| entry["title"] == "Bank").unwrap();
        let code = entries.iter().find(|entry| entry["type"] == "AUTHENTICATOR").unwrap();
        assert_eq!(bank["linkedAuthenticatorId"], code["id"]);
        assert_eq!((code["secondaryValue"].as_str(), bank["tags"].as_str()), (Some("JBSWY3DPEHPK3PXP"), Some("KeePass: Work")));
        let notes = vault.list_notes().unwrap();
        assert_eq!(notes[0].title, "Office Wi-Fi");
        // Each new item is an ordinary signed change, so it syncs to paired devices.
        assert!(ChangeStore::record(&vault.connection, "entry", bank["id"].as_str().unwrap()).unwrap().is_some());

        // The same file again adds nothing new.
        let again = vault.import_keepass(&plan).unwrap();
        assert_eq!((again.logins, again.duplicates), (0, 4));
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_key_statement_matches_sqlcipher_syntax_without_growing_its_buffer() {
        let key: [u8; 32] = std::array::from_fn(|index| (index * 37 + 5) as u8);
        let statement = key_statement(&key);
        assert_eq!(statement.as_str(), format!("PRAGMA key = \"x'{}'\";", hex::encode(key)));
        // Exactly the reserved size: no reallocation left a copy of the key text behind.
        assert_eq!(statement.len(), statement.capacity());
    }

    #[test]
    fn a_new_vault_saves_its_argon2id_settings() {
        let directory = std::env::temp_dir().join(format!("nuvori-kdf-new-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        drop(store.create("synthetic-test-password").unwrap());
        let file = read_bootstrap(&directory);
        assert_eq!(file["formatVersion"], 2);
        assert_eq!(file["kdf"], serde_json::json!({"memoryKib": 65_536, "iterations": 3, "parallelism": 1}));
        drop(store.unlock("synthetic-test-password").unwrap());
        assert!(matches!(store.unlock("wrong-test-password"), Err(VaultError::WrongPasswordOrCorruptKey)));
        fs::remove_dir_all(directory).unwrap();
    }

    /// A Windows 2.2.9 vault: format 1, no settings in the file, always 64 MiB and 3 passes.
    #[test]
    fn a_format_1_vault_opens_and_is_saved_again_in_format_2() {
        let directory = std::env::temp_dir().join(format!("nuvori-kdf-legacy-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        vault.save_note(None, "Kept", "across the upgrade", None).unwrap();
        let key = vault.key;
        drop(vault);
        let mut legacy = wrap_vault_key(&key, "synthetic-test-password", KdfParams::LEGACY).unwrap();
        legacy.format_version = LEGACY_BOOTSTRAP_VERSION;
        legacy.kdf = None;
        let path = directory.join(BOOTSTRAP_FILE);
        write_new_bootstrap(&path, &legacy).unwrap();
        assert_eq!(read_bootstrap(&directory).get("kdf"), None, "the file looks like 2.2.9 wrote it");

        assert!(matches!(store.unlock("wrong-test-password"), Err(VaultError::WrongPasswordOrCorruptKey)));
        assert_eq!(read_bootstrap(&directory)["formatVersion"], 1, "a wrong password changes nothing");

        let vault = store.unlock("synthetic-test-password").unwrap();
        assert_eq!(vault.list_notes().unwrap()[0].title, "Kept");
        drop(vault);
        let upgraded = read_bootstrap(&directory);
        assert_eq!(upgraded["formatVersion"], 2);
        assert_eq!(upgraded["kdf"]["memoryKib"], 65_536);
        assert_ne!(upgraded["salt"], serde_json::to_value(&legacy.salt).unwrap(), "a new salt");

        // The same vault key is inside: the database and the Hello unlock keep working.
        let vault = store.unlock("synthetic-test-password").unwrap();
        assert_eq!(vault.key, key);
        drop(vault);
        assert!(fs::read_dir(&directory).unwrap().all(|entry| !entry.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn edited_or_newer_key_files_are_refused_before_any_key_derivation() {
        let directory = std::env::temp_dir().join(format!("nuvori-kdf-limits-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        drop(store.create("synthetic-test-password").unwrap());
        let path = directory.join(BOOTSTRAP_FILE);
        let original = read_bootstrap(&directory);
        let edit = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut file = original.clone();
            change(&mut file);
            fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
            store.unlock("synthetic-test-password").err()
        };
        // 4 GiB of memory or a thousand passes would freeze the unlock: refused.
        assert!(matches!(edit(&|file| file["kdf"]["memoryKib"] = 4_194_304.into()), Some(VaultError::InvalidBootstrap)));
        assert!(matches!(edit(&|file| file["kdf"]["iterations"] = 1_000.into()), Some(VaultError::InvalidBootstrap)));
        // Fewer passes than 2.2.9 used would weaken the file: refused.
        assert!(matches!(edit(&|file| file["kdf"]["iterations"] = 1.into()), Some(VaultError::InvalidBootstrap)));
        assert!(matches!(edit(&|file| file["kdf"]["parallelism"] = 8.into()), Some(VaultError::InvalidBootstrap)));
        assert!(matches!(edit(&|file| { file.as_object_mut().unwrap().remove("kdf"); }), Some(VaultError::InvalidBootstrap)));
        assert!(matches!(edit(&|file| file["formatVersion"] = 3.into()), Some(VaultError::UnsupportedBootstrap(3))));
        fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
        drop(store.unlock("synthetic-test-password").unwrap());
        fs::remove_dir_all(directory).unwrap();
    }

    /// Real Argon2id runs on this machine: the timed setting must take about the target time.
    #[test]
    fn calibration_on_this_machine_meets_the_target() {
        let target = std::time::Duration::from_millis(400);
        let params = KdfParams::calibrated_within(target).unwrap();
        assert!(params.valid(), "{params:?}");
        let salt = [7u8; 16];
        let started = std::time::Instant::now();
        derive("synthetic-test-password", &salt, params).unwrap();
        let took = started.elapsed();
        eprintln!("calibrated {params:?}: one derivation took {took:?} for a {target:?} target");
        if params.iterations > KdfParams::LEGACY.iterations && params.iterations < KDF_MAX_ITERATIONS {
            // A debug build and a busy test machine are noisy: allow a wide band around the target.
            assert!(took > target / 3 && took < target * 3, "{took:?} for {target:?}");
        }
    }

    #[test]
    fn passes_fill_about_one_second_within_the_limits() {
        // 44 ms per 64 MiB pass (measured on a desktop PC): about 23 passes for one second.
        assert_eq!(iterations_for(0.044, 1.0), 23);
        // A slow phone-class device keeps the 2.2.9 minimum, never less.
        assert_eq!(iterations_for(0.6, 1.0), 3);
        // A very fast device, or a timer that reports 0, stops at the maximum.
        assert_eq!(iterations_for(0.001, 1.0), KDF_MAX_ITERATIONS);
        assert_eq!(iterations_for(0.0, 1.0), KDF_MAX_ITERATIONS);
        // The legacy unlock measures 3 passes; the result is per pass.
        let params = KdfParams { iterations: iterations_for(0.264 / 3.0, 1.0), ..KdfParams::LEGACY };
        assert_eq!(params.iterations, 11);
        assert!(params.valid());
    }

    #[test]
    fn encrypted_vault_reopens_and_rejects_wrong_password() {
        let directory = std::env::temp_dir().join(format!("nuvori-vault-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store
            .create("twelve-character-password")
            .expect("vault must be created");
        assert!(store.is_initialized());
        vault.connection().execute(
            "INSERT INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json) VALUES ('entry', 'one', 'secret-test-value', 1, '{}')",
            [],
        ).expect("test record must be stored");
        drop(vault);

        let bytes = fs::read(directory.join(DATABASE_FILE)).expect("database must exist");
        assert!(!bytes.starts_with(b"SQLite format 3"));
        assert!(
            !bytes
                .windows(b"secret-test-value".len())
                .any(|part| part == b"secret-test-value")
        );
        assert!(matches!(
            store.unlock("wrong-password-123"),
            Err(VaultError::WrongPasswordOrCorruptKey)
        ));
        let mut reopened = store
            .unlock("twelve-character-password")
            .expect("vault must reopen");
        let value: String = reopened
            .connection()
            .query_row(
                "SELECT payload_ciphertext FROM vault_records WHERE entity_id = 'one'",
                [],
                |row| row.get(0),
            )
            .expect("test record must survive restart");
        assert_eq!(value, "secret-test-value");
        drop(reopened);
        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[test]
    fn notes_survive_reopen_and_delete_from_encrypted_vault() {
        let directory = std::env::temp_dir().join(format!("nuvori-notes-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let note = vault
            .save_note(None, "Travel", "Recovery phrase stays private", None)
            .unwrap();
        assert_eq!(vault.note_count().unwrap(), 1);
        assert_eq!(ChangeStore::operation_count(vault.connection()).unwrap(), 1);
        let (mutation_id, occurred_at, ciphertext, nonce, signature, hash): (String, String, String, String, String, String) = vault.connection().query_row(
            "SELECT mutation_id, occurred_at_utc, payload_ciphertext, payload_nonce, device_signature, hash FROM sync_operations WHERE entity_id = ?1",
            [&note.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).unwrap();
        let identity = vault.identity_store.get_or_create().unwrap();
        let vault_id: String = vault
            .connection()
            .query_row("SELECT vault_id FROM local_sync_settings", [], |row| {
                row.get(0)
            })
            .unwrap();
        let operation = ChangeRecord::create(
            vault_id,
            &identity.device_id,
            1,
            GENESIS_HASH,
            mutation_id,
            "entry",
            &note.id,
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([(&identity.device_id, 1)]),
            occurred_at,
            ciphertext,
            nonce,
            signature.clone(),
        );
        assert_eq!(operation.hash, hash);
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature)
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_signature(
            &identity.public_key,
            &operation.signing_bytes(),
            &signature
        ));
        let payload: serde_json::Value =
            serde_json::from_slice(&payload::decrypt(&vault.key, &operation).unwrap()).unwrap();
        assert_eq!(payload["entry"]["type"], "NOTE");
        assert_eq!(payload["entry"]["notes"], note.body);
        assert_eq!(payload["groupIds"], serde_json::json!([]));
        drop(vault);

        let database = fs::read(directory.join(DATABASE_FILE)).unwrap();
        assert!(
            !database
                .windows(note.body.len())
                .any(|window| window == note.body.as_bytes())
        );

        let mut reopened = store.unlock("twelve-character-password").unwrap();
        assert_eq!(reopened.list_notes().unwrap()[0].body, note.body);
        let edited = reopened
            .save_note(Some(&note.id), "Travel updated", "New contents", None)
            .unwrap();
        assert_eq!(edited.id, note.id);
        assert_eq!(edited.created_at, note.created_at);
        assert_eq!(
            ChangeStore::operation_count(reopened.connection()).unwrap(),
            2
        );
        reopened.delete_note(&note.id).unwrap();
        assert_eq!(
            ChangeStore::operation_count(reopened.connection()).unwrap(),
            3
        );
        let tombstones: u32 = reopened
            .connection()
            .query_row(
                "SELECT count(*) FROM sync_tombstones WHERE entity_id = ?1",
                [&note.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tombstones, 1);
        assert!(reopened.list_notes().unwrap().is_empty());
        assert!(matches!(
            reopened.delete_note(&note.id),
            Err(VaultError::NoteNotFound)
        ));
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn enrolled_vault_uses_shared_content_key_for_new_changes() {
        let directory = std::env::temp_dir().join(format!("nuvori-enrolled-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        vault
            .connection()
            .execute(
                "INSERT INTO sync_group_state (vault_id, content_key, transport_secret)
                 VALUES ('android-vault', ?1, ?2)",
                params![[7_u8; 32].as_slice(), [8_u8; 32].as_slice()],
            )
            .unwrap();
        vault
            .connection()
            .execute(
                "UPDATE local_sync_settings SET vault_id = 'android-vault' WHERE id = 1",
                [],
            )
            .unwrap();
        let note = vault
            .save_note(None, "Imported", "New shared note", None)
            .unwrap();
        let (mutation_id, device_id, ciphertext, nonce, signature, occurred_at):
            (String, String, String, String, String, String) = vault
            .connection()
            .query_row(
                "SELECT mutation_id, device_id, payload_ciphertext, payload_nonce,
                        device_signature, occurred_at_utc FROM sync_operations WHERE entity_id = ?1",
                [&note.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .unwrap();
        let operation = ChangeRecord::create(
            "android-vault",
            &device_id,
            1,
            GENESIS_HASH,
            mutation_id,
            "entry",
            &note.id,
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([(&device_id, 1)]),
            occurred_at,
            ciphertext,
            nonce,
            signature,
        );
        assert!(payload::decrypt(&vault.key, &operation).is_err());
        let plaintext = payload::decrypt(&[7_u8; 32], &operation).unwrap();
        let entry: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(entry["entry"]["notes"], "New shared note");
        vault
            .connection()
            .execute(
                "INSERT INTO sync_membership_events (vault_id, sequence, event_json)
             VALUES ('android-vault', 1, '{}')",
                [],
            )
            .unwrap();
        vault
            .connection()
            .execute("DELETE FROM sync_group_state", [])
            .unwrap();
        assert!(matches!(
            vault.save_note(None, "Unsafe", "Missing shared key", None),
            Err(VaultError::InvalidVaultKey)
        ));
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn leaving_group_keeps_local_content_and_rebuilds_its_history() {
        use p256::{
            SecretKey,
            pkcs8::{EncodePrivateKey, EncodePublicKey},
        };
        let directory = std::env::temp_dir().join(format!("nuvori-leave-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        vault.connection().execute(
            "INSERT INTO sync_group_state (vault_id, content_key, transport_secret) VALUES ('android-vault', ?1, ?2)",
            params![[7_u8; 32].as_slice(), [8_u8; 32].as_slice()],
        ).unwrap();
        vault
            .connection()
            .execute(
                "UPDATE local_sync_settings SET vault_id = 'android-vault' WHERE id = 1",
                [],
            )
            .unwrap();
        let group = vault.save_group(None, "Notes", "", "NOTE").unwrap();
        let note = vault
            .save_note(
                None,
                "Kept note",
                "Private content",
                Some(vec![group.id.clone()]),
            )
            .unwrap();
        let entry = vault.save_entry(serde_json::json!({"type": "PASSWORD", "title": "Example login", "primaryValue": "someone", "secondaryValue": "secret"})).unwrap();
        let entry_id = entry["id"].as_str().unwrap();
        vault
            .add_entry_photo(
                entry_id,
                "image/gif",
                &URL_SAFE_NO_PAD.encode(b"GIF89aexample"),
            )
            .unwrap();
        let secret = SecretKey::from_slice(&[9; 32]).unwrap();
        let passkey = VaultPasskey {
            id: URL_SAFE_NO_PAD.encode([7; 32]),
            rp_id: "example.com".to_owned(),
            user_handle: URL_SAFE_NO_PAD.encode([3; 16]),
            username: "alice".to_owned(),
            display_name: "Alice".to_owned(),
            private_key: URL_SAFE_NO_PAD.encode(secret.to_pkcs8_der().unwrap().as_bytes()),
            public_key: URL_SAFE_NO_PAD
                .encode(secret.public_key().to_public_key_der().unwrap().as_bytes()),
            created_at: 100,
        };
        vault.save_passkey(passkey).unwrap();
        vault.connection().execute(
            "INSERT INTO sync_membership_events (vault_id, sequence, event_json) VALUES ('android-vault', 1, '{}')", [],
        ).unwrap();
        vault.connection().execute(
            "INSERT INTO sync_conflicts (conflict_id, entity_type, entity_id, local_change_hash, remote_change_hash, local_version_json, remote_version_json, detected_at_utc) VALUES ('conflict', 'entry', 'unresolved', 'local', 'remote', '{}', '{}', 'now')", [],
        ).unwrap();
        assert!(matches!(
            vault.stop_sharing(),
            Err(VaultError::PendingConflicts)
        ));
        assert!(vault.is_enrolled().unwrap());
        vault
            .connection()
            .execute("DELETE FROM sync_conflicts", [])
            .unwrap();

        vault.stop_sharing().unwrap();
        assert!(!vault.is_enrolled().unwrap());
        assert_eq!(vault.list_notes().unwrap()[0].body, "Private content");
        assert_eq!(vault.list_notes().unwrap()[0].group_ids, vec![group.id]);
        assert_eq!(vault.list_entries().unwrap()[0]["secondaryValue"], "secret");
        assert_eq!(vault.list_entry_photos(entry_id).unwrap().len(), 1);
        assert_eq!(vault.list_passkeys().unwrap()[0].rp_id, "example.com");
        assert_eq!(vault.local_change_count().unwrap(), 4);
        let vault_id: String = vault
            .connection()
            .query_row(
                "SELECT vault_id FROM local_sync_settings WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(vault_id, "android-vault");
        let old_operations: i64 = vault
            .connection()
            .query_row(
                "SELECT count(*) FROM sync_operations WHERE vault_id = 'android-vault'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_operations, 0);
        vault
            .save_note(Some(&note.id), "Kept note", "Edited after leaving", None)
            .unwrap();
        drop(vault);
        let reopened = store.unlock("twelve-character-password").unwrap();
        assert_eq!(
            reopened.list_notes().unwrap()[0].body,
            "Edited after leaving"
        );
        assert_eq!(reopened.local_change_count().unwrap(), 5);
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn version_zero_vault_gains_photo_metadata_without_losing_photos() {
        let directory = std::env::temp_dir().join(format!("nuvori-schema-test-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("correct horse battery staple").unwrap();
        let entry = vault
            .save_entry(serde_json::json!({
                "type": "CARD", "title": "Card", "primaryValue": "4111111111111111"
            }))
            .unwrap();
        let entry_id = entry["id"].as_str().unwrap().to_owned();
        // Rebuild the photo table exactly as builds before schema version 1 created it.
        vault
            .connection()
            .execute_batch(
                "DROP TABLE local_entry_photos;
                 CREATE TABLE local_entry_photos (
                     id TEXT NOT NULL PRIMARY KEY, entry_id TEXT NOT NULL,
                     mime_type TEXT NOT NULL, data BLOB NOT NULL
                 );
                 PRAGMA user_version = 0;",
            )
            .unwrap();
        vault
            .connection()
            .execute(
                "INSERT INTO local_entry_photos (id, entry_id, mime_type, data) VALUES ('old-photo', ?1, 'image/png', ?2)",
                params![entry_id, b"\x89PNG\r\n\x1a\nold".to_vec()],
            )
            .unwrap();
        drop(vault);

        let mut vault = store.unlock("correct horse battery staple").unwrap();
        let version: i64 = vault
            .connection()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, LOCAL_SCHEMA_VERSION);
        let photos = vault.list_entry_photos(&entry_id).unwrap();
        assert_eq!(photos.len(), 1);
        assert_eq!((photos[0].id.as_str(), photos[0].is_cover, photos[0].added_at), ("old-photo", false, 0));
        vault
            .add_entry_photo(&entry_id, "image/png", &base64::engine::general_purpose::STANDARD.encode(b"\x89PNG\r\n\x1a\nnew"))
            .unwrap();
        let photos = vault.list_entry_photos(&entry_id).unwrap();
        assert!(photos[0].is_cover && photos[0].added_at > 0, "first photo with metadata becomes the cover");
        drop(vault);
        // Reopening at the current version is a no-op.
        let vault = store.unlock("correct horse battery staple").unwrap();
        assert_eq!(vault.list_entry_photos(&entry_id).unwrap().len(), 2);
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn hello_key_opens_vault_and_reset_removes_it() {
        let directory = std::env::temp_dir().join(format!("nuvori-hello-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        vault
            .save_note(None, "Hello note", "Still encrypted", None)
            .unwrap();
        // A stand-in signer replaces the Windows Hello prompt; the file format and DPAPI are real.
        let sealed = hello::seal(vault.key_for_hello(), hello::test_signer(1)).unwrap();
        store.enable_hello(&sealed).unwrap();
        assert!(store.hello_enabled());
        drop(vault);
        let key = hello::open(&store.hello_file().unwrap(), hello::test_signer(1)).unwrap();
        let reopened = store.unlock_hello(&key).unwrap();
        assert_eq!(reopened.list_notes().unwrap()[0].body, "Still encrypted");
        drop(reopened);
        // A different Hello key cannot open the file, and the vault stays intact.
        assert!(hello::open(&store.hello_file().unwrap(), hello::test_signer(2)).is_err());
        assert!(store.is_initialized() && store.hello_enabled());
        store.disable_hello().unwrap();
        assert!(!store.hello_enabled());
        let vault = store.unlock("twelve-character-password").unwrap();
        let sealed = hello::seal(vault.key_for_hello(), hello::test_signer(1)).unwrap();
        store.enable_hello(&sealed).unwrap();
        drop(vault);
        store.reset_files().unwrap();
        assert!(!store.hello_enabled());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn legacy_hello_file_opens_once_and_is_replaced() {
        let directory = std::env::temp_dir().join(format!("nuvori-hello-legacy-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let vault = store.create("twelve-character-password").unwrap();
        let key = Zeroizing::new(*vault.key_for_hello());
        drop(vault);
        // A file from Nuvori 2.2.3 and earlier: the vault key under DPAPI only.
        fs::write(directory.join(HELLO_FILE), hello::protect_legacy_for_test(&key)).unwrap();
        assert!(store.hello_enabled());
        let saved = store.hello_file().unwrap();
        assert!(hello::is_legacy(&saved));
        assert!(store.enable_hello(&saved).is_err(), "a legacy file is never saved again");
        let legacy_key = hello::open_legacy(&saved).unwrap();
        drop(store.unlock_hello(&legacy_key).unwrap());
        // The upgrade the unlock command performs right after.
        store.enable_hello(&hello::seal(&legacy_key, hello::test_signer(1)).unwrap()).unwrap();
        let upgraded = store.hello_file().unwrap();
        assert!(!hello::is_legacy(&upgraded));
        assert_eq!(*hello::open(&upgraded, hello::test_signer(1)).unwrap(), *key);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reset_removes_only_this_vault_after_password_check() {
        let directory = std::env::temp_dir().join(format!("nuvori-reset-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        vault
            .save_note(None, "Delete me", "Local content", None)
            .unwrap();
        drop(vault);
        assert!(matches!(
            store.verify_password("wrong-password-123"),
            Err(VaultError::WrongPasswordOrCorruptKey)
        ));
        assert!(store.is_initialized());
        store.verify_password("twelve-character-password").unwrap();
        store.reset_files().unwrap();
        assert!(!store.is_initialized());
        let fresh = store.create("another-long-password").unwrap();
        assert!(fresh.list_notes().unwrap().is_empty());
        drop(fresh);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn previous_local_notes_are_backfilled_once() {
        let directory =
            std::env::temp_dir().join(format!("nuvori-note-upgrade-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        vault.connection().execute(
            "INSERT INTO local_notes (id, title, body, created_at, updated_at) VALUES ('old-note', 'Old', 'Existing content', 123, 456)",
            [],
        ).unwrap();
        drop(vault);

        let vault = store.unlock("twelve-character-password").unwrap();
        assert_eq!(vault.list_notes().unwrap()[0].body, "Existing content");
        assert_eq!(ChangeStore::operation_count(&vault.connection).unwrap(), 1);
        drop(vault);
        let vault = store.unlock("twelve-character-password").unwrap();
        assert_eq!(ChangeStore::operation_count(&vault.connection).unwrap(), 1);
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_change_does_not_edit_visible_note() {
        let directory = std::env::temp_dir().join(format!("nuvori-note-atomic-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let note = vault.save_note(None, "First", "Original", None).unwrap();
        vault
            .connection()
            .execute_batch(
                "CREATE TRIGGER reject_new_operation BEFORE INSERT ON sync_operations
             BEGIN SELECT RAISE(ABORT, 'simulated operation failure'); END;",
            )
            .unwrap();

        assert!(matches!(
            vault.save_note(Some(&note.id), "Changed", "New contents", None),
            Err(VaultError::Store(StoreError::Sqlite(_)))
        ));
        assert_eq!(vault.list_notes().unwrap()[0].body, "Original");
        assert_eq!(ChangeStore::operation_count(vault.connection()).unwrap(), 1);
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_update_preserves_the_entry_and_rejects_stale_approval() {
        use sha2::{Digest, Sha256};
        let directory = std::env::temp_dir().join(format!("nuvori-browser-update-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let entry = vault.save_entry(serde_json::json!({
            "type": "PASSWORD", "title": "Personal account", "primaryValue": "alice",
            "secondaryValue": "old-secret", "tertiaryValue": "https://example.com",
            "notes": "Keep these notes", "favorite": true
        })).unwrap();
        let id = entry["id"].as_str().unwrap();
        let old_hash: [u8; 32] = Sha256::digest(b"old-secret").into();
        assert!(vault.review_browser_login("https://example.com", "alice", "new-secret").is_err());
        assert_eq!(vault.local_change_count().unwrap(), 1);
        assert!(vault.update_browser_login("https://other.example.com", id, "alice", "new-secret", &old_hash).is_err());
        vault.save_entry(serde_json::json!({"id": id, "type": "PASSWORD", "title": "Personal account", "secondaryValue": "edited-in-app"})).unwrap();
        assert!(matches!(vault.update_browser_login("https://example.com", id, "alice", "new-secret", &old_hash), Err(VaultError::BrowserLoginConflict)));
        assert_eq!(vault.selected_login(id, "https://example.com").unwrap().unwrap().1, "edited-in-app");
        let fresh_hash: [u8; 32] = Sha256::digest(b"edited-in-app").into();
        vault.update_browser_login("https://example.com", id, "alice", "new-secret", &fresh_hash).unwrap();
        let saved = vault.list_entries().unwrap().remove(0);
        for field in ["id", "title", "notes", "favorite", "createdAt", "primaryValue", "tertiaryValue", "groupIds"] { assert_eq!(saved[field], entry[field], "{field}"); }
        assert_eq!(saved["secondaryValue"], "new-secret");
        assert_eq!(vault.local_change_count().unwrap(), 3);
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn password_only_and_titled_browser_logins_match_only_their_own_username() {
        use sha2::{Digest, Sha256};
        let directory = std::env::temp_dir().join(format!("nuvori-browser-title-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        assert!(vault.save_new_browser_login("https://example.com", "alice", "alice-secret", Some("  Work mail  ")).unwrap());
        assert!(vault.save_new_browser_login("https://example.com", "", "pin-secret", None).unwrap());
        let logins = vault.matching_logins("https://example.com").unwrap();
        let titles: BTreeMap<String, String> = logins.iter().map(|(_, title, user)| (user.clone(), title.clone())).collect();
        assert_eq!(titles["alice"], "Work mail");
        assert_eq!(titles[""], "example.com");
        // Same password-only capture again is already saved; a new password conflicts only with
        // the empty-username login, never with alice's.
        assert!(!vault.review_browser_login("https://example.com", "", "pin-secret").unwrap());
        assert!(matches!(vault.review_browser_login("https://example.com", "", "alice-secret"), Err(VaultError::BrowserLoginConflict)));
        assert!(matches!(vault.review_browser_login("https://example.com", "", "new-pin"), Err(VaultError::BrowserLoginConflict)));
        assert!(vault.review_browser_login("https://example.com", "bob", "pin-secret").unwrap());
        let empty_id = logins.iter().find(|(_, _, user)| user.is_empty()).unwrap().0.clone();
        let alice_id = logins.iter().find(|(_, _, user)| user == "alice").unwrap().0.clone();
        let alice_hash: [u8; 32] = Sha256::digest(b"alice-secret").into();
        assert!(matches!(vault.update_browser_login("https://example.com", &alice_id, "", "new-pin", &alice_hash), Err(VaultError::BrowserLoginConflict)));
        let pin_hash: [u8; 32] = Sha256::digest(b"pin-secret").into();
        vault.update_browser_login("https://example.com", &empty_id, "", "new-pin", &pin_hash).unwrap();
        assert_eq!(vault.selected_login(&alice_id, "https://example.com").unwrap().unwrap().1, "alice-secret");
        assert!(matches!(vault.save_new_browser_login("https://example.com", "carol", "x", Some("Bad\u{7}title")), Err(VaultError::InvalidEntry)));
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn browser_login_save_is_origin_bound_and_does_not_overwrite_passwords() {
        let directory = std::env::temp_dir().join(format!("nuvori-browser-save-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        assert!(vault.save_new_browser_login("https://example.com", "alice", "first-secret", None).unwrap());
        assert_eq!(vault.local_change_count().unwrap(), 1);
        assert!(!vault.save_new_browser_login("https://example.com", "alice", "first-secret", None).unwrap());
        assert_eq!(vault.local_change_count().unwrap(), 1);
        assert!(matches!(vault.save_new_browser_login("https://example.com", "alice", "new-secret", None), Err(VaultError::BrowserLoginConflict)));
        assert!(matches!(vault.save_new_browser_login("https://example.com.evil.test", "  ", "secret", None), Err(VaultError::InvalidEntry)));
        assert!(vault.matching_logins("https://example.com.evil.test").unwrap().is_empty());
        assert_eq!(vault.matching_logins("https://example.com").unwrap()[0].2, "alice");
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn login_entry_uses_android_fields_and_signed_change_history() {
        let directory = std::env::temp_dir().join(format!("nuvori-entry-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let created = vault
            .save_entry(serde_json::json!({
                "type": "PASSWORD", "title": "Example", "primaryValue": "alice",
                "secondaryValue": "secret", "tertiaryValue": "https://example.com"
            }))
            .unwrap();
        assert_eq!(created["type"], "PASSWORD");
        assert_eq!(created["cardKind"], "CREDIT");
        assert_eq!(
            vault.matching_logins("https://example.com").unwrap().len(),
            1
        );
        assert!(
            vault
                .matching_logins("https://login.example.com")
                .unwrap()
                .is_empty()
        );
        assert!(
            vault
                .selected_login(created["id"].as_str().unwrap(), "https://login.example.com")
                .unwrap()
                .is_none()
        );
        assert_eq!(vault.entry_counts().unwrap()["PASSWORD"], 1);
        assert_eq!(ChangeStore::operation_count(vault.connection()).unwrap(), 1);
        let id = created["id"].as_str().unwrap();
        let changed = vault
            .save_entry(serde_json::json!({
                "id": id, "type": "PASSWORD", "title": "Example renamed"
            }))
            .unwrap();
        assert_eq!(changed["secondaryValue"], "secret");
        assert_eq!(ChangeStore::operation_count(vault.connection()).unwrap(), 2);
        assert!(matches!(
            vault.save_entry(serde_json::json!({
                "id": id, "type": "CARD", "title": "Wrong type", "primaryValue": "1234"
            })),
            Err(VaultError::InvalidEntry)
        ));
        drop(vault);

        let mut vault = store.unlock("twelve-character-password").unwrap();
        assert_eq!(vault.list_entries().unwrap()[0]["title"], "Example renamed");
        vault.delete_entry(id).unwrap();
        assert!(vault.list_entries().unwrap().is_empty());
        assert_eq!(ChangeStore::operation_count(vault.connection()).unwrap(), 3);
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn entry_photos_are_encrypted_database_data_and_do_not_change_signed_history() {
        let directory = std::env::temp_dir().join(format!("nuvori-entry-photo-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let entry = vault
            .save_entry(serde_json::json!({
                "type": "CARD", "title": "Travel card", "primaryValue": "4111111111111111"
            }))
            .unwrap();
        let entry_id = entry["id"].as_str().unwrap();
        let image = base64::engine::general_purpose::STANDARD.encode(b"\x89PNG\r\n\x1a\nphoto");
        vault
            .add_entry_photo(entry_id, "image/png", &image)
            .unwrap();
        assert_eq!(vault.list_entry_photos(entry_id).unwrap().len(), 1);
        assert_eq!(ChangeStore::operation_count(vault.connection()).unwrap(), 1);
        assert!(matches!(
            vault.add_entry_photo(entry_id, "image/png", "YWJj"),
            Err(VaultError::InvalidPhoto)
        ));
        drop(vault);

        let database = fs::read(directory.join(DATABASE_FILE)).unwrap();
        assert!(!database.windows(5).any(|window| window == b"photo"));
        let mut vault = store.unlock("twelve-character-password").unwrap();
        let photos = vault.list_entry_photos(entry_id).unwrap();
        assert_eq!(photos.len(), 1);
        vault.delete_entry(entry_id).unwrap();
        assert!(vault.list_entry_photos(entry_id).is_err());
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn folder_membership_is_saved_in_the_signed_entry_and_survives_reopen() {
        let directory = std::env::temp_dir().join(format!("nuvori-folders-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let folder = vault
            .save_group(None, "Work", "Shared work items", "PASSWORD")
            .unwrap();
        let entry = vault
            .save_entry(serde_json::json!({
                "type": "PASSWORD", "title": "Work account", "secondaryValue": "secret",
                "groupIds": [folder.id]
            }))
            .unwrap();
        assert_eq!(entry["groupIds"], serde_json::json!([folder.id]));
        let id = entry["id"].as_str().unwrap().to_owned();
        let group_id = folder.id.clone();
        let operation: (String, String, String, String, String, String, i64, String) = vault.connection().query_row(
            "SELECT vault_id, device_id, mutation_id, occurred_at_utc, payload_ciphertext, payload_nonce, sequence, previous_hash
             FROM sync_operations WHERE entity_type = 'entry' AND entity_id = ?1", [&id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?))
        ).unwrap();
        let change = ChangeRecord::create(
            operation.0,
            operation.1.clone(),
            operation.6 as u64,
            operation.7,
            operation.2,
            "entry",
            &id,
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([(&operation.1, 1)]),
            operation.3,
            operation.4,
            operation.5,
            "",
        );
        let payload: serde_json::Value =
            serde_json::from_slice(&payload::decrypt(&vault.key, &change).unwrap()).unwrap();
        assert_eq!(payload["groupIds"], serde_json::json!([group_id]));
        drop(vault);
        let mut vault = store.unlock("twelve-character-password").unwrap();
        assert_eq!(
            vault.list_entries().unwrap()[0]["groupIds"],
            serde_json::json!([group_id])
        );
        assert!(matches!(
            vault.save_entry(serde_json::json!({
                "type": "CARD", "title": "Wrong category", "primaryValue": "4111",
                "groupIds": [group_id]
            })),
            Err(VaultError::InvalidEntry)
        ));
        let notes_folder = vault.save_group(None, "Private notes", "", "NOTE").unwrap();
        let note = vault
            .save_note(
                None,
                "Plan",
                "Keep this",
                Some(vec![notes_folder.id.clone()]),
            )
            .unwrap();
        assert_eq!(
            vault.list_notes().unwrap()[0].group_ids,
            vec![notes_folder.id.clone()]
        );
        assert!(matches!(
            vault.save_note(
                Some(&note.id),
                "Plan",
                "Keep this",
                Some(vec![group_id.clone()])
            ),
            Err(VaultError::InvalidNote)
        ));
        vault.delete_group(&group_id).unwrap();
        assert_eq!(
            vault.list_entries().unwrap()[0]["groupIds"],
            serde_json::json!([])
        );
        assert_eq!(
            vault.list_notes().unwrap()[0].group_ids,
            vec![notes_folder.id]
        );
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn logins_with_passkeys_marks_only_the_same_account_on_a_matching_site() {
        use p256::{
            SecretKey,
            pkcs8::{EncodePrivateKey, EncodePublicKey},
        };
        let directory = std::env::temp_dir().join(format!("nuvori-passkey-mark-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let mut login = |title: &str, username: &str, url: &str| {
            vault.save_entry(serde_json::json!({
                "type": "PASSWORD", "title": title, "primaryValue": username,
                "secondaryValue": "secret", "tertiaryValue": url
            })).unwrap()["id"].as_str().unwrap().to_owned()
        };
        let same_account = login("GitHub", "Dev@Example.com ", "https://github.com/login");
        let subdomain = login("GitHub gist", "dev@example.com", "https://gist.github.com");
        let bare_host = login("GitHub bare", "dev@example.com", "github.com");
        let other_account = login("GitHub work", "work@example.com", "https://github.com");
        let other_site = login("GitLab", "dev@example.com", "https://gitlab.com");
        let lookalike = login("Fake", "dev@example.com", "https://notgithub.com");
        let plain_http = login("Old", "dev@example.com", "http://github.com");
        let linked = vault.save_entry(serde_json::json!({
            "type": "PASSWORD", "title": "Linked on the phone", "primaryValue": "dev@example.com",
            "secondaryValue": "secret", "tertiaryValue": "", "autofillOrigins": "https://other.example\nhttps://github.com"
        })).unwrap()["id"].as_str().unwrap().to_owned();
        assert!(vault.logins_with_passkeys().unwrap().is_empty(), "no passkeys, no marks");

        let secret = SecretKey::from_slice(&[9; 32]).unwrap();
        vault.save_passkey(VaultPasskey {
            id: URL_SAFE_NO_PAD.encode([7; 32]),
            rp_id: "github.com".to_owned(),
            user_handle: URL_SAFE_NO_PAD.encode([3; 16]),
            username: "dev@example.com".to_owned(),
            display_name: "Dev".to_owned(),
            private_key: URL_SAFE_NO_PAD.encode(secret.to_pkcs8_der().unwrap().as_bytes()),
            public_key: URL_SAFE_NO_PAD.encode(secret.public_key().to_public_key_der().unwrap().as_bytes()),
            created_at: 100,
        }).unwrap();

        let marked = vault.logins_with_passkeys().unwrap();
        assert!(marked.contains(&same_account), "username case and outer spaces do not matter");
        assert!(marked.contains(&subdomain), "an RP ID covers its subdomains");
        assert!(marked.contains(&bare_host), "a website saved without https:// still counts");
        assert!(marked.contains(&linked), "an origin linked on Android counts like the saved website");
        for id in [&other_account, &other_site, &lookalike, &plain_http] {
            assert!(!marked.contains(id));
        }
        assert_eq!(marked.len(), 4);
    }

    #[test]
    fn passkey_private_key_stays_encrypted_and_deletion_has_a_tombstone() {
        use p256::{
            SecretKey,
            pkcs8::{EncodePrivateKey, EncodePublicKey},
        };
        let directory = std::env::temp_dir().join(format!("nuvori-passkey-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let secret = SecretKey::from_slice(&[9; 32]).unwrap();
        let key = VaultPasskey {
            id: URL_SAFE_NO_PAD.encode([7; 32]),
            rp_id: "example.com".to_owned(),
            user_handle: URL_SAFE_NO_PAD.encode([3; 16]),
            username: "alice".to_owned(),
            display_name: "Alice".to_owned(),
            private_key: URL_SAFE_NO_PAD.encode(secret.to_pkcs8_der().unwrap().as_bytes()),
            public_key: URL_SAFE_NO_PAD
                .encode(secret.public_key().to_public_key_der().unwrap().as_bytes()),
            created_at: 100,
        };
        vault.save_passkey(key.clone()).unwrap();
        assert_eq!(vault.list_passkeys().unwrap()[0].rp_id, "example.com");
        assert!(matches!(
            vault.save_passkey(key.clone()),
            Err(VaultError::PasskeyAlreadyExists)
        ));
        assert_eq!(ChangeStore::operation_count(vault.connection()).unwrap(), 1);
        drop(vault);
        let bytes = fs::read(directory.join(DATABASE_FILE)).unwrap();
        assert!(
            !bytes
                .windows(key.private_key.len())
                .any(|bytes| bytes == key.private_key.as_bytes())
        );
        let mut vault = store.unlock("twelve-character-password").unwrap();
        vault.delete_passkey(&key.id).unwrap();
        assert!(vault.list_passkeys().unwrap().is_empty());
        let tombstones: i64 = vault
            .connection()
            .query_row(
                "SELECT count(*) FROM sync_tombstones WHERE entity_type = 'passkey'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tombstones, 1);
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    /// C1: checking the master password (card codes, Windows Hello, reset) opens no second unlocked
    /// vault, so the keys of a rotated epoch stay loaded, and writes keep the newest epoch.
    #[test]
    fn verifying_the_password_keeps_the_rotated_keys_of_the_unlocked_vault() {
        let directory = std::env::temp_dir().join(format!("nuvori-c1-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let vault = store.create("synthetic-test-password").unwrap();
        let vault_id: String = vault.connection.query_row("SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get(0)).unwrap();
        vault.connection.execute_batch(crate::epoch_keys::SCHEMA).unwrap();
        vault.connection.execute("INSERT INTO sync_epoch_keys VALUES (?1, 2, ?2, ?3)", params![vault_id, &[7u8; 32][..], &[8u8; 32][..]]).unwrap();
        crate::epoch_keys::load(&vault.connection, &vault.keyring).unwrap();
        store.verify_password("synthetic-test-password").unwrap();
        assert!(store.verify_password("wrong").is_err());
        assert_eq!(crate::epoch_keys::content_key(&vault_id, 2).map(|key| *key), Some([7; 32]));
        let payload = payload::encrypt_in(&vault.connection, &[1; 32], "entry", &vault_id, "m", "e", b"{}").unwrap();
        assert!(payload.nonce.starts_with("e2."));
        drop(vault);
        assert!(crate::epoch_keys::content_key(&vault_id, 2).is_none(), "locking releases them");
        std::fs::remove_dir_all(directory).ok();
    }
}
