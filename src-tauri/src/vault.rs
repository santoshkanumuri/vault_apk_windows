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

const BOOTSTRAP_VERSION: u16 = 1;
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
}

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

    pub fn enable_hello(&self, key: &[u8; 32]) -> Result<(), VaultError> {
        let wrapped = hello::protect(key).map_err(VaultError::Hello)?;
        fs::write(self.directory.join(HELLO_FILE), wrapped)?;
        Ok(())
    }

    pub fn disable_hello(&self) -> Result<(), VaultError> {
        let path = self.directory.join(HELLO_FILE);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn unlock_hello(&self) -> Result<UnlockedVault, VaultError> {
        let wrapped = fs::read(self.directory.join(HELLO_FILE))?;
        let key = Zeroizing::new(hello::unprotect(&wrapped).map_err(VaultError::Hello)?);
        self.open_with_key(&key)
    }

    pub fn verify_password(&self, password: &str) -> Result<(), VaultError> {
        drop(self.unlock(password)?);
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
        let salt: [u8; 16] = random_array()?;
        let nonce: [u8; 12] = random_array()?;
        let wrapping_key = Zeroizing::new(derive(password, &salt)?);
        let wrapped = Aes256Gcm::new_from_slice(&*wrapping_key)
            .expect("32-byte key")
            .encrypt(Nonce::from_slice(&nonce), vault_key.as_ref())
            .map_err(|_| VaultError::KeyWrappingFailed);
        let wrapped = wrapped?;
        let bootstrap = VaultBootstrap {
            format_version: BOOTSTRAP_VERSION,
            salt: URL_SAFE_NO_PAD.encode(salt),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            wrapped_key: URL_SAFE_NO_PAD.encode(wrapped),
        };

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
        })
    }

    pub fn unlock(&self, password: &str) -> Result<UnlockedVault, VaultError> {
        let bootstrap: VaultBootstrap =
            serde_json::from_slice(&fs::read(self.directory.join(BOOTSTRAP_FILE))?)?;
        if bootstrap.format_version != BOOTSTRAP_VERSION {
            return Err(VaultError::UnsupportedBootstrap(bootstrap.format_version));
        }
        let salt: [u8; 16] = decode_array(&bootstrap.salt)?;
        let nonce: [u8; 12] = decode_array(&bootstrap.nonce)?;
        let wrapped = URL_SAFE_NO_PAD.decode(&bootstrap.wrapped_key)?;
        let wrapping_key = Zeroizing::new(derive(password, &salt)?);
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
        self.open_with_key(&key)
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
        };
        vault.backfill_independent_history()?;
        // Local housekeeping only; a failure here must not block unlocking.
        let _ = vault.sweep_orphan_photos();
        let _ = vault.publish_unsynced_photos();
        Ok(vault)
    }
}

impl UnlockedVault {
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
        transaction.commit()?;
        // Shared photo blobs are encrypted with the group's content key, which is gone now.
        let _ = self.blobs.remove_all();
        self.backfill_independent_history()
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

    pub fn change_revision(&self) -> Result<u64, VaultError> {
        let count: i64 = self.connection.query_row("SELECT (SELECT count(*) FROM sync_operations) + (SELECT count(*) FROM sync_applied_operations) + (SELECT count(*) FROM sync_membership_events)", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    pub fn local_change_count(&self) -> Result<u32, VaultError> {
        if !self.identity_store.exists() {
            return Ok(0);
        }
        let device_id = self.identity_store.get_or_create()?.device_id;
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM sync_operations
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
            "SELECT id, title, body, created_at, updated_at FROM local_notes ORDER BY updated_at DESC, id",
        )?;
        let notes = statement.query_map([], |row| {
            Ok(LocalNote {
                id: row.get(0)?,
                title: row.get(1)?,
                body: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                group_ids: Vec::new(),
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
        let title = title.trim();
        let body = body.trim();
        if title.is_empty() || body.is_empty() || title.len() > 500 || body.len() > 1_048_576 {
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
            }
        } else {
            LocalNote {
                id: Uuid::new_v4().to_string(),
                title: title.to_owned(),
                body: body.to_owned(),
                created_at: now,
                updated_at: now,
                group_ids: group_ids.clone(),
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
                    })
                },
            )
            .optional()?
            .ok_or(VaultError::NoteNotFound)?;
        self.write_note_change(&note, ChangeKind::Delete, |transaction| {
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
        let (hash, size) = self.create_photo_blob(&photo_id, &data)?;
        let payload = photo_payload(&photo_id, entry_id, !has_cover, added_at, &hash, size);
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
        let secret = crate::membership_exit::transport_epoch_secret(&secret, &verified.vault_id, verified.key_epoch)
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
        self.leave_locally(true)?;
        if !keep_items {
            self.clear_local_items()?;
        }
        exit::store_pending_leave(&self.connection, &PendingLeave {
            request,
            signature,
            transport_secret: Zeroizing::new(secret),
            address,
        })?;
        Ok(())
    }

    /// Empties this vault after leaving so it can join another group with nothing to merge.
    /// The master password, Windows Hello, device identity, and pending leave notice stay.
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
    pub(crate) fn leave_after_removal(&mut self, by: &str, at: i64) -> Result<(), VaultError> {
        self.leave_locally(false)?;
        crate::membership_exit::record_removed(&self.connection, by, at)?;
        crate::membership_exit::clear_pending_leave(&self.connection)?;
        Ok(())
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

    fn create_photo_blob(&self, photo_id: &str, data: &[u8]) -> Result<(String, u64), VaultError> {
        let key = self.sync_content_key()?.ok_or(VaultError::NotSharing)?;
        let vault_id: String =
            self.connection
                .query_row("SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get(0))?;
        self.blobs
            .create(&*key, &vault_id, photo_id, data)
            .map_err(|_| VaultError::InvalidPhoto)
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
            let (hash, size) = self.create_photo_blob(&photo_id, &data)?;
            let added_at = if added_at > 0 { added_at } else { now_millis()? };
            let payload = photo_payload(&photo_id, &entry_id, is_cover, added_at, &hash, size);
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

    /// Logins saved for another page of the same site ("related_logins"), for listing and filling
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
    pub fn browser_cards(&self) -> Result<Vec<(String, String, String)>, VaultError> {
        Ok(self.entries_of_type("CARD")?.iter().filter_map(|entry| {
            let digits = browser::card_digits(entry["primaryValue"].as_str()?);
            let last4 = digits.get(digits.len().saturating_sub(4)..).unwrap_or("");
            let network = entry["network"].as_str().filter(|network| !network.trim().is_empty())
                .map(str::to_owned).unwrap_or_else(|| browser::card_network(&digits).to_owned());
            let expiry = entry["tertiaryValue"].as_str().unwrap_or("");
            let label = [if network.is_empty() { "Card".to_owned() } else { network }, format!("•••• {last4}"), expiry.to_owned()]
                .into_iter().filter(|part| !part.trim().is_empty()).collect::<Vec<_>>().join(" · ");
            Some((entry["id"].as_str()?.to_owned(), entry["title"].as_str().unwrap_or("").to_owned(), label))
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
    pub fn browser_profiles(&self) -> Result<Vec<(String, String, String)>, VaultError> {
        Ok(self.entries_of_type("AUTOFILL")?.iter().filter_map(|entry| {
            let profile = profile_of(entry);
            let label = [&profile.name, &profile.email, &profile.city].into_iter()
                .filter(|part| !part.trim().is_empty()).cloned().collect::<Vec<_>>().join(" · ");
            Some((entry["id"].as_str()?.to_owned(), entry["title"].as_str().unwrap_or("").to_owned(), label))
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
        self.write_change("entry", &id, ChangeKind::Upsert, payload, |transaction| {
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
        let encrypted = payload::encrypt(
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
fn photo_payload(id: &str, entry_id: &str, is_cover: bool, added_at: i64, hash: &str, size: u64) -> serde_json::Value {
    serde_json::json!({"photo": {
        "id": id, "entryId": entry_id, "isCover": is_cover, "addedAt": added_at,
        "blobHash": hash, "blobSize": size
    }})
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

pub(crate) fn note_sync_json(note: &LocalNote) -> serde_json::Value {
    serde_json::json!({
        "id": note.id, "type": "NOTE", "title": note.title,
        "primaryValue": "", "secondaryValue": "", "tertiaryValue": "", "fourthValue": "",
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
        self.key.zeroize();
    }
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
    connection.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key)))?;
    connection.query_row("PRAGMA cipher_version", [], |_| Ok(()))?;
    connection.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
    Ok(connection)
}

fn derive(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], VaultError> {
    let params = Params::new(65_536, 3, 1, Some(32))
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
        assert_eq!(vault.browser_cards().unwrap(), vec![(card_id.to_owned(), "Travel".to_owned(), "Visa · •••• 1111 · 7/29".to_owned())]);
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
        assert_eq!(vault.browser_profile(&profiles[0].0).unwrap().unwrap().postal_code, "411001");
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    use super::*;
    use crate::identity::verify_signature;

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
        store.enable_hello(vault.key_for_hello()).unwrap();
        assert!(store.hello_enabled());
        drop(vault);
        let reopened = store.unlock_hello().unwrap();
        assert_eq!(reopened.list_notes().unwrap()[0].body, "Still encrypted");
        drop(reopened);
        store.disable_hello().unwrap();
        assert!(!store.hello_enabled());
        let vault = store.unlock("twelve-character-password").unwrap();
        store.enable_hello(vault.key_for_hello()).unwrap();
        drop(vault);
        store.reset_files().unwrap();
        assert!(!store.hello_enabled());
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
}
