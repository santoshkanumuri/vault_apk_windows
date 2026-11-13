//! Commits a verified Android enrollment snapshot into a SQLCipher vault.

use std::{
    collections::{HashMap, HashSet},
    io::Read,
};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::Value;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    identity::{DeviceIdentity, DeviceIdentityStore, IdentityError},
    migration_inventory::{self, InventoryError, MigrationInventory},
    payload::{self, PayloadError},
    portable_backup::{self, BackupError, PortableBackup},
    protocol::{RecordVersion, VersionRelation},
    snapshot::{self, SnapshotError, SnapshotRecordState, VerifiedSnapshotMetadata},
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
    vault::{self, LocalNote as VaultNote},
};

pub struct PreparedEnrollment {
    metadata: VerifiedSnapshotMetadata,
    backup: PortableBackup,
}

impl PreparedEnrollment {
    /// Consumes and verifies the complete snapshot before either peer sends `ready`.
    pub fn read<R: Read>(
        input: &mut R,
        pairing_key: &[u8; 32],
        expected_vault_id: &str,
        local: &DeviceIdentity,
        peer: &DeviceIdentity,
    ) -> Result<Self, ImportError> {
        let metadata = snapshot::read_metadata(input, pairing_key, expected_vault_id, local, peer)?;
        if metadata.membership.manager_device_id != peer.device_id {
            return Err(ImportError::Mismatch);
        }
        let backup = portable_backup::read_portable_backup(input, &metadata.vault_id)?;
        Ok(Self { metadata, backup })
    }

    /// Call only after the host sends `commit` over the authenticated pairing channel.
    pub fn commit_empty(self, connection: &mut Connection) -> Result<(), ImportError> {
        commit_empty(connection, self.metadata, self.backup)
    }

    /// Reissues current Windows items under fresh IDs and the new vault key in one transaction.
    pub fn commit_preserving_local(
        self,
        connection: &mut Connection,
        identity_store: &DeviceIdentityStore,
    ) -> Result<(), ImportError> {
        let (present, current_records) = validate_snapshot(&self.metadata, &self.backup)?;
        let old_changes: i64 =
            connection.query_row("SELECT count(*) FROM sync_operations", [], |row| row.get(0))?;
        if old_changes > 0 && !identity_store.exists() {
            return Err(ImportError::MissingIdentity);
        }
        let identity = identity_store.get_or_create()?;
        let member = self
            .metadata
            .membership
            .members
            .get(&identity.device_id)
            .ok_or(ImportError::Mismatch)?;
        if !member.active || member.public_key != identity.public_key {
            return Err(ImportError::Mismatch);
        }
        let transaction = connection.transaction()?;
        let inventory = migration_inventory::read(&transaction)?;
        let already_enrolled: bool =
            transaction.query_row("SELECT EXISTS(SELECT 1 FROM sync_group_state)", [], |row| {
                row.get(0)
            })?;
        let membership_rows: i64 = transaction.query_row(
            "SELECT (SELECT count(*) FROM sync_membership_events) +
                    (SELECT count(*) FROM sync_memberships)",
            [],
            |row| row.get(0),
        )?;
        if already_enrolled || membership_rows != 0 {
            return Err(ImportError::NotEmpty);
        }
        transaction.execute_batch(
            "DELETE FROM entry_groups;
             DELETE FROM local_entry_photos;
             DELETE FROM local_note_details;
             DELETE FROM local_notes;
             DELETE FROM local_entries;
             DELETE FROM local_passkeys;
             DELETE FROM local_groups;
             DELETE FROM vault_records;
             DELETE FROM sync_tombstones;
             DELETE FROM sync_conflicts;",
        )?;
        insert_snapshot(
            &transaction,
            &self.metadata,
            &self.backup,
            &present,
            current_records,
        )?;
        migrate_inventory(
            &transaction,
            inventory,
            &self.metadata,
            &self.backup,
            identity_store,
            &identity,
        )?;
        transaction.commit()?;
        Ok(())
    }
}

pub fn commit_empty(
    connection: &mut Connection,
    metadata: VerifiedSnapshotMetadata,
    backup: PortableBackup,
) -> Result<(), ImportError> {
    let (present, current_records) = validate_snapshot(&metadata, &backup)?;
    let transaction = connection.transaction()?;
    require_empty(&transaction)?;
    insert_snapshot(&transaction, &metadata, &backup, &present, current_records)?;
    transaction.commit()?;
    Ok(())
}

type CurrentRecord<'a> = (&'a SnapshotRecordState, &'a ChangeRecord);
type PresentRecords<'a> = HashSet<(&'a str, &'a str)>;

fn validate_snapshot<'a>(
    metadata: &'a VerifiedSnapshotMetadata,
    backup: &'a PortableBackup,
) -> Result<(PresentRecords<'a>, Vec<CurrentRecord<'a>>), ImportError> {
    if metadata.vault_id != backup.vault_id {
        return Err(ImportError::Mismatch);
    }
    let mut operation_by_entity: HashMap<(&str, &str), Vec<&ChangeRecord>> = HashMap::new();
    for operation in &metadata.operations {
        let mut plaintext = payload::decrypt(&*metadata.content_key, operation)?;
        plaintext.zeroize();
        operation_by_entity
            .entry((&operation.entity_type, &operation.entity_id))
            .or_default()
            .push(operation);
    }
    let present: HashSet<(&str, &str)> = backup
        .entries
        .iter()
        .map(|entry| ("entry", entry["id"].as_str().unwrap_or_default()))
        .chain(
            backup
                .groups
                .iter()
                .map(|group| ("group", group["id"].as_str().unwrap_or_default())),
        )
        .chain(
            backup
                .passkeys
                .iter()
                .map(|key| ("passkey", key.id.as_str())),
        )
        .chain(
            backup
                .photos
                .iter()
                .map(|photo| ("photo", photo.metadata.id.as_str())),
        )
        .collect();
    let mut current_records = Vec::new();
    for record in &metadata.records {
        let key = (record.entity_type.as_str(), record.entity_id.as_str());
        if !matches!(key.0, "entry" | "group" | "passkey" | "photo" | "photo_cover") {
            continue;
        }
        let matching = operation_by_entity.get(&key).and_then(|operations| {
            operations.iter().find(|operation| {
                serde_json::from_str::<RecordVersion>(&record.record_version_json)
                    .is_ok_and(|version| version == operation.record_version)
            })
        });
        // A cover record is keyed by its entry and has no row of its own; keep its version so
        // later cover changes compare correctly.
        // Photo records are kept only when they line up; a photo whose blob never reached the
        // phone has no row, and that must not block pairing.
        if matches!(key.0, "photo_cover" | "photo") {
            if let Some(operation) = matching.filter(|operation| {
                operation.kind == ChangeKind::Upsert && (key.0 == "photo_cover" || present.contains(&key))
            }) {
                current_records.push((record, *operation));
            }
            continue;
        }
        match matching {
            Some(operation) if operation.kind == ChangeKind::Upsert && present.contains(&key) => {
                current_records.push((record, *operation));
            }
            Some(operation) if operation.kind == ChangeKind::Delete && !present.contains(&key) => {}
            None if !present.contains(&key) => {}
            _ => return Err(ImportError::Mismatch),
        }
    }

    Ok((present, current_records))
}

fn require_empty(transaction: &Transaction<'_>) -> Result<(), ImportError> {
    for table in [
        "local_notes",
        "local_note_details",
        "local_entries",
        "local_entry_photos",
        "local_groups",
        "entry_groups",
        "local_passkeys",
        "vault_records",
        "sync_operations",
        "sync_device_heads",
        "sync_tombstones",
        "sync_conflicts",
        "sync_group_state",
    ] {
        let count: i64 =
            transaction.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        if count != 0 {
            return Err(ImportError::NotEmpty);
        }
    }
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS sync_membership_events (
             vault_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_json TEXT NOT NULL,
             PRIMARY KEY (vault_id, sequence)
         );
         CREATE TABLE IF NOT EXISTS sync_memberships (
             vault_id TEXT NOT NULL, device_id TEXT NOT NULL, member_json TEXT NOT NULL,
             PRIMARY KEY (vault_id, device_id)
         );",
    )?;
    for table in ["sync_membership_events", "sync_memberships"] {
        let count: i64 =
            transaction.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        if count != 0 {
            return Err(ImportError::NotEmpty);
        }
    }
    Ok(())
}

fn insert_snapshot(
    transaction: &Transaction<'_>,
    metadata: &VerifiedSnapshotMetadata,
    backup: &PortableBackup,
    present: &HashSet<(&str, &str)>,
    current_records: Vec<CurrentRecord<'_>>,
) -> Result<(), ImportError> {
    for group in &backup.groups {
        transaction.execute(
            "INSERT INTO local_groups (id, name, notes, folder_type) VALUES (?1, ?2, ?3, ?4)",
            params![
                text(group, "id")?,
                text(group, "name")?,
                text(group, "notes")?,
                text(group, "folderType")?
            ],
        )?;
    }
    for entry in &backup.entries {
        let id = text(entry, "id")?;
        let updated = number(entry, "updatedAt")?;
        if text(entry, "type")? == "NOTE" {
            transaction.execute(
                "INSERT INTO local_notes (id, title, body, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, text(entry, "title")?, text(entry, "notes")?, number(entry, "createdAt")?, updated],
            )?;
            transaction.execute(
                "INSERT INTO local_note_details (id, data_json) VALUES (?1, ?2)",
                params![id, serde_json::to_string(entry)?],
            )?;
        } else {
            transaction.execute(
                "INSERT INTO local_entries (id, type, data_json, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params![id, text(entry, "type")?, serde_json::to_string(entry)?, updated],
            )?;
        }
    }
    for link in &backup.links {
        transaction.execute(
            "INSERT INTO entry_groups (entry_id, group_id) VALUES (?1, ?2)",
            params![text(link, "entryId")?, text(link, "groupId")?],
        )?;
    }
    for passkey in &backup.passkeys {
        transaction.execute(
            "INSERT INTO local_passkeys (id, rp_id, data_json) VALUES (?1, ?2, ?3)",
            params![passkey.id, passkey.rp_id, serde_json::to_string(passkey)?],
        )?;
    }
    for photo in &backup.photos {
        transaction.execute(
            "INSERT INTO local_entry_photos (id, entry_id, mime_type, data, is_cover, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                photo.metadata.id,
                photo.metadata.entry_id,
                photo_mime(&photo.bytes)?,
                &*photo.bytes,
                photo.metadata.is_cover,
                photo.metadata.added_at
            ],
        )?;
    }
    for event in &metadata.membership_events {
        transaction.execute(
            "INSERT INTO sync_membership_events (vault_id, sequence, event_json) VALUES (?1, ?2, ?3)",
            params![event.vault_id, integer(event.sequence)?, serde_json::to_string(event)?],
        )?;
    }
    for member in &metadata.members {
        transaction.execute(
            "INSERT INTO sync_memberships (vault_id, device_id, member_json) VALUES (?1, ?2, ?3)",
            params![
                member.vault_id,
                member.device_id,
                serde_json::to_string(member)?
            ],
        )?;
    }
    for operation in &metadata.operations {
        insert_operation(transaction, operation)?;
    }
    for head in &metadata.heads {
        transaction.execute(
            "INSERT INTO sync_device_heads (vault_id, device_id, sequence, hash) VALUES (?1, ?2, ?3, ?4)",
            params![head.vault_id, head.device_id, integer(head.sequence)?, head.hash],
        )?;
    }
    for (record, operation) in current_records {
        transaction.execute(
            "INSERT INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![record.entity_type, record.entity_id, operation.payload_ciphertext,
                integer(record.revision)?, record.record_version_json],
        )?;
    }
    for tombstone in &metadata.tombstones {
        if present.contains(&(tombstone.entity_type.as_str(), tombstone.entity_id.as_str())) {
            let current = metadata
                .records
                .iter()
                .find(|record| {
                    record.entity_type == tombstone.entity_type
                        && record.entity_id == tombstone.entity_id
                })
                .ok_or(ImportError::Mismatch)?;
            let current_version: RecordVersion =
                serde_json::from_str(&current.record_version_json)?;
            let deleted_version: RecordVersion =
                serde_json::from_str(&tombstone.record_version_json)?;
            if current_version.relation_to(&deleted_version) != VersionRelation::After {
                return Err(ImportError::Mismatch);
            }
            continue;
        }
        transaction.execute(
            "INSERT INTO sync_tombstones (tombstone_id, entity_type, entity_id,
             deleted_by_device_id, delete_sequence, record_version_json, deleted_at_utc, change_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![tombstone.tombstone_id, tombstone.entity_type, tombstone.entity_id,
                tombstone.deleted_by_device_id, integer(tombstone.delete_sequence)?,
                tombstone.record_version_json, tombstone.deleted_at_utc, tombstone.change_hash],
        )?;
    }
    for conflict in &metadata.conflicts {
        transaction.execute(
            "INSERT INTO sync_conflicts (conflict_id, entity_type, entity_id, local_change_hash,
             remote_change_hash, local_version_json, remote_version_json, detected_at_utc, resolved_at_utc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![conflict.conflict_id, conflict.entity_type, conflict.entity_id,
                conflict.local_change_hash, conflict.remote_change_hash, conflict.local_version_json,
                conflict.remote_version_json, conflict.detected_at_utc, conflict.resolved_at_utc],
        )?;
    }
    transaction.execute(
        "INSERT INTO sync_group_state (vault_id, content_key, transport_secret) VALUES (?1, ?2, ?3)",
        params![metadata.vault_id, &*metadata.content_key, &*metadata.transport_secret],
    )?;
    transaction.execute(
        "UPDATE local_sync_settings SET vault_id = ?1 WHERE id = 1",
        [&metadata.vault_id],
    )?;
    Ok(())
}

fn insert_operation(
    transaction: &Transaction<'_>,
    operation: &ChangeRecord,
) -> Result<(), ImportError> {
    transaction.execute(
        "INSERT INTO sync_operations (mutation_id, format_version, vault_id, device_id,
         sequence, previous_hash, entity_type, entity_id, kind, base_revision,
         record_version_json, occurred_at_utc, payload_ciphertext, payload_nonce,
         device_signature, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            operation.mutation_id,
            operation.format_version,
            operation.vault_id,
            operation.device_id,
            integer(operation.sequence)?,
            operation.previous_hash,
            operation.entity_type,
            operation.entity_id,
            if operation.kind == ChangeKind::Upsert {
                "upsert"
            } else {
                "delete"
            },
            integer(operation.base_revision)?,
            serde_json::to_string(&operation.record_version)?,
            operation.occurred_at_utc,
            operation.payload_ciphertext,
            operation.payload_nonce,
            operation.device_signature,
            operation.hash
        ],
    )?;
    Ok(())
}

fn migrate_inventory(
    transaction: &Transaction<'_>,
    inventory: MigrationInventory,
    metadata: &VerifiedSnapshotMetadata,
    backup: &PortableBackup,
    identity_store: &DeviceIdentityStore,
    identity: &DeviceIdentity,
) -> Result<(), ImportError> {
    let mut used_ids: HashSet<String> = backup
        .entries
        .iter()
        .filter_map(|entry| entry["id"].as_str().map(str::to_owned))
        .chain(
            backup
                .groups
                .iter()
                .filter_map(|group| group["id"].as_str().map(str::to_owned)),
        )
        .chain(backup.passkeys.iter().map(|passkey| passkey.id.clone()))
        .chain(backup.photos.iter().map(|photo| photo.metadata.id.clone()))
        .collect();
    let mut group_ids = HashMap::new();
    for group in &inventory.groups {
        if group_ids
            .insert(group.id.clone(), new_id(&mut used_ids))
            .is_some()
        {
            return Err(ImportError::Mismatch);
        }
    }
    let mut entry_ids = HashMap::new();
    for id in inventory.notes.iter().map(|note| note.id.as_str()).chain(
        inventory
            .entries
            .iter()
            .filter_map(|entry| entry["id"].as_str()),
    ) {
        if entry_ids
            .insert(id.to_owned(), new_id(&mut used_ids))
            .is_some()
        {
            return Err(ImportError::Mismatch);
        }
    }
    let mut head = metadata
        .heads
        .iter()
        .find(|head| head.device_id == identity.device_id)
        .map(|head| (head.sequence, head.hash.clone()))
        .unwrap_or((0, GENESIS_HASH.to_owned()));

    for group in &inventory.groups {
        let id = group_ids.get(&group.id).ok_or(ImportError::Mismatch)?;
        transaction.execute(
            "INSERT INTO local_groups (id, name, notes, folder_type) VALUES (?1, ?2, ?3, ?4)",
            params![id, group.name, group.notes, group.folder_type],
        )?;
        let payload = serde_json::json!({"group": {"id": id, "name": group.name,
            "notes": group.notes, "folderType": group.folder_type}});
        sign_migrated_upsert(
            transaction,
            metadata,
            identity_store,
            identity,
            &mut head,
            "group",
            id,
            &payload,
        )?;
    }

    let links_for = |old_id: &str| -> Result<Vec<String>, ImportError> {
        inventory
            .links
            .iter()
            .filter(|link| link.entry_id == old_id)
            .map(|link| {
                group_ids
                    .get(&link.group_id)
                    .cloned()
                    .ok_or(ImportError::Mismatch)
            })
            .collect()
    };
    for note in &inventory.notes {
        let id = entry_ids.get(&note.id).ok_or(ImportError::Mismatch)?;
        let group_links = links_for(&note.id)?;
        let mut entry = note.details.clone().unwrap_or_else(|| {
            vault::note_sync_json(&VaultNote {
                id: note.id.clone(),
                title: note.title.clone(),
                body: note.body.clone(),
                created_at: note.created_at,
                updated_at: note.updated_at,
                group_ids: vec![],
            })
        });
        entry["id"] = id.clone().into();
        transaction.execute(
            "INSERT INTO local_notes (id, title, body, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, note.title, note.body, note.created_at, note.updated_at],
        )?;
        transaction.execute(
            "INSERT INTO local_note_details (id, data_json) VALUES (?1, ?2)",
            params![id, serde_json::to_string(&entry)?],
        )?;
        insert_links(transaction, id, &group_links)?;
        let payload = serde_json::json!({"entry": entry, "groupIds": group_links});
        sign_migrated_upsert(
            transaction,
            metadata,
            identity_store,
            identity,
            &mut head,
            "entry",
            id,
            &payload,
        )?;
    }

    let mut entries = inventory.entries;
    entries.sort_by_key(|entry| {
        if entry["type"] == "AUTHENTICATOR" {
            0
        } else {
            1
        }
    });
    for mut entry in entries {
        let old_id = text(&entry, "id")?.to_owned();
        let id = entry_ids.get(&old_id).ok_or(ImportError::Mismatch)?;
        let group_links = links_for(&old_id)?;
        let linked = text(&entry, "linkedAuthenticatorId")?.to_owned();
        entry["id"] = id.clone().into();
        if !linked.is_empty() {
            entry["linkedAuthenticatorId"] = entry_ids
                .get(&linked)
                .ok_or(ImportError::Mismatch)?
                .clone()
                .into();
        }
        transaction.execute(
            "INSERT INTO local_entries (id, type, data_json, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                id,
                text(&entry, "type")?,
                serde_json::to_string(&entry)?,
                number(&entry, "updatedAt")?
            ],
        )?;
        insert_links(transaction, id, &group_links)?;
        let payload = serde_json::json!({"entry": entry, "groupIds": group_links});
        sign_migrated_upsert(
            transaction,
            metadata,
            identity_store,
            identity,
            &mut head,
            "entry",
            id,
            &payload,
        )?;
    }
    for passkey in &inventory.passkeys {
        let stored: Option<String> = transaction
            .query_row(
                "SELECT data_json FROM local_passkeys WHERE id = ?1",
                [&passkey.id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(stored) = stored {
            if serde_json::from_str::<Value>(&stored)? != serde_json::to_value(passkey)? {
                return Err(ImportError::PasskeyCollision);
            }
            continue;
        }
        transaction.execute(
            "INSERT INTO local_passkeys (id, rp_id, data_json) VALUES (?1, ?2, ?3)",
            params![passkey.id, passkey.rp_id, serde_json::to_string(passkey)?],
        )?;
        let payload = serde_json::json!({"passkey": passkey});
        sign_migrated_upsert(
            transaction,
            metadata,
            identity_store,
            identity,
            &mut head,
            "passkey",
            &passkey.id,
            &payload,
        )?;
    }
    for photo in &inventory.photos {
        let id = new_id(&mut used_ids);
        let entry_id = entry_ids
            .get(&photo.entry_id)
            .ok_or(ImportError::Mismatch)?;
        transaction.execute(
            "INSERT INTO local_entry_photos (id, entry_id, mime_type, data) VALUES (?1, ?2, ?3, ?4)",
            params![id, entry_id, photo.mime_type, &*photo.data],
        )?;
    }
    Ok(())
}

fn new_id(used: &mut HashSet<String>) -> String {
    loop {
        let id = Uuid::new_v4().to_string();
        if used.insert(id.clone()) {
            return id;
        }
    }
}

fn insert_links(
    transaction: &Transaction<'_>,
    id: &str,
    groups: &[String],
) -> Result<(), ImportError> {
    for group in groups {
        transaction.execute(
            "INSERT INTO entry_groups (entry_id, group_id) VALUES (?1, ?2)",
            params![id, group],
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_migrated_upsert(
    transaction: &Transaction<'_>,
    metadata: &VerifiedSnapshotMetadata,
    identity_store: &DeviceIdentityStore,
    identity: &DeviceIdentity,
    head: &mut (u64, String),
    entity_type: &str,
    entity_id: &str,
    payload_json: &Value,
) -> Result<(), ImportError> {
    let sequence = head.0.checked_add(1).ok_or(ImportError::Mismatch)?;
    let mutation = Uuid::new_v4().to_string();
    let plaintext = Zeroizing::new(serde_json::to_vec(payload_json)?);
    let encrypted = payload::encrypt(
        &*metadata.content_key,
        entity_type,
        &metadata.vault_id,
        &mutation,
        entity_id,
        &plaintext,
    )?;
    let occurred = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| ImportError::Clock)?;
    let version = RecordVersion::from_entries([(&identity.device_id, 1)]);
    let operation = ChangeRecord::create_signed_with(
        &metadata.vault_id,
        &identity.device_id,
        sequence,
        &head.1,
        mutation,
        entity_type,
        entity_id,
        ChangeKind::Upsert,
        0,
        version.clone(),
        occurred,
        encrypted.ciphertext,
        encrypted.nonce,
        |message| identity_store.sign(message),
    )?;
    insert_operation(transaction, &operation)?;
    transaction.execute(
        "INSERT INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json)
         VALUES (?1, ?2, ?3, 1, ?4)",
        params![entity_type, entity_id, operation.payload_ciphertext, serde_json::to_string(&version)?],
    )?;
    transaction.execute(
        "INSERT INTO sync_device_heads (vault_id, device_id, sequence, hash) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(vault_id, device_id) DO UPDATE SET sequence = excluded.sequence, hash = excluded.hash",
        params![metadata.vault_id, identity.device_id, integer(sequence)?, operation.hash],
    )?;
    *head = (sequence, operation.hash);
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ImportError> {
    value[key].as_str().ok_or(ImportError::Mismatch)
}

fn number(value: &Value, key: &str) -> Result<i64, ImportError> {
    value[key].as_i64().ok_or(ImportError::Mismatch)
}

fn integer(value: u64) -> Result<i64, ImportError> {
    i64::try_from(value).map_err(|_| ImportError::Mismatch)
}

fn photo_mime(bytes: &[u8]) -> Result<&'static str, ImportError> {
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Ok("image/jpeg")
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Ok("image/png")
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Ok("image/webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Ok("image/gif")
    } else {
        Err(ImportError::InvalidPhoto)
    }
}

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("joining vault already contains data")]
    NotEmpty,
    #[error("snapshot body and signed state disagree")]
    Mismatch,
    #[error("existing Windows change history has no signing identity")]
    MissingIdentity,
    #[error("Windows and Android passkeys reuse a credential ID with different keys")]
    PasskeyCollision,
    #[error("system clock could not format the migrated change time")]
    Clock,
    #[error("snapshot photo format is unsupported")]
    InvalidPhoto,
    #[error("snapshot database write failed: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("snapshot JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("snapshot payload failed: {0}")]
    Payload(#[from] PayloadError),
    #[error("snapshot metadata failed: {0}")]
    Snapshot(#[from] SnapshotError),
    #[error("snapshot body failed: {0}")]
    Backup(#[from] BackupError),
    #[error("local inventory is invalid: {0}")]
    Inventory(#[from] InventoryError),
    #[error("device identity is unavailable: {0}")]
    Identity(#[from] IdentityError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        identity::DeviceIdentityStore,
        membership::VerifiedMember,
        membership::VerifiedMembership,
        portable_backup::{PhotoMetadata, PortablePhoto},
        snapshot::{SnapshotRecordState, SnapshotTombstone},
        sync::GENESIS_HASH,
        vault::VaultStore,
    };

    fn metadata() -> VerifiedSnapshotMetadata {
        VerifiedSnapshotMetadata {
            vault_id: "android-vault".to_owned(),
            content_key: Zeroizing::new([7; 32]),
            transport_secret: Zeroizing::new([8; 32]),
            membership: VerifiedMembership {
                vault_id: "android-vault".to_owned(),
                manager_device_id: "phone".to_owned(),
                key_epoch: 1,
                head: String::new(),
                members: BTreeMap::new(),
                pending_transfer: None,
                transfer_accepted: false,
            },
            members: vec![],
            membership_events: vec![],
            heads: vec![],
            records: vec![],
            operations: vec![],
            tombstones: vec![],
            conflicts: vec![],
        }
    }

    fn backup(photo: Vec<u8>) -> PortableBackup {
        PortableBackup {
            vault_id: "android-vault".to_owned(),
            entries: vec![json!({"id":"note-a", "type":"NOTE", "title":"Phone note",
                "notes":"Saved on Android", "createdAt":100, "updatedAt":200,
                "favorite":true, "color":123, "tags":"imported"})],
            groups: vec![json!({"id":"group-a", "name":"Personal", "notes":"",
                "folderType":"NOTE"})],
            links: vec![json!({"entryId":"note-a", "groupId":"group-a"})],
            passkeys: vec![],
            photos: vec![PortablePhoto {
                metadata: PhotoMetadata {
                    id: "photo-a".to_owned(),
                    entry_id: "note-a".to_owned(),
                    is_cover: true,
                    added_at: 100,
                },
                bytes: Zeroizing::new(photo),
            }],
        }
    }

    fn member_metadata(identity: &DeviceIdentity) -> VerifiedSnapshotMetadata {
        let mut incoming = metadata();
        incoming.membership.members.insert(
            identity.device_id.clone(),
            VerifiedMember {
                device_id: identity.device_id.clone(),
                public_key: identity.public_key,
                active: true,
                added_by_device_id: "phone".to_owned(),
                membership_sequence: 2,
                key_epoch: 1,
                removal_cutoff: None,
            },
        );
        incoming
    }

    #[test]
    fn imports_android_body_and_sync_keys_in_one_transaction() {
        let directory = std::env::temp_dir().join(format!("nuvori-import-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        commit_empty(
            vault.connection(),
            metadata(),
            backup(b"\xff\xd8\xff\xe0image".to_vec()),
        )
        .unwrap();
        assert_eq!(vault.list_notes().unwrap()[0].body, "Saved on Android");
        assert_eq!(vault.list_groups().unwrap()[0].name, "Personal");
        let (vault_id, key): (String, Vec<u8>) = vault
            .connection()
            .query_row(
                "SELECT vault_id, content_key FROM sync_group_state",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(vault_id, "android-vault");
        assert_eq!(key, vec![7; 32]);
        let (is_cover, added_at): (bool, i64) = vault
            .connection()
            .query_row(
                "SELECT is_cover, added_at FROM local_entry_photos WHERE id = 'photo-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((is_cover, added_at), (true, 100), "Android photo metadata survives import");
        drop(vault);
        let mut reopened = store.unlock("twelve-character-password").unwrap();
        assert_eq!(reopened.list_notes().unwrap()[0].group_ids, vec!["group-a"]);
        assert_eq!(reopened.local_change_count().unwrap(), 0);
        reopened
            .save_note(Some("note-a"), "Phone note", "Edited on Windows", None)
            .unwrap();
        let details: String = reopened
            .connection()
            .query_row(
                "SELECT data_json FROM local_note_details WHERE id = 'note-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let details: Value = serde_json::from_str(&details).unwrap();
        assert_eq!(details["favorite"], true);
        assert_eq!(details["color"], 123);
        assert_eq!(details["tags"], "imported");
        let (mutation, device, ciphertext, nonce, signature, occurred):
            (String, String, String, String, String, String) = reopened.connection().query_row(
                "SELECT mutation_id, device_id, payload_ciphertext, payload_nonce,
                        device_signature, occurred_at_utc FROM sync_operations WHERE entity_id = 'note-a'",
                [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            ).unwrap();
        let operation = ChangeRecord::create(
            "android-vault",
            &device,
            1,
            crate::sync::GENESIS_HASH,
            mutation,
            "entry",
            "note-a",
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([(&device, 1)]),
            occurred,
            ciphertext,
            nonce,
            signature,
        );
        let plain = payload::decrypt(&[7; 32], &operation).unwrap();
        let signed: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(signed["entry"]["favorite"], true);
        assert_eq!(signed["entry"]["tags"], "imported");
        assert_eq!(signed["groupIds"], json!(["group-a"]));
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn refuses_existing_items_and_rolls_back_invalid_photos() {
        let directory = std::env::temp_dir().join(format!("nuvori-import-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        assert!(matches!(
            commit_empty(
                vault.connection(),
                metadata(),
                backup(b"not-an-image".to_vec())
            ),
            Err(ImportError::InvalidPhoto)
        ));
        assert_eq!(vault.note_count().unwrap(), 0);
        vault.save_note(None, "Local", "Keep me", None).unwrap();
        assert!(matches!(
            commit_empty(
                vault.connection(),
                metadata(),
                backup(b"\xff\xd8\xff\xe0image".to_vec())
            ),
            Err(ImportError::NotEmpty)
        ));
        assert_eq!(vault.list_notes().unwrap()[0].body, "Keep me");
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn restored_entry_does_not_keep_an_obsolete_delete_tombstone() {
        let directory = std::env::temp_dir().join(format!("nuvori-import-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let mut metadata = metadata();
        let deleted = payload::encrypt(
            &[7; 32],
            "entry",
            "android-vault",
            "delete-a",
            "note-a",
            br#"{"deleted":true}"#,
        )
        .unwrap();
        let deletion = ChangeRecord::create(
            "android-vault",
            "phone",
            1,
            GENESIS_HASH,
            "delete-a",
            "entry",
            "note-a",
            ChangeKind::Delete,
            0,
            RecordVersion::from_entries([("phone", 1)]),
            "2026-09-27T00:00:00Z",
            deleted.ciphertext,
            deleted.nonce,
            "signature-a",
        );
        let restored = payload::encrypt(
            &[7; 32],
            "entry",
            "android-vault",
            "restore-a",
            "note-a",
            br#"{"entry":{"id":"note-a"},"groupIds":[]}"#,
        )
        .unwrap();
        let upsert = ChangeRecord::create(
            "android-vault",
            "phone",
            2,
            &deletion.hash,
            "restore-a",
            "entry",
            "note-a",
            ChangeKind::Upsert,
            1,
            RecordVersion::from_entries([("phone", 2)]),
            "2026-09-27T00:01:00Z",
            restored.ciphertext,
            restored.nonce,
            "signature-b",
        );
        metadata.records.push(SnapshotRecordState {
            entity_type: "entry".to_owned(),
            entity_id: "note-a".to_owned(),
            revision: 2,
            record_version_json: serde_json::to_string(&upsert.record_version).unwrap(),
        });
        metadata.tombstones.push(SnapshotTombstone {
            tombstone_id: deletion.mutation_id.clone(),
            entity_type: "entry".to_owned(),
            entity_id: "note-a".to_owned(),
            deleted_by_device_id: "phone".to_owned(),
            delete_sequence: 1,
            record_version_json: serde_json::to_string(&deletion.record_version).unwrap(),
            deleted_at_utc: deletion.occurred_at_utc.clone(),
            change_hash: deletion.hash.clone(),
        });
        metadata.operations = vec![deletion, upsert];
        commit_empty(
            vault.connection(),
            metadata,
            backup(b"\xff\xd8\xff\xe0image".to_vec()),
        )
        .unwrap();
        let tombstones: i64 = vault
            .connection()
            .query_row("SELECT count(*) FROM sync_tombstones", [], |row| row.get(0))
            .unwrap();
        assert_eq!(tombstones, 0);
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn migrates_populated_windows_notes_and_groups_without_losing_android_items() {
        let directory = std::env::temp_dir().join(format!("nuvori-migrate-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let group = vault
            .save_group(None, "Windows folder", "", "NOTE")
            .unwrap();
        let local = vault
            .save_note(None, "Windows note", "Keep this", Some(vec![group.id]))
            .unwrap();
        let identity_store = DeviceIdentityStore::new(directory.join("device-identity-v1.json"));
        let identity = identity_store.get_or_create().unwrap();
        let incoming = member_metadata(&identity);
        PreparedEnrollment {
            metadata: incoming,
            backup: backup(b"\xff\xd8\xff\xe0image".to_vec()),
        }
        .commit_preserving_local(vault.connection(), &identity_store)
        .unwrap();
        let notes = vault.list_notes().unwrap();
        assert_eq!(notes.len(), 2);
        assert!(
            notes
                .iter()
                .any(|note| note.id == "note-a" && note.body == "Saved on Android")
        );
        let migrated = notes.iter().find(|note| note.body == "Keep this").unwrap();
        assert_ne!(migrated.id, local.id);
        assert_eq!(migrated.group_ids.len(), 1);
        let groups = vault.list_groups().unwrap();
        assert_eq!(groups.len(), 2);
        assert!(
            groups
                .iter()
                .any(|group| group.id == migrated.group_ids[0] && group.name == "Windows folder")
        );
        let new_operations: i64 = vault
            .connection()
            .query_row(
                "SELECT count(*) FROM sync_operations WHERE vault_id = 'android-vault'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_operations, 2);
        let old_operations: i64 = vault
            .connection()
            .query_row(
                "SELECT count(*) FROM sync_operations WHERE vault_id != 'android-vault'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_operations, 2);
        assert_eq!(vault.local_change_count().unwrap(), 2);
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn populated_import_rolls_back_when_android_photo_is_invalid() {
        let directory = std::env::temp_dir().join(format!("nuvori-migrate-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let local = vault
            .save_note(None, "Windows note", "Keep this", None)
            .unwrap();
        let identity_store = DeviceIdentityStore::new(directory.join("device-identity-v1.json"));
        let identity = identity_store.get_or_create().unwrap();
        let result = PreparedEnrollment {
            metadata: member_metadata(&identity),
            backup: backup(b"invalid-photo".to_vec()),
        }
        .commit_preserving_local(vault.connection(), &identity_store);
        assert!(matches!(result, Err(ImportError::InvalidPhoto)));
        let notes = vault.list_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, local.id);
        assert_eq!(notes[0].body, local.body);
        assert_eq!(vault.local_change_count().unwrap(), 1);
        let vault_id: String = vault
            .connection()
            .query_row(
                "SELECT vault_id FROM local_sync_settings WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(vault_id, "android-vault");
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn populated_import_preserves_entries_links_and_photo_bytes() {
        let directory = std::env::temp_dir().join(format!("nuvori-migrate-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let folder = vault.save_group(None, "Logins", "", "PASSWORD").unwrap();
        let login = vault
            .save_entry(json!({
                "type": "PASSWORD", "title": "Example", "primaryValue": "alice",
                "secondaryValue": "secret", "tertiaryValue": "https://example.com",
                "groupIds": [folder.id]
            }))
            .unwrap();
        let old_id = login["id"].as_str().unwrap().to_owned();
        vault
            .add_entry_photo(
                &old_id,
                "image/png",
                &STANDARD.encode(b"\x89PNG\r\n\x1a\nphoto"),
            )
            .unwrap();
        let identity_store = DeviceIdentityStore::new(directory.join("device-identity-v1.json"));
        let identity = identity_store.get_or_create().unwrap();
        PreparedEnrollment {
            metadata: member_metadata(&identity),
            backup: backup(b"\xff\xd8\xff\xe0image".to_vec()),
        }
        .commit_preserving_local(vault.connection(), &identity_store)
        .unwrap();
        let entries = vault.list_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["secondaryValue"], "secret");
        let id = entries[0]["id"].as_str().unwrap();
        assert_ne!(id, old_id);
        assert_eq!(entries[0]["groupIds"].as_array().unwrap().len(), 1);
        let photos = vault.list_entry_photos(id).unwrap();
        assert_eq!(photos.len(), 1);
        assert_eq!(
            photos[0].data_url,
            format!(
                "data:image/png;base64,{}",
                STANDARD.encode(b"\x89PNG\r\n\x1a\nphoto")
            )
        );
        assert_eq!(vault.local_change_count().unwrap(), 2);
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
