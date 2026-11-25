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
    join_match::{GroupItems, JoinSummary, Match},
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
        Self::read_with(input, pairing_key, expected_vault_id, local, peer, false)
    }

    /// [`Self::read`]; `host_merges` when the phone announced `merge-join-v1` (it may send a lineage).
    pub fn read_with<R: Read>(
        input: &mut R,
        pairing_key: &[u8; 32],
        expected_vault_id: &str,
        local: &DeviceIdentity,
        peer: &DeviceIdentity,
        host_merges: bool,
    ) -> Result<Self, ImportError> {
        let metadata = snapshot::read_metadata_with(input, pairing_key, expected_vault_id, local, peer, host_merges)?;
        if metadata.membership.manager_device_id != peer.device_id {
            return Err(ImportError::Mismatch);
        }
        let backup = portable_backup::read_portable_backup(input, &metadata.vault_id)?;
        // Every check of the content runs here, before this PC sends `ready`: the phone stores this
        // PC's ADD on `ready`, so a refusal after it would leave a member that never syncs.
        if let Err(error) = validate_snapshot(&metadata, &backup) {
            crate::epoch_keys::forget(&metadata.vault_id);
            return Err(error);
        }
        Ok(Self { metadata, backup })
    }

    /// Call only after the host sends `commit` over the authenticated pairing channel.
    pub fn commit_empty(self, connection: &mut Connection) -> Result<(), ImportError> {
        commit_empty(connection, self.metadata, self.backup)
    }

    /// Adds this PC's items to the group's vault in one transaction: new items under fresh IDs,
    /// without the ones the group already has (`migrate_inventory`). Returns what happened.
    pub fn commit_preserving_local(
        self,
        connection: &mut Connection,
        identity_store: &DeviceIdentityStore,
    ) -> Result<JoinSummary, ImportError> {
        self.commit_joining(connection, identity_store, false)
    }

    /// With `host_merges` (the phone announced `merge-join-v1`) this PC's items keep their IDs and
    /// are merged by ID (`merge_inventory`), and a PC still in a group whose managing phone it
    /// marked as lost may join (it leaves that group in the same transaction). A copy of the vault
    /// file is saved first (`merge_join::backup_before_join`).
    pub fn commit_joining(
        self,
        connection: &mut Connection,
        identity_store: &DeviceIdentityStore,
        host_merges: bool,
    ) -> Result<JoinSummary, ImportError> {
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
        let current_vault: String = connection
            .query_row("SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get(0))
            .optional()?
            .unwrap_or_default();
        let frozen = host_merges && crate::merge_join::lost_freeze(connection, &current_vault)?.is_some();
        if host_merges && let Some(path) = connection.path().filter(|path| !path.is_empty()).map(std::path::PathBuf::from) {
            let now = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).map_err(|_| ImportError::Clock)?;
            crate::merge_join::backup_before_join(connection, &path, now).map_err(|_| ImportError::LocalBackup)?;
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
        if (already_enrolled || membership_rows != 0) && !frozen {
            return Err(ImportError::NotEmpty);
        }
        // What this PC knew of the group it leaves, read before anything is deleted.
        let old = if host_merges {
            let versions = if frozen { crate::merge_join::current_versions(&transaction)? } else { Vec::new() };
            if frozen && !versions.is_empty() {
                crate::merge_join::save_lineage(&transaction, &current_vault, &versions, &inventory_digests(&inventory))?;
            }
            Some(OldGroup {
                vault_id: current_vault.clone(),
                member: frozen,
                versions: versions.iter().map(|(kind, id, version, _)| ((kind.clone(), id.clone()), version.clone())).collect(),
                lineage: if frozen { None } else { crate::merge_join::saved_lineage(&transaction)? },
            })
        } else {
            None
        };
        if frozen {
            // Leave the frozen group on this PC: its sync state goes, this PC's items stay. The
            // identity stays too: the new group just added it.
            for table in [
                "sync_received_operations", "sync_applied_operations", "sync_exchange_state", "sync_peer_endpoints",
                "sync_peer_acknowledgements", "sync_peer_progress", "sync_attachment_manifests", "sync_device_heads",
                "sync_operations", "sync_memberships", "sync_membership_events", "sync_group_state",
                "site_icon_sync_state", "sync_epoch_keys", "sync_key_packages", "sync_key_statements",
            ] {
                let exists: bool = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)", [table], |row| row.get(0))?;
                if exists {
                    transaction.execute(&format!("DELETE FROM {table}"), [])?;
                }
            }
        }
        crate::merge_join::clear_lost(&transaction)?;
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
        let summary = match &old {
            Some(old) => merge_inventory(&transaction, inventory, &self.metadata, &self.backup, identity_store, &identity, old)?,
            None => migrate_inventory(&transaction, inventory, &self.metadata, &self.backup, identity_store, &identity)?,
        };
        transaction.commit()?;
        adopt_appearance(&self.metadata);
        adopt_site_icons(connection, &self.metadata);
        adopt_sign_in_methods(connection, &self.metadata);
        Ok(summary)
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
    adopt_appearance(&metadata);
    adopt_site_icons(connection, &metadata);
    adopt_sign_in_methods(connection, &metadata);
    Ok(())
}

/// The group's appearance change a joining device adopts (`appearance::snapshot_choice`).
fn appearance_choice(metadata: &VerifiedSnapshotMetadata) -> Option<(&ChangeRecord, String, String)> {
    let operations: Vec<&ChangeRecord> = metadata
        .operations
        .iter()
        .filter(|operation| operation.entity_type == crate::appearance::ENTITY_TYPE)
        .collect();
    crate::appearance::snapshot_choice(&operations, &*metadata.content_key)
}

/// After the commit: a joining device shows the group's appearance. Best effort: the next
/// appearance change reaches this device through sync anyway.
fn adopt_appearance(metadata: &VerifiedSnapshotMetadata) {
    if let Some(store) = crate::appearance::installed()
        && let Some((operation, accent, surface)) = appearance_choice(metadata)
        && let Err(error) = crate::appearance::adopt_from_snapshot(store, operation, accent, surface)
    {
        crate::activity::diagnostic(crate::activity::Category::Pairing, "Could not save the group's appearance", error);
    }
}

/// The change each site icon entity settles on (`site_icon_sync::snapshot_choices`).
fn site_icon_choices(metadata: &VerifiedSnapshotMetadata) -> Vec<(&ChangeRecord, String, Vec<u8>)> {
    let operations: Vec<&ChangeRecord> = metadata
        .operations
        .iter()
        .filter(|operation| operation.entity_type == crate::site_icon_sync::ENTITY_TYPE)
        .collect();
    crate::site_icon_sync::snapshot_choices(&operations, &*metadata.content_key)
}

/// After the commit: a joining device shows the group's website icons. Best effort, as for the
/// appearance: a later icon change reaches this device through sync anyway.
fn adopt_site_icons(connection: &Connection, metadata: &VerifiedSnapshotMetadata) {
    if let Err(error) = crate::site_icon_sync::adopt_from_snapshot(connection, &site_icon_choices(metadata)) {
        crate::activity::diagnostic(crate::activity::Category::Pairing, "Could not save the group's website icons", error);
    }
}

/// What each sign-in method entity settles on (`sign_in_sync::snapshot_choices`).
fn sign_in_choices(metadata: &VerifiedSnapshotMetadata) -> Vec<crate::sign_in_sync::SnapshotChoice<'_>> {
    let operations: Vec<&ChangeRecord> = metadata
        .operations
        .iter()
        .filter(|operation| operation.entity_type == crate::sign_in_sync::ENTITY_TYPE)
        .collect();
    crate::sign_in_sync::snapshot_choices(&operations, &*metadata.content_key)
}

/// After the commit: a joining device takes the group's sign-in methods, merged with its own. Best effort:
/// a later change of a method reaches this device through sync anyway.
fn adopt_sign_in_methods(connection: &Connection, metadata: &VerifiedSnapshotMetadata) {
    match crate::sign_in_sync::adopt_from_snapshot(connection, &*metadata.content_key, &sign_in_choices(metadata)) {
        Ok(()) => crate::sign_ins::notify_changed(),
        Err(error) => crate::activity::diagnostic(crate::activity::Category::Pairing, "Could not save the group's sign-in methods", error),
    }
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
    // A change of a rotated epoch N decrypts only with K(N) (`payload::key_for` reads the keyring),
    // and the snapshot brings those keys. Before this, every such change failed here.
    for (epoch, content, secret) in &metadata.epoch_keys {
        crate::epoch_keys::install(&metadata.vault_id, *epoch, content, secret);
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
    let icon_choices = site_icon_choices(metadata);
    let sign_in_choices = sign_in_choices(metadata);
    for record in &metadata.records {
        let key = (record.entity_type.as_str(), record.entity_id.as_str());
        if key == (crate::appearance::ENTITY_TYPE, crate::appearance::ENTITY_ID) {
            // Keep the group's version (it may be a merge of concurrent changes) with the change
            // that holds its value; the value itself goes to appearance.json after the commit.
            if let Some((operation, ..)) = appearance_choice(metadata) {
                current_records.push((record, operation));
            }
            continue;
        }
        if key.0 == crate::site_icon_sync::ENTITY_TYPE {
            // Keep the group's version with the change that holds the icon; the icon itself is
            // stored after the commit (`adopt_site_icons`).
            if let Some((operation, ..)) = icon_choices.iter().find(|(operation, ..)| operation.entity_id == key.1) {
                current_records.push((record, *operation));
            }
            continue;
        }
        if key.0 == crate::sign_in_sync::ENTITY_TYPE {
            // Keep the group's version with the latest writer's change of a live method; the rows
            // themselves are stored after the commit (`adopt_sign_in_methods`).
            if let Some(choice) = sign_in_choices.iter().find(|choice| choice.entity_id == key.1 && choice.method.is_some()) {
                current_records.push((record, choice.operation));
            }
            continue;
        }
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
    // The base of a checkpoint join: changes below these heads are missing on purpose, not lost.
    if let Some(checkpoint) = &metadata.checkpoint {
        crate::change_store::save_checkpoint(transaction, &metadata.vault_id, &serde_json::to_string(checkpoint)?)?;
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
        // A sign-in method used again after its delete has a live record: that one counts.
        if tombstone.entity_type == crate::sign_in_sync::ENTITY_TYPE
            && metadata.records.iter().any(|record| record.entity_type == tombstone.entity_type && record.entity_id == tombstone.entity_id)
        {
            continue;
        }
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
    // Keys of rotated epochs: stored, and into memory so this PC writes with the newest (`epoch_keys.rs`).
    transaction.execute_batch(crate::epoch_keys::SCHEMA)?;
    transaction.execute("DELETE FROM sync_epoch_keys", [])?;
    transaction.execute("DELETE FROM sync_key_packages", [])?;
    for (epoch, content, secret) in &metadata.epoch_keys {
        transaction.execute(
            "INSERT INTO sync_epoch_keys (vault_id, epoch, content_key, transport_secret) VALUES (?1, ?2, ?3, ?4)",
            params![metadata.vault_id, *epoch as i64, &content[..], &secret[..]],
        )?;
        crate::epoch_keys::install(&metadata.vault_id, *epoch, content, secret);
    }
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

/// What a join does with one of this PC's notes or entries (`join_match.rs`).
enum Plan {
    /// The group has the same item: this PC's copy is dropped. Links point at the group's item.
    Same(String),
    /// The group has another version: it stays, and this PC's version goes to Recently deleted.
    Review(String),
    /// New to the group: added under this new ID.
    New(String),
}

impl Plan {
    /// The ID that links (folders, a login's code) point at after the join.
    fn id(&self) -> &str {
        match self {
            Plan::Same(id) | Plan::Review(id) | Plan::New(id) => id,
        }
    }
}

/// True when every photo of this PC's item is already on the group's item, byte for byte.
fn photos_covered(inventory: &MigrationInventory, backup: &PortableBackup, local_id: &str, group_id: &str) -> bool {
    inventory.photos.iter().filter(|photo| photo.entry_id == local_id).all(|photo| {
        backup.photos.iter().any(|theirs| theirs.metadata.entry_id == group_id && *theirs.bytes == *photo.data)
    })
}

/// Adds this PC's items to the group's vault. An item the group already has is not added twice,
/// and an item the group has in another version is kept in Recently deleted for review. New
/// items and folders are signed as this PC's own changes, so they sync like any edit.
fn migrate_inventory(
    transaction: &Transaction<'_>,
    inventory: MigrationInventory,
    metadata: &VerifiedSnapshotMetadata,
    backup: &PortableBackup,
    identity_store: &DeviceIdentityStore,
    identity: &DeviceIdentity,
) -> Result<JoinSummary, ImportError> {
    crate::local_recovery::initialize(transaction)?;
    let now = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| ImportError::Clock)?;
    let mut summary = JoinSummary::default();
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
    // A folder with the same name, type and notes as one of the group's is that folder.
    let mut group_ids = HashMap::new();
    let mut new_groups = HashSet::new();
    for group in &inventory.groups {
        let existing = backup.groups.iter().find(|theirs| {
            theirs["name"].as_str().map(str::trim) == Some(group.name.trim())
                && theirs["folderType"].as_str() == Some(group.folder_type.as_str())
                && theirs["notes"].as_str().map(str::trim) == Some(group.notes.trim())
        });
        let id = match existing.and_then(|theirs| theirs["id"].as_str()) {
            Some(id) => id.to_owned(),
            None => {
                new_groups.insert(group.id.clone());
                new_id(&mut used_ids)
            }
        };
        if group_ids.insert(group.id.clone(), id).is_some() {
            return Err(ImportError::Mismatch);
        }
    }
    let notes: Vec<Value> = inventory
        .notes
        .iter()
        .map(|note| {
            note.details.clone().unwrap_or_else(|| {
                vault::note_sync_json(&VaultNote {
                    id: note.id.clone(),
                    title: note.title.clone(),
                    body: note.body.clone(),
                    created_at: note.created_at,
                    updated_at: note.updated_at,
                    group_ids: vec![],
                    rich: String::new(),
                })
            })
        })
        .collect();
    let group_items = GroupItems::new(&backup.entries);
    let mut plans: HashMap<String, Plan> = HashMap::new();
    for (id, item) in inventory
        .notes
        .iter()
        .map(|note| note.id.as_str())
        .zip(&notes)
        .chain(inventory.entries.iter().map(|entry| (entry["id"].as_str().unwrap_or_default(), entry)))
    {
        let has_photos = inventory.photos.iter().any(|photo| photo.entry_id == id);
        // Recently deleted keeps no photos, so an item with photos is never set aside there.
        let plan = match group_items.find(item) {
            Match::Same(theirs) if photos_covered(&inventory, backup, id, &theirs) => Plan::Same(theirs),
            Match::Differs(theirs) if !has_photos => Plan::Review(theirs),
            _ => Plan::New(new_id(&mut used_ids)),
        };
        if id.is_empty() || plans.insert(id.to_owned(), plan).is_some() {
            return Err(ImportError::Mismatch);
        }
    }
    let entry_ids: HashMap<String, String> =
        plans.iter().map(|(old, plan)| (old.clone(), plan.id().to_owned())).collect();
    let mut head = metadata
        .heads
        .iter()
        .find(|head| head.device_id == identity.device_id)
        .map(|head| (head.sequence, head.hash.clone()))
        .unwrap_or((0, GENESIS_HASH.to_owned()));

    for group in inventory.groups.iter().filter(|group| new_groups.contains(&group.id)) {
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
        let mut links: Vec<String> = Vec::new();
        for link in inventory.links.iter().filter(|link| link.entry_id == old_id) {
            let id = group_ids.get(&link.group_id).ok_or(ImportError::Mismatch)?;
            // Two of this PC's folders can be one of the group's.
            if !links.contains(id) {
                links.push(id.clone());
            }
        }
        Ok(links)
    };
    for (note, mut entry) in inventory.notes.iter().zip(notes) {
        let group_links = links_for(&note.id)?;
        let id = match plans.get(&note.id).ok_or(ImportError::Mismatch)? {
            Plan::Same(_) => {
                summary.already_there += 1;
                continue;
            }
            Plan::Review(_) => {
                let copy = serde_json::json!({"title": note.title, "body": note.body});
                crate::local_recovery::keep_join_copy(transaction, &note.id, "note", "NOTE", &note.title, &copy, &group_links, now)?;
                summary.needs_review += 1;
                continue;
            }
            Plan::New(id) => id,
        };
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
        summary.added += 1;
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
        let group_links = links_for(&old_id)?;
        let linked = text(&entry, "linkedAuthenticatorId")?.to_owned();
        if !linked.is_empty() {
            entry["linkedAuthenticatorId"] = entry_ids
                .get(&linked)
                .ok_or(ImportError::Mismatch)?
                .clone()
                .into();
        }
        let id = match plans.get(&old_id).ok_or(ImportError::Mismatch)? {
            Plan::Same(theirs) => {
                // This PC's previous passwords for the login stay with the group's copy.
                crate::local_recovery::move_history(transaction, &old_id, theirs)?;
                summary.already_there += 1;
                continue;
            }
            Plan::Review(_) => {
                // Its previous passwords stay under the old ID; a restore moves them along.
                let kind = text(&entry, "type")?.to_owned();
                let title = text(&entry, "title")?.to_owned();
                crate::local_recovery::keep_join_copy(transaction, &old_id, "entry", &kind, &title, &entry, &group_links, now)?;
                summary.needs_review += 1;
                continue;
            }
            Plan::New(id) => id,
        };
        entry["id"] = id.clone().into();
        transaction.execute(
            "INSERT INTO local_entries (id, type, data_json, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                id,
                text(&entry, "type")?,
                serde_json::to_string(&entry)?,
                number(&entry, "updatedAt")?
            ],
        )?;
        crate::local_recovery::move_history(transaction, &old_id, id)?;
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
        summary.added += 1;
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
            summary.already_there += 1;
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
        summary.added += 1;
    }
    for photo in &inventory.photos {
        // Only a new item takes its photos; the group's copy of a same item already has them.
        let Some(Plan::New(entry_id)) = plans.get(&photo.entry_id) else {
            continue;
        };
        let id = new_id(&mut used_ids);
        transaction.execute(
            "INSERT INTO local_entry_photos (id, entry_id, mime_type, data) VALUES (?1, ?2, ?3, ?4)",
            params![id, entry_id, photo.mime_type, &*photo.data],
        )?;
    }
    Ok(summary)
}

/// What this PC knew of the group it leaves by a merge join: its ID, whether this PC was still a
/// member (marked its manager as lost), its versions, and the lineage it kept from an earlier leave.
pub(crate) struct OldGroup {
    pub vault_id: String,
    pub member: bool,
    pub versions: HashMap<(String, String), String>,
    pub lineage: Option<(String, Vec<crate::merge_join::LineageRow>)>,
}

/// This PC's entries (notes included), folders and passkeys as sync JSON: (ID, entry, is a note).
fn inventory_items(inventory: &MigrationInventory) -> Vec<(String, Value, bool)> {
    inventory
        .notes
        .iter()
        .map(|note| {
            let json = note.details.clone().unwrap_or_else(|| {
                vault::note_sync_json(&VaultNote {
                    id: note.id.clone(),
                    title: note.title.clone(),
                    body: note.body.clone(),
                    created_at: note.created_at,
                    updated_at: note.updated_at,
                    group_ids: vec![],
                    rich: String::new(),
                })
            });
            (note.id.clone(), json, true)
        })
        .chain(inventory.entries.iter().map(|entry| (entry["id"].as_str().unwrap_or_default().to_owned(), entry.clone(), false)))
        .collect()
}

/// The content digest of each of this PC's items now (`merge_join::content_digest`), with an
/// entry's own folder IDs: what a lineage row keeps, and what a later merge join compares it with.
pub(crate) fn inventory_digests(inventory: &MigrationInventory) -> HashMap<(String, String), String> {
    let mut digests = HashMap::new();
    for (id, entry, _) in inventory_items(inventory) {
        let mut links: Vec<String> = inventory.links.iter().filter(|link| link.entry_id == id).map(|link| link.group_id.clone()).collect();
        links.sort();
        digests.insert(("entry".to_owned(), id), crate::merge_join::content_digest("entry", &entry_payload(&entry, &links)));
    }
    for group in &inventory.groups {
        digests.insert(("group".to_owned(), group.id.clone()), crate::merge_join::content_digest("group", &group_payload(group)));
    }
    for passkey in &inventory.passkeys {
        digests.insert(("passkey".to_owned(), passkey.id.clone()),
            crate::merge_join::content_digest("passkey", &serde_json::json!({"passkey": passkey})));
    }
    digests
}

/// Payload-shaped copies, as `merge_join::same_content` compares them.
fn entry_payload(entry: &Value, groups: &[String]) -> Value {
    serde_json::json!({"entry": entry, "groupIds": groups})
}

fn group_payload(group: &migration_inventory::LocalGroup) -> Value {
    serde_json::json!({"group": {"id": group.id, "name": group.name, "notes": group.notes, "folderType": group.folder_type}})
}

/// The ID-preserving merge join (`merge_join.rs`). Each of this PC's items with the same ID as the
/// group's follows `merge_join::decide`; an item with another ID is matched by account as before
/// (`join_match.rs`) and otherwise added under its own ID. An item that differs becomes a conflict:
/// this PC signs its copy with a fresh version, so every device shows both copies for review.
#[allow(clippy::too_many_arguments)]
fn merge_inventory(
    transaction: &Transaction<'_>,
    inventory: MigrationInventory,
    metadata: &VerifiedSnapshotMetadata,
    backup: &PortableBackup,
    identity_store: &DeviceIdentityStore,
    identity: &DeviceIdentity,
    old: &OldGroup,
) -> Result<JoinSummary, ImportError> {
    use crate::merge_join::{self, HostState, Outcome};
    crate::local_recovery::initialize(transaction)?;
    let now = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| ImportError::Clock)?;
    let detected = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| ImportError::Clock)?;
    let lineage = metadata.lineage.as_ref();
    let via_membership = lineage.is_some_and(|lineage| old.member && lineage.from_vault_id == old.vault_id);
    let via_lineage = lineage.is_some_and(|lineage| old.lineage.as_ref().is_some_and(|(from, _)| *from == lineage.from_vault_id));
    let shared = via_membership || via_lineage;
    let joiner_old = |kind: &str, id: &str| -> Option<RecordVersion> {
        let json = if via_membership {
            old.versions.get(&(kind.to_owned(), id.to_owned())).cloned()
        } else if via_lineage {
            old.lineage.as_ref().and_then(|(_, rows)| rows.iter().find(|row| row.0 == kind && row.1 == id).map(|row| row.2.clone()))
        } else {
            None
        };
        json.and_then(|json| serde_json::from_str(&json).ok())
    };
    // Through saved lineage the old version is from when this PC left: it counts only while the item
    // is still the copy it had then (M3). A missing digest counts as edited.
    let current_digests = if via_lineage && !via_membership { inventory_digests(&inventory) } else { HashMap::new() };
    let joiner_unchanged = |kind: &str, id: &str| -> bool {
        via_membership || !via_lineage || old.lineage.as_ref()
            .and_then(|(_, rows)| rows.iter().find(|row| row.0 == kind && row.1 == id))
            .is_some_and(|row| !row.3.is_empty() && current_digests.get(&(kind.to_owned(), id.to_owned())) == Some(&row.3))
    };
    let records: HashMap<(&str, &str), &SnapshotRecordState> =
        metadata.records.iter().map(|record| ((record.entity_type.as_str(), record.entity_id.as_str()), record)).collect();
    let tombstones: HashMap<(&str, &str), &crate::snapshot::SnapshotTombstone> =
        metadata.tombstones.iter().map(|tombstone| ((tombstone.entity_type.as_str(), tombstone.entity_id.as_str()), tombstone)).collect();
    let host_entries: HashMap<&str, &Value> = backup.entries.iter().filter_map(|entry| Some((entry["id"].as_str()?, entry))).collect();
    let host_groups: HashMap<&str, &Value> = backup.groups.iter().filter_map(|group| Some((group["id"].as_str()?, group))).collect();
    let host_passkeys: HashMap<&str, &crate::passkeys::VaultPasskey> = backup.passkeys.iter().map(|key| (key.id.as_str(), key)).collect();
    let mut host_links: HashMap<&str, Vec<String>> = HashMap::new();
    for link in &backup.links {
        if let (Some(entry), Some(group)) = (link["entryId"].as_str(), link["groupId"].as_str()) {
            host_links.entry(entry).or_default().push(group.to_owned());
        }
    }
    let lineage_versions: HashMap<(&str, &str), RecordVersion> = lineage
        .map(|lineage| lineage.records.iter().chain(&lineage.tombstones)
            .filter_map(|row| Some(((row.entity_type.as_str(), row.entity_id.as_str()), serde_json::from_str(&row.record_version_json).ok()?)))
            .collect())
        .unwrap_or_default();
    let known = |kind: &str, id: &str| -> bool { tombstones.contains_key(&(kind, id)) || lineage_versions.contains_key(&(kind, id)) };
    let host_state = |kind: &str, id: &str, present: bool| {
        if present { HostState::Present } else if tombstones.contains_key(&(kind, id)) { HostState::Deleted } else { HostState::Absent }
    };
    let outcome = |kind: &str, id: &str, mine: &Value, theirs: Option<Value>| -> Outcome {
        let same = theirs.as_ref().is_some_and(|theirs| merge_join::same_content(kind, mine, theirs));
        merge_join::decide(same, host_state(kind, id, theirs.is_some()), shared, joiner_old(kind, id).as_ref(),
            lineage_versions.get(&(kind, id)), joiner_unchanged(kind, id))
    };
    let mut summary = JoinSummary::default();
    let mut head = metadata
        .heads
        .iter()
        .find(|head| head.device_id == identity.device_id)
        .map(|head| (head.sequence, head.hash.clone()))
        .unwrap_or((0, GENESIS_HASH.to_owned()));

    // Signs this PC's copy as a conflict with the group's: a fresh version, CONCURRENT everywhere.
    // False when the group's copy has no signed version here; the caller then keeps the group's.
    let sign_conflict = |head: &mut (u64, String), kind: &str, id: &str, present: bool, payload: &Value| -> Result<bool, ImportError> {
        let Some(record) = records.get(&(kind, id)) else { return Ok(false) };
        let host_version: RecordVersion = serde_json::from_str(&record.record_version_json)?;
        // The group's side: the change that holds its copy, or its delete.
        let remote = if present {
            metadata
                .operations
                .iter()
                .find(|operation| operation.entity_type == kind && operation.entity_id == id && operation.record_version == host_version)
                .map(|operation| operation.hash.clone())
        } else {
            tombstones
                .get(&(kind, id))
                .filter(|tombstone| serde_json::from_str::<RecordVersion>(&tombstone.record_version_json).is_ok_and(|version| version == host_version))
                .map(|tombstone| tombstone.change_hash.clone())
        };
        let Some(remote) = remote else { return Ok(false) };
        let mine = host_version.counters().get(&identity.device_id).copied().unwrap_or(0).checked_add(1).ok_or(ImportError::Mismatch)?;
        let version = RecordVersion::new([(identity.device_id.clone(), mine)].into_iter().collect());
        if version.relation_to(&host_version) != VersionRelation::Concurrent {
            return Ok(false);
        }
        let operation = sign_merged_upsert(transaction, metadata, identity_store, identity, head, kind, id, payload, &version, record.revision)?;
        transaction.execute(
            "INSERT INTO sync_conflicts (conflict_id, entity_type, entity_id, local_change_hash, remote_change_hash,
             local_version_json, remote_version_json, detected_at_utc, resolved_at_utc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '')",
            params![Uuid::new_v4().to_string(), kind, id, operation.hash, remote,
                serde_json::to_string(&version)?, record.record_version_json, detected],
        )?;
        Ok(true)
    };

    // Folders: by ID, else a folder with the same name, type and notes is that folder.
    let mut group_ids: HashMap<String, String> = HashMap::new();
    let mut final_groups: HashSet<String> = host_groups.keys().map(|id| (*id).to_owned()).collect();
    for group in &inventory.groups {
        let payload = group_payload(group);
        let theirs = host_groups.get(group.id.as_str()).map(|value| serde_json::json!({"group": value}));
        let by_id = theirs.is_some() || known("group", &group.id);
        let named = (!by_id).then(|| backup.groups.iter().find(|theirs| {
            theirs["name"].as_str().map(str::trim) == Some(group.name.trim())
                && theirs["folderType"].as_str() == Some(group.folder_type.as_str())
                && theirs["notes"].as_str().map(str::trim) == Some(group.notes.trim())
        }).and_then(|theirs| theirs["id"].as_str())).flatten();
        if let Some(id) = named {
            group_ids.insert(group.id.clone(), id.to_owned());
            continue;
        }
        let decision = outcome("group", &group.id, &payload, theirs);
        group_ids.insert(group.id.clone(), group.id.clone());
        match decision {
            Outcome::Add | Outcome::Conflict => {
                transaction.execute(
                    "INSERT OR REPLACE INTO local_groups (id, name, notes, folder_type) VALUES (?1, ?2, ?3, ?4)",
                    params![group.id, group.name, group.notes, group.folder_type],
                )?;
                final_groups.insert(group.id.clone());
                if decision == Outcome::Add {
                    sign_migrated_upsert(transaction, metadata, identity_store, identity, &mut head, "group", &group.id, &payload)?;
                } else if sign_conflict(&mut head, "group", &group.id, host_groups.contains_key(group.id.as_str()), &payload)? {
                    summary.conflicts += 1;
                } else {
                    // No reviewable conflict: keep the group's folder (or none, as the group has).
                    if let Some(theirs) = host_groups.get(group.id.as_str()) {
                        transaction.execute(
                            "INSERT OR REPLACE INTO local_groups (id, name, notes, folder_type) VALUES (?1, ?2, ?3, ?4)",
                            params![group.id, text(theirs, "name")?, text(theirs, "notes")?, text(theirs, "folderType")?],
                        )?;
                    } else {
                        transaction.execute("DELETE FROM local_groups WHERE id = ?1", [&group.id])?;
                        final_groups.remove(&group.id);
                    }
                }
            }
            Outcome::Same | Outcome::KeepHost | Outcome::Drop => {}
        }
    }

    // Entries and notes, in sync JSON.
    let mut items: Vec<(String, Value, bool)> = inventory_items(&inventory);
    // Codes first, so a login keeps its link to a code that came along.
    items.sort_by_key(|(id, entry, _)| (entry["type"] != "AUTHENTICATOR", id.clone()));
    let links_of = |id: &str| -> Vec<String> {
        let mut links: Vec<String> = Vec::new();
        for link in inventory.links.iter().filter(|link| link.entry_id == id) {
            if let Some(mapped) = group_ids.get(&link.group_id)
                && !links.contains(mapped)
            {
                links.push(mapped.clone());
            }
        }
        links.sort();
        links
    };
    let group_items = GroupItems::new(&backup.entries);
    let mut decisions: Vec<(String, Value, bool, Outcome, Option<String>)> = Vec::new();
    for (id, entry, note) in items {
        if id.is_empty() {
            return Err(ImportError::Mismatch);
        }
        let links = links_of(&id);
        let mine = entry_payload(&entry, &links);
        let theirs = host_entries.get(id.as_str()).map(|theirs| entry_payload(theirs, host_links.get(id.as_str()).map(Vec::as_slice).unwrap_or(&[])));
        if theirs.is_none() && !known("entry", &id) {
            // Another ID: the account match of an older join (same, other version, or new).
            let has_photos = inventory.photos.iter().any(|photo| photo.entry_id == id);
            match group_items.find(&entry) {
                Match::Same(theirs) if photos_covered(&inventory, backup, &id, &theirs) => {
                    decisions.push((id, entry, note, Outcome::Same, Some(theirs)));
                }
                Match::Differs(theirs) if !has_photos => decisions.push((id, entry, note, Outcome::Drop, Some(theirs))),
                _ => decisions.push((id, entry, note, Outcome::Add, None)),
            }
            continue;
        }
        let decision = outcome("entry", &id, &mine, theirs);
        decisions.push((id, entry, note, decision, None));
    }
    let final_entries: HashSet<String> = host_entries
        .keys()
        .map(|id| (*id).to_owned())
        .chain(decisions.iter().filter(|d| matches!(d.3, Outcome::Add | Outcome::Conflict)).map(|d| d.0.clone()))
        .collect();
    let host_photo_ids: HashSet<&str> = backup.photos.iter().map(|photo| photo.metadata.id.as_str()).collect();
    for (id, mut entry, note, decision, account_match) in decisions {
        let links: Vec<String> = links_of(&id).into_iter().filter(|group| final_groups.contains(group)).collect();
        let title = text(&entry, "title").unwrap_or_default().to_owned();
        let kind = if note { "note" } else { "entry" };
        let item_type = text(&entry, "type").unwrap_or("NOTE").to_owned();
        match (decision, account_match) {
            (Outcome::Same, Some(theirs)) => {
                crate::local_recovery::move_history(transaction, &id, &theirs)?;
                summary.already_there += 1;
                continue;
            }
            (Outcome::Drop, Some(_)) => {
                let copy = if note { serde_json::json!({"title": title, "body": text(&entry, "notes").unwrap_or_default()}) } else { entry.clone() };
                crate::local_recovery::keep_join_copy(transaction, &id, kind, &item_type, &title, &copy, &links, now)?;
                summary.needs_review += 1;
                continue;
            }
            (Outcome::Same, None) | (Outcome::KeepHost, _) => {
                summary.already_there += 1;
                if decision == Outcome::KeepHost {
                    continue;
                }
            }
            (Outcome::Drop, None) => {
                let copy = if note { serde_json::json!({"title": title, "body": text(&entry, "notes").unwrap_or_default()}) } else { entry.clone() };
                crate::local_recovery::keep_join_copy(transaction, &id, kind, &item_type, &title, &copy, &links, now)?;
                summary.deleted_in_group += 1;
                continue;
            }
            (Outcome::Add | Outcome::Conflict, _) => {
                let linked = text(&entry, "linkedAuthenticatorId").unwrap_or_default().to_owned();
                if !linked.is_empty() && !final_entries.contains(&linked) {
                    entry["linkedAuthenticatorId"] = "".into();
                }
                let previous_row = host_entries.get(id.as_str()).map(|value| (*value).clone());
                write_merged_entry(transaction, &id, &entry, &links)?;
                let payload = entry_payload(&entry, &links);
                if decision == Outcome::Add {
                    sign_migrated_upsert(transaction, metadata, identity_store, identity, &mut head, "entry", &id, &payload)?;
                    summary.added += 1;
                } else if sign_conflict(&mut head, "entry", &id, previous_row.is_some(), &payload)? {
                    summary.conflicts += 1;
                } else {
                    // No reviewable conflict: the group's copy stays; this PC's copy goes to Recently deleted.
                    transaction.execute("DELETE FROM local_entries WHERE id = ?1", [&id])?;
                    transaction.execute("DELETE FROM local_note_details WHERE id = ?1", [&id])?;
                    transaction.execute("DELETE FROM local_notes WHERE id = ?1", [&id])?;
                    transaction.execute("DELETE FROM entry_groups WHERE entry_id = ?1", [&id])?;
                    if let Some(theirs) = previous_row {
                        let groups = host_links.get(id.as_str()).cloned().unwrap_or_default();
                        write_merged_entry(transaction, &id, &theirs, &groups)?;
                    }
                    let copy = if note { serde_json::json!({"title": title, "body": text(&entry, "notes").unwrap_or_default()}) } else { entry.clone() };
                    crate::local_recovery::keep_join_copy(transaction, &id, kind, &item_type, &title, &copy, &links, now)?;
                    summary.needs_review += 1;
                    continue;
                }
            }
        }
        // Photos are matched by ID: one the group already has (or deleted) stays the group's. The
        // rest are signed by `UnlockedVault::publish_unsynced_photos` before the next sync.
        for photo in inventory.photos.iter().filter(|photo| photo.entry_id == id) {
            if host_photo_ids.contains(photo.id.as_str()) || tombstones.contains_key(&("photo", photo.id.as_str())) {
                continue;
            }
            transaction.execute(
                "INSERT OR IGNORE INTO local_entry_photos (id, entry_id, mime_type, data) VALUES (?1, ?2, ?3, ?4)",
                params![photo.id, id, photo.mime_type, &*photo.data],
            )?;
        }
    }

    for passkey in &inventory.passkeys {
        let mine = serde_json::json!({"passkey": passkey});
        let theirs = host_passkeys.get(passkey.id.as_str()).map(|theirs| serde_json::json!({"passkey": theirs}));
        let decision = outcome("passkey", &passkey.id, &mine, theirs);
        match decision {
            Outcome::Same | Outcome::KeepHost => summary.already_there += 1,
            Outcome::Drop => summary.deleted_in_group += 1,
            Outcome::Add | Outcome::Conflict => {
                transaction.execute(
                    "INSERT OR REPLACE INTO local_passkeys (id, rp_id, data_json) VALUES (?1, ?2, ?3)",
                    params![passkey.id, passkey.rp_id, serde_json::to_string(passkey)?],
                )?;
                if decision == Outcome::Add {
                    sign_migrated_upsert(transaction, metadata, identity_store, identity, &mut head, "passkey", &passkey.id, &mine)?;
                    summary.added += 1;
                } else if sign_conflict(&mut head, "passkey", &passkey.id, host_passkeys.contains_key(passkey.id.as_str()), &mine)? {
                    summary.conflicts += 1;
                } else if let Some(theirs) = host_passkeys.get(passkey.id.as_str()) {
                    transaction.execute(
                        "INSERT OR REPLACE INTO local_passkeys (id, rp_id, data_json) VALUES (?1, ?2, ?3)",
                        params![theirs.id, theirs.rp_id, serde_json::to_string(theirs)?],
                    )?;
                    summary.already_there += 1;
                }
            }
        }
    }
    Ok(summary)
}

/// Writes one entry or note row (notes live in their own tables) and its folder links.
fn write_merged_entry(transaction: &Transaction<'_>, id: &str, entry: &Value, links: &[String]) -> Result<(), ImportError> {
    transaction.execute("DELETE FROM entry_groups WHERE entry_id = ?1", [id])?;
    transaction.execute("DELETE FROM local_entries WHERE id = ?1", [id])?;
    transaction.execute("DELETE FROM local_note_details WHERE id = ?1", [id])?;
    transaction.execute("DELETE FROM local_notes WHERE id = ?1", [id])?;
    if text(entry, "type")? == "NOTE" {
        transaction.execute(
            "INSERT INTO local_notes (id, title, body, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, text(entry, "title")?, text(entry, "notes")?, number(entry, "createdAt")?, number(entry, "updatedAt")?],
        )?;
        transaction.execute("INSERT INTO local_note_details (id, data_json) VALUES (?1, ?2)", params![id, serde_json::to_string(entry)?])?;
    } else {
        transaction.execute(
            "INSERT INTO local_entries (id, type, data_json, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, text(entry, "type")?, serde_json::to_string(entry)?, number(entry, "updatedAt")?],
        )?;
    }
    insert_links(transaction, id, links)
}

/// [`sign_migrated_upsert`] with a given version and revision, replacing the group's record.
#[allow(clippy::too_many_arguments)]
fn sign_merged_upsert(
    transaction: &Transaction<'_>,
    metadata: &VerifiedSnapshotMetadata,
    identity_store: &DeviceIdentityStore,
    identity: &DeviceIdentity,
    head: &mut (u64, String),
    entity_type: &str,
    entity_id: &str,
    payload_json: &Value,
    version: &RecordVersion,
    revision: u64,
) -> Result<ChangeRecord, ImportError> {
    let sequence = head.0.checked_add(1).ok_or(ImportError::Mismatch)?;
    let mutation = Uuid::new_v4().to_string();
    let plaintext = Zeroizing::new(serde_json::to_vec(payload_json)?);
    let encrypted = payload::encrypt_in(transaction, &*metadata.content_key, entity_type, &metadata.vault_id, &mutation, entity_id, &plaintext)?;
    let occurred = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| ImportError::Clock)?;
    let operation = ChangeRecord::create_signed_with(
        &metadata.vault_id,
        &identity.device_id,
        sequence,
        &head.1,
        mutation,
        entity_type,
        entity_id,
        ChangeKind::Upsert,
        revision,
        version.clone(),
        occurred,
        encrypted.ciphertext,
        encrypted.nonce,
        |message| identity_store.sign(message),
    )?;
    insert_operation(transaction, &operation)?;
    transaction.execute(
        "INSERT OR REPLACE INTO vault_records (entity_type, entity_id, payload_ciphertext, revision, record_version_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![entity_type, entity_id, operation.payload_ciphertext, integer(revision + 1)?, serde_json::to_string(version)?],
    )?;
    transaction.execute(
        "INSERT INTO sync_device_heads (vault_id, device_id, sequence, hash) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(vault_id, device_id) DO UPDATE SET sequence = excluded.sequence, hash = excluded.hash",
        params![metadata.vault_id, identity.device_id, integer(sequence)?, operation.hash],
    )?;
    *head = (sequence, operation.hash.clone());
    Ok(operation)
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
    let encrypted = payload::encrypt_in(
        transaction,
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
    #[error("Nuvori could not save a backup of this PC's items before joining")]
    LocalBackup,
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
            checkpoint: None,
            lineage: None,
            epoch_keys: vec![],
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

    fn phone_login(id: &str, url: &str, user: &str, password: &str) -> Value {
        json!({"id": id, "type": "PASSWORD", "title": "Login", "primaryValue": user,
            "secondaryValue": password, "tertiaryValue": url, "fourthValue": "", "cardKind": "CREDIT",
            "network": "", "totpAlgorithm": "SHA1", "totpDigits": 6, "totpPeriod": 30, "linkedApps": "",
            "autofillSignatures": "", "autofillOrigins": "", "linkedAuthenticatorId": "", "notes": "",
            "color": 0xFF08704A_u64, "tags": "", "favorite": false, "lastOpenedAt": 0, "sortOrder": 1,
            "createdAt": 1, "updatedAt": 1})
    }

    #[test]
    fn a_join_drops_items_the_phone_has_and_sets_aside_other_versions() {
        let directory = std::env::temp_dir().join(format!("nuvori-join-match-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        // The same folder and note as the phone's backup(): dropped, nothing signed.
        let folder = vault.save_group(None, "Personal", "", "NOTE").unwrap();
        vault.save_note(None, "Phone note", "Saved on Android", Some(vec![folder.id.clone()])).unwrap();
        let same = vault.save_entry(json!({"type": "PASSWORD", "title": "Login", "primaryValue": "alice",
            "secondaryValue": "s3cret", "tertiaryValue": "https://github.com/login"})).unwrap();
        // Same site and username, another password: the phone's version stays.
        let other = vault.save_entry(json!({"type": "PASSWORD", "title": "Mail", "primaryValue": "bob",
            "secondaryValue": "pc-password", "tertiaryValue": "https://mail.example.com"})).unwrap();
        // A previous password on the PC moves with the PC's version.
        vault.save_entry(json!({"id": other["id"], "secondaryValue": "pc-password-2"})).unwrap();
        let same_id = same["id"].as_str().unwrap().to_owned();
        vault.save_entry(json!({"id": same_id, "secondaryValue": "s3cret-new"})).unwrap();
        vault.save_entry(json!({"id": same_id, "secondaryValue": "s3cret"})).unwrap();
        // Only on the PC: added and signed as before.
        vault.save_note(None, "Windows only", "Keep this", Some(vec![folder.id])).unwrap();
        let identity_store = DeviceIdentityStore::new(directory.join("device-identity-v1.json"));
        let identity = identity_store.get_or_create().unwrap();
        let mut body = backup(b"\xff\xd8\xff\xe0image".to_vec());
        body.entries.push(phone_login("login-a", "https://github.com", "alice", "s3cret"));
        body.entries.push(phone_login("login-b", "mail.example.com", "bob", "phone-password"));
        let summary = PreparedEnrollment { metadata: member_metadata(&identity), backup: body }
            .commit_preserving_local(vault.connection(), &identity_store)
            .unwrap();
        assert_eq!(summary, JoinSummary { already_there: 2, needs_review: 1, added: 1, ..Default::default() });

        let notes = vault.list_notes().unwrap();
        assert_eq!(notes.len(), 2, "the phone's note once, plus the PC-only note");
        let added = notes.iter().find(|note| note.title == "Windows only").unwrap();
        assert_eq!(added.group_ids, vec!["group-a"], "the PC's folder is the phone's folder");
        assert_eq!(vault.list_groups().unwrap().len(), 1);
        let entries = vault.list_entries().unwrap();
        assert_eq!(entries.len(), 2);
        let mail = entries.iter().find(|entry| entry["id"] == "login-b").unwrap();
        assert_eq!(mail["secondaryValue"], "phone-password");
        assert_eq!(vault.previous_passwords("login-a").unwrap().len(), 2, "PC history joins the phone's copy");
        let signed: i64 = vault.connection()
            .query_row("SELECT count(*) FROM sync_operations WHERE vault_id = 'android-vault'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(signed, 1, "only the PC-only note goes out as a change");

        let trash = vault.trashed_items().unwrap();
        assert_eq!(trash.len(), 1);
        assert_eq!((trash[0].reason.as_str(), trash[0].title.as_str(), trash[0].expires_at), ("join", "Mail", 0));
        // A join copy outlives the 30-day purge.
        crate::local_recovery::purge(vault.connection(), i64::MAX / 2).unwrap();
        assert_eq!(vault.trashed_items().unwrap().len(), 1);
        let restored = vault.restore_trashed(&trash[0].id).unwrap();
        let restored_id = restored["id"].as_str().unwrap();
        let entry = vault.list_entries().unwrap().into_iter().find(|entry| entry["id"] == restored_id).unwrap();
        assert_eq!(entry["secondaryValue"], "pc-password-2");
        assert_eq!(vault.previous_passwords(restored_id).unwrap()[0].password, "pc-password");
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn host_change(id: &str, sequence: u64, previous: &str, version: RecordVersion) -> ChangeRecord {
        let key = [7u8; 32];
        let mutation = Uuid::new_v4().to_string();
        let encrypted = crate::payload::encrypt(&key, "entry", "android-vault", &mutation, id, b"{\"entry\":{}}").unwrap();
        ChangeRecord::create_signed_with("android-vault", "phone", sequence, previous, mutation, "entry", id,
            ChangeKind::Upsert, 0, version, "2026-11-23T00:00:00Z", encrypted.ciphertext, encrypted.nonce,
            |_| Ok::<_, ImportError>([1u8; 64])).unwrap()
    }

    #[test]
    fn a_merge_join_keeps_ids_and_shows_differing_items_as_conflicts() {
        let directory = std::env::temp_dir().join(format!("nuvori-merge-join-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let login = |title: &str, user: &str, password: &str| json!({"type": "PASSWORD", "title": title,
            "primaryValue": user, "secondaryValue": password, "tertiaryValue": format!("https://{title}.example")});
        let same = vault.save_entry(login("same", "ann", "one")).unwrap();
        let newer = vault.save_entry(login("newer", "bob", "two")).unwrap();
        // This PC changed it again after the group last had it.
        vault.save_entry(json!({"id": newer["id"], "secondaryValue": "two-pc"})).unwrap();
        let older = vault.save_entry(login("older", "cat", "three")).unwrap();
        let only = vault.save_entry(login("only", "dan", "four")).unwrap();
        let deleted = vault.save_entry(login("deleted", "eve", "five")).unwrap();
        let identity_store = DeviceIdentityStore::new(directory.join("device-identity-v1.json"));
        let identity = identity_store.get_or_create().unwrap();
        let pc = identity.device_id.clone();
        let old_vault: String = vault.connection()
            .query_row("SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get(0)).unwrap();
        // "Mark as lost" on this PC for its old group.
        crate::merge_join::clear_lost(vault.connection()).unwrap();
        vault.connection().execute("INSERT INTO sync_lost_manager VALUES (?1, 'old-phone', 2, 5, ?2, 1)",
            params![old_vault, "ab".repeat(32)]).unwrap();
        let id = |value: &Value| value["id"].as_str().unwrap().to_owned();
        let entries = vault.list_entries().unwrap();
        let pc_copy = |entry_id: &str| entries.iter().find(|entry| entry["id"] == entry_id).unwrap().clone();

        // The group (the new managing phone) has: `same` as is, `newer` and `older` with other
        // passwords, no `only`, and `deleted` gone after it had this PC's version.
        let mut metadata = member_metadata(&identity);
        let v = |pairs: &[(&str, u64)]| RecordVersion::new(pairs.iter().map(|(device, counter)| ((*device).to_owned(), *counter)).collect());
        let mut body = backup(b"\xff\xd8\xff\xe0image".to_vec());
        body.entries.push(pc_copy(&id(&same)));
        let mut theirs_newer = pc_copy(&id(&newer));
        theirs_newer["secondaryValue"] = "two-phone".into();
        body.entries.push(theirs_newer);
        let mut theirs_older = pc_copy(&id(&older));
        theirs_older["secondaryValue"] = "three-phone".into();
        body.entries.push(theirs_older);
        let witness_newer = host_change(&id(&newer), 1, GENESIS_HASH, v(&[("phone", 1)]));
        let witness_older = host_change(&id(&older), 2, &witness_newer.hash, v(&[("phone", 2)]));
        for (entry_id, change) in [(id(&newer), &witness_newer), (id(&older), &witness_older)] {
            metadata.records.push(SnapshotRecordState { entity_type: "entry".into(), entity_id: entry_id,
                revision: 1, record_version_json: serde_json::to_string(&change.record_version).unwrap() });
        }
        metadata.operations = vec![witness_newer.clone(), witness_older.clone()];
        let lineage_row = |entry_id: String, version: RecordVersion| crate::merge_join::LineageRecord {
            entity_type: "entry".into(), entity_id: entry_id, record_version_json: serde_json::to_string(&version).unwrap() };
        metadata.lineage = Some(crate::merge_join::Lineage {
            from_vault_id: old_vault.clone(),
            records: vec![
                lineage_row(id(&same), v(&[(&pc, 1)])),
                lineage_row(id(&newer), v(&[(&pc, 1)])),
                lineage_row(id(&older), v(&[(&pc, 1), ("old-phone", 1)])),
            ],
            tombstones: vec![lineage_row(id(&deleted), v(&[(&pc, 1), ("old-phone", 1)]))],
        });
        let summary = PreparedEnrollment { metadata, backup: body }
            .commit_joining(vault.connection(), &identity_store, true)
            .unwrap();
        assert_eq!(summary, JoinSummary { already_there: 2, added: 1, conflicts: 1, deleted_in_group: 1, needs_review: 0 });

        let after = vault.list_entries().unwrap();
        let ids: HashSet<String> = after.iter().map(|entry| entry["id"].as_str().unwrap().to_owned()).collect();
        assert_eq!(after.len(), ids.len(), "no duplicates");
        assert_eq!(ids, [id(&same), id(&newer), id(&older), id(&only)].into_iter().collect(), "IDs are kept");
        let by_id = |entry_id: String| after.iter().find(|entry| entry["id"] == entry_id.as_str()).unwrap().clone();
        assert_eq!(by_id(id(&newer))["secondaryValue"], "two-pc", "this PC keeps its copy; both wait for review");
        assert_eq!(by_id(id(&older))["secondaryValue"], "three-phone", "the group already had this PC's copy");
        let conflict: (String, String, String) = vault.connection().query_row(
            "SELECT entity_id, local_change_hash, remote_change_hash FROM sync_conflicts WHERE resolved_at_utc = ''", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
        assert_eq!(conflict.0, id(&newer));
        assert_eq!(conflict.2, witness_newer.hash, "the group's side is its witness change");
        let (author, version): (String, String) = vault.connection().query_row(
            "SELECT device_id, record_version_json FROM sync_operations WHERE hash = ?1", [&conflict.1],
            |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!(author, pc);
        let version: RecordVersion = serde_json::from_str(&version).unwrap();
        assert_eq!(version.relation_to(&witness_newer.record_version), VersionRelation::Concurrent);
        let added: String = vault.connection().query_row(
            "SELECT entity_id FROM sync_operations WHERE vault_id = 'android-vault' AND device_id = ?1 AND entity_id = ?2",
            params![pc, id(&only)], |row| row.get(0)).unwrap();
        assert_eq!(added, id(&only), "a PC-only item is signed under its own ID");
        let trash = vault.trashed_items().unwrap();
        assert_eq!(trash.len(), 1);
        assert_eq!(trash[0].title, "deleted");
        // The freeze ended, the lineage of the old group is kept, and a backup came first.
        assert_eq!(crate::merge_join::lost_freeze(vault.connection(), &old_vault).unwrap(), None);
        assert_eq!(crate::merge_join::saved_lineage(vault.connection()).unwrap().unwrap().0, old_vault);
        let backups: Vec<_> = std::fs::read_dir(directory.join("join-backups")).unwrap().flatten().collect();
        assert_eq!(backups.len(), 1);
        let header = std::fs::read(backups[0].path()).unwrap();
        assert!(header.len() > 4096 && !header.starts_with(b"SQLite format 3"), "the backup is encrypted like the vault");
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn without_the_phone_merging_a_paired_pc_still_cannot_join_another_group() {
        let directory = std::env::temp_dir().join(format!("nuvori-merge-skew-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        vault.save_entry(json!({"type": "PASSWORD", "title": "Mail", "primaryValue": "a", "secondaryValue": "b"})).unwrap();
        let identity_store = DeviceIdentityStore::new(directory.join("device-identity-v1.json"));
        let identity = identity_store.get_or_create().unwrap();
        vault.connection().execute_batch(
            "INSERT INTO sync_group_state (vault_id, content_key, transport_secret) VALUES ('old', zeroblob(32), zeroblob(32))").unwrap();
        let old_vault: String = vault.connection()
            .query_row("SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get(0)).unwrap();
        crate::merge_join::clear_lost(vault.connection()).unwrap();
        vault.connection().execute("INSERT INTO sync_lost_manager VALUES (?1, 'old-phone', 2, 5, 'ab', 1)", [&old_vault]).unwrap();
        // An older phone (no merge-join-v1): the frozen group does not let this PC in.
        let result = PreparedEnrollment { metadata: member_metadata(&identity), backup: backup(b"\xff\xd8\xff\xe0image".to_vec()) }
            .commit_joining(vault.connection(), &identity_store, false);
        assert!(matches!(result, Err(ImportError::NotEmpty)));
        assert!(!directory.join("join-backups").exists(), "no backup without a merge");
        assert_eq!(vault.list_entries().unwrap().len(), 1, "nothing changed");
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_join_keeps_a_pc_item_whose_photos_the_phone_lacks() {
        let directory = std::env::temp_dir().join(format!("nuvori-join-photo-{}", Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let login = vault.save_entry(json!({"type": "PASSWORD", "title": "Login", "primaryValue": "alice",
            "secondaryValue": "s3cret", "tertiaryValue": "https://github.com"})).unwrap();
        vault.add_entry_photo(login["id"].as_str().unwrap(), "image/png", &STANDARD.encode(b"\x89PNG\r\n\x1a\nscan")).unwrap();
        let identity_store = DeviceIdentityStore::new(directory.join("device-identity-v1.json"));
        let identity = identity_store.get_or_create().unwrap();
        let mut body = backup(b"\xff\xd8\xff\xe0image".to_vec());
        body.entries.push(phone_login("login-a", "https://github.com", "alice", "s3cret"));
        let summary = PreparedEnrollment { metadata: member_metadata(&identity), backup: body }
            .commit_preserving_local(vault.connection(), &identity_store)
            .unwrap();
        assert_eq!(summary, JoinSummary { already_there: 0, needs_review: 0, added: 1, ..Default::default() });
        let entries = vault.list_entries().unwrap();
        assert_eq!(entries.len(), 2);
        let mine = entries.iter().find(|entry| entry["id"] != "login-a").unwrap();
        assert_eq!(vault.list_entry_photos(mine["id"].as_str().unwrap()).unwrap().len(), 1);
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
