//! Checkpoint enrollment (sync protocol `checkpoint-enroll-v1`, snapshot v4 `NUVSYNC4`) and the
//! keep set it shares with history compaction. Mirrors Android `SyncCheckpoint.kt`; the shared
//! vectors are `fixtures/checkpoint-v1.json` (written by the Android repository's
//! `scripts/sync-vectors/checkpoint.py`, which also describes the rules).

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    appearance::{Stamp, incoming_wins},
    identity::verify_signature,
    membership::VerifiedMembership,
    protocol::{RecordVersion, VersionRelation},
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
};

pub const FORMAT: u32 = 1;
const ORDINARY: [&str; 5] = ["entry", "group", "passkey", "photo", "photo_cover"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointHead {
    pub device_id: String,
    pub sequence: u64,
    pub hash: String,
}

/// The managing device's signed statement about a v4 snapshot. The joiner keeps it as its base.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    pub format: u32,
    pub vault_id: String,
    pub issuer_device_id: String,
    pub membership_count: u64,
    pub membership_head: String,
    pub created_at: i64,
    pub heads: Vec<CheckpointHead>,
    pub operations_digest: String,
    pub records_digest: String,
    pub tombstones_digest: String,
    pub conflicts_digest: String,
    pub signature: String,
}

impl Checkpoint {
    /// UTF-8 lines, each ending with a newline; nothing is JSON-canonicalized.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut heads: Vec<&CheckpointHead> = self.heads.iter().filter(|head| head.sequence > 0).collect();
        heads.sort_by(|left, right| left.device_id.as_bytes().cmp(right.device_id.as_bytes()));
        let mut text = format!(
            "nuvori-checkpoint-v1\n{}\n{}\n{}\n{}\n{}\nheads {}\n",
            self.vault_id,
            self.issuer_device_id,
            self.membership_count,
            self.membership_head,
            self.created_at,
            heads.len()
        );
        for head in heads {
            text.push_str(&format!("{}:{}:{}\n", head.device_id, head.sequence, head.hash));
        }
        text.push_str(&format!(
            "ops {}\nrecords {}\ntombstones {}\nconflicts {}\n",
            self.operations_digest, self.records_digest, self.tombstones_digest, self.conflicts_digest
        ));
        text.into_bytes()
    }
}

/// What the keep set and the digests need of a record state, a tombstone and a conflict.
pub struct RecordRef<'a> {
    pub entity_type: &'a str,
    pub entity_id: &'a str,
    pub revision: u64,
    pub version: RecordVersion,
}

pub struct TombstoneRef<'a> {
    pub entity_type: &'a str,
    pub entity_id: &'a str,
    pub change_hash: &'a str,
}

pub struct ConflictRef<'a> {
    pub conflict_id: &'a str,
    pub local_change_hash: &'a str,
    pub remote_change_hash: &'a str,
    pub resolved: bool,
}

/// A held change without its payload.
#[derive(Clone, Debug)]
pub struct HeldChange {
    pub device_id: String,
    pub sequence: u64,
    pub hash: String,
    pub entity_type: String,
    pub entity_id: String,
    pub delete: bool,
    pub version: RecordVersion,
    pub occurred_at_utc: String,
}

impl HeldChange {
    pub fn of(change: &ChangeRecord) -> Self {
        HeldChange {
            device_id: change.device_id.clone(),
            sequence: change.sequence,
            hash: change.hash.clone(),
            entity_type: change.entity_type.clone(),
            entity_id: change.entity_id.clone(),
            delete: change.kind == ChangeKind::Delete,
            version: change.record_version.clone(),
            occurred_at_utc: change.occurred_at_utc.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Digests {
    pub operations: String,
    pub records: String,
    pub tombstones: String,
    pub conflicts: String,
}

fn digest(mut lines: Vec<String>) -> String {
    lines.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    hex(&Sha256::digest(lines.join("\n").as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `dev=n,dev=n`, sorted by device ID.
pub fn canonical_version(version: &RecordVersion) -> String {
    version
        .counters()
        .iter()
        .map(|(device, counter)| format!("{device}={counter}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn digests(operation_hashes: &[&str], records: &[RecordRef], tombstones: &[TombstoneRef], conflicts: &[ConflictRef]) -> Digests {
    Digests {
        operations: digest(operation_hashes.iter().map(|hash| (*hash).to_owned()).collect()),
        records: digest(
            records
                .iter()
                .map(|r| format!("{}\t{}\t{}\t{}", r.entity_type, r.entity_id, r.revision, canonical_version(&r.version)))
                .collect(),
        ),
        tombstones: digest(tombstones.iter().map(|t| format!("{}\t{}\t{}", t.entity_type, t.entity_id, t.change_hash)).collect()),
        conflicts: digest(
            conflicts
                .iter()
                .filter(|c| !c.resolved)
                .map(|c| format!("{}\t{}\t{}", c.conflict_id, c.local_change_hash, c.remote_change_hash))
                .collect(),
        ),
    }
}

/// The hashes of the changes a device must keep (rules 1 to 5 of the keep set).
pub fn keep_set(changes: &[HeldChange], records: &[RecordRef], tombstones: &[TombstoneRef], conflicts: &[ConflictRef]) -> HashSet<String> {
    let mut kept = HashSet::new();
    // 1. Head witnesses.
    let mut heads: HashMap<&str, &HeldChange> = HashMap::new();
    for change in changes {
        let head = heads.entry(&change.device_id).or_insert(change);
        if change.sequence > head.sequence {
            *head = change;
        }
    }
    kept.extend(heads.values().map(|change| change.hash.clone()));
    let states: HashMap<(&str, &str), &RecordVersion> =
        records.iter().map(|r| ((r.entity_type, r.entity_id), &r.version)).collect();
    let deleted: HashSet<(&str, &str)> = tombstones.iter().map(|t| (t.entity_type, t.entity_id)).collect();
    let mut by_entity: BTreeMap<(&str, &str), Vec<&HeldChange>> = BTreeMap::new();
    for change in changes {
        by_entity.entry((&change.entity_type, &change.entity_id)).or_default().push(change);
    }
    // 2 and 5. Entity witnesses, or everything when nothing explains the state.
    for (key, group) in by_entity {
        let entity_type = key.0;
        if entity_type == crate::appearance::ENTITY_TYPE || entity_type == crate::site_icon_sync::ENTITY_TYPE {
            if let Some(winner) = last_writer(&group) {
                kept.insert(winner.hash.clone());
            }
        } else if entity_type == crate::sign_in_sync::ENTITY_TYPE {
            // Merged, never a conflict: every change no other change of the entity includes, upserts
            // and deletes, so a joiner can merge them again (`sign_in_sync::snapshot_choices`).
            kept.extend(
                group
                    .iter()
                    .filter(|change| {
                        !group.iter().any(|other| other.hash != change.hash && change.version.relation_to(&other.version) == VersionRelation::Before)
                    })
                    .map(|change| change.hash.clone()),
            );
        } else if entity_type == "device_name" {
            let mut newest: HashMap<&str, &HeldChange> = HashMap::new();
            for change in &group {
                let entry = newest.entry(&change.device_id).or_insert(change);
                if change.sequence > entry.sequence {
                    *entry = change;
                }
            }
            kept.extend(newest.values().map(|change| change.hash.clone()));
        } else if ORDINARY.contains(&entity_type) {
            match states.get(&key) {
                None if deleted.contains(&key) => {}
                None => kept.extend(group.iter().map(|change| change.hash.clone())),
                Some(target) => {
                    let witness = group
                        .iter()
                        .filter(|change| change.version.relation_to(target) == VersionRelation::Equal)
                        .max_by(|left, right| {
                            (left.device_id.as_bytes(), left.sequence).cmp(&(right.device_id.as_bytes(), right.sequence))
                        });
                    match witness {
                        Some(change) => {
                            kept.insert(change.hash.clone());
                        }
                        None => kept.extend(group.iter().map(|change| change.hash.clone())),
                    }
                }
            }
        } else {
            kept.extend(group.iter().map(|change| change.hash.clone()));
        }
    }
    // 3. Tombstone witnesses. 4. Unresolved conflict witnesses.
    kept.extend(tombstones.iter().map(|t| t.change_hash.to_owned()));
    for conflict in conflicts.iter().filter(|c| !c.resolved) {
        kept.insert(conflict.local_change_hash.to_owned());
        kept.insert(conflict.remote_change_hash.to_owned());
    }
    kept.remove(GENESIS_HASH);
    kept
}

/// The last-writer-wins winner among the upserts no other upsert dominates (Android `AppearanceSyncRules.current`).
fn last_writer<'a>(group: &[&'a HeldChange]) -> Option<&'a HeldChange> {
    let upserts: Vec<&HeldChange> = group.iter().copied().filter(|change| !change.delete).collect();
    let mut best: Option<&HeldChange> = None;
    for change in upserts
        .iter()
        .copied()
        .filter(|change| !upserts.iter().any(|other| change.version.relation_to(&other.version) == VersionRelation::Before))
    {
        let wins = best.is_none_or(|current| {
            incoming_wins(
                &Stamp::new(Some(&current.occurred_at_utc), Some(&current.device_id)),
                &Stamp::new(Some(&change.occurred_at_utc), Some(&change.device_id)),
            )
        });
        if wins {
            best = Some(change);
        }
    }
    best
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckpointError {
    Membership,
    Issuer,
    Signature,
    Heads,
    Change,
    Digest,
    Reference,
}

/// Checks a v4 snapshot's checkpoint against the snapshot's own content, in the design's order:
/// the membership it names; the managing device's signature (it must be `peer_device_id`); each
/// head against its author's own signature; every change's hash, author and signature (with no
/// chain continuity: changes between witnesses are gone on purpose); the digests; and that each
/// tombstone and conflict refers to an included change.
#[allow(clippy::too_many_arguments)]
pub fn validate(
    checkpoint: &Checkpoint,
    membership: &VerifiedMembership,
    membership_count: usize,
    peer_device_id: &str,
    heads: &[CheckpointHead],
    operations: &[ChangeRecord],
    records: &[RecordRef],
    tombstones: &[TombstoneRef],
    conflicts: &[ConflictRef],
) -> Result<(), CheckpointError> {
    if checkpoint.format != FORMAT || checkpoint.vault_id != membership.vault_id {
        return Err(CheckpointError::Membership);
    }
    // 1. The membership it names.
    if checkpoint.membership_count != membership_count as u64 || checkpoint.membership_head != membership.head {
        return Err(CheckpointError::Membership);
    }
    // 2. Signed by the managing device, which is the paired peer.
    if checkpoint.issuer_device_id != membership.manager_device_id || checkpoint.issuer_device_id != peer_device_id {
        return Err(CheckpointError::Issuer);
    }
    let issuer = membership.members.get(&checkpoint.issuer_device_id).ok_or(CheckpointError::Issuer)?;
    if !signature_ok(&issuer.public_key, &checkpoint.signing_bytes(), &checkpoint.signature) {
        return Err(CheckpointError::Signature);
    }
    // 3. Each head is proven by its author's own signature.
    let mut claimed: HashMap<&str, &CheckpointHead> = HashMap::new();
    for head in &checkpoint.heads {
        if head.sequence == 0 || !is_hash(&head.hash) || claimed.insert(&head.device_id, head).is_some() {
            return Err(CheckpointError::Heads);
        }
    }
    let mut by_hash: HashMap<&str, &ChangeRecord> = HashMap::new();
    let mut mutations = HashSet::new();
    for operation in operations {
        if by_hash.insert(&operation.hash, operation).is_some() || !mutations.insert(operation.mutation_id.as_str()) {
            return Err(CheckpointError::Change);
        }
    }
    for head in claimed.values() {
        let witnesses: Vec<&ChangeRecord> = operations
            .iter()
            .filter(|operation| operation.device_id == head.device_id && operation.sequence == head.sequence)
            .collect();
        if witnesses.len() != 1 || witnesses[0].hash != head.hash {
            return Err(CheckpointError::Heads);
        }
    }
    // 4. Every change: hash, author, signature, at or below its author's head.
    for operation in operations {
        let member = membership.members.get(&operation.device_id).ok_or(CheckpointError::Change)?;
        // A removed device's change counts up to its cutoff. A removal signed before cutoffs
        // existed has none; its changes are then trusted as snapshot v3 trusts them.
        let allowed = member.active
            || member.removal_cutoff.is_none()
            || crate::protocol::within_removal_cutoff(member.removal_cutoff.as_ref(), operation.sequence, &operation.hash);
        let head = claimed.get(operation.device_id.as_str()).map_or(0, |head| head.sequence);
        if !allowed
            || operation.vault_id != membership.vault_id
            || operation.sequence > head
            || crate::incoming::validate_signed(operation, &member.public_key).is_err()
        {
            return Err(CheckpointError::Change);
        }
    }
    // 5. Digests.
    let hashes: Vec<&str> = operations.iter().map(|operation| operation.hash.as_str()).collect();
    if conflicts.iter().any(|conflict| conflict.resolved) {
        return Err(CheckpointError::Digest);
    }
    let expected = digests(&hashes, records, tombstones, conflicts);
    if expected
        != (Digests {
            operations: checkpoint.operations_digest.clone(),
            records: checkpoint.records_digest.clone(),
            tombstones: checkpoint.tombstones_digest.clone(),
            conflicts: checkpoint.conflicts_digest.clone(),
        })
    {
        return Err(CheckpointError::Digest);
    }
    // 6. The snapshot's heads, tombstones and conflicts agree with the included changes.
    let mut listed: Vec<&CheckpointHead> = heads.iter().collect();
    let mut signed: Vec<&CheckpointHead> = checkpoint.heads.iter().collect();
    listed.sort_by(|l, r| l.device_id.cmp(&r.device_id));
    signed.sort_by(|l, r| l.device_id.cmp(&r.device_id));
    if listed != signed {
        return Err(CheckpointError::Heads);
    }
    for tombstone in tombstones {
        let change = by_hash.get(tombstone.change_hash).ok_or(CheckpointError::Reference)?;
        if change.kind != ChangeKind::Delete || change.entity_type != tombstone.entity_type || change.entity_id != tombstone.entity_id {
            return Err(CheckpointError::Reference);
        }
    }
    for conflict in conflicts {
        if !by_hash.contains_key(conflict.remote_change_hash)
            || (conflict.local_change_hash != GENESIS_HASH && !by_hash.contains_key(conflict.local_change_hash))
        {
            return Err(CheckpointError::Reference);
        }
    }
    Ok(())
}

fn is_hash(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn signature_ok(public_key: &[u8; 32], bytes: &[u8], signature: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|signature| <[u8; 64]>::try_from(signature).ok())
        .is_some_and(|signature| verify_signature(public_key, bytes, &signature))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;

    use super::*;
    use crate::{identity::DeviceIdentity, snapshot};

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../fixtures/checkpoint-v1.json")).unwrap()
    }

    fn device<'a>(vectors: &'a Value, id: &str) -> &'a Value {
        vectors["devices"].as_array().unwrap().iter().find(|d| d["deviceId"] == id).unwrap()
    }

    fn identity(vectors: &Value, id: &str) -> DeviceIdentity {
        DeviceIdentity {
            device_id: id.to_owned(),
            public_key: URL_SAFE_NO_PAD.decode(device(vectors, id)["publicKey"].as_str().unwrap()).unwrap().try_into().unwrap(),
        }
    }

    fn seed(vectors: &Value, id: &str) -> [u8; 32] {
        let hex = device(vectors, id)["seedHex"].as_str().unwrap();
        (0..32).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect::<Vec<_>>().try_into().unwrap()
    }

    fn held(change: &Value) -> HeldChange {
        HeldChange {
            device_id: change["deviceId"].as_str().unwrap().to_owned(),
            sequence: change["sequence"].as_u64().unwrap(),
            hash: change["hash"].as_str().unwrap().to_owned(),
            entity_type: change["entityType"].as_str().unwrap().to_owned(),
            entity_id: change["entityId"].as_str().unwrap().to_owned(),
            delete: change["kind"] == "delete",
            version: serde_json::from_str(change["recordVersionJson"].as_str().unwrap()).unwrap(),
            occurred_at_utc: change["occurredAtUtc"].as_str().unwrap().to_owned(),
        }
    }

    fn records(list: &Value) -> Vec<RecordRef<'_>> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|r| RecordRef {
                entity_type: r["entityType"].as_str().unwrap(),
                entity_id: r["entityId"].as_str().unwrap(),
                revision: r["revision"].as_u64().unwrap(),
                version: serde_json::from_str(r["recordVersionJson"].as_str().unwrap()).unwrap(),
            })
            .collect()
    }

    fn tombstones(list: &Value) -> Vec<TombstoneRef<'_>> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|t| TombstoneRef {
                entity_type: t["entityType"].as_str().unwrap(),
                entity_id: t["entityId"].as_str().unwrap(),
                change_hash: t["changeHash"].as_str().unwrap(),
            })
            .collect()
    }

    fn conflicts(list: &Value) -> Vec<ConflictRef<'_>> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|c| ConflictRef {
                conflict_id: c["conflictId"].as_str().unwrap(),
                local_change_hash: c["localChangeHash"].as_str().unwrap(),
                remote_change_hash: c["remoteChangeHash"].as_str().unwrap(),
                resolved: !c["resolvedAtUtc"].as_str().unwrap().is_empty(),
            })
            .collect()
    }

    /// The stream as the phone writes it: magic, nonce, length, AES-GCM(metadata) with the magic as AAD.
    fn stream(magic: &[u8; 8], metadata: &Value, key: &[u8; 32]) -> Vec<u8> {
        let nonce = [9u8; 12];
        let sealed = Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &serde_json::to_vec(metadata).unwrap(), aad: magic })
            .unwrap();
        [magic.as_slice(), &nonce, &(sealed.len() as i32).to_be_bytes(), &sealed].concat()
    }

    fn read(vectors: &Value, metadata: &Value, magic: &[u8; 8]) -> Result<snapshot::VerifiedSnapshotMetadata, snapshot::SnapshotError> {
        let key = [7u8; 32];
        snapshot::read_metadata(
            &mut Cursor::new(stream(magic, metadata, &key)),
            &key,
            vectors["vaultId"].as_str().unwrap(),
            &identity(vectors, vectors["joiner"].as_str().unwrap()),
            &identity(vectors, vectors["manager"].as_str().unwrap()),
        )
    }

    #[test]
    fn keep_set_matches_the_shared_vectors() {
        let vectors = vectors();
        let input = &vectors["keepSetInput"];
        let changes: Vec<HeldChange> = input["operations"].as_array().unwrap().iter().map(held).collect();
        assert_eq!(changes.len(), 40);
        let kept = keep_set(&changes, &records(&input["records"]), &tombstones(&input["tombstones"]), &conflicts(&input["conflicts"]));
        let expected: HashSet<String> = vectors["keepSet"].as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_owned()).collect();
        assert_eq!(kept, expected);
    }

    #[test]
    fn digests_signing_bytes_and_signature_match_the_shared_vectors() {
        let vectors = vectors();
        let state = &vectors["snapshot"];
        let hashes: Vec<&str> = state["operations"].as_array().unwrap().iter().map(|c| c["hash"].as_str().unwrap()).collect();
        let computed = digests(&hashes, &records(&state["records"]), &tombstones(&state["tombstones"]), &conflicts(&state["conflicts"]));
        let expected = &vectors["digests"];
        assert_eq!(computed.operations, expected["operations"].as_str().unwrap());
        assert_eq!(computed.records, expected["records"].as_str().unwrap());
        assert_eq!(computed.tombstones, expected["tombstones"].as_str().unwrap());
        assert_eq!(computed.conflicts, expected["conflicts"].as_str().unwrap());
        let checkpoint: Checkpoint = serde_json::from_value(state["checkpoint"].clone()).unwrap();
        assert_eq!(String::from_utf8(checkpoint.signing_bytes()).unwrap(), vectors["signingBytesText"].as_str().unwrap());
        // Ed25519 is deterministic: signing again gives the vector's signature.
        let manager = SigningKey::from_bytes(&seed(&vectors, vectors["manager"].as_str().unwrap()));
        assert_eq!(URL_SAFE_NO_PAD.encode(manager.sign(&checkpoint.signing_bytes()).to_bytes()), checkpoint.signature);
    }

    #[test]
    fn a_valid_v4_snapshot_verifies_and_keeps_its_checkpoint() {
        let vectors = vectors();
        let metadata = read(&vectors, &vectors["snapshot"], b"NUVSYNC4").unwrap();
        assert_eq!(metadata.operations.len(), 8);
        assert_eq!(metadata.checkpoint.as_ref().unwrap().issuer_device_id, vectors["manager"].as_str().unwrap());
        assert_eq!(metadata.heads.len(), 3);
        // The magic and the version must agree, and a v3 snapshot never carries a checkpoint.
        assert!(read(&vectors, &vectors["snapshot"], b"NUVSYNC3").is_err());
        let mut v3 = vectors["snapshot"].clone();
        v3["version"] = 3.into();
        assert!(read(&vectors, &v3, b"NUVSYNC3").is_err());
    }

    #[test]
    fn every_negative_case_is_refused() {
        let vectors = vectors();
        let negatives = vectors["negative"].as_array().unwrap();
        assert_eq!(negatives.len(), 9);
        for case in negatives {
            let name = case["name"].as_str().unwrap();
            let result = read(&vectors, &case["snapshot"], b"NUVSYNC4");
            if name == "present item without a witness" {
                // The metadata is consistent; the import refuses it when the item is in the vault
                // copy (`snapshot_import::validate_snapshot`): no included change has its version.
                let metadata = result.expect(name);
                let record = metadata.records.iter().find(|r| r.entity_id == "e2").unwrap();
                let version: RecordVersion = serde_json::from_str(&record.record_version_json).unwrap();
                assert!(!metadata.operations.iter().any(|o| o.entity_id == "e2" && o.record_version == version), "{name}");
            } else {
                assert!(result.is_err(), "{name} must be refused");
            }
        }
    }

    fn backup(vectors: &Value) -> crate::portable_backup::PortableBackup {
        let note = |id: &str| serde_json::json!({"id": id, "type": "NOTE", "title": id, "notes": "", "createdAt": 1, "updatedAt": 2});
        crate::portable_backup::PortableBackup {
            vault_id: vectors["vaultId"].as_str().unwrap().to_owned(),
            entries: vec![note("e1"), note("e2")],
            groups: vec![serde_json::json!({"id": "g1", "name": "Group", "notes": "", "folderType": "NOTE"})],
            links: vec![],
            passkeys: vec![],
            photos: vec![],
        }
    }

    #[test]
    fn a_v4_join_stores_the_witnesses_heads_and_its_base() {
        let vectors = vectors();
        let directory = std::env::temp_dir().join(format!("nuvori-checkpoint-{}", uuid::Uuid::new_v4()));
        let store = crate::vault::VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let metadata = read(&vectors, &vectors["snapshot"], b"NUVSYNC4").unwrap();
        crate::snapshot_import::commit_empty(vault.connection(), metadata, backup(&vectors)).unwrap();
        let db = vault.connection();
        let count = |sql: &str| db.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap();
        assert_eq!(count("SELECT count(*) FROM sync_operations"), 8, "only the keep set is stored");
        assert_eq!(count("SELECT count(*) FROM sync_device_heads"), 3);
        let stored: String = db.query_row("SELECT checkpoint_json FROM sync_checkpoints", [], |row| row.get(0)).unwrap();
        let base: Checkpoint = serde_json::from_str(&stored).unwrap();
        assert_eq!(base, serde_json::from_value::<Checkpoint>(vectors["snapshot"]["checkpoint"].clone()).unwrap());
        // The next change of an author must continue its checkpoint head.
        let pc_head: i64 = db.query_row("SELECT sequence FROM sync_device_heads WHERE device_id = 'dev-pc'", [], |row| row.get(0)).unwrap();
        assert_eq!(pc_head, 16);
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();

        // A present item that no included change explains is refused, and nothing is stored.
        let directory = std::env::temp_dir().join(format!("nuvori-checkpoint-{}", uuid::Uuid::new_v4()));
        let store = crate::vault::VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let case = vectors["negative"].as_array().unwrap().iter().find(|c| c["name"] == "present item without a witness").unwrap();
        let metadata = read(&vectors, &case["snapshot"], b"NUVSYNC4").unwrap();
        assert!(crate::snapshot_import::commit_empty(vault.connection(), metadata, backup(&vectors)).is_err());
        assert_eq!(vault.connection().query_row("SELECT count(*) FROM sync_operations", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn sign_in_methods_keep_every_change_no_other_change_includes() {
        let change = |device: &str, sequence: u64, hash: &str, entity: &str, delete: bool, version: RecordVersion| HeldChange {
            device_id: device.to_owned(), sequence, hash: hash.to_owned(), entity_type: crate::sign_in_sync::ENTITY_TYPE.to_owned(),
            entity_id: entity.to_owned(), delete, version, occurred_at_utc: "2026-11-20T10:00:00Z".to_owned(),
        };
        let changes = [
            change("pc", 1, "pc-1", "a", false, RecordVersion::from_entries([("pc", 1)])),
            change("pc", 2, "pc-2", "a", false, RecordVersion::from_entries([("pc", 2)])),
            change("phone", 1, "phone-1", "a", false, RecordVersion::from_entries([("pc", 1), ("phone", 1)])),
            change("pc", 3, "pc-3", "b", false, RecordVersion::from_entries([("pc", 3)])),
            change("phone", 2, "phone-2", "b", true, RecordVersion::from_entries([("pc", 3), ("phone", 2)])),
            change("pc", 4, "pc-4", "c", false, RecordVersion::from_entries([("pc", 4)])),
        ];
        let tombstones = [TombstoneRef { entity_type: crate::sign_in_sync::ENTITY_TYPE, entity_id: "b", change_hash: "phone-2" }];
        let kept = keep_set(&changes, &[], &tombstones, &[]);
        let mut kept: Vec<&str> = kept.iter().map(String::as_str).collect();
        kept.sort_unstable();
        // a: the two concurrent upserts (pc-1 is included in both); b: the delete; c: the live upsert (also pc's head).
        assert_eq!(kept, ["pc-2", "pc-4", "phone-1", "phone-2"]);
    }

    #[test]
    fn this_build_announces_checkpoint_enrollment() {
        assert!(crate::protocol::SYNC_FEATURES.contains(&crate::protocol::CHECKPOINT_ENROLL_FEATURE));
        assert_eq!(vectors()["feature"], crate::protocol::CHECKPOINT_ENROLL_FEATURE);
    }
}
