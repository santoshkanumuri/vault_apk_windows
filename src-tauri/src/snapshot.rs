//! Reads Android's authenticated enrollment metadata. The backup body is handled separately.

use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    identity::DeviceIdentity,
    incoming::{IncomingError, IncomingVerifier},
    membership::{self, MembershipError, MembershipEvent, VerifiedMembership},
    protocol::RecordVersion,
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
};

const MAGIC: &[u8; 8] = b"NUVSYNC3";
/// Android 2.1.4+ sends this instead of [MAGIC] when it cannot prepare the vault copy.
const FAILURE_MAGIC: &[u8; 8] = b"NUVFAIL1";
const MAX_METADATA: usize = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AndroidMetadata {
    version: u32,
    vault_id: String,
    content_key: String,
    transport_secret: String,
    members: Vec<SnapshotMember>,
    membership_events: Vec<MembershipEvent>,
    heads: Vec<SnapshotHead>,
    records: Vec<SnapshotRecordState>,
    operations: Vec<AndroidOperation>,
    tombstones: Vec<SnapshotTombstone>,
    conflicts: Vec<SnapshotConflict>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotMember {
    pub vault_id: String,
    pub device_id: String,
    pub display_name: String,
    pub identity_public_key: String,
    pub status: String,
    pub added_by_device_id: String,
    pub membership_sequence: u64,
    pub key_epoch: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotHead {
    pub vault_id: String,
    pub device_id: String,
    pub sequence: u64,
    pub hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotRecordState {
    pub entity_type: String,
    pub entity_id: String,
    pub revision: u64,
    pub record_version_json: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotTombstone {
    pub tombstone_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub deleted_by_device_id: String,
    pub delete_sequence: u64,
    pub record_version_json: String,
    pub deleted_at_utc: String,
    pub change_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotConflict {
    pub conflict_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub local_change_hash: String,
    pub remote_change_hash: String,
    pub local_version_json: String,
    pub remote_version_json: String,
    pub detected_at_utc: String,
    pub resolved_at_utc: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AndroidOperation {
    mutation_id: String,
    format_version: u16,
    vault_id: String,
    device_id: String,
    sequence: u64,
    previous_hash: String,
    entity_type: String,
    entity_id: String,
    kind: ChangeKind,
    base_revision: u64,
    record_version_json: String,
    occurred_at_utc: String,
    payload_ciphertext: String,
    payload_nonce: String,
    device_signature: String,
    hash: String,
}

pub struct VerifiedSnapshotMetadata {
    pub vault_id: String,
    pub content_key: Zeroizing<[u8; 32]>,
    pub transport_secret: Zeroizing<[u8; 32]>,
    pub membership: VerifiedMembership,
    pub members: Vec<SnapshotMember>,
    pub membership_events: Vec<MembershipEvent>,
    pub heads: Vec<SnapshotHead>,
    pub records: Vec<SnapshotRecordState>,
    pub operations: Vec<ChangeRecord>,
    pub tombstones: Vec<SnapshotTombstone>,
    pub conflicts: Vec<SnapshotConflict>,
}

/// Leaves the input positioned at Android's encrypted vault backup body.
pub fn read_metadata<R: Read>(
    input: &mut R,
    pairing_key: &[u8; 32],
    expected_vault_id: &str,
    local: &DeviceIdentity,
    peer: &DeviceIdentity,
) -> Result<VerifiedSnapshotMetadata, SnapshotError> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic).map_err(|error| match error.kind() {
        std::io::ErrorKind::UnexpectedEof => SnapshotError::PhoneSentNothing,
        _ => SnapshotError::Io(error),
    })?;
    if &magic == FAILURE_MAGIC {
        return Err(SnapshotError::PhoneFailed(read_failure(input)));
    }
    if &magic != MAGIC {
        return Err(SnapshotError::InvalidMetadata);
    }
    let mut nonce = [0; 12];
    input.read_exact(&mut nonce)?;
    let mut size = [0; 4];
    input.read_exact(&mut size)?;
    let size = i32::from_be_bytes(size);
    if size < 16 || size as usize > MAX_METADATA + 16 {
        return Err(SnapshotError::InvalidMetadata);
    }
    let mut ciphertext = Zeroizing::new(vec![0; size as usize]);
    input.read_exact(&mut ciphertext)?;
    let cipher =
        Aes256Gcm::new_from_slice(pairing_key).map_err(|_| SnapshotError::InvalidMetadata)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: MAGIC,
                },
            )
            .map_err(|_| SnapshotError::AuthenticationFailed)?,
    );
    let metadata: AndroidMetadata = serde_json::from_slice(&plaintext)?;
    validate(metadata, expected_vault_id, local, peer)
}

fn validate(
    mut state: AndroidMetadata,
    expected_vault_id: &str,
    local: &DeviceIdentity,
    peer: &DeviceIdentity,
) -> Result<VerifiedSnapshotMetadata, SnapshotError> {
    if state.version != 3
        || state.vault_id != expected_vault_id
        || local.device_id == peer.device_id
    {
        return Err(SnapshotError::InvalidMetadata);
    }
    let content_encoded = Zeroizing::new(std::mem::take(&mut state.content_key));
    let transport_encoded = Zeroizing::new(std::mem::take(&mut state.transport_secret));
    let content_key = Zeroizing::new(decode_key(&content_encoded)?);
    let transport_secret = Zeroizing::new(decode_key(&transport_encoded)?);
    let membership = membership::verify(&state.membership_events)?;
    if membership.vault_id != state.vault_id || state.members.len() != membership.members.len() {
        return Err(SnapshotError::InvalidMembership);
    }
    let active = membership
        .members
        .values()
        .filter(|member| member.active)
        .count();
    if !(2..=membership::MAX_ACTIVE_DEVICES).contains(&active) {
        return Err(SnapshotError::InvalidMembership);
    }
    let mut seen = HashSet::new();
    for stored in &state.members {
        let verified = membership
            .members
            .get(&stored.device_id)
            .ok_or(SnapshotError::InvalidMembership)?;
        if !seen.insert(&stored.device_id)
            || stored.vault_id != state.vault_id
            || stored.display_name.is_empty()
            || decode_key(&stored.identity_public_key)? != verified.public_key
            || (stored.status == "ACTIVE") != verified.active
            || !matches!(stored.status.as_str(), "ACTIVE" | "REVOKED")
            || stored.added_by_device_id != verified.added_by_device_id
            || stored.membership_sequence != verified.membership_sequence
            || stored.key_epoch != verified.key_epoch
        {
            return Err(SnapshotError::InvalidMembership);
        }
    }
    for identity in [local, peer] {
        let member = membership
            .members
            .get(&identity.device_id)
            .ok_or(SnapshotError::InvalidMembership)?;
        if !member.active || member.public_key != identity.public_key {
            return Err(SnapshotError::InvalidMembership);
        }
    }

    let mut operations = state
        .operations
        .into_iter()
        .map(AndroidOperation::into_change)
        .collect::<Result<Vec<_>, _>>()?;
    operations.sort_by(|left, right| {
        (&left.device_id, left.sequence).cmp(&(&right.device_id, right.sequence))
    });
    let mut mutation_ids = HashSet::new();
    let mut operation_by_hash = BTreeMap::new();
    let mut heads = BTreeMap::new();
    let mut current_device = String::new();
    let mut verifier: Option<IncomingVerifier> = None;
    for operation in &operations {
        if !mutation_ids.insert(operation.mutation_id.as_str()) {
            return Err(SnapshotError::InvalidHistory);
        }
        if operation_by_hash
            .insert(operation.hash.as_str(), operation)
            .is_some()
        {
            return Err(SnapshotError::InvalidHistory);
        }
        if operation.device_id != current_device {
            if let Some(previous) = verifier.take() {
                heads.insert(
                    current_device.clone(),
                    (previous.head().0, previous.head().1.to_owned()),
                );
            }
            let member = membership
                .members
                .get(&operation.device_id)
                .ok_or(SnapshotError::InvalidHistory)?;
            current_device.clone_from(&operation.device_id);
            verifier = Some(IncomingVerifier::new(
                &state.vault_id,
                &operation.device_id,
                member.public_key,
                0,
                GENESIS_HASH,
            )?);
        }
        let verifier = verifier.as_mut().ok_or(SnapshotError::InvalidHistory)?;
        let batch = verifier.verify_batch(vec![operation.clone()])?;
        verifier.commit(&batch)?;
    }
    if let Some(previous) = verifier {
        heads.insert(
            current_device,
            (previous.head().0, previous.head().1.to_owned()),
        );
    }
    if heads.len() != state.heads.len() {
        return Err(SnapshotError::InvalidHistory);
    }
    let mut seen_heads = HashSet::new();
    for head in &state.heads {
        if head.vault_id != state.vault_id
            || !seen_heads.insert(&head.device_id)
            || heads.get(&head.device_id) != Some(&(head.sequence, head.hash.clone()))
        {
            return Err(SnapshotError::InvalidHistory);
        }
    }
    let mut record_ids = HashSet::new();
    for record in &state.records {
        if record.entity_type.is_empty()
            || record.entity_id.is_empty()
            || record.revision == 0
            || !record_ids.insert((&record.entity_type, &record.entity_id))
        {
            return Err(SnapshotError::InvalidHistory);
        }
        let version: RecordVersion = serde_json::from_str(&record.record_version_json)?;
        version
            .validate()
            .map_err(|_| SnapshotError::InvalidHistory)?;
    }
    let mut tombstone_ids = HashSet::new();
    let mut deleted_entities = HashSet::new();
    for tombstone in &state.tombstones {
        let operation = operation_by_hash
            .get(tombstone.change_hash.as_str())
            .ok_or(SnapshotError::InvalidHistory)?;
        let version: RecordVersion = serde_json::from_str(&tombstone.record_version_json)?;
        version
            .validate()
            .map_err(|_| SnapshotError::InvalidHistory)?;
        if !tombstone_ids.insert(&tombstone.tombstone_id)
            || !deleted_entities.insert((&tombstone.entity_type, &tombstone.entity_id))
            || tombstone.tombstone_id != operation.mutation_id
            || tombstone.entity_type != operation.entity_type
            || tombstone.entity_id != operation.entity_id
            || tombstone.deleted_by_device_id != operation.device_id
            || tombstone.delete_sequence != operation.sequence
            || version != operation.record_version
            || tombstone.deleted_at_utc != operation.occurred_at_utc
            || operation.kind != ChangeKind::Delete
        {
            return Err(SnapshotError::InvalidHistory);
        }
    }
    let mut conflict_ids = HashSet::new();
    for conflict in &state.conflicts {
        let remote = operation_by_hash
            .get(conflict.remote_change_hash.as_str())
            .ok_or(SnapshotError::InvalidHistory)?;
        if conflict.conflict_id.is_empty()
            || !conflict_ids.insert(&conflict.conflict_id)
            || conflict.entity_type != remote.entity_type
            || conflict.entity_id != remote.entity_id
            || (conflict.local_change_hash != GENESIS_HASH
                && !operation_by_hash.contains_key(conflict.local_change_hash.as_str()))
        {
            return Err(SnapshotError::InvalidHistory);
        }
        for encoded in [&conflict.local_version_json, &conflict.remote_version_json] {
            let version: RecordVersion = serde_json::from_str(encoded)?;
            version
                .validate()
                .map_err(|_| SnapshotError::InvalidHistory)?;
        }
    }
    Ok(VerifiedSnapshotMetadata {
        vault_id: state.vault_id,
        content_key,
        transport_secret,
        membership,
        members: state.members,
        membership_events: state.membership_events,
        heads: state.heads,
        records: state.records,
        operations,
        tombstones: state.tombstones,
        conflicts: state.conflicts,
    })
}

impl AndroidOperation {
    fn into_change(self) -> Result<ChangeRecord, SnapshotError> {
        Ok(ChangeRecord {
            mutation_id: self.mutation_id,
            format_version: self.format_version,
            vault_id: self.vault_id,
            device_id: self.device_id,
            sequence: self.sequence,
            previous_hash: self.previous_hash,
            entity_type: self.entity_type,
            entity_id: self.entity_id,
            kind: self.kind,
            base_revision: self.base_revision,
            record_version: serde_json::from_str(&self.record_version_json)?,
            occurred_at_utc: self.occurred_at_utc,
            payload_ciphertext: self.payload_ciphertext,
            payload_nonce: self.payload_nonce,
            device_signature: self.device_signature,
            hash: self.hash,
        })
    }
}

/// Reads the phone's short failure text that follows [FAILURE_MAGIC], up to 1 KiB.
fn read_failure<R: Read>(input: &mut R) -> String {
    let mut bytes = Vec::new();
    let _ = input.take(1024).read_to_end(&mut bytes);
    let text: String = String::from_utf8_lossy(&bytes)
        .chars()
        .filter(|character| !character.is_control())
        .take(240)
        .collect();
    if text.trim().is_empty() {
        "the phone could not prepare the vault copy".to_owned()
    } else {
        text
    }
}

fn decode_key(encoded: &str) -> Result<[u8; 32], SnapshotError> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SnapshotError::InvalidMetadata)?
        .try_into()
        .map_err(|_| SnapshotError::InvalidMetadata)
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("snapshot read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the phone could not send the vault copy: {0}")]
    PhoneFailed(String),
    #[error("the phone ended the transfer without sending the vault copy")]
    PhoneSentNothing,
    #[error("snapshot JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("snapshot authentication failed")]
    AuthenticationFailed,
    #[error("snapshot metadata is invalid")]
    InvalidMetadata,
    #[error("snapshot membership is invalid")]
    InvalidMembership,
    #[error("snapshot operation history is invalid")]
    InvalidHistory,
    #[error("snapshot signed membership is invalid: {0}")]
    Membership(#[from] MembershipError),
    #[error("snapshot operation is invalid: {0}")]
    Incoming(#[from] IncomingError),
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::membership::MembershipAction;

    fn event(
        signer: &SigningKey,
        previous: Option<&MembershipEvent>,
        action: MembershipAction,
        issuer: &str,
        subject: &str,
        subject_key: &str,
    ) -> MembershipEvent {
        let mut event = MembershipEvent {
            vault_id: "vault-a".to_owned(),
            sequence: previous.map_or(1, |previous| previous.sequence + 1),
            format_version: 1,
            previous_hash: previous
                .map_or(GENESIS_HASH.to_owned(), |previous| previous.hash.clone()),
            action,
            issuer_device_id: issuer.to_owned(),
            subject_device_id: subject.to_owned(),
            subject_public_key: subject_key.to_owned(),
            key_epoch: 1,
            signature: String::new(),
            hash: String::new(),
        };
        let bytes = event.signing_bytes().unwrap();
        event.signature = URL_SAFE_NO_PAD.encode(signer.sign(&bytes).to_bytes());
        let mut digest = Sha256::new();
        digest.update(&bytes);
        digest.update(event.signature.as_bytes());
        event.hash = hex::encode(digest.finalize());
        event
    }

    fn fixture() -> (Value, DeviceIdentity, DeviceIdentity) {
        let host_key = SigningKey::from_bytes(&[3; 32]);
        let windows_key = SigningKey::from_bytes(&[4; 32]);
        let host = DeviceIdentity {
            device_id: "android".to_owned(),
            public_key: host_key.verifying_key().to_bytes(),
        };
        let windows = DeviceIdentity {
            device_id: "windows".to_owned(),
            public_key: windows_key.verifying_key().to_bytes(),
        };
        let genesis = event(
            &host_key,
            None,
            MembershipAction::Genesis,
            "android",
            "android",
            &host.public_key_base64_url(),
        );
        let add = event(
            &host_key,
            Some(&genesis),
            MembershipAction::Add,
            "android",
            "windows",
            &windows.public_key_base64_url(),
        );
        let metadata = json!({
            "version": 3, "vaultId": "vault-a",
            "contentKey": URL_SAFE_NO_PAD.encode([8; 32]),
            "transportSecret": URL_SAFE_NO_PAD.encode([9; 32]),
            "members": [
                {"vaultId": "vault-a", "deviceId": "android", "displayName": "Phone",
                 "identityPublicKey": host.public_key_base64_url(), "status": "ACTIVE",
                 "addedByDeviceId": "android", "membershipSequence": 1, "keyEpoch": 1},
                {"vaultId": "vault-a", "deviceId": "windows", "displayName": "Windows",
                 "identityPublicKey": windows.public_key_base64_url(), "status": "ACTIVE",
                 "addedByDeviceId": "android", "membershipSequence": 2, "keyEpoch": 1}
            ],
            "membershipEvents": [genesis, add], "heads": [], "records": [],
            "operations": [], "tombstones": [], "conflicts": []
        });
        (metadata, windows, host)
    }

    fn encrypted(metadata: &Value) -> Vec<u8> {
        let plaintext = serde_json::to_vec(metadata).unwrap();
        let nonce = [1; 12];
        let ciphertext = Aes256Gcm::new_from_slice(&[7; 32])
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: MAGIC,
                },
            )
            .unwrap();
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&(ciphertext.len() as i32).to_be_bytes());
        bytes.extend_from_slice(&ciphertext);
        bytes.extend_from_slice(b"backup-body");
        bytes
    }

    #[test]
    fn reports_phone_failure_and_empty_transfer() {
        let (_, local, peer) = fixture();
        let mut failed = Cursor::new(b"NUVFAIL1Only the managing phone can enroll a device".to_vec());
        match read_metadata(&mut failed, &[7; 32], "vault-a", &local, &peer) {
            Err(SnapshotError::PhoneFailed(reason)) => {
                assert_eq!(reason, "Only the managing phone can enroll a device")
            }
            other => panic!("unexpected result: {:?}", other.err()),
        }
        let mut empty = Cursor::new(Vec::new());
        assert!(matches!(
            read_metadata(&mut empty, &[7; 32], "vault-a", &local, &peer),
            Err(SnapshotError::PhoneSentNothing)
        ));
    }

    #[test]
    fn reads_authenticated_android_metadata_and_leaves_backup_body() {
        let (metadata, windows, host) = fixture();
        let mut input = Cursor::new(encrypted(&metadata));
        let checked = read_metadata(&mut input, &[7; 32], "vault-a", &windows, &host).unwrap();
        assert_eq!(checked.vault_id, "vault-a");
        assert_eq!(checked.membership.manager_device_id, "android");
        assert_eq!(&*checked.content_key, &[8; 32]);
        let mut remaining = Vec::new();
        input.read_to_end(&mut remaining).unwrap();
        assert_eq!(remaining, b"backup-body");
    }

    #[test]
    fn rejects_modified_ciphertext_or_unsigned_membership() {
        let (mut metadata, windows, host) = fixture();
        let mut ciphertext = encrypted(&metadata);
        ciphertext[30] ^= 1;
        assert!(matches!(
            read_metadata(
                &mut Cursor::new(ciphertext),
                &[7; 32],
                "vault-a",
                &windows,
                &host
            ),
            Err(SnapshotError::AuthenticationFailed)
        ));

        metadata["members"][1]["identityPublicKey"] = json!(URL_SAFE_NO_PAD.encode([1; 32]));
        assert!(matches!(
            read_metadata(
                &mut Cursor::new(encrypted(&metadata)),
                &[7; 32],
                "vault-a",
                &windows,
                &host
            ),
            Err(SnapshotError::InvalidMembership)
        ));
    }

    #[test]
    fn verifies_android_operation_entity_and_its_head() {
        let (mut metadata, windows, host) = fixture();
        let host_key = SigningKey::from_bytes(&[3; 32]);
        let encrypted_payload = crate::payload::encrypt(
            &[8; 32],
            "entry",
            "vault-a",
            "mutation-a",
            "entry-a",
            b"example",
        )
        .unwrap();
        let change = ChangeRecord::create_signed_with(
            "vault-a",
            "android",
            1,
            GENESIS_HASH,
            "mutation-a",
            "entry",
            "entry-a",
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([("android", 1)]),
            "2026-09-27T00:00:00Z",
            encrypted_payload.ciphertext,
            encrypted_payload.nonce,
            |bytes| Ok::<_, std::convert::Infallible>(host_key.sign(bytes).to_bytes()),
        )
        .unwrap();
        let mut stored = serde_json::to_value(&change).unwrap();
        stored["recordVersionJson"] = json!(serde_json::to_string(&change.record_version).unwrap());
        stored.as_object_mut().unwrap().remove("recordVersion");
        metadata["operations"] = json!([stored]);
        metadata["heads"] = json!([{"vaultId": "vault-a", "deviceId": "android",
            "sequence": 1, "hash": change.hash}]);
        let checked = read_metadata(
            &mut Cursor::new(encrypted(&metadata)),
            &[7; 32],
            "vault-a",
            &windows,
            &host,
        )
        .unwrap();
        assert_eq!(checked.operations[0], change);

        metadata["heads"][0]["hash"] = json!(GENESIS_HASH);
        assert!(matches!(
            read_metadata(
                &mut Cursor::new(encrypted(&metadata)),
                &[7; 32],
                "vault-a",
                &windows,
                &host
            ),
            Err(SnapshotError::InvalidHistory)
        ));

        metadata["heads"][0]["hash"] = json!(change.hash);
        metadata["records"] = json!([
            {"entityType": "entry", "entityId": "entry-a", "revision": 1,
             "recordVersionJson": serde_json::to_string(&change.record_version).unwrap()},
            {"entityType": "entry", "entityId": "entry-a", "revision": 2,
             "recordVersionJson": serde_json::to_string(&change.record_version).unwrap()}
        ]);
        assert!(matches!(
            read_metadata(
                &mut Cursor::new(encrypted(&metadata)),
                &[7; 32],
                "vault-a",
                &windows,
                &host
            ),
            Err(SnapshotError::InvalidHistory)
        ));

        metadata["records"] = json!([]);
        metadata["tombstones"] = json!([{
            "tombstoneId": "mutation-a", "entityType": "entry", "entityId": "entry-a",
            "deletedByDeviceId": "android", "deleteSequence": 1,
            "recordVersionJson": serde_json::to_string(&change.record_version).unwrap(),
            "deletedAtUtc": "2026-09-27T00:00:00Z", "changeHash": change.hash
        }]);
        assert!(matches!(
            read_metadata(
                &mut Cursor::new(encrypted(&metadata)),
                &[7; 32],
                "vault-a",
                &windows,
                &host
            ),
            Err(SnapshotError::InvalidHistory)
        ));
    }
    #[test]
    fn enrollment_accepts_the_complete_six_mobile_two_windows_group() {
        let (mut metadata, windows, host) = fixture();
        let signer = SigningKey::from_bytes(&[3; 32]);
        let mut events: Vec<MembershipEvent> = serde_json::from_value(metadata["membershipEvents"].clone()).unwrap();
        for index in 3..=8 {
            let key = SigningKey::from_bytes(&[index + 10; 32]);
            let id = format!("device-{index}");
            let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
            let admission = event(&signer, events.last(), MembershipAction::Add, "android", &id, &public_key);
            metadata["members"].as_array_mut().unwrap().push(json!({
                "vaultId": "vault-a", "deviceId": id,
                "displayName": if index == 8 { "Second Windows PC" } else { "Mobile device" },
                "identityPublicKey": public_key, "status": "ACTIVE", "addedByDeviceId": "android",
                "membershipSequence": admission.sequence, "keyEpoch": 1
            }));
            events.push(admission);
        }
        metadata["membershipEvents"] = serde_json::to_value(events).unwrap();
        let checked = read_metadata(&mut Cursor::new(encrypted(&metadata)), &[7; 32],
            "vault-a", &windows, &host).unwrap();
        assert_eq!(checked.members.len(), 8);
        assert_eq!(checked.membership.members.values().filter(|member| member.active).count(), 8);
    }

}
