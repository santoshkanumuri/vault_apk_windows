//! Validates Android's signed membership history before trusting a sync peer.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{identity::verify_signature, sync::GENESIS_HASH};

pub(crate) const MAX_ACTIVE_DEVICES: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MembershipAction {
    Genesis,
    Add,
    Remove,
    OfferTransfer,
    AcceptTransfer,
    CancelTransfer,
    Transfer,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MembershipEvent {
    pub vault_id: String,
    pub sequence: u64,
    pub format_version: u32,
    pub previous_hash: String,
    pub action: MembershipAction,
    pub issuer_device_id: String,
    pub subject_device_id: String,
    pub subject_public_key: String,
    pub key_epoch: u64,
    pub signature: String,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMember {
    pub device_id: String,
    pub public_key: [u8; 32],
    pub active: bool,
    pub added_by_device_id: String,
    pub membership_sequence: u64,
    pub key_epoch: u64,
    /// For a removed device: its last change the group still accepts (`cutoff1:` in the REMOVE).
    pub removal_cutoff: Option<(u64, String)>,
}

#[derive(Debug)]
pub struct VerifiedMembership {
    pub vault_id: String,
    pub manager_device_id: String,
    pub key_epoch: u64,
    pub head: String,
    pub members: BTreeMap<String, VerifiedMember>,
    /// Device offered the managing role and not yet transferred or canceled.
    pub pending_transfer: Option<String>,
    pub transfer_accepted: bool,
}

impl MembershipEvent {
    /// Kotlin DataOutputStream encodes integers big endian and strings as i32 length + UTF-8.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, MembershipError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.format_version.to_be_bytes());
        append_string(&mut bytes, &self.vault_id)?;
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        append_string(&mut bytes, &self.previous_hash)?;
        append_string(&mut bytes, self.action.as_android_name())?;
        append_string(&mut bytes, &self.issuer_device_id)?;
        append_string(&mut bytes, &self.subject_device_id)?;
        append_string(&mut bytes, &self.subject_public_key)?;
        bytes.extend_from_slice(&self.key_epoch.to_be_bytes());
        Ok(bytes)
    }

    fn computed_hash(&self, signing_bytes: &[u8]) -> String {
        let mut digest = Sha256::new();
        digest.update(signing_bytes);
        digest.update(self.signature.as_bytes());
        hex::encode(digest.finalize())
    }
}

impl MembershipAction {
    fn as_android_name(self) -> &'static str {
        match self {
            Self::Genesis => "GENESIS",
            Self::Add => "ADD",
            Self::Remove => "REMOVE",
            Self::OfferTransfer => "OFFER_TRANSFER",
            Self::AcceptTransfer => "ACCEPT_TRANSFER",
            Self::CancelTransfer => "CANCEL_TRANSFER",
            Self::Transfer => "TRANSFER",
        }
    }
}

pub fn verify(events: &[MembershipEvent]) -> Result<VerifiedMembership, MembershipError> {
    if events.is_empty() || events.len() > 1024 {
        return Err(MembershipError::InvalidHistory);
    }
    let vault_id = &events[0].vault_id;
    if vault_id.is_empty() {
        return Err(MembershipError::InvalidHistory);
    }
    let mut members = BTreeMap::<String, VerifiedMember>::new();
    let mut manager = String::new();
    let mut epoch = 1;
    let mut pending_transfer: Option<String> = None;
    let mut transfer_accepted = false;
    let mut previous_hash = GENESIS_HASH;

    for (index, event) in events.iter().enumerate() {
        let bytes = event.signing_bytes()?;
        if event.format_version != 1
            || &event.vault_id != vault_id
            || event.sequence != index as u64 + 1
            || event.previous_hash != previous_hash
            || event.hash != event.computed_hash(&bytes)
            || event.issuer_device_id.is_empty()
            || event.subject_device_id.is_empty()
        {
            return Err(MembershipError::InvalidHistory);
        }
        let issuer_key = if index == 0 {
            if event.action != MembershipAction::Genesis
                || event.issuer_device_id != event.subject_device_id
                || event.key_epoch != 1
            {
                return Err(MembershipError::InvalidHistory);
            }
            decode_key(&event.subject_public_key)?
        } else if event.action == MembershipAction::AcceptTransfer {
            if pending_transfer.as_deref() != Some(&event.issuer_device_id) || transfer_accepted {
                return Err(MembershipError::InvalidHistory);
            }
            let issuer = members
                .get(&event.issuer_device_id)
                .ok_or(MembershipError::InvalidHistory)?;
            if !issuer.active {
                return Err(MembershipError::InvalidHistory);
            }
            issuer.public_key
        } else {
            if event.action == MembershipAction::Genesis || event.issuer_device_id != manager {
                return Err(MembershipError::InvalidHistory);
            }
            members
                .get(&manager)
                .ok_or(MembershipError::InvalidHistory)?
                .public_key
        };
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&event.signature)
            .map_err(|_| MembershipError::InvalidSignature)?
            .try_into()
            .map_err(|_| MembershipError::InvalidSignature)?;
        if !verify_signature(&issuer_key, &bytes, &signature) {
            return Err(MembershipError::InvalidSignature);
        }

        match event.action {
            MembershipAction::Genesis | MembershipAction::Add => {
                let public_key = decode_key(&event.subject_public_key)?;
                if pending_transfer.is_some()
                    || event.key_epoch != epoch
                    || members.contains_key(&event.subject_device_id)
                    || members.values().filter(|member| member.active).count() >= MAX_ACTIVE_DEVICES
                    || members
                        .values()
                        .any(|member| member.public_key == public_key)
                {
                    return Err(MembershipError::InvalidHistory);
                }
                members.insert(
                    event.subject_device_id.clone(),
                    VerifiedMember {
                        device_id: event.subject_device_id.clone(),
                        public_key,
                        active: true,
                        added_by_device_id: event.issuer_device_id.clone(),
                        membership_sequence: event.sequence,
                        key_epoch: epoch,
                        removal_cutoff: None,
                    },
                );
                if index == 0 {
                    manager = event.subject_device_id.clone();
                }
            }
            MembershipAction::Remove => {
                // The subject key field is empty, or names the removed device's last accepted change.
                let cutoff = crate::protocol::parse_removal_cutoff(&event.subject_public_key)
                    .map_err(|_| MembershipError::InvalidHistory)?;
                if pending_transfer.is_some()
                    || event.subject_device_id == manager
                    || event.key_epoch != epoch + 1
                {
                    return Err(MembershipError::InvalidHistory);
                }
                let subject = members
                    .get_mut(&event.subject_device_id)
                    .ok_or(MembershipError::InvalidHistory)?;
                if !subject.active {
                    return Err(MembershipError::InvalidHistory);
                }
                epoch = event.key_epoch;
                subject.active = false;
                subject.membership_sequence = event.sequence;
                subject.key_epoch = epoch;
                subject.removal_cutoff = cutoff;
            }
            MembershipAction::OfferTransfer => {
                if !event.subject_public_key.is_empty()
                    || event.key_epoch != epoch
                    || pending_transfer.is_some()
                    || event.subject_device_id == manager
                    || !members
                        .get(&event.subject_device_id)
                        .is_some_and(|member| member.active)
                {
                    return Err(MembershipError::InvalidHistory);
                }
                pending_transfer = Some(event.subject_device_id.clone());
            }
            MembershipAction::AcceptTransfer => {
                if !event.subject_public_key.is_empty()
                    || event.key_epoch != epoch
                    || pending_transfer.as_deref() != Some(&event.subject_device_id)
                {
                    return Err(MembershipError::InvalidHistory);
                }
                transfer_accepted = true;
            }
            MembershipAction::CancelTransfer => {
                if !event.subject_public_key.is_empty()
                    || event.key_epoch != epoch
                    || pending_transfer.as_deref() != Some(&event.subject_device_id)
                {
                    return Err(MembershipError::InvalidHistory);
                }
                pending_transfer = None;
                transfer_accepted = false;
            }
            MembershipAction::Transfer => {
                if !event.subject_public_key.is_empty()
                    || event.key_epoch != epoch
                    || pending_transfer.as_deref() != Some(&event.subject_device_id)
                    || !transfer_accepted
                {
                    return Err(MembershipError::InvalidHistory);
                }
                manager = event.subject_device_id.clone();
                pending_transfer = None;
                transfer_accepted = false;
            }
        }
        previous_hash = &event.hash;
    }
    Ok(VerifiedMembership {
        vault_id: vault_id.clone(),
        manager_device_id: manager,
        key_epoch: epoch,
        head: previous_hash.to_owned(),
        members,
        pending_transfer,
        transfer_accepted,
    })
}

fn append_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), MembershipError> {
    if value.len() > 4096 {
        return Err(MembershipError::InvalidHistory);
    }
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_key(encoded: &str) -> Result<[u8; 32], MembershipError> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| MembershipError::InvalidHistory)?
        .try_into()
        .map_err(|_| MembershipError::InvalidHistory)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MembershipError {
    #[error("membership history is invalid")]
    InvalidHistory,
    #[error("membership signature is invalid")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn signed(
        key: &SigningKey,
        previous: Option<&MembershipEvent>,
        action: MembershipAction,
        issuer: &str,
        subject: &str,
        subject_key: &str,
        epoch: u64,
    ) -> MembershipEvent {
        let mut event = MembershipEvent {
            vault_id: "vault-a".to_owned(),
            sequence: previous.map_or(1, |event| event.sequence + 1),
            format_version: 1,
            previous_hash: previous.map_or(GENESIS_HASH.to_owned(), |event| event.hash.clone()),
            action,
            issuer_device_id: issuer.to_owned(),
            subject_device_id: subject.to_owned(),
            subject_public_key: subject_key.to_owned(),
            key_epoch: epoch,
            signature: String::new(),
            hash: String::new(),
        };
        let bytes = event.signing_bytes().unwrap();
        event.signature = URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes());
        event.hash = event.computed_hash(&bytes);
        event
    }

    #[test]
    fn verifies_android_format_admission_and_rejects_tampering() {
        let host = SigningKey::from_bytes(&[7; 32]);
        let peer = SigningKey::from_bytes(&[9; 32]);
        let genesis = signed(
            &host,
            None,
            MembershipAction::Genesis,
            "host",
            "host",
            &URL_SAFE_NO_PAD.encode(host.verifying_key().to_bytes()),
            1,
        );
        let add = signed(
            &host,
            Some(&genesis),
            MembershipAction::Add,
            "host",
            "windows",
            &URL_SAFE_NO_PAD.encode(peer.verifying_key().to_bytes()),
            1,
        );
        let verified = verify(&[genesis.clone(), add.clone()]).unwrap();
        assert_eq!(verified.head, add.hash);
        assert_eq!(verified.manager_device_id, "host");
        assert_eq!(
            verified.members["windows"].public_key,
            peer.verifying_key().to_bytes()
        );

        let mut changed = add.clone();
        changed.subject_device_id = "attacker".to_owned();
        changed.hash = changed.computed_hash(&changed.signing_bytes().unwrap());
        assert!(matches!(
            verify(&[genesis.clone(), changed]),
            Err(MembershipError::InvalidSignature)
        ));
        assert!(matches!(
            verify(&[add]),
            Err(MembershipError::InvalidHistory)
        ));
    }

    #[test]
    fn transfer_requires_recipient_acceptance_and_revocation_changes_epoch() {
        let host = SigningKey::from_bytes(&[7; 32]);
        let peer = SigningKey::from_bytes(&[9; 32]);
        let genesis = signed(
            &host,
            None,
            MembershipAction::Genesis,
            "host",
            "host",
            &URL_SAFE_NO_PAD.encode(host.verifying_key().to_bytes()),
            1,
        );
        let add = signed(
            &host,
            Some(&genesis),
            MembershipAction::Add,
            "host",
            "windows",
            &URL_SAFE_NO_PAD.encode(peer.verifying_key().to_bytes()),
            1,
        );
        let offer = signed(
            &host,
            Some(&add),
            MembershipAction::OfferTransfer,
            "host",
            "windows",
            "",
            1,
        );
        let accept = signed(
            &peer,
            Some(&offer),
            MembershipAction::AcceptTransfer,
            "windows",
            "windows",
            "",
            1,
        );
        let transfer = signed(
            &host,
            Some(&accept),
            MembershipAction::Transfer,
            "host",
            "windows",
            "",
            1,
        );
        assert!(matches!(
            verify(&[
                genesis.clone(),
                add.clone(),
                offer.clone(),
                transfer.clone()
            ]),
            Err(MembershipError::InvalidHistory)
        ));
        let verified = verify(&[
            genesis.clone(),
            add.clone(),
            offer.clone(),
            accept.clone(),
            transfer.clone(),
        ])
        .unwrap();
        assert_eq!(verified.manager_device_id, "windows");
        let remove = signed(
            &peer,
            Some(&transfer),
            MembershipAction::Remove,
            "windows",
            "host",
            "",
            2,
        );
        let verified = verify(&[genesis, add, offer, accept, transfer, remove]).unwrap();
        assert_eq!(verified.key_epoch, 2);
        assert!(!verified.members["host"].active);
    }

    #[test]
    fn a_signed_removal_may_name_the_removed_devices_last_change() {
        let host = SigningKey::from_bytes(&[7; 32]);
        let peer = SigningKey::from_bytes(&[9; 32]);
        let genesis = signed(&host, None, MembershipAction::Genesis, "host", "host",
            &URL_SAFE_NO_PAD.encode(host.verifying_key().to_bytes()), 1);
        let add = signed(&host, Some(&genesis), MembershipAction::Add, "host", "tablet",
            &URL_SAFE_NO_PAD.encode(peer.verifying_key().to_bytes()), 1);
        let hash = "ab".repeat(32);
        let remove = signed(&host, Some(&add), MembershipAction::Remove, "host", "tablet", &format!("cutoff1:7:{hash}"), 2);
        let verified = verify(&[genesis.clone(), add.clone(), remove]).unwrap();
        let tablet = &verified.members["tablet"];
        assert!(!tablet.active);
        assert_eq!(tablet.removal_cutoff, Some((7, hash)));
        let plain = signed(&host, Some(&add), MembershipAction::Remove, "host", "tablet", "", 2);
        assert_eq!(verify(&[genesis.clone(), add.clone(), plain]).unwrap().members["tablet"].removal_cutoff, None);
        let other = signed(&host, Some(&add), MembershipAction::Remove, "host", "tablet", "not-a-cutoff", 2);
        assert!(verify(&[genesis, add, other]).is_err(), "anything else in the field is still rejected");
    }
}
