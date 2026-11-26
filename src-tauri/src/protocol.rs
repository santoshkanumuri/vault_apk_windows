use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const KEY_ENVELOPE_FORMAT_VERSION: u16 = 1;
pub const PAIRING_CODE_DIGITS: u8 = 24;
pub const RECOVERY_SECRET_BITS: u16 = 256;

/// Announced in the sync handshake `features` list (Android `RemovalCutoff.FEATURE`): this build
/// accepts a REMOVE that names the removed device's last change, and accepts that device's
/// changes up to it.
pub const REMOVAL_CUTOFF_FEATURE: &str = "removal-cutoff-v1";
/// Announced by builds that read the synced vault appearance (`appearance.rs`). A build writes an
/// appearance change only when every other active member announced it.
pub const APPEARANCE_FEATURE: &str = "appearance-v1";
/// Announced by builds that read synced website icons (`site_icon_sync.rs`). A build writes an icon
/// change only when every other active member announced it.
pub const SITE_ICONS_FEATURE: &str = "site-icons-v1";
/// Announced by builds that read enrollment snapshot v4 (`checkpoint.rs`), relay only gap-free
/// chains and acknowledge old resends. The phone sends v4 only to a device that announced it.
pub const CHECKPOINT_ENROLL_FEATURE: &str = "checkpoint-enroll-v1";
/// Announced by builds that read synced sign-in methods (`sign_in_sync.rs`). A build writes a
/// sign-in method change only when every other active member announced it.
pub const SIGN_IN_METHODS_FEATURE: &str = "sign-in-methods-v1";
/// Announced in the pairing hello by builds that join a group keeping their items, matched by ID
/// (`merge_join.rs`). Used only when the phone announced it too.
pub const MERGE_JOIN_FEATURE: &str = crate::merge_join::FEATURE;
/// Also written to the Google Drive progress file (`features`), so a member that syncs only
/// through the drive announces them too (`cloud_sync.rs`).
/// Announced by builds that read changes of rotated key epochs and send a signed key statement
/// (`epoch_keys.rs`). The managing phone rotates only on statements, never on this string.
pub const EPOCH_KEYS_FEATURE: &str = crate::epoch_keys::FEATURE;
/// Announced by builds that read Google Drive floor markers (`compaction.rs` `drive`). Drive cleanup
/// runs only when every active member announced it.
pub const HISTORY_COMPACTION_FEATURE: &str = crate::compaction::drive::FEATURE;
/// Announced by builds that listen on the Wi-Fi port in 20000-32767 and try a paired device's
/// other ports when one refuses (`lan_sync::sync_port`, L5). While any other active member hasn't
/// announced it, a build also listens on the port older versions use.
pub const SYNC_PORTS_FEATURE: &str = "sync-ports-v2";
/// Announced by builds that switch to the managing phone's new master password when it changes
/// (`master_password.rs`). The phone changes its password while paired only when every other active
/// member announced it.
pub const MASTER_PASSWORD_FEATURE: &str = crate::master_password::FEATURE;
/// M12 and M11 (`refusal.rs`): this build tells a peer when it refuses what the peer sent, and
/// confirms received photo bytes as they arrive. Each is used only with a peer that announced it.
pub const SYNC_FEATURES: [&str; 12] = [REMOVAL_CUTOFF_FEATURE, APPEARANCE_FEATURE, SITE_ICONS_FEATURE, CHECKPOINT_ENROLL_FEATURE,
    SIGN_IN_METHODS_FEATURE, MERGE_JOIN_FEATURE, EPOCH_KEYS_FEATURE, HISTORY_COMPACTION_FEATURE, SYNC_PORTS_FEATURE,
    crate::refusal::FEATURE, crate::refusal::PHOTO_RECEIPTS_FEATURE, MASTER_PASSWORD_FEATURE];

/// `cutoff1:<sequence>:<hash>` in a REMOVE event's subject key field (Android `RemovalCutoff`).
/// `Ok(None)` for an empty field; `Err` for anything else that is not a valid cutoff.
pub fn parse_removal_cutoff(value: &str) -> Result<Option<(u64, String)>, ()> {
    if value.is_empty() {
        return Ok(None);
    }
    let rest = value.strip_prefix("cutoff1:").ok_or(())?;
    let (sequence, hash) = rest.split_once(':').ok_or(())?;
    let valid_sequence = !sequence.is_empty() && sequence.len() <= 19 && !sequence.starts_with('0')
        && sequence.bytes().all(|byte| byte.is_ascii_digit());
    let valid_hash = hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid_sequence || !valid_hash {
        return Err(());
    }
    Ok(Some((sequence.parse().map_err(|_| ())?, hash.to_owned())))
}

/// A change at `sequence` with `hash` by a removed device is within its `cutoff`.
pub fn within_removal_cutoff(cutoff: Option<&(u64, String)>, sequence: u64, hash: &str) -> bool {
    cutoff.is_some_and(|(last, last_hash)| (1..=*last).contains(&sequence) && (sequence != *last || hash == last_hash))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MemberStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMembership {
    pub vault_id: String,
    pub device_id: String,
    pub display_name: String,
    pub identity_public_key: String,
    pub status: MemberStatus,
    pub added_by_device_id: String,
    pub membership_sequence: u64,
    pub key_epoch: u64,
}

impl DeviceMembership {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_text("vaultId", &self.vault_id)?;
        require_text("deviceId", &self.device_id)?;
        require_text("displayName", &self.display_name)?;
        require_text("identityPublicKey", &self.identity_public_key)?;
        require_text("addedByDeviceId", &self.added_by_device_id)?;
        if self.membership_sequence == 0 {
            return Err(ProtocolError::ZeroValue("membershipSequence"));
        }
        if self.key_epoch == 0 {
            return Err(ProtocolError::ZeroValue("keyEpoch"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EnvelopeRecipientType {
    Password,
    Device,
    RecoveryCard,
    Backup,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultKeyEnvelope {
    pub format_version: u16,
    pub vault_id: String,
    pub key_epoch: u64,
    pub recipient_type: EnvelopeRecipientType,
    pub recipient_id: String,
    pub algorithm: String,
    pub nonce: String,
    pub wrapped_vault_key: String,
}

impl VaultKeyEnvelope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.format_version != KEY_ENVELOPE_FORMAT_VERSION {
            return Err(ProtocolError::UnsupportedEnvelopeFormat(
                self.format_version,
            ));
        }
        require_text("vaultId", &self.vault_id)?;
        require_text("recipientId", &self.recipient_id)?;
        require_text("algorithm", &self.algorithm)?;
        require_text("nonce", &self.nonce)?;
        require_text("wrappedVaultKey", &self.wrapped_vault_key)?;
        if self.key_epoch == 0 {
            return Err(ProtocolError::ZeroValue("keyEpoch"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncFrontier {
    counters: BTreeMap<String, u64>,
}

impl SyncFrontier {
    pub fn new(counters: BTreeMap<String, u64>) -> Self {
        Self { counters }
    }

    pub fn counters(&self) -> &BTreeMap<String, u64> {
        &self.counters
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        for device_id in self.counters.keys() {
            require_text("frontierDeviceId", device_id)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordVersion {
    counters: BTreeMap<String, u64>,
}

impl RecordVersion {
    pub fn new(counters: BTreeMap<String, u64>) -> Self {
        Self { counters }
    }

    pub fn from_entries<const N: usize>(entries: [(&str, u64); N]) -> Self {
        Self {
            counters: entries
                .into_iter()
                .map(|(device_id, counter)| (device_id.to_owned(), counter))
                .collect(),
        }
    }

    pub fn counters(&self) -> &BTreeMap<String, u64> {
        &self.counters
    }

    pub fn relation_to(&self, other: &Self) -> VersionRelation {
        let mut less = false;
        let mut greater = false;

        for device_id in self.counters.keys().chain(other.counters.keys()) {
            let left = self.counters.get(device_id).copied().unwrap_or_default();
            let right = other.counters.get(device_id).copied().unwrap_or_default();
            less |= left < right;
            greater |= left > right;
        }

        match (less, greater) {
            (false, false) => VersionRelation::Equal,
            (true, false) => VersionRelation::Before,
            (false, true) => VersionRelation::After,
            (true, true) => VersionRelation::Concurrent,
        }
    }

    /// The pointwise maximum of both versions: the smallest version that includes both.
    pub fn merged(&self, other: &Self) -> Self {
        let mut counters = self.counters.clone();
        for (device_id, counter) in &other.counters {
            let entry = counters.entry(device_id.clone()).or_default();
            *entry = (*entry).max(*counter);
        }
        Self { counters }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.counters.is_empty() {
            return Err(ProtocolError::EmptyRecordVersion);
        }
        for (device_id, counter) in &self.counters {
            require_text("recordVersionDeviceId", device_id)?;
            if *counter == 0 {
                return Err(ProtocolError::ZeroValue("recordVersionCounter"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionRelation {
    Before,
    After,
    Equal,
    Concurrent,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("{0} must not be blank")]
    BlankField(&'static str),
    #[error("{0} must be greater than zero")]
    ZeroValue(&'static str),
    #[error("unsupported key envelope format {0}")]
    UnsupportedEnvelopeFormat(u16),
    #[error("record version must contain at least one device")]
    EmptyRecordVersion,
}

fn require_text(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.trim().is_empty() {
        Err(ProtocolError::BlankField(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{ChangeRecord, SYNC_FORMAT_VERSION};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FoundationFixture {
        format_version: u16,
        pairing_code_digits: u8,
        recovery_secret_bits: u16,
        membership: DeviceMembership,
        key_envelope: VaultKeyEnvelope,
        frontier: SyncFrontier,
        change: ChangeRecord,
        expected_change_hash: String,
    }

    #[test]
    fn compares_concurrent_versions() {
        let left = RecordVersion::from_entries([("device-a", 2), ("device-b", 1)]);
        let right = RecordVersion::from_entries([("device-a", 1), ("device-b", 2)]);

        assert_eq!(left.relation_to(&right), VersionRelation::Concurrent);
        let merged = left.merged(&right);
        assert_eq!(merged, RecordVersion::from_entries([("device-a", 2), ("device-b", 2)]));
        assert_eq!(merged.relation_to(&left), VersionRelation::After);
        assert_eq!(merged.relation_to(&right), VersionRelation::After);
    }

    #[test]
    fn compares_ordered_versions() {
        let earlier = RecordVersion::from_entries([("device-a", 1)]);
        let later = RecordVersion::from_entries([("device-a", 2), ("device-b", 1)]);

        assert_eq!(earlier.relation_to(&later), VersionRelation::Before);
        assert_eq!(later.relation_to(&earlier), VersionRelation::After);
    }

    #[test]
    fn reads_shared_foundation_fixture() {
        let fixture: FoundationFixture =
            serde_json::from_str(include_str!("../fixtures/sync-foundation-v1.json"))
                .expect("fixture must deserialize");

        assert_eq!(fixture.format_version, SYNC_FORMAT_VERSION);
        assert_eq!(fixture.pairing_code_digits, PAIRING_CODE_DIGITS);
        assert_eq!(fixture.recovery_secret_bits, RECOVERY_SECRET_BITS);
        assert_eq!(fixture.membership.validate(), Ok(()));
        assert_eq!(fixture.key_envelope.validate(), Ok(()));
        assert_eq!(fixture.frontier.validate(), Ok(()));
        assert_eq!(fixture.change.record_version.validate(), Ok(()));
        assert_eq!(fixture.change.compute_hash(), fixture.expected_change_hash);
        assert_eq!(fixture.change.hash, fixture.expected_change_hash);
    }

    #[test]
    fn removal_cutoffs_parse_like_android_and_bound_the_removed_device() {
        let hash = "ab".repeat(32);
        assert_eq!(parse_removal_cutoff(""), Ok(None));
        assert_eq!(parse_removal_cutoff(&format!("cutoff1:12:{hash}")), Ok(Some((12, hash.clone()))));
        for bad in [format!("cutoff1:0:{hash}"), format!("cutoff1:012:{hash}"), format!("cutoff1:12:{}", "AB".repeat(32)),
            format!("cutoff2:12:{hash}"), "cutoff1:12".to_owned(), "a-public-key".to_owned()] {
            assert_eq!(parse_removal_cutoff(&bad), Err(()), "{bad}");
        }
        let cutoff = (3, hash.clone());
        assert!(within_removal_cutoff(Some(&cutoff), 1, &"00".repeat(32)));
        assert!(within_removal_cutoff(Some(&cutoff), 3, &hash));
        assert!(!within_removal_cutoff(Some(&cutoff), 3, &"cd".repeat(32)));
        assert!(!within_removal_cutoff(Some(&cutoff), 4, &hash));
        assert!(!within_removal_cutoff(None, 1, &hash));
    }
}
