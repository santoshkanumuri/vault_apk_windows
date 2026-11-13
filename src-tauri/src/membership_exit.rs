//! Leaving a sync group (SPEC3): the signed `leave1` request this PC sends to the managing
//! phone, and verification of the `removed1` removal notice a phone may answer with.
//!
//! Windows also accepts sync connections. Its listener answers a device on one of the last four
//! key epochs with `removed1` (see `lan_sync.rs`); those secrets are derived on demand.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::membership::{self, MembershipAction, MembershipEvent, VerifiedMembership};

/// Transport secret for a membership key epoch, as Android `TransportEpochs.secret`: epoch 1 is
/// the stored group secret; epoch N > 1 is HMAC-SHA256(epoch-1 secret, "nuvori-transport-epoch-v1:<vaultId>:<N>").
pub fn transport_epoch_secret(root: &[u8], vault_id: &str, epoch: u64) -> Option<Zeroizing<Vec<u8>>> {
    if root.len() != 32 || epoch == 0 {
        return None;
    }
    if epoch == 1 {
        return Some(Zeroizing::new(root.to_vec()));
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(root).ok()?;
    mac.update(format!("nuvori-transport-epoch-v1:{vault_id}:{epoch}").as_bytes());
    Some(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

/// What a verified `removed1` history means for this device.
#[derive(Debug)]
pub enum Notice {
    /// The history removes this device.
    Removed(Removal),
    /// This device is still active and only missed later membership events (a key epoch moved).
    CatchUp(VerifiedMembership),
}

/// A pending leave request is retried for at most this long, then dropped.
pub const LEAVE_RETENTION_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;

/// JSON body of a leave request, field order as in SPEC3.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaveRequest {
    pub vault_id: String,
    pub device_id: String,
    pub membership_head: String,
    pub key_epoch: u64,
    pub created_at: i64,
}

impl LeaveRequest {
    /// `nuvori-leave-v1\n<vaultId>\n<deviceId>\n<membershipHead>\n<keyEpoch>\n<createdAtMillis>`
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "nuvori-leave-v1\n{}\n{}\n{}\n{}\n{}",
            self.vault_id, self.device_id, self.membership_head, self.key_epoch, self.created_at
        )
        .into_bytes()
    }

    pub fn json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("leave request serializes")
    }
}

/// `leave1.<b64 proof>.<b64 json>.<b64 signature>`, sent in place of the transport proof.
pub fn leave_frame(proof: &[u8], request_json: &[u8], signature: &[u8; 64]) -> String {
    format!(
        "leave1.{}.{}.{}",
        URL_SAFE_NO_PAD.encode(proof),
        URL_SAFE_NO_PAD.encode(request_json),
        URL_SAFE_NO_PAD.encode(signature)
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaveReply {
    Left,
    NotManager,
    Busy,
    Unknown,
}

pub fn leave_reply(frame: &[u8]) -> LeaveReply {
    match frame {
        b"left1" => LeaveReply::Left,
        b"notmanager1" => LeaveReply::NotManager,
        b"busy1" => LeaveReply::Busy,
        _ => LeaveReply::Unknown,
    }
}

/// This PC's answer to another device's `leave1` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaveAnswer {
    /// Close without detail.
    Reject,
    /// The signed history already removes that device: reply `left1`.
    Left,
    /// The request is valid, but only the managing device can sign the removal: reply `notmanager1`.
    NotManager,
}

const LEAVE_MAX_CLOCK_SKEW_MILLIS: i64 = 5 * 60 * 1000;

/// Checks a `leave1` frame as Android `LeaveRequestHandler` does: the proof must match this
/// session's `challenge` under the secret of the request's key epoch (the current one or one of
/// the four before it), the request must name a point of this PC's signed history at that epoch,
/// and the signature must verify against the device's key in that history. A PC never signs a
/// removal, so a valid request from an active device gets `notmanager1`.
pub fn answer_leave(
    frame: &[u8],
    challenge: &[u8],
    root_secret: &[u8],
    events: &[MembershipEvent],
    local_device: &str,
    now: i64,
) -> LeaveAnswer {
    let parsed = (|| {
        let text = std::str::from_utf8(frame).ok()?.strip_prefix("leave1.")?;
        let mut parts = text.split('.').map(|part| URL_SAFE_NO_PAD.decode(part).ok());
        let (proof, json, signature) = (parts.next()??, parts.next()??, parts.next()??);
        if parts.next().is_some() || proof.len() != 32 {
            return None;
        }
        let request: LeaveRequest = serde_json::from_slice(&json).ok()?;
        Some((proof, request, <[u8; 64]>::try_from(signature).ok()?))
    })();
    let Some((proof, request, signature)) = parsed else { return LeaveAnswer::Reject };
    let Ok(verified) = membership::verify(events) else { return LeaveAnswer::Reject };
    let accepted = verified.key_epoch.saturating_sub(4).max(1)..=verified.key_epoch;
    if request.vault_id != verified.vault_id
        || request.device_id.is_empty()
        || request.device_id.len() > 128
        || !accepted.contains(&request.key_epoch)
        || request.created_at > now.saturating_add(LEAVE_MAX_CLOCK_SKEW_MILLIS)
        || request.created_at < now.saturating_sub(LEAVE_RETENTION_MILLIS)
    {
        return LeaveAnswer::Reject;
    }
    let proved = transport_epoch_secret(root_secret, &verified.vault_id, request.key_epoch).is_some_and(|secret| {
        let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(&secret) else { return false };
        mac.update(b"nuvori-lan-probe-v1");
        mac.update(challenge);
        mac.verify_slice(&proof).is_ok()
    });
    if !proved {
        return LeaveAnswer::Reject;
    }
    let epoch_at_head = events
        .iter()
        .position(|event| event.hash == request.membership_head)
        .and_then(|index| membership::verify(&events[..=index]).ok())
        .map(|history| history.key_epoch);
    if epoch_at_head != Some(request.key_epoch) {
        return LeaveAnswer::Reject;
    }
    let Some(member) = verified.members.get(&request.device_id) else { return LeaveAnswer::Reject };
    if !crate::identity::verify_signature(&member.public_key, &request.signing_bytes(), &signature) {
        return LeaveAnswer::Reject;
    }
    if !member.active {
        return LeaveAnswer::Left;
    }
    if request.device_id == verified.manager_device_id || verified.manager_device_id == local_device {
        return LeaveAnswer::Reject;
    }
    LeaveAnswer::NotManager
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemovalError {
    #[error("removal notice is not a valid signed history")]
    Invalid,
    #[error("removal notice does not extend this device's history")]
    Diverged,
    #[error("removal notice does not remove this device")]
    NotRemoved,
}

/// Who removed this device, from a verified history.
#[derive(Debug, PartialEq, Eq)]
pub struct Removal {
    pub issuer_device_id: String,
    pub sequence: u64,
}

/// Accepts a `removed1` history only if it verifies, extends `stored` exactly (same vault and
/// every stored event at the same sequence with the same hash), and contains a REMOVE of
/// `local_device` that leaves it inactive. Anything else is an unauthenticated claim.
pub fn verify_removal(
    stored: &[MembershipEvent],
    received: &[MembershipEvent],
    local_device: &str,
) -> Result<Notice, RemovalError> {
    let verified = membership::verify(received).map_err(|_| RemovalError::Invalid)?;
    if stored.is_empty()
        || received.len() < stored.len()
        || stored.iter().zip(received).any(|(mine, theirs)| mine.hash != theirs.hash || mine.sequence != theirs.sequence)
        || stored[0].vault_id != verified.vault_id
    {
        return Err(RemovalError::Diverged);
    }
    if verified.members.get(local_device).is_some_and(|member| member.active) {
        return if received.len() > stored.len() {
            Ok(Notice::CatchUp(verified))
        } else {
            Err(RemovalError::NotRemoved)
        };
    }
    let removal = received
        .iter()
        .rev()
        .find(|event| event.action == MembershipAction::Remove && event.subject_device_id == local_device)
        .ok_or(RemovalError::NotRemoved)?;
    Ok(Notice::Removed(Removal {
        issuer_device_id: removal.issuer_device_id.clone(),
        sequence: removal.sequence,
    }))
}

pub const PEER_SEEN_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS local_peer_seen (
    device_id TEXT NOT NULL PRIMARY KEY,
    seen_at INTEGER NOT NULL
)";

pub fn record_peer_seen(db: &Connection, device_id: &str, at: i64) -> rusqlite::Result<()> {
    db.execute_batch(PEER_SEEN_SCHEMA)?;
    db.execute(
        "INSERT INTO local_peer_seen (device_id, seen_at) VALUES (?1, ?2)
         ON CONFLICT(device_id) DO UPDATE SET seen_at = max(seen_at, excluded.seen_at)",
        params![device_id, at],
    )?;
    Ok(())
}

pub fn peer_seen(db: &Connection, device_id: &str) -> rusqlite::Result<i64> {
    db.execute_batch(PEER_SEEN_SCHEMA)?;
    Ok(db
        .query_row("SELECT seen_at FROM local_peer_seen WHERE device_id = ?1", [device_id], |row| row.get(0))
        .optional()?
        .unwrap_or(0))
}

pub const NOTICE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS local_membership_notices (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    removed_by TEXT NOT NULL DEFAULT '',
    removed_at INTEGER NOT NULL DEFAULT 0,
    leave_request TEXT NOT NULL DEFAULT '',
    leave_signature TEXT NOT NULL DEFAULT '',
    leave_secret BLOB,
    leave_address TEXT NOT NULL DEFAULT '',
    leave_attempted_at INTEGER NOT NULL DEFAULT 0
)";

/// A leave request waiting for the managing phone. Lives in the encrypted vault, survives the
/// local leave, and holds the old group's transport secret only to answer the phone's challenge.
pub struct PendingLeave {
    pub request: LeaveRequest,
    pub signature: [u8; 64],
    pub transport_secret: Zeroizing<Vec<u8>>,
    /// One address, or several separated by commas, tried in order.
    pub address: String,
}

/// The history sent with `removed1` to a device that proved `proved_epoch`, as Android
/// `MembershipWire.historyForEpoch`: everything up to and including the event that ended that
/// epoch. Devices added later are never shown to a holder of an old secret.
pub fn history_for_epoch(events: &[MembershipEvent], proved_epoch: u64) -> &[MembershipEvent] {
    match events.iter().position(|event| event.key_epoch > proved_epoch) {
        Some(end) => &events[..=end],
        None => events,
    }
}

/// At most `LIMIT` removal notices per minute, as Android `NoticeRateLimiter`.
pub fn removal_notice_allowed(now: std::time::Instant) -> bool {
    const LIMIT: usize = 10;
    static SENT: std::sync::Mutex<std::collections::VecDeque<std::time::Instant>> =
        std::sync::Mutex::new(std::collections::VecDeque::new());
    let Ok(mut sent) = SENT.lock() else { return false };
    while sent.front().is_some_and(|first| now.duration_since(*first) >= std::time::Duration::from_secs(60)) {
        sent.pop_front();
    }
    if sent.len() >= LIMIT {
        return false;
    }
    sent.push_back(now);
    true
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberRow {
    pub device_id: String,
    pub name: String,
    /// android | windows | unknown
    pub platform: &'static str,
    /// active | removed
    pub status: &'static str,
    pub is_manager: bool,
    pub is_this_device: bool,
    /// Unix ms of the last completed exchange with this device; 0 = unknown.
    pub last_seen: i64,
    /// Counts from the device's last report, computed as the phone's `peerSyncCounts`.
    pub counts: PeerCounts,
}

/// Changes still moving between this PC and one device, from its last progress report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerCounts {
    /// False until the device reported its progress once.
    pub checked: bool,
    /// This PC's changes the device has not received.
    pub to_send: u64,
    /// The device's changes received here and not applied yet.
    pub to_apply_here: u64,
    /// This PC's changes the device received and has not applied yet.
    pub received_there: u64,
    /// The device's own changes (as of its last report) that have not arrived here.
    pub to_receive_here: u64,
}

/// Android `peerSyncCounts`, over `(sequence, hash)` heads.
pub fn peer_counts(
    local_id: &str,
    peer_id: &str,
    local: &crate::progress::SyncProgress,
    peer: Option<&crate::progress::SyncProgress>,
) -> PeerCounts {
    let Some(peer) = peer else { return PeerCounts::default() };
    let head = |heads: &std::collections::BTreeMap<String, (u64, String)>, id: &str| heads.get(id).map_or(0, |head| head.0);
    let local_written = head(&local.applied, local_id);
    let remote_received = head(&peer.received, local_id);
    let remote_applied = head(&peer.applied, local_id);
    let peer_written = head(&peer.applied, peer_id);
    let local_received = head(&local.received, peer_id);
    let local_applied = head(&local.applied, peer_id);
    PeerCounts {
        checked: true,
        to_send: local_written.saturating_sub(remote_received),
        to_apply_here: local_received.saturating_sub(local_applied),
        received_there: remote_received.saturating_sub(remote_applied),
        to_receive_here: peer_written.saturating_sub(local_received),
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MembershipStatus {
    pub manager_device_id: String,
    pub manager_name: String,
    pub local_device_id: String,
    pub devices: Vec<MemberRow>,
    pub pending_transfer_to: String,
    pub transfer_accepted: bool,
    pub removed_notice: Option<RemovedNotice>,
    pub pending_leave: bool,
    /// First address a leave request from this PC goes to; empty when none is known.
    pub leave_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemovedNotice {
    pub by: String,
    pub at: i64,
}

fn ensure(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(NOTICE_SCHEMA)?;
    db.execute("INSERT OR IGNORE INTO local_membership_notices (id) VALUES (1)", [])?;
    Ok(())
}

pub fn store_pending_leave(db: &Connection, pending: &PendingLeave) -> rusqlite::Result<()> {
    ensure(db)?;
    db.execute(
        "UPDATE local_membership_notices SET leave_request = ?1, leave_signature = ?2, leave_secret = ?3,
             leave_address = ?4, leave_attempted_at = 0 WHERE id = 1",
        params![
            String::from_utf8_lossy(&pending.request.json()),
            URL_SAFE_NO_PAD.encode(pending.signature),
            &*pending.transport_secret,
            pending.address
        ],
    )?;
    Ok(())
}

/// The pending leave, or `None`. Requests older than 30 days are dropped here.
pub fn pending_leave(db: &Connection, now: i64) -> rusqlite::Result<Option<PendingLeave>> {
    ensure(db)?;
    let row: Option<(String, String, Option<Vec<u8>>, String)> = db
        .query_row(
            "SELECT leave_request, leave_signature, leave_secret, leave_address FROM local_membership_notices
             WHERE id = 1 AND leave_request != ''",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((json, signature, secret, address)) = row else {
        return Ok(None);
    };
    let parsed = serde_json::from_str::<LeaveRequest>(&json).ok().zip(
        URL_SAFE_NO_PAD
            .decode(signature)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok()),
    );
    match (parsed, secret) {
        (Some((request, signature)), Some(secret))
            if secret.len() == 32 && now - request.created_at <= LEAVE_RETENTION_MILLIS =>
        {
            Ok(Some(PendingLeave { request, signature, transport_secret: Zeroizing::new(secret), address }))
        }
        _ => {
            clear_pending_leave(db)?;
            Ok(None)
        }
    }
}

pub fn clear_pending_leave(db: &Connection) -> rusqlite::Result<()> {
    ensure(db)?;
    db.execute(
        "UPDATE local_membership_notices SET leave_request = '', leave_signature = '', leave_secret = NULL,
             leave_address = '', leave_attempted_at = 0 WHERE id = 1",
        [],
    )?;
    Ok(())
}

/// Records an attempt; returns false when the last attempt was under `min_gap_millis` ago.
pub fn claim_leave_attempt(db: &Connection, now: i64, min_gap_millis: i64) -> rusqlite::Result<bool> {
    ensure(db)?;
    Ok(db.execute(
        "UPDATE local_membership_notices SET leave_attempted_at = ?1
         WHERE id = 1 AND leave_request != '' AND (leave_attempted_at = 0 OR ?1 - leave_attempted_at >= ?2)",
        params![now, min_gap_millis],
    )? == 1)
}

pub fn record_removed(db: &Connection, by: &str, at: i64) -> rusqlite::Result<()> {
    ensure(db)?;
    db.execute(
        "UPDATE local_membership_notices SET removed_by = ?1, removed_at = ?2 WHERE id = 1",
        params![by, at],
    )?;
    Ok(())
}

pub fn removed_notice(db: &Connection) -> rusqlite::Result<Option<RemovedNotice>> {
    ensure(db)?;
    db.query_row(
        "SELECT removed_by, removed_at FROM local_membership_notices WHERE id = 1 AND removed_at != 0",
        [],
        |row| Ok(RemovedNotice { by: row.get(0)?, at: row.get(1)? }),
    )
    .optional()
}

pub fn dismiss_removed(db: &Connection) -> rusqlite::Result<()> {
    ensure(db)?;
    db.execute("UPDATE local_membership_notices SET removed_by = '', removed_at = 0 WHERE id = 1", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::sync::GENESIS_HASH;

    fn event(signer: &SigningKey, previous: Option<&MembershipEvent>, action: MembershipAction, subject: &str, key: &str, epoch: u64) -> MembershipEvent {
        let mut event = MembershipEvent {
            vault_id: "vault-a".into(),
            sequence: previous.map_or(1, |e| e.sequence + 1),
            format_version: 1,
            previous_hash: previous.map_or(GENESIS_HASH.into(), |e| e.hash.clone()),
            action,
            issuer_device_id: "phone".into(),
            subject_device_id: subject.into(),
            subject_public_key: key.into(),
            key_epoch: epoch,
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

    fn histories() -> (Vec<MembershipEvent>, Vec<MembershipEvent>, SigningKey) {
        let phone = SigningKey::from_bytes(&[17; 32]);
        let pc = SigningKey::from_bytes(&[18; 32]);
        let genesis = event(&phone, None, MembershipAction::Genesis, "phone",
            &URL_SAFE_NO_PAD.encode(phone.verifying_key().to_bytes()), 1);
        let add = event(&phone, Some(&genesis), MembershipAction::Add, "pc",
            &URL_SAFE_NO_PAD.encode(pc.verifying_key().to_bytes()), 1);
        let remove = event(&phone, Some(&add), MembershipAction::Remove, "pc", "", 2);
        (vec![genesis.clone(), add.clone()], vec![genesis, add, remove], phone)
    }

    #[test]
    fn removal_notice_must_extend_our_history_and_remove_us() {
        let (stored, removed, phone) = histories();
        assert!(matches!(verify_removal(&stored, &removed, "pc"),
            Ok(Notice::Removed(Removal { ref issuer_device_id, sequence: 3 })) if issuer_device_id == "phone"));
        assert_eq!(verify_removal(&stored, &stored, "pc").unwrap_err(), RemovalError::NotRemoved);
        assert!(matches!(verify_removal(&stored, &removed, "phone"), Ok(Notice::CatchUp(_))));
        let mut forged = removed.clone();
        forged[2].subject_device_id = "other".into();
        assert_eq!(verify_removal(&stored, &forged, "pc").unwrap_err(), RemovalError::Invalid);
        // A different, validly signed chain (another genesis) does not extend ours.
        let other_genesis = event(&phone, None, MembershipAction::Genesis, "phone",
            &URL_SAFE_NO_PAD.encode(phone.verifying_key().to_bytes()), 1);
        let mut diverged_stored = stored.clone();
        diverged_stored[0] = other_genesis.clone();
        diverged_stored[0].hash = "f".repeat(64);
        assert_eq!(verify_removal(&diverged_stored, &removed, "pc").unwrap_err(), RemovalError::Diverged);
        assert_eq!(verify_removal(&removed, &stored, "pc").unwrap_err(), RemovalError::Diverged, "a shorter history never removes us");
        assert_eq!(verify_removal(&[], &removed, "pc").unwrap_err(), RemovalError::Diverged);
    }

    #[test]
    fn leave_request_bytes_and_frame_follow_spec3() {
        let request = LeaveRequest {
            vault_id: "vault-a".into(), device_id: "pc".into(), membership_head: "ab".repeat(32),
            key_epoch: 1, created_at: 1_760_000_000_000,
        };
        assert_eq!(
            String::from_utf8(request.signing_bytes()).unwrap(),
            format!("nuvori-leave-v1\nvault-a\npc\n{}\n1\n1760000000000", "ab".repeat(32))
        );
        assert_eq!(
            String::from_utf8(request.json()).unwrap(),
            format!(r#"{{"vaultId":"vault-a","deviceId":"pc","membershipHead":"{}","keyEpoch":1,"createdAt":1760000000000}}"#, "ab".repeat(32))
        );
        let frame = leave_frame(&[1; 32], &request.json(), &[2; 64]);
        let parts: Vec<&str> = frame.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "leave1");
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap(), request.json());
        assert!(frame.len() < 4096 && frame.is_ascii());
        assert_eq!(leave_reply(b"left1"), LeaveReply::Left);
        assert_eq!(leave_reply(b"notmanager1"), LeaveReply::NotManager);
        assert_eq!(leave_reply(b"busy1"), LeaveReply::Busy);
        assert_eq!(leave_reply(b"ok"), LeaveReply::Unknown);
    }

    #[test]
    fn pending_leave_persists_and_expires_after_thirty_days() {
        let db = Connection::open_in_memory().unwrap();
        let request = LeaveRequest { vault_id: "v".into(), device_id: "pc".into(), membership_head: "h".into(), key_epoch: 1, created_at: 1_000 };
        store_pending_leave(&db, &PendingLeave { request: request.clone(), signature: [3; 64],
            transport_secret: Zeroizing::new(vec![5; 32]), address: "192.168.1.4".into() }).unwrap();
        let pending = pending_leave(&db, 2_000).unwrap().unwrap();
        assert_eq!((pending.request, pending.signature, pending.address.as_str()), (request, [3; 64], "192.168.1.4"));
        assert!(claim_leave_attempt(&db, 5_000, 60_000).unwrap());
        assert!(!claim_leave_attempt(&db, 6_000, 60_000).unwrap());
        assert!(claim_leave_attempt(&db, 70_000, 60_000).unwrap());
        assert!(pending_leave(&db, 1_000 + LEAVE_RETENTION_MILLIS + 1).unwrap().is_none());
        assert!(pending_leave(&db, 2_000).unwrap().is_none(), "expired requests are deleted");
        record_removed(&db, "Pixel 8", 42).unwrap();
        assert_eq!(removed_notice(&db).unwrap(), Some(RemovedNotice { by: "Pixel 8".into(), at: 42 }));
        dismiss_removed(&db).unwrap();
        assert_eq!(removed_notice(&db).unwrap(), None);
    }

    /// Shared Android/Windows vectors (`app/src/test/resources/sync-vectors/membership-v1.json`).
    #[test]
    fn matches_android_membership_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/membership-v1.json")).unwrap();
        let b64 = |value: &serde_json::Value| URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap();
        let transport = &vectors["transport"];
        let vault_id = transport["vaultId"].as_str().unwrap();
        let root = b64(&transport["epoch1SecretB64"]);
        for epoch in transport["epochs"].as_array().unwrap() {
            let derived = transport_epoch_secret(&root, vault_id, epoch["epoch"].as_u64().unwrap()).unwrap();
            assert_eq!(*derived, b64(&epoch["secretB64"]), "epoch {}", epoch["epoch"]);
        }

        let probe = &vectors["probe"];
        let challenge = hex::decode(probe["challengeHex"].as_str().unwrap()).unwrap();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&b64(&probe["secretB64"])).unwrap();
        mac.update(b"nuvori-lan-probe-v1");
        mac.update(&challenge);
        let proof = mac.finalize().into_bytes();
        assert_eq!(proof.to_vec(), b64(&probe["proofB64"]));

        let leave = &vectors["leaveRequest"];
        let request: LeaveRequest = serde_json::from_value(leave["fields"].clone()).unwrap();
        assert_eq!(String::from_utf8(request.json()).unwrap(), leave["json"].as_str().unwrap());
        assert_eq!(hex::encode(request.signing_bytes()), leave["signingBytesHex"].as_str().unwrap());
        let seed: [u8; 32] = hex::decode(vectors["client"]["seedHex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let client = SigningKey::from_bytes(&seed);
        assert_eq!(URL_SAFE_NO_PAD.encode(client.verifying_key().to_bytes()), vectors["client"]["publicKeyB64"].as_str().unwrap());
        let signature = client.sign(&request.signing_bytes()).to_bytes();
        assert_eq!(signature.to_vec(), b64(&leave["signatureB64"]));
        assert_eq!(leave_frame(&proof, &request.json(), &signature), leave["frame"].as_str().unwrap());
        assert_eq!(leave_reply(vectors["replies"]["left"].as_str().unwrap().as_bytes()), LeaveReply::Left);
        assert_eq!(leave_reply(vectors["replies"]["notManager"].as_str().unwrap().as_bytes()), LeaveReply::NotManager);
        assert_eq!(leave_reply(vectors["replies"]["busy"].as_str().unwrap().as_bytes()), LeaveReply::Busy);

        let history = &vectors["history"];
        let events: Vec<MembershipEvent> = serde_json::from_value(history["events"].clone()).unwrap();
        let head = history["clientHeadSequence"].as_u64().unwrap() as usize;
        let stored = &events[..head];
        assert_eq!(stored.last().unwrap().hash, history["clientHeadHash"].as_str().unwrap());
        assert_eq!(membership::verify(&events).unwrap().key_epoch, history["keyEpochAfter"].as_u64().unwrap());
        let client_id = history["clientDeviceId"].as_str().unwrap();
        match verify_removal(stored, &events, client_id).unwrap() {
            Notice::Removed(removal) => {
                assert_eq!(removal.issuer_device_id, vectors["manager"]["deviceId"].as_str().unwrap());
                assert_eq!(removal.sequence, 4);
            }
            Notice::CatchUp(_) => panic!("the client was removed"),
        }
        let other = vectors["other"]["deviceId"].as_str().unwrap();
        assert!(matches!(verify_removal(stored, &events, other), Ok(Notice::CatchUp(ref verified)) if verified.key_epoch == 2),
            "a remaining member catches up to the new epoch");
        let mut tampered = events.clone();
        tampered[3].subject_device_id = other.into();
        assert!(verify_removal(stored, &tampered, client_id).is_err());
    }

    #[test]
    fn removal_history_stops_at_the_event_that_ended_the_proved_epoch() {
        let event = |sequence: u64, key_epoch: u64| MembershipEvent {
            vault_id: "vault-a".into(), sequence, format_version: 1, previous_hash: String::new(),
            action: MembershipAction::Remove, issuer_device_id: "host".into(), subject_device_id: "x".into(),
            subject_public_key: String::new(), key_epoch, signature: String::new(), hash: format!("h{sequence}"),
        };
        let events = [event(1, 1), event(2, 1), event(3, 2), event(4, 2), event(5, 3)];
        assert_eq!(history_for_epoch(&events, 1).len(), 3, "epoch 1 ends at the first epoch-2 event");
        assert_eq!(history_for_epoch(&events, 2).len(), 5);
        assert_eq!(history_for_epoch(&events, 3).len(), 5, "the current epoch sees everything");
    }

    #[test]
    fn removal_notices_are_limited_to_ten_a_minute() {
        let start = std::time::Instant::now() + std::time::Duration::from_secs(3600);
        let allowed = (0..12).filter(|_| removal_notice_allowed(start)).count();
        assert_eq!(allowed, 10);
        assert!(removal_notice_allowed(start + std::time::Duration::from_secs(61)));
    }

    /// The leave request of the shared vectors, answered by a device that is not the manager.
    #[test]
    fn answers_a_leave_request_like_android_without_signing_a_removal() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/membership-v1.json")).unwrap();
        let b64 = |value: &serde_json::Value| URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap();
        let root = b64(&vectors["transport"]["epoch1SecretB64"]);
        let challenge = hex::decode(vectors["probe"]["challengeHex"].as_str().unwrap()).unwrap();
        let leave = &vectors["leaveRequest"];
        let frame = leave["frame"].as_str().unwrap().as_bytes();
        let now = leave["serverNowMillis"].as_i64().unwrap();
        let removed: Vec<MembershipEvent> = serde_json::from_value(vectors["history"]["events"].clone()).unwrap();
        let before = &removed[..vectors["history"]["clientHeadSequence"].as_u64().unwrap() as usize];
        let other = vectors["other"]["deviceId"].as_str().unwrap();
        let manager = vectors["manager"]["deviceId"].as_str().unwrap();

        assert_eq!(answer_leave(frame, &challenge, &root, before, other, now), LeaveAnswer::NotManager);
        assert_eq!(answer_leave(frame, &challenge, &root, &removed, other, now), LeaveAnswer::Left,
            "a history that already removes the device confirms the leave");
        assert_eq!(answer_leave(frame, &challenge, &root, before, manager, now), LeaveAnswer::Reject,
            "this PC never signs a removal");
        assert_eq!(answer_leave(frame, &[7; 32], &root, before, other, now), LeaveAnswer::Reject,
            "a frame captured in another session does not match this challenge");
        assert_eq!(answer_leave(frame, &challenge, &root, before, other, now + LEAVE_RETENTION_MILLIS + 1), LeaveAnswer::Reject);
        let mut forged = frame.to_vec();
        let last = forged.len() - 1;
        forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(answer_leave(&forged, &challenge, &root, before, other, now), LeaveAnswer::Reject);
        assert_eq!(answer_leave(b"leave1.a.b", &challenge, &root, before, other, now), LeaveAnswer::Reject);
    }
}
