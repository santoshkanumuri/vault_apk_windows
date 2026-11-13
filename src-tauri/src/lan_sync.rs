//! Android LAN exchange. Network waits never hold the vault mutex.
//!
//! Wire limits come from Android's `LanSyncExchange.kt`: one connection alternates at most
//! 32 receive/send rounds, each batch carries at most 100 operations, and every operation is
//! one encrypted frame of at most 2 MiB. Windows stays inside those limits, adds a byte budget
//! per batch, and reconnects within one sync pass while the phone still has more changes.
use crate::{
    ManagedState,
    identity::verify_signature,
    incoming::IncomingVerifier,
    incoming_apply::{ApplyError, IncomingApply},
    incoming_store::IncomingStore,
    membership::{self, MembershipEvent, VerifiedMembership},
    pairing::{self, PairingError},
    photo_blobs::{self, PhotoBlobs},
    progress::SyncProgress,
    snapshot::SnapshotMember,
    sync::{ChangeRecord, GENESIS_HASH},
    vault::UnlockedVault,
    wire::{EncryptedSyncChannel, MAX_FRAME, SyncFrames, WireError},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, String>;

/// Android loops `repeat(32)` per connection; more rounds would desynchronize the peers.
const MAX_ROUNDS: usize = 32;
/// Android rejects a batch announcement above 100 (`require(count in 0..100)`).
const MAX_BATCH_OPERATIONS: usize = 100;
/// Keeps one outgoing batch short on slow Wi-Fi. A batch always carries at least one change.
const BATCH_BYTE_BUDGET: usize = 4 * 1024 * 1024;
/// Reconnects within one sync pass while the phone reports more changes.
const MAX_SESSIONS: usize = 16;
/// Android's socket timeout is 30 s, so wait a little longer and let its timeout fire first.
const READ_IDLE: Duration = Duration::from_secs(45);
const WRITE_IDLE: Duration = Duration::from_secs(30);
/// Slowest throughput assumed when sizing a write timeout.
const MIN_BYTES_PER_SECOND: u64 = 32 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) const UNREACHABLE: &str =
    "No paired device answered. Keep device sync on, use the same local network, and allow Nuvori through Windows Firewall for your local network.";
pub(crate) const REJECTED: &str = "The device did not prove membership in this vault group.";
pub(crate) const BUSY: &str = "The device is busy syncing with another device. Retrying shortly.";
pub(crate) const TIMED_OUT: &str = "Timed out. The device stopped responding. Saved changes are kept.";
pub(crate) const INTERRUPTED: &str =
    "Connection interrupted. Saved changes are kept and sync resumes next time.";
const REMOVED: &str = "This PC is no longer in the sync group. Pair again.";
pub(crate) const REMOVED_NOTICE: &str = "This PC was removed from the sync group. Your items stay on this PC.";
/// Internal: the device list caught up to a later key epoch; the pass reconnects at once.
const MEMBERSHIP_UPDATED: &str = "The device list changed. Syncing again.";
/// Internal: the listener answered a `leave1` request; no sync happened.
const LEAVE_ANSWERED: &str = "A device asked to leave the sync group.";
const MORE_REMAIN: &str = "More changes remain. Sync will continue on the next pass.";
const TOO_LARGE: &str = "A saved change is too large to sync. Existing items are kept.";
/// Android serves and requests at most 32 photos per exchange (`servePhotos` `require(requests.size <= 32)`).
const MAX_PHOTO_REQUESTS: usize = 32;
const PHOTO_FAILED: &str = "A photo failed its integrity check. It will download again next time.";

#[derive(Serialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub sent: usize,
    pub received: usize,
    pub waiting_to_apply: usize,
    pub conflicts: usize,
    /// Photo blobs downloaded from / uploaded to the phone in this pass.
    pub photos_received: usize,
    pub photos_sent: usize,
    /// This device's change count when the pass started (follow-up pass detection; not sent to the UI).
    #[serde(skip)]
    pub local_revision_at_start: u64,
    #[serde(skip)]
    pub peer_device_id: String,
    pub peers_checked: usize,
    pub peers_waiting: usize,
    /// This pass also exchanged changes through the cloud drive.
    pub cloud: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    last_sync: String,
    waiting_to_apply: usize,
    /// Part of `waiting_to_apply`: changes this PC could not read (set aside, retried each pass).
    set_aside: usize,
    conflicts: usize,
    pub phone_address: String,
    pub automatic: bool,
    pub running: bool,
    pub message: String,
    /// idle | connecting | sending | receiving | applying | done | error
    pub phase: &'static str,
    pub progress_done: u64,
    pub progress_total: u64,
    /// Short human text without secrets; empty when the last pass succeeded.
    pub last_error: String,
    /// RFC 3339 start of the last attempt, or empty.
    pub last_attempt: String,
    pub consecutive_failures: u32,
    /// Seconds until the next automatic retry; 0 when none is scheduled.
    pub next_retry_seconds: u64,
    /// How often automatic sync checks devices on this Wi-Fi (one of [`WIFI_CHECKS`]).
    pub wifi_check_seconds: u64,
    /// How often it checks Google Drive (one of [`DRIVE_CHECKS`]); 0 = only on Sync now.
    pub drive_check_seconds: u64,
}

/// Wi-Fi check intervals offered on the Sync page; the same choices as the phone.
pub(crate) const WIFI_CHECKS: [u64; 4] = [30, 60, 300, 900];
/// Google Drive check intervals. 0 = only when this PC unlocks, on Sync now, and after its own
/// changes (they still upload about 2 seconds after each change).
pub(crate) const DRIVE_CHECKS: [u64; 4] = [15, 60, 300, 0];
const DEFAULT_WIFI_CHECK: u64 = 60;
const DEFAULT_DRIVE_CHECK: u64 = 15;

/// How often the automatic loop checks each way. A setting of this PC, not of the vault group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Schedule {
    pub wifi_seconds: u64,
    pub drive_seconds: u64,
}

fn schedule_table(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS local_sync_schedule (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        wifi_seconds INTEGER NOT NULL,
        drive_seconds INTEGER NOT NULL)")
}

/// The saved schedule. A missing or unknown value falls back to its default.
pub(crate) fn schedule(db: &Connection) -> Schedule {
    let stored = schedule_table(db).ok().and_then(|()| db.query_row(
        "SELECT wifi_seconds, drive_seconds FROM local_sync_schedule WHERE id = 1", [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))).optional().ok().flatten());
    let pick = |value: Option<i64>, allowed: &[u64], default: u64| value
        .and_then(|value| u64::try_from(value).ok()).filter(|value| allowed.contains(value)).unwrap_or(default);
    Schedule {
        wifi_seconds: pick(stored.map(|value| value.0), &WIFI_CHECKS, DEFAULT_WIFI_CHECK),
        drive_seconds: pick(stored.map(|value| value.1), &DRIVE_CHECKS, DEFAULT_DRIVE_CHECK),
    }
}

pub(crate) fn set_schedule(db: &Connection, schedule: Schedule) -> Result<()> {
    if !WIFI_CHECKS.contains(&schedule.wifi_seconds) || !DRIVE_CHECKS.contains(&schedule.drive_seconds) {
        return Err("Choose one of the listed check intervals.".into());
    }
    schedule_table(db).map_err(storage_error)?;
    db.execute("INSERT INTO local_sync_schedule (id, wifi_seconds, drive_seconds) VALUES (1, ?1, ?2)
        ON CONFLICT(id) DO UPDATE SET wifi_seconds = excluded.wifi_seconds, drive_seconds = excluded.drive_seconds",
        params![schedule.wifi_seconds as i64, schedule.drive_seconds as i64]).map_err(storage_error)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Idle,
    Connecting,
    Sending,
    Receiving,
    Applying,
    Done,
    Error,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::Sending => "sending",
            Self::Receiving => "receiving",
            Self::Applying => "applying",
            Self::Done => "done",
            Self::Error => "error",
        }
    }
}

#[derive(Default)]
struct TrackerState {
    generation: u64,
    phase: Phase,
    done: u64,
    total: u64,
    outgoing_remaining: u64,
    incoming_remaining: u64,
    last_error: String,
    last_attempt: String,
    consecutive_failures: u32,
    next_retry_at: Option<Instant>,
    photo_transferred: u64,
    photo_total: u64,
}

impl TrackerState {
    fn recompute(&mut self) {
        self.total = self
            .total
            .max(self.done + self.outgoing_remaining + self.incoming_remaining);
    }
}

/// Live sync progress for `sync_status`. It has its own lock and is never held with the
/// vault mutex across network waits.
#[derive(Default)]
pub struct SyncTracker {
    state: Mutex<TrackerState>,
}

impl SyncTracker {
    fn update(&self, change: impl FnOnce(&mut TrackerState)) {
        if let Ok(mut state) = self.state.lock() {
            change(&mut state);
        }
    }

    pub fn begin(&self) {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        self.update(|state| {
            state.generation = state.generation.wrapping_add(1);
            state.phase = Phase::Connecting;
            state.done = 0;
            state.total = 0;
            state.outgoing_remaining = 0;
            state.incoming_remaining = 0;
            state.last_attempt = now;
            state.next_retry_at = None;
            state.photo_transferred = 0;
            state.photo_total = 0;
        });
    }

    pub fn set_phase(&self, phase: Phase) {
        self.update(|state| state.phase = phase);
    }

    fn outgoing_remaining(&self, remaining: u64) {
        self.update(|state| {
            state.outgoing_remaining = remaining;
            state.recompute();
        });
    }

    fn incoming_announced(&self, count: u64) {
        self.update(|state| {
            state.incoming_remaining += count;
            state.recompute();
        });
    }

    fn sent_one(&self) {
        self.update(|state| {
            state.done += 1;
            state.outgoing_remaining = state.outgoing_remaining.saturating_sub(1);
            state.recompute();
        });
    }

    fn received_one(&self) {
        self.update(|state| {
            state.done += 1;
            state.incoming_remaining = state.incoming_remaining.saturating_sub(1);
            state.recompute();
        });
    }

    pub fn succeed(&self) {
        self.update(|state| {
            state.phase = Phase::Done;
            state.incoming_remaining = 0;
            state.outgoing_remaining = 0;
            state.last_error.clear();
            state.consecutive_failures = 0;
            state.next_retry_at = None;
        });
    }

    pub fn fail(&self, message: &str) {
        self.update(|state| {
            state.phase = Phase::Error;
            state.incoming_remaining = 0;
            state.outgoing_remaining = 0;
            state.last_error = message.to_owned();
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        });
    }

    /// Replaces the sentence of a failure that was already counted.
    pub fn set_error(&self, message: &str) {
        self.update(|state| state.last_error = message.to_owned());
    }

    fn defer_busy(&self) {
        self.update(|state| {
            state.phase = Phase::Idle;
            state.last_error = BUSY.to_owned();
            state.consecutive_failures = 0;
        });
    }

    pub fn peer_busy(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.last_error == BUSY)
    }

    fn photo_expected(&self, bytes: u64) {
        self.update(|state| state.photo_total = state.photo_total.saturating_add(bytes));
    }

    fn photo_moved(&self, bytes: u64) {
        self.update(|state| {
            state.photo_transferred = state.photo_transferred.saturating_add(bytes);
            state.photo_total = state.photo_total.max(state.photo_transferred);
        });
    }

    /// `(transferred, total)` photo bytes of the current or last pass.
    pub fn photo_bytes(&self) -> (u64, u64) {
        self.state
            .lock()
            .map_or((0, 0), |state| (state.photo_transferred, state.photo_total))
    }

    pub fn schedule_retry(&self, at: Option<Instant>) {
        self.update(|state| state.next_retry_at = at);
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.state
            .lock()
            .map_or(0, |state| state.consecutive_failures)
    }

    #[cfg(test)]
    pub fn progress(&self) -> (Phase, u64, u64) {
        self.state
            .lock()
            .map_or((Phase::Idle, 0, 0), |state| (state.phase, state.done, state.total))
    }

    pub fn fill(&self, status: &mut SyncStatus) {
        if let Ok(state) = self.state.lock() {
            status.phase = state.phase.as_str();
            status.progress_done = state.done;
            status.progress_total = state.total;
            status.last_error = state.last_error.clone();
            status.last_attempt = state.last_attempt.clone();
            status.consecutive_failures = state.consecutive_failures;
            status.next_retry_seconds = state.next_retry_at.map_or(0, |at| {
                let left = at.saturating_duration_since(Instant::now());
                left.as_secs() + u64::from(left.subsec_nanos() > 0)
            });
        }
    }
}

/// Exponential backoff with ±20% jitter for automatic retries: 15 s, 30 s, 60 s, ... capped at 5 min.
pub(crate) fn retry_delay(failures: u32, jitter: u16) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let base = 15u64.saturating_mul(1u64 << failures.saturating_sub(1).min(5)).min(300);
    // jitter maps 0..=u16::MAX onto 0.8..=1.2 of the base delay.
    let scaled = base * 1000 * (800 + u64::from(jitter) * 400 / u64::from(u16::MAX)) / 1000;
    Duration::from_millis(scaled.min(300_000))
}

pub(crate) fn random_jitter() -> u16 {
    let mut bytes = [0u8; 2];
    let _ = getrandom::fill(&mut bytes);
    u16::from_le_bytes(bytes)
}

pub(crate) fn status(vault: &mut UnlockedVault) -> Result<SyncStatus> {
    let db = vault.connection();
    let id: String = db
        .query_row(
            "SELECT vault_id FROM local_sync_settings WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .map_err(storage_error)?;
    let last_sync = db
        .query_row(
            "SELECT last_sync_utc FROM sync_exchange_state WHERE vault_id = ?1",
            [&id],
            |r| r.get(0),
        )
        .optional()
        .map_err(storage_error)?
        .unwrap_or_default();
    let (phone_address, automatic) = configuration(vault)?;
    let db = vault.connection();
    Ok(SyncStatus {
        last_sync,
        phone_address,
        automatic,
        running: false,
        message: String::new(),
        waiting_to_apply: waiting(db, &id)?.len(),
        set_aside: set_aside_count(db, &id),
        conflicts: db
            .query_row(
                "SELECT count(*) FROM sync_conflicts WHERE resolved_at_utc = ''",
                [],
                |r| r.get::<_, u32>(0),
            )
            .map_err(storage_error)? as usize,
        phase: Phase::Idle.as_str(),
        progress_done: 0,
        progress_total: 0,
        last_error: String::new(),
        last_attempt: String::new(),
        consecutive_failures: 0,
        next_retry_seconds: 0,
        wifi_check_seconds: schedule(db).wifi_seconds,
        drive_check_seconds: schedule(db).drive_seconds,
    })
}

pub(crate) fn configuration(vault: &mut UnlockedVault) -> Result<(String, bool)> {
    vault.connection().query_row("SELECT phone_address, automatic FROM sync_exchange_state WHERE vault_id = (SELECT vault_id FROM local_sync_settings WHERE id = 1)", [], |row| Ok((row.get(0)?, row.get(1)?))).optional().map_err(storage_error).map(|value| value.unwrap_or_else(|| (String::new(), true)))
}

pub(crate) fn configure(vault: &mut UnlockedVault, address: &str, automatic: bool) -> Result<()> {
    if !vault.is_enrolled().map_err(storage_error)? {
        return Err("Pair this PC with your phone first".into());
    }
    let db = vault.connection();
    let id: String = db
        .query_row(
            "SELECT vault_id FROM local_sync_settings WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .map_err(storage_error)?;
    if !address.trim().is_empty() { endpoint(address, &id)?; }
    db.execute("INSERT INTO sync_exchange_state (vault_id, phone_address, automatic) VALUES (?1, ?2, ?3) ON CONFLICT(vault_id) DO UPDATE SET phone_address = excluded.phone_address, automatic = excluded.automatic", params![id, address.trim(), automatic]).map_err(storage_error)?;
    Ok(())
}

/// Checks every discovered or last-authenticated endpoint, so one offline peer cannot block others.
pub(crate) fn run(state: &ManagedState, helper: &Path, address: &str,
    tracker: &SyncTracker, discovered: &[SocketAddr]) -> Result<SyncReport> {
    let (id, local, peers, saved, revision) = {
        let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
        let local = app.store.identity_store().get_or_create().map_err(storage_error)?.device_id;
        let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
        let revision = u64::from(vault.local_change_count().map_err(storage_error)?);
        let events = vault.stored_membership().map_err(storage_error)?;
        let membership = membership::verify(&events).map_err(storage_error)?;
        let peers: std::collections::BTreeSet<_> = membership.members.values()
            .filter(|member| member.active && member.device_id != local)
            .map(|member| member.device_id.clone()).collect();
        let db = vault.connection();
        let mut query = db.prepare("SELECT peer_device_id, address FROM sync_peer_endpoints WHERE vault_id = ?1").map_err(storage_error)?;
        let saved = query.query_map([&membership.vault_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .map_err(storage_error)?.collect::<std::result::Result<Vec<_>, _>>().map_err(storage_error)?;
        (membership.vault_id, local, peers, saved, revision)
    };
    tracker.begin();
    let mut targets = Vec::new();
    if !address.trim().is_empty() { targets.push(endpoint(address, &id)?); }
    targets.extend(saved.into_iter().filter(|(peer, _)| peers.contains(peer))
        .filter_map(|(_, address)| endpoint(&address, &id).ok()));
    targets.extend_from_slice(discovered);
    let mut seen = std::collections::BTreeSet::new();
    targets.retain(|target| seen.insert(*target));
    let mut checked = std::collections::BTreeSet::new();
    let mut total = SyncReport { local_revision_at_start: revision, ..Default::default() };
    let mut last_error = UNREACHABLE.to_owned();
    for target in targets.into_iter().take(64) {
        match run_to(state, helper, &target.to_string(), tracker) {
            Ok(report) => {
                if report.peer_device_id != local { checked.insert(report.peer_device_id.clone()); }
                total.sent += report.sent;
                total.received += report.received;
                total.photos_sent += report.photos_sent;
                total.photos_received += report.photos_received;
                total.waiting_to_apply = report.waiting_to_apply;
                total.conflicts = report.conflicts;
            }
            Err(error) => {
                if error != REJECTED && (last_error == UNREACHABLE || error == BUSY) {
                    last_error = error;
                }
            }
        }
        if checked.len() == peers.len() { break; }
    }
    if checked.is_empty() {
        if last_error == BUSY { tracker.defer_busy(); } else { tracker.fail(&last_error); }
        return Err(last_error);
    }
    total.peers_checked = checked.len();
    total.peers_waiting = peers.len().saturating_sub(checked.len());
    tracker.succeed();
    Ok(total)
}

pub(crate) fn reply_busy(stream: TcpStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let _ = SyncFrames::new(io::empty(), stream).send(BUSY_REPLY, 4096);
}

/// Android `MembershipWire.BUSY`: the word a phone sends, and expects, when the sync lock is held.
const BUSY_REPLY: &[u8] = b"busy1";

/// True for a busy reply from a phone (`busy1`) or from Windows up to 2.1.6 (`busy`).
fn is_busy_reply(frame: &[u8]) -> bool {
    frame == BUSY_REPLY || frame == b"busy"
}

/// Only called after signed enrollment or an authenticated exchange has committed.
pub(crate) fn remember_peer_endpoint(vault: &mut UnlockedVault, vault_id: &str, peer: &str,
    address: SocketAddr) -> rusqlite::Result<()> {
    if crate::discovery::private_address(address.ip()) {
        vault.connection().execute("INSERT INTO sync_peer_endpoints (vault_id, peer_device_id, address) VALUES (?1, ?2, ?3) ON CONFLICT(vault_id, peer_device_id) DO UPDATE SET address = excluded.address",
            params![vault_id, peer, address.to_string()])?;
    }
    Ok(())
}

pub(crate) fn serve(state: &ManagedState, helper: &Path, stream: TcpStream,
    tracker: &SyncTracker) -> Result<SyncReport> {
    let before = tracker.state.lock().map_or(0, |state| state.generation);
    let result = exchange_role(state, helper, tracker, true, |_| Ok(stream));
    match result {
        Ok((report, true)) => { tracker.succeed(); Ok(report) }
        Ok((_, false)) => { tracker.fail(MORE_REMAIN); Err(MORE_REMAIN.into()) }
        Err(error) => {
            // A nearby device outside this group must not replace the paired-device status.
            let authenticated = tracker.state.lock().is_ok_and(|state| state.generation != before);
            if authenticated { tracker.fail(&error); }
            Err(error)
        }
    }
}

/// One user-visible sync pass. Reconnects while the phone still has more changes.
fn run_to(
    state: &ManagedState,
    helper: &Path,
    address: &str,
    tracker: &SyncTracker,
) -> Result<SyncReport> {
    let revision = state
        .lock()
        .ok()
        .and_then(|app| app.unlocked.as_ref().map(UnlockedVault::local_change_count))
        .and_then(std::result::Result::ok)
        .map_or(0, u64::from);
    let mut caught_up = false;
    let result = run_sessions(|| loop {
        tracker.set_phase(Phase::Connecting);
        let session = exchange(state, helper, tracker, |vault_id| {
            TcpStream::connect_timeout(&endpoint(address, vault_id)?, CONNECT_TIMEOUT)
                .map_err(|_| UNREACHABLE.into())
        });
        // After catching up to a later key epoch, reconnect once with that epoch's secret.
        if matches!(&session, Err(error) if error == MEMBERSHIP_UPDATED) && !caught_up {
            caught_up = true;
            continue;
        }
        break session;
    });
    result.map(|report| SyncReport { local_revision_at_start: revision, ..report })
}

/// Repeats bounded sessions until one completes, a session makes no progress, or the cap is hit.
/// Each session commits what it received, so a later pass resumes from the saved frontier.
fn run_sessions(mut session: impl FnMut() -> Result<(SyncReport, bool)>) -> Result<SyncReport> {
    let mut total = SyncReport::default();
    for _ in 0..MAX_SESSIONS {
        let (report, complete) = session()?;
        total.sent += report.sent;
        total.received += report.received;
        total.waiting_to_apply = report.waiting_to_apply;
        total.conflicts = report.conflicts;
        total.photos_received += report.photos_received;
        total.photos_sent += report.photos_sent;
        total.peer_device_id = report.peer_device_id;
        if complete {
            return Ok(total);
        }
        if report.sent == 0 && report.received == 0 && report.photos_received == 0 {
            break;
        }
    }
    Err(MORE_REMAIN.into())
}

/// Sets per-write timeouts proportional to the buffer size. Reads use an idle timeout set on
/// the socket, so a long transfer never hits a fixed session deadline while data flows.
pub(crate) struct PacedWriter {
    stream: TcpStream,
}

impl Write for PacedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(write_timeout(buffer.len())))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub(crate) fn write_timeout(bytes: usize) -> Duration {
    WRITE_IDLE + Duration::from_millis((bytes as u64).saturating_mul(1000) / MIN_BYTES_PER_SECOND)
}

fn exchange(state: &ManagedState, helper: &Path, tracker: &SyncTracker,
    connect: impl FnOnce(&str) -> Result<TcpStream>) -> Result<(SyncReport, bool)> {
    exchange_role(state, helper, tracker, false, connect)
}

fn exchange_role(
    state: &ManagedState,
    helper: &Path,
    tracker: &SyncTracker,
    server: bool,
    connect: impl FnOnce(&str) -> Result<TcpStream>,
) -> Result<(SyncReport, bool)> {
    if !helper.is_file() {
        return Err("The pairing helper is missing. Rebuild or reinstall Nuvori.".into());
    }
    let (vault_id, events, secret, content_key, signer, blobs) = {
        let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
        let signer = app.store.identity_store();
        let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
        // Photos added before pairing or migrated into the group get their signed change now.
        let _ = vault.publish_unsynced_photos();
        let blobs = vault.photo_blobs();
        let db = vault.connection();
        let (id, transport, content): (String, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT vault_id, transport_secret, content_key FROM sync_group_state",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| "Pair this PC with your phone first")?;
        (
            id.clone(),
            read_membership(db, &id)?,
            Zeroizing::new(transport),
            Zeroizing::new(content),
            signer,
            blobs,
        )
    };
    if secret.len() != 32 || content_key.len() != 32 {
        return Err("Invalid sync keys".into());
    }
    let local = signer
        .get_or_create()
        .map_err(|_| "Device identity unavailable")?;
    let membership = membership::verify(&events).map_err(|_| "Invalid signed membership")?;
    require_member(&membership, &local.device_id, &local.public_key).map_err(|_| REMOVED)?;
    let stream = connect(&vault_id)?;
    let peer_address = stream.peer_addr().ok();
    stream.set_read_timeout(Some(if server { Duration::from_secs(5) } else { READ_IDLE })).map_err(network_error)?;
    let _ = stream.set_nodelay(true);
    let timeout_handle = stream.try_clone().map_err(network_error)?;
    let reader = stream.try_clone().map_err(network_error)?;
    let mut frames = SyncFrames::new(reader, PacedWriter { stream });
    let mut epoch_secret = crate::membership_exit::transport_epoch_secret(&secret, &vault_id, membership.key_epoch)
        .ok_or("Invalid sync keys")?;
    let challenge;
    if server {
        challenge = { let mut bytes = vec![0; 32]; getrandom::fill(&mut bytes).map_err(storage_error)?; bytes };
        frames.send(&challenge, 4096).map_err(network_error)?;
        let supplied = frames.receive(4096).map_err(network_error)?;
        if supplied.starts_with(b"leave1.") {
            // A device that left asks to be removed. Only the managing device can sign that; this
            // PC confirms a removal it already knows, or says that it is not the manager.
            use crate::membership_exit::{LeaveAnswer, answer_leave};
            let now = crate::activity::now_millis() as i64;
            let reply: &[u8] = match answer_leave(&supplied, &challenge, &secret, &events, &local.device_id, now) {
                LeaveAnswer::Left => b"left1",
                LeaveAnswer::NotManager => b"notmanager1",
                LeaveAnswer::Reject => return Err(REJECTED.into()),
            };
            frames.send(reply, 4096).map_err(network_error)?;
            return Err(LEAVE_ANSWERED.into());
        }
        let supplied = URL_SAFE_NO_PAD.decode(&supplied).map_err(|_| REJECTED)?;
        let matches = |key: &[u8]| -> bool {
            let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(key) else { return false; };
            mac.update(b"nuvori-lan-probe-v1"); mac.update(&challenge);
            mac.verify_slice(&supplied).is_ok()
        };
        let accepted = (membership.key_epoch..=membership.key_epoch + 4).find_map(|epoch| {
            let key = crate::membership_exit::transport_epoch_secret(&secret, &vault_id, epoch)?;
            matches(&key).then_some(key)
        });
        if let Some(key) = accepted { epoch_secret = key; }
        else {
            // A device on an earlier epoch was removed or missed a removal: show it the signed
            // history up to the event that ended its epoch. Nothing else is sent before authentication.
            let prior = (membership.key_epoch.saturating_sub(4).max(1)..membership.key_epoch).rev().find(|epoch| {
                crate::membership_exit::transport_epoch_secret(&secret, &vault_id, *epoch).is_some_and(|key| matches(&key))
            });
            if let Some(epoch) = prior.filter(|_| crate::membership_exit::removal_notice_allowed(Instant::now())) {
                let history = crate::membership_exit::history_for_epoch(&events, epoch);
                frames.send(b"removed1", 4096).map_err(network_error)?;
                frames.send(&serde_json::to_vec(history).map_err(storage_error)?, 1_000_000).map_err(network_error)?;
            }
            return Err(REJECTED.into());
        }
        frames.send(b"ok", 4096).map_err(network_error)?;
    } else {
        challenge = frames.receive(4096).map_err(|error| closed_as(error, BUSY))?;
        if is_busy_reply(&challenge) { return Err(BUSY.into()); }
        if challenge.len() != 32 { return Err("Invalid peer challenge".into()); }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&epoch_secret).map_err(storage_error)?;
        mac.update(b"nuvori-lan-probe-v1"); mac.update(&challenge);
        frames.send(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()).as_bytes(), 4096).map_err(network_error)?;
        let reply = frames.receive(4096).map_err(|error| closed_as(error, REJECTED))?;
        if reply == b"removed1" { return Err(accept_removal(state, &mut frames, &events, &local.device_id)); }
        if reply != b"ok" { return Err(REJECTED.into()); }
    }

    timeout_handle.set_read_timeout(Some(READ_IDLE)).map_err(network_error)?;
    let encoded_secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(&epoch_secret));
    let session = pairing::handshake(
        &mut frames,
        helper,
        &local,
        &encoded_secret,
        &URL_SAFE_NO_PAD.encode(&challenge),
        &vault_id,
        server,
        None,
    )
    .map_err(handshake_error)?;
    let mut channel =
        EncryptedSyncChannel::new(frames, &session.key, server).map_err(network_error)?;
    channel
        .send(&serde_json::to_vec(&events).map_err(storage_error)?)
        .map_err(network_error)?;
    let remote = channel.receive().map_err(|error| closed_as(error, REJECTED))?;
    if remote.len() > 1_000_000 {
        return Err("Membership history too large".into());
    }
    let remote: Vec<MembershipEvent> =
        serde_json::from_slice(&remote).map_err(|_| "Invalid membership history")?;
    let accepted = merge_membership(&events, &remote)?;
    require_member(&accepted, &local.device_id, &local.public_key).map_err(|_| REMOVED)?;
    require_member(&accepted, &session.peer.device_id, &session.peer.public_key)?;
    with_vault(state, &vault_id, &membership.head, |vault| {
        persist_membership(vault.connection(), &vault_id, &events, &remote, &accepted)
    })?;
    let local_proof = identity_proof(
        &session.key,
        &vault_id,
        &local.device_id,
        &session.peer.device_id,
    )?;
    channel
        .send(&signer.sign(&local_proof).map_err(storage_error)?)
        .map_err(network_error)?;
    let signature = channel.receive().map_err(|error| closed_as(error, REJECTED))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| "Invalid device signature")?;
    if !verify_signature(
        &session.peer.public_key,
        &identity_proof(
            &session.key,
            &vault_id,
            &session.peer.device_id,
            &local.device_id,
        )?,
        &signature,
    ) {
        return Err("Peer identity proof failed".into());
    }
    if server { tracker.begin(); }
    let relay_removed = session.peer_features.iter().any(|feature| feature == crate::protocol::REMOVAL_CUTOFF_FEATURE);
    let rounds = exchange_rounds_role(
        &mut channel,
        state,
        &accepted,
        &content_key,
        &local.device_id,
        &session.peer.device_id,
        tracker,
        server,
        relay_removed,
    );
    let (mut report, complete) = match rounds {
        Ok(result) => result,
        Err(error) => {
            // Everything acknowledged so far is already committed; show it without waiting
            // for the next pass. This is local work only, so holding the vault lock is fine.
            let _ = with_vault(state, &vault_id, &accepted.head, |vault| {
                apply_waiting(vault, &vault_id, &content_key)
            });
            return Err(error);
        }
    };
    // Photo blobs, in Android's order: the phone serves our requests first, then asks for its own.
    let wanted = with_vault(state, &vault_id, &accepted.head, |vault| {
        vault.waiting_photo_blobs().map_err(storage_error)
    })?;
    let missing: Vec<(String, u64)> =
        wanted.into_iter().filter(|(hash, size)| !blobs.has(hash, *size)).collect();
    let more_photos = missing.len() > MAX_PHOTO_REQUESTS;
    if server { report.photos_sent = serve_photos(&mut channel, &blobs, tracker)?; }
    report.photos_received = request_photos(
        &mut channel,
        &blobs,
        &missing[..missing.len().min(MAX_PHOTO_REQUESTS)],
        tracker,
    )?;
    if !server { report.photos_sent = serve_photos(&mut channel, &blobs, tracker)?; }
    let complete = complete && !(more_photos && report.photos_received > 0);
    tracker.set_phase(Phase::Applying);
    let peer_id = session.peer.device_id.clone();
    with_vault(state, &vault_id, &accepted.head, |vault| {
        apply_waiting(vault, &vault_id, &content_key)?;
        vault.record_peer_seen(&peer_id).map_err(storage_error)?;
        report.peer_device_id = peer_id.clone();
        if let Some(address) = peer_address.filter(|address| crate::discovery::private_address(address.ip())) {
            let address = if server { SocketAddr::new(address.ip(), sync_port(&vault_id)) } else { address };
            remember_peer_endpoint(vault, &vault_id, &peer_id, address).map_err(storage_error)?;
        }
        let db = vault.connection();
        report.waiting_to_apply = waiting(db, &vault_id)?.len();
        report.conflicts = db
            .query_row(
                "SELECT count(*) FROM sync_conflicts WHERE resolved_at_utc = ''",
                [],
                |r| r.get::<_, u32>(0),
            )
            .map_err(storage_error)? as usize;
        if complete {
            let now = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(storage_error)?;
            db.execute("INSERT INTO sync_exchange_state (vault_id, last_sync_utc) VALUES (?1, ?2) ON CONFLICT(vault_id) DO UPDATE SET last_sync_utc = excluded.last_sync_utc", params![vault_id, now]).map_err(storage_error)?;
        }
        Ok(())
    })?;
    Ok((report, complete))
}

/// Alternates bounded receive and send batches in Android's order (the phone serves first).
/// Returns `false` when the round limit ended the session before both sides were caught up.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn exchange_rounds<R: Read, W: Write>(channel: &mut EncryptedSyncChannel<R, W>,
    state: &ManagedState, membership: &VerifiedMembership, key: &[u8], local: &str,
    peer: &str, tracker: &SyncTracker) -> Result<(SyncReport, bool)> {
    exchange_rounds_role(channel, state, membership, key, local, peer, tracker, false, false)
}

#[allow(clippy::too_many_arguments)]
fn exchange_rounds_role<R: Read, W: Write>(
    channel: &mut EncryptedSyncChannel<R, W>,
    state: &ManagedState,
    membership: &VerifiedMembership,
    key: &[u8],
    local: &str,
    peer: &str,
    tracker: &SyncTracker,
    server: bool,
    relay_removed: bool,
) -> Result<(SyncReport, bool)> {
    let mut report = SyncReport::default();
    for _ in 0..MAX_ROUNDS {
        let (sent, received) = if server {
            let sent = send_batch(channel, state, membership, local, peer, tracker, relay_removed)?;
            (sent, receive_batch(channel, state, membership, key, tracker)?)
        } else {
            let received = receive_batch(channel, state, membership, key, tracker)?;
            (send_batch(channel, state, membership, local, peer, tracker, relay_removed)?, received)
        };
        report.received += received;
        report.sent += sent;
        if sent == 0 && received == 0 {
            return Ok((report, true));
        }
    }
    Ok((report, false))
}

fn endpoint(address: &str, vault_id: &str) -> Result<SocketAddr> {
    let endpoint = address
        .trim()
        .parse::<SocketAddr>()
        .or_else(|_| {
            address
                .trim()
                .parse::<IpAddr>()
                .map(|ip| SocketAddr::new(ip, sync_port(vault_id)))
        })
        .map_err(|_| "Enter the phone's Wi-Fi IP address, optionally followed by :port")?;
    let private = match endpoint.ip() {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    };
    if !private || endpoint.port() < 1024 {
        return Err("Use a private local-network address and a port above 1023".into());
    }
    Ok(endpoint)
}

pub(crate) fn sync_port(vault_id: &str) -> u16 {
    let hash = vault_id.encode_utf16().fold(0i32, |hash, c| {
        hash.wrapping_mul(31).wrapping_add(i32::from(c))
    });
    (20_000 + hash.rem_euclid(30_000)) as u16
}

fn integer(value: u64) -> Result<i64> {
    value.try_into().map_err(storage_error)
}
fn counter(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    value.try_into().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

/// Short human text for a transport failure. Never includes peer data or key material.
fn network_error(error: impl Into<WireError>) -> String {
    match error.into() {
        WireError::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            TIMED_OUT.into()
        }
        _ => INTERRUPTED.into(),
    }
}
fn storage_error(error: impl std::fmt::Display) -> String {
    crate::activity::diagnostic(crate::activity::Category::Sync, "Sync storage error", error);
    "Sync data could not be verified or stored. Your existing items are kept.".into()
}

fn with_vault<T>(
    state: &ManagedState,
    vault_id: &str,
    head: &str,
    work: impl FnOnce(&mut UnlockedVault) -> Result<T>,
) -> Result<T> {
    let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
    let vault = app
        .unlocked
        .as_mut()
        .ok_or("Vault locked. Unlock and retry sync.")?;
    let events = read_membership(vault.connection(), vault_id)?;
    let current = membership::verify(&events).map_err(storage_error)?;
    if current.head != head {
        return Err("Device membership changed. Retry sync.".into());
    }
    work(vault)
}

fn read_membership(db: &Connection, id: &str) -> Result<Vec<MembershipEvent>> {
    let mut query = db
        .prepare(
            "SELECT event_json FROM sync_membership_events WHERE vault_id = ?1 ORDER BY sequence",
        )
        .map_err(storage_error)?;
    let rows = query
        .query_map([id], |r| r.get::<_, String>(0))
        .map_err(storage_error)?;
    rows.map(|row| serde_json::from_str(&row.map_err(storage_error)?).map_err(storage_error))
        .collect()
}

fn merge_membership(
    local: &[MembershipEvent],
    remote: &[MembershipEvent],
) -> Result<VerifiedMembership> {
    let current = membership::verify(local).map_err(storage_error)?;
    let incoming = membership::verify(remote).map_err(storage_error)?;
    // Either side may be ahead after a removal raised the key epoch; both must be the same chain.
    if current.vault_id != incoming.vault_id
        || local.iter().zip(remote).any(|(a, b)| a.hash != b.hash)
    {
        return Err("Conflicting device membership history".into());
    }
    Ok(if remote.len() > local.len() {
        incoming
    } else {
        current
    })
}

fn require_member(membership: &VerifiedMembership, id: &str, key: &[u8; 32]) -> Result<()> {
    if !membership
        .members
        .get(id)
        .is_some_and(|m| m.active && &m.public_key == key && m.key_epoch <= membership.key_epoch)
    {
        return Err("Device is not an active signed member of this vault".into());
    }
    Ok(())
}

fn persist_membership(
    db: &mut Connection,
    id: &str,
    local: &[MembershipEvent],
    remote: &[MembershipEvent],
    verified: &VerifiedMembership,
) -> Result<()> {
    if remote.len() <= local.len() {
        return Ok(());
    }
    let tx = db.transaction().map_err(storage_error)?;
    for event in &remote[local.len()..] {
        tx.execute("INSERT INTO sync_membership_events (vault_id, sequence, event_json) VALUES (?1, ?2, ?3)", params![id, integer(event.sequence)?, serde_json::to_string(event).map_err(storage_error)?]).map_err(storage_error)?;
    }
    for member in verified.members.values() {
        let saved: Option<String> = tx
            .query_row(
                "SELECT member_json FROM sync_memberships WHERE vault_id = ?1 AND device_id = ?2",
                params![id, member.device_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage_error)?;
        let name = saved
            .and_then(|s| serde_json::from_str::<SnapshotMember>(&s).ok())
            .map(|m| m.display_name)
            .unwrap_or_else(|| "Paired device".into());
        let entry = SnapshotMember {
            vault_id: id.into(),
            device_id: member.device_id.clone(),
            display_name: name,
            identity_public_key: URL_SAFE_NO_PAD.encode(member.public_key),
            status: if member.active { "ACTIVE" } else { "REVOKED" }.into(),
            added_by_device_id: member.added_by_device_id.clone(),
            membership_sequence: member.membership_sequence,
            key_epoch: member.key_epoch,
        };
        tx.execute("INSERT INTO sync_memberships (vault_id, device_id, member_json) VALUES (?1, ?2, ?3) ON CONFLICT(vault_id, device_id) DO UPDATE SET member_json = excluded.member_json", params![id, member.device_id, serde_json::to_string(&entry).map_err(storage_error)?]).map_err(storage_error)?;
    }
    tx.commit().map_err(storage_error)
}

fn identity_proof(key: &[u8], id: &str, author: &str, recipient: &str) -> Result<Vec<u8>> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(storage_error)?;
    mac.update(format!("nuvori-lan-identity-v2:{id}:{author}:{recipient}").as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(crate) fn progress(db: &Connection, id: &str) -> Result<SyncProgress> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS sync_applied_operations (mutation_id TEXT NOT NULL PRIMARY KEY REFERENCES sync_operations(mutation_id), change_hash TEXT NOT NULL, outcome TEXT NOT NULL CHECK (outcome IN ('applied', 'conflict', 'obsolete')), applied_at_utc TEXT NOT NULL)").map_err(storage_error)?;
    let mut query = db
        .prepare("SELECT device_id, sequence, hash FROM sync_device_heads WHERE vault_id = ?1")
        .map_err(storage_error)?;
    let received: BTreeMap<String, (u64, String)> = query
        .query_map([id], |r| Ok((r.get(0)?, (counter(r, 1)?, r.get(2)?))))
        .map_err(storage_error)?
        .collect::<std::result::Result<_, _>>()
        .map_err(storage_error)?;
    let mut applied = received.clone();
    // Snapshot and local operations are already materialized. A received marker
    // distinguishes new remote operations until dependency checks can apply them.
    for (device, (seq, _)) in &received {
        let first: Option<i64> = db.query_row("SELECT min(o.sequence) FROM sync_operations o JOIN sync_received_operations r ON r.mutation_id = o.mutation_id LEFT JOIN sync_applied_operations a ON a.mutation_id = o.mutation_id WHERE o.vault_id = ?1 AND o.device_id = ?2 AND a.mutation_id IS NULL", params![id, device], |r| r.get(0)).map_err(storage_error)?;
        if let Some(first) = first {
            let before = u64::try_from(first - 1).map_err(storage_error)?;
            let hash = if before == 0 {
                GENESIS_HASH.into()
            } else {
                db.query_row("SELECT hash FROM sync_operations WHERE vault_id = ?1 AND device_id = ?2 AND sequence = ?3", params![id, device, integer(before)?], |r| r.get(0)).map_err(storage_error)?
            };
            if before < *seq {
                applied.insert(device.clone(), (before, hash));
            }
        }
    }
    Ok(SyncProgress { received, applied })
}

fn initialize_received(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS sync_received_operations (mutation_id TEXT NOT NULL PRIMARY KEY REFERENCES sync_operations(mutation_id))").map_err(storage_error)
}

fn operation_from_wire(bytes: &[u8]) -> Result<ChangeRecord> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes).map_err(storage_error)?;
    let version: crate::protocol::RecordVersion = serde_json::from_str(
        value["recordVersionJson"]
            .as_str()
            .ok_or("Missing record version")?,
    )
    .map_err(storage_error)?;
    value
        .as_object_mut()
        .ok_or("Invalid operation")?
        .remove("recordVersionJson");
    value["recordVersion"] = serde_json::to_value(version).map_err(storage_error)?;
    serde_json::from_value(value).map_err(storage_error)
}

fn operation_wire(operation: &ChangeRecord) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(operation).map_err(storage_error)?;
    value
        .as_object_mut()
        .ok_or("Invalid operation")?
        .remove("recordVersion");
    value["recordVersionJson"] = serde_json::Value::String(
        serde_json::to_string(&operation.record_version).map_err(storage_error)?,
    );
    serde_json::to_vec(&value).map_err(storage_error)
}

const OPERATION_COLUMNS: &str = "o.format_version, o.vault_id, o.device_id, o.sequence, o.previous_hash, o.mutation_id, o.entity_type, o.entity_id, o.kind, o.base_revision, o.record_version_json, o.occurred_at_utc, o.payload_ciphertext, o.payload_nonce, o.device_signature, o.hash";

fn read_operations(
    db: &Connection,
    sql: &str,
    arguments: impl rusqlite::Params,
) -> Result<Vec<ChangeRecord>> {
    let mut query = db.prepare(sql).map_err(storage_error)?;
    let rows = query
        .query_map(arguments, |r| {
            let kind: String = r.get(8)?;
            let version: String = r.get(10)?;
            Ok((
                ChangeRecord {
                    format_version: r.get(0)?,
                    vault_id: r.get(1)?,
                    device_id: r.get(2)?,
                    sequence: counter(r, 3)?,
                    previous_hash: r.get(4)?,
                    mutation_id: r.get(5)?,
                    entity_type: r.get(6)?,
                    entity_id: r.get(7)?,
                    kind: if kind == "upsert" {
                        crate::sync::ChangeKind::Upsert
                    } else {
                        crate::sync::ChangeKind::Delete
                    },
                    base_revision: counter(r, 9)?,
                    record_version: Default::default(),
                    occurred_at_utc: r.get(11)?,
                    payload_ciphertext: r.get(12)?,
                    payload_nonce: r.get(13)?,
                    device_signature: r.get(14)?,
                    hash: r.get(15)?,
                },
                version,
            ))
        })
        .map_err(storage_error)?;
    rows.map(|row| {
        let (mut operation, version) = row.map_err(storage_error)?;
        operation.record_version = serde_json::from_str(&version).map_err(storage_error)?;
        Ok(operation)
    })
    .collect()
}

/// Received operations that are not applied yet, in per-device chain order.
fn waiting(db: &Connection, id: &str) -> Result<Vec<ChangeRecord>> {
    read_operations(
        db,
        &format!("SELECT {OPERATION_COLUMNS} FROM sync_operations o JOIN sync_received_operations r ON r.mutation_id = o.mutation_id LEFT JOIN sync_applied_operations a ON a.mutation_id = o.mutation_id WHERE o.vault_id = ?1 AND a.mutation_id IS NULL ORDER BY o.device_id, o.sequence"),
        [id],
    )
}

/// Received changes this PC could not read. They stay unapplied and are tried again on each pass.
const SET_ASIDE_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS sync_set_aside_operations (mutation_id TEXT NOT NULL PRIMARY KEY)";

fn set_aside_count(db: &Connection, id: &str) -> usize {
    db.query_row(
        "SELECT count(*) FROM sync_set_aside_operations s JOIN sync_operations o ON o.mutation_id = s.mutation_id
         LEFT JOIN sync_applied_operations a ON a.mutation_id = o.mutation_id
         WHERE o.vault_id = ?1 AND a.mutation_id IS NULL",
        [id],
        |row| row.get::<_, u32>(0),
    )
    .map_or(0, |count| count as usize)
}

fn apply_waiting(vault: &mut UnlockedVault, id: &str, key: &[u8]) -> Result<()> {
    let blobs = vault.photo_blobs();
    let db = vault.connection();
    db.execute_batch(SET_ASIDE_SCHEMA).map_err(storage_error)?;
    loop {
        let mut advanced = false;
        for operation in waiting(db, id)? {
            match IncomingApply::apply_with_blobs(db, &operation, key, Some(&blobs)) {
                Ok(_) => {
                    advanced = true;
                    db.execute("DELETE FROM sync_set_aside_operations WHERE mutation_id = ?1", [&operation.mutation_id])
                        .map_err(storage_error)?;
                }
                Err(
                    ApplyError::MissingGroupDependency
                    | ApplyError::MissingEntryDependency
                    | ApplyError::MissingPhotoBlob
                    | ApplyError::MissingPhotoDependency
                    | ApplyError::UnsupportedEntity,
                ) => {}
                // A change this PC cannot read is set aside, as Android quarantines it: it stays
                // counted as waiting, and the other changes and the rest of the pass go on.
                Err(
                    ApplyError::InvalidPayload
                    | ApplyError::Payload(_)
                    | ApplyError::Json(_)
                    | ApplyError::Passkey(_)
                    | ApplyError::PasskeyIdConflict,
                ) => {
                    db.execute("INSERT OR IGNORE INTO sync_set_aside_operations (mutation_id) VALUES (?1)", [&operation.mutation_id])
                        .map_err(storage_error)?;
                    crate::activity::global().record_coalesced(
                    crate::activity::Level::Warning,
                    crate::activity::Category::Sync,
                    "A received change could not be read and was set aside. Other changes still sync".to_owned(),
                    Duration::from_secs(15 * 60),
                    );
                }
                Err(_) => return Err("Received changes are saved, but one could not be applied. Existing items are kept.".into()),
            }
        }
        if !advanced {
            return Ok(());
        }
    }
}

/// Verifies one received change against its author's signed chain and commits it. Wi-Fi sync
/// and cloud sync both store changes through this function.
fn store_received(state: &ManagedState, membership: &VerifiedMembership, operation: &ChangeRecord) -> Result<()> {
    // An active member, or a removed one within its cutoff (Android `RemovalCutoff`).
    let member = membership
        .members
        .get(&operation.device_id)
        .filter(|m| m.active || crate::protocol::within_removal_cutoff(m.removal_cutoff.as_ref(), operation.sequence, &operation.hash))
        .ok_or("Unknown operation author")?;
    with_vault(state, &membership.vault_id, &membership.head, |vault| {
        let db = vault.connection();
        initialize_received(db)?;
        let head = progress(db, &membership.vault_id)?
            .received
            .get(&operation.device_id)
            .cloned()
            .unwrap_or((0, GENESIS_HASH.into()));
        let verifier = IncomingVerifier::new(
            &membership.vault_id,
            &member.device_id,
            member.public_key,
            head.0,
            head.1,
        )
        .map_err(storage_error)?;
        let batch = verifier
            .verify_batch(vec![operation.clone()])
            .map_err(storage_error)?;
        IncomingStore::persist_batch(db, &batch).map_err(storage_error)?;
        Ok(())
    })
}

fn receive_batch<R: Read, W: Write>(
    channel: &mut EncryptedSyncChannel<R, W>,
    state: &ManagedState,
    membership: &VerifiedMembership,
    key: &[u8],
    tracker: &SyncTracker,
) -> Result<usize> {
    tracker.set_phase(Phase::Receiving);
    let encoded = with_vault(state, &membership.vault_id, &membership.head, |vault| {
        initialize_received(vault.connection())?;
        progress(vault.connection(), &membership.vault_id)?
            .encode()
            .map_err(storage_error)
    })?;
    channel.send(&encoded).map_err(network_error)?;
    let count = channel.receive().map_err(network_error)?;
    let count: usize = std::str::from_utf8(&count)
        .map_err(storage_error)?
        .parse()
        .map_err(storage_error)?;
    if count > MAX_BATCH_OPERATIONS {
        return Err("Sync batch too large".into());
    }
    tracker.incoming_announced(count as u64);
    for _ in 0..count {
        let operation = operation_from_wire(&channel.receive().map_err(network_error)?)?;
        store_received(state, membership, &operation)?;
        // Acknowledge only after the verified operation is committed.
        channel
            .send(operation.hash.as_bytes())
            .map_err(network_error)?;
        tracker.received_one();
    }
    if count > 0 {
        tracker.set_phase(Phase::Applying);
        with_vault(state, &membership.vault_id, &membership.head, |vault| {
            apply_waiting(vault, &membership.vault_id, key)
        })?;
    }
    Ok(count)
}

fn validate_peer_progress(
    db: &mut Connection,
    id: &str,
    local_id: &str,
    peer: &str,
    progress: &SyncProgress,
) -> Result<()> {
    progress.validate().map_err(storage_error)?;
    let tx = db.transaction().map_err(storage_error)?;
    for (author, (seq, hash)) in progress.received.iter().chain(&progress.applied) {
        let known: Option<String> = if *seq == 0 {
            Some(GENESIS_HASH.into())
        } else {
            tx.query_row("SELECT hash FROM sync_operations WHERE vault_id = ?1 AND device_id = ?2 AND sequence = ?3", params![id, author, integer(*seq)?], |r| r.get(0)).optional().map_err(storage_error)?
        };
        if known.as_ref().is_some_and(|known| known != hash)
            || author == local_id && known.is_none()
        {
            return Err("Peer reported a conflicting change head".into());
        }
    }
    for (author, (seq, _)) in &progress.received {
        let old: Option<i64> = tx.query_row("SELECT sequence FROM sync_peer_acknowledgements WHERE vault_id = ?1 AND peer_device_id = ?2 AND source_device_id = ?3", params![id, peer, author], |r| r.get(0)).optional().map_err(storage_error)?;
        let sequence = integer(*seq)?;
        if old.is_some_and(|old| old > sequence) {
            return Err("Peer progress moved backward".into());
        }
        tx.execute("INSERT INTO sync_peer_acknowledgements (vault_id, peer_device_id, source_device_id, sequence, acknowledged_at_utc) VALUES (?1, ?2, ?3, ?4, '') ON CONFLICT(vault_id, peer_device_id, source_device_id) DO UPDATE SET sequence = excluded.sequence", params![id, peer, author, sequence]).map_err(storage_error)?;
    }
    // The whole report, for the per-device counts in the devices list (as the phone shows them).
    let encoded = String::from_utf8(progress.encode().map_err(storage_error)?).map_err(storage_error)?;
    tx.execute("CREATE TABLE IF NOT EXISTS sync_peer_progress (vault_id TEXT NOT NULL, peer_device_id TEXT NOT NULL, progress_json TEXT NOT NULL, PRIMARY KEY (vault_id, peer_device_id))", [])
        .map_err(storage_error)?;
    tx.execute("INSERT INTO sync_peer_progress (vault_id, peer_device_id, progress_json) VALUES (?1, ?2, ?3) ON CONFLICT(vault_id, peer_device_id) DO UPDATE SET progress_json = excluded.progress_json",
        params![id, peer, encoded]).map_err(storage_error)?;
    tx.commit().map_err(storage_error)
}

/// Operations the peer lacks, in `(device_id, sequence)` order, bounded by count and bytes.
/// Returns the batch with each operation's wire bytes and the total number still missing.
fn pending_operations(
    db: &Connection,
    id: &str,
    frontier: &BTreeMap<String, (u64, String)>,
    max_count: usize,
    max_bytes: usize,
    relay_limit: &dyn Fn(&str) -> Option<u64>,
) -> Result<(Vec<(ChangeRecord, Vec<u8>)>, usize)> {
    let devices: Vec<String> = db
        .prepare("SELECT DISTINCT device_id FROM sync_operations WHERE vault_id = ?1 ORDER BY device_id")
        .map_err(storage_error)?
        .query_map([id], |r| r.get(0))
        .map_err(storage_error)?
        .collect::<std::result::Result<_, _>>()
        .map_err(storage_error)?;
    let mut batch = Vec::new();
    let mut bytes = 0usize;
    let mut remaining = 0usize;
    let mut full = max_count == 0;
    // A receiver rejects a change by a device that is not an active member, and that ends the
    // session. A removed device's changes go only up to its cutoff, and only to peers that take them.
    for device in devices {
        let Some(limit) = relay_limit(&device) else { continue };
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let after = integer(frontier.get(&device).map_or(0, |head| head.0))?;
        let missing: i64 = db
            .query_row(
                "SELECT count(*) FROM sync_operations WHERE vault_id = ?1 AND device_id = ?2 AND sequence > ?3 AND sequence <= ?4",
                params![id, device, after, limit],
                |r| r.get(0),
            )
            .map_err(storage_error)?;
        remaining += usize::try_from(missing).map_err(storage_error)?;
        if full || missing == 0 {
            continue;
        }
        let count_limit = integer((max_count - batch.len()) as u64)?;
        let operations = read_operations(
            db,
            &format!("SELECT {OPERATION_COLUMNS} FROM sync_operations o WHERE o.vault_id = ?1 AND o.device_id = ?2 AND o.sequence > ?3 AND o.sequence <= ?5 ORDER BY o.sequence LIMIT ?4"),
            params![id, device, after, count_limit, limit],
        )?;
        for operation in operations {
            let wire = operation_wire(&operation)?;
            if wire.len() > MAX_FRAME - 16 {
                return Err(TOO_LARGE.into());
            }
            if !batch.is_empty() && bytes + wire.len() > max_bytes {
                full = true;
                break;
            }
            bytes += wire.len();
            batch.push((operation, wire));
            if batch.len() >= max_count {
                full = true;
                break;
            }
        }
    }
    Ok((batch, remaining))
}

fn send_batch<R: Read, W: Write>(
    channel: &mut EncryptedSyncChannel<R, W>,
    state: &ManagedState,
    membership: &VerifiedMembership,
    local: &str,
    peer: &str,
    tracker: &SyncTracker,
    relay_removed: bool,
) -> Result<usize> {
    let progress =
        SyncProgress::parse(&channel.receive().map_err(network_error)?).map_err(storage_error)?;
    tracker.set_phase(Phase::Sending);
    let (pending, remaining) = with_vault(state, &membership.vault_id, &membership.head, |vault| {
        let db = vault.connection();
        validate_peer_progress(db, &membership.vault_id, local, peer, &progress)?;
        pending_operations(
            db,
            &membership.vault_id,
            &progress.received,
            MAX_BATCH_OPERATIONS,
            BATCH_BYTE_BUDGET,
            &|author| match membership.members.get(author) {
                Some(member) if member.active => Some(u64::MAX),
                Some(member) if relay_removed => member.removal_cutoff.as_ref().map(|cutoff| cutoff.0),
                _ => None,
            },
        )
    })?;
    tracker.outgoing_remaining(remaining as u64);
    channel
        .send(pending.len().to_string().as_bytes())
        .map_err(network_error)?;
    for (operation, wire) in &pending {
        with_vault(state, &membership.vault_id, &membership.head, |_| Ok(()))?;
        channel.send(wire).map_err(network_error)?;
        if channel.receive().map_err(network_error)? != operation.hash.as_bytes() {
            return Err("Peer did not acknowledge the saved change".into());
        }
        tracker.sent_one();
    }
    Ok(pending.len())
}

/// Android `requestPhotos` counterpart: asks for missing blobs, resuming partial downloads.
/// Chunks go straight to blob files, so no vault lock is held while bytes arrive.
fn request_photos<R: Read, W: Write>(
    channel: &mut EncryptedSyncChannel<R, W>,
    blobs: &PhotoBlobs,
    missing: &[(String, u64)],
    tracker: &SyncTracker,
) -> Result<usize> {
    let mut requests = Vec::with_capacity(missing.len());
    for (hash, size) in missing {
        let mut offset = blobs.partial_size(hash).map_err(storage_error)?;
        if offset > *size {
            blobs.discard_partial(hash).map_err(storage_error)?;
            offset = 0;
        }
        tracker.photo_expected(size - offset);
        requests.push(serde_json::json!({"hash": hash, "offset": offset}));
    }
    channel
        .send(&serde_json::to_vec(&requests).map_err(storage_error)?)
        .map_err(network_error)?;
    if !requests.is_empty() {
        tracker.set_phase(Phase::Receiving);
    }
    let mut received = 0;
    for request in &requests {
        let hash = request["hash"].as_str().unwrap_or_default();
        let offset = request["offset"].as_u64().unwrap_or_default();
        let size: i64 = std::str::from_utf8(&channel.receive().map_err(network_error)?)
            .map_err(storage_error)?
            .parse()
            .map_err(storage_error)?;
        if size == -2 {
            // The phone's copy is shorter than our partial: start over next time.
            blobs.discard_partial(hash).map_err(storage_error)?;
            continue;
        }
        if size < 0 {
            continue;
        }
        let size = size as u64;
        if !photo_blobs::valid_size(size) || offset > size {
            return Err("Invalid photo transfer".into());
        }
        let mut position = offset;
        while position < size {
            let chunk = channel.receive().map_err(network_error)?;
            let allowed = (size - position).min(photo_blobs::CHUNK_BYTES as u64) as usize;
            if chunk.is_empty() || chunk.len() > allowed {
                return Err("Invalid photo transfer".into());
            }
            blobs.append(hash, position, &chunk).map_err(storage_error)?;
            position += chunk.len() as u64;
            tracker.photo_moved(chunk.len() as u64);
        }
        blobs.finish(hash, size).map_err(|_| PHOTO_FAILED)?;
        channel.send(hash.as_bytes()).map_err(network_error)?;
        received += 1;
    }
    Ok(received)
}

/// Android `servePhotos` counterpart: answers with each blob's size (`-1` unknown, `-2` the
/// requested offset is past our copy) and streams it from the offset in 64 KiB chunks.
fn serve_photos<R: Read, W: Write>(
    channel: &mut EncryptedSyncChannel<R, W>,
    blobs: &PhotoBlobs,
    tracker: &SyncTracker,
) -> Result<usize> {
    let requests: serde_json::Value =
        serde_json::from_slice(&channel.receive().map_err(network_error)?).map_err(storage_error)?;
    let requests = requests
        .as_array()
        .filter(|items| items.len() <= MAX_PHOTO_REQUESTS)
        .ok_or("Invalid photo request")?;
    let mut parsed = Vec::with_capacity(requests.len());
    for request in requests {
        // Android 2.1.1-2.1.3 release builds sent R8-renamed keys `a` and `b`.
        let hash = request["hash"]
            .as_str()
            .or_else(|| request["a"].as_str())
            .filter(|hash| photo_blobs::valid_hash(hash));
        let offset = request["offset"].as_u64().or_else(|| request["b"].as_u64());
        let (Some(hash), Some(offset)) = (hash, offset) else {
            return Err("Invalid photo request".into());
        };
        parsed.push((hash.to_owned(), offset));
    }
    if !parsed.is_empty() {
        tracker.set_phase(Phase::Sending);
    }
    let mut sent = 0;
    for (hash, offset) in parsed {
        let size = blobs.size(&hash).map_err(storage_error)?;
        let answer: i64 = match size {
            None => -1,
            Some(size) if offset > size => -2,
            Some(size) => size as i64,
        };
        channel.send(answer.to_string().as_bytes()).map_err(network_error)?;
        let Some(size) = size.filter(|size| offset <= *size) else {
            continue;
        };
        tracker.photo_expected(size - offset);
        let mut file = blobs.open_at(&hash, offset).map_err(storage_error)?;
        let mut buffer = vec![0u8; photo_blobs::CHUNK_BYTES];
        loop {
            let count = file.read(&mut buffer).map_err(storage_error)?;
            if count == 0 {
                break;
            }
            channel.send(&buffer[..count]).map_err(network_error)?;
            tracker.photo_moved(count as u64);
        }
        if channel.receive().map_err(network_error)? != hash.as_bytes() {
            return Err("Photo transfer was not acknowledged".into());
        }
        sent += 1;
    }
    Ok(sent)
}

/// Reads and checks a `removed1` history. Only a verified history that extends ours and removes
/// this device makes Windows leave; anything else counts as an ordinary connection failure.
fn accept_removal<R: Read, W: Write>(
    state: &ManagedState,
    frames: &mut SyncFrames<R, W>,
    stored: &[MembershipEvent],
    local_device: &str,
) -> String {
    let Ok(history) = frames.receive(1_000_000) else {
        return INTERRUPTED.into();
    };
    let Ok(received) = serde_json::from_slice::<Vec<MembershipEvent>>(&history) else {
        return INTERRUPTED.into();
    };
    adopt_history(state, stored, &received, local_device)
}

/// Acts on a signed history that is longer than ours: leaves the group when it removes this
/// device, otherwise stores the new events. Returns the sentence to show.
fn adopt_history(
    state: &ManagedState,
    stored: &[MembershipEvent],
    received: &[MembershipEvent],
    local_device: &str,
) -> String {
    let Ok(notice) = crate::membership_exit::verify_removal(stored, received, local_device) else {
        return INTERRUPTED.into();
    };
    let Ok(mut app) = state.lock() else {
        return INTERRUPTED.into();
    };
    let Some(vault) = app.unlocked.as_mut() else {
        return "Vault locked. Unlock and retry sync.".into();
    };
    // The local history must not have moved while we were reading.
    if vault.stored_membership().ok().as_deref() != Some(stored) {
        return INTERRUPTED.into();
    }
    let removal = match notice {
        crate::membership_exit::Notice::Removed(removal) => removal,
        crate::membership_exit::Notice::CatchUp(verified) => {
            let Ok(vault_id) = vault.connection().query_row(
                "SELECT vault_id FROM local_sync_settings WHERE id = 1", [], |row| row.get::<_, String>(0)) else {
                return INTERRUPTED.into();
            };
            return match persist_membership(vault.connection(), &vault_id, stored, received, &verified) {
                Ok(()) => MEMBERSHIP_UPDATED.into(),
                Err(error) => error,
            };
        }
    };
    let by = vault
        .display_name_of(&removal.issuer_device_id)
        .unwrap_or_else(|| "the managing device".to_owned());
    let at = crate::activity::now_millis() as i64;
    if vault.leave_after_removal(&by, at).is_err() {
        return storage_error("leave");
    }
    crate::activity::log(
        crate::activity::Level::Warning,
        crate::activity::Category::Pairing,
        format!("{by} removed this PC from the sync group. Items stay on this PC"),
    );
    REMOVED_NOTICE.into()
}

/// Sends the pending SPEC3 `leave1` request to each saved address in turn until the managing
/// device confirms, at most once per `min_gap_millis`. Returns the last answer, or `None` when
/// nothing was due.
pub(crate) fn deliver_leave(
    state: &ManagedState,
    min_gap_millis: i64,
) -> Result<Option<crate::membership_exit::LeaveReply>> {
    deliver_leave_with(state, min_gap_millis, |address, vault_id| {
        TcpStream::connect_timeout(&endpoint(address, vault_id)?, CONNECT_TIMEOUT)
            .map_err(|_| UNREACHABLE.into())
    })
}

fn deliver_leave_with(
    state: &ManagedState,
    min_gap_millis: i64,
    connect: impl Fn(&str, &str) -> Result<TcpStream>,
) -> Result<Option<crate::membership_exit::LeaveReply>> {
    use crate::membership_exit::LeaveReply;
    let pending = {
        let app = state.lock().map_err(|_| "Vault state unavailable")?;
        let Some(vault) = app.unlocked.as_ref() else {
            return Ok(None);
        };
        let Some(pending) = vault.pending_leave().map_err(storage_error)? else {
            return Ok(None);
        };
        if pending.address.is_empty() || !vault.claim_leave_attempt(min_gap_millis).map_err(storage_error)? {
            return Ok(None);
        }
        pending
    };
    let mut outcome = Err(UNREACHABLE.to_owned());
    for address in pending.address.split(',').filter(|address| !address.is_empty()) {
        let reply = send_leave(state, &pending, address, &connect);
        let confirmed = matches!(reply, Ok(LeaveReply::Left));
        // Keep the most useful answer: any reply beats an unreachable address.
        if reply.is_ok() || outcome.is_err() {
            outcome = reply;
        }
        if confirmed {
            break;
        }
    }
    outcome.map(Some)
}

/// One `leave1` attempt at `address`.
fn send_leave(
    state: &ManagedState,
    pending: &crate::membership_exit::PendingLeave,
    address: &str,
    connect: &impl Fn(&str, &str) -> Result<TcpStream>,
) -> Result<crate::membership_exit::LeaveReply> {
    use crate::membership_exit::{LeaveReply, leave_frame, leave_reply};
    let stream = connect(address, &pending.request.vault_id)?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(network_error)?;
    let writer = PacedWriter { stream: stream.try_clone().map_err(network_error)? };
    let mut frames = SyncFrames::new(stream, writer);
    let challenge = frames.receive(4096).map_err(|error| closed_as(error, BUSY))?;
    if challenge.len() != 32 {
        return Err("Invalid peer challenge".into());
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&pending.transport_secret).map_err(storage_error)?;
    mac.update(b"nuvori-lan-probe-v1");
    mac.update(&challenge);
    let frame = leave_frame(&mac.finalize().into_bytes(), &pending.request.json(), &pending.signature);
    frames.send(frame.as_bytes(), 4096).map_err(network_error)?;
    // Old phones cannot decode the frame and simply close: keep the request for later.
    let reply = frames.receive(4096).map_or(LeaveReply::Unknown, |reply| leave_reply(&reply));
    use crate::activity::{Category, Level, log};
    match reply {
        LeaveReply::Left => {
            let app = state.lock().map_err(|_| "Vault state unavailable")?;
            if let Some(vault) = app.unlocked.as_ref() {
                vault.finish_pending_leave().map_err(storage_error)?;
            }
            log(Level::Success, Category::Pairing, "The managing phone removed this PC from the group");
        }
        LeaveReply::NotManager => log(Level::Info, Category::Pairing, "The device at a saved address does not manage the group. Leave request kept"),
        LeaveReply::Busy => log(Level::Info, Category::Pairing, "The managing phone is busy. Leave request kept"),
        LeaveReply::Unknown => {}
    }
    Ok(reply)
}

/// Maps a closed connection at a step where the phone deliberately hangs up to `message`.
fn closed_as(error: WireError, message: &str) -> String {
    match &error {
        WireError::Io(io)
            if matches!(
                io.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) =>
        {
            message.into()
        }
        _ => network_error(error),
    }
}

fn handshake_error(error: PairingError) -> String {
    match error {
        PairingError::Wire(error) => closed_as(error, REJECTED),
        PairingError::Io(error) => closed_as(WireError::Io(error), REJECTED),
        PairingError::HelperUnavailable => {
            "The pairing helper is missing. Rebuild or reinstall Nuvori.".into()
        }
        _ => REJECTED.into(),
    }
}

/// Cloud sync shares this module's storage, verify and apply functions.
#[path = "cloud_sync.rs"]
pub(crate) mod cloud;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_check_schedule_keeps_only_listed_intervals() {
        let db = Connection::open_in_memory().unwrap();
        assert_eq!(schedule(&db), Schedule { wifi_seconds: 60, drive_seconds: 15 });
        set_schedule(&db, Schedule { wifi_seconds: 300, drive_seconds: 0 }).unwrap();
        assert_eq!(schedule(&db), Schedule { wifi_seconds: 300, drive_seconds: 0 });
        assert!(set_schedule(&db, Schedule { wifi_seconds: 7, drive_seconds: 15 }).is_err());
        assert!(set_schedule(&db, Schedule { wifi_seconds: 60, drive_seconds: 1 }).is_err());
        assert_eq!(schedule(&db), Schedule { wifi_seconds: 300, drive_seconds: 0 }, "a refused value changes nothing");
        // A value written by a later version that this one does not offer falls back to the default.
        db.execute("UPDATE local_sync_schedule SET drive_seconds = 2", []).unwrap();
        assert_eq!(schedule(&db).drive_seconds, 15);
    }
    use crate::{
        AppState, change_store::ChangeStore, identity::DeviceIdentity,
        membership::MembershipAction, protocol::RecordVersion, sync::ChangeKind, vault::VaultStore,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;

    pub(super) fn phone_change() -> ChangeRecord {
        let signer = SigningKey::from_bytes(&[17; 32]);
        let plaintext = serde_json::to_vec(&serde_json::json!({"group": {
            "id": "phone-folder", "name": "Phone notes", "notes": "", "folderType": "NOTE"
        }}))
        .unwrap();
        let payload = crate::payload::encrypt(
            &[4; 32],
            "group",
            "vault-a",
            "phone-change",
            "phone-folder",
            &plaintext,
        )
        .unwrap();
        ChangeRecord::create_signed_with(
            "vault-a",
            "phone",
            1,
            GENESIS_HASH,
            "phone-change",
            "group",
            "phone-folder",
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([("phone", 1)]),
            "2026-10-02T12:00:00Z",
            payload.ciphertext,
            payload.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()),
        )
        .unwrap()
    }

    pub(super) fn signed_member(
        previous: Option<&MembershipEvent>,
        subject: &DeviceIdentity,
    ) -> MembershipEvent {
        let signer = SigningKey::from_bytes(&[17; 32]);
        let mut event = MembershipEvent {
            vault_id: "vault-a".into(),
            sequence: previous.map_or(1, |e| e.sequence + 1),
            format_version: 1,
            previous_hash: previous.map_or(GENESIS_HASH.into(), |e| e.hash.clone()),
            action: if previous.is_none() {
                MembershipAction::Genesis
            } else {
                MembershipAction::Add
            },
            issuer_device_id: "phone".into(),
            subject_device_id: subject.device_id.clone(),
            subject_public_key: subject.public_key_base64_url(),
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

    #[test]
    fn staging_marker_and_operation_roll_back_together() {
        let mut db = Connection::open_in_memory().unwrap();
        ChangeStore::initialize(&db).unwrap();
        db.execute_batch("CREATE TRIGGER fail_marker BEFORE INSERT ON sync_received_operations BEGIN SELECT RAISE(ABORT, 'interrupted'); END;").unwrap();
        let operation = phone_change();
        let key = SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes();
        let verifier = IncomingVerifier::new("vault-a", "phone", key, 0, GENESIS_HASH).unwrap();
        let batch = verifier.verify_batch(vec![operation.clone()]).unwrap();
        assert!(IncomingStore::persist_batch(&mut db, &batch).is_err());
        assert_eq!(
            db.query_row("SELECT count(*) FROM sync_operations", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        db.execute_batch("DROP TRIGGER fail_marker;").unwrap();
        IncomingStore::persist_batch(&mut db, &batch).unwrap();
        let heads = progress(&db, "vault-a").unwrap();
        assert_eq!(heads.received["phone"], (1, operation.hash.clone()));
        assert_eq!(heads.applied["phone"], (0, GENESIS_HASH.into()));
        let forged = SyncProgress {
            received: heads.received.clone(),
            applied: BTreeMap::from([("phone".into(), (1, "a".repeat(64)))]),
        };
        assert!(validate_peer_progress(&mut db, "vault-a", "phone", "pc", &forged).is_err());
    }

    #[test]
    fn manual_exchange_authenticates_both_directions_and_resumes_without_duplicates() {
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pairing-helper/publish/Nuvori.PairingHelper.exe");
        assert!(
            helper.is_file(),
            "Run npm run prepare:pairing before this test"
        );
        let directory =
            std::env::temp_dir().join(format!("nuvori-lan-test-{}", uuid::Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        let local = store.identity_store().get_or_create().unwrap();
        let phone_key = SigningKey::from_bytes(&[17; 32]);
        let phone = DeviceIdentity {
            device_id: "phone".into(),
            public_key: phone_key.verifying_key().to_bytes(),
        };
        let first = signed_member(None, &phone);
        let second = signed_member(Some(&first), &local);
        let events = vec![first, second];
        let db = vault.connection();
        db.execute(
            "UPDATE local_sync_settings SET vault_id = 'vault-a' WHERE id = 1",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO sync_group_state (vault_id, content_key, transport_secret) VALUES ('vault-a', ?1, ?2)", params![&[4u8; 32], &[5u8; 32]]).unwrap();
        for event in &events {
            db.execute("INSERT INTO sync_membership_events (vault_id, sequence, event_json) VALUES ('vault-a', ?1, ?2)", params![integer(event.sequence).unwrap(), serde_json::to_string(event).unwrap()]).unwrap();
        }
        vault
            .save_note(None, "Windows note", "Offline Windows edit", Some(vec![]))
            .unwrap();
        let state = std::sync::Arc::new(std::sync::Mutex::new(AppState {
            store,
            unlocked: Some(vault),
        }));
        let phone_operation = phone_change();
        let mut acknowledged = None;
        for pass in 0..3 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = listener.local_addr().unwrap();
            let server_helper = helper.clone();
            let server_events = events.clone();
            let server_phone = phone.clone();
            let server_local = local.clone();
            let server_change = phone_operation.clone();
            let phone_key = phone_key.clone();
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut frames = SyncFrames::new(stream.try_clone().unwrap(), stream);
                let challenge = [9u8; 32];
                frames.send(&challenge, 4096).unwrap();
                let proof = URL_SAFE_NO_PAD
                    .decode(frames.receive(4096).unwrap())
                    .unwrap();
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&[5; 32]).unwrap();
                mac.update(b"nuvori-lan-probe-v1");
                mac.update(&challenge);
                mac.verify_slice(&proof).unwrap();
                frames.send(b"ok", 4096).unwrap();
                let session = pairing::handshake(
                    &mut frames,
                    &server_helper,
                    &server_phone,
                    &URL_SAFE_NO_PAD.encode([5; 32]),
                    &URL_SAFE_NO_PAD.encode(challenge),
                    "vault-a",
                    true,
                    Some(&server_local),
                )
                .unwrap();
                let mut channel = EncryptedSyncChannel::new(frames, &session.key, true).unwrap();
                channel
                    .send(&serde_json::to_vec(&server_events).unwrap())
                    .unwrap();
                let _: Vec<MembershipEvent> =
                    serde_json::from_slice(&channel.receive().unwrap()).unwrap();
                let proof =
                    identity_proof(&session.key, "vault-a", "phone", &server_local.device_id)
                        .unwrap();
                channel.send(&phone_key.sign(&proof).to_bytes()).unwrap();
                let signature: [u8; 64] = channel.receive().unwrap().try_into().unwrap();
                assert!(verify_signature(
                    &server_local.public_key,
                    &identity_proof(&session.key, "vault-a", &server_local.device_id, "phone")
                        .unwrap(),
                    &signature
                ));
                let change = server_change;
                let mut received_local: Option<ChangeRecord> = acknowledged;
                loop {
                    let progress = SyncProgress::parse(&channel.receive().unwrap()).unwrap();
                    let send = progress.received.get("phone").map(|h| h.0).unwrap_or(0) == 0;
                    channel.send(if send { b"1" } else { b"0" }).unwrap();
                    if send {
                        channel.send(&operation_wire(&change).unwrap()).unwrap();
                        if pass == 0 {
                            return received_local;
                        }
                        assert_eq!(channel.receive().unwrap(), change.hash.as_bytes());
                    }
                    let mut heads = BTreeMap::from([("phone".into(), (1, change.hash.clone()))]);
                    if let Some(op) = &received_local {
                        heads.insert(
                            server_local.device_id.clone(),
                            (op.sequence, op.hash.clone()),
                        );
                    }
                    channel
                        .send(
                            &SyncProgress {
                                received: heads.clone(),
                                applied: heads,
                            }
                            .encode()
                            .unwrap(),
                        )
                        .unwrap();
                    let count: usize = std::str::from_utf8(&channel.receive().unwrap())
                        .unwrap()
                        .parse()
                        .unwrap();
                    for _ in 0..count {
                        let op = operation_from_wire(&channel.receive().unwrap()).unwrap();
                        let verifier = IncomingVerifier::new(
                            "vault-a",
                            &server_local.device_id,
                            server_local.public_key,
                            0,
                            GENESIS_HASH,
                        )
                        .unwrap();
                        verifier.verify_batch(vec![op.clone()]).unwrap();
                        let payload = crate::payload::decrypt(&[4; 32], &op).unwrap();
                        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                        assert_eq!(payload["entry"]["title"], "Windows note");
                        channel.send(op.hash.as_bytes()).unwrap();
                        received_local = Some(op);
                    }
                    if !send && count == 0 {
                        break;
                    }
                }
                assert_eq!(channel.receive().unwrap(), b"[]");
                channel.send(b"[]").unwrap();
                received_local
            });
            let result = exchange(&state, &helper, &SyncTracker::default(), |_| {
                TcpStream::connect(endpoint).map_err(network_error)
            })
            .map(|(report, complete)| {
                assert!(complete);
                report
            });
            if pass == 0 {
                assert!(result.is_err());
            } else {
                let report = result.unwrap();
                assert_eq!(report.sent, if pass == 1 { 1 } else { 0 });
                assert_eq!(report.received, 0);
                assert_eq!(report.waiting_to_apply, 0);
            }
            acknowledged = server.join().unwrap();
        }
        {
            let mut app = state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            assert_eq!(vault.list_groups().unwrap()[0].name, "Phone notes");
            assert_eq!(vault.list_notes().unwrap().len(), 1);
            assert!(!status(vault).unwrap().last_sync.is_empty());
            configure(vault, "192.168.1.24", true).unwrap();
            assert_eq!(configuration(vault).unwrap(), ("192.168.1.24".into(), true));
            assert!(configure(vault, "8.8.8.8", true).is_err());
            configure(vault, "192.168.1.24", false).unwrap();
            assert!(!status(vault).unwrap().automatic);
            vault.stop_sharing().unwrap();
            assert_eq!(configuration(vault).unwrap(), (String::new(), true));
            assert_eq!(vault.list_groups().unwrap()[0].name, "Phone notes");
        }
        drop(state);
        std::fs::remove_dir_all(directory).unwrap();
    }
    fn phone_group_change(sequence: u64, previous: &str) -> ChangeRecord {
        let signer = SigningKey::from_bytes(&[17; 32]);
        let id = format!("phone-folder-{sequence}");
        let mutation = format!("phone-change-{sequence}");
        let plaintext = serde_json::to_vec(&serde_json::json!({"group": {
            "id": id, "name": format!("Phone folder {sequence}"), "notes": "", "folderType": ""
        }}))
        .unwrap();
        let payload =
            crate::payload::encrypt(&[4; 32], "group", "vault-a", &mutation, &id, &plaintext)
                .unwrap();
        ChangeRecord::create_signed_with(
            "vault-a",
            "phone",
            sequence,
            previous,
            mutation,
            "group",
            id,
            ChangeKind::Upsert,
            0,
            RecordVersion::from_entries([("phone", 1)]),
            "2026-10-02T12:00:00Z",
            payload.ciphertext,
            payload.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes()),
        )
        .unwrap()
    }

    fn phone_chain(count: u64) -> Vec<ChangeRecord> {
        let mut previous = GENESIS_HASH.to_owned();
        (1..=count)
            .map(|sequence| {
                let change = phone_group_change(sequence, &previous);
                previous = change.hash.clone();
                change
            })
            .collect()
    }

    pub(super) struct Synthetic {
        pub(super) directory: std::path::PathBuf,
        pub(super) state: ManagedState,
        pub(super) local: DeviceIdentity,
        pub(super) membership: VerifiedMembership,
    }

    pub(super) fn synthetic_vault(local_notes: usize) -> Synthetic {
        let directory =
            std::env::temp_dir().join(format!("nuvori-lan-test-{}", uuid::Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        let local = store.identity_store().get_or_create().unwrap();
        let phone = DeviceIdentity {
            device_id: "phone".into(),
            public_key: SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes(),
        };
        let first = signed_member(None, &phone);
        let second = signed_member(Some(&first), &local);
        let events = vec![first, second];
        let db = vault.connection();
        db.execute("UPDATE local_sync_settings SET vault_id = 'vault-a' WHERE id = 1", [])
            .unwrap();
        db.execute("INSERT INTO sync_group_state (vault_id, content_key, transport_secret) VALUES ('vault-a', ?1, ?2)", params![&[4u8; 32], &[5u8; 32]]).unwrap();
        for event in &events {
            db.execute("INSERT INTO sync_membership_events (vault_id, sequence, event_json) VALUES ('vault-a', ?1, ?2)", params![integer(event.sequence).unwrap(), serde_json::to_string(event).unwrap()]).unwrap();
        }
        for index in 0..local_notes {
            vault
                .save_note(None, &format!("Note {index}"), "Body", Some(vec![]))
                .unwrap();
        }
        Synthetic {
            directory,
            state: std::sync::Arc::new(std::sync::Mutex::new(AppState {
                store,
                unlocked: Some(vault),
            })),
            local,
            membership: membership::verify(&events).unwrap(),
        }
    }

    /// What the scripted phone observed in one session.
    struct PhoneSession {
        received: Vec<ChangeRecord>,
        reported_phone_heads: Vec<u64>,
        batch_sizes: Vec<usize>,
    }

    /// Plays Android's server side of `LanSyncExchange.run` after authentication. With
    /// `cut_after`, the phone hangs up right after sending that many operations.
    fn scripted_phone(
        listener: std::net::TcpListener,
        ops: Vec<ChangeRecord>,
        mut received: Vec<ChangeRecord>,
        local_id: String,
        cut_after: Option<usize>,
    ) -> std::thread::JoinHandle<PhoneSession> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            let frames = SyncFrames::new(stream.try_clone().unwrap(), stream);
            let mut channel = EncryptedSyncChannel::new(frames, &[8; 32], true).unwrap();
            let mut session = PhoneSession {
                received: Vec::new(),
                reported_phone_heads: Vec::new(),
                batch_sizes: Vec::new(),
            };
            let mut sent_total = 0;
            for _ in 0..MAX_ROUNDS {
                let progress = SyncProgress::parse(&channel.receive().unwrap()).unwrap();
                let head = progress.received.get("phone").map_or(0, |h| h.0);
                session.reported_phone_heads.push(head);
                let pending: Vec<_> = ops
                    .iter()
                    .filter(|op| op.sequence > head)
                    .take(100)
                    .collect();
                channel.send(pending.len().to_string().as_bytes()).unwrap();
                for op in &pending {
                    channel.send(&operation_wire(op).unwrap()).unwrap();
                    sent_total += 1;
                    if cut_after == Some(sent_total) {
                        session.received = received;
                        return session;
                    }
                    assert_eq!(channel.receive().unwrap(), op.hash.as_bytes());
                }
                let last = ops.last().unwrap();
                let mut heads = BTreeMap::from([("phone".into(), (last.sequence, last.hash.clone()))]);
                if let Some(op) = received.last() {
                    heads.insert(local_id.clone(), (op.sequence, op.hash.clone()));
                }
                channel
                    .send(&SyncProgress { received: heads.clone(), applied: heads }.encode().unwrap())
                    .unwrap();
                let count: usize = std::str::from_utf8(&channel.receive().unwrap())
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(count <= 100, "Android rejects batches above 100");
                session.batch_sizes.push(count);
                for _ in 0..count {
                    let op = operation_from_wire(&channel.receive().unwrap()).unwrap();
                    assert_eq!(op.sequence, received.last().map_or(0, |o| o.sequence) + 1);
                    channel.send(op.hash.as_bytes()).unwrap();
                    received.push(op);
                }
                if pending.is_empty() && count == 0 {
                    break;
                }
            }
            session.received = received;
            session
        })
    }

    fn windows_rounds(
        synthetic: &Synthetic,
        address: std::net::SocketAddr,
        tracker: &SyncTracker,
    ) -> Result<(SyncReport, bool)> {
        let stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let frames = SyncFrames::new(stream.try_clone().unwrap(), stream);
        let mut channel = EncryptedSyncChannel::new(frames, &[8; 32], false).unwrap();
        exchange_rounds(
            &mut channel,
            &synthetic.state,
            &synthetic.membership,
            &[4; 32],
            &synthetic.local.device_id,
            "phone",
            tracker,
        )
    }

    #[test]
    fn interrupted_pagination_commits_received_batches_and_resumes_from_frontier() {
        let synthetic = synthetic_vault(120);
        let ops = phone_chain(150);
        let tracker = SyncTracker::default();

        // Session 1: one full batch each way, then the phone drops mid-way through batch two.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let phone = scripted_phone(listener, ops.clone(), Vec::new(), synthetic.local.device_id.clone(), Some(120));
        tracker.begin();
        let first = windows_rounds(&synthetic, address, &tracker);
        let first_session = phone.join().unwrap();
        assert!(first.is_err());
        assert_eq!(first_session.batch_sizes, vec![100]);
        assert_eq!(first_session.received.len(), 100);
        {
            let mut app = synthetic.state.lock().unwrap();
            let db = app.unlocked.as_mut().unwrap().connection();
            let stored: i64 = db
                .query_row("SELECT count(*) FROM sync_operations WHERE device_id = 'phone'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(stored, 120, "every operation received before the cut is committed");
        }
        let (_, done, total) = tracker.progress();
        assert!(done >= 219 && total >= done, "{done}/{total}");

        // Session 2 resumes from the saved frontier without duplicates in either direction.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let phone = scripted_phone(listener, ops.clone(), first_session.received, synthetic.local.device_id.clone(), None);
        let (report, complete) = windows_rounds(&synthetic, address, &tracker).unwrap();
        let second_session = phone.join().unwrap();
        assert!(complete);
        assert_eq!(second_session.reported_phone_heads[0], 120);
        assert_eq!(report.received, 30);
        assert_eq!(report.sent, 20);
        assert_eq!(second_session.received.len(), 120);
        let mut app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_mut().unwrap();
        let groups = vault.list_groups().unwrap();
        assert_eq!(groups.len(), 150);
        assert_eq!(
            groups.iter().map(|g| &g.id).collect::<std::collections::BTreeSet<_>>().len(),
            150
        );
        assert_eq!(waiting(vault.connection(), "vault-a").unwrap().len(), 0);
        drop(app);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    #[test]
    fn outgoing_batches_respect_count_and_byte_budget() {
        let synthetic = synthetic_vault(5);
        let mut app = synthetic.state.lock().unwrap();
        let db = app.unlocked.as_mut().unwrap().connection();
        let frontier = BTreeMap::new();
        let (all, remaining) = pending_operations(db, "vault-a", &frontier, 100, usize::MAX, &|_| Some(u64::MAX)).unwrap();
        assert_eq!((all.len(), remaining), (5, 5));
        let two = all[0].1.len() + all[1].1.len();
        let (budgeted, remaining) = pending_operations(db, "vault-a", &frontier, 100, two, &|_| Some(u64::MAX)).unwrap();
        assert_eq!((budgeted.len(), remaining), (2, 5));
        let (minimum, _) = pending_operations(db, "vault-a", &frontier, 100, 1, &|_| Some(u64::MAX)).unwrap();
        assert_eq!(minimum.len(), 1, "a batch always carries at least one change");
        let (counted, _) = pending_operations(db, "vault-a", &frontier, 3, usize::MAX, &|_| Some(u64::MAX)).unwrap();
        assert_eq!(counted.len(), 3);
        let after_two = BTreeMap::from([(
            synthetic.local.device_id.clone(),
            (2, all[1].0.hash.clone()),
        )]);
        let (rest, remaining) = pending_operations(db, "vault-a", &after_two, 100, usize::MAX, &|_| Some(u64::MAX)).unwrap();
        assert_eq!(remaining, 3);
        assert_eq!(rest.iter().map(|(op, _)| op.sequence).collect::<Vec<_>>(), vec![3, 4, 5]);
        // Changes of a device that is no longer an active member are never offered: the peer
        // would reject them and end the session.
        let (none, remaining) = pending_operations(db, "vault-a", &frontier, 100, usize::MAX, &|_| None).unwrap();
        assert_eq!((none.len(), remaining), (0, 0));
        drop(app);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    #[test]
    fn sessions_continue_until_caught_up_and_stop_without_progress() {
        let mut calls = 0;
        let report = run_sessions(|| {
            calls += 1;
            Ok((
                SyncReport { sent: 10, received: 5, ..Default::default() },
                calls == 3,
            ))
        })
        .unwrap();
        assert_eq!((calls, report.sent, report.received), (3, 30, 15));
        let mut calls = 0;
        let stalled = run_sessions(|| {
            calls += 1;
            Ok((SyncReport::default(), false))
        });
        assert_eq!((calls, stalled), (1, Err(MORE_REMAIN.to_owned())));
        let failed = run_sessions(|| Err(UNREACHABLE.to_owned()));
        assert_eq!(failed, Err(UNREACHABLE.to_owned()));
    }

    #[test]
    fn retry_backoff_grows_with_jitter_and_caps_at_five_minutes() {
        assert_eq!(retry_delay(0, 0), Duration::ZERO);
        assert!((Duration::from_millis(14_900)..=Duration::from_secs(15)).contains(&retry_delay(1, u16::MAX / 2)));
        assert_eq!(retry_delay(1, 0), Duration::from_secs(12));
        assert_eq!(retry_delay(1, u16::MAX), Duration::from_secs(18));
        assert!(retry_delay(3, 0) > retry_delay(2, u16::MAX));
        for failures in 6..40 {
            assert!(retry_delay(failures, u16::MAX) <= Duration::from_secs(300));
            assert!(retry_delay(failures, 0) >= Duration::from_secs(240));
        }
    }

    #[test]
    fn timeouts_scale_with_payload_and_errors_stay_human() {
        assert_eq!(write_timeout(0), WRITE_IDLE);
        assert!(write_timeout(MAX_FRAME) >= WRITE_IDLE + Duration::from_secs(60));
        let eof = || WireError::Io(io::Error::from(io::ErrorKind::UnexpectedEof));
        assert_eq!(closed_as(eof(), REJECTED), REJECTED);
        assert_eq!(closed_as(eof(), BUSY), BUSY);
        assert_eq!(network_error(io::Error::from(io::ErrorKind::TimedOut)), TIMED_OUT);
        assert_eq!(network_error(io::Error::from(io::ErrorKind::WouldBlock)), TIMED_OUT);
        assert_eq!(network_error(eof()), INTERRUPTED);
        assert_eq!(network_error(WireError::AuthenticationFailed), INTERRUPTED);
        assert_eq!(handshake_error(PairingError::InvalidHandshake), REJECTED);
    }

    #[test]
    fn tracker_reports_progress_failures_and_retry() {
        let tracker = SyncTracker::default();
        tracker.begin();
        tracker.incoming_announced(3);
        tracker.received_one();
        tracker.outgoing_remaining(2);
        tracker.sent_one();
        assert_eq!(tracker.progress(), (Phase::Connecting, 2, 5));
        tracker.fail(TIMED_OUT);
        tracker.fail(TIMED_OUT);
        tracker.schedule_retry(Some(Instant::now() + Duration::from_secs(30)));
        let mut status = SyncStatus {
            last_sync: String::new(), waiting_to_apply: 0, set_aside: 0, conflicts: 0,
            phone_address: String::new(), automatic: true, running: false,
            message: String::new(), phase: "idle", progress_done: 0, progress_total: 0,
            last_error: String::new(), last_attempt: String::new(),
            consecutive_failures: 0, next_retry_seconds: 0, wifi_check_seconds: 60, drive_check_seconds: 15,
        };
        tracker.fill(&mut status);
        assert_eq!(status.phase, "error");
        assert_eq!(status.last_error, TIMED_OUT);
        assert_eq!(status.consecutive_failures, 2);
        assert!((29..=30).contains(&status.next_retry_seconds));
        assert!(!status.last_attempt.is_empty());
        let json = serde_json::to_value(&status).unwrap();
        for key in ["phase", "progressDone", "progressTotal", "lastError", "lastAttempt", "consecutiveFailures", "nextRetrySeconds"] {
            assert!(json.get(key).is_some(), "{key}");
        }
        tracker.succeed();
        tracker.fill(&mut status);
        assert_eq!((status.phase, status.consecutive_failures, status.next_retry_seconds), ("done", 0, 0));
        assert!(status.last_error.is_empty());
    }

    pub(super) fn phone_op(sequence: u64, previous: &str, entity_type: &str, entity_id: &str, version: RecordVersion, base: u64, body: serde_json::Value) -> ChangeRecord {
        let signer = SigningKey::from_bytes(&[17; 32]);
        let mutation = format!("phone-op-{sequence}-{}", uuid::Uuid::new_v4());
        let payload = crate::payload::encrypt(&[4; 32], entity_type, "vault-a", &mutation, entity_id,
            &serde_json::to_vec(&body).unwrap()).unwrap();
        ChangeRecord::create_signed_with("vault-a", "phone", sequence, previous, mutation, entity_type, entity_id,
            ChangeKind::Upsert, base, version, "2026-10-04T12:00:00Z", payload.ciphertext, payload.nonce,
            |bytes| Ok::<_, ()>(signer.sign(bytes).to_bytes())).unwrap()
    }

    pub(super) fn login_entry(id: &str, title: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id, "type": "PASSWORD", "title": title, "primaryValue": "user", "secondaryValue": "pw",
            "tertiaryValue": "", "fourthValue": "", "cardKind": "CREDIT", "network": "", "totpAlgorithm": "SHA1",
            "totpDigits": 6, "totpPeriod": 30, "linkedApps": "", "autofillSignatures": "", "autofillOrigins": "",
            "linkedAuthenticatorId": "", "notes": "", "color": 1, "tags": "", "favorite": false,
            "lastOpenedAt": 0, "sortOrder": 1, "createdAt": 1, "updatedAt": 2
        })
    }

    /// Verifies and stages phone operations exactly as `receive_batch` does.
    pub(super) fn stage(synthetic: &Synthetic, operations: &[ChangeRecord]) {
        let mut app = synthetic.state.lock().unwrap();
        let db = app.unlocked.as_mut().unwrap().connection();
        initialize_received(db).unwrap();
        for operation in operations {
            let head = progress(db, "vault-a").unwrap().received.get("phone").cloned().unwrap_or((0, GENESIS_HASH.into()));
            let key = SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes();
            let verifier = IncomingVerifier::new("vault-a", "phone", key, head.0, head.1).unwrap();
            let batch = verifier.verify_batch(vec![operation.clone()]).unwrap();
            IncomingStore::persist_batch(db, &batch).unwrap();
        }
    }

    fn loopback_pair() -> (std::net::TcpListener, std::net::SocketAddr) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    fn windows_channel(address: std::net::SocketAddr) -> EncryptedSyncChannel<TcpStream, TcpStream> {
        let stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        EncryptedSyncChannel::new(SyncFrames::new(stream.try_clone().unwrap(), stream), &[8; 32], false).unwrap()
    }

    fn phone_channel(listener: &std::net::TcpListener) -> EncryptedSyncChannel<TcpStream, TcpStream> {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        EncryptedSyncChannel::new(SyncFrames::new(stream.try_clone().unwrap(), stream), &[8; 32], true).unwrap()
    }

    #[test]
    fn phone_photo_downloads_resume_verify_and_apply() {
        let synthetic = synthetic_vault(0);
        let phone_blobs = PhotoBlobs::new(synthetic.directory.join("phone-blobs"));
        let mut image = vec![0xff, 0xd8, 0xff, 0xe0];
        image.extend(std::iter::repeat_n(9u8, 150_000));
        let (hash, size) = phone_blobs.create(&[4; 32], "vault-a", "photo-p", &image).unwrap();
        let entry = phone_op(1, GENESIS_HASH, "entry", "entry-p", RecordVersion::from_entries([("phone", 1)]), 0,
            serde_json::json!({"entry": login_entry("entry-p", "Phone login"), "groupIds": []}));
        let photo = phone_op(2, &entry.hash, "photo", "photo-p", RecordVersion::from_entries([("phone", 1)]), 0,
            serde_json::json!({"photo": {"id": "photo-p", "entryId": "entry-p", "isCover": true, "addedAt": 5,
                "blobHash": hash, "blobSize": size}}));
        stage(&synthetic, &[entry, photo]);
        let (blobs, wanted) = {
            let mut app = synthetic.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            apply_waiting(vault, "vault-a", &[4; 32]).unwrap();
            assert_eq!(waiting(vault.connection(), "vault-a").unwrap().len(), 1, "the photo waits for its blob");
            (vault.photo_blobs(), vault.waiting_photo_blobs().unwrap())
        };
        assert_eq!(wanted, vec![(hash.clone(), size)]);
        let mut blob = Vec::new();
        phone_blobs.open_at(&hash, 0).unwrap().read_to_end(&mut blob).unwrap();
        let tracker = SyncTracker::default();

        // Session 1: the phone sends one chunk, then the connection drops.
        let (listener, address) = loopback_pair();
        let first = blob.clone();
        let phone = std::thread::spawn(move || {
            let mut channel = phone_channel(&listener);
            let requests: serde_json::Value = serde_json::from_slice(&channel.receive().unwrap()).unwrap();
            assert_eq!(requests[0]["offset"], 0);
            channel.send(first.len().to_string().as_bytes()).unwrap();
            channel.send(&first[..photo_blobs::CHUNK_BYTES]).unwrap();
        });
        assert!(request_photos(&mut windows_channel(address), &blobs, &wanted, &tracker).is_err());
        phone.join().unwrap();
        assert_eq!(blobs.partial_size(&hash).unwrap(), photo_blobs::CHUNK_BYTES as u64);

        // Session 2 resumes at the stored offset and acknowledges only verified data.
        let (listener, address) = loopback_pair();
        let rest = blob.clone();
        let phone = std::thread::spawn(move || {
            let mut channel = phone_channel(&listener);
            let requests: serde_json::Value = serde_json::from_slice(&channel.receive().unwrap()).unwrap();
            let offset = requests[0]["offset"].as_u64().unwrap() as usize;
            assert_eq!(offset, photo_blobs::CHUNK_BYTES);
            channel.send(rest.len().to_string().as_bytes()).unwrap();
            for chunk in rest[offset..].chunks(photo_blobs::CHUNK_BYTES) {
                channel.send(chunk).unwrap();
            }
            channel.receive().unwrap()
        });
        assert_eq!(request_photos(&mut windows_channel(address), &blobs, &wanted, &tracker).unwrap(), 1);
        assert_eq!(phone.join().unwrap(), hash.as_bytes());
        let (moved, total) = tracker.photo_bytes();
        assert!(moved >= size && total >= moved);

        let mut app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_mut().unwrap();
        apply_waiting(vault, "vault-a", &[4; 32]).unwrap();
        assert_eq!(waiting(vault.connection(), "vault-a").unwrap().len(), 0, "waitingToApply clears once the photo lands");
        assert_eq!(vault.photos_waiting_for_data().unwrap(), 0);
        let photos = vault.list_entry_photos("entry-p").unwrap();
        assert_eq!((photos.len(), photos[0].is_cover, photos[0].added_at, photos[0].mime_type.as_str()), (1, true, 5, "image/jpeg"));
        drop(app);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    #[test]
    fn windows_photos_are_signed_served_in_chunks_and_deleted_with_their_entry() {
        let synthetic = synthetic_vault(0);
        let image = [b"\x89PNG\r\n\x1a\n".as_slice(), &vec![3u8; 100_000]].concat();
        let (entry_id, blobs, hash, size) = {
            let mut app = synthetic.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            let entry = vault.save_entry(serde_json::json!({"type": "CARD", "title": "Card", "primaryValue": "4111"})).unwrap();
            let id = entry["id"].as_str().unwrap().to_owned();
            vault.add_entry_photo(&id, "image/png", &base64::engine::general_purpose::STANDARD.encode(&image)).unwrap();
            let photo = vault.list_entry_photos(&id).unwrap().remove(0);
            let (ciphertext, nonce, mutation): (String, String, String) = vault.connection().query_row(
                "SELECT payload_ciphertext, payload_nonce, mutation_id FROM sync_operations WHERE entity_type = 'photo'",
                [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
            let operation = ChangeRecord::create("vault-a", "", 1, GENESIS_HASH, mutation, "photo", &photo.id,
                ChangeKind::Upsert, 0, RecordVersion::default(), "", ciphertext, nonce, "");
            let payload: serde_json::Value = serde_json::from_slice(&crate::payload::decrypt(&[4; 32], &operation).unwrap()).unwrap();
            assert_eq!((payload["photo"]["entryId"].as_str(), payload["photo"]["isCover"].as_bool()), (Some(id.as_str()), Some(true)));
            let hash = payload["photo"]["blobHash"].as_str().unwrap().to_owned();
            let size = payload["photo"]["blobSize"].as_u64().unwrap();
            assert_eq!(&*vault.photo_blobs().decrypt(&[4; 32], "vault-a", &photo.id, &hash, size).unwrap(), image.as_slice());
            (id, vault.photo_blobs(), hash, size)
        };
        let (listener, address) = loopback_pair();
        let wanted = hash.clone();
        let phone = std::thread::spawn(move || {
            let mut channel = phone_channel(&listener);
            channel.send(serde_json::json!([
                {"hash": wanted, "offset": 10},
                {"hash": wanted, "offset": size + 5},
                {"hash": "a".repeat(64), "offset": 0},
            ]).to_string().as_bytes()).unwrap();
            let size: u64 = String::from_utf8(channel.receive().unwrap()).unwrap().parse().unwrap();
            let mut received = 10;
            while received < size {
                let chunk = channel.receive().unwrap();
                assert!(!chunk.is_empty() && chunk.len() <= photo_blobs::CHUNK_BYTES);
                received += chunk.len() as u64;
            }
            channel.send(wanted.as_bytes()).unwrap();
            let past_end = channel.receive().unwrap();
            let unknown = channel.receive().unwrap();
            (size, past_end, unknown)
        });
        let tracker = SyncTracker::default();
        assert_eq!(serve_photos(&mut windows_channel(address), &blobs, &tracker).unwrap(), 1);
        let (served, past_end, unknown) = phone.join().unwrap();
        assert_eq!((served, past_end.as_slice(), unknown.as_slice()), (size, b"-2".as_slice(), b"-1".as_slice()));

        let mut app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_mut().unwrap();
        vault.delete_entry(&entry_id).unwrap();
        let deletes: Vec<String> = vault.connection()
            .prepare("SELECT entity_type FROM sync_operations WHERE kind = 'delete' ORDER BY sequence").unwrap()
            .query_map([], |row| row.get(0)).unwrap().collect::<std::result::Result<_, _>>().unwrap();
        assert_eq!(deletes, vec!["photo", "entry"], "a published photo gets its own tombstone first");
        vault.sweep_orphan_photos().unwrap();
        assert!(!blobs.has(&hash, size), "the unreferenced blob is pruned");
        drop(app);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    #[test]
    fn orphan_sweep_keeps_photos_whose_entry_is_still_arriving() {
        let synthetic = synthetic_vault(0);
        let waiting_entry = phone_op(1, GENESIS_HASH, "entry", "entry-late", RecordVersion::from_entries([("phone", 1)]), 0,
            serde_json::json!({"entry": login_entry("entry-late", "Late"), "groupIds": ["missing-folder"]}));
        stage(&synthetic, &[waiting_entry]);
        let mut app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_mut().unwrap();
        apply_waiting(vault, "vault-a", &[4; 32]).unwrap();
        vault.connection().execute_batch(
            "INSERT INTO local_entry_photos (id, entry_id, mime_type, data) VALUES ('orphan', 'gone-entry', 'image/png', x'00');
             INSERT INTO local_entry_photos (id, entry_id, mime_type, data) VALUES ('early', 'entry-late', 'image/png', x'00');").unwrap();
        assert_eq!(vault.sweep_orphan_photos().unwrap(), 1);
        let left: Vec<String> = vault.connection().prepare("SELECT id FROM local_entry_photos").unwrap()
            .query_map([], |row| row.get(0)).unwrap().collect::<std::result::Result<_, _>>().unwrap();
        assert_eq!(left, vec!["early"]);
        drop(app);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    #[test]
    fn edits_during_a_session_are_sent_and_remote_edits_never_overwrite_them() {
        let synthetic = synthetic_vault(0);
        let (entry_id, stored) = {
            let mut app = synthetic.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            let entry = vault.save_entry(serde_json::json!({"type": "PASSWORD", "title": "Shared", "secondaryValue": "pw"})).unwrap();
            let id = entry["id"].as_str().unwrap().to_owned();
            let mut stored = entry.clone();
            stored.as_object_mut().unwrap().remove("groupIds");
            (id, stored)
        };
        let (edit_now, edit_requested) = std::sync::mpsc::channel::<()>();
        let (edit_done, edit_finished) = std::sync::mpsc::channel::<()>();
        let (listener, address) = loopback_pair();
        let local_id = synthetic.local.device_id.clone();
        let mut remote_entry = stored.clone();
        remote_entry["title"] = "Phone title".into();
        let phone_edit = phone_op(1, GENESIS_HASH, "entry", &entry_id,
            RecordVersion::new(BTreeMap::from([(local_id.clone(), 1), ("phone".into(), 1)])), 1,
            serde_json::json!({"entry": remote_entry, "groupIds": []}));
        let phone = std::thread::spawn(move || {
            let mut channel = phone_channel(&listener);
            let mut received: Vec<ChangeRecord> = Vec::new();
            let mut sent_edit = false;
            for round in 0..MAX_ROUNDS {
                let _windows_progress = SyncProgress::parse(&channel.receive().unwrap()).unwrap();
                let send = round == 1 && !sent_edit;
                channel.send(if send { b"1" } else { b"0" }).unwrap();
                if send {
                    channel.send(&operation_wire(&phone_edit).unwrap()).unwrap();
                    assert_eq!(channel.receive().unwrap(), phone_edit.hash.as_bytes());
                    sent_edit = true;
                }
                let mut heads = BTreeMap::new();
                if sent_edit {
                    heads.insert("phone".to_owned(), (1, phone_edit.hash.clone()));
                }
                if let Some(op) = received.last() {
                    heads.insert(local_id.clone(), (op.sequence, op.hash.clone()));
                }
                channel.send(&SyncProgress { received: heads.clone(), applied: heads }.encode().unwrap()).unwrap();
                let count: usize = String::from_utf8(channel.receive().unwrap()).unwrap().parse().unwrap();
                for _ in 0..count {
                    let op = operation_from_wire(&channel.receive().unwrap()).unwrap();
                    channel.send(op.hash.as_bytes()).unwrap();
                    received.push(op);
                }
                if round == 0 {
                    // The user edits the same login on the PC while the session is running.
                    edit_now.send(()).unwrap();
                    edit_finished.recv().unwrap();
                }
                if round > 1 && !send && count == 0 {
                    break;
                }
            }
            received
        });
        let editor_state = synthetic.state.clone();
        let editor_id = entry_id.clone();
        let editor = std::thread::spawn(move || {
            edit_requested.recv().unwrap();
            let mut app = editor_state.lock().unwrap();
            app.unlocked.as_mut().unwrap()
                .save_entry(serde_json::json!({"id": editor_id, "title": "PC title"})).unwrap();
            drop(app);
            edit_done.send(()).unwrap();
        });
        let tracker = SyncTracker::default();
        let (report, complete) = windows_rounds(&synthetic, address, &tracker).unwrap();
        editor.join().unwrap();
        let received = phone.join().unwrap();
        assert!(complete);
        assert_eq!((report.sent, report.received), (2, 1));
        assert_eq!(received.iter().map(|op| op.sequence).collect::<Vec<_>>(), vec![1, 2], "the mid-session edit went out in the same session");
        let mut app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_mut().unwrap();
        let entry = vault.list_entries().unwrap().into_iter().find(|e| e["id"] == entry_id.as_str()).unwrap();
        assert_eq!(entry["title"], "PC title", "the concurrent phone edit does not overwrite the local edit");
        let conflicts = vault.list_conflicts().unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].summary, "Different: Title");
        drop(app);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    pub(super) fn remove_event(previous: &MembershipEvent, subject: &str, valid: bool) -> MembershipEvent {
        let signer = SigningKey::from_bytes(&[if valid { 17 } else { 99 }; 32]);
        let mut event = MembershipEvent {
            vault_id: "vault-a".into(), sequence: previous.sequence + 1, format_version: 1,
            previous_hash: previous.hash.clone(), action: MembershipAction::Remove,
            issuer_device_id: "phone".into(), subject_device_id: subject.into(), subject_public_key: String::new(),
            key_epoch: 2, signature: String::new(), hash: String::new(),
        };
        let bytes = event.signing_bytes().unwrap();
        event.signature = URL_SAFE_NO_PAD.encode(signer.sign(&bytes).to_bytes());
        let mut digest = Sha256::new();
        digest.update(&bytes);
        digest.update(event.signature.as_bytes());
        event.hash = hex::encode(digest.finalize());
        event
    }

    fn removal_server(history: Vec<MembershipEvent>) -> (std::thread::JoinHandle<()>, std::net::SocketAddr) {
        let (listener, address) = loopback_pair();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut frames = SyncFrames::new(stream.try_clone().unwrap(), stream);
            frames.send(&[9; 32], 4096).unwrap();
            let _proof = frames.receive(4096).unwrap();
            frames.send(b"removed1", 4096).unwrap();
            frames.send(&serde_json::to_vec(&history).unwrap(), 1_000_000).unwrap();
        });
        (server, address)
    }

    #[test]
    fn verified_removal_notice_leaves_locally_and_forged_ones_do_not() {
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pairing-helper/publish/Nuvori.PairingHelper.exe");
        let synthetic = synthetic_vault(1);
        let stored = {
            let app = synthetic.state.lock().unwrap();
            app.unlocked.as_ref().unwrap().stored_membership().unwrap()
        };
        let tracker = SyncTracker::default();
        let forged = remove_event(&stored[1], &synthetic.local.device_id, false);
        let (server, address) = removal_server(vec![stored[0].clone(), stored[1].clone(), forged]);
        let result = exchange(&synthetic.state, &helper, &tracker, |_| TcpStream::connect(address).map_err(network_error));
        server.join().unwrap();
        assert_eq!(result.unwrap_err(), INTERRUPTED, "an unverified claim is only a connection failure");
        assert!(synthetic.state.lock().unwrap().unlocked.as_ref().unwrap().is_enrolled().unwrap());

        let removal = remove_event(&stored[1], &synthetic.local.device_id, true);
        let (server, address) = removal_server(vec![stored[0].clone(), stored[1].clone(), removal]);
        let result = exchange(&synthetic.state, &helper, &tracker, |_| TcpStream::connect(address).map_err(network_error));
        server.join().unwrap();
        assert_eq!(result.unwrap_err(), REMOVED_NOTICE);
        let app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_ref().unwrap();
        assert!(!vault.is_enrolled().unwrap());
        assert_eq!(vault.list_notes().unwrap().len(), 1, "items stay on this PC");
        let status = vault.membership_status().unwrap();
        let notice = status.removed_notice.clone().unwrap();
        assert_eq!(notice.by, "the managing device");
        assert!(notice.at > 0 && status.devices.is_empty() && status.manager_device_id.is_empty());
        vault.dismiss_removed_notice().unwrap();
        assert!(vault.membership_status().unwrap().removed_notice.is_none());
        drop(app);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    /// A vault created by an older build has no tables added to the change store since, and
    /// only a completed LAN exchange used to create them. Unlocking must add them so status
    /// and leaving work before the first sync.
    #[test]
    fn older_vault_without_newer_sync_tables_reports_status_and_leaves_after_unlock() {
        let synthetic = synthetic_vault(1);
        let mut app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_mut().unwrap();
        vault
            .connection()
            .execute_batch(
                "DROP TABLE sync_received_operations; DROP TABLE sync_applied_operations;
                 DROP TABLE sync_exchange_state; DROP TABLE sync_peer_acknowledgements;",
            )
            .unwrap();
        assert!(status(vault).is_err(), "the old schema reproduces the failure");
        app.unlocked = None;
        let mut vault = app.store.unlock("synthetic-test-password").unwrap();
        let reported = status(&mut vault).unwrap();
        assert_eq!(reported.waiting_to_apply, 0);
        assert!(reported.phone_address.is_empty());
        vault.leave_group(true).unwrap();
        assert!(!vault.is_enrolled().unwrap());
        assert!(vault.membership_status().unwrap().pending_leave);
    }

    #[test]
    fn leaving_with_an_empty_vault_removes_items_but_keeps_the_leave_request_and_password() {
        let synthetic = synthetic_vault(3);
        let mut app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_mut().unwrap();
        assert_eq!(vault.list_notes().unwrap().len(), 3);
        vault.leave_group(false).unwrap();
        assert!(!vault.is_enrolled().unwrap());
        assert!(vault.list_notes().unwrap().is_empty());
        assert!(vault.membership_status().unwrap().pending_leave);
        let operations: i64 = vault
            .connection()
            .query_row("SELECT count(*) FROM sync_operations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(operations, 0);
        app.unlocked = None;
        let mut vault = app.store.unlock("synthetic-test-password").unwrap();
        assert!(vault.list_notes().unwrap().is_empty());
        vault.save_note(None, "Fresh start", "Body", Some(vec![])).unwrap();
        assert_eq!(vault.list_notes().unwrap().len(), 1);
    }

    #[test]
    fn leave_request_is_signed_before_leaving_and_retried_until_the_manager_confirms() {
        let synthetic = synthetic_vault(0);
        let head = {
            let mut app = synthetic.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            vault.connection().execute("INSERT INTO sync_exchange_state (vault_id, phone_address) VALUES ('vault-a', '192.168.1.24')", []).unwrap();
            let status = vault.membership_status().unwrap();
            assert_eq!(status.manager_device_id, "phone");
            assert_eq!(status.devices.len(), 2);
            assert!(status.devices.iter().any(|d| d.is_this_device && d.platform == "windows" && d.status == "active"));
            let head = membership::verify(&vault.stored_membership().unwrap()).unwrap().head;
            vault.leave_group(true).unwrap();
            assert!(!vault.is_enrolled().unwrap());
            assert!(vault.membership_status().unwrap().pending_leave);
            head
        };
        let local = synthetic.local.clone();
        for (reply, kept) in [(b"notmanager1".as_slice(), true), (b"left1".as_slice(), false)] {
            let (listener, address) = loopback_pair();
            let expected_head = head.clone();
            let local = local.clone();
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut frames = SyncFrames::new(stream.try_clone().unwrap(), stream);
                frames.send(&[9; 32], 4096).unwrap();
                let frame = String::from_utf8(frames.receive(4096).unwrap()).unwrap();
                let parts: Vec<&str> = frame.split('.').collect();
                assert_eq!(parts[0], "leave1");
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&[5; 32]).unwrap();
                mac.update(b"nuvori-lan-probe-v1");
                mac.update(&[9; 32]);
                mac.verify_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
                let request: crate::membership_exit::LeaveRequest =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
                assert_eq!((request.vault_id.as_str(), request.device_id.as_str(), request.membership_head.as_str(), request.key_epoch),
                    ("vault-a", local.device_id.as_str(), expected_head.as_str(), 1));
                let signature: [u8; 64] = URL_SAFE_NO_PAD.decode(parts[3]).unwrap().try_into().unwrap();
                assert!(verify_signature(&local.public_key, &request.signing_bytes(), &signature));
                frames.send(reply, 4096).unwrap();
            });
            let answer = deliver_leave_with(&synthetic.state, 0, |address_text, vault_id| {
                assert_eq!((address_text, vault_id), ("192.168.1.24", "vault-a"));
                TcpStream::connect(address).map_err(network_error)
            })
            .unwrap();
            server.join().unwrap();
            assert!(answer.is_some());
            let app = synthetic.state.lock().unwrap();
            assert_eq!(app.unlocked.as_ref().unwrap().membership_status().unwrap().pending_leave, kept);
        }
        assert_eq!(deliver_leave_with(&synthetic.state, 0, |_, _| panic!("nothing is pending")).unwrap(), None);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    #[test]
    fn endpoints_are_private_and_ports_match_java() {
        assert_eq!(sync_port("android-vault"), 23492);
        assert_eq!(
            endpoint("192.168.1.4", "android-vault").unwrap().port(),
            sync_port("android-vault")
        );
        assert!(endpoint("8.8.8.8:1234", "vault").is_err());
        assert!(endpoint("127.0.0.1:1234", "vault").is_err());
        assert!(endpoint("192.168.1.4:80", "vault").is_err());
    }
    #[test]
    fn android_operation_wire_round_trips() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/sync-foundation-v1.json")).unwrap();
        let operation: ChangeRecord = serde_json::from_value(fixture["change"].clone()).unwrap();
        let bytes = operation_wire(&operation).unwrap();
        assert_eq!(operation_from_wire(&bytes).unwrap(), operation);
        let encoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(encoded["recordVersionJson"].is_string());
        assert!(encoded.get("recordVersion").is_none());
    }
    #[test]
    fn two_windows_exchange_photos_and_relay_android_changes_in_eight_member_group() {
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pairing-helper/publish/Nuvori.PairingHelper.exe");
        assert!(helper.is_file(), "Build the pairing helper before running sync tests");
        let mut a = synthetic_vault(1);
        let mut b = synthetic_vault(1);
        let phone = DeviceIdentity { device_id: "phone".into(),
            public_key: SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes() };
        let mut history = vec![signed_member(None, &phone)];
        for device in [&a.local, &b.local] {
            history.push(signed_member(history.last(), device));
        }
        for index in 2..=6 {
            let device = DeviceIdentity { device_id: format!("phone-{index}"),
                public_key: SigningKey::from_bytes(&[30 + index; 32]).verifying_key().to_bytes() };
            history.push(signed_member(history.last(), &device));
        }
        assert_eq!(membership::verify(&history).unwrap().members.len(), 8);
        let extra = DeviceIdentity { device_id: "extra".into(),
            public_key: SigningKey::from_bytes(&[50; 32]).verifying_key().to_bytes() };
        let mut too_many = history.clone();
        too_many.push(signed_member(history.last(), &extra));
        assert!(membership::verify(&too_many).is_err());
        for device in [&mut a, &mut b] {
            let mut app = device.state.lock().unwrap();
            let db = app.unlocked.as_mut().unwrap().connection();
            db.execute("DELETE FROM sync_membership_events", []).unwrap();
            let verified = membership::verify(&history).unwrap();
            persist_membership(db, "vault-a", &[], &history, &verified).unwrap();
            device.membership = verified;
        }
        stage(&a, &[phone_change()]);
        let image = [b"\x89PNG\r\n\x1a\n".as_slice(), &vec![7u8; 100_000]].concat();
        let entry_id = {
            let mut app = a.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            let entry = vault.save_entry(serde_json::json!({"type": "CARD", "title": "From PC A", "primaryValue": "4111"})).unwrap();
            let id = entry["id"].as_str().unwrap().to_owned();
            vault.add_entry_photo(&id, "image/png", &base64::engine::general_purpose::STANDARD.encode(&image)).unwrap();
            id
        };
        let (listener, address) = loopback_pair();
        let server_state = a.state.clone();
        let server_helper = helper.clone();
        let server = std::thread::spawn(move || {
            exchange_role(&server_state, &server_helper, &SyncTracker::default(), true,
                |_| listener.accept().map(|(stream, _)| stream).map_err(network_error))
        });
        let (client_report, complete) = exchange(&b.state, &helper, &SyncTracker::default(),
            |_| TcpStream::connect(address).map_err(network_error)).unwrap();
        let (server_report, server_complete) = server.join().unwrap().unwrap();
        assert!(complete && server_complete);
        assert_eq!((client_report.sent, client_report.received), (1, 4));
        assert_eq!((server_report.sent, server_report.received), (4, 1));
        assert_eq!((client_report.photos_received, server_report.photos_sent), (1, 1));
        {
            let mut app = b.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            assert_eq!(vault.list_notes().unwrap().len(), 2);
            assert_eq!(vault.connection().query_row("SELECT name FROM local_groups WHERE id = 'phone-folder'", [], |row| row.get::<_, String>(0)).unwrap(), "Phone notes");
            assert_eq!(vault.list_entry_photos(&entry_id).unwrap().len(), 1);
        }
        // Swap the initiator and retry the same history. Acknowledged changes are not duplicated.
        let (listener, address) = loopback_pair();
        let server_state = b.state.clone();
        let server_helper = helper.clone();
        let server = std::thread::spawn(move || {
            exchange_role(&server_state, &server_helper, &SyncTracker::default(), true,
                |_| listener.accept().map(|(stream, _)| stream).map_err(network_error))
        });
        let (report, complete) = exchange(&a.state, &helper, &SyncTracker::default(),
            |_| TcpStream::connect(address).map_err(network_error)).unwrap();
        assert!(server.join().unwrap().unwrap().1 && complete);
        assert_eq!((report.sent, report.received, report.photos_received), (0, 0, 0));
        for device in [a, b] {
            drop(device.state);
            std::fs::remove_dir_all(device.directory).unwrap();
        }
    }

    #[test]
    fn applied_changes_advance_ui_revision_after_ciphertext_was_already_received() {
        let synthetic = synthetic_vault(0);
        stage(&synthetic, &[phone_change()]);
        let mut app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_mut().unwrap();
        let received_revision = vault.change_revision().unwrap();
        let operations = vault.connection().query_row("SELECT count(*) FROM sync_operations", [], |row| row.get::<_, u32>(0)).unwrap();
        apply_waiting(vault, "vault-a", &[4; 32]).unwrap();
        assert!(vault.change_revision().unwrap() > received_revision);
        assert_eq!(vault.connection().query_row("SELECT count(*) FROM sync_operations", [], |row| row.get::<_, u32>(0)).unwrap(), operations);
        drop(app);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    #[test]
    fn an_unreadable_change_is_set_aside_and_the_rest_still_apply() {
        let synthetic = synthetic_vault(0);
        let blank = phone_op(1, GENESIS_HASH, "entry", "bad", RecordVersion::from_entries([("phone", 1)]), 0,
            serde_json::json!({"entry": login_entry("bad", " "), "groupIds": []}));
        let good = phone_op(2, &blank.hash, "entry", "good", RecordVersion::from_entries([("phone", 2)]), 0,
            serde_json::json!({"entry": login_entry("good", "Bank"), "groupIds": []}));
        stage(&synthetic, &[blank, good]);
        let mut app = synthetic.state.lock().unwrap();
        let vault = app.unlocked.as_mut().unwrap();
        apply_waiting(vault, "vault-a", &[4; 32]).expect("one unreadable change does not fail the pass");
        apply_waiting(vault, "vault-a", &[4; 32]).unwrap();
        let reported = status(vault).unwrap();
        assert_eq!((reported.waiting_to_apply, reported.set_aside), (1, 1));
        let titles: Vec<String> = vault.list_entries().unwrap().iter()
            .map(|entry| entry["title"].as_str().unwrap_or_default().to_owned()).collect();
        assert_eq!(titles, ["Bank"]);
        drop(app);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    #[test]
    #[ignore = "requires a private local IPv4 interface"]
    fn group_sync_continues_after_an_offline_endpoint_and_reports_waiting_peers() {
        let ip = crate::discovery::local_addresses().into_iter().find(|ip| ip.is_ipv4()).unwrap();
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pairing-helper/publish/Nuvori.PairingHelper.exe");
        let a = synthetic_vault(1);
        let b = synthetic_vault(0);
        let phone = DeviceIdentity { device_id: "phone".into(),
            public_key: SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes() };
        let mut history = vec![signed_member(None, &phone)];
        for device in [&a.local, &b.local] { history.push(signed_member(history.last(), device)); }
        for device in [&a, &b] {
            let mut app = device.state.lock().unwrap();
            let db = app.unlocked.as_mut().unwrap().connection();
            db.execute("DELETE FROM sync_membership_events", []).unwrap();
            persist_membership(db, "vault-a", &[], &history, &membership::verify(&history).unwrap()).unwrap();
        }
        let offline = std::net::TcpListener::bind((ip, 0)).unwrap();
        let offline_address = offline.local_addr().unwrap();
        drop(offline);
        let failed = SyncTracker::default();
        assert_eq!(run(&a.state, &helper, "", &failed, &[offline_address]).unwrap_err(), UNREACHABLE);
        assert_eq!(failed.consecutive_failures(), 1, "one failed group check counts once, not once per candidate plus once per group");
        assert!(!failed.state.lock().unwrap().last_attempt.is_empty());
        let busy_listener = std::net::TcpListener::bind((ip, 0)).unwrap();
        let busy_address = busy_listener.local_addr().unwrap();
        let busy_server = std::thread::spawn(move || {
            let stream = busy_listener.accept().unwrap().0;
            reply_busy(stream);
        });
        let busy = SyncTracker::default();
        assert_eq!(run(&a.state, &helper, "", &busy, &[busy_address, offline_address]).unwrap_err(), BUSY);
        busy_server.join().unwrap();
        assert_eq!(busy.consecutive_failures(), 0, "busy peers are reachable and do not extend failure backoff");
        let listener = std::net::TcpListener::bind((ip, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = b.state.clone();
        let server_helper = helper.clone();
        let server = std::thread::spawn(move || serve(&server_state, &server_helper,
            listener.accept().unwrap().0, &SyncTracker::default()));
        let tracker = SyncTracker::default();
        let report = run(&a.state, &helper, "", &tracker, &[offline_address, address]).unwrap();
        server.join().unwrap().unwrap();
        assert_eq!((report.sent, report.peers_checked, report.peers_waiting), (1, 1, 1));
        assert_eq!(tracker.consecutive_failures(), 0);
        assert_eq!(b.state.lock().unwrap().unlocked.as_ref().unwrap().list_notes().unwrap().len(), 1);
        for device in [a, b] {
            drop(device.state);
            std::fs::remove_dir_all(device.directory).unwrap();
        }
    }

    #[test]
    fn unrelated_incoming_probe_does_not_replace_successful_sync_status() {
        let synthetic = synthetic_vault(0);
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pairing-helper/publish/Nuvori.PairingHelper.exe");
        let tracker = std::sync::Arc::new(SyncTracker::default());
        tracker.succeed();
        let (listener, address) = loopback_pair();
        let server_state = synthetic.state.clone();
        let server_tracker = tracker.clone();
        let server = std::thread::spawn(move || serve(&server_state, &helper,
            listener.accept().unwrap().0, &server_tracker));
        let stream = TcpStream::connect(address).unwrap();
        let mut frames = SyncFrames::new(stream.try_clone().unwrap(), stream);
        assert_eq!(frames.receive(4096).unwrap().len(), 32);
        frames.send(URL_SAFE_NO_PAD.encode([0; 32]).as_bytes(), 4096).unwrap();
        assert_eq!(server.join().unwrap().unwrap_err(), REJECTED);
        assert_eq!(tracker.state.lock().unwrap().phase, Phase::Done);
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    /// Run with WindowsInteropSyncTest on an emulator and adb forward tcp:18474 tcp:18474.
    #[test]
    #[ignore = "requires the Android emulator interoperability instrumentation test"]
    fn android_emulator_sync_interop() {
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pairing-helper/publish/Nuvori.PairingHelper.exe");
        let fixture = synthetic_vault(0);
        let bootstrap = std::net::TcpListener::bind("127.0.0.1:18472").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:18473").unwrap();
        bootstrap.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(180);
        eprintln!("Android interoperability host ready on 18472");
        let stream = loop {
            if let Ok((stream, _)) = bootstrap.accept() { break stream; }
            assert!(Instant::now() < deadline, "Android instrumentation did not connect");
            std::thread::sleep(Duration::from_millis(100));
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(90))).unwrap();
        let mut control = SyncFrames::new(stream.try_clone().unwrap(), stream);
        let entry_id = {
            let mut app = fixture.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            vault.save_note(None, "Windows offline edit", "Windows body", Some(vec![])).unwrap().id
        };
        control.send(serde_json::json!({"deviceId": fixture.local.device_id,
            "publicKey": fixture.local.public_key_base64_url(), "entryId": entry_id}).to_string().as_bytes(), MAX_FRAME).unwrap();
        let history: Vec<MembershipEvent> = serde_json::from_slice(&control.receive(MAX_FRAME).unwrap()).unwrap();
        let accepted = membership::verify(&history).unwrap();
        {
            let mut app = fixture.state.lock().unwrap();
            let db = app.unlocked.as_mut().unwrap().connection();
            db.execute("DELETE FROM sync_membership_events", []).unwrap();
            db.execute("DELETE FROM sync_memberships", []).unwrap();
            persist_membership(db, "vault-a", &[], &history, &accepted).unwrap();
        }
        control.send(b"ready", MAX_FRAME).unwrap();
        let (report, complete) = exchange_role(&fixture.state, &helper, &SyncTracker::default(), true,
            |_| listener.accept().map(|(stream, _)| stream).map_err(network_error))
            .expect("Android client must complete an authenticated Windows server exchange");
        assert!(complete);
        assert_eq!((report.sent, report.received), (1, 1));
        {
            let mut app = fixture.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            assert!(vault.list_notes().unwrap().iter().any(|note| note.title == "Android offline edit"));
            vault.save_note(Some(&entry_id), "Windows later edit", "Windows body", Some(vec![])).unwrap();
        }
        control.send(b"received", MAX_FRAME).unwrap();
        assert_eq!(control.receive(MAX_FRAME).unwrap(), b"listening");
        let (report, complete) = exchange(&fixture.state, &helper, &SyncTracker::default(),
            |_| TcpStream::connect("127.0.0.1:18474").map_err(network_error))
            .expect("Windows client must complete an authenticated Android server exchange");
        assert!(complete);
        assert_eq!((report.sent, report.received), (1, 1));
        {
            let mut app = fixture.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            assert!(vault.list_notes().unwrap().iter().any(|note| note.title == "Android later edit"));
            assert!(waiting(vault.connection(), "vault-a").unwrap().is_empty());
        }
        control.send(b"complete", MAX_FRAME).unwrap();
        drop(fixture.state);
        std::fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn confirmed_peer_route_is_saved_and_public_addresses_are_rejected() {
        let synthetic = synthetic_vault(0);
        {
            let mut app = synthetic.state.lock().unwrap();
            let vault = app.unlocked.as_mut().unwrap();
            let address: SocketAddr = "192.168.1.20:26578".parse().unwrap();
            remember_peer_endpoint(vault, "test-vault", "phone", address).unwrap();
            remember_peer_endpoint(vault, "test-vault", "phone", "8.8.8.8:26578".parse().unwrap()).unwrap();
            let saved: String = vault.connection().query_row(
                "SELECT address FROM sync_peer_endpoints WHERE peer_device_id = 'phone'", [], |row| row.get(0)).unwrap();
            assert_eq!(saved, address.to_string());
        }
        drop(synthetic.state);
        std::fs::remove_dir_all(synthetic.directory).unwrap();
    }

    #[test]
    fn busy_peer_keeps_local_changes_and_enrollment() {
        let fixture = synthetic_vault(1);
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pairing-helper/publish/Nuvori.PairingHelper.exe");
        let (listener, address) = loopback_pair();
        let server = std::thread::spawn(move || {
            let stream = listener.accept().unwrap().0;
            reply_busy(stream);
        });
        let error = exchange(&fixture.state, &helper, &SyncTracker::default(),
            |_| TcpStream::connect(address).map_err(network_error)).unwrap_err();
        server.join().unwrap();
        assert_eq!(error, BUSY);
        let app = fixture.state.lock().unwrap();
        let vault = app.unlocked.as_ref().unwrap();
        assert!(vault.is_enrolled().unwrap());
        assert_eq!(vault.local_change_count().unwrap(), 1);
        drop(app);
        drop(fixture.state);
        std::fs::remove_dir_all(fixture.directory).unwrap();
    }

    /// Android sends `busy1` (`MembershipWire.BUSY`); Windows up to 2.1.6 sent `busy`.
    #[test]
    fn busy_word_matches_android_and_older_windows() {
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pairing-helper/publish/Nuvori.PairingHelper.exe");
        for word in [b"busy1".as_slice(), b"busy".as_slice()] {
            let fixture = synthetic_vault(1);
            let (listener, address) = loopback_pair();
            let server = std::thread::spawn(move || {
                let stream = listener.accept().unwrap().0;
                SyncFrames::new(io::empty(), stream).send(word, 4096).unwrap();
            });
            let error = exchange(&fixture.state, &helper, &SyncTracker::default(),
                |_| TcpStream::connect(address).map_err(network_error)).unwrap_err();
            server.join().unwrap();
            assert_eq!(error, BUSY, "{:?} is a busy reply", std::str::from_utf8(word));
            drop(fixture.state);
            std::fs::remove_dir_all(fixture.directory).unwrap();
        }
        // What this PC sends is the word a phone accepts.
        let (listener, address) = loopback_pair();
        let server = std::thread::spawn(move || reply_busy(listener.accept().unwrap().0));
        let stream = TcpStream::connect(address).unwrap();
        let sent = SyncFrames::new(stream, io::sink()).receive(4096).unwrap();
        server.join().unwrap();
        assert_eq!(sent, b"busy1");
    }

}
