pub mod activity;
pub mod browser;
pub mod browser_ipc;
mod browser_setup;
pub mod change_store;
pub mod conflicts;
mod desktop;
pub mod dpapi;
pub mod enrollment;
pub mod hello;
pub mod identity;
pub mod incoming;
pub mod incoming_apply;
pub mod incoming_store;
mod discovery;
mod google_drive;
mod lan_sync;
pub mod membership;
pub mod membership_exit;
pub mod migration_inventory;
pub mod pairing;
mod passkey_plugin;
pub mod passkeys;
pub mod payload;
pub mod photo_blobs;
pub mod portable_backup;
pub mod progress;
pub mod protocol;
pub mod snapshot;
pub mod snapshot_import;
mod store_build;
pub mod sync;
mod totp;
pub mod vault;
pub mod wire;

use std::{
    net::{Shutdown, TcpStream},
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::{Zeroize, Zeroizing};

use crate::vault::{
    EntryPhoto, LocalGroup, LocalNote, PasskeySummary, UnlockedVault, VaultError, VaultStore,
};
use crate::{
    activity::{Category, Level},
    browser::{BrowserAction, FilledItem, ItemKind, PendingDetails, SelectedCredential},
    browser_ipc::{
        BrowserCredentialProvider, BrowserIpcError, BrowserIpcServer, BrowserStatus,
        LoginCandidate,
    },
    enrollment::{JoinSession, PairingInvitation, ReverseOffer},
    identity::DeviceIdentityStore,
};

type ManagedState = Arc<Mutex<AppState>>;

struct VaultBrowserProvider {
    state: ManagedState,
}

impl BrowserCredentialProvider for VaultBrowserProvider {
    fn query_credentials(&self, origin: &str) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
        let app = self
            .state
            .lock()
            .map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_ref().ok_or(BrowserIpcError::VaultLocked)?;
        let exact = vault.matching_logins(origin).map_err(|_| BrowserIpcError::InvalidRequest)?;
        let related = vault.related_logins(origin).map_err(|_| BrowserIpcError::InvalidRequest)?;
        // Logins for this exact site first, then those saved for another page of the same site.
        Ok(exact
            .into_iter()
            .map(|(id, title, username)| LoginCandidate { id, title, username, related: false })
            .chain(related.into_iter().map(|(id, title, username)| LoginCandidate { id, title, username, related: true }))
            .collect())
    }

    fn load_selected_credential(
        &self,
        id: &str,
        origin: &str,
    ) -> Result<Option<SelectedCredential>, BrowserIpcError> {
        let app = self
            .state
            .lock()
            .map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_ref().ok_or(BrowserIpcError::VaultLocked)?;
        Ok(vault
            .fillable_login(id, origin)
            .map_err(|_| BrowserIpcError::InvalidRequest)?
            .map(|(username, password)| SelectedCredential {
                id: id.to_owned(),
                username,
                password,
            }))
    }

    fn save_new_login(&self, origin: &str, username: &str, password: &str, title: Option<&str>) -> Result<bool, BrowserIpcError> {
        let mut app = self.state.lock().map_err(|_| BrowserIpcError::SaveFailed)?;
        let vault = app.unlocked.as_mut().ok_or(BrowserIpcError::VaultLocked)?;
        vault.save_new_browser_login(origin, username, password, title).map_err(|error| match error {
            VaultError::BrowserLoginConflict => BrowserIpcError::LoginConflict,
            _ => BrowserIpcError::SaveFailed,
        })
    }
    fn update_login(&self, origin: &str, id: &str, username: &str, password: &str, expected_hash: &[u8; 32]) -> Result<(), BrowserIpcError> {
        let mut app = self.state.lock().map_err(|_| BrowserIpcError::SaveFailed)?;
        let vault = app.unlocked.as_mut().ok_or(BrowserIpcError::VaultLocked)?;
        vault.update_browser_login(origin, id, username, password, expected_hash).map_err(|error| match error {
            VaultError::BrowserLoginConflict => BrowserIpcError::LoginConflict,
            _ => BrowserIpcError::SaveFailed,
        })
    }
    fn review_login(&self, origin: &str, username: &str, password: &str) -> Result<bool, BrowserIpcError> {
        let app = self.state.lock().map_err(|_| BrowserIpcError::SaveFailed)?;
        let vault = app.unlocked.as_ref().ok_or(BrowserIpcError::VaultLocked)?;
        vault.review_browser_login(origin, username, password).map_err(|error| match error {
            VaultError::BrowserLoginConflict => BrowserIpcError::LoginConflict,
            _ => BrowserIpcError::SaveFailed,
        })
    }

    fn query_items(&self, kind: ItemKind, origin: &str, all: bool) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
        let app = self.state.lock().map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_ref().ok_or(BrowserIpcError::VaultLocked)?;
        let items = match kind {
            ItemKind::Card => vault.browser_cards(),
            ItemKind::Profile => vault.browser_profiles(),
            ItemKind::Code => vault.browser_codes(origin, all),
        }
        .map_err(|_| BrowserIpcError::InvalidRequest)?;
        Ok(items.into_iter().map(|(id, title, username)| LoginCandidate { id, title, username, related: false }).collect())
    }

    fn load_item(&self, kind: ItemKind, id: &str, _origin: &str) -> Result<Option<FilledItem>, BrowserIpcError> {
        let app = self.state.lock().map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_ref().ok_or(BrowserIpcError::VaultLocked)?;
        let item = |card, profile, code| FilledItem { id: id.to_owned(), kind, card, profile, code, cvv_token: None };
        let loaded = match kind {
            ItemKind::Card => vault.browser_card(id).map(|card| card.map(|card| item(Some(card), None, None))),
            ItemKind::Profile => vault.browser_profile(id).map(|profile| profile.map(|profile| item(None, Some(profile), None))),
            ItemKind::Code => {
                let now = time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
                vault.browser_code(id, now).map(|code| code.map(|code| item(None, None, Some(code))))
            }
        };
        loaded.map_err(|_| BrowserIpcError::InvalidRequest)
    }

    fn review_details(&self, pending: &PendingDetails) -> Result<bool, BrowserIpcError> {
        let app = self.state.lock().map_err(|_| BrowserIpcError::SaveFailed)?;
        let vault = app.unlocked.as_ref().ok_or(BrowserIpcError::VaultLocked)?;
        vault.review_browser_details(pending).map_err(|_| BrowserIpcError::SaveFailed)
    }

    fn save_details(&self, pending: &PendingDetails, title: Option<&str>) -> Result<bool, BrowserIpcError> {
        let mut app = self.state.lock().map_err(|_| BrowserIpcError::SaveFailed)?;
        let vault = app.unlocked.as_mut().ok_or(BrowserIpcError::VaultLocked)?;
        let saved = vault.save_browser_details(pending, title).map_err(|_| BrowserIpcError::SaveFailed)?;
        if saved {
            activity::log(Level::Success, Category::Browser, if matches!(pending.kind, ItemKind::Card) { "Added a card from the browser" } else { "Added an address from the browser" });
        }
        Ok(saved)
    }
}

struct AppState {
    store: VaultStore,
    unlocked: Option<UnlockedVault>,
}

#[derive(Default)]
struct SyncController {
    gate: Mutex<()>,
    message: Mutex<String>,
    tracker: lan_sync::SyncTracker,
    discovery: Mutex<Option<discovery::LanDiscovery>>,
    cloud: CloudController,
}

/// The Google Drive side of sync. `drive` keeps the access token between passes.
#[derive(Default)]
struct CloudController {
    drive: Mutex<Option<google_drive::GoogleDrive>>,
    connecting: std::sync::atomic::AtomicBool,
    cancel: std::sync::atomic::AtomicBool,
    needs_sign_in: std::sync::atomic::AtomicBool,
    last_error: Mutex<String>,
    /// When the whole app folder was last listed; other passes list only what changed since.
    listed_all: Mutex<Option<Instant>>,
}

const CLOUD_FULL_LISTING: Duration = Duration::from_secs(6 * 60 * 60);

impl CloudController {
    /// One cloud pass. `None` when this PC is not connected to a drive or not in a sync group.
    fn pass(&self, state: &ManagedState, tracker: &lan_sync::SyncTracker, manual: bool) -> Option<Result<lan_sync::SyncReport, String>> {
        use std::sync::atomic::Ordering;
        google_drive::client()?;
        let account = {
            let mut app = state.lock().ok()?;
            let vault = app.unlocked.as_mut()?;
            if !vault.is_enrolled().ok()? { return None; }
            lan_sync::cloud::account(vault.connection())?
        };
        let mut drive = self.drive.lock().ok()?;
        let store = drive.get_or_insert_with(|| google_drive::GoogleDrive::new(account.refresh_token.clone()));
        let full = manual || self.listed_all.lock().ok()?.is_none_or(|at| at.elapsed() > CLOUD_FULL_LISTING);
        let result = lan_sync::cloud::run(state, store, tracker, full);
        match &result {
            Ok(_) => {
                if full && let Ok(mut listed) = self.listed_all.lock() { *listed = Some(Instant::now()); }
                self.needs_sign_in.store(false, Ordering::SeqCst);
                if let Ok(mut error) = self.last_error.lock() { error.clear(); }
            }
            Err(error) => {
                if error == lan_sync::cloud::AUTH_NEEDED {
                    self.needs_sign_in.store(true, Ordering::SeqCst);
                    *drive = None;
                }
                if let Ok(mut last) = self.last_error.lock() { *last = error.clone(); }
            }
        }
        Some(result)
    }

    /// True when this build has a Google client and this PC saved a Google Drive sign-in.
    fn connected(state: &ManagedState) -> bool {
        google_drive::client().is_some() && state.lock().ok().is_some_and(|mut app| {
            app.unlocked.as_mut().is_some_and(|vault| lan_sync::cloud::account(vault.connection()).is_some())
        })
    }

    fn reset(&self) {
        use std::sync::atomic::Ordering;
        if let Ok(mut drive) = self.drive.lock() { *drive = None; }
        if let Ok(mut listed) = self.listed_all.lock() { *listed = None; }
        if let Ok(mut error) = self.last_error.lock() { error.clear(); }
        self.needs_sign_in.store(false, Ordering::SeqCst);
    }
}

impl SyncController {
    fn endpoints(&self) -> Vec<std::net::SocketAddr> {
        let Ok(mut network) = self.discovery.lock() else { return Vec::new(); };
        if network.is_none() { *network = discovery::LanDiscovery::new().ok(); }
        network.as_mut().map_or_else(Vec::new, discovery::LanDiscovery::endpoints)
    }

    /// Runs one pass over `ways`. `manual` passes always log; automatic passes log only when
    /// something moved or failed so the activity log is not flooded by idle checks.
    fn exchange(&self, state: &ManagedState, helper: &std::path::Path, address: &str, manual: bool, ways: Ways) -> PassOutcome {
        let Ok(_guard) = self.gate.try_lock() else {
            return PassOutcome::not_run(Err("A sync pass is already running".into()));
        };
        // Google Drive alone was asked for and is not connected: nothing runs, the status stays.
        if !ways.wifi && !CloudController::connected(state) {
            return PassOutcome::not_run(Err(DRIVE_NOT_CONNECTED.into()));
        }
        if let Ok(mut message) = self.message.lock() { *message = "Syncing with your devices...".into(); }
        if manual {
            activity::log(Level::Progress, Category::Sync, "Sync started");
        }
        let mut endpoints = if ways.wifi { self.endpoints() } else { Vec::new() };
        if manual && ways.wifi && endpoints.is_empty() {
            for _ in 0..6 {
                thread::sleep(Duration::from_millis(500));
                endpoints = self.endpoints();
                if !endpoints.is_empty() { break; }
            }
        }
        let mut outcome = self.pass(state, helper, address, &endpoints, manual, ways);
        // Continuous editing: edits saved on this PC while the pass ran get a prompt follow-up
        // pass (after a short debounce) instead of waiting for the next interval.
        for _ in 0..MAX_FOLLOW_UP_PASSES {
            let Ok(report) = &outcome.result else { break };
            if !local_edits_since(state, report.local_revision_at_start) {
                break;
            }
            let previous = report.clone();
            thread::sleep(FOLLOW_UP_DEBOUNCE);
            let endpoints = if ways.wifi { self.endpoints() } else { Vec::new() };
            let follow_up = self.pass(state, helper, address, &endpoints, false, ways);
            outcome = PassOutcome {
                result: follow_up.result.map(|next| lan_sync::SyncReport {
                    sent: previous.sent + next.sent,
                    received: previous.received + next.received,
                    photos_received: previous.photos_received + next.photos_received,
                    photos_sent: previous.photos_sent + next.photos_sent,
                    ..next
                }),
                ..follow_up
            };
        }
        if !outcome.quiet {
            if let Ok(mut message) = self.message.lock() {
                *message = match &outcome.result { Ok(report) => sync_summary(report), Err(error) => error.clone() };
            }
            log_sync_result(&outcome.result, manual);
        }
        outcome
    }

    /// One pass over `ways`: devices on this Wi-Fi first, then Google Drive when it is connected.
    /// The pass succeeds when either way worked, so a PC away from its phone still syncs.
    fn pass(&self, state: &ManagedState, helper: &std::path::Path, address: &str,
        endpoints: &[std::net::SocketAddr], manual: bool, ways: Ways) -> PassOutcome {
        let lan = ways.wifi.then(|| lan_sync::run(state, helper, address, &self.tracker, endpoints));
        let cloud = if ways.drive { self.cloud.pass(state, &self.tracker, manual) } else { None };
        let way = |result: &Option<Result<lan_sync::SyncReport, String>>| {
            result.as_ref().map(|result| result.as_ref().map(|_| ()).map_err(Clone::clone))
        };
        let (wifi, drive) = (way(&lan), way(&cloud));
        let mut quiet = false;
        let result = match (lan, cloud) {
            (None, None) => {
                quiet = true;
                Err(DRIVE_NOT_CONNECTED.to_owned())
            }
            (Some(lan), None) => {
                // Wi-Fi alone, with Google Drive connected: no device on this Wi-Fi is normal for
                // a PC away from its phone. It is not shown or logged as a sync failure.
                if !manual && lan.as_ref().is_err_and(|error| error == lan_sync::UNREACHABLE) && CloudController::connected(state) {
                    self.tracker.succeed();
                    quiet = true;
                }
                lan
            }
            (None, Some(cloud)) => {
                // Google Drive alone. Its errors show on the Google Drive card, not as a Wi-Fi failure.
                if cloud.is_ok() { self.tracker.succeed(); } else { self.tracker.set_phase(lan_sync::Phase::Done); }
                quiet = cloud.is_err() && !manual;
                cloud.map(|report| lan_sync::SyncReport { cloud: true, ..report })
            }
            (Some(lan), Some(cloud)) => self.merge(lan, cloud),
        };
        PassOutcome { result, wifi, drive, quiet }
    }

    fn merge(&self, lan: Result<lan_sync::SyncReport, String>, cloud: Result<lan_sync::SyncReport, String>) -> Result<lan_sync::SyncReport, String> {
        match (lan, cloud) {
            (Ok(lan), Ok(cloud)) => {
                self.tracker.succeed();
                Ok(lan_sync::SyncReport {
                    sent: lan.sent + cloud.sent,
                    received: lan.received + cloud.received,
                    photos_received: lan.photos_received + cloud.photos_received,
                    photos_sent: lan.photos_sent + cloud.photos_sent,
                    waiting_to_apply: cloud.waiting_to_apply,
                    conflicts: cloud.conflicts,
                    cloud: true,
                    ..lan
                })
            }
            (Err(_), Ok(cloud)) => {
                self.tracker.succeed();
                Ok(lan_sync::SyncReport { cloud: true, ..cloud })
            }
            // The cloud card on the Sync page shows the cloud error; Wi-Fi sync still counts.
            (Ok(lan), Err(_)) => {
                self.tracker.succeed();
                Ok(lan)
            }
            (Err(lan), Err(cloud)) => {
                // With no device on this Wi-Fi, the cloud error says what to fix.
                let error = if lan == lan_sync::UNREACHABLE { cloud } else { lan };
                self.tracker.set_error(&error);
                Err(error)
            }
        }
    }
}

/// Which ways one pass uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ways {
    wifi: bool,
    drive: bool,
}

impl Ways {
    const ALL: Ways = Ways { wifi: true, drive: true };
    const DRIVE: Ways = Ways { wifi: false, drive: true };
}

/// The result of one pass, and of each way that ran (`None`: it did not run). The automatic loop
/// keeps a retry delay per way. `quiet`: an expected miss that changes no status message or log.
struct PassOutcome {
    result: Result<lan_sync::SyncReport, String>,
    wifi: Option<Result<(), String>>,
    drive: Option<Result<(), String>>,
    quiet: bool,
}

impl PassOutcome {
    fn not_run(result: Result<lan_sync::SyncReport, String>) -> Self {
        PassOutcome { result, wifi: None, drive: None, quiet: true }
    }
}

const DRIVE_NOT_CONNECTED: &str = "Google Drive is not connected on this PC.";

fn sync_summary(report: &lan_sync::SyncReport) -> String {
    match (report.cloud, report.peers_checked) {
        (true, 0) => format!("Synced through Google Drive. Sent {} changes and received {}.", report.sent, report.received),
        (true, devices) => format!("Sent {} changes and received {}, over Wi-Fi ({devices} devices) and Google Drive.", report.sent, report.received),
        (false, _) => format!("Sent {} changes and received {}. Checked {} devices; {} waiting to connect.",
            report.sent, report.received, report.peers_checked, report.peers_waiting),
    }
}

const MAX_FOLLOW_UP_PASSES: usize = 2;
const LEAVE_RETRY_MILLIS: i64 = 5 * 60 * 1000;
const FOLLOW_UP_DEBOUNCE: Duration = Duration::from_secs(2);

/// True when this device recorded a change after a pass started.
fn local_edits_since(state: &ManagedState, revision_at_start: u64) -> bool {
    state
        .lock()
        .ok()
        .and_then(|app| app.unlocked.as_ref().map(UnlockedVault::local_change_count))
        .and_then(Result::ok)
        .is_some_and(|now| u64::from(now) > revision_at_start)
}

fn log_sync_result(result: &Result<lan_sync::SyncReport, String>, manual: bool) {
    match result {
        Ok(report) => {
            if manual || report.sent + report.received > 0 {
                activity::log(
                    Level::Success,
                    Category::Sync,
                    format!("Sync finished: sent {}, received {}", report.sent, report.received),
                );
            }
            if report.conflicts > 0 && (manual || report.received > 0) {
                activity::log(
                    Level::Warning,
                    Category::Sync,
                    format!("{} sync conflict(s) need review", report.conflicts),
                );
            }
        }
        // Errors from lan_sync are fixed, display-safe sentences without peer data or keys.
        Err(error) if error == lan_sync::BUSY => activity::global().record_coalesced(
            Level::Warning, Category::Sync, error.clone(), Duration::from_secs(15)),
        Err(error) if manual => {
            activity::log(Level::Error, Category::Sync, format!("Sync failed: {error}"));
        }
        Err(error) => activity::global().record_coalesced(
            Level::Error,
            Category::Sync,
            format!("Auto-sync failed: {error}"),
            Duration::from_secs(15 * 60),
        ),
    }
}

#[tauri::command]
fn sync_status(state: State<'_, ManagedState>, sync: State<'_, Arc<SyncController>>) -> Result<lan_sync::SyncStatus, String> {
    let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
    let mut status = lan_sync::status(app.unlocked.as_mut().ok_or("Unlock the vault first")?)?;
    drop(app);
    status.running = sync.gate.try_lock().is_err();
    status.message = sync.message.lock().map_err(|_| "Sync status unavailable")?.clone();
    sync.tracker.fill(&mut status);
    Ok(status)
}

#[tauri::command]
fn configure_sync(address: String, automatic: bool, state: State<'_, ManagedState>) -> Result<(), String> {
    let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
    lan_sync::configure(app.unlocked.as_mut().ok_or("Unlock the vault first")?, &address, automatic)?;
    activity::log(
        Level::Info,
        Category::Sync,
        if automatic { "Connection saved. Auto-sync is on" } else { "Connection saved. Auto-sync is off" },
    );
    Ok(())
}

/// Saves how often automatic sync checks Wi-Fi devices and Google Drive (Sync page). A value
/// left out keeps its saved choice.
#[tauri::command]
fn set_sync_schedule(wifi_seconds: Option<u64>, drive_seconds: Option<u64>, state: State<'_, ManagedState>) -> Result<(), String> {
    let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
    let db = app.unlocked.as_mut().ok_or("Unlock the vault first")?.connection();
    let saved = lan_sync::schedule(db);
    lan_sync::set_schedule(db, lan_sync::Schedule {
        wifi_seconds: wifi_seconds.unwrap_or(saved.wifi_seconds),
        drive_seconds: drive_seconds.unwrap_or(saved.drive_seconds),
    })
}

#[tauri::command]
async fn sync_now(address: String, state: State<'_, ManagedState>, pairing: State<'_, Arc<PairingController>>, sync: State<'_, Arc<SyncController>>) -> Result<lan_sync::SyncReport, String> {
    if pairing.is_active()? { return Err("Finish or cancel pairing before syncing".into()); }
    let state = state.inner().clone();
    let helper = pairing.helper_path.clone();
    let sync = sync.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        sync.exchange(&state, &helper, &address, true, Ways::ALL).result
    }).await.map_err(|_| "Sync stopped unexpectedly. Retry to continue.".to_owned())?
}

#[tauri::command]
fn membership_status(state: State<'_, ManagedState>) -> Result<membership_exit::MembershipStatus, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_ref()
        .ok_or("Unlock the vault first")?
        .membership_status()
        .map_err(public_vault_error)
}

/// SPEC3: leave on this PC now and send a signed leave request to the managing phone.
#[tauri::command]
async fn leave_group(
    keep_items: Option<bool>,
    state: State<'_, ManagedState>,
    pairing: State<'_, Arc<PairingController>>,
    sync: State<'_, Arc<SyncController>>,
) -> Result<AppSnapshot, String> {
    if pairing.is_active()? {
        return Err("Finish or cancel pairing before leaving the sync group".to_owned());
    }
    pairing.cancel()?;
    let keep_items = keep_items.unwrap_or(true);
    let state = state.inner().clone();
    let sync = sync.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _gate = sync.gate.lock().map_err(|_| "Sync status unavailable")?;
        let snapshot = {
            let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
            app.unlocked
                .as_mut()
                .ok_or("Unlock the vault first")?
                .leave_group(keep_items)
                .map_err(public_vault_error)?;
            app.snapshot()?
        };
        activity::log(
            Level::Warning,
            Category::Pairing,
            if keep_items { "Left the sync group on this PC. Items stay on this PC" } else { "Left the sync group and emptied this PC's vault" },
        );
        let background = state.clone();
        thread::spawn(move || {
            let _ = lan_sync::deliver_leave(&background, 0);
        });
        Ok(snapshot)
    })
    .await
    .map_err(|_| "Leaving the sync group stopped unexpectedly".to_owned())?
}

#[tauri::command]
fn dismiss_removed_notice(state: State<'_, ManagedState>) -> Result<(), String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_ref()
        .ok_or("Unlock the vault first")?
        .dismiss_removed_notice()
        .map_err(public_vault_error)
}

#[tauri::command]
fn list_conflicts(state: State<'_, ManagedState>) -> Result<Vec<conflicts::SyncConflict>, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_ref()
        .ok_or("Unlock the vault first")?
        .list_conflicts()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn resolve_conflict(id: String, keep: String, state: State<'_, ManagedState>) -> Result<AppSnapshot, String> {
    let keep_remote = match keep.as_str() {
        "remote" => true,
        "local" => false,
        _ => return Err("Choose which version to keep.".into()),
    };
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_mut()
        .ok_or("Unlock the vault first")?
        .resolve_conflict(&id, keep_remote)
        .map_err(|error| error.to_string())?;
    activity::log(
        Level::Success,
        Category::Sync,
        if keep_remote { "Resolved a sync conflict with the other device's version" } else { "Resolved a sync conflict with this PC's version" },
    );
    app.snapshot()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhotoSyncStatus {
    waiting: usize,
    transferred_bytes: u64,
    total_bytes: u64,
}

#[tauri::command]
fn photo_sync_status(state: State<'_, ManagedState>, sync: State<'_, Arc<SyncController>>) -> Result<PhotoSyncStatus, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let waiting = app
        .unlocked
        .as_ref()
        .ok_or("Unlock the vault first")?
        .photos_waiting_for_data()
        .map_err(public_vault_error)?;
    drop(app);
    let (transferred_bytes, total_bytes) = sync.tracker.photo_bytes();
    Ok(PhotoSyncStatus { waiting, transferred_bytes, total_bytes })
}

#[tauri::command]
fn activity_log(limit: Option<usize>) -> Vec<activity::ActivityEvent> {
    activity::global().recent(limit)
}

#[tauri::command]
fn clear_activity_log() {
    activity::global().clear();
}

fn log_browser_connect(result: std::io::Result<browser_setup::ConnectReport>, manual: bool) {
    match &result {
        Ok(report) if report.changed => activity::log(Level::Info, Category::Browser,
            format!("Connected the browser extension for {}. Restart the browser to use it", report.browsers.join(", "))),
        Ok(report) if manual && report.browsers.is_empty() => activity::log(Level::Warning, Category::Browser,
            "No Chrome, Edge or Brave profile was found on this PC"),
        Ok(_) => {}
        Err(error) => activity::diagnostic(Category::Browser, "Could not connect the browser extension", error),
    }
}

/// Settings > Browser extension > Connect browsers.
#[tauri::command]
async fn connect_browsers() -> Result<browser_setup::ConnectReport, String> {
    let result = tauri::async_runtime::spawn_blocking(browser_setup::connect)
        .await
        .map_err(|_| "Couldn't connect the browsers".to_owned())?;
    log_browser_connect(result.as_ref().map(Clone::clone).map_err(|error| std::io::Error::new(error.kind(), error.to_string())), true);
    result.map_err(|error| if error.kind() == std::io::ErrorKind::NotFound {
        "The browser host is missing. Reinstall Nuvori.".to_owned()
    } else {
        "Couldn't write the browser registration. Try again.".to_owned()
    })
}

/// Settings: which build this is and whether Windows can use Nuvori's passkeys.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuildStatus {
    version: String,
    store_build: bool,
    /// Store build only: the installer build is installed too.
    installer_build_installed: bool,
    passkey_provider: passkey_plugin::ProviderState,
}

#[tauri::command]
async fn build_status(app: AppHandle) -> Result<BuildStatus, String> {
    let version = app.package_info().version.to_string();
    tauri::async_runtime::spawn_blocking(move || BuildStatus {
        version,
        store_build: passkey_plugin::packaged(),
        installer_build_installed: store_build::installer_build_installed(),
        passkey_provider: passkey_plugin::provider_state(),
    })
    .await
    .map_err(|_| "Build status is unavailable".to_owned())
}

/// The Windows Settings pages Nuvori links to. Only these two can be opened.
fn windows_settings_uri(page: &str) -> Option<&'static str> {
    match page {
        // Settings > Accounts > Passkeys > Advanced options, where passkey managers are turned on.
        "passkeys" => Some("ms-settings:passkeys-advancedoptions"),
        // Settings > Apps > Installed apps.
        "apps" => Some("ms-settings:appsfeatures"),
        _ => None,
    }
}

/// Opens an address with its default program (a settings page, or a web page in the browser).
fn open_address(address: &str) -> bool {
    use windows::{Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL}, core::{HSTRING, PCWSTR, w}};
    let result = unsafe { ShellExecuteW(None, w!("open"), &HSTRING::from(address), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
    // ShellExecute reports success with a value above 32.
    result.0 as usize > 32
}

#[tauri::command]
fn open_windows_settings(page: String) -> Result<(), String> {
    let uri = windows_settings_uri(&page).ok_or_else(|| "Unknown settings page".to_owned())?;
    if open_address(uri) { Ok(()) } else { Err("Couldn't open Windows Settings.".to_owned()) }
}

/// The cloud card on the Sync page.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CloudStatus {
    /// False when this build has no Google sign-in configured.
    available: bool,
    connected: bool,
    /// The Google account's email address; empty when not connected.
    account: String,
    /// RFC 3339 time of the last finished cloud pass, or empty.
    last_sync: String,
    last_error: String,
    connecting: bool,
    needs_sign_in: bool,
    /// How often automatic sync checks Google Drive; 0 = only on Sync now.
    check_seconds: u64,
}

fn read_cloud_status(state: &ManagedState, sync: &SyncController) -> Result<CloudStatus, String> {
    use std::sync::atomic::Ordering;
    let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
    let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
    let account = lan_sync::cloud::account(vault.connection());
    Ok(CloudStatus {
        available: google_drive::client().is_some(),
        connected: account.is_some(),
        account: account.map(|account| account.account).unwrap_or_default(),
        last_sync: lan_sync::cloud::last_sync(vault.connection()),
        last_error: sync.cloud.last_error.lock().map(|error| error.clone()).unwrap_or_default(),
        connecting: sync.cloud.connecting.load(Ordering::SeqCst),
        needs_sign_in: sync.cloud.needs_sign_in.load(Ordering::SeqCst),
        check_seconds: lan_sync::schedule(vault.connection()).drive_seconds,
    })
}

#[tauri::command]
fn cloud_status(state: State<'_, ManagedState>, sync: State<'_, Arc<SyncController>>) -> Result<CloudStatus, String> {
    read_cloud_status(state.inner(), sync.inner())
}

/// Opens Google's sign-in in the browser and waits for it. Returns the new status; it is still
/// "not connected" when the user cancels or closes the browser tab.
#[tauri::command]
async fn cloud_connect(state: State<'_, ManagedState>, pairing: State<'_, Arc<PairingController>>,
    sync: State<'_, Arc<SyncController>>) -> Result<CloudStatus, String> {
    use std::sync::atomic::Ordering;
    if google_drive::client().is_none() {
        return Err("Google Drive sync is not set up in this build of Nuvori.".into());
    }
    {
        let app = state.lock().map_err(|_| "Vault state unavailable")?;
        let vault = app.unlocked.as_ref().ok_or("Unlock the vault first")?;
        if !vault.is_enrolled().map_err(public_vault_error)? {
            return Err("Pair this PC with your phone first. Google Drive then keeps them in sync when they are apart.".into());
        }
    }
    if sync.cloud.connecting.swap(true, Ordering::SeqCst) {
        return Err("Finish the Google sign-in in your browser, or cancel it.".into());
    }
    sync.cloud.cancel.store(false, Ordering::SeqCst);
    let (state, sync, helper) = (state.inner().clone(), sync.inner().clone(), pairing.helper_path.clone());
    tauri::async_runtime::spawn_blocking(move || {
        let signed_in = google_drive::sign_in(&sync.cloud.cancel, open_address);
        sync.cloud.connecting.store(false, Ordering::SeqCst);
        let signed_in = signed_in.map_err(|error| match error {
            lan_sync::cloud::CloudError::Offline => "Can't reach Google. Check the internet connection.".to_owned(),
            error => {
                activity::diagnostic(Category::Sync, "Google sign-in failed", format!("{error:?}"));
                "Google sign-in didn't finish. Try again.".to_owned()
            }
        })?;
        if let Some(signed_in) = signed_in {
            {
                let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
                let vault = app.unlocked.as_mut().ok_or("The vault locked during sign-in. Unlock it and connect again.")?;
                lan_sync::cloud::save_account(vault.connection(), &signed_in.account, &signed_in.refresh_token)?;
            }
            sync.cloud.reset();
            // The address is the user's own account; it is shown in the app anyway.
            activity::log(Level::Success, Category::Sync, "Google Drive connected. Changes now also sync through your Drive");
            // First upload right away, so the other devices find this PC's changes.
            let (state, sync) = (state.clone(), sync.clone());
            thread::spawn(move || { let _ = sync.exchange(&state, &helper, "", false, Ways::DRIVE); });
        }
        read_cloud_status(&state, &sync)
    })
    .await
    .map_err(|_| "Google sign-in stopped unexpectedly. Try again.".to_owned())?
}

#[tauri::command]
fn cloud_cancel_connect(sync: State<'_, Arc<SyncController>>) {
    sync.cloud.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Signs this PC out of Google Drive. The encrypted files in the Drive stay for the other devices.
#[tauri::command]
fn cloud_disconnect(state: State<'_, ManagedState>, sync: State<'_, Arc<SyncController>>) -> Result<CloudStatus, String> {
    let removed = {
        let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
        let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
        lan_sync::cloud::remove_account(vault.connection())?
    };
    sync.cloud.reset();
    if let Some(account) = removed {
        activity::log(Level::Info, Category::Sync, "Google Drive disconnected on this PC");
        thread::spawn(move || google_drive::revoke(&account.refresh_token));
    }
    read_cloud_status(state.inner(), sync.inner())
}

#[tauri::command]
async fn browser_status(browser: State<'_, Arc<BrowserIpcServer>>) -> Result<BrowserStatus, String> {
    let browser = browser.inner().clone();
    tauri::async_runtime::spawn_blocking(move || browser.status())
        .await
        .map_err(|_| "Browser status is unavailable".to_owned())
}

fn retry_label(delay: Duration) -> String {
    let seconds = delay.as_secs().max(1);
    if seconds < 90 {
        format!("{seconds} s")
    } else {
        format!("{} min", seconds.div_ceil(60))
    }
}

/// The automatic loop's state for one way (Wi-Fi or Google Drive). Each way has its own
/// interval and its own retry delay, so a phone away from this Wi-Fi does not slow down Drive.
#[derive(Default)]
struct WayClock {
    /// The address and change revision of the last attempt; a new value means something changed.
    seen: Option<(String, u64)>,
    last: Option<Instant>,
    retry_at: Option<Instant>,
    failures: u32,
}

impl WayClock {
    /// Due after `every` (`None`: never by time), 2 s after a change, at once the first time,
    /// or after a failure only at its retry deadline.
    fn due(&self, seen: &(String, u64), every: Option<Duration>, now: Instant) -> bool {
        if let Some(at) = self.retry_at { return now >= at; }
        let Some(last) = self.last else { return true };
        let elapsed = now.saturating_duration_since(last);
        (self.seen.as_ref() != Some(seen) && elapsed >= FOLLOW_UP_DEBOUNCE) || every.is_some_and(|every| elapsed >= every)
    }

    fn start(&mut self, seen: &(String, u64), now: Instant) {
        self.seen = Some(seen.clone());
        self.last = Some(now);
    }

    /// Records a result; returns the retry delay after a failure.
    fn finish(&mut self, result: &Result<(), String>, now: Instant) -> Option<Duration> {
        match result {
            Ok(()) => { self.failures = 0; self.retry_at = None; None }
            Err(error) => {
                self.failures = self.failures.saturating_add(1);
                let delay = if error == lan_sync::BUSY {
                    Duration::from_millis(5_000 + u64::from(lan_sync::random_jitter()) % 5_000)
                } else { lan_sync::retry_delay(self.failures, lan_sync::random_jitter()) };
                self.retry_at = Some(now + delay);
                Some(delay)
            }
        }
    }
}

#[test]
fn each_way_keeps_its_own_interval_and_retry_delay() {
    let start = Instant::now();
    let seen = (String::new(), 7);
    let mut drive = WayClock::default();
    assert!(drive.due(&seen, Some(Duration::from_secs(15)), start), "the first check runs at once");
    drive.start(&seen, start);
    assert!(!drive.due(&seen, Some(Duration::from_secs(15)), start + Duration::from_secs(14)));
    assert!(drive.due(&seen, Some(Duration::from_secs(15)), start + Duration::from_secs(15)));
    // A change runs a pass 2 s later, also when Drive checks only on Sync now.
    let changed = (String::new(), 8);
    assert!(!drive.due(&changed, None, start + Duration::from_secs(1)));
    assert!(drive.due(&changed, None, start + Duration::from_secs(2)));
    assert!(!drive.due(&seen, None, start + Duration::from_secs(3600)), "no change, no time interval: no check");
    // A failure waits for its retry deadline, whatever the interval says.
    let delay = drive.finish(&Err(lan_sync::TIMED_OUT.into()), start).unwrap();
    assert!(delay >= Duration::from_secs(12));
    assert!(!drive.due(&changed, Some(Duration::from_secs(15)), start + Duration::from_secs(11)));
    assert!(drive.due(&seen, Some(Duration::from_secs(15)), start + delay));
    assert_eq!(drive.finish(&Ok(()), start + delay), None);
    assert_eq!((drive.failures, drive.retry_at), (0, None));
    assert_eq!(retry_label(Duration::from_secs(15)), "15 s");
    assert_eq!(retry_label(Duration::from_secs(240)), "4 min");
}

/// Advertise and accept only while this vault is unlocked and automatic sync is enabled.
fn start_lan_listener(state: ManagedState, pairing: Arc<PairingController>, sync: Arc<SyncController>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(500));
        let vault_id = (|| {
            let mut app = state.lock().ok()?;
            let vault = app.unlocked.as_mut()?;
            if !vault.is_enrolled().ok()? || !lan_sync::configuration(vault).ok()?.1 { return None; }
            vault.connection().query_row("SELECT vault_id FROM sync_group_state", [], |row| row.get::<_, String>(0)).ok()
        })();
        let stream = {
            let Ok(mut network) = sync.discovery.lock() else { continue; };
            if network.is_none() { *network = discovery::LanDiscovery::new().ok(); }
            let Some(network) = network.as_mut() else { continue; };
            if network.advertise(vault_id.as_deref()).is_err() { continue; }
            network.endpoints();
            network.accept()
        };
        let Some(stream) = stream else { continue; };
        if pairing.is_active().unwrap_or(true) || sync.gate.try_lock().is_err() { lan_sync::reply_busy(stream); continue; }
        // The session runs on its own thread so this loop keeps accepting: a second device that
        // connects meanwhile gets a busy reply at once instead of waiting for its timeout.
        let (state, pairing, sync) = (state.clone(), pairing.clone(), sync.clone());
        thread::spawn(move || {
            let Ok(_guard) = sync.gate.try_lock() else { lan_sync::reply_busy(stream); return; };
            if let Ok(report) = lan_sync::serve(&state, &pairing.helper_path, stream, &sync.tracker) {
                if let Ok(mut message) = sync.message.lock() {
                    *message = format!("Sent {} changes and received {} from a paired device.", report.sent, report.received);
                }
                log_sync_result(&Ok(report), false);
            }
        });
    });
}

/// Uploads the Google Drive copy of a pending leave request (see `cloud_sync::save_pending_leave`).
fn upload_drive_leave(state: &ManagedState) {
    if google_drive::client().is_none() { return; }
    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let pending = state.lock().ok().and_then(|mut app| {
        app.unlocked.as_mut().and_then(|vault| lan_sync::cloud::pending_leave_upload(vault.connection(), now as i64))
    });
    let Some((name, sealed, account)) = pending else { return };
    let mut drive = google_drive::GoogleDrive::new(account.refresh_token.clone());
    if lan_sync::cloud::upload_sealed(&mut drive, &name, &sealed).is_ok()
        && let Ok(mut app) = state.lock()
        && let Some(vault) = app.unlocked.as_mut() {
        lan_sync::cloud::finish_pending_leave(vault.connection());
        activity::log(Level::Info, Category::Sync, "The leave request was also sent through Google Drive");
    }
}

/// What the automatic loop reads from the unlocked vault on each tick.
struct LoopPlan {
    seen: (String, u64),
    automatic: bool,
    drive: bool,
    schedule: lan_sync::Schedule,
}

fn start_background_sync(state: ManagedState, pairing: Arc<PairingController>, sync: Arc<SyncController>) {
    thread::spawn(move || {
        let (mut wifi, mut drive) = (WayClock::default(), WayClock::default());
        loop {
            thread::sleep(Duration::from_secs(2));
            if pairing.is_active().unwrap_or(true) { continue; }
            // A queued leave request is retried every 5 minutes for up to 30 days, over Wi-Fi and
            // through Google Drive.
            if sync.gate.try_lock().is_ok() {
                let _ = lan_sync::deliver_leave(&state, LEAVE_RETRY_MILLIS);
                upload_drive_leave(&state);
            }
            let plan = (|| {
                let mut app = state.lock().ok()?;
                let vault = app.unlocked.as_mut()?;
                if !vault.is_enrolled().ok()? { return None; }
                let revision = vault.change_revision().ok()?;
                let (address, automatic) = lan_sync::configuration(vault).ok()?;
                let schedule = lan_sync::schedule(vault.connection());
                let drive = google_drive::client().is_some() && lan_sync::cloud::account(vault.connection()).is_some();
                Some(LoopPlan { seen: (address, revision), automatic, drive, schedule })
            })();
            let Some(plan) = plan else {
                if wifi.retry_at.is_some() { sync.tracker.schedule_retry(None); }
                (wifi, drive) = (WayClock::default(), WayClock::default());
                continue;
            };
            // Wi-Fi sync switched off, or Google Drive disconnected: that way starts fresh later.
            if !plan.automatic {
                if wifi.retry_at.is_some() { sync.tracker.schedule_retry(None); }
                wifi = WayClock::default();
            }
            if !plan.drive { drive = WayClock::default(); }
            // A successful pass of any kind (also Sync now) ends the Wi-Fi retry delay early.
            if wifi.retry_at.is_some() && sync.tracker.consecutive_failures() == 0 && !sync.tracker.peer_busy() {
                wifi.retry_at = None;
                wifi.failures = 0;
            }
            let now = Instant::now();
            let ways = Ways {
                wifi: plan.automatic && wifi.due(&plan.seen, Some(Duration::from_secs(plan.schedule.wifi_seconds)), now),
                drive: plan.drive && drive.due(&plan.seen, (plan.schedule.drive_seconds > 0)
                    .then(|| Duration::from_secs(plan.schedule.drive_seconds)), now),
            };
            if !ways.wifi && !ways.drive { continue; }
            if sync.gate.try_lock().is_err() { continue; }
            if ways.wifi { wifi.start(&plan.seen, now); }
            if ways.drive { drive.start(&plan.seen, now); }
            let outcome = sync.exchange(&state, &pairing.helper_path, &plan.seen.0, false, ways);
            let finished = Instant::now();
            if let Some(result) = &outcome.drive {
                drive.finish(result, finished);
            }
            if let Some(result) = &outcome.wifi {
                let delay = wifi.finish(result, finished);
                // A quiet miss (no device on this Wi-Fi while Drive works) backs off silently.
                if let (Some(delay), false) = (delay, outcome.quiet) {
                    sync.tracker.schedule_retry(wifi.retry_at);
                    activity::global().record_coalesced(
                        Level::Warning,
                        Category::Sync,
                        format!("Auto-sync will retry in {} (attempt {})", retry_label(delay), wifi.failures),
                        Duration::from_secs(1),
                    );
                }
            }
        }
    });
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingStatus {
    stage: String,
    confirmation: String,
    message: String,
    invitation: String,
}

#[derive(Default)]
struct PairingProgress {
    status: PairingStatus,
    active: bool,
    approved: bool,
    canceled: bool,
    socket: Option<TcpStream>,
}

struct PairingController {
    progress: Mutex<PairingProgress>,
    approval: Condvar,
    helper_path: PathBuf,
}

impl PairingController {
    fn begin(&self) -> Result<(), String> {
        let mut progress = self.progress.lock().map_err(|_| "Pairing is unavailable")?;
        if progress.active {
            return Err("A pairing attempt is already running".to_owned());
        }
        *progress = PairingProgress {
            status: PairingStatus {
                stage: "connecting".to_owned(),
                message: "Connecting to the phone on this Wi-Fi network".to_owned(),
                ..Default::default()
            },
            active: true,
            ..Default::default()
        };
        Ok(())
    }

    fn begin_reverse(&self, invitation: &str) -> Result<(), String> {
        self.begin()?;
        self.set_stage(
            "offering",
            "Scan this QR on the managing Android phone within two minutes.",
            "",
        )?;
        self.progress
            .lock()
            .map_err(|_| "Pairing is unavailable")?
            .status
            .invitation = invitation.to_owned();
        Ok(())
    }

    fn is_canceled(&self) -> bool {
        self.progress
            .lock()
            .map_or(true, |progress| progress.canceled)
    }

    fn is_active(&self) -> Result<bool, String> {
        Ok(self
            .progress
            .lock()
            .map_err(|_| "Pairing is unavailable")?
            .active)
    }

    fn status(&self) -> Result<PairingStatus, String> {
        Ok(self
            .progress
            .lock()
            .map_err(|_| "Pairing is unavailable")?
            .status
            .clone())
    }

    fn attach_socket(&self, socket: &TcpStream) -> std::io::Result<()> {
        let mut progress = self
            .progress
            .lock()
            .map_err(|_| std::io::Error::other("pairing state is unavailable"))?;
        if progress.canceled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "pairing canceled",
            ));
        }
        progress.socket = Some(socket.try_clone()?);
        Ok(())
    }

    fn set_stage(&self, stage: &str, message: &str, confirmation: &str) -> Result<(), String> {
        let mut progress = self.progress.lock().map_err(|_| "Pairing is unavailable")?;
        if progress.canceled {
            return Err("Pairing canceled".to_owned());
        }
        if progress.status.stage != stage {
            log_pairing_stage(stage);
        }
        progress.status = PairingStatus {
            stage: stage.to_owned(),
            message: message.to_owned(),
            confirmation: confirmation.to_owned(),
            invitation: String::new(),
        };
        Ok(())
    }

    fn wait_for_approval(&self) -> Result<(), String> {
        let progress = self.progress.lock().map_err(|_| "Pairing is unavailable")?;
        let (progress, _) = self
            .approval
            .wait_timeout_while(progress, enrollment::CONFIRMATION_TIMEOUT, |state| {
                !state.approved && !state.canceled
            })
            .map_err(|_| "Pairing is unavailable")?;
        if progress.canceled {
            Err("Pairing canceled".to_owned())
        } else if !progress.approved {
            Err("Confirmation expired. Create a new QR and confirm on both devices within two minutes.".to_owned())
        } else {
            Ok(())
        }
    }

    fn approve(&self) -> Result<(), String> {
        let mut progress = self.progress.lock().map_err(|_| "Pairing is unavailable")?;
        if progress.status.stage != "confirm" || !progress.active {
            return Err("There is no code to confirm".to_owned());
        }
        progress.approved = true;
        activity::log(Level::Info, Category::Pairing, "Pairing code confirmed on this PC");
        progress.status.stage = "transferring".to_owned();
        progress.status.message = "Waiting for the phone to confirm the same code".to_owned();
        self.approval.notify_all();
        Ok(())
    }

    fn cancel(&self) -> Result<(), String> {
        let mut progress = self.progress.lock().map_err(|_| "Pairing is unavailable")?;
        if progress.active && !progress.canceled {
            activity::log(Level::Warning, Category::Pairing, "Pairing canceled");
        }
        progress.canceled = true;
        if let Some(socket) = progress.socket.take() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        progress.status = if progress.active {
            PairingStatus {
                stage: "canceling".to_owned(),
                message: "Stopping pairing".to_owned(),
                ..Default::default()
            }
        } else {
            PairingStatus::default()
        };
        self.approval.notify_all();
        Ok(())
    }

    fn finish(&self, result: Result<bool, String>) {
        if let Ok(mut progress) = self.progress.lock() {
            let canceled = progress.canceled;
            let failed_stage = progress.status.stage.clone();
            match &result {
                Ok(true) => activity::log(Level::Success, Category::Pairing, "Paired with the phone"),
                Ok(false) => activity::log(Level::Warning, Category::Pairing, "Paired, but the phone may not have confirmed"),
                Err(_) if canceled => {}
                // The detailed reason stays on the pairing screen; it can include network text.
                Err(_) => activity::log(Level::Error, Category::Pairing, format!("Pairing failed during {}", pairing_stage_label(&failed_stage))),
            }
            progress.active = false;
            progress.socket = None;
            progress.status = if canceled && result.is_err() {
                PairingStatus::default()
            } else if let Err(message) = result {
                PairingStatus {
                    stage: "failed".to_owned(),
                    message,
                    ..Default::default()
                }
            } else {
                PairingStatus {
                    stage: "paired".to_owned(),
                    message: if result == Ok(true) {
                        "Vault copied. Windows and Android now keep their own local copies."
                    } else {
                        "Vault copied, but the phone may not have received final confirmation. Check its pairing status."
                    }.to_owned(),
                    ..Default::default()
                }
            };
        }
    }
}

fn pairing_stage_label(stage: &str) -> &'static str {
    match stage {
        "connecting" => "connection",
        "offering" => "the QR step",
        "confirm" => "code confirmation",
        "transferring" => "the vault copy",
        _ => "setup",
    }
}

fn log_pairing_stage(stage: &str) {
    let message = match stage {
        "connecting" => "Pairing: connecting to the phone",
        "offering" => "Pairing: showing a QR for the phone",
        "confirm" => "Pairing: compare the code on both devices",
        "transferring" => "Pairing: receiving the encrypted vault copy",
        _ => return,
    };
    activity::log(Level::Progress, Category::Pairing, message);
}

fn join_android(
    state: ManagedState,
    controller: &PairingController,
    link: &str,
    password: &str,
) -> Result<bool, String> {
    let invitation = PairingInvitation::parse(link).map_err(|error| error.to_string())?;
    controller.set_stage(
        "connecting",
        &format!("Connecting to Android at {}", invitation.address()),
        "",
    )?;
    let identity_store = {
        let app = state.lock().map_err(|_| "Vault state is unavailable")?;
        app.store.identity_store()
    };
    let mut session = JoinSession::connect(
        invitation,
        password,
        &controller.helper_path,
        &identity_store,
        |socket| controller.attach_socket(socket),
    )
    .map_err(|error| error.to_string())?;
    finish_join(state, controller, &identity_store, &mut session)
}

fn join_reverse(
    state: ManagedState,
    controller: &PairingController,
    offer: ReverseOffer,
    password: &str,
) -> Result<bool, String> {
    let stream = offer
        .accept(|| controller.is_canceled())
        .map_err(|error| error.to_string())?;
    controller
        .attach_socket(&stream)
        .map_err(|error| error.to_string())?;
    controller.set_stage("connecting", "Checking the Android pairing request", "")?;
    let identity_store = {
        let app = state.lock().map_err(|_| "Vault state is unavailable")?;
        app.store.identity_store()
    };
    let mut session = JoinSession::accept(
        stream,
        &offer,
        password,
        &controller.helper_path,
        &identity_store,
    )
    .map_err(|error| error.to_string())?;
    finish_join(state, controller, &identity_store, &mut session)
}

fn finish_join(
    state: ManagedState,
    controller: &PairingController,
    identity_store: &DeviceIdentityStore,
    session: &mut JoinSession,
) -> Result<bool, String> {
    controller.set_stage(
        "confirm",
        "Compare this code with the one on your phone. Confirm on both devices within two minutes.",
        session.confirmation(),
    )?;
    controller.wait_for_approval()?;
    session.approve().map_err(|error| error.to_string())?;
    controller.set_stage("transferring", "Receiving the encrypted vault copy", "")?;
    let prepared = session.prepare().map_err(|error| error.to_string())?;
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let vault = app
        .unlocked
        .as_mut()
        .ok_or("Unlock the Windows vault before pairing")?;
    session
        .commit(prepared, vault, identity_store)
        .map_err(|error| error.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Counts {
    cards: u32,
    logins: u32,
    codes: u32,
    notes: u32,
    questions: u32,
    autofill: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppSnapshot {
    vault_state: &'static str,
    hello_enabled: bool,
    counts: Counts,
    paired_devices: u32,
    enrolled: bool,
    pending_changes: u32,
    revision: u64,
    chain_state: &'static str,
}

impl AppState {
    fn snapshot(&self) -> Result<AppSnapshot, String> {
        let local_changes = self
            .unlocked
            .as_ref()
            .map_or(Ok(0), UnlockedVault::local_change_count)
            .map_err(public_vault_error)?;
        let entry_counts = self
            .unlocked
            .as_ref()
            .map_or(Ok(Default::default()), UnlockedVault::entry_counts)
            .map_err(public_vault_error)?;
        Ok(AppSnapshot {
            vault_state: if self.unlocked.is_some() {
                "unlocked"
            } else if self.store.is_initialized() {
                "locked"
            } else {
                "notConfigured"
            },
            hello_enabled: self.store.hello_enabled(),
            counts: Counts {
                cards: *entry_counts.get("CARD").unwrap_or(&0),
                logins: *entry_counts.get("PASSWORD").unwrap_or(&0),
                codes: *entry_counts.get("AUTHENTICATOR").unwrap_or(&0),
                notes: self
                    .unlocked
                    .as_ref()
                    .map_or(Ok(0), UnlockedVault::note_count)
                    .map_err(public_vault_error)?,
                questions: *entry_counts.get("QUESTION").unwrap_or(&0),
                autofill: *entry_counts.get("AUTOFILL").unwrap_or(&0),
            },
            paired_devices: self
                .unlocked
                .as_ref()
                .map_or(Ok(0), UnlockedVault::paired_device_count)
                .map_err(public_vault_error)?,
            enrolled: self
                .unlocked
                .as_ref()
                .map_or(Ok(false), UnlockedVault::is_enrolled)
                .map_err(public_vault_error)?,
            pending_changes: local_changes,
            revision: self.unlocked.as_ref().map_or(Ok(0), UnlockedVault::change_revision).map_err(public_vault_error)?,
            chain_state: if local_changes == 0 {
                "empty"
            } else {
                "recorded"
            },
        })
    }
}

#[tauri::command]
fn app_snapshot(state: State<'_, ManagedState>) -> Result<AppSnapshot, String> {
    state
        .lock()
        .map_err(|_| "Vault state is unavailable")?
        .snapshot()
}

#[tauri::command]
fn pairing_status(controller: State<'_, Arc<PairingController>>) -> Result<PairingStatus, String> {
    controller.status()
}

#[tauri::command]
fn start_pairing(
    setup_link: String,
    master_password: String,
    state: State<'_, ManagedState>,
    controller: State<'_, Arc<PairingController>>,
) -> Result<(), String> {
    ensure_pairing_ready(state.inner(), controller.inner())?;
    controller.begin()?;
    activity::log(Level::Progress, Category::Pairing, "Pairing started with a phone setup link");
    let app = state.inner().clone();
    let controller = controller.inner().clone();
    thread::spawn(move || {
        let link = Zeroizing::new(setup_link);
        let password = Zeroizing::new(master_password);
        let result = join_android(app, &controller, &link, &password);
        controller.finish(result);
    });
    Ok(())
}

fn ensure_pairing_ready(
    state: &ManagedState,
    controller: &PairingController,
) -> Result<(), String> {
    {
        let app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app
            .unlocked
            .as_ref()
            .ok_or("Unlock the Windows vault before pairing")?;
        if vault.is_enrolled().map_err(public_vault_error)? {
            return Err("This Windows vault is already paired".to_owned());
        }
    }
    if !controller.helper_path.is_file() {
        return Err(
            "The Windows pairing helper is missing. Rebuild or reinstall Nuvori.".to_owned(),
        );
    }
    Ok(())
}

#[tauri::command]
fn start_reverse_pairing(
    master_password: String,
    state: State<'_, ManagedState>,
    controller: State<'_, Arc<PairingController>>,
) -> Result<(), String> {
    ensure_pairing_ready(state.inner(), controller.inner())?;
    if master_password.chars().count() < 12 {
        return Err("Enter the Android vault's master password first".to_owned());
    }
    let offer = ReverseOffer::bind().map_err(|error| error.to_string())?;
    controller.begin_reverse(offer.link())?;
    activity::log(Level::Progress, Category::Pairing, "Pairing started from this PC");
    let app = state.inner().clone();
    let controller = controller.inner().clone();
    thread::spawn(move || {
        let password = Zeroizing::new(master_password);
        let result = join_reverse(app, &controller, offer, &password);
        controller.finish(result);
    });
    Ok(())
}

#[tauri::command]
fn approve_pairing(controller: State<'_, Arc<PairingController>>) -> Result<(), String> {
    controller.approve()
}

#[tauri::command]
fn cancel_pairing(controller: State<'_, Arc<PairingController>>) -> Result<(), String> {
    controller.cancel()
}

#[tauri::command]
async fn create_vault(
    password: String,
    app_handle: AppHandle,
    state: State<'_, ManagedState>,
    browser: State<'_, Arc<BrowserIpcServer>>,
) -> Result<AppSnapshot, String> {
    let state = state.inner().clone();
    let browser = browser.inner().clone();
    let snapshot = tauri::async_runtime::spawn_blocking(move || -> Result<AppSnapshot, String> {
        let mut password = password;
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let result = app.store.create(&password);
        password.zeroize();
        app.unlocked = Some(result.map_err(public_vault_error)?);
        let snapshot = app.snapshot()?;
        drop(app);
        browser.set_provider(Some(Arc::new(VaultBrowserProvider { state })));
        activity::log(Level::Success, Category::Vault, "Vault created");
        Ok(snapshot)
    })
    .await
    .map_err(|_| "Vault setup stopped unexpectedly".to_owned())??;
    vault_changed(&app_handle, true);
    Ok(snapshot)
}

#[tauri::command]
async fn unlock_vault(
    password: String,
    app_handle: AppHandle,
    state: State<'_, ManagedState>,
    browser: State<'_, Arc<BrowserIpcServer>>,
) -> Result<AppSnapshot, String> {
    let state = state.inner().clone();
    let browser = browser.inner().clone();
    let snapshot = tauri::async_runtime::spawn_blocking(move || -> Result<AppSnapshot, String> {
        let mut password = password;
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let result = app.store.unlock(&password);
        password.zeroize();
        let vault = result.map_err(|error| {
            activity::log(Level::Warning, Category::Security, "Unlock failed");
            public_vault_error(error)
        })?;
        app.unlocked = Some(vault);
        let snapshot = app.snapshot()?;
        drop(app);
        browser.set_provider(Some(Arc::new(VaultBrowserProvider { state })));
        activity::log(Level::Success, Category::Vault, "Vault unlocked");
        Ok(snapshot)
    })
    .await
    .map_err(|_| "Vault unlock stopped unexpectedly".to_owned())??;
    vault_changed(&app_handle, true);
    Ok(snapshot)
}

#[tauri::command]
async fn hello_available() -> bool {
    tauri::async_runtime::spawn_blocking(hello::available)
        .await
        .unwrap_or(false)
}

#[tauri::command]
async fn enable_hello(
    password: String,
    window: tauri::WebviewWindow,
    state: State<'_, ManagedState>,
) -> Result<AppSnapshot, String> {
    let hwnd = window
        .hwnd()
        .map_err(|_| "Windows Hello needs an app window")?
        .0 as isize;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut password = Zeroizing::new(password);
        {
            let app = state.lock().map_err(|_| "Vault state is unavailable")?;
            if app.unlocked.is_none() {
                return Err("Unlock the vault first".to_owned());
            }
            app.store
                .verify_password(&password)
                .map_err(public_vault_error)?;
        }
        password.zeroize();
        hello::verify(windows::Win32::Foundation::HWND(hwnd as *mut _))?;
        let app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app.unlocked.as_ref().ok_or("Unlock the vault first")?;
        app.store
            .enable_hello(vault.key_for_hello())
            .map_err(public_vault_error)?;
        activity::log(Level::Success, Category::Security, "Windows Hello unlock turned on");
        app.snapshot()
    })
    .await
    .map_err(|_| "Windows Hello setup stopped unexpectedly".to_owned())?
}

#[tauri::command]
async fn unlock_hello(
    window: tauri::WebviewWindow,
    app_handle: AppHandle,
    state: State<'_, ManagedState>,
    browser: State<'_, Arc<BrowserIpcServer>>,
) -> Result<AppSnapshot, String> {
    let hwnd = window
        .hwnd()
        .map_err(|_| "Windows Hello needs an app window")?
        .0 as isize;
    let state = state.inner().clone();
    let browser = browser.inner().clone();
    let snapshot = tauri::async_runtime::spawn_blocking(move || -> Result<AppSnapshot, String> {
        {
            let app = state.lock().map_err(|_| "Vault state is unavailable")?;
            if !app.store.hello_enabled() {
                return Err(
                    "Set up Windows Hello after unlocking with your master password".to_owned(),
                );
            }
        }
        hello::verify(windows::Win32::Foundation::HWND(hwnd as *mut _)).inspect_err(|_| {
            activity::log(Level::Warning, Category::Security, "Windows Hello unlock failed");
        })?;
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app.store.unlock_hello().map_err(|error| {
            activity::log(Level::Warning, Category::Security, "Windows Hello unlock failed");
            public_vault_error(error)
        })?;
        app.unlocked = Some(vault);
        let snapshot = app.snapshot()?;
        drop(app);
        browser.set_provider(Some(Arc::new(VaultBrowserProvider { state })));
        activity::log(Level::Success, Category::Vault, "Vault unlocked with Windows Hello");
        Ok(snapshot)
    })
    .await
    .map_err(|_| "Windows Hello unlock stopped unexpectedly".to_owned())??;
    vault_changed(&app_handle, true);
    Ok(snapshot)
}

#[tauri::command]
fn disable_hello(state: State<'_, ManagedState>) -> Result<AppSnapshot, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    if app.unlocked.is_none() {
        return Err("Unlock the vault first".to_owned());
    }
    app.store.disable_hello().map_err(public_vault_error)?;
    activity::log(Level::Info, Category::Security, "Windows Hello unlock turned off");
    app.snapshot()
}

#[tauri::command]
fn lock_vault(
    app_handle: AppHandle,
    state: State<'_, ManagedState>,
    browser: State<'_, Arc<BrowserIpcServer>>,
    pairing: State<'_, Arc<PairingController>>,
) -> Result<AppSnapshot, String> {
    let snapshot = lock(&state, &browser, &pairing)?;
    vault_changed(&app_handle, false);
    Ok(snapshot)
}

fn lock(state: &ManagedState, browser: &BrowserIpcServer, pairing: &PairingController) -> Result<AppSnapshot, String> {
    pairing.cancel()?;
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let was_unlocked = app.unlocked.take().is_some();
    let snapshot = app.snapshot();
    drop(app);
    browser.set_provider(None);
    if was_unlocked {
        activity::log(Level::Info, Category::Vault, "Vault locked");
    }
    snapshot
}

/// Tray "Lock vault". Runs off the UI thread because a sync may hold the vault for a moment.
fn lock_from_tray(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let locked = lock(
            app.state::<ManagedState>().inner(),
            app.state::<Arc<BrowserIpcServer>>().inner(),
            app.state::<Arc<PairingController>>().inner(),
        );
        if locked.is_ok() {
            vault_changed(&app, false);
        }
    });
}

/// Tells every window that the vault opened or closed. An unlock from any window also closes the
/// small unlock window.
fn vault_changed(app: &AppHandle, unlocked: bool) {
    if unlocked {
        desktop::close_unlock_prompt(app);
    }
    let _ = app.emit("vault-changed", ());
}

fn vault_configured(app: &AppHandle) -> bool {
    // A busy vault is configured; only a fresh install needs the full setup window.
    app.state::<ManagedState>()
        .try_lock()
        .map_or(true, |state| state.store.is_initialized())
}

/// A card security code waiting for approval, as the approval window shows it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CardCodeRequest {
    id: String,
    title: String,
    card: String,
    site: String,
    hello_available: bool,
}

#[tauri::command]
async fn pending_card_code(
    state: State<'_, ManagedState>,
    browser: State<'_, Arc<BrowserIpcServer>>,
) -> Result<Option<CardCodeRequest>, String> {
    let Some((id, card_id, origin)) = browser.waiting_card_code() else { return Ok(None) };
    let (title, card) = {
        let app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app.unlocked.as_ref().ok_or("Unlock the vault first")?;
        vault.browser_cards().map_err(public_vault_error)?.into_iter()
            .find(|card| card.0 == card_id).map(|card| (card.1, card.2)).unwrap_or_default()
    };
    let site = url::Url::parse(&origin).ok().and_then(|url| url.host_str().map(str::to_owned)).unwrap_or(origin);
    let hello_available = tauri::async_runtime::spawn_blocking(hello::available).await.unwrap_or(false);
    Ok(Some(CardCodeRequest { id, title, card, site, hello_available }))
}

/// Approve with Windows Hello (no password) or the master password, then fill the code.
#[tauri::command]
async fn approve_card_code(
    id: String,
    password: Option<String>,
    window: tauri::WebviewWindow,
    app_handle: AppHandle,
    state: State<'_, ManagedState>,
    browser: State<'_, Arc<BrowserIpcServer>>,
) -> Result<(), String> {
    let hwnd = window.hwnd().map_err(|_| "Windows Hello needs an app window")?.0 as isize;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        match password {
            Some(password) => {
                let password = Zeroizing::new(password);
                let app = state.lock().map_err(|_| "Vault state is unavailable")?;
                app.store.verify_password(&password).map_err(|error| {
                    activity::log(Level::Warning, Category::Security, "Card security code approval failed");
                    public_vault_error(error)
                })
            }
            None => hello::verify_for(windows::Win32::Foundation::HWND(hwnd as *mut _), "Fill this card's security code"),
        }
    })
    .await
    .map_err(|_| "Approval stopped unexpectedly".to_owned())??;
    if !browser.resolve_card_code(&id, true) {
        return Err("This request expired. Choose the card in your browser again.".to_owned());
    }
    desktop::close_card_code_prompt(&app_handle);
    Ok(())
}

#[tauri::command]
async fn decline_card_code(id: String, app_handle: AppHandle, browser: State<'_, Arc<BrowserIpcServer>>) -> Result<(), String> {
    browser.resolve_card_code(&id, false);
    desktop::close_card_code_prompt(&app_handle);
    Ok(())
}

/// The unlock window's "Open Nuvori". Async so the window is not created on the UI thread.
#[tauri::command]
async fn show_main_window(app_handle: AppHandle) {
    desktop::show_main(&app_handle);
}

/// The unlock window's "Not now". Nuvori keeps running in the tray.
#[tauri::command]
async fn close_unlock_prompt(app_handle: AppHandle) {
    desktop::close_unlock_prompt(&app_handle);
}

#[tauri::command]
async fn stop_sharing(
    state: State<'_, ManagedState>,
    pairing: State<'_, Arc<PairingController>>,
) -> Result<AppSnapshot, String> {
    if pairing.is_active()? {
        return Err("Finish or cancel pairing before leaving the sync group".to_owned());
    }
    pairing.cancel()?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
        // Same as leave_group: a member also tells the managing phone. If Windows somehow
        // manages the group (not possible today), fall back to the local-only stop.
        let notify = match vault.leave_group(true) {
            Ok(()) => true,
            Err(VaultError::ManagingDevice | VaultError::NotSharing) => {
                vault.stop_sharing().map_err(public_vault_error)?;
                false
            }
            Err(error) => return Err(public_vault_error(error)),
        };
        activity::log(Level::Warning, Category::Pairing, "Stopped sharing with paired devices");
        let snapshot = app.snapshot();
        drop(app);
        if notify {
            let background = state.clone();
            thread::spawn(move || {
                let _ = lan_sync::deliver_leave(&background, 0);
            });
        }
        snapshot
    })
    .await
    .map_err(|_| "Leaving the sync group stopped unexpectedly".to_owned())?
}

#[tauri::command]
async fn reset_vault(
    password: String,
    app_handle: AppHandle,
    state: State<'_, ManagedState>,
    browser: State<'_, Arc<BrowserIpcServer>>,
    pairing: State<'_, Arc<PairingController>>,
) -> Result<AppSnapshot, String> {
    if pairing.is_active()? {
        return Err("Finish or cancel pairing before resetting the vault".to_owned());
    }
    pairing.cancel()?;
    let state = state.inner().clone();
    let browser = browser.inner().clone();
    let snapshot = tauri::async_runtime::spawn_blocking(move || -> Result<AppSnapshot, String> {
        let mut password = password;
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        if app.unlocked.is_none() {
            password.zeroize();
            return Err("Unlock the vault first".to_owned());
        }
        let verification = app.store.verify_password(&password);
        password.zeroize();
        verification.map_err(|error| {
            activity::log(Level::Warning, Category::Security, "Vault reset blocked: wrong password");
            public_vault_error(error)
        })?;
        app.unlocked = None;
        browser.set_provider(None);
        app.store.reset_files().map_err(public_vault_error)?;
        activity::log(Level::Warning, Category::Security, "Vault reset on this PC");
        app.snapshot()
    })
    .await
    .map_err(|_| "Vault reset stopped unexpectedly".to_owned())??;
    vault_changed(&app_handle, false);
    Ok(snapshot)
}

#[tauri::command]
fn list_notes(state: State<'_, ManagedState>) -> Result<Vec<LocalNote>, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_ref()
        .ok_or("Unlock the vault first".to_owned())?
        .list_notes()
        .map_err(public_vault_error)
}

#[tauri::command]
fn save_note(
    id: Option<String>,
    title: String,
    body: String,
    group_ids: Option<Vec<String>>,
    state: State<'_, ManagedState>,
) -> Result<LocalNote, String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let note = app
        .unlocked
        .as_mut()
        .ok_or("Unlock the vault first".to_owned())?
        .save_note(id.as_deref(), &title, &body, group_ids)
        .map_err(public_vault_error)?;
    activity::log(Level::Success, Category::Items, activity::item_saved_message("NOTE", id.is_none()));
    Ok(note)
}

#[tauri::command]
fn delete_note(id: String, state: State<'_, ManagedState>) -> Result<(), String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_mut()
        .ok_or("Unlock the vault first".to_owned())?
        .delete_note(&id)
        .map_err(public_vault_error)?;
    activity::log(Level::Info, Category::Items, activity::item_deleted_message("NOTE"));
    Ok(())
}

#[tauri::command]
fn list_entries(state: State<'_, ManagedState>) -> Result<Vec<serde_json::Value>, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_ref()
        .ok_or("Unlock the vault first".to_owned())?
        .list_entries()
        .map_err(public_vault_error)
}

#[tauri::command]
fn save_entry(
    entry: serde_json::Value,
    state: State<'_, ManagedState>,
) -> Result<serde_json::Value, String> {
    let created = entry.get("id").is_none_or(|id| id.is_null() || id.as_str() == Some(""));
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let saved = app
        .unlocked
        .as_mut()
        .ok_or("Unlock the vault first".to_owned())?
        .save_entry(entry)
        .map_err(public_vault_error)?;
    log_entry_saved(&saved, created);
    Ok(saved)
}

/// Logs an item save by type only. The entry's title, usernames and secrets never leave it.
fn log_entry_saved(entry: &serde_json::Value, created: bool) {
    let entry_type = entry["type"].as_str().unwrap_or_default();
    activity::log(Level::Success, Category::Items, activity::item_saved_message(entry_type, created));
}

#[tauri::command]
fn delete_entry(id: String, state: State<'_, ManagedState>) -> Result<(), String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let vault = app.unlocked.as_mut().ok_or("Unlock the vault first".to_owned())?;
    let entry_type = vault.entry_type(&id).map_err(public_vault_error)?.unwrap_or_default();
    vault.delete_entry(&id).map_err(public_vault_error)?;
    activity::log(Level::Info, Category::Items, activity::item_deleted_message(&entry_type));
    Ok(())
}

#[tauri::command]
fn list_entry_photos(
    entry_id: String,
    state: State<'_, ManagedState>,
) -> Result<Vec<EntryPhoto>, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_ref()
        .ok_or("Unlock the vault first".to_owned())?
        .list_entry_photos(&entry_id)
        .map_err(public_vault_error)
}

#[tauri::command]
fn add_entry_photo(
    entry_id: String,
    mime_type: String,
    data: String,
    state: State<'_, ManagedState>,
) -> Result<(), String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_mut()
        .ok_or("Unlock the vault first".to_owned())?
        .add_entry_photo(&entry_id, &mime_type, &data)
        .map_err(public_vault_error)?;
    activity::log(Level::Success, Category::Items, "Added a photo to an item");
    Ok(())
}

#[tauri::command]
fn delete_entry_photo(photo_id: String, state: State<'_, ManagedState>) -> Result<(), String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_mut()
        .ok_or("Unlock the vault first".to_owned())?
        .delete_entry_photo(&photo_id)
        .map_err(public_vault_error)?;
    activity::log(Level::Info, Category::Items, "Removed a photo from an item");
    Ok(())
}

#[tauri::command]
fn list_groups(state: State<'_, ManagedState>) -> Result<Vec<LocalGroup>, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_ref()
        .ok_or("Unlock the vault first".to_owned())?
        .list_groups()
        .map_err(public_vault_error)
}

#[tauri::command]
fn save_group(
    id: Option<String>,
    name: String,
    notes: String,
    folder_type: String,
    state: State<'_, ManagedState>,
) -> Result<LocalGroup, String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let group = app
        .unlocked
        .as_mut()
        .ok_or("Unlock the vault first".to_owned())?
        .save_group(id.as_deref(), &name, &notes, &folder_type)
        .map_err(public_vault_error)?;
    activity::log(
        Level::Success,
        Category::Items,
        if id.is_none() { "Created a folder" } else { "Updated a folder" },
    );
    Ok(group)
}

#[tauri::command]
fn delete_group(id: String, state: State<'_, ManagedState>) -> Result<(), String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_mut()
        .ok_or("Unlock the vault first".to_owned())?
        .delete_group(&id)
        .map_err(public_vault_error)?;
    activity::log(Level::Info, Category::Items, "Deleted a folder");
    Ok(())
}

#[tauri::command]
fn list_passkeys(state: State<'_, ManagedState>) -> Result<Vec<PasskeySummary>, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_ref()
        .ok_or("Unlock the vault first".to_owned())?
        .list_passkeys()
        .map_err(public_vault_error)
}

#[tauri::command]
fn delete_passkey(id: String, state: State<'_, ManagedState>) -> Result<(), String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked
        .as_mut()
        .ok_or("Unlock the vault first".to_owned())?
        .delete_passkey(&id)
        .map_err(public_vault_error)?;
    activity::log(Level::Info, Category::Items, "Deleted a passkey");
    Ok(())
}

fn public_vault_error(error: VaultError) -> String {
    match error {
        VaultError::PasswordTooShort => {
            "Use a master password with at least 12 characters.".to_owned()
        }
        VaultError::AlreadyInitialized => "A Windows vault already exists.".to_owned(),
        VaultError::WrongPasswordOrCorruptKey => "Wrong password or damaged vault key.".to_owned(),
        VaultError::InvalidNote => {
            "A note needs a title and contents within the size limit.".to_owned()
        }
        VaultError::NoteNotFound => "That note no longer exists.".to_owned(),
        VaultError::InvalidEntry => "Check the item fields and try again.".to_owned(),
        VaultError::EntryNotFound => "That item no longer exists.".to_owned(),
        VaultError::InvalidPhoto => {
            "Choose an image under 10 MB. Each item can hold up to 20 photos.".to_owned()
        }
        VaultError::PhotoNotFound => "That photo no longer exists.".to_owned(),
        VaultError::InvalidGroup => "Check the folder name and type.".to_owned(),
        VaultError::GroupNotFound => "That folder no longer exists.".to_owned(),
        VaultError::Passkey(_) => "That passkey has invalid key material.".to_owned(),
        VaultError::PasskeyAlreadyExists => "That passkey already exists.".to_owned(),
        VaultError::PasskeyNotFound => "That passkey no longer exists.".to_owned(),
        VaultError::MissingDeviceIdentity => {
            "This device's signing identity is missing. Restore it before editing the vault."
                .to_owned()
        }
        VaultError::MissingNoteChange => {
            "This note's change history is missing. The vault needs repair before editing."
                .to_owned()
        }
        VaultError::NotSharing => "This vault is not paired with another device.".to_owned(),
        VaultError::ManagingDevice => {
            "This PC manages the group. Transfer the managing role first.".to_owned()
        }
        VaultError::PendingConflicts => {
            "Resolve the pending sync conflicts before leaving the group.".to_owned()
        }
        VaultError::Hello(message) => message,
        other => {
            activity::diagnostic(Category::Vault, "Vault operation failed", &other);
            "The vault could not be opened. Check its local storage.".to_owned()
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let background = desktop::background_launch();
    // Store and installer builds on one PC: the Store build runs (store_build.rs).
    store_build::record();
    if store_build::open_store_build_instead(background) {
        return;
    }
    // One Nuvori per Windows session: a second launch brings the first one forward. A Store
    // build first asks a running installer-build copy to close, then takes its place.
    let instance = desktop::claim_instance().or_else(|| {
        store_build::ask_installer_build_to_close()
            .then(|| desktop::claim_instance_within(store_build::hand_over_wait()))
            .flatten()
    });
    let Some(_instance) = instance else {
        desktop::hand_over_to_running_app(background);
        return;
    };
    let app = tauri::Builder::default()
        .setup(move |app| {
            let directory = app.path().app_data_dir()?;
            if passkey_plugin::storage_is_redirected(&directory) {
                // Never open a private copy of the vault: it would split this PC's sync history.
                use windows::{Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW}, core::w};
                unsafe {
                    MessageBoxW(None,
                        w!("Windows is keeping this copy of Nuvori's data in a private folder, so it can't use your vault safely.\n\nNothing was changed. Use the Nuvori installer build, and report this message."),
                        w!("Nuvori"), MB_OK | MB_ICONERROR);
                }
                std::process::exit(1);
            }
            activity::set_diagnostics_file(directory.join("diagnostics.log"));
            // Installed and Store builds connect the browser extension by themselves. A
            // development build leaves the registration alone; use Settings to connect it.
            if !cfg!(debug_assertions) {
                std::thread::spawn(|| log_browser_connect(browser_setup::connect(), false));
            }
            let packaged_helper = app
                .path()
                .resource_dir()?
                .join("pairing/Nuvori.PairingHelper.exe");
            let development_helper = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../pairing-helper/publish/Nuvori.PairingHelper.exe");
            app.manage(Arc::new(PairingController {
                progress: Mutex::new(PairingProgress::default()),
                approval: Condvar::new(),
                helper_path: if packaged_helper.is_file() {
                    packaged_helper
                } else {
                    development_helper
                },
            }));
            app.manage(Arc::new(Mutex::new(AppState {
                store: VaultStore::new(directory),
                unlocked: None,
            })));
            app.manage(Arc::new(BrowserIpcServer::start()?));
            app.manage(Arc::new(SyncController::default()));
            start_lan_listener(app.state::<ManagedState>().inner().clone(), app.state::<Arc<PairingController>>().inner().clone(), app.state::<Arc<SyncController>>().inner().clone());
            start_background_sync(app.state::<ManagedState>().inner().clone(), app.state::<Arc<PairingController>>().inner().clone(), app.state::<Arc<SyncController>>().inner().clone());
            let handle = app.handle().clone();
            browser_ipc::set_window_handler(move |action, unlocked| {
                if matches!(action, BrowserAction::RequestCvv) {
                    let app = handle.clone();
                    let _ = handle.run_on_main_thread(move || desktop::show_card_code_prompt(&app));
                    return;
                }
                let show_app = matches!(action, BrowserAction::ShowApp) || !vault_configured(&handle);
                if !show_app && unlocked {
                    return;
                }
                let app = handle.clone();
                let _ = handle.run_on_main_thread(move || {
                    if show_app { desktop::show_main(&app) } else { desktop::show_unlock_prompt(&app) }
                });
            });
            let handle = app.handle().clone();
            browser_ipc::set_hand_over_handler(store_build::hand_over_allowed, move || {
                activity::diagnostic(Category::Vault, "Closed for the Microsoft Store build", "it asked to run instead");
                handle.exit(0);
            });
            if let Err(error) = desktop::create_tray(app.handle(), lock_from_tray) {
                activity::diagnostic(Category::Vault, "Could not add the tray icon", error);
            }
            passkey_plugin::start(app.state::<ManagedState>().inner().clone(), app.handle().clone());
            if desktop::plugin_launch() {
                // Windows started Nuvori for a passkey request. The request opens the unlock window if needed.
            } else if background && vault_configured(app.handle()) {
                desktop::show_unlock_prompt(app.handle());
            } else {
                desktop::show_main(app.handle());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_snapshot,
            sync_now,
            sync_status,
            configure_sync,
            set_sync_schedule,
            pairing_status,
            start_pairing,
            start_reverse_pairing,
            approve_pairing,
            cancel_pairing,
            create_vault,
            unlock_vault,
            hello_available,
            enable_hello,
            unlock_hello,
            disable_hello,
            lock_vault,
            stop_sharing,
            reset_vault,
            list_notes,
            save_note,
            delete_note,
            list_entries,
            save_entry,
            delete_entry,
            list_entry_photos,
            add_entry_photo,
            delete_entry_photo,
            list_groups,
            save_group,
            delete_group,
            list_passkeys,
            delete_passkey,
            activity_log,
            clear_activity_log,
            browser_status,
            connect_browsers,
            build_status,
            open_windows_settings,
            cloud_status,
            cloud_connect,
            cloud_cancel_connect,
            cloud_disconnect,
            list_conflicts,
            resolve_conflict,
            photo_sync_status,
            membership_status,
            leave_group,
            dismiss_removed_notice,
            show_main_window,
            close_unlock_prompt,
            pending_card_code,
            approve_card_code,
            decline_card_code
        ])
        .build(tauri::generate_context!())
        .expect("failed to run Nuvori");
    app.run(|app, event| {
        // Closing the last window keeps Nuvori in the tray, so browser filling keeps working.
        // "Quit Nuvori" in the tray exits with a code and is not stopped here.
        if let tauri::RunEvent::ExitRequested { code: None, api, .. } = event
            && app.tray_by_id(desktop::TRAY_ID).is_some()
        {
            api.prevent_exit();
        }
    });
}

#[cfg(test)]
mod activity_tests {
    use super::*;

    #[test]
    fn only_two_windows_settings_pages_can_be_opened() {
        assert_eq!(windows_settings_uri("passkeys"), Some("ms-settings:passkeys-advancedoptions"));
        assert_eq!(windows_settings_uri("apps"), Some("ms-settings:appsfeatures"));
        for page in ["", "ms-settings:privacy", "file:///C:/Windows", "https://example.com"] {
            assert_eq!(windows_settings_uri(page), None, "{page}");
        }
    }

    #[test]
    fn item_save_activity_names_the_type_but_never_the_title_or_username() {
        let directory = std::env::temp_dir().join(format!("nuvori-activity-test-{}", uuid::Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("synthetic-test-password").unwrap();
        let saved = vault
            .save_entry(serde_json::json!({
                "type": "PASSWORD", "title": "Zephyr Credit Union",
                "primaryValue": "quentin.member@example.com", "secondaryValue": "correct horse battery",
                "autofillOrigins": "https://zephyr.example"
            }))
            .unwrap();
        log_entry_saved(&saved, true);
        log_entry_saved(&saved, false);
        let events = activity::global().recent(None);
        assert!(events.iter().any(|event| event.message == "Added a login"));
        assert!(events.iter().any(|event| event.message == "Updated a login"));
        for event in &events {
            for secret in ["Zephyr", "quentin", "correct horse", "zephyr.example"] {
                assert!(!event.message.contains(secret), "{} leaked into the activity log", secret);
            }
        }
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn sync_failures_are_logged_as_short_reasons() {
        log_sync_result(&Err(lan_sync::UNREACHABLE.to_owned()), true);
        let events = activity::global().recent(None);
        assert!(events.iter().any(|event| event.level == Level::Error
            && event.message == format!("Sync failed: {}", lan_sync::UNREACHABLE)));
    }
}
