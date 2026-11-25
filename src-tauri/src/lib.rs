pub mod activity;
mod auto_lock;
mod auto_type;
pub mod appearance;
pub mod browser;
pub mod browser_ipc;
mod browser_setup;
mod browsers;
mod clipboard;
pub mod change_store;
pub mod checkpoint;
pub mod compaction;
pub mod conflicts;
pub mod drive_refill;
mod desktop;
pub mod dpapi;
pub mod enrollment;
pub mod epoch_keys;
pub mod hello;
pub mod identity;
pub mod incoming;
pub mod incoming_apply;
pub mod incoming_store;
pub mod install_marker;
pub mod join_match;
pub mod keepass_import;
pub mod local_recovery;
pub mod merge_join;
mod discovery;
mod google_drive;
mod lan_sync;
mod preauth;
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
pub mod quick_search;
pub mod site_icon_sync;
pub mod sign_in_sync;
pub mod sign_ins;
pub mod site_icons;
pub mod signer;
pub mod snapshot;
pub mod snapshot_import;
mod store_build;
pub mod store_launch;
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
        let with_passkey = if exact.is_empty() && related.is_empty() {
            Default::default()
        } else {
            vault.logins_with_passkeys().map_err(|_| BrowserIpcError::InvalidRequest)?
        };
        // Logins for this exact site first, then those saved for another page of the same site.
        Ok(exact
            .into_iter()
            .map(|login| (login, false))
            .chain(related.into_iter().map(|login| (login, true)))
            .map(|((id, title, username), related)| {
                let passkey = with_passkey.contains(&id);
                LoginCandidate { id, title, username, related, passkey, color: None, site: None, preview: None }
            })
            .collect())
    }

    fn icon_wanted(&self, origin: &str) -> Result<bool, BrowserIpcError> {
        let mut app = self.state.lock().map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_mut().ok_or(BrowserIpcError::VaultLocked)?;
        let now = activity::now_millis() as i64;
        site_icons::wanted(vault.connection(), origin, site_icons::enabled(), now).map_err(|_| BrowserIpcError::InvalidRequest)
    }

    fn save_site_icon(&self, origin: &str, png: &[u8]) -> Result<(), BrowserIpcError> {
        let mut app = self.state.lock().map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_mut().ok_or(BrowserIpcError::VaultLocked)?;
        let now = activity::now_millis() as i64;
        site_icons::save(vault.connection(), origin, png, site_icons::enabled(), now).map_err(|_| BrowserIpcError::InvalidRequest)?;
        if let Some(site) = site_icons::site_of_origin(origin)
            && let Err(error) = site_icon_sync::remember_capture(vault.connection(), &site, png)
        {
            activity::diagnostic(activity::Category::Sync, "Could not note a captured website icon", error);
        }
        // Share it with the sync group now when the gate is open; otherwise the next sync writes it.
        let identity_store = app.store.identity_store();
        if let Some(vault) = app.unlocked.as_mut() {
            site_icon_sync::flush_installed(vault, &identity_store);
        }
        drop(app);
        site_icons::notify_saved();
        Ok(())
    }

    fn query_sign_ins(&self, origin: &str) -> Result<Option<browser::SignInsAnswer>, BrowserIpcError> {
        if !sign_ins::enabled() {
            return Ok(None);
        }
        let mut app = self.state.lock().map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_mut().ok_or(BrowserIpcError::VaultLocked)?;
        let (site, methods) = sign_ins::for_origin(vault.connection(), origin)
            .map_err(|_| BrowserIpcError::InvalidRequest)?
            .ok_or(BrowserIpcError::InvalidRequest)?;
        Ok(Some(sign_in_answer(site, methods)))
    }

    fn record_sign_in(&self, origin: &str, details: &browser::SignInDetails) -> Result<browser::SignInsAnswer, BrowserIpcError> {
        let mut app = self.state.lock().map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_mut().ok_or(BrowserIpcError::VaultLocked)?;
        let now = activity::now_millis() as i64;
        let stored = sign_ins::record(vault.connection(), origin, &details.provider, details.account.as_deref(), sign_ins::enabled(), now)
            .map_err(|_| BrowserIpcError::InvalidRequest)?;
        let (site, methods) = sign_ins::for_origin(vault.connection(), origin)
            .map_err(|_| BrowserIpcError::InvalidRequest)?
            .unwrap_or_else(|| (stored.site.clone(), vec![stored]));
        // Share it with the sync group now when the gate is open; a quiet re-record waits up to a day.
        let identity_store = app.store.identity_store();
        if let Some(vault) = app.unlocked.as_mut() {
            sign_in_sync::flush_installed(vault, &identity_store);
        }
        drop(app);
        sign_ins::notify_changed();
        Ok(sign_in_answer(site, methods))
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

    fn query_all_credentials(&self) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
        let app = self.state.lock().map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_ref().ok_or(BrowserIpcError::VaultLocked)?;
        let with_passkey = vault.logins_with_passkeys().map_err(|_| BrowserIpcError::InvalidRequest)?;
        Ok(vault
            .all_logins()
            .map_err(|_| BrowserIpcError::InvalidRequest)?
            .into_iter()
            .map(|(id, title, username, site)| {
                let passkey = with_passkey.contains(&id);
                LoginCandidate { id, title, username, related: false, passkey, color: None, site: Some(site), preview: None }
            })
            .collect())
    }

    fn load_any_credential(&self, id: &str) -> Result<Option<SelectedCredential>, BrowserIpcError> {
        let app = self.state.lock().map_err(|_| BrowserIpcError::InvalidRequest)?;
        let vault = app.unlocked.as_ref().ok_or(BrowserIpcError::VaultLocked)?;
        Ok(vault
            .any_login(id)
            .map_err(|_| BrowserIpcError::InvalidRequest)?
            .map(|(username, password)| SelectedCredential { id: id.to_owned(), username, password }))
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
        let plain = |items: Vec<(String, String, String)>| items.into_iter()
            .map(|(id, title, username)| LoginCandidate { id, title, username, related: false, passkey: false, color: None, site: None, preview: None }).collect::<Vec<_>>();
        let items = match kind {
            ItemKind::Card => vault.browser_cards().map(|cards| cards.into_iter()
                .map(|(id, title, username, color)| LoginCandidate { id, title, username, related: false, passkey: false, color, site: None, preview: None }).collect()),
            ItemKind::Profile => vault.browser_profiles().map(|profiles| profiles.into_iter()
                .map(|(id, title, username, profile)| LoginCandidate { id, title, username, related: false, passkey: false, color: None, site: None, preview: Some(profile) }).collect()),
            ItemKind::Code => vault.browser_codes(origin, all).map(plain),
        };
        items.map_err(|_| BrowserIpcError::InvalidRequest)
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
    /// Nuvori was opened: the loop runs one pass over every way as soon as the vault is unlocked.
    open_requested: std::sync::atomic::AtomicBool,
    last_open: Mutex<Option<Instant>>,
}

/// Opening Nuvori again within this time does not start another pass.
const OPEN_PASS_MIN_GAP: Duration = Duration::from_secs(60);

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
    /// M14: passes in a row that needed a Google sign-in, and when the user was last told.
    sign_in_failures: std::sync::atomic::AtomicU32,
    sign_in_told_at: Mutex<Option<Instant>>,
    /// Shows or clears the sign-in reminder outside the app window (the tray icon's tooltip).
    sign_in_alert: std::sync::OnceLock<Box<dyn Fn(bool) + Send + Sync>>,
}

const CLOUD_FULL_LISTING: Duration = Duration::from_secs(6 * 60 * 60);
/// M14, as on Android: after this many passes in a row needed a sign-in, the user is told once,
/// at most once a day; a pass that works again clears it.
const SIGN_IN_FAILURES_BEFORE_NOTICE: u32 = 3;
const SIGN_IN_NOTICE_GAP: Duration = Duration::from_secs(24 * 60 * 60);
const SIGN_IN_NOTICE: &str = "Google Drive sync needs you to sign in. Open Nuvori and sign in again so your devices keep in step.";

/// True when the failures in a row and the last notice call for telling the user now.
fn sign_in_notice_due(failures: u32, told_at: Option<Instant>, now: Instant) -> bool {
    failures >= SIGN_IN_FAILURES_BEFORE_NOTICE
        && told_at.is_none_or(|at| now.saturating_duration_since(at) >= SIGN_IN_NOTICE_GAP)
}

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
        let sign_in = match &result {
            Ok(_) => Some(false),
            Err(error) if error == lan_sync::cloud::AUTH_NEEDED => Some(true),
            Err(_) => None,
        };
        match self.note_sign_in(sign_in, Instant::now()) {
            Some(true) => {
                activity::log(Level::Warning, Category::Sync, SIGN_IN_NOTICE);
                if let Some(alert) = self.sign_in_alert.get() { alert(true); }
            }
            Some(false) => if let Some(alert) = self.sign_in_alert.get() { alert(false); },
            None => {}
        }
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

    /// M14: counts passes that needed a sign-in (`Some(true)`); a pass that worked (`Some(false)`)
    /// ends the run. Other failures change nothing. Returns `Some(true)` when the user is to be told
    /// now and `Some(false)` when a reminder they were given no longer holds.
    fn note_sign_in(&self, needed: Option<bool>, now: Instant) -> Option<bool> {
        use std::sync::atomic::Ordering;
        let mut told = self.sign_in_told_at.lock().ok()?;
        match needed? {
            true => {
                let failures = self.sign_in_failures.fetch_add(1, Ordering::SeqCst).saturating_add(1);
                if !sign_in_notice_due(failures, *told, now) { return None; }
                *told = Some(now);
                Some(true)
            }
            false => {
                self.sign_in_failures.store(0, Ordering::SeqCst);
                told.take().map(|_| false)
            }
        }
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
        if self.note_sign_in(Some(false), Instant::now()) == Some(false)
            && let Some(alert) = self.sign_in_alert.get() { alert(false); }
    }
}

impl SyncController {
    /// Nuvori came to the front. Asks for one pass, at most once per [`OPEN_PASS_MIN_GAP`].
    fn request_open_pass(&self) { self.request_open_pass_at(Instant::now()); }

    fn request_open_pass_at(&self, now: Instant) {
        let Ok(mut last) = self.last_open.lock() else { return };
        if last.is_some_and(|at| now.saturating_duration_since(at) < OPEN_PASS_MIN_GAP) { return; }
        *last = Some(now);
        self.open_requested.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn endpoints(&self) -> Vec<std::net::SocketAddr> {
        let Ok(mut network) = self.discovery.lock() else { return Vec::new(); };
        if network.is_none() { *network = discovery::LanDiscovery::new().ok(); }
        network.as_mut().map_or_else(Vec::new, discovery::LanDiscovery::endpoints)
    }

    /// Runs one pass over `ways`. `manual` passes always log; automatic passes log only when
    /// something moved or failed so the activity log is not flooded by idle checks.
    /// `opened`: the pass on opening Nuvori. Like Sync now it waits briefly for devices to show up
    /// on Wi-Fi, but finding none is normal and changes no status message or log.
    fn exchange(&self, state: &ManagedState, helper: &std::path::Path, address: &str, manual: bool, ways: Ways, opened: bool) -> PassOutcome {
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
        if (manual || opened) && ways.wifi && endpoints.is_empty() {
            for _ in 0..6 {
                thread::sleep(Duration::from_millis(500));
                endpoints = self.endpoints();
                if !endpoints.is_empty() { break; }
            }
        }
        let mut outcome = self.pass(state, helper, address, &endpoints, manual, ways, opened);
        // Continuous editing: edits saved on this PC while the pass ran get a prompt follow-up
        // pass (after a short debounce) instead of waiting for the next interval.
        // L1: when the pass ended at its session cap with more to exchange, the next pass starts
        // at once, without the debounce.
        for _ in 0..MAX_FOLLOW_UP_PASSES {
            let Ok(report) = &outcome.result else { break };
            let edited = local_edits_since(state, report.local_revision_at_start);
            if !edited && !report.more_remain {
                break;
            }
            let previous = report.clone();
            if edited && !report.more_remain { thread::sleep(FOLLOW_UP_DEBOUNCE); }
            let endpoints = if ways.wifi { self.endpoints() } else { Vec::new() };
            let follow_up = self.pass(state, helper, address, &endpoints, false, ways, opened);
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
        endpoints: &[std::net::SocketAddr], manual: bool, ways: Ways, opened: bool) -> PassOutcome {
        let lan = ways.wifi.then(|| lan_sync::run(state, helper, address, &self.tracker, endpoints, opened && !manual));
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
                } else if opened && !manual && lan.as_ref().is_err_and(|error| error == lan_sync::UNREACHABLE) {
                    // Opened away from the other devices: nothing to report.
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
            (Err(lan), Ok(cloud)) => {
                // M12: Drive carried the changes, but a problem on this PC stays shown (a device's
                // refusal is kept by `succeed`).
                if lan_sync::failure_class(&lan) != lan_sync::FailureClass::NeedsYou { self.tracker.succeed(); }
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
    let summary = sync_counts(report);
    // L1: honest about a pass that stopped at its cap: the next pass continues.
    if report.more_remain { format!("{summary} More changes remain, and sync continues.") } else { summary }
}

fn sync_counts(report: &lan_sync::SyncReport) -> String {
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
/// Turns "Sync when Nuvori opens" on or off on this PC (Sync page).
#[tauri::command]
fn set_sync_on_open(enabled: bool, state: State<'_, ManagedState>) -> Result<(), String> {
    let mut app = state.lock().map_err(|_| "Vault state unavailable")?;
    lan_sync::set_sync_on_open(app.unlocked.as_mut().ok_or("Unlock the vault first")?.connection(), enabled)?;
    activity::log(Level::Info, Category::Sync,
        if enabled { "Sync when Nuvori opens is on" } else { "Sync when Nuvori opens is off" });
    Ok(())
}

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
        sync.exchange(&state, &helper, &address, true, Ways::ALL, false).result
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

/// "Mark as lost" for the managing phone (`merge_join.rs`); `lost: false` undoes it.
#[tauri::command]
fn mark_manager_lost(lost: bool, state: State<'_, ManagedState>) -> Result<membership_exit::MembershipStatus, String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
    if lost {
        vault.mark_manager_lost().map_err(public_vault_error)?;
        activity::log(Level::Warning, Category::Pairing, "Managing phone marked as lost. This PC no longer takes its changes");
    } else {
        vault.undo_manager_lost().map_err(public_vault_error)?;
        activity::log(Level::Info, Category::Pairing, "Managing phone trusted again");
    }
    vault.membership_status().map_err(public_vault_error)
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
            "No connected browser was found on this PC"),
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

/// Settings > Browser extension: every browser found on this PC, with its choices.
#[tauri::command]
async fn list_browsers() -> Result<Vec<browsers::Browser>, String> {
    tauri::async_runtime::spawn_blocking(browser_setup::list)
        .await
        .map_err(|_| "Couldn't list the browsers".to_owned())?
        .map_err(|_| "Couldn't list the browsers".to_owned())
}

/// Connect or disconnect one browser, or change whether it asks for the password at start. The
/// registration changes at once. `family` counts only for a browser Nuvori could not classify.
#[tauri::command]
async fn set_browser(
    id: String,
    connected: Option<bool>,
    ask_at_start: Option<bool>,
    family: Option<browsers::Family>,
) -> Result<Vec<browsers::Browser>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || browser_setup::set(&id, connected, ask_at_start, family))
        .await
        .map_err(|_| "Couldn't change the browser".to_owned())?;
    result.map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => "That browser is no longer installed.".to_owned(),
        std::io::ErrorKind::NotFound => "The browser host is missing. Reinstall Nuvori.".to_owned(),
        _ => "Couldn't write the browser registration. Try again.".to_owned(),
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

/// A link in a note, checked again here: only web and mail addresses open, and only after the
/// person confirmed it in the app.
fn note_link_allowed(link: &str) -> bool {
    let lower = link.to_ascii_lowercase();
    link.len() <= 2048
        && !link.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '<' || c == '>')
        && ((lower.starts_with("https://") || lower.starts_with("http://")) && link.splitn(2, "://").nth(1).is_some_and(|rest| {
            let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
            !host.is_empty() && !host.contains('@')
        }) || lower.starts_with("mailto:") && link.len() > 7)
}

#[tauri::command]
fn open_note_link(link: String) -> Result<(), String> {
    if !note_link_allowed(&link) {
        return Err("This link can't be opened.".to_owned());
    }
    if open_address(&link) { Ok(()) } else { Err("Couldn't open the link.".to_owned()) }
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
            thread::spawn(move || { let _ = sync.exchange(&state, &helper, "", false, Ways::DRIVE, false); });
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

    /// Records a result; returns the retry delay after a failure. M12: a refusal or a problem on
    /// this PC is not retried at the fast rate; the next check comes at the usual interval.
    fn finish(&mut self, result: &Result<(), String>, now: Instant) -> Option<Duration> {
        match result {
            Ok(()) => { self.failures = 0; self.retry_at = None; None }
            Err(error) if error == lan_sync::DEVICE_REFUSED
                || lan_sync::failure_class(error) == lan_sync::FailureClass::NeedsYou => { self.failures = 0; self.retry_at = None; None }
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
fn a_refusal_waits_for_the_usual_interval_and_a_dropped_link_retries_soon() {
    let start = Instant::now();
    let mut clock = WayClock::default();
    clock.start(&(String::new(), 1), start);
    assert!(clock.finish(&Err(lan_sync::INTERRUPTED.into()), start).is_some());
    assert!(clock.retry_at.is_some());
    assert_eq!(clock.finish(&Err(lan_sync::DEVICE_REFUSED.into()), start), None);
    assert_eq!((clock.retry_at, clock.failures), (None, 0));
    let every = Some(Duration::from_secs(60));
    assert!(!clock.due(&(String::new(), 1), every, start + Duration::from_secs(30)));
    assert!(clock.due(&(String::new(), 1), every, start + Duration::from_secs(60)));
}

#[test]
fn opening_nuvori_asks_for_one_pass_per_minute() {
    use std::sync::atomic::Ordering;
    let sync = SyncController::default();
    let start = Instant::now();
    sync.request_open_pass_at(start);
    assert!(sync.open_requested.swap(false, Ordering::SeqCst), "the first open asks for a pass");
    sync.request_open_pass_at(start + Duration::from_secs(20));
    assert!(!sync.open_requested.load(Ordering::SeqCst), "switching back within a minute does not");
    sync.request_open_pass_at(start + OPEN_PASS_MIN_GAP);
    assert!(sync.open_requested.load(Ordering::SeqCst), "a minute later it does again");
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
    // Security review L-20: an address whose connections keep failing the proof is turned away.
    let limiter = Arc::new(std::sync::Mutex::new(preauth::PreAuthLimiter::default()));
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
        let Ok(source) = stream.peer_addr().map(|address| address.ip()) else { continue; };
        let admit = limiter.lock().map_or(preauth::Admit::Blocked, |mut limiter| limiter.try_start(source, Instant::now()));
        match admit {
            preauth::Admit::Start => {}
            preauth::Admit::Full => { lan_sync::reply_busy(stream); continue; }
            preauth::Admit::Blocked => { drop(stream); continue; }
        }
        if pairing.is_active().unwrap_or(true) {
            if let Ok(mut limiter) = limiter.lock() { limiter.release(source); }
            lan_sync::reply_busy(stream);
            continue;
        }
        // The session runs on its own thread so this loop keeps accepting. M7: the device proves
        // membership first and only then takes the sync lock (`serve_proved`), so a device outside
        // the group can't hold sync, Google Drive or this PC's own passes.
        let (state, pairing, sync, limiter) = (state.clone(), pairing.clone(), sync.clone(), limiter.clone());
        thread::spawn(move || {
            let (result, proved) = lan_sync::serve_proved(&state, &pairing.helper_path, stream, &sync.tracker, Some(&sync.gate));
            if let Ok(mut limiter) = limiter.lock() { limiter.finish(source, proved, Instant::now()); }
            if let Ok(report) = result {
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
    on_open: bool,
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
                let on_open = lan_sync::sync_on_open(vault.connection());
                Some(LoopPlan { seen: (address, revision), automatic, drive, schedule, on_open })
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
            // Nuvori was opened (and the vault is unlocked now): every way runs once, Wi-Fi too
            // when automatic Wi-Fi sync is off. A request waits here while the vault is locked.
            let open_requested = sync.open_requested.load(std::sync::atomic::Ordering::SeqCst);
            if open_requested && !plan.on_open { sync.open_requested.store(false, std::sync::atomic::Ordering::SeqCst); }
            let opened = open_requested && plan.on_open;
            let ways = if opened { Ways { wifi: true, drive: plan.drive } } else { Ways {
                wifi: plan.automatic && wifi.due(&plan.seen, Some(Duration::from_secs(plan.schedule.wifi_seconds)), now),
                drive: plan.drive && drive.due(&plan.seen, (plan.schedule.drive_seconds > 0)
                    .then(|| Duration::from_secs(plan.schedule.drive_seconds)), now),
            } };
            if !ways.wifi && !ways.drive { continue; }
            if sync.gate.try_lock().is_err() { continue; }
            if opened { sync.open_requested.store(false, std::sync::atomic::Ordering::SeqCst); }
            if ways.wifi { wifi.start(&plan.seen, now); }
            if ways.drive { drive.start(&plan.seen, now); }
            let outcome = sync.exchange(&state, &pairing.helper_path, &plan.seen.0, false, ways, opened);
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
    /// After a join: this PC's items that differ from the group's (now in Recently deleted).
    needs_review: u32,
    /// After a join that kept item IDs: items waiting in Sync conflicts (`merge_join.rs`).
    conflicts: u32,
}

#[derive(Default)]
struct PairingProgress {
    status: PairingStatus,
    active: bool,
    approved: bool,
    canceled: bool,
    socket: Option<TcpStream>,
    joined: Option<join_match::JoinSummary>,
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
            ..Default::default()
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
                let joined = progress.joined.take().unwrap_or_default();
                let base = if result == Ok(true) {
                    "Vault copied. Windows and Android now keep their own local copies."
                } else {
                    "Vault copied, but the phone may not have received final confirmation. Check its pairing status."
                };
                PairingStatus {
                    stage: "paired".to_owned(),
                    message: match joined.describe() {
                        Some(items) => format!("{base} {items}"),
                        None => base.to_owned(),
                    },
                    needs_review: joined.needs_review + joined.deleted_in_group,
                    conflicts: joined.conflicts,
                    ..Default::default()
                }
            };
        }
    }

    /// After a join that kept this PC's items: what happened to them (`join_match.rs`).
    fn note_join(&self, summary: join_match::JoinSummary) {
        if let Some(items) = summary.describe() {
            activity::log(Level::Info, Category::Pairing, format!("This PC's items: {items}"));
        }
        if let Ok(mut progress) = self.progress.lock() {
            progress.joined = Some(summary);
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
    let identity_store = {
        let app = state.lock().map_err(|_| "Vault state is unavailable")?;
        app.store.identity_store()
    };
    // Security review L-20: the first device to dial the QR's port may not be the phone. A
    // connection that never proves the QR's code is dropped, and the offer waits for the next one
    // until it expires. Once the code is proved, any failure is final.
    let mut attempts = 0;
    let mut session = loop {
        attempts += 1;
        let stream = offer
            .accept(|| controller.is_canceled())
            .map_err(|error| error.to_string())?;
        controller
            .attach_socket(&stream)
            .map_err(|error| error.to_string())?;
        controller.set_stage("connecting", "Checking the Android pairing request", "")?;
        let mut code_proved = false;
        match JoinSession::accept_proving(stream, &offer, password, &controller.helper_path,
            &identity_store, &mut code_proved) {
            Ok(session) => break session,
            Err(_) if !code_proved && !controller.is_canceled() && attempts < enrollment::REVERSE_ATTEMPTS => {
                activity::log(Level::Warning, Category::Pairing,
                    "A device connected to the pairing QR without its code. Still waiting for the phone");
                controller.set_stage("connecting", "Waiting for the phone to scan the QR", "")?;
            }
            Err(error) => return Err(error.to_string()),
        }
    };
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
    let (joined, summary) = session
        .commit(prepared, vault, identity_store)
        .map_err(|error| error.to_string())?;
    // A leave request this same identity signed earlier must not remove it again later.
    let _ = vault.forget_own_pending_leave();
    drop(app);
    controller.note_join(summary);
    Ok(joined)
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
    /// The vault here was last opened by an earlier install of Nuvori (`install_marker.rs`).
    welcome_back: bool,
    /// While locked: when the vault was last changed, in Unix milliseconds (a file time); 0 otherwise.
    last_used_at: i64,
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
            welcome_back: self.welcome_back(),
            last_used_at: if self.unlocked.is_none() && self.store.is_initialized() {
                self.store.last_used_millis().unwrap_or(0)
            } else {
                0
            },
        })
    }

    /// A locked vault that this install has never opened: the unlock screen says "Welcome back".
    fn welcome_back(&self) -> bool {
        self.welcome_back_for(install_marker::installed())
    }

    fn welcome_back_for(&self, marker: Option<&install_marker::InstallMarker>) -> bool {
        self.unlocked.is_none()
            && self.store.is_initialized()
            && marker.is_some_and(|marker| marker.is_new_install(self.store.last_used_millis()))
    }

    /// "Start fresh on this PC": deletes this PC's vault without its password (`VaultStore::start_fresh`).
    /// Never while the vault is unlocked in any window. Only local files go, and nothing is sent to
    /// other devices. The activity log gets one line without secrets.
    fn start_fresh(&mut self) -> Result<AppSnapshot, String> {
        if self.unlocked.is_some() {
            activity::log(Level::Warning, Category::Security, "Start fresh blocked: the vault is unlocked");
            return Err(START_FRESH_UNLOCKED.to_owned());
        }
        let earlier_install = self.welcome_back();
        self.store.start_fresh().map_err(|error| match error {
            VaultError::InUse => {
                activity::log(Level::Warning, Category::Security, "Start fresh blocked: the vault is open in another program");
                START_FRESH_IN_USE.to_owned()
            }
            other => {
                activity::diagnostic(Category::Security, "Could not start fresh", &other);
                "Couldn't delete this PC's vault. Restart Nuvori and try again.".to_owned()
            }
        })?;
        activity::log(Level::Warning, Category::Security, if earlier_install {
            "Started fresh on this PC: deleted the vault from an earlier install without its password"
        } else {
            "Started fresh on this PC: deleted the vault without its password"
        });
        self.snapshot()
    }
}

/// The word the person types to confirm "Start fresh on this PC".
const START_FRESH_WORD: &str = "RESET";
const START_FRESH_UNLOCKED: &str = "The vault is unlocked in another window. Lock it first, or reset it in Settings.";
const START_FRESH_IN_USE: &str = "Another program has the vault open. Close it and try again.";

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
        // After "Mark as lost" this PC may pair with a new managing phone and keep its items.
        if vault.is_enrolled().map_err(public_vault_error)? && !vault.manager_lost().map_err(public_vault_error)? {
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
        // Received changes that wait apply now, before the vault is shown (H5).
        if let Some(vault) = app.unlocked.as_mut() { let _ = lan_sync::apply_received(vault); }
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
    state: State<'_, ManagedState>,
) -> Result<AppSnapshot, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut password = Zeroizing::new(password);
        let key = {
            let app = state.lock().map_err(|_| "Vault state is unavailable")?;
            let vault = app.unlocked.as_ref().ok_or("Unlock the vault first")?;
            app.store
                .verify_password(&password)
                .map_err(public_vault_error)?;
            Zeroizing::new(*vault.key_for_hello())
        };
        password.zeroize();
        // The Hello prompts run without the vault lock held.
        let sealed = hello::enroll(&key)?;
        let app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app.unlocked.as_ref().ok_or("Unlock the vault first")?;
        if *vault.key_for_hello() != *key {
            return Err("The vault changed while Windows Hello was open. Try again.".to_owned());
        }
        app.store.enable_hello(&sealed).map_err(public_vault_error)?;
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
        let saved = {
            let app = state.lock().map_err(|_| "Vault state is unavailable")?;
            if !app.store.hello_enabled() {
                return Err(
                    "Set up Windows Hello after unlocking with your master password".to_owned(),
                );
            }
            app.store.hello_file().map_err(public_vault_error)?
        };
        let failed = |_: &String| {
            activity::log(Level::Warning, Category::Security, "Windows Hello unlock failed");
        };
        // The Hello prompts run without the vault lock held.
        let legacy = hello::is_legacy(&saved);
        let key = if legacy {
            // Legacy path (DPAPI-only file from Nuvori 2.2.3 and earlier): consent prompt, then
            // DPAPI, once. The file is saved again in the Hello-bound format below. Remove this
            // branch in a later release.
            hello::verify(windows::Win32::Foundation::HWND(hwnd as *mut _)).inspect_err(failed)?;
            hello::open_legacy(&saved).inspect_err(failed)?
        } else {
            hello::unseal(&saved).inspect_err(failed)?
        };
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app.store.unlock_hello(&key).map_err(|error| {
            activity::log(Level::Warning, Category::Security, "Windows Hello unlock failed");
            public_vault_error(error)
        })?;
        app.unlocked = Some(vault);
        // Received changes that wait apply now, before the vault is shown (H5).
        if let Some(vault) = app.unlocked.as_mut() { let _ = lan_sync::apply_received(vault); }
        let snapshot = app.snapshot()?;
        drop(app);
        browser.set_provider(Some(Arc::new(VaultBrowserProvider { state: state.clone() })));
        activity::log(Level::Success, Category::Vault, "Vault unlocked with Windows Hello");
        if legacy {
            upgrade_legacy_hello(&state, &key, &saved);
        }
        Ok(snapshot)
    })
    .await
    .map_err(|_| "Windows Hello unlock stopped unexpectedly".to_owned())??;
    vault_changed(&app_handle, true);
    Ok(snapshot)
}

/// Saves a legacy (DPAPI-only) Hello unlock again in the Hello-bound format. This shows one more
/// Hello prompt. On cancel or error the legacy file stays, and the next Hello unlock tries again.
// Remove together with the legacy branch of `unlock_hello` in a later release.
fn upgrade_legacy_hello(state: &ManagedState, key: &[u8; 32], legacy: &[u8]) {
    let result = hello::enroll(key).and_then(|sealed| {
        let app = state.lock().map_err(|_| "Vault state is unavailable".to_owned())?;
        // Skip if Hello was turned off or set up again while the prompt was open.
        if app.store.hello_file().ok().as_deref() != Some(legacy) {
            return Ok(());
        }
        app.store.enable_hello(&sealed).map_err(public_vault_error)
    });
    match result {
        Ok(()) => activity::log(
            Level::Success,
            Category::Security,
            "Windows Hello unlock now uses a Windows Hello key",
        ),
        Err(error) => activity::diagnostic(
            Category::Security,
            "Windows Hello unlock upgrade will be tried again at the next Hello unlock",
            error,
        ),
    }
}

#[tauri::command]
async fn disable_hello(state: State<'_, ManagedState>) -> Result<AppSnapshot, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let snapshot = {
            let app = state.lock().map_err(|_| "Vault state is unavailable")?;
            if app.unlocked.is_none() {
                return Err("Unlock the vault first".to_owned());
            }
            app.store.disable_hello().map_err(public_vault_error)?;
            activity::log(Level::Info, Category::Security, "Windows Hello unlock turned off");
            app.snapshot()?
        };
        // The file is gone, so the Hello key alone opens nothing; a failure here is only logged.
        if let Err(error) = hello::delete_credential() {
            activity::diagnostic(Category::Security, "Windows Hello key cleanup failed", error);
        }
        Ok(snapshot)
    })
    .await
    .map_err(|_| "Windows Hello setup stopped unexpectedly".to_owned())?
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
    // A password copied from Nuvori goes when the vault locks, if nothing was copied since.
    clipboard::clear_secret_now();
    if was_unlocked {
        activity::log(Level::Info, Category::Vault, "Vault locked");
    }
    snapshot
}

/// H-03: the backend's auto-lock (idle, Windows session lock, sleep). Runs on the auto-lock
/// threads, never the UI thread; a vault that is already locked is left alone.
fn auto_lock_vault(app: &AppHandle, reason: auto_lock::Reason) {
    let state = app.state::<ManagedState>();
    let unlocked = state.lock().is_ok_and(|state| state.unlocked.is_some());
    if !unlocked {
        return;
    }
    if reason != auto_lock::Reason::Suspend
        && let Some(sync) = app.try_state::<Arc<SyncController>>()
    {
        drive_pass_before_lock(reason, state.inner(), sync.inner());
        // Sleep may have locked the vault meanwhile.
        if !state.lock().is_ok_and(|state| state.unlocked.is_some()) {
            return;
        }
    }
    let locked = lock(
        state.inner(),
        app.state::<Arc<BrowserIpcServer>>().inner(),
        app.state::<Arc<PairingController>>().inner(),
    );
    if locked.is_ok() {
        activity::log(Level::Info, Category::Security, reason.message());
        vault_changed(app, false);
    }
}

/// M1: a locked PC neither listens on Wi-Fi nor checks Google Drive, so before an idle or
/// Windows-lock auto-lock, one Google Drive pass runs when Drive is connected and checked
/// automatically. The other devices then get what this PC holds (its own changes and the ones it
/// received over Wi-Fi) and its progress. Best effort and bounded: the vault locks after this
/// long whatever the pass is doing. Sleep locks at once, without a pass.
const PRE_LOCK_DRIVE_WAIT: Duration = Duration::from_secs(20);

/// Sleep gives a program about two seconds, so it never waits for Drive. Drive set to "only when
/// you select Sync now" is not checked either.
fn pass_before_lock(reason: auto_lock::Reason, drive_seconds: u64, connected: bool) -> bool {
    reason != auto_lock::Reason::Suspend && drive_seconds > 0 && connected
}

fn drive_pass_before_lock(reason: auto_lock::Reason, state: &ManagedState, sync: &Arc<SyncController>) {
    let drive_seconds = state.lock().ok().and_then(|mut app| {
        app.unlocked.as_mut().filter(|vault| vault.is_enrolled().unwrap_or(false))
            .map(|vault| lan_sync::schedule(vault.connection()).drive_seconds)
    });
    let Some(drive_seconds) = drive_seconds else { return };
    if !pass_before_lock(reason, drive_seconds, CloudController::connected(state)) {
        return;
    }
    let (state, sync) = (state.clone(), sync.clone());
    let (done, finished) = std::sync::mpsc::channel();
    let started = thread::Builder::new().name("nuvori-pre-lock-drive".to_owned()).spawn(move || {
        // A pass already running is not waited for: the vault locks at once.
        if let Ok(_guard) = sync.gate.try_lock() {
            let _ = sync.cloud.pass(&state, &sync.tracker, false);
        }
        let _ = done.send(());
    });
    if started.is_ok() {
        let _ = finished.recv_timeout(PRE_LOCK_DRIVE_WAIT);
    }
}

// Secret copies (L-17). The clipboard formats and the clearing live in `clipboard.rs`.

/// Copies a password or code without clipboard history or cloud clipboard, and clears it after
/// `clear_after_seconds` (0: never) if nothing was copied since.
#[tauri::command]
async fn copy_secret(text: String, clear_after_seconds: u32) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || clipboard::copy_secret(text, clear_after_seconds))
        .await
        .map_err(|_| "The clipboard could not be set".to_owned())?
}

#[tauri::command]
async fn clear_secret_clipboard() {
    let _ = tauri::async_runtime::spawn_blocking(clipboard::clear_secret_now).await;
}

// Auto-lock commands. The timer and the Windows session watcher live in `auto_lock.rs`.

#[tauri::command]
fn auto_lock_status(auto_lock: State<'_, Arc<auto_lock::AutoLock>>) -> auto_lock::Status {
    auto_lock.status()
}

#[tauri::command]
fn set_auto_lock(minutes: u32, auto_lock: State<'_, Arc<auto_lock::AutoLock>>) -> Result<auto_lock::Status, String> {
    auto_lock.set_minutes(minutes)
}

/// The app's windows report user input here (throttled by the page): it restarts the idle time.
#[tauri::command]
fn note_user_activity(auto_lock: State<'_, Arc<auto_lock::AutoLock>>) {
    auto_lock.touch();
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
        // This install has now opened the vault: no "Welcome back" on the next start.
        install_marker::record_current();
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

/// "Start fresh on this PC" on the unlock screen, for a forgotten password or an earlier
/// install's vault. No password: `confirmation` must be the typed word RESET. Works only while the
/// vault is locked (`AppState::start_fresh`). The Settings reset keeps its password check.
#[tauri::command]
async fn start_fresh(
    confirmation: String,
    app_handle: AppHandle,
    state: State<'_, ManagedState>,
    browser: State<'_, Arc<BrowserIpcServer>>,
    pairing: State<'_, Arc<PairingController>>,
) -> Result<AppSnapshot, String> {
    if confirmation != START_FRESH_WORD {
        return Err("Type RESET to confirm.".to_owned());
    }
    if pairing.is_active()? {
        return Err("Finish or cancel pairing before you start fresh".to_owned());
    }
    pairing.cancel()?;
    let state = state.inner().clone();
    let browser = browser.inner().clone();
    let snapshot = tauri::async_runtime::spawn_blocking(move || -> Result<AppSnapshot, String> {
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        // The vault is locked, so the browser has nothing to ask; make sure it stays that way.
        if app.unlocked.is_none() {
            browser.set_provider(None);
        }
        app.start_fresh()
    })
    .await
    .map_err(|_| "Starting fresh stopped unexpectedly".to_owned())??;
    vault_changed(&app_handle, false);
    // No vault now: this install creates the next one.
    install_marker::record_current();
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
    rich: Option<String>,
    state: State<'_, ManagedState>,
) -> Result<LocalNote, String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let note = app
        .unlocked
        .as_mut()
        .ok_or("Unlock the vault first".to_owned())?
        .save_rich_note(id.as_deref(), &title, &body, rich.as_deref(), group_ids)
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

// Import from KeePass (keepass_import.rs). The file arrives as base64 from the import dialog and
// is opened in memory only. Both commands run the KeePass key derivation off the UI thread.

fn open_keepass(data: &str, password: &str, key_file: Option<&str>) -> Result<keepass_import::Plan, String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    if data.len() > keepass_import::MAX_FILE_BYTES / 3 * 4 + 8 {
        return Err(keepass_import::KeepassError::TooLarge.to_string());
    }
    let bytes = zeroize::Zeroizing::new(STANDARD.decode(data).map_err(|_| keepass_import::KeepassError::Unreadable.to_string())?);
    let key = match key_file {
        Some(key) => Some(zeroize::Zeroizing::new(STANDARD.decode(key).map_err(|_| "The key file couldn't be read.".to_owned())?)),
        None => None,
    };
    keepass_import::read(&bytes, password, key.as_deref().map(Vec::as_slice)).map_err(|error| error.to_string())
}

#[tauri::command]
async fn keepass_preview(data: String, password: String, key_file: Option<String>) -> Result<keepass_import::Summary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut password = password;
        let plan = open_keepass(&data, &password, key_file.as_deref());
        password.zeroize();
        Ok(plan?.summary())
    })
    .await
    .map_err(|_| "The KeePass file couldn't be read.".to_owned())?
}

#[tauri::command]
async fn keepass_import(data: String, password: String, key_file: Option<String>, state: State<'_, ManagedState>) -> Result<keepass_import::Summary, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut password = password;
        let plan = open_keepass(&data, &password, key_file.as_deref());
        password.zeroize();
        let plan = plan?;
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let summary = app.unlocked.as_mut().ok_or("Unlock the vault first".to_owned())?
            .import_keepass(&plan).map_err(public_vault_error)?;
        activity::log(Level::Success, Category::Items, format!("Imported {} logins, {} codes and {} notes from KeePass", summary.logins, summary.codes, summary.notes));
        Ok(summary)
    })
    .await
    .map_err(|_| "The import stopped unexpectedly.".to_owned())?
}

// Website icons: captured by the extension, kept on this PC only (site_icons.rs). The page
// shows an icon from this list, or a built-in one, or the letter avatar.

fn site_icons_view(state: &ManagedState) -> Result<site_icons::View, String> {
    let enabled = site_icons::enabled();
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let icons = match app.unlocked.as_mut() {
        Some(vault) if enabled => site_icons::data_urls(vault.connection()).map_err(|_| "Could not read the website icons.")?,
        _ => Default::default(),
    };
    Ok(site_icons::View { enabled, icons })
}

#[tauri::command]
fn site_icons(state: State<'_, ManagedState>) -> Result<site_icons::View, String> {
    site_icons_view(state.inner())
}

#[tauri::command]
fn set_site_icons(enabled: bool, state: State<'_, ManagedState>) -> Result<site_icons::View, String> {
    site_icons::set_enabled(enabled).map_err(|_| "Could not save the setting.".to_owned())?;
    if !enabled {
        // A locked vault keeps its icons until the next unlock, which clears them.
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        if let Some(vault) = app.unlocked.as_mut() {
            site_icons::clear(vault.connection()).map_err(|_| "Could not delete the website icons.")?;
        }
    }
    site_icons_view(state.inner())
}

// Sign-in methods ("Sign in with Google" and the account): remembered by the extension after the user
// agrees, kept in the vault on this PC (sign_ins.rs). The Sign-ins page lists, edits and deletes them.

fn sign_in_answer(site: String, methods: Vec<sign_ins::SignIn>) -> browser::SignInsAnswer {
    browser::SignInsAnswer {
        site,
        methods: methods
            .into_iter()
            .map(|row| browser::SignInMethod { provider: row.provider, account: row.account, last_used_at: row.last_used_at, use_count: row.use_count })
            .collect(),
    }
}

fn sign_ins_view(state: &ManagedState) -> Result<sign_ins::View, String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
    sign_ins::view(vault.connection(), sign_ins::enabled()).map_err(|_| "Could not read the sign-in methods.".to_owned())
}

#[tauri::command]
fn sign_ins(state: State<'_, ManagedState>) -> Result<sign_ins::View, String> {
    sign_ins_view(state.inner())
}

#[tauri::command]
fn set_sign_ins(enabled: bool, state: State<'_, ManagedState>) -> Result<sign_ins::View, String> {
    sign_ins::set_enabled(enabled).map_err(|_| "Could not save the setting.".to_owned())?;
    sign_ins_view(state.inner())
}

#[tauri::command]
fn delete_sign_in(id: String, state: State<'_, ManagedState>) -> Result<sign_ins::View, String> {
    {
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
        if sign_ins::delete(vault.connection(), &id).map_err(|_| "Could not delete the sign-in method.")? {
            activity::log(Level::Info, Category::Items, "Deleted a remembered sign-in method");
        }
        let identity_store = app.store.identity_store();
        if let Some(vault) = app.unlocked.as_mut() {
            sign_in_sync::flush_installed(vault, &identity_store);
        }
    }
    sign_ins_view(state.inner())
}

#[tauri::command]
fn edit_sign_in(id: String, account: Option<String>, state: State<'_, ManagedState>) -> Result<sign_ins::View, String> {
    {
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
        sign_ins::set_account(vault.connection(), &id, account.as_deref()).map_err(|refused| match refused {
            sign_ins::Refused::BadAccount => format!("Use at most {} characters, without line breaks.", sign_ins::MAX_ACCOUNT_CHARS),
            sign_ins::Refused::Missing => "This sign-in method was deleted.".to_owned(),
            _ => "Could not save the account.".to_owned(),
        })?;
        let identity_store = app.store.identity_store();
        if let Some(vault) = app.unlocked.as_mut() {
            sign_in_sync::flush_installed(vault, &identity_store);
        }
    }
    sign_ins_view(state.inner())
}

#[tauri::command]
fn clear_site_icons(state: State<'_, ManagedState>) -> Result<site_icons::View, String> {
    {
        let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
        let vault = app.unlocked.as_mut().ok_or("Unlock the vault first".to_owned())?;
        site_icons::clear(vault.connection()).map_err(|_| "Could not delete the website icons.")?;
    }
    site_icons_view(state.inner())
}

// Previous passwords and Recently deleted: kept on this PC only (local_recovery.rs).

#[tauri::command]
fn previous_passwords(entry_id: String, state: State<'_, ManagedState>) -> Result<Vec<local_recovery::PreviousPassword>, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked.as_ref().ok_or("Unlock the vault first".to_owned())?
        .previous_passwords(&entry_id).map_err(public_vault_error)
}

#[tauri::command]
fn clear_previous_passwords(entry_id: String, state: State<'_, ManagedState>) -> Result<(), String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked.as_ref().ok_or("Unlock the vault first".to_owned())?
        .clear_previous_passwords(&entry_id).map_err(public_vault_error)?;
    activity::log(Level::Info, Category::Items, "Cleared previous passwords of a login");
    Ok(())
}

#[tauri::command]
fn list_trash(state: State<'_, ManagedState>) -> Result<Vec<local_recovery::TrashedItem>, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked.as_ref().ok_or("Unlock the vault first".to_owned())?
        .trashed_items().map_err(public_vault_error)
}

#[tauri::command]
fn restore_trashed(id: String, state: State<'_, ManagedState>) -> Result<serde_json::Value, String> {
    let mut app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let restored = app.unlocked.as_mut().ok_or("Unlock the vault first".to_owned())?
        .restore_trashed(&id).map_err(public_vault_error)?;
    activity::log(Level::Success, Category::Items, "Restored an item from Recently deleted");
    Ok(restored)
}

#[tauri::command]
fn forget_trashed(id: String, state: State<'_, ManagedState>) -> Result<(), String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked.as_ref().ok_or("Unlock the vault first".to_owned())?
        .forget_trashed(&id).map_err(public_vault_error)?;
    activity::log(Level::Info, Category::Items, "Deleted an item for good");
    Ok(())
}

#[tauri::command]
fn empty_trash(state: State<'_, ManagedState>) -> Result<(), String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    app.unlocked.as_ref().ok_or("Unlock the vault first".to_owned())?
        .empty_trash().map_err(public_vault_error)?;
    activity::log(Level::Info, Category::Items, "Emptied Recently deleted");
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

/// "passkey_mark": ids of the logins with a passkey for the same account, for the mark in the list.
#[tauri::command]
fn passkey_login_ids(state: State<'_, ManagedState>) -> Result<Vec<String>, String> {
    let app = state.lock().map_err(|_| "Vault state is unavailable")?;
    let mut ids: Vec<String> = app
        .unlocked
        .as_ref()
        .ok_or("Unlock the vault first".to_owned())?
        .logins_with_passkeys()
        .map_err(public_vault_error)?
        .into_iter()
        .collect();
    ids.sort();
    Ok(ids)
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
        VaultError::UnsupportedBootstrap(_) => {
            "A newer version of Nuvori saved this vault. Update Nuvori to open it.".to_owned()
        }
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
        VaultError::InUse => START_FRESH_IN_USE.to_owned(),
        other => {
            activity::diagnostic(Category::Vault, "Vault operation failed", &other);
            "The vault could not be opened. Check its local storage.".to_owned()
        }
    }
}

// Synced appearance commands. The rules live in `appearance.rs`.

/// Works while the vault is locked: the unlock screen uses it.
#[tauri::command]
fn get_appearance() -> Result<appearance::View, String> {
    appearance::installed().map(appearance::AppearanceStore::view).ok_or_else(|| "Appearance is unavailable".to_owned())
}

#[tauri::command]
async fn set_appearance(accent: String, surface: String, state: State<'_, ManagedState>) -> Result<appearance::View, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || appearance::set_from_ui(&state, &accent, &surface))
        .await
        .map_err(|_| "The appearance could not be saved".to_owned())?
}

// Auto-type commands. The shortcut and the typing live in `auto_type.rs`.

#[tauri::command]
fn auto_type_status(auto_type: State<'_, auto_type::AutoType>) -> auto_type::Status {
    auto_type.status()
}

#[tauri::command]
fn set_auto_type(
    app: AppHandle,
    auto_type: State<'_, auto_type::AutoType>,
    enabled: bool,
    preset: Option<String>,
    press_enter: Option<bool>,
) -> Result<auto_type::Status, String> {
    auto_type.change(&app, enabled, preset.as_deref(), press_enter)
}

/// The window the shortcut recorded, while the picker may still type into it.
#[tauri::command]
fn auto_type_pending(auto_type: State<'_, auto_type::AutoType>) -> Option<auto_type::TargetInfo> {
    auto_type.pending()
}

#[tauri::command]
fn auto_type_cancel(auto_type: State<'_, auto_type::AutoType>) {
    auto_type.cancel();
}

/// Types the login's username and password into the recorded window. The vault lock is
/// released before typing starts; the copies are wiped afterwards.
#[tauri::command]
async fn auto_type_login(id: String, app: AppHandle, state: State<'_, ManagedState>) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (mut username, mut password) = {
            let app_state = state.lock().map_err(|_| "Vault state is unavailable")?;
            let vault = app_state.unlocked.as_ref().ok_or("Unlock the vault first".to_owned())?;
            let entries = vault.list_entries().map_err(public_vault_error)?;
            let entry = entries.iter().find(|entry| entry["id"] == id.as_str() && entry["type"] == "PASSWORD")
                .ok_or("That login no longer exists.".to_owned())?;
            (entry["primaryValue"].as_str().unwrap_or_default().to_owned(), entry["secondaryValue"].as_str().unwrap_or_default().to_owned())
        };
        let result = app.state::<auto_type::AutoType>().type_login(&app, &username, &password);
        username.zeroize();
        password.zeroize();
        let target = result?;
        activity::log(Level::Success, Category::Items, format!("Auto-typed a login into {target}"));
        Ok(())
    })
    .await
    .map_err(|_| "Auto-type stopped unexpectedly.".to_owned())?
}

// Quick search shortcut commands. The shortcut itself lives in `quick_search.rs`.

#[tauri::command]
fn quick_search_status(search: State<'_, quick_search::QuickSearch>) -> quick_search::Status {
    search.status()
}

#[tauri::command]
fn set_quick_search(
    app: AppHandle,
    search: State<'_, quick_search::QuickSearch>,
    enabled: bool,
    preset: Option<String>,
) -> Result<quick_search::Status, String> {
    search.change(&app, enabled, preset.as_deref())
}

/// The unlocked main window asks whether the shortcut was pressed recently. Answers yes once.
#[tauri::command]
fn take_quick_search_request(search: State<'_, quick_search::QuickSearch>) -> bool {
    search.take_request()
}

/// Hides the main window to the tray (the shortcut pressed again while the palette is open).
#[tauri::command]
fn hide_main_window(app: AppHandle) {
    if let Some(window) = app.get_webview_window(desktop::MAIN_WINDOW) {
        let _ = window.hide();
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
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
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
            install_marker::install(&directory);
            if !VaultStore::new(directory.clone()).is_initialized() {
                // No vault to welcome back: this install is the one that will create it.
                install_marker::record_current();
            }
            // Installed and Store builds connect the browser extension by themselves. A
            // development build leaves the registration alone; use Settings to connect it.
            browsers::install(&directory);
            browser_ipc::set_browser_hooks(browser_ipc::BrowserHooks {
                seen: Box::new(|id| {
                    if let Some(store) = browsers::installed() {
                        store.note_seen(id);
                    }
                }),
                ask_at_start: Box::new(|id| browsers::installed().is_none_or(|store| store.ask_at_start(id))),
            });
            if !cfg!(debug_assertions) {
                std::thread::spawn(|| log_browser_connect(browser_setup::connect(), false));
            }
            let packaged_helper = app
                .path()
                .resource_dir()?
                .join("pairing/Nuvori.PairingHelper.exe");
            // Only a development build may fall back to the helper in the source tree. A release
            // build never runs a program from a path baked in on the build machine (a folder that
            // could exist, and be writable, on the user's PC); without the packaged helper,
            // pairing reports that the helper is missing.
            #[cfg(debug_assertions)]
            let helper_path = if packaged_helper.is_file() {
                packaged_helper
            } else {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pairing-helper/publish/Nuvori.PairingHelper.exe")
            };
            #[cfg(not(debug_assertions))]
            let helper_path = packaged_helper;
            app.manage(Arc::new(PairingController {
                progress: Mutex::new(PairingProgress::default()),
                approval: Condvar::new(),
                helper_path,
            }));
            app.manage(Arc::new(Mutex::new(AppState {
                store: VaultStore::new(directory.clone()),
                unlocked: None,
            })));
            app.manage(Arc::new(BrowserIpcServer::start()?));
            let auto_lock = auto_lock::AutoLock::new(directory.clone());
            app.manage(auto_lock.clone());
            let activity_source = auto_lock.clone();
            browser_ipc::set_user_activity_hook(move || activity_source.touch());
            let watched = app.state::<ManagedState>().inner().clone();
            let lock_handle = app.handle().clone();
            auto_lock.start(
                // A vault busy with a sync is checked again on the next tick.
                move || watched.try_lock().ok().map(|state| state.unlocked.is_some()),
                move |reason| auto_lock_vault(&lock_handle, reason),
            );
            app.manage(Arc::new(SyncController::default()));
            app.manage(quick_search::QuickSearch::new(directory.clone()));
            app.state::<quick_search::QuickSearch>().apply(app.handle());
            let icons_handle = app.handle().clone();
            site_icons::install(&directory, move || {
                let _ = icons_handle.emit(site_icons::EVENT, ());
            });
            let sign_ins_handle = app.handle().clone();
            sign_ins::install(&directory, move || {
                let _ = sign_ins_handle.emit(sign_ins::EVENT, ());
            });
            app.manage(auto_type::AutoType::new(directory.clone()));
            app.state::<auto_type::AutoType>().apply(app.handle());
            let handle = app.handle().clone();
            appearance::install(appearance::AppearanceStore::with_notify(&directory, move |view| {
                let _ = handle.emit(appearance::EVENT, view);
            }));
            browser_ipc::set_appearance_source(|| {
                appearance::installed().map(|store| { let stored = store.load(); (stored.accent, stored.surface) }).unwrap_or_default()
            });
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
            // M14: the tray icon says so while Google Drive needs a sign-in the user was told about.
            let handle = app.handle().clone();
            let _ = app.state::<Arc<SyncController>>().cloud.sign_in_alert
                .set(Box::new(move |needed| desktop::show_sign_in_needed(&handle, needed)));
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
            site_icons,
            set_site_icons,
            clear_site_icons,
            sign_ins,
            set_sign_ins,
            delete_sign_in,
            edit_sign_in,
            auto_type_status,
            set_auto_type,
            auto_type_pending,
            auto_type_cancel,
            auto_type_login,
            keepass_preview,
            keepass_import,
            previous_passwords,
            clear_previous_passwords,
            list_trash,
            restore_trashed,
            forget_trashed,
            empty_trash,
            sync_now,
            sync_status,
            configure_sync,
            set_sync_schedule,
            set_sync_on_open,
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
            start_fresh,
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
            passkey_login_ids,
            delete_passkey,
            activity_log,
            clear_activity_log,
            browser_status,
            connect_browsers,
            list_browsers,
            set_browser,
            build_status,
            open_windows_settings,
            open_note_link,
            cloud_status,
            cloud_connect,
            cloud_cancel_connect,
            cloud_disconnect,
            list_conflicts,
            resolve_conflict,
            photo_sync_status,
            membership_status,
            mark_manager_lost,
            leave_group,
            dismiss_removed_notice,
            show_main_window,
            quick_search_status,
            set_quick_search,
            auto_lock_status,
            set_auto_lock,
            note_user_activity,
            copy_secret,
            clear_secret_clipboard,
            take_quick_search_request,
            get_appearance,
            set_appearance,
            hide_main_window,
            close_unlock_prompt,
            pending_card_code,
            approve_card_code,
            decline_card_code
        ])
        .build(tauri::generate_context!())
        .expect("failed to run Nuvori");
    app.run(|app, event| {
        // Opening Nuvori syncs on its own: the main window coming to the front asks for one pass.
        if let tauri::RunEvent::WindowEvent { label, event: tauri::WindowEvent::Focused(true), .. } = &event
            && label == desktop::MAIN_WINDOW
        {
            app.state::<Arc<SyncController>>().request_open_pass();
        }
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
mod sign_in_notice_tests {
    use super::*;

    #[test]
    fn the_user_is_told_after_three_sign_in_failures_in_a_row_at_most_once_a_day() {
        let cloud = CloudController::default();
        let start = Instant::now();
        assert_eq!(cloud.note_sign_in(Some(true), start), None);
        assert_eq!(cloud.note_sign_in(None, start), None, "a dropped link neither counts nor ends the run");
        assert_eq!(cloud.note_sign_in(Some(true), start), None);
        assert_eq!(cloud.note_sign_in(Some(true), start), Some(true), "the third in a row tells the user");
        assert_eq!(cloud.note_sign_in(Some(true), start + Duration::from_secs(60 * 60)), None, "not again the same day");
        assert_eq!(cloud.note_sign_in(Some(true), start + SIGN_IN_NOTICE_GAP), Some(true), "again a day later");
        assert_eq!(cloud.note_sign_in(Some(false), start + SIGN_IN_NOTICE_GAP), Some(false), "a good pass clears it");
        assert_eq!(cloud.note_sign_in(Some(false), start + SIGN_IN_NOTICE_GAP), None);
        let later = start + SIGN_IN_NOTICE_GAP;
        assert_eq!(cloud.note_sign_in(Some(true), later), None, "the count starts over");
        assert_eq!(cloud.note_sign_in(Some(true), later), None);
        assert_eq!(cloud.note_sign_in(Some(true), later), Some(true));
    }
}

#[cfg(test)]
mod start_fresh_tests {
    use super::*;
    use crate::install_marker::{Install, InstallMarker};

    const PASSWORD: &str = "synthetic-test-password";

    /// A locked vault with a note, a photo blob folder, a Hello file and a device identity, as an
    /// earlier install left it.
    fn earlier_vault() -> (PathBuf, AppState, identity::DeviceIdentity) {
        let directory = std::env::temp_dir().join(format!("nuvori-start-fresh-{}", uuid::Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create(PASSWORD).unwrap();
        vault.save_note(None, "Quartz ledger", "kept only here", Some(vec![])).unwrap();
        drop(vault);
        let old = store.identity_store().get_or_create().unwrap();
        std::fs::create_dir_all(directory.join("photo-blobs")).unwrap();
        std::fs::write(directory.join("photo-blobs").join("blob"), b"photo").unwrap();
        std::fs::write(directory.join("hello-unlock-v1.bin"), b"sealed").unwrap();
        InstallMarker::new(&directory, Install { id: "exe:earlier".into(), installed_at: 1 }).record().unwrap();
        (directory, AppState { store, unlocked: None }, old)
    }

    #[test]
    fn a_vault_from_an_earlier_install_is_welcomed_back_until_this_install_opens_it() {
        let (directory, mut app, _) = earlier_vault();
        let this_install = InstallMarker::new(&directory, Install { id: "exe:now".into(), installed_at: 2 });
        assert!(app.welcome_back_for(Some(&this_install)));
        let snapshot = app.snapshot().unwrap();
        assert_eq!(snapshot.vault_state, "locked");
        let now = activity::now_millis() as i64;
        assert!(snapshot.last_used_at > now - 600_000 && snapshot.last_used_at <= now + 1_000, "a file time, not vault contents");
        app.unlocked = Some(app.store.unlock(PASSWORD).unwrap());
        assert!(!app.welcome_back_for(Some(&this_install)), "never while unlocked");
        assert_eq!(app.snapshot().unwrap().last_used_at, 0);
        this_install.record().unwrap();
        app.unlocked = None;
        assert!(!app.welcome_back_for(Some(&this_install)), "this install opened it");
        drop(app);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn starting_fresh_deletes_only_this_pcs_vault_files_without_the_password() {
        let (directory, mut app, old) = earlier_vault();
        std::fs::write(directory.join("diagnostics.log"), b"kept").unwrap();
        let snapshot = app.start_fresh().unwrap();
        assert_eq!(snapshot.vault_state, "notConfigured");
        assert!(!snapshot.welcome_back);
        for name in ["vault.db", "vault.db-wal", "vault-key-v1.json", "device-identity-v1.json", "hello-unlock-v1.bin", "photo-blobs"] {
            assert!(!directory.join(name).exists(), "{name} is deleted");
        }
        assert!(directory.join("diagnostics.log").exists(), "files outside the vault stay");
        let events = activity::global().recent(None);
        assert!(events.iter().any(|event| event.message.starts_with("Started fresh on this PC") && event.level == Level::Warning));
        for event in &events {
            for secret in ["Quartz", "kept only here", PASSWORD] {
                assert!(!event.message.contains(secret), "{secret} leaked into the activity log");
            }
        }
        // Next: a new vault with a new device identity, which a phone can pair as a new device.
        let mut vault = app.store.create("another-long-password").unwrap();
        assert!(vault.list_notes().unwrap().is_empty());
        assert!(!vault.is_enrolled().unwrap());
        vault.save_note(None, "New", "Body", Some(vec![])).unwrap();
        let new = app.store.identity_store().get_or_create().unwrap();
        assert_ne!(new.device_id, old.device_id);
        assert_ne!(new.public_key, old.public_key);
        drop(vault);
        drop(app);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn starting_fresh_never_runs_while_the_vault_is_unlocked() {
        let (directory, mut app, _) = earlier_vault();
        app.unlocked = Some(app.store.unlock(PASSWORD).unwrap());
        assert_eq!(app.start_fresh().err().unwrap(), START_FRESH_UNLOCKED);
        let vault = app.unlocked.as_ref().unwrap();
        assert_eq!(vault.list_notes().unwrap()[0].title, "Quartz ledger", "nothing was deleted");
        assert!(directory.join("device-identity-v1.json").exists() && directory.join("photo-blobs").exists());
        drop(app);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn starting_fresh_stops_when_another_program_has_the_database_open() {
        let (directory, mut app, _) = earlier_vault();
        // Another process (a second Nuvori, a backup tool) with the database open.
        let other = VaultStore::new(&directory).unlock(PASSWORD).unwrap();
        assert_eq!(app.start_fresh().err().unwrap(), START_FRESH_IN_USE);
        assert!(app.store.is_initialized());
        for name in ["vault.db", "device-identity-v1.json", "hello-unlock-v1.bin", "photo-blobs"] {
            assert!(directory.join(name).exists(), "{name} stays");
        }
        drop(other);
        app.start_fresh().unwrap();
        assert!(!app.store.is_initialized());
        drop(app);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
mod pre_lock_tests {
    use super::*;

    #[test]
    fn a_drive_pass_runs_before_an_idle_or_windows_lock_but_not_before_sleep() {
        use auto_lock::Reason::{Idle, SessionLocked, Suspend};
        assert!(pass_before_lock(Idle, 300, true));
        assert!(pass_before_lock(SessionLocked, 15, true));
        assert!(!pass_before_lock(Suspend, 300, true));
        assert!(!pass_before_lock(Idle, 0, true), "Drive checked only on Sync now");
        assert!(!pass_before_lock(SessionLocked, 300, false), "Drive not connected");
        assert!(PRE_LOCK_DRIVE_WAIT <= Duration::from_secs(30));
    }
}

#[cfg(test)]
mod activity_tests {
    use super::*;

    /// L1: a pass that stopped at its session cap says that sync continues, not that it failed.
    #[test]
    fn a_pass_with_more_remaining_says_sync_continues() {
        let report = lan_sync::SyncReport { sent: 3, received: 3200, peers_checked: 1, more_remain: true, ..Default::default() };
        assert_eq!(sync_summary(&report),
            "Sent 3 changes and received 3200. Checked 1 devices; 0 waiting to connect. More changes remain, and sync continues.");
        assert!(!sync_summary(&lan_sync::SyncReport { more_remain: false, ..report }).contains("remain"));
    }

    #[test]
    fn only_web_and_mail_links_in_notes_can_be_opened() {
        for link in ["https://example.com", "http://example.com/a?b=1#c", "mailto:someone@example.com", "HTTPS://EXAMPLE.COM"] {
            assert!(note_link_allowed(link), "{link}");
        }
        for link in ["", "javascript:alert(1)", "file:///C:/Windows/system32/calc.exe", "ms-settings:privacy", "https://",
            "https://bank.example@evil.example/", "https://a b.example", "https://example.com/\u{0}", "mailto:", "\\\\server\\share"] {
            assert!(!note_link_allowed(link), "{link}");
        }
        assert!(!note_link_allowed(&format!("https://example.com/{}", "a".repeat(2048))));
    }

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
