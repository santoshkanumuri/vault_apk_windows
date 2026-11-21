use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    os::windows::io::FromRawHandle,
    path::Path,
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    collections::VecDeque,
    mem::ManuallyDrop,
    os::windows::io::{AsRawHandle, RawHandle},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
        System::{
            IO::{CancelIoEx, CancelSynchronousIo},
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
                PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
                PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            },
            Threading::{
                OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW,
            },
            Registry::{HKEY_CURRENT_USER, RRF_RT_REG_SZ, RegGetValueW},
        },
    },
    core::{PCWSTR, PWSTR, w},
};
use serde::Serialize;
use zeroize::Zeroize;
use sha2::{Digest, Sha256};

use crate::browser::{
    BROWSER_PROTOCOL_VERSION, BrowserAction, BrowserRequest, BrowserResponse, CardDetails,
    CredentialChoice, FilledItem, ItemKind, PendingDetails, PendingLogin, ProfileDetails, SelectedCredential,
    canonical_https_origin, valid_capture_username, valid_card_capture, valid_login_title,
    valid_profile_capture,
};
use crate::{
    activity::{self, Category, Level},
    dpapi,
};

const PIPE_NAME: &str = r"\\.\pipe\nuvori-browser-v2";
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const MAX_CANDIDATES: usize = 200;
/// "all_logins": the most logins one listing of every login returns.
const MAX_ALL_CANDIDATES: usize = 1_000;
/// Largest decoded site icon (site_icons.rs `MAX_PNG_BYTES` checks the same limit).
const MAX_ICON_BYTES: usize = 32 * 1024;
const SELECTION_TTL: Duration = Duration::from_secs(30);
/// How long the user has to approve a card security code in Nuvori.
const CVV_TTL: Duration = Duration::from_secs(120);
/// One connection may take at most this long; a stalled client is disconnected after it.
#[cfg(not(test))]
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
/// Connections handled at once; more are closed immediately.
const MAX_ACTIVE_CONNECTIONS: usize = 8;
/// Login checks (review or save) per site per minute, so a page cannot use their outcomes as an oracle.
const LOGIN_CHECKS_PER_MINUTE: usize = 10;

/// Opens app windows for `unlock_prompt` and `show_app`. Called on a pipe thread with the request
/// and whether the vault is unlocked; it must return quickly.
type WindowHandler = Box<dyn Fn(&BrowserAction, bool) + Send + Sync>;
static WINDOW_HANDLER: OnceLock<WindowHandler> = OnceLock::new();

/// Set once by the app at startup. Without a handler, window requests only report the vault state.
pub fn set_window_handler(handler: impl Fn(&BrowserAction, bool) + Send + Sync + 'static) {
    let _ = WINDOW_HANDLER.set(Box::new(handler));
}

/// What the app does with the browser id that the native host adds to each request.
/// `seen` records that the browser used Nuvori; `ask_at_start` answers whether `unlock_prompt`
/// with `startup` may open a window for that browser. Without hooks (the native host, tests)
/// every browser is asked.
pub struct BrowserHooks {
    pub seen: Box<dyn Fn(&str) + Send + Sync>,
    pub ask_at_start: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

static BROWSER_HOOKS: OnceLock<BrowserHooks> = OnceLock::new();

pub fn set_browser_hooks(hooks: BrowserHooks) {
    let _ = BROWSER_HOOKS.set(hooks);
}

/// A browser id: lower case exe name without ".exe", at most 40 of `[a-z0-9_-]`.
pub fn valid_browser_id(id: &str) -> bool {
    (1..=40).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_')
}

/// The id for a program's exe file name ("Zen.exe" -> "zen"). Opera starts through `launcher.exe`.
pub fn browser_id_from_exe(exe: &str) -> Option<String> {
    let name = exe.rsplit(['\\', '/']).next().unwrap_or(exe).to_ascii_lowercase();
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    if stem == "launcher" {
        return Some("opera".to_owned());
    }
    let id: String = stem.chars().map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' { c } else { '-' }).take(40).collect();
    valid_browser_id(&id).then_some(id)
}

/// One running process, as the process snapshot lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent: u32,
    pub exe: String,
}

/// Programs that sit between a browser and its native host: Chrome starts hosts through cmd.exe.
const HOST_RELAYS: [&str; 3] = ["cmd.exe", "conhost.exe", "nuvori-native-host.exe"];

/// The browser that started process `pid`: walks up at most 4 parents, skips the relays, and
/// names the first program left.
pub fn browser_of_chain(table: &[ProcessEntry], pid: u32) -> Option<String> {
    let mut current = table.iter().find(|entry| entry.pid == pid)?.parent;
    for _ in 0..4 {
        let entry = table.iter().find(|entry| entry.pid == current)?;
        let exe = entry.exe.to_ascii_lowercase();
        if !HOST_RELAYS.contains(&exe.as_str()) {
            return browser_id_from_exe(&exe);
        }
        current = entry.parent;
    }
    None
}

/// A snapshot of the running processes (name and parent only).
pub fn process_table() -> Vec<ProcessEntry> {
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else { return Vec::new() };
    let mut table = Vec::new();
    let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while more {
        let length = entry.szExeFile.iter().position(|unit| *unit == 0).unwrap_or(entry.szExeFile.len());
        table.push(ProcessEntry { pid: entry.th32ProcessID, parent: entry.th32ParentProcessID, exe: String::from_utf16_lossy(&entry.szExeFile[..length]) });
        more = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }
    unsafe {
        let _ = CloseHandle(snapshot);
    }
    table
}

/// The browser that started this process, for the native host.
pub fn calling_browser() -> Option<String> {
    browser_of_chain(&process_table(), std::process::id())
}

/// `hand_over`: `allowed` checks the calling process ID; `close` ends this copy of the app after
/// the answer is written. Without a handler (the native host), the request is refused.
struct HandOverHandler {
    allowed: Box<dyn Fn(u32) -> bool + Send + Sync>,
    close: Box<dyn Fn() + Send + Sync>,
}

static HAND_OVER_HANDLER: OnceLock<HandOverHandler> = OnceLock::new();

pub fn set_hand_over_handler(
    allowed: impl Fn(u32) -> bool + Send + Sync + 'static,
    close: impl Fn() + Send + Sync + 'static,
) {
    let _ = HAND_OVER_HANDLER.set(HandOverHandler { allowed: Box::new(allowed), close: Box::new(close) });
}

#[derive(Clone, Debug)]
pub struct LoginCandidate {
    pub id: String,
    pub title: String,
    pub username: String,
    /// Saved for another page of the same site (listing and filling only).
    pub related: bool,
    /// "passkey_mark": a passkey for the same account is saved too (logins only).
    pub passkey: bool,
    /// A card's own color (opaque ARGB), so the suggestion can show the card as it looks in Nuvori.
    pub color: Option<u64>,
    /// "all_logins": the host of the login's saved website ("" when none).
    pub site: Option<String>,
    /// An address's values for its suggestion row. Listed for addresses only.
    pub preview: Option<ProfileDetails>,
}

pub trait BrowserCredentialProvider: Send + Sync + 'static {
    fn query_credentials(&self, origin: &str) -> Result<Vec<LoginCandidate>, BrowserIpcError>;

    fn load_selected_credential(
        &self,
        id: &str,
        origin: &str,
    ) -> Result<Option<SelectedCredential>, BrowserIpcError>;

    /// `title` is the requested name ("login_title"); `None` keeps the host-based default.
    fn save_new_login(&self, origin: &str, username: &str, password: &str, title: Option<&str>) -> Result<bool, BrowserIpcError>;
    fn update_login(&self, origin: &str, id: &str, username: &str, password: &str, expected_hash: &[u8; 32]) -> Result<(), BrowserIpcError>;
    fn review_login(&self, origin: &str, username: &str, password: &str) -> Result<bool, BrowserIpcError>;

    /// "all_logins": every saved login, for the user to choose from on any site.
    fn query_all_credentials(&self) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
        Ok(Vec::new())
    }
    /// "all_logins": one login the user chose from that list, whatever site it is saved for.
    fn load_any_credential(&self, _id: &str) -> Result<Option<SelectedCredential>, BrowserIpcError> {
        Ok(None)
    }

    /// "cards" / "profiles" / "codes": (id, title, subtitle) for `kind`. `all` lists every code.
    fn query_items(&self, _kind: ItemKind, _origin: &str, _all: bool) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
        Ok(Vec::new())
    }
    /// One item. A card includes its security code; the server releases that only after approval.
    fn load_item(&self, _kind: ItemKind, _id: &str, _origin: &str) -> Result<Option<FilledItem>, BrowserIpcError> {
        Ok(None)
    }
    /// "save_details": true when a captured card or address is not saved yet.
    fn review_details(&self, _pending: &PendingDetails) -> Result<bool, BrowserIpcError> {
        Err(BrowserIpcError::SaveFailed)
    }
    /// Saves a captured card or address as a new item; false when already saved.
    fn save_details(&self, _pending: &PendingDetails, _title: Option<&str>) -> Result<bool, BrowserIpcError> {
        Err(BrowserIpcError::SaveFailed)
    }
    /// "query_credentials": true when the app wants this origin's icon (site_icons.rs `wanted`).
    fn icon_wanted(&self, _origin: &str) -> Result<bool, BrowserIpcError> {
        Ok(false)
    }
    /// "save_site_icon": keeps a PNG for the origin's site. `InvalidRequest` means the app
    /// refused it: setting off, no matching login or passkey, or not a valid small PNG.
    fn save_site_icon(&self, _origin: &str, _png: &[u8]) -> Result<(), BrowserIpcError> {
        Err(BrowserIpcError::InvalidRequest)
    }
}

#[derive(Debug, Error)]
pub enum BrowserIpcError {
    #[error("browser IPC failed: {0}")]
    Io(#[from] io::Error),
    #[error("browser IPC JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Windows named pipe failed: {0}")]
    Windows(#[from] windows::core::Error),
    #[error("secure random generation failed: {0}")]
    Random(String),
    #[error("browser IPC request is invalid")]
    InvalidRequest,
    #[error("vault is locked")]
    VaultLocked,
    #[error("a different password is already saved for this account")]
    LoginConflict,
    #[error("the Windows vault could not save this login")]
    SaveFailed,
    #[error("the browser pipe is not served by the Nuvori app")]
    UntrustedServer,
}

/// What a selection token may release. A card token never releases a login, and so on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantKind {
    Login,
    /// "all_logins": a login the user picked from every saved login, for a site it is not saved for.
    /// It fills only; it never updates the login.
    AnyLogin,
    Item(ItemKind),
    Cvv,
}

/// A card security code waits for the user to approve it in a Nuvori window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Approval {
    NotAsked,
    Waiting,
    Approved,
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CvvState {
    Missing,
    Waiting,
    Approved,
    Denied,
}

#[derive(Clone)]
struct SelectionGrant {
    record_id: String,
    origin: String,
    expires: Instant,
    password_hash: Option<[u8; 32]>,
    kind: GrantKind,
    approval: Approval,
}

#[derive(Default)]
struct SelectionGrants {
    grants: HashMap<String, SelectionGrant>,
    login_checks: HashMap<String, VecDeque<Instant>>,
}

impl SelectionGrants {
    fn issue(&mut self, record_id: String, origin: &str) -> Result<String, BrowserIpcError> {
        self.issue_kind(record_id, origin, GrantKind::Login)
    }

    fn issue_kind(&mut self, record_id: String, origin: &str, kind: GrantKind) -> Result<String, BrowserIpcError> {
        self.grants
            .retain(|_, grant| grant.expires > Instant::now());
        if self.grants.len() >= 6_000 {
            return Err(BrowserIpcError::InvalidRequest);
        }
        let mut token_bytes = [0_u8; 32];
        getrandom::fill(&mut token_bytes)
            .map_err(|error| BrowserIpcError::Random(error.to_string()))?;
        let token = hex::encode(token_bytes);
        token_bytes.zeroize();
        self.grants.insert(
            token.clone(),
            SelectionGrant {
                record_id,
                origin: origin.to_owned(),
                expires: Instant::now() + if kind == GrantKind::Cvv { CVV_TTL } else { SELECTION_TTL },
                password_hash: None,
                kind,
                approval: Approval::NotAsked,
            },
        );
        Ok(token)
    }

    fn consume_item(&mut self, token: &str, record_id: &str, origin: &str, kind: ItemKind) -> bool {
        let Some(grant) = self.grants.remove(token) else {
            return false;
        };
        grant.expires > Instant::now() && grant.record_id == record_id && grant.origin == origin
            && grant.kind == GrantKind::Item(kind)
    }

    fn cvv_grant(&mut self, token: &str, record_id: &str, origin: &str) -> Option<&mut SelectionGrant> {
        let live = self.grants.get(token).is_some_and(|grant| grant.expires > Instant::now()
            && grant.kind == GrantKind::Cvv && grant.record_id == record_id && grant.origin == origin);
        if !live {
            self.grants.remove(token);
            return None;
        }
        self.grants.get_mut(token)
    }

    /// Start (or keep) waiting for the user's approval of this security code.
    fn ask_cvv(&mut self, token: &str, record_id: &str, origin: &str) -> bool {
        let Some(grant) = self.cvv_grant(token, record_id, origin) else { return false };
        if grant.approval == Approval::NotAsked {
            grant.approval = Approval::Waiting;
            grant.expires = Instant::now() + CVV_TTL;
        }
        grant.approval == Approval::Waiting
    }

    /// Approved or denied grants are used up by this call. Asking before `ask_cvv` keeps the grant.
    fn cvv_state(&mut self, token: &str, record_id: &str, origin: &str) -> CvvState {
        let state = match self.cvv_grant(token, record_id, origin).map(|grant| grant.approval) {
            None | Some(Approval::NotAsked) => return CvvState::Missing,
            Some(Approval::Waiting) => return CvvState::Waiting,
            Some(Approval::Approved) => CvvState::Approved,
            Some(Approval::Denied) => CvvState::Denied,
        };
        self.grants.remove(token);
        state
    }

    fn resolve_cvv(&mut self, token: &str, approved: bool) -> bool {
        match self.grants.get_mut(token) {
            Some(grant) if grant.kind == GrantKind::Cvv && grant.approval == Approval::Waiting && grant.expires > Instant::now() => {
                grant.approval = if approved { Approval::Approved } else { Approval::Denied };
                grant.expires = Instant::now() + SELECTION_TTL;
                true
            }
            _ => false,
        }
    }

    /// Counts one login check for `origin`; false once the per-minute budget is spent.
    fn allow_login_check(&mut self, origin: &str) -> bool {
        let now = Instant::now();
        self.login_checks.retain(|_, hits| {
            while hits.front().is_some_and(|hit| now.duration_since(*hit) >= Duration::from_secs(60)) {
                hits.pop_front();
            }
            !hits.is_empty()
        });
        if self.login_checks.len() >= 1_000 && !self.login_checks.contains_key(origin) {
            return false;
        }
        let hits = self.login_checks.entry(origin.to_owned()).or_default();
        if hits.len() >= LOGIN_CHECKS_PER_MINUTE {
            return false;
        }
        hits.push_back(now);
        true
    }

    /// The grant's kind (`Login` or `AnyLogin`) when the token may release this login here.
    fn consume(&mut self, token: &str, record_id: &str, origin: &str) -> Option<GrantKind> {
        let grant = self.grants.remove(token)?;
        (grant.expires > Instant::now() && grant.record_id == record_id && grant.origin == origin && grant.password_hash.is_none()
            && matches!(grant.kind, GrantKind::Login | GrantKind::AnyLogin))
            .then_some(grant.kind)
    }

    fn consume_update(&mut self, token: &str, id: &str, origin: &str) -> Option<[u8; 32]> {
        let grant = self.grants.remove(token)?;
        if grant.expires <= Instant::now() || grant.record_id != id || grant.origin != origin || grant.kind != GrantKind::Login { return None; }
        grant.password_hash
    }
}

/// Supplies the vault's (accent, background) ids; set by the app, absent in the native host.
type AppearanceSource = Box<dyn Fn() -> (String, String) + Send + Sync>;
static APPEARANCE_SOURCE: OnceLock<AppearanceSource> = OnceLock::new();

pub fn set_appearance_source(source: impl Fn() -> (String, String) + Send + Sync + 'static) {
    let _ = APPEARANCE_SOURCE.set(Box::new(source));
}

/// Adds the vault's accent and background ids to a status response (readable while locked).
fn with_appearance(mut response: BrowserResponse) -> BrowserResponse {
    response.appearance = APPEARANCE_SOURCE.get().map(|source| {
        let (accent, surface) = source();
        crate::browser::BrowserAppearance { accent, surface }
    });
    response
}

/// Native messaging host manifests checked by `browser_status` (HKCU, default value).
pub const NATIVE_HOST_KEYS: [(&str, &str); 4] = [
    ("chrome", r"Software\Google\Chrome\NativeMessagingHosts\com.nuvori.desktop"),
    ("brave", r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.nuvori.desktop"),
    ("edge", r"Software\Microsoft\Edge\NativeMessagingHosts\com.nuvori.desktop"),
    // Chromium forks without their own key (Vivaldi, Opera, Thorium ...) read Chrome's or this one.
    ("chromium", r"Software\Chromium\NativeMessagingHosts\com.nuvori.desktop"),
];
/// Firefox reads its own key, and a manifest that lists add-on IDs ("allowed_extensions").
pub const FIREFOX_HOST_KEY: &str = r"Software\Mozilla\NativeMessagingHosts\com.nuvori.desktop";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct BrowserHosts {
    pub chrome: bool,
    pub brave: bool,
    pub edge: bool,
    pub firefox: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    pub hosts: BrowserHosts,
    pub listening: bool,
    /// Unix milliseconds of the last request of any kind, 0 = never.
    pub last_request_at: u64,
    /// Display-safe description of the last non-status request (site host only).
    pub last_action: String,
    /// Non-status requests since the vault was last unlocked or locked.
    pub requests_since_unlock: u64,
}

/// Request counters for `browser_status`. Holds no request content beyond a site host.
#[derive(Default)]
struct BrowserStats {
    listening: AtomicBool,
    last_request_at: AtomicU64,
    requests_since_unlock: AtomicU64,
    connected: AtomicBool,
    last_action: Mutex<String>,
}

impl BrowserStats {
    fn record(&self, action: RequestKind, host: Option<&str>, status: &str) {
        self.last_request_at
            .store(activity::now_millis(), Ordering::Relaxed);
        if !self.connected.swap(true, Ordering::Relaxed) {
            activity::log(Level::Info, Category::Browser, "Browser extension connected");
        }
        // Status pings and the security-code wait poll are not activity.
        // Icon saves can come with every page visit, so they never reach the activity log.
        if matches!(action, RequestKind::Status | RequestKind::SiteIcon) || (action == RequestKind::Cvv && status == "pending") {
            return;
        }
        self.requests_since_unlock.fetch_add(1, Ordering::Relaxed);
        let (level, message) = describe(action, host, status);
        if let Ok(mut last) = self.last_action.lock() {
            last.clone_from(&message);
        }
        if matches!(action, RequestKind::Query | RequestKind::ItemQuery) {
            activity::global().record_coalesced(
                level,
                Category::Browser,
                message,
                Duration::from_secs(60),
            );
        } else {
            activity::log(level, Category::Browser, message);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestKind {
    Status,
    Query,
    Fill,
    Seal,
    Save,
    Update,
    Review,
    Unlock,
    ItemQuery,
    ItemFill,
    Cvv,
    DetailsReview,
    DetailsSave,
    SiteIcon,
}

impl From<&BrowserAction> for RequestKind {
    fn from(action: &BrowserAction) -> Self {
        match action {
            BrowserAction::Status => Self::Status,
            BrowserAction::QueryCredentials => Self::Query,
            BrowserAction::FillCredential => Self::Fill,
            BrowserAction::SealLogin => Self::Seal,
            BrowserAction::CommitLogin => Self::Save,
            BrowserAction::UpdateLogin => Self::Update,
            BrowserAction::ReviewLogin => Self::Review,
            BrowserAction::UnlockPrompt | BrowserAction::ShowApp | BrowserAction::HandOver => Self::Unlock,
            BrowserAction::QueryItems => Self::ItemQuery,
            BrowserAction::FillItem => Self::ItemFill,
            BrowserAction::RequestCvv | BrowserAction::FillCvv => Self::Cvv,
            BrowserAction::SealDetails | BrowserAction::ReviewDetails => Self::DetailsReview,
            BrowserAction::CommitDetails => Self::DetailsSave,
            BrowserAction::SaveSiteIcon => Self::SiteIcon,
        }
    }
}

/// Activity text for one browser request. Only the site host is included.
fn describe(action: RequestKind, host: Option<&str>, status: &str) -> (Level, String) {
    let site = host.unwrap_or("a site");
    match (action, status) {
        (RequestKind::Unlock, _) => (Level::Info, "Browser asked to unlock Nuvori".to_owned()),
        (RequestKind::ItemQuery, "ok") => (Level::Info, format!("Looked up saved details for {site}")),
        (RequestKind::ItemFill, "ok") => (Level::Success, format!("Filled saved details on {site}")),
        (RequestKind::Cvv, "pending") => (Level::Info, format!("Asked to approve a card security code for {site}")),
        (RequestKind::Cvv, "ok") => (Level::Success, format!("Filled an approved card security code on {site}")),
        (RequestKind::Cvv, "denied") => (Level::Info, format!("Declined a card security code for {site}")),
        (RequestKind::DetailsSave, "saved") => (Level::Success, format!("Saved details from {site}")),
        (RequestKind::DetailsReview, "needs_save") => (Level::Info, format!("Reviewed new details from {site}")),
        (_, "locked") => (Level::Info, format!("Browser request from {site} waited for unlock")),
        (_, "invalid_request") => (Level::Warning, "Rejected an invalid browser request".to_owned()),
        (_, "rate_limited") => (Level::Warning, format!("Slowed down repeated login checks from {site}")),
        (RequestKind::Query, _) => (Level::Info, format!("Looked up logins for {site}")),
        (RequestKind::Fill, "ok") => (Level::Success, format!("Filled a login on {site}")),
        (RequestKind::Fill, "selection_expired") => {
            (Level::Warning, format!("Fill on {site} expired. Choose the account again"))
        }
        (RequestKind::Fill, _) => (Level::Warning, format!("Could not fill a login on {site}")),
        (RequestKind::Save, "saved") => (Level::Success, format!("Saved a login from {site}")),
        (RequestKind::Update, "saved") => (Level::Success, format!("Updated a login for {site}")),
        (RequestKind::Update, "selection_expired") => {
            (Level::Warning, format!("Update for {site} expired. Review it again"))
        }
        (RequestKind::Review, "needs_save") => {
            (Level::Info, format!("Reviewed a new login from {site}"))
        }
        (_, "already_saved") => (Level::Info, format!("Login from {site} is already saved")),
        (_, "account_exists") => {
            (Level::Warning, format!("{site} already has a different saved password"))
        }
        (_, "retry") => (Level::Warning, format!("Could not save a login from {site} yet")),
        _ => (Level::Info, format!("Handled a browser request from {site}")),
    }
}

/// True when HKCU has a native messaging host key whose default value names a manifest file
/// that exists. Read-only.
pub fn native_host_registered(subkey: &str) -> bool {
    native_host_manifest(subkey).is_some()
}

/// Points one browser's native host key at `manifest` (HKCU, default value).
pub fn set_native_host_manifest(subkey: &str, manifest: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::System::Registry::{REG_SZ, RegSetKeyValueW};
    let value: Vec<u16> = manifest.as_os_str().encode_wide().chain(Some(0)).collect();
    let key: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    let status = unsafe {
        RegSetKeyValueW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr()), PCWSTR::null(), REG_SZ.0,
            Some(value.as_ptr().cast()), (value.len() * 2) as u32)
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status.0 as i32));
    }
    Ok(())
}

/// The manifest file a native host key names, when that file exists.
pub(crate) fn native_host_manifest(subkey: &str) -> Option<std::path::PathBuf> {
    let key: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    let mut size = 0_u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(key.as_ptr()),
            PCWSTR::null(),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS || !(4..=65_536).contains(&size) {
        return None;
    }
    let mut buffer = vec![0_u16; (size as usize).div_ceil(2)];
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(key.as_ptr()),
            PCWSTR::null(),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let end = buffer.iter().position(|&unit| unit == 0).unwrap_or(buffer.len());
    let path = String::from_utf16_lossy(&buffer[..end]);
    let path = std::path::PathBuf::from(path.trim().trim_matches('"'));
    (!path.as_os_str().is_empty() && path.is_file()).then_some(path)
}

pub fn registered_hosts() -> BrowserHosts {
    let registered = |name: &str| {
        NATIVE_HOST_KEYS
            .iter()
            .find(|(browser, _)| *browser == name)
            .is_some_and(|(_, key)| native_host_registered(key))
    };
    BrowserHosts {
        chrome: registered("chrome"),
        brave: registered("brave"),
        edge: registered("edge"),
        firefox: native_host_registered(FIREFOX_HOST_KEY),
    }
}

/// Owns one owner-only named-pipe server for the current Windows user session.
/// Call `set_provider(None)` on lock; an unlocked provider is installed by the app.
pub struct BrowserIpcServer {
    provider: Arc<RwLock<Option<Arc<dyn BrowserCredentialProvider>>>>,
    grants: Arc<Mutex<SelectionGrants>>,
    stats: Arc<BrowserStats>,
}

impl BrowserIpcServer {
    pub fn start() -> Result<Self, BrowserIpcError> {
        let provider = Arc::new(RwLock::new(None));
        let grants = Arc::new(Mutex::new(SelectionGrants::default()));
        let stats = Arc::new(BrowserStats::default());
        let server_provider = Arc::clone(&provider);
        let server_grants = Arc::clone(&grants);
        let server_stats = Arc::clone(&stats);
        thread::Builder::new()
            .name("nuvori-browser-ipc".to_owned())
            .spawn(move || accept_loop(server_provider, server_grants, server_stats))?;
        Ok(Self {
            provider,
            grants,
            stats,
        })
    }

    pub fn status(&self) -> BrowserStatus {
        BrowserStatus {
            hosts: registered_hosts(),
            listening: self.stats.listening.load(Ordering::Relaxed),
            last_request_at: self.stats.last_request_at.load(Ordering::Relaxed),
            last_action: self
                .stats
                .last_action
                .lock()
                .map(|last| last.clone())
                .unwrap_or_default(),
            requests_since_unlock: self.stats.requests_since_unlock.load(Ordering::Relaxed),
        }
    }

    /// The newest security code waiting for approval: (confirmation id, card id, site origin).
    pub fn waiting_card_code(&self) -> Option<(String, String, String)> {
        let grants = self.grants.lock().ok()?;
        let now = Instant::now();
        grants.grants.iter()
            .filter(|(_, grant)| grant.kind == GrantKind::Cvv && grant.approval == Approval::Waiting && grant.expires > now)
            .max_by_key(|(_, grant)| grant.expires)
            .map(|(token, grant)| (token.clone(), grant.record_id.clone(), grant.origin.clone()))
    }

    /// The user approved or declined a security code in Nuvori. False when it already expired.
    pub fn resolve_card_code(&self, id: &str, approved: bool) -> bool {
        self.grants.lock().is_ok_and(|mut grants| grants.resolve_cvv(id, approved))
    }

    pub fn set_provider(&self, provider: Option<Arc<dyn BrowserCredentialProvider>>) {
        self.stats.requests_since_unlock.store(0, Ordering::Relaxed);
        self.stats.connected.store(false, Ordering::Relaxed);
        *self
            .provider
            .write()
            .expect("browser provider lock poisoned") = provider;
        if self
            .provider
            .read()
            .expect("browser provider lock poisoned")
            .is_none()
        {
            self.grants
                .lock()
                .expect("browser grant lock poisoned")
                .grants
                .clear();
        }
    }
}

/// Called by the Native Messaging host process for one browser request.
pub fn send_to_app(request: &BrowserRequest) -> Result<BrowserResponse, BrowserIpcError> {
    // ERROR_PIPE_BUSY (231): every instance is taken for a moment while the app opens the next.
    for _ in 0..50 {
        match send_to_app_once(request) {
            Err(BrowserIpcError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::NotFound | io::ErrorKind::WouldBlock
                ) || error.raw_os_error() == Some(231) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
    send_to_app_once(request)
}

fn send_to_app_once(request: &BrowserRequest) -> Result<BrowserResponse, BrowserIpcError> {
    let request_bytes = serde_json::to_vec(request)?;
    let length = u32::try_from(request_bytes.len()).map_err(|_| BrowserIpcError::InvalidRequest)?;
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)?;
    // Another program running as this user could have taken the name; only talk to Nuvori.
    verify_pipe_server(&pipe)?;
    pipe.write_all(&length.to_le_bytes())?;
    pipe.write_all(&request_bytes)?;
    pipe.flush()?;
    let response_bytes = read_frame(&mut pipe)?;
    let response: BrowserResponse = serde_json::from_slice(&response_bytes)?;
    if response.request_id != request.request_id || response.version != BROWSER_PROTOCOL_VERSION {
        return Err(BrowserIpcError::InvalidRequest);
    }
    Ok(response)
}

type Provider = Arc<RwLock<Option<Arc<dyn BrowserCredentialProvider>>>>;

/// Owns the pipe name for the app's lifetime: the first instance is created with
/// FILE_FLAG_FIRST_PIPE_INSTANCE (so no other process holds the name), and the next instance is
/// created before a connected one is handed off, so the name is never released.
fn accept_loop(provider: Provider, grants: Arc<Mutex<SelectionGrants>>, stats: Arc<BrowserStats>) {
    let active = Arc::new(AtomicUsize::new(0));
    let first_instance = |stats: &BrowserStats| loop {
        match create_pipe(true) {
            Ok(pipe) => {
                stats.listening.store(true, Ordering::Relaxed);
                return pipe;
            }
            Err(_) => {
                stats.listening.store(false, Ordering::Relaxed);
                thread::sleep(Duration::from_secs(1));
            }
        }
    };
    let mut pipe = first_instance(&stats);
    loop {
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = connected
            && error.code() != windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
        {
            let replacement = create_pipe(false).ok();
            unsafe {
                let _ = CloseHandle(pipe);
            }
            pipe = replacement.unwrap_or_else(|| first_instance(&stats));
            continue;
        }
        let next = create_pipe(false).ok();
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_ACTIVE_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
        } else {
            spawn_connection(pipe, provider.clone(), grants.clone(), stats.clone(), active.clone());
        }
        pipe = next.unwrap_or_else(|| first_instance(&stats));
    }
}

/// Serves one connection on its own thread. A watchdog disconnects it after REQUEST_TIMEOUT and
/// is the only owner that closes the handle, so it never touches a reused handle value.
fn spawn_connection(
    pipe: HANDLE,
    provider: Provider,
    grants: Arc<Mutex<SelectionGrants>>,
    stats: Arc<BrowserStats>,
    active: Arc<AtomicUsize>,
) {
    let raw = pipe.0 as usize;
    let (done, finished) = mpsc::channel::<()>();
    let worker = thread::Builder::new().name("nuvori-browser-request".into()).spawn(move || {
        if let Err(error) = serve_connection(HANDLE(raw as *mut _), &provider, &grants, &stats) {
            eprintln!("Nuvori browser IPC request failed: {error}");
        }
        let _ = done.send(());
    });
    let Ok(worker) = worker else {
        unsafe {
            let _ = CloseHandle(HANDLE(raw as *mut _));
        }
        active.fetch_sub(1, Ordering::AcqRel);
        return;
    };
    let worker_thread = worker.as_raw_handle() as usize;
    let _ = thread::Builder::new().name("nuvori-browser-watchdog".into()).spawn(move || {
        let pipe = HANDLE(raw as *mut _);
        if finished.recv_timeout(REQUEST_TIMEOUT).is_err() {
            // The pipe is synchronous, so a pending read or write must be cancelled on the worker
            // thread itself; DisconnectNamedPipe would queue behind it. Repeat in case the worker
            // was between calls when the first cancel landed.
            loop {
                unsafe {
                    let _ = CancelSynchronousIo(HANDLE(worker_thread as *mut _));
                    let _ = CancelIoEx(pipe, None);
                }
                if finished.recv_timeout(Duration::from_millis(100)).is_ok() {
                    break;
                }
            }
        }
        let _ = worker.join();
        unsafe {
            let _ = DisconnectNamedPipe(pipe);
            let _ = CloseHandle(pipe);
        }
        active.fetch_sub(1, Ordering::AcqRel);
    });
}

fn serve_connection(
    pipe: HANDLE,
    provider: &RwLock<Option<Arc<dyn BrowserCredentialProvider>>>,
    grants: &Mutex<SelectionGrants>,
    stats: &BrowserStats,
) -> Result<(), BrowserIpcError> {
    // The watchdog owns the handle; never close it here.
    let mut stream = ManuallyDrop::new(unsafe { File::from_raw_handle(pipe.0 as RawHandle) });
    let mut seen = None;
    let mut handed_over = false;
    // A read that failed or was cancelled by the watchdog gets no answer.
    let bytes = read_frame(&mut *stream)?;
    let result = match Ok::<_, io::Error>(bytes) {
        Ok(bytes) => match serde_json::from_slice::<BrowserRequest>(&bytes) {
            Ok(request) if matches!(request.action, BrowserAction::HandOver) => {
                handed_over = bare_request(&request)
                    && HAND_OVER_HANDLER.get().zip(pipe_client_process(pipe)).is_some_and(|(handler, client)| (handler.allowed)(client));
                Ok(if handed_over {
                    ok_response(request.request_id, None, None)
                } else {
                    BrowserResponse::invalid(request.request_id, "This copy of Nuvori keeps running.")
                })
            }
            Ok(request) => {
                let host = canonical_https_origin(&request.origin)
                    .map(|origin| activity::origin_host(&origin))
                    .filter(|host| !host.ends_with(".invalid"));
                if !matches!(request.action, BrowserAction::ShowApp) {
                    seen = Some((RequestKind::from(&request.action), host));
                }
                handle_request(request, provider, grants)
            }
            Err(error) => Err(error.into()),
        },
        Err(error) => Err(error.into()),
    };
    let response = match result {
        Ok(response) => response,
        Err(_) => BrowserResponse::invalid(String::new(), "Invalid browser request."),
    };
    if let Some((kind, host)) = seen {
        stats.record(kind, host.as_deref(), &response.status);
    }
    let response_bytes = serde_json::to_vec(&response)?;
    let length =
        u32::try_from(response_bytes.len()).map_err(|_| BrowserIpcError::InvalidRequest)?;
    stream.write_all(&length.to_le_bytes())?;
    stream.write_all(&response_bytes)?;
    stream.flush()?;
    // Close only after the Store build has its answer, so it knows to wait for the instance.
    if handed_over && let Some(handler) = HAND_OVER_HANDLER.get() {
        (handler.close)();
    }
    Ok(())
}

/// A window or hand-over request: the protocol version, an ID, and nothing else.
fn bare_request(request: &BrowserRequest) -> bool {
    request.version == BROWSER_PROTOCOL_VERSION
        && (1..=128).contains(&request.request_id.len())
        && request.origin.is_empty()
        && request.credential_id.is_none() && request.selection_token.is_none() && request.username.is_none()
        && request.password.is_none() && request.sealed_login.is_none() && request.title.is_none()
        && request.kind.is_none() && request.all.is_none() && request.card.is_none() && request.profile.is_none()
}

/// Process ID of the program connected to this pipe instance.
fn pipe_client_process(pipe: HANDLE) -> Option<u32> {
    let mut pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.ok()?;
    (pid != 0).then_some(pid)
}

fn handle_request(
    request: BrowserRequest,
    provider: &RwLock<Option<Arc<dyn BrowserCredentialProvider>>>,
    grants: &Mutex<SelectionGrants>,
) -> Result<BrowserResponse, BrowserIpcError> {
    handle_request_with(request, provider, grants, BROWSER_HOOKS.get())
}

fn handle_request_with(
    request: BrowserRequest,
    provider: &RwLock<Option<Arc<dyn BrowserCredentialProvider>>>,
    grants: &Mutex<SelectionGrants>,
    hooks: Option<&BrowserHooks>,
) -> Result<BrowserResponse, BrowserIpcError> {
    let status_ping = matches!(request.action, BrowserAction::Status);
    let window_request = request.action.is_window_request();
    // "status_no_origin": a status ping may omit the origin; every other action needs one.
    // Window requests never carry one.
    let origin = match canonical_https_origin(&request.origin) {
        Some(origin) if !window_request => origin,
        None if (status_ping || window_request) && request.origin.is_empty() => String::new(),
        _ => {
            return Ok(BrowserResponse::invalid(
                request.request_id,
                "Only canonical HTTPS site origins are allowed.",
            ));
        }
    };
    if request.title.as_deref().is_some_and(|title| {
        !matches!(request.action, BrowserAction::CommitLogin | BrowserAction::CommitDetails) || !valid_login_title(title)
    }) {
        return Ok(BrowserResponse::invalid(request.request_id, "Invalid login name."));
    }
    // "startup_browsers": `startup` belongs to "unlock_prompt" only. The browser id is the host's.
    if (request.startup.is_some() && !matches!(request.action, BrowserAction::UnlockPrompt))
        || request.browser.as_deref().is_some_and(|browser| !valid_browser_id(browser))
    {
        return Ok(BrowserResponse::invalid(request.request_id, "The browser request is incomplete."));
    }
    let item_action = matches!(request.action, BrowserAction::QueryItems | BrowserAction::FillItem
        | BrowserAction::RequestCvv | BrowserAction::FillCvv);
    // An icon belongs to "save_site_icon" only, and that action needs one.
    if request.icon.is_some() != matches!(request.action, BrowserAction::SaveSiteIcon) {
        return Ok(BrowserResponse::invalid(request.request_id, "The browser request is incomplete."));
    }
    // Only the native host takes captured fields ("seal_details"); the app never does.
    if request.card.is_some() || request.profile.is_some()
        || (!item_action && request.kind.is_some())
        || (request.all.is_some() && !(matches!(request.action, BrowserAction::QueryCredentials)
            || (matches!(request.action, BrowserAction::QueryItems) && request.kind == Some(ItemKind::Code))))
        || (item_action && request.kind.is_none())
    {
        return Ok(BrowserResponse::invalid(request.request_id, "The browser request is incomplete."));
    }
    if request.version != BROWSER_PROTOCOL_VERSION
        || request.request_id.is_empty()
        || request.request_id.len() > 128
    {
        return Ok(BrowserResponse::invalid(
            request.request_id,
            "The browser request is incomplete.",
        ));
    }
    if let (Some(hooks), Some(browser)) = (hooks, request.browser.as_deref()) {
        (hooks.seen)(browser);
    }
    if window_request {
        if request.credential_id.is_some() || request.selection_token.is_some() || request.username.is_some()
            || request.password.is_some() || request.sealed_login.is_some() || request.kind.is_some()
            || request.all.is_some() || request.card.is_some() || request.profile.is_some()
        {
            return Ok(BrowserResponse::invalid(request.request_id, "The browser request is incomplete."));
        }
        // The user turned "ask when the browser starts" off for this browser.
        if request.startup == Some(true)
            && let (Some(hooks), Some(browser)) = (hooks, request.browser.as_deref())
            && !(hooks.ask_at_start)(browser)
        {
            let mut response = ok_response(request.request_id, None, None);
            response.status = "skipped".to_owned();
            return Ok(response);
        }
        let unlocked = provider.read().expect("browser provider lock poisoned").is_some();
        if let Some(handler) = WINDOW_HANDLER.get() {
            handler(&request.action, unlocked);
        }
        return Ok(if unlocked { ok_response(request.request_id, None, None) } else { locked_response(request.request_id) });
    }
    let provider = provider
        .read()
        .expect("browser provider lock poisoned")
        .clone();
    let Some(provider) = provider else {
        let locked = locked_response(request.request_id);
        return Ok(if status_ping { with_appearance(locked.with_features()) } else { locked });
    };

    match request.action {
        BrowserAction::Status => Ok(with_appearance(ok_response(request.request_id, None, None).with_features())),
        // Answered above, before the vault is consulted.
        BrowserAction::UnlockPrompt | BrowserAction::ShowApp => Ok(ok_response(request.request_id, None, None)),
        BrowserAction::QueryCredentials => {
            if request.credential_id.is_some() || request.selection_token.is_some() {
                return Ok(BrowserResponse::invalid(
                    request.request_id,
                    "Account lookup cannot include a selected credential.",
                ));
            }
            let every = request.all == Some(true);
            let listed = if every { provider.query_all_credentials() } else { provider.query_credentials(&origin) };
            let candidates = match listed {
                Ok(candidates) => candidates,
                Err(BrowserIpcError::VaultLocked) => {
                    return Ok(locked_response(request.request_id));
                }
                Err(error) => return Err(error),
            };
            // A failed check only means no icon this time.
            let icon_wanted = provider.icon_wanted(&origin).unwrap_or(false);
            let mut credentials = Vec::new();
            let mut token_store = grants.lock().expect("browser grant lock poisoned");
            let limit = if every { MAX_ALL_CANDIDATES } else { MAX_CANDIDATES };
            for candidate in candidates.into_iter().take(limit) {
                if candidate.id.is_empty() || candidate.id.len() > 256 {
                    continue;
                }
                let kind = if every { GrantKind::AnyLogin } else { GrantKind::Login };
                let selection_token = token_store.issue_kind(candidate.id.clone(), &origin, kind)?;
                credentials.push(CredentialChoice {
                    id: candidate.id,
                    title: candidate.title,
                    username: candidate.username,
                    selection_token,
                    related: candidate.related,
                    passkey: candidate.passkey,
                    color: None,
                    site: candidate.site,
                    preview: None,
                });
            }
            let mut response = ok_response(request.request_id, Some(credentials), None);
            response.icon_wanted = icon_wanted;
            Ok(response)
        }
        BrowserAction::SaveSiteIcon => {
            if request.credential_id.is_some() || request.selection_token.is_some() || request.username.is_some()
                || request.password.is_some() || request.sealed_login.is_some() || request.title.is_some() || request.all.is_some()
            {
                return Ok(BrowserResponse::invalid(request.request_id, "The browser request is incomplete."));
            }
            let refused = |request_id: String| BrowserResponse::invalid(request_id, "The site icon was not accepted.");
            let icon = request.icon.as_deref().unwrap_or_default();
            // Base64 is 4 characters per 3 bytes; check the text length before it is decoded.
            if icon.len() > MAX_ICON_BYTES.div_ceil(3) * 4 {
                return Ok(refused(request.request_id));
            }
            let Ok(png) = base64::engine::general_purpose::STANDARD.decode(icon) else {
                return Ok(refused(request.request_id));
            };
            match provider.save_site_icon(&origin, &png) {
                Ok(()) => Ok(ok_response(request.request_id, None, None)),
                Err(BrowserIpcError::VaultLocked) => Ok(locked_response(request.request_id)),
                Err(_) => Ok(refused(request.request_id)),
            }
        }
        BrowserAction::FillCredential => {
            let (Some(record_id), Some(selection_token)) =
                (request.credential_id, request.selection_token)
            else {
                return Ok(BrowserResponse::invalid(
                    request.request_id,
                    "Choose an account before filling.",
                ));
            };
            if record_id.is_empty() || record_id.len() > 256 || selection_token.len() != 64 {
                return Ok(BrowserResponse::invalid(
                    request.request_id,
                    "The selected account is invalid or expired.",
                ));
            }
            let authorized = grants.lock().expect("browser grant lock poisoned").consume(
                &selection_token,
                &record_id,
                &origin,
            );
            let Some(granted) = authorized else {
                return Ok(BrowserResponse {
                    version: BROWSER_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    status: "selection_expired".to_owned(),
                    message: "Choose the account again; this selection expired.".to_owned(),
                    credentials: None,
                    credential: None,
                    sealed_login: None, features: None, appearance: None, item: None, icon_wanted: false,
                });
            };
            let loaded = if granted == GrantKind::AnyLogin {
                provider.load_any_credential(&record_id)
            } else {
                provider.load_selected_credential(&record_id, &origin)
            };
            let selected = match loaded {
                Ok(selected) => selected,
                Err(BrowserIpcError::VaultLocked) => {
                    return Ok(locked_response(request.request_id));
                }
                Err(error) => return Err(error),
            };
            let Some(credential) = selected else {
                return Ok(BrowserResponse {
                    version: BROWSER_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    status: "credential_unavailable".to_owned(),
                    message: "The selected account is no longer available for this site."
                        .to_owned(),
                    credentials: None,
                    credential: None,
                    sealed_login: None, features: None, appearance: None, item: None, icon_wanted: false,
                });
            };
            if credential.id != record_id {
                return Ok(BrowserResponse::invalid(
                    request.request_id,
                    "The selected account did not match.",
                ));
            }
            Ok(ok_response(request.request_id, None, Some(credential)))
        }
        BrowserAction::SealLogin | BrowserAction::SealDetails => Ok(BrowserResponse::invalid(
            request.request_id, "Use the registered native host to protect logins.",
        )),
        // Answered in `serve_connection`, with the caller's package identity.
        BrowserAction::HandOver => Ok(BrowserResponse::invalid(request.request_id, "The browser request is incomplete.")),
        BrowserAction::QueryItems => {
            let kind = request.kind.expect("checked above");
            if request.credential_id.is_some() || request.selection_token.is_some() || request.username.is_some()
                || request.password.is_some() || request.sealed_login.is_some() {
                return Ok(BrowserResponse::invalid(request.request_id, "Item lookup cannot include other fields."));
            }
            let candidates = match provider.query_items(kind, &origin, request.all == Some(true)) {
                Ok(candidates) => candidates,
                Err(BrowserIpcError::VaultLocked) => return Ok(locked_response(request.request_id)),
                Err(error) => return Err(error),
            };
            let mut token_store = grants.lock().expect("browser grant lock poisoned");
            let mut choices = Vec::new();
            for candidate in candidates.into_iter().take(MAX_CANDIDATES) {
                if candidate.id.is_empty() || candidate.id.len() > 256 {
                    continue;
                }
                let selection_token = token_store.issue_kind(candidate.id.clone(), &origin, GrantKind::Item(kind))?;
                choices.push(CredentialChoice { id: candidate.id, title: candidate.title, username: candidate.username, selection_token, related: false, passkey: false, color: candidate.color, site: None,
                    preview: if kind == ItemKind::Profile { candidate.preview } else { None } });
            }
            Ok(ok_response(request.request_id, Some(choices), None))
        }
        BrowserAction::FillItem | BrowserAction::RequestCvv | BrowserAction::FillCvv => {
            let kind = request.kind.expect("checked above");
            let (Some(record_id), Some(token)) = (request.credential_id, request.selection_token) else {
                return Ok(BrowserResponse::invalid(request.request_id, "Choose an item before filling."));
            };
            if record_id.is_empty() || record_id.len() > 256 || token.len() != 64 || request.username.is_some()
                || request.password.is_some() || request.sealed_login.is_some()
                || (!matches!(request.action, BrowserAction::FillItem) && kind != ItemKind::Card)
            {
                return Ok(BrowserResponse::invalid(request.request_id, "The selected item is invalid or expired."));
            }
            let status_response = |request_id: String, status: &str, message: &str| BrowserResponse {
                version: BROWSER_PROTOCOL_VERSION, request_id, status: status.to_owned(), message: message.to_owned(),
                credentials: None, credential: None, sealed_login: None, features: None, appearance: None, item: None, icon_wanted: false,
            };
            let expired = "Choose the item again; this selection expired.";
            match request.action {
                BrowserAction::RequestCvv => {
                    if !grants.lock().expect("browser grant lock poisoned").ask_cvv(&token, &record_id, &origin) {
                        return Ok(status_response(request.request_id, "selection_expired", expired));
                    }
                    if let Some(handler) = WINDOW_HANDLER.get() {
                        handler(&request.action, true);
                    }
                    Ok(status_response(request.request_id, "pending", "Approve the security code in Nuvori."))
                }
                BrowserAction::FillCvv => {
                    let state = grants.lock().expect("browser grant lock poisoned").cvv_state(&token, &record_id, &origin);
                    match state {
                        CvvState::Waiting => Ok(status_response(request.request_id, "pending", "Approve the security code in Nuvori.")),
                        CvvState::Denied => Ok(status_response(request.request_id, "denied", "The security code was not approved.")),
                        CvvState::Missing => Ok(status_response(request.request_id, "selection_expired", expired)),
                        CvvState::Approved => {
                            let loaded = match provider.load_item(ItemKind::Card, &record_id, &origin) {
                                Ok(loaded) => loaded,
                                Err(BrowserIpcError::VaultLocked) => return Ok(locked_response(request.request_id)),
                                Err(error) => return Err(error),
                            };
                            let Some(mut card) = loaded.and_then(|mut item| item.card.take()).filter(|card| !card.cvv.is_empty()) else {
                                return Ok(status_response(request.request_id, "credential_unavailable", "This card has no saved security code."));
                            };
                            let mut only_code = CardDetails::default();
                            only_code.cvv = std::mem::take(&mut card.cvv);
                            let mut response = ok_response(request.request_id, None, None);
                            response.item = Some(FilledItem { id: record_id, kind, card: Some(only_code), profile: None, code: None, cvv_token: None });
                            Ok(response)
                        }
                    }
                }
                _ => {
                    if !grants.lock().expect("browser grant lock poisoned").consume_item(&token, &record_id, &origin, kind) {
                        return Ok(status_response(request.request_id, "selection_expired", expired));
                    }
                    let loaded = match provider.load_item(kind, &record_id, &origin) {
                        Ok(loaded) => loaded,
                        Err(BrowserIpcError::VaultLocked) => return Ok(locked_response(request.request_id)),
                        Err(error) => return Err(error),
                    };
                    let Some(mut item) = loaded.filter(|item| item.id == record_id && item.kind == kind) else {
                        return Ok(status_response(request.request_id, "credential_unavailable", "This item is no longer available."));
                    };
                    // The security code needs its own approval ("request_cvv" / "fill_cvv").
                    item.cvv_token = None;
                    if let Some(card) = item.card.as_mut() {
                        let has_code = !card.cvv.is_empty();
                        card.cvv.zeroize();
                        card.cvv.clear();
                        if has_code {
                            item.cvv_token = Some(grants.lock().expect("browser grant lock poisoned").issue_kind(record_id.clone(), &origin, GrantKind::Cvv)?);
                        }
                    }
                    let mut response = ok_response(request.request_id, None, None);
                    response.item = Some(item);
                    Ok(response)
                }
            }
        }
        BrowserAction::ReviewDetails | BrowserAction::CommitDetails => {
            let committing = matches!(request.action, BrowserAction::CommitDetails);
            let Some(sealed) = request.sealed_login else {
                return Ok(BrowserResponse::invalid(request.request_id, "Missing captured details."));
            };
            if sealed.len() > 32768 || request.credential_id.is_some() || request.selection_token.is_some()
                || request.username.is_some() || request.password.is_some() {
                return Ok(BrowserResponse::invalid(request.request_id, "Invalid captured details."));
            }
            if !grants.lock().expect("browser grant lock poisoned").allow_login_check(&origin) {
                return Ok(BrowserResponse {
                    version: BROWSER_PROTOCOL_VERSION, request_id: request.request_id,
                    status: "rate_limited".into(), message: "Too many checks for this site. Try again in a minute.".into(),
                    credentials: None, credential: None, sealed_login: None, features: None, appearance: None, item: None, icon_wanted: false,
                });
            }
            let bytes = URL_SAFE_NO_PAD.decode(sealed).map_err(|_| BrowserIpcError::InvalidRequest)?;
            let plaintext = dpapi::unprotect(&bytes).map_err(|_| BrowserIpcError::InvalidRequest)?;
            let pending: PendingDetails = serde_json::from_slice(&plaintext)?;
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let shape_ok = match pending.kind {
                ItemKind::Card => pending.profile.is_none() && pending.card.as_ref().is_some_and(valid_card_capture),
                ItemKind::Profile => pending.card.is_none() && pending.profile.as_ref().is_some_and(valid_profile_capture),
                ItemKind::Code => false,
            };
            if pending.version != 1 || pending.origin != origin || pending.created_at > now + 60
                || pending.created_at < now - 7 * 24 * 60 * 60 || !shape_ok {
                return Ok(BrowserResponse::invalid(request.request_id, "These details expired or belong to another site."));
            }
            let result = if committing { provider.save_details(&pending, request.title.as_deref()) } else { provider.review_details(&pending) };
            let (status, message) = match result {
                Ok(true) if committing => ("saved", "Saved in your Windows vault."),
                Ok(true) => ("needs_save", "Review these details before saving them."),
                Ok(false) => ("already_saved", "These details are already saved."),
                Err(BrowserIpcError::VaultLocked) => return Ok(locked_response(request.request_id)),
                Err(BrowserIpcError::SaveFailed) => ("retry", "Could not save yet."),
                Err(error) => return Err(error),
            };
            Ok(BrowserResponse {
                version: BROWSER_PROTOCOL_VERSION, request_id: request.request_id, status: status.to_owned(),
                message: message.to_owned(), credentials: None, credential: None, sealed_login: None, features: None, appearance: None, item: None, icon_wanted: false,
            })
        }
        BrowserAction::CommitLogin | BrowserAction::UpdateLogin | BrowserAction::ReviewLogin => {
            let updating = matches!(request.action, BrowserAction::UpdateLogin);
            let reviewing = matches!(request.action, BrowserAction::ReviewLogin);
            let Some(sealed) = request.sealed_login else {
                return Ok(BrowserResponse::invalid(request.request_id, "Missing pending login."));
            };
            if !updating && !grants.lock().expect("browser grant lock poisoned").allow_login_check(&origin) {
                return Ok(BrowserResponse {
                    version: BROWSER_PROTOCOL_VERSION, request_id: request.request_id,
                    status: "rate_limited".into(),
                    message: "Too many login checks for this site. Try again in a minute.".into(),
                    credentials: None, credential: None, sealed_login: None, features: None, appearance: None, item: None, icon_wanted: false,
                });
            }
            let committing = !updating && !reviewing;
            // "login_edit": a save may correct the captured username, never the password or site.
            if sealed.len() > 32768 || (!updating && (request.credential_id.is_some() || request.selection_token.is_some()))
                || request.username.as_deref().is_some_and(|username| !committing || !valid_capture_username(username))
                || request.password.is_some() {
                return Ok(BrowserResponse::invalid(request.request_id, "Invalid pending login."));
            }
            let bytes = URL_SAFE_NO_PAD.decode(sealed).map_err(|_| BrowserIpcError::InvalidRequest)?;
            let plaintext = dpapi::unprotect(&bytes).map_err(|_| BrowserIpcError::InvalidRequest)?;
            let mut pending: PendingLogin = serde_json::from_slice(&plaintext)?;
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            if pending.version != 1 || pending.origin != origin || pending.created_at > now + 60
                || pending.created_at < now - 7 * 24 * 60 * 60 {
                return Ok(BrowserResponse::invalid(request.request_id, "This pending login expired or belongs to another site."));
            }
            if !valid_capture_username(&pending.username)
                || pending.title.as_deref().is_some_and(|title| !valid_login_title(title)) {
                return Ok(BrowserResponse::invalid(request.request_id, "Invalid pending login."));
            }
            if let Some(username) = request.username {
                pending.username = username.trim().to_owned();
            }
            // A name chosen at review time wins over one captured with the form.
            let title = request.title.as_deref().or(pending.title.as_deref());
            let saved = if updating {
                let (Some(id), Some(token)) = (request.credential_id, request.selection_token) else {
                    return Ok(BrowserResponse::invalid(request.request_id, "Review this account before updating it."));
                };
                let expected = grants.lock().expect("browser grant lock poisoned").consume_update(&token, &id, &origin);
                let Some(expected) = expected else {
                    return Ok(BrowserResponse { version: BROWSER_PROTOCOL_VERSION, request_id: request.request_id,
                        status: "selection_expired".into(), message: "Review this update again; its approval expired.".into(),
                        credentials: None, credential: None, sealed_login: None, features: None, appearance: None, item: None, icon_wanted: false, });
                };
                provider.update_login(&origin, &id, &pending.username, &pending.password, &expected).map(|_| true)
            } else if reviewing { provider.review_login(&origin, &pending.username, &pending.password) }
            else { provider.save_new_login(&origin, &pending.username, &pending.password, title) };
            let (status, message) = match saved {
                Ok(true) if reviewing => ("needs_save", "Review this new account before saving it."),
                Ok(true) => ("saved", "Saved in your Windows vault."),
                Ok(false) => ("already_saved", "This login is already saved."),
                Err(BrowserIpcError::VaultLocked) => return Ok(locked_response(request.request_id)),
                Err(BrowserIpcError::LoginConflict) => ("account_exists", "Review this account before replacing its saved password."),
                Err(BrowserIpcError::SaveFailed) => ("retry", "Could not save yet. Nuvori will retry."),
                Err(error) => return Err(error),
            };
            // "multi_update": one update choice per saved account with this exact username
            // (empty for password-only forms). Each token is bound to its record, the origin and
            // that record's current password fingerprint, and expires like any selection.
            let credentials = if status == "account_exists" {
                let matches: Vec<_> = provider.query_credentials(&origin)?.into_iter()
                    .filter(|candidate| candidate.username == pending.username
                        && !candidate.id.is_empty() && candidate.id.len() <= 256)
                    .take(MAX_CANDIDATES)
                    .collect();
                let mut choices = Vec::with_capacity(matches.len());
                for candidate in matches {
                    let Some(mut selected) = provider.load_selected_credential(&candidate.id, &origin)? else { continue };
                    let hash: [u8; 32] = Sha256::digest(selected.password.as_bytes()).into();
                    selected.password.zeroize();
                    let mut grants = grants.lock().expect("browser grant lock poisoned");
                    let token = grants.issue(candidate.id.clone(), &origin)?;
                    grants.grants.get_mut(&token).expect("issued update grant").password_hash = Some(hash);
                    choices.push(CredentialChoice { id: candidate.id, title: candidate.title, username: candidate.username, selection_token: token, related: false, passkey: false, color: None, site: None, preview: None });
                }
                (!choices.is_empty()).then_some(choices)
            } else { None };
            let message = if credentials.as_ref().is_some_and(|choices| choices.len() > 1) {
                "Choose which saved account to update."
            } else { message };
            Ok(BrowserResponse {
                version: BROWSER_PROTOCOL_VERSION, request_id: request.request_id,
                status: status.to_owned(), message: message.to_owned(),
                credentials, credential: None, sealed_login: None, features: None, appearance: None, item: None, icon_wanted: false,
            })
        }
    }
}

fn locked_response(request_id: String) -> BrowserResponse {
    BrowserResponse {
        version: BROWSER_PROTOCOL_VERSION,
        request_id,
        status: "locked".to_owned(),
        message: "Unlock Nuvori for Windows to use browser filling.".to_owned(),
        credentials: None,
        credential: None,
        sealed_login: None,
        features: None, appearance: None, item: None, icon_wanted: false,
    }
}

fn ok_response(
    request_id: String,
    credentials: Option<Vec<CredentialChoice>>,
    credential: Option<SelectedCredential>,
) -> BrowserResponse {
    BrowserResponse {
        version: BROWSER_PROTOCOL_VERSION,
        request_id,
        status: "ok".to_owned(),
        message: String::new(),
        credentials,
        credential,
        sealed_login: None,
        features: None, appearance: None, item: None, icon_wanted: false,
    }
}

fn create_pipe(first: bool) -> Result<HANDLE, BrowserIpcError> {
    let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:P(A;;GA;;;OW)"),
            SDDL_REVISION_1,
            &mut security_descriptor,
            None,
        )?;
    }
    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor.0,
        bInheritHandle: windows::core::BOOL(0),
    };
    let pipe_name: Vec<u16> = PIPE_NAME.encode_utf16().chain(Some(0)).collect();
    let pipe = unsafe {
        CreateNamedPipeW(
            windows::core::PCWSTR(pipe_name.as_ptr()),
            if first { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX },
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            MAX_MESSAGE_SIZE as u32,
            MAX_MESSAGE_SIZE as u32,
            0,
            Some(&security_attributes),
        )
    };
    let error = pipe.is_invalid().then(windows::core::Error::from_win32);
    // The pipe keeps its own copy of the security descriptor.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(security_descriptor.0)));
    }
    match error {
        Some(error) => Err(error.into()),
        None => Ok(pipe),
    }
}

/// Executables allowed to serve the browser pipe: the Nuvori app installed next to (or one level
/// above) this native host, or in the standard per-user / per-machine install folders.
fn trusted_server_images() -> Vec<std::path::PathBuf> {
    let mut images = Vec::new();
    let names = ["nuvori.exe", "Nuvori.exe"];
    if let Some(directory) = std::env::current_exe().ok().and_then(|exe| exe.parent().map(Path::to_path_buf)) {
        for name in names {
            images.push(directory.join(name));
            if let Some(parent) = directory.parent() {
                images.push(parent.join(name));
            }
        }
    }
    for (variable, suffix) in [("LOCALAPPDATA", "Nuvori"), ("LOCALAPPDATA", "Programs\\Nuvori"),
        ("ProgramFiles", "Nuvori"), ("ProgramW6432", "Nuvori")] {
        if let Some(base) = std::env::var_os(variable) {
            for name in names {
                images.push(std::path::PathBuf::from(&base).join(suffix).join(name));
            }
        }
    }
    #[cfg(test)]
    images.extend(std::env::current_exe().ok());
    images
}

/// The installed Nuvori app the native host may start: the first trusted pipe server that exists.
pub fn installed_app_image() -> Option<std::path::PathBuf> {
    trusted_server_images().into_iter().find(|path| {
        path.is_file() && path.file_name().is_some_and(|name| name.eq_ignore_ascii_case("nuvori.exe"))
    })
}

fn same_path(left: &Path, right: &Path) -> bool {
    let normalize = |path: &Path| {
        std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_lowercase()
    };
    normalize(left) == normalize(right)
}

/// Process ID of the process serving the connected pipe.
fn pipe_server_pid(pipe: &File) -> Option<u32> {
    let mut pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle() as *mut _), &mut pid) }.ok()?;
    Some(pid)
}

/// Image path of the process serving the connected pipe.
fn pipe_server_image(pipe: &File) -> Option<std::path::PathBuf> {
    let pid = pipe_server_pid(pipe)?;
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buffer = vec![0u16; 32_768];
    let mut size = buffer.len() as u32;
    let queried = unsafe {
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut size)
    };
    unsafe {
        let _ = CloseHandle(process);
    }
    queried.ok()?;
    Some(std::path::PathBuf::from(String::from_utf16_lossy(&buffer[..size as usize])))
}

fn verify_pipe_server(pipe: &File) -> Result<(), BrowserIpcError> {
    let image = pipe_server_image(pipe).ok_or(BrowserIpcError::UntrustedServer)?;
    if trusted_server_images().iter().any(|trusted| same_path(trusted, &image)) {
        return Ok(());
    }
    // A host copied out of the Store package (for Firefox) runs outside it, so the Store app's
    // folder is not next to it. The server is still trusted when it runs from the recorded,
    // installed Store package.
    let store = crate::store_launch::installed_store_build().map(|store| store.family_name);
    let server = pipe_server_pid(pipe).and_then(crate::store_launch::process_family);
    if store.zip(server).is_some_and(|(store, server)| store.eq_ignore_ascii_case(&server)) {
        Ok(())
    } else {
        Err(BrowserIpcError::UntrustedServer)
    }
}

fn read_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid browser IPC frame size",
        ));
    }
    let mut message = vec![0_u8; length];
    reader.read_exact(&mut message)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::BrowserAction;

    struct ExampleProvider;

    impl BrowserCredentialProvider for ExampleProvider {
        fn query_credentials(&self, origin: &str) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
            Ok(if origin == "https://example.com" {
                vec![LoginCandidate {
                    id: "login-1".to_owned(),
                    title: "Example".to_owned(),
                    username: "alice".to_owned(), related: false, passkey: false, color: None, site: None, preview: None
                }]
            } else {
                Vec::new()
            })
        }

        fn load_selected_credential(
            &self,
            id: &str,
            origin: &str,
        ) -> Result<Option<SelectedCredential>, BrowserIpcError> {
            Ok(
                (id == "login-1" && origin == "https://example.com").then(|| SelectedCredential {
                    id: id.to_owned(),
                    username: "alice".to_owned(),
                    password: "secret".to_owned(),
                }),
            )
        }

        fn save_new_login(&self, _: &str, _: &str, _: &str, _: Option<&str>) -> Result<bool, BrowserIpcError> {
            Ok(true)
        }
        fn update_login(&self, _: &str, _: &str, _: &str, _: &str, _: &[u8; 32]) -> Result<(), BrowserIpcError> { Ok(()) }
        fn review_login(&self, _: &str, _: &str, _: &str) -> Result<bool, BrowserIpcError> { Ok(true) }
    }

    fn request(action: BrowserAction, id: Option<&str>, token: Option<&str>) -> BrowserRequest {
        BrowserRequest {
            version: BROWSER_PROTOCOL_VERSION,
            request_id: uuid::Uuid::new_v4().to_string(),
            action,
            origin: "https://example.com".to_owned(),
            credential_id: id.map(str::to_owned),
            selection_token: token.map(str::to_owned),
            username: None,
            password: None,
            sealed_login: None,
            title: None,
            ..Default::default()
        }
    }

    #[test]
    fn named_pipe_releases_only_one_selected_password_and_locks() {
        let server = BrowserIpcServer::start().unwrap();
        server.set_provider(Some(Arc::new(ExampleProvider)));
        let query = request(BrowserAction::QueryCredentials, None, None);
        let choices = (0..20)
            .find_map(|_| match send_to_app(&query) {
                Ok(response) => Some(response),
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(10));
                    None
                }
            })
            .expect("named pipe must accept a request");
        assert_eq!(choices.status, "ok");
        let selected = &choices.credentials.unwrap()[0];
        let token = selected.selection_token.clone();

        let fill = send_to_app(&request(
            BrowserAction::FillCredential,
            Some("login-1"),
            Some(&token),
        ))
        .unwrap();
        assert_eq!(fill.credential.unwrap().password, "secret");
        let replay = send_to_app(&request(
            BrowserAction::FillCredential,
            Some("login-1"),
            Some(&token),
        ))
        .unwrap();
        assert_eq!(replay.status, "selection_expired");

        let status = server.status();
        assert!(status.listening);
        assert!(status.last_request_at > 0);
        assert_eq!(status.requests_since_unlock, 3);
        assert_eq!(status.last_action, "Fill on example.com expired. Choose the account again");
        let activity = activity::global().recent(None);
        assert!(activity.iter().any(|event| event.message == "Filled a login on example.com"));
        assert!(activity.iter().all(|event| !event.message.contains("alice")
            && !event.message.contains("secret")
            && !event.message.contains("https://")));

        // A client that connects and never writes is cut off; others are still served meanwhile.
        let mut stalled = std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME).unwrap();
        let started = Instant::now();
        let served = send_to_app(&request(BrowserAction::QueryCredentials, None, None)).unwrap();
        assert_eq!(served.status, "ok");
        assert!(started.elapsed() < REQUEST_TIMEOUT, "a stalled client does not block other requests");
        let mut byte = [0u8; 1];
        assert!(!matches!(stalled.read(&mut byte), Ok(1)), "the stalled client is disconnected");
        assert!(started.elapsed() < REQUEST_TIMEOUT * 4);

        server.set_provider(None);
        assert_eq!(server.status().requests_since_unlock, 0);
        let locked = send_to_app(&request(BrowserAction::QueryCredentials, None, None)).unwrap();
        assert_eq!(locked.status, "locked");
    }

    #[test]
    fn native_host_check_requires_a_registered_existing_manifest() {
        assert!(!native_host_registered(r"Software\Nuvori\Tests\missing-host-key"));
        let key = format!(r"HKCU\Software\Nuvori\Tests\host-{}", uuid::Uuid::new_v4());
        let subkey = key.trim_start_matches(r"HKCU\").to_owned();
        let manifest = std::env::temp_dir().join(format!("nuvori-host-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&manifest, b"{}").unwrap();
        let added = std::process::Command::new("reg")
            .args(["add", &key, "/ve", "/d", manifest.to_str().unwrap(), "/f"])
            .output()
            .unwrap();
        assert!(added.status.success());
        assert!(native_host_registered(&subkey));
        std::fs::remove_file(&manifest).unwrap();
        assert!(!native_host_registered(&subkey), "a stale manifest path is not registered");
        let _ = std::process::Command::new("reg").args(["delete", &key, "/f"]).output();
        assert!(!native_host_registered(&subkey));
    }

    #[test]
    fn browser_activity_names_only_the_site_host() {
        let (level, message) = describe(RequestKind::Save, Some("github.com"), "saved");
        assert_eq!((level, message.as_str()), (Level::Success, "Saved a login from github.com"));
        assert_eq!(describe(RequestKind::Review, Some("a.example"), "needs_save").1, "Reviewed a new login from a.example");
        assert_eq!(describe(RequestKind::Update, Some("a.example"), "saved").1, "Updated a login for a.example");
        assert_eq!(describe(RequestKind::Query, None, "ok").1, "Looked up logins for a site");
    }

    #[test]
    fn selection_grants_are_origin_bound_and_single_use() {
        let mut grants = SelectionGrants::default();
        let token = grants
            .issue("login-1".to_owned(), "https://example.com")
            .unwrap();
        assert!(grants.consume(&token, "login-1", "https://sub.example.com").is_none());
        assert!(grants.consume(&token, "login-1", "https://example.com").is_none());

        let token = grants
            .issue("login-1".to_owned(), "https://example.com")
            .unwrap();
        assert!(grants.consume(&token, "login-2", "https://example.com").is_none());
        assert!(grants.consume(&token, "login-1", "https://example.com").is_none());

        let token = grants
            .issue("login-1".to_owned(), "https://example.com")
            .unwrap();
        assert_eq!(grants.consume(&token, "login-1", "https://example.com"), Some(GrantKind::Login));
        assert!(grants.consume(&token, "login-1", "https://example.com").is_none());
    }

    #[test]
    fn invalid_origins_fail_before_the_provider_is_called() {
        let provider = RwLock::new(None);
        let grants = Mutex::new(SelectionGrants::default());
        let request = BrowserRequest {
            version: BROWSER_PROTOCOL_VERSION,
            request_id: "r1".to_owned(),
            action: BrowserAction::QueryCredentials,
            origin: "https://foo:bar".to_owned(),
            ..Default::default()
        };
        let response = handle_request(request, &provider, &grants).unwrap();
        assert_eq!(response.status, "invalid_request");
    }

    #[test]
    fn password_update_grants_are_separate_from_fill_and_single_use() {
        let mut grants = SelectionGrants::default();
        let fill = grants.issue("login-1".into(), "https://example.com").unwrap();
        assert!(grants.consume_update(&fill, "login-1", "https://example.com").is_none());
        let update = grants.issue("login-1".into(), "https://example.com").unwrap();
        grants.grants.get_mut(&update).unwrap().password_hash = Some([7; 32]);
        assert!(grants.consume(&update, "login-1", "https://example.com").is_none());
        assert!(grants.consume_update(&update, "login-1", "https://example.com").is_none());
        let update = grants.issue("login-1".into(), "https://example.com").unwrap();
        grants.grants.get_mut(&update).unwrap().password_hash = Some([7; 32]);
        assert!(grants.consume_update(&update, "login-1", "https://other.example.com").is_none());
        let update = grants.issue("login-1".into(), "https://example.com").unwrap();
        grants.grants.get_mut(&update).unwrap().password_hash = Some([7; 32]);
        assert_eq!(grants.consume_update(&update, "login-1", "https://example.com"), Some([7; 32]));
        assert!(grants.consume_update(&update, "login-1", "https://example.com").is_none());
    }

    #[test]
    fn sealed_login_waits_while_locked_then_commits_for_its_origin() {
        let pending = PendingLogin {
            version: 1, origin: "https://example.com".to_owned(),
            username: "alice".to_owned(), password: "secret".to_owned(),
            created_at: time::OffsetDateTime::now_utc().unix_timestamp(), title: None,
        };
        let ciphertext = dpapi::protect(&serde_json::to_vec(&pending).unwrap(), "test pending login").unwrap();
        let sealed = URL_SAFE_NO_PAD.encode(ciphertext);
        let provider = RwLock::new(None);
        let grants = Mutex::new(SelectionGrants::default());
        let mut commit = request(BrowserAction::CommitLogin, None, None);
        commit.sealed_login = Some(sealed.clone());
        assert_eq!(handle_request(commit, &provider, &grants).unwrap().status, "locked");
        *provider.write().unwrap() = Some(Arc::new(ExampleProvider));
        let mut wrong_origin = request(BrowserAction::CommitLogin, None, None);
        wrong_origin.origin = "https://other.example.com".to_owned();
        wrong_origin.sealed_login = Some(sealed.clone());
        assert_eq!(handle_request(wrong_origin, &provider, &grants).unwrap().status, "invalid_request");
        let mut commit = request(BrowserAction::CommitLogin, None, None);
        commit.sealed_login = Some(sealed);
        assert_eq!(handle_request(commit, &provider, &grants).unwrap().status, "saved");
    }

    /// Several saved accounts share one username; records saves for assertions.
    struct SharedUsernameProvider {
        saved: Mutex<Vec<(String, String, Option<String>)>>,
    }

    impl BrowserCredentialProvider for SharedUsernameProvider {
        fn query_credentials(&self, _: &str) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
            Ok(vec![
                LoginCandidate { id: "a".into(), title: "Personal".into(), username: "".into(), related: false, passkey: false, color: None, site: None, preview: None },
                LoginCandidate { id: "b".into(), title: "Work".into(), username: "".into(), related: false, passkey: false, color: None, site: None, preview: None },
                LoginCandidate { id: "c".into(), title: "Other".into(), username: "carol".into(), related: false, passkey: false, color: None, site: None, preview: None },
            ])
        }
        fn load_selected_credential(&self, id: &str, _: &str) -> Result<Option<SelectedCredential>, BrowserIpcError> {
            Ok(Some(SelectedCredential { id: id.into(), username: if id == "c" { "carol" } else { "" }.into(), password: format!("old-{id}") }))
        }
        fn save_new_login(&self, _: &str, username: &str, _: &str, title: Option<&str>) -> Result<bool, BrowserIpcError> {
            if username.is_empty() { return Err(BrowserIpcError::LoginConflict); }
            self.saved.lock().unwrap().push((username.into(), String::new(), title.map(str::to_owned)));
            Ok(true)
        }
        fn update_login(&self, _: &str, _: &str, _: &str, _: &str, _: &[u8; 32]) -> Result<(), BrowserIpcError> { Ok(()) }
        fn review_login(&self, _: &str, username: &str, _: &str) -> Result<bool, BrowserIpcError> {
            if username.is_empty() { Err(BrowserIpcError::LoginConflict) } else { Ok(true) }
        }
    }

    fn sealed(username: &str, title: Option<&str>) -> String {
        let pending = PendingLogin {
            version: 1, origin: "https://example.com".to_owned(),
            username: username.to_owned(), password: "new-secret".to_owned(),
            created_at: time::OffsetDateTime::now_utc().unix_timestamp(), title: title.map(str::to_owned),
        };
        URL_SAFE_NO_PAD.encode(dpapi::protect(&serde_json::to_vec(&pending).unwrap(), "test pending login").unwrap())
    }

    /// Saved for seedr.cc only; "Search all logins" may still offer it on any site.
    struct EveryLoginProvider;

    impl BrowserCredentialProvider for EveryLoginProvider {
        fn query_credentials(&self, origin: &str) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
            Ok(if origin == "https://www.seedr.cc" {
                vec![LoginCandidate { id: "seedr".into(), title: "Seedr".into(), username: "me@example.com".into(), related: false, passkey: false, color: None, site: None, preview: None }]
            } else {
                Vec::new()
            })
        }
        fn load_selected_credential(&self, id: &str, origin: &str) -> Result<Option<SelectedCredential>, BrowserIpcError> {
            Ok((id == "seedr" && origin == "https://www.seedr.cc").then(|| SelectedCredential {
                id: id.into(), username: "me@example.com".into(), password: "seedr-pass".into() }))
        }
        fn query_all_credentials(&self) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
            Ok(vec![
                LoginCandidate { id: "seedr".into(), title: "Seedr".into(), username: "me@example.com".into(), related: false, passkey: true, color: None, site: Some("seedr.cc".into()), preview: None },
                LoginCandidate { id: "bank".into(), title: "Bank".into(), username: "me".into(), related: false, passkey: false, color: None, site: Some("bank.example".into()), preview: None },
            ])
        }
        fn load_any_credential(&self, id: &str) -> Result<Option<SelectedCredential>, BrowserIpcError> {
            Ok((id == "seedr").then(|| SelectedCredential { id: id.into(), username: "me@example.com".into(), password: "seedr-pass".into() }))
        }
        fn save_new_login(&self, _: &str, _: &str, _: &str, _: Option<&str>) -> Result<bool, BrowserIpcError> { Ok(true) }
        fn update_login(&self, _: &str, _: &str, _: &str, _: &str, _: &[u8; 32]) -> Result<(), BrowserIpcError> { Ok(()) }
        fn review_login(&self, _: &str, _: &str, _: &str) -> Result<bool, BrowserIpcError> { Ok(true) }
    }

    #[test]
    fn all_logins_lists_every_login_and_fills_the_chosen_one_on_that_page_only() {
        let provider: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(Some(Arc::new(EveryLoginProvider)));
        let grants = Mutex::new(SelectionGrants::default());
        let on = |action, origin: &str, id: Option<&str>, token: Option<&str>, all: Option<bool>| {
            let mut request = request(action, id, token);
            request.origin = origin.to_owned();
            request.all = all;
            request
        };
        // The page's own listing has nothing for this site; the full listing has every login and its site.
        let matched = handle_request(on(BrowserAction::QueryCredentials, "https://other.example", None, None, None), &provider, &grants).unwrap();
        assert!(matched.credentials.unwrap().is_empty());
        let every = handle_request(on(BrowserAction::QueryCredentials, "https://other.example", None, None, Some(true)), &provider, &grants).unwrap();
        let choices = every.credentials.unwrap();
        assert_eq!(choices.iter().map(|choice| choice.site.as_deref().unwrap()).collect::<Vec<_>>(), ["seedr.cc", "bank.example"]);
        let token = choices[0].selection_token.clone();
        assert!(serde_json::to_string(&choices[0]).unwrap().contains("\"site\":\"seedr.cc\""));
        // "passkey_mark" goes to the extension when set, and is left out (not false) otherwise.
        assert!(serde_json::to_string(&choices[0]).unwrap().contains("\"passkey\":true"));
        assert!(!serde_json::to_string(&choices[1]).unwrap().contains("passkey"));

        // The token works for that login on the page it was listed for, and not on another page.
        let elsewhere = handle_request(on(BrowserAction::FillCredential, "https://evil.example", Some("seedr"), Some(&token), None), &provider, &grants).unwrap();
        assert_eq!(elsewhere.status, "selection_expired");
        let every = handle_request(on(BrowserAction::QueryCredentials, "https://other.example", None, None, Some(true)), &provider, &grants).unwrap();
        let token = every.credentials.unwrap()[0].selection_token.clone();
        let filled = handle_request(on(BrowserAction::FillCredential, "https://other.example", Some("seedr"), Some(&token), None), &provider, &grants).unwrap();
        assert_eq!(filled.status, "ok");
        assert_eq!(filled.credential.as_ref().unwrap().password, "seedr-pass");
        // Single use.
        let replay = handle_request(on(BrowserAction::FillCredential, "https://other.example", Some("seedr"), Some(&token), None), &provider, &grants).unwrap();
        assert_eq!(replay.status, "selection_expired");
        // A token from the full listing never updates a login.
        let every = handle_request(on(BrowserAction::QueryCredentials, "https://other.example", None, None, Some(true)), &provider, &grants).unwrap();
        let token = every.credentials.unwrap()[0].selection_token.clone();
        assert!(grants.lock().unwrap().consume_update(&token, "seedr", "https://other.example").is_none());
        // "all" belongs to listings only.
        let misplaced = handle_request(on(BrowserAction::FillCredential, "https://other.example", Some("seedr"), Some(&"0".repeat(64)), Some(true)), &provider, &grants).unwrap();
        assert_eq!(misplaced.status, "invalid_request");
        // Matched listings keep releasing only matching logins.
        let own = handle_request(on(BrowserAction::QueryCredentials, "https://www.seedr.cc", None, None, None), &provider, &grants).unwrap();
        let token = own.credentials.unwrap()[0].selection_token.clone();
        let filled = handle_request(on(BrowserAction::FillCredential, "https://www.seedr.cc", Some("seedr"), Some(&token), None), &provider, &grants).unwrap();
        assert_eq!(filled.credential.unwrap().username, "me@example.com");
    }

    #[test]
    fn status_without_origin_lists_features_but_other_actions_need_an_origin() {
        let provider: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(None);
        let grants = Mutex::new(SelectionGrants::default());
        let mut status = request(BrowserAction::Status, None, None);
        status.origin = String::new();
        let locked = handle_request(status, &provider, &grants).unwrap();
        assert_eq!(locked.status, "locked");
        assert_eq!(locked.features.as_ref().unwrap().len(), crate::browser::BROWSER_FEATURES.len());
        *provider.write().unwrap() = Some(Arc::new(ExampleProvider));
        let mut status = request(BrowserAction::Status, None, None);
        status.origin = String::new();
        let ok = handle_request(status, &provider, &grants).unwrap();
        assert_eq!(ok.status, "ok");
        assert!(ok.features.unwrap().contains(&"multi_update".to_owned()));
        let mut query = request(BrowserAction::QueryCredentials, None, None);
        query.origin = String::new();
        assert_eq!(handle_request(query, &provider, &grants).unwrap().status, "invalid_request");
        let query = handle_request(request(BrowserAction::QueryCredentials, None, None), &provider, &grants).unwrap();
        assert!(query.features.is_none());
    }

    struct CardProvider;

    impl BrowserCredentialProvider for CardProvider {
        fn query_credentials(&self, _: &str) -> Result<Vec<LoginCandidate>, BrowserIpcError> { Ok(Vec::new()) }
        fn load_selected_credential(&self, _: &str, _: &str) -> Result<Option<SelectedCredential>, BrowserIpcError> { Ok(None) }
        fn save_new_login(&self, _: &str, _: &str, _: &str, _: Option<&str>) -> Result<bool, BrowserIpcError> { Ok(true) }
        fn update_login(&self, _: &str, _: &str, _: &str, _: &str, _: &[u8; 32]) -> Result<(), BrowserIpcError> { Ok(()) }
        fn review_login(&self, _: &str, _: &str, _: &str) -> Result<bool, BrowserIpcError> { Ok(true) }
        fn query_items(&self, kind: ItemKind, _: &str, _: bool) -> Result<Vec<LoginCandidate>, BrowserIpcError> {
            let home = ProfileDetails { name: "Alice Smith".into(), email: "alice@example.com".into(), postal_code: "78701".into(), ..Default::default() };
            Ok(match kind {
                // A provider that sends values with a card must not get them through.
                ItemKind::Card => vec![LoginCandidate { id: "card-1".into(), title: "Travel".into(), username: "Visa · •••• 1111".into(), related: false, passkey: false, color: Some(0xFF31_5B8C), site: None, preview: Some(home) }],
                ItemKind::Profile => vec![LoginCandidate { id: "home".into(), title: "Home".into(), username: "Alice Smith".into(), related: false, passkey: false, color: None, site: None, preview: Some(home) }],
                ItemKind::Code => Vec::new(),
            })
        }
        fn load_item(&self, kind: ItemKind, id: &str, _: &str) -> Result<Option<FilledItem>, BrowserIpcError> {
            Ok(Some(FilledItem { id: id.into(), kind, card: Some(CardDetails::with("4111111111111111", "12/29", "123")),
                profile: None, code: None, cvv_token: None }))
        }
    }

    #[test]
    fn card_codes_wait_for_approval_and_tokens_keep_their_kind() {
        let provider: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(Some(Arc::new(CardProvider)));
        let grants = Mutex::new(SelectionGrants::default());
        let item = |action: BrowserAction, token: &str| {
            let mut request = request(action, Some("card-1"), Some(token));
            request.kind = Some(ItemKind::Card);
            request
        };
        let card_token = || {
            let mut query = request(BrowserAction::QueryItems, None, None);
            query.kind = Some(ItemKind::Card);
            handle_request(query, &provider, &grants).unwrap().credentials.unwrap().remove(0).selection_token
        };
        // The listing carries the card's color for its row, and only for cards.
        let mut listing = request(BrowserAction::QueryItems, None, None);
        listing.kind = Some(ItemKind::Card);
        let listed = handle_request(listing, &provider, &grants).unwrap();
        assert_eq!(listed.credentials.as_ref().unwrap()[0].color, Some(0xFF31_5B8C));
        assert!(serde_json::to_string(&listed).unwrap().contains("\"color\":4281424780"));
        assert!(listed.credentials.as_ref().unwrap()[0].preview.is_none(), "values are listed for addresses only");
        // An address listing carries its values, so the row can show the focused field's value.
        let mut addresses = request(BrowserAction::QueryItems, None, None);
        addresses.kind = Some(ItemKind::Profile);
        let addresses = serde_json::to_value(handle_request(addresses, &provider, &grants).unwrap()).unwrap();
        assert_eq!(addresses["credentials"][0]["preview"]["email"], "alice@example.com");
        assert_eq!(addresses["credentials"][0]["preview"]["postalCode"], "78701");
        // A card token never releases a login, and a login request can't list items.
        let token = card_token();
        assert_eq!(handle_request(request(BrowserAction::FillCredential, Some("card-1"), Some(&token)), &provider, &grants).unwrap().status, "selection_expired");
        let mut wrong_kind = item(BrowserAction::FillItem, &card_token());
        wrong_kind.kind = Some(ItemKind::Profile);
        assert_eq!(handle_request(wrong_kind, &provider, &grants).unwrap().status, "selection_expired");

        let filled = handle_request(item(BrowserAction::FillItem, &card_token()), &provider, &grants).unwrap();
        let filled = filled.item.unwrap();
        let card = filled.card.as_ref().unwrap();
        assert_eq!((card.number.as_str(), card.cvv.as_str()), ("4111111111111111", ""), "no security code without approval");
        let code_token = filled.cvv_token.clone().unwrap();
        assert_eq!(handle_request(item(BrowserAction::FillCvv, &code_token), &provider, &grants).unwrap().status, "selection_expired");
        assert_eq!(handle_request(item(BrowserAction::RequestCvv, &code_token), &provider, &grants).unwrap().status, "pending");
        assert_eq!(handle_request(item(BrowserAction::FillCvv, &code_token), &provider, &grants).unwrap().status, "pending");
        assert!(grants.lock().unwrap().resolve_cvv(&code_token, true));
        let released = handle_request(item(BrowserAction::FillCvv, &code_token), &provider, &grants).unwrap();
        let released = released.item.unwrap();
        let only = released.card.as_ref().unwrap();
        assert_eq!((only.cvv.as_str(), only.number.as_str()), ("123", ""));
        assert_eq!(handle_request(item(BrowserAction::FillCvv, &code_token), &provider, &grants).unwrap().status, "selection_expired", "single use");

        // Declined codes are never released.
        let filled = handle_request(item(BrowserAction::FillItem, &card_token()), &provider, &grants).unwrap();
        let declined = filled.item.unwrap().cvv_token.clone().unwrap();
        handle_request(item(BrowserAction::RequestCvv, &declined), &provider, &grants).unwrap();
        assert!(grants.lock().unwrap().resolve_cvv(&declined, false));
        assert_eq!(handle_request(item(BrowserAction::FillCvv, &declined), &provider, &grants).unwrap().status, "denied");
    }

    fn process(pid: u32, parent: u32, exe: &str) -> ProcessEntry {
        ProcessEntry { pid, parent, exe: exe.to_owned() }
    }

    #[test]
    fn the_calling_browser_is_the_first_program_above_the_host_that_is_not_a_relay() {
        // Chrome starts native hosts through cmd.exe.
        let table = [process(1, 0, "explorer.exe"), process(10, 1, "chrome.exe"), process(11, 10, "cmd.exe"),
            process(12, 11, "conhost.exe"), process(13, 11, "nuvori-native-host.exe")];
        assert_eq!(browser_of_chain(&table, 13).as_deref(), Some("chrome"));
        // Firefox starts the host itself.
        let table = [process(20, 1, "Zen.exe"), process(21, 20, "nuvori-native-host.exe")];
        assert_eq!(browser_of_chain(&table, 21).as_deref(), Some("zen"));
        assert_eq!(browser_of_chain(&[process(30, 1, "opera.exe"), process(31, 30, "launcher.exe"), process(32, 31, "cmd.exe"), process(33, 32, "nuvori-native-host.exe")], 33).as_deref(), Some("opera"));
        // More than 4 relays, a missing parent, or an unknown PID: no answer.
        let deep = [process(1, 0, "a.exe"), process(2, 1, "cmd.exe"), process(3, 2, "cmd.exe"), process(4, 3, "cmd.exe"),
            process(5, 4, "cmd.exe"), process(6, 5, "nuvori-native-host.exe")];
        assert_eq!(browser_of_chain(&deep, 6), None);
        assert_eq!(browser_of_chain(&[process(6, 99, "nuvori-native-host.exe")], 6), None);
        assert_eq!(browser_of_chain(&table, 777), None);
        assert_eq!(browser_id_from_exe(r"C:\Apps\My Browser (x64).EXE").as_deref(), Some("my-browser--x64-"));
        assert!(valid_browser_id("zen") && !valid_browser_id("Zen") && !valid_browser_id("") && !valid_browser_id(&"a".repeat(41)));
        // The real snapshot sees this test process under its parent.
        assert!(process_table().iter().any(|entry| entry.pid == std::process::id()));
    }

    #[test]
    fn a_startup_prompt_is_skipped_for_a_browser_that_does_not_ask_and_only_on_unlock_prompt() {
        let provider: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(None);
        let grants = Mutex::new(SelectionGrants::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let hooks = {
            let seen = Arc::clone(&seen);
            BrowserHooks {
                seen: Box::new(move |id| seen.lock().unwrap().push(id.to_owned())),
                ask_at_start: Box::new(|id| id != "zen"),
            }
        };
        let prompt = |browser: Option<&str>, startup: Option<bool>| {
            let mut prompt = request(BrowserAction::UnlockPrompt, None, None);
            prompt.origin = String::new();
            prompt.browser = browser.map(str::to_owned);
            prompt.startup = startup;
            prompt
        };
        let status = |request| handle_request_with(request, &provider, &grants, Some(&hooks)).unwrap();
        let skipped = status(prompt(Some("zen"), Some(true)));
        assert_eq!((skipped.status.as_str(), skipped.message.as_str()), ("skipped", ""));
        assert_eq!(status(prompt(Some("chrome"), Some(true))).status, "locked", "chrome asks");
        assert_eq!(status(prompt(Some("zen"), None)).status, "locked", "a prompt that is not a start-up one always runs");
        assert_eq!(status(prompt(Some("zen"), Some(false))).status, "locked");
        assert_eq!(status(prompt(None, Some(true))).status, "locked", "an old host sends no browser: ask");
        assert_eq!(*seen.lock().unwrap(), ["zen", "chrome", "zen", "zen"], "every request with a browser is recorded");
        // `startup` belongs to unlock_prompt only; a malformed browser id is refused.
        let mut query = request(BrowserAction::QueryCredentials, None, None);
        query.startup = Some(true);
        assert_eq!(status(query).status, "invalid_request");
        let mut bad = request(BrowserAction::Status, None, None);
        bad.origin = String::new();
        bad.browser = Some("Bad Id".into());
        assert_eq!(status(bad).status, "invalid_request");
        // The request JSON accepts both fields and the host's browser field.
        let json: BrowserRequest = serde_json::from_str(r#"{"version":2,"requestId":"r","action":"unlock_prompt","origin":"","startup":true,"browser":"zen"}"#).unwrap();
        assert_eq!((json.startup, json.browser.as_deref()), (Some(true), Some("zen")));
    }

    #[test]
    fn unlock_prompt_reports_the_vault_state_and_takes_no_origin_or_fields() {
        let provider: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(None);
        let grants = Mutex::new(SelectionGrants::default());
        let prompt = |origin: &str| {
            let mut prompt = request(BrowserAction::UnlockPrompt, None, None);
            prompt.origin = origin.to_owned();
            prompt
        };
        assert_eq!(handle_request(prompt(""), &provider, &grants).unwrap().status, "locked");
        assert_eq!(handle_request(prompt("https://example.com"), &provider, &grants).unwrap().status, "invalid_request");
        let mut with_secret = prompt("");
        with_secret.password = Some("p".into());
        assert_eq!(handle_request(with_secret, &provider, &grants).unwrap().status, "invalid_request");
        *provider.write().unwrap() = Some(Arc::new(ExampleProvider));
        let unlocked = handle_request(prompt(""), &provider, &grants).unwrap();
        assert_eq!(unlocked.status, "ok");
        assert!(unlocked.credentials.is_none() && unlocked.credential.is_none());
    }

    #[test]
    fn password_only_conflicts_offer_every_matching_account_with_bound_tokens() {
        let provider_impl = Arc::new(SharedUsernameProvider { saved: Mutex::new(Vec::new()) });
        let provider: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(Some(provider_impl.clone()));
        let grants = Mutex::new(SelectionGrants::default());
        let mut review = request(BrowserAction::ReviewLogin, None, None);
        review.sealed_login = Some(sealed("", None));
        let response = handle_request(review, &provider, &grants).unwrap();
        assert_eq!(response.status, "account_exists");
        let choices = response.credentials.unwrap();
        assert_eq!(choices.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["a", "b"], "only empty-username accounts match");
        assert!(choices.iter().all(|c| c.username.is_empty()));
        let mut store = grants.lock().unwrap();
        let hash: [u8; 32] = Sha256::digest(b"old-b").into();
        assert!(store.consume_update(&choices[0].selection_token, "b", "https://example.com").is_none(), "token is bound to its record");
        assert_eq!(store.consume_update(&choices[1].selection_token, "b", "https://example.com"), Some(hash));
        assert!(store.consume_update(&choices[1].selection_token, "b", "https://example.com").is_none(), "one use");
        drop(store);
        let mut commit = request(BrowserAction::CommitLogin, None, None);
        commit.sealed_login = Some(sealed("", None));
        let committed = handle_request(commit, &provider, &grants).unwrap();
        assert_eq!((committed.status.as_str(), committed.credentials.unwrap().len()), ("account_exists", 2));
        assert_eq!(committed.message, "Choose which saved account to update.");
    }

    #[test]
    fn login_titles_come_from_commit_or_seal_and_are_validated() {
        let provider_impl = Arc::new(SharedUsernameProvider { saved: Mutex::new(Vec::new()) });
        let provider: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(Some(provider_impl.clone()));
        let grants = Mutex::new(SelectionGrants::default());
        let mut commit = request(BrowserAction::CommitLogin, None, None);
        commit.sealed_login = Some(sealed("dave", Some("Sealed name")));
        assert_eq!(handle_request(commit, &provider, &grants).unwrap().status, "saved");
        let mut commit = request(BrowserAction::CommitLogin, None, None);
        commit.sealed_login = Some(sealed("erin", Some("Sealed name")));
        commit.title = Some("Reviewed name".into());
        assert_eq!(handle_request(commit, &provider, &grants).unwrap().status, "saved");
        let mut commit = request(BrowserAction::CommitLogin, None, None);
        commit.sealed_login = Some(sealed("fay", None));
        assert_eq!(handle_request(commit, &provider, &grants).unwrap().status, "saved");
        let saved = provider_impl.saved.lock().unwrap().clone();
        assert_eq!(saved.iter().map(|s| s.2.clone()).collect::<Vec<_>>(),
            vec![Some("Sealed name".to_owned()), Some("Reviewed name".to_owned()), None]);
        let mut bad = request(BrowserAction::CommitLogin, None, None);
        bad.sealed_login = Some(sealed("gus", None));
        bad.title = Some("Line\nbreak".into());
        assert_eq!(handle_request(bad, &provider, &grants).unwrap().status, "invalid_request");
        let mut misplaced = request(BrowserAction::QueryCredentials, None, None);
        misplaced.title = Some("Name".into());
        assert_eq!(handle_request(misplaced, &provider, &grants).unwrap().status, "invalid_request");
        let mut bad_seal = request(BrowserAction::CommitLogin, None, None);
        bad_seal.sealed_login = Some(sealed("hal", Some(&"x".repeat(300))));
        assert_eq!(handle_request(bad_seal, &provider, &grants).unwrap().status, "invalid_request");
        assert!(activity::global().recent(None).iter().all(|e| !e.message.contains("name")));
    }

    /// Wants an icon for example.com only, and records what `save_site_icon` receives.
    struct IconProvider { saved: Mutex<Vec<(String, Vec<u8>)>> }

    impl BrowserCredentialProvider for IconProvider {
        fn query_credentials(&self, _: &str) -> Result<Vec<LoginCandidate>, BrowserIpcError> { Ok(Vec::new()) }
        fn load_selected_credential(&self, _: &str, _: &str) -> Result<Option<SelectedCredential>, BrowserIpcError> { Ok(None) }
        fn save_new_login(&self, _: &str, _: &str, _: &str, _: Option<&str>) -> Result<bool, BrowserIpcError> { Ok(true) }
        fn update_login(&self, _: &str, _: &str, _: &str, _: &str, _: &[u8; 32]) -> Result<(), BrowserIpcError> { Ok(()) }
        fn review_login(&self, _: &str, _: &str, _: &str) -> Result<bool, BrowserIpcError> { Ok(true) }
        fn icon_wanted(&self, origin: &str) -> Result<bool, BrowserIpcError> { Ok(origin == "https://example.com") }
        fn save_site_icon(&self, origin: &str, png: &[u8]) -> Result<(), BrowserIpcError> {
            if png.starts_with(b"\x89PNG") {
                self.saved.lock().unwrap().push((origin.to_owned(), png.to_vec()));
                Ok(())
            } else {
                Err(BrowserIpcError::InvalidRequest)
            }
        }
    }

    #[test]
    fn site_icons_ride_on_query_credentials_and_save_site_icon() {
        use base64::engine::general_purpose::STANDARD;
        let icons = Arc::new(IconProvider { saved: Mutex::new(Vec::new()) });
        let provider: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(Some(icons.clone()));
        let grants = Mutex::new(SelectionGrants::default());
        let icon_request = |icon: Option<String>| {
            let mut save = request(BrowserAction::SaveSiteIcon, None, None);
            save.icon = icon;
            save
        };
        let png = b"\x89PNG\r\n\x1a\nrest";

        // `iconWanted` is present only when true.
        let wanted = handle_request(request(BrowserAction::QueryCredentials, None, None), &provider, &grants).unwrap();
        assert!(wanted.icon_wanted);
        assert_eq!(serde_json::to_value(&wanted).unwrap()["iconWanted"], true);
        let mut other = request(BrowserAction::QueryCredentials, None, None);
        other.origin = "https://other.example".into();
        let unwanted = serde_json::to_value(handle_request(other, &provider, &grants).unwrap()).unwrap();
        assert!(unwanted.get("iconWanted").is_none());

        // A good icon reaches the provider, with the origin.
        let saved = handle_request(icon_request(Some(STANDARD.encode(png))), &provider, &grants).unwrap();
        assert_eq!(saved.status, "ok");
        assert_eq!(icons.saved.lock().unwrap().as_slice(), [("https://example.com".to_owned(), png.to_vec())]);

        // Missing, bad base64, URL-safe alphabet, a data: prefix, too long, and refused bytes all fail.
        let invalid = |icon: Option<String>| handle_request(icon_request(icon), &provider, &grants).unwrap().status;
        assert_eq!(invalid(None), "invalid_request");
        assert_eq!(invalid(Some("not base64!".into())), "invalid_request");
        assert_eq!(invalid(Some(format!("data:image/png;base64,{}", STANDARD.encode(png)))), "invalid_request");
        assert_eq!(invalid(Some(STANDARD.encode(vec![0u8; MAX_ICON_BYTES + 3]))), "invalid_request");
        assert_eq!(invalid(Some(STANDARD.encode(b"GIF89a"))), "invalid_request");
        assert_eq!(icons.saved.lock().unwrap().len(), 1);

        // Extra fields are rejected on this action.
        let mut extra = icon_request(Some(STANDARD.encode(png)));
        extra.username = Some("u".into());
        assert_eq!(handle_request(extra, &provider, &grants).unwrap().status, "invalid_request");

        // `icon` belongs to no other action.
        for action in [BrowserAction::QueryCredentials, BrowserAction::FillCredential, BrowserAction::Status, BrowserAction::CommitLogin, BrowserAction::UnlockPrompt] {
            let mut misplaced = request(action, Some("id"), Some("token"));
            misplaced.icon = Some(STANDARD.encode(png));
            assert_eq!(handle_request(misplaced, &provider, &grants).unwrap().status, "invalid_request");
        }

        // A locked vault (no provider) answers "locked" and stores nothing.
        let locked: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(None);
        let response = handle_request(icon_request(Some(STANDARD.encode(png))), &locked, &grants).unwrap();
        assert_eq!(response.status, "locked");
        assert_eq!(icons.saved.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_request_parser_knows_the_icon_field() {
        let parsed: BrowserRequest = serde_json::from_str(
            r#"{"version":2,"requestId":"r","action":"save_site_icon","origin":"https://a.example","icon":"AAAA"}"#,
        ).unwrap();
        assert!(matches!(parsed.action, BrowserAction::SaveSiteIcon));
        assert_eq!(parsed.icon.as_deref(), Some("AAAA"));
        assert!(serde_json::from_str::<BrowserRequest>(r#"{"version":2,"requestId":"r","action":"status","origin":"","image":"x"}"#).is_err());
    }

    #[test]
    fn login_checks_are_limited_per_site_per_minute() {
        let mut grants = SelectionGrants::default();
        for _ in 0..LOGIN_CHECKS_PER_MINUTE {
            assert!(grants.allow_login_check("https://a.example"));
        }
        assert!(!grants.allow_login_check("https://a.example"));
        assert!(grants.allow_login_check("https://b.example"), "the limit is per site");
        let provider: RwLock<Option<Arc<dyn BrowserCredentialProvider>>> = RwLock::new(Some(Arc::new(ExampleProvider)));
        let grants = Mutex::new(SelectionGrants::default());
        let statuses: Vec<String> = (0..LOGIN_CHECKS_PER_MINUTE + 1)
            .map(|_| {
                let mut review = request(BrowserAction::ReviewLogin, None, None);
                review.sealed_login = Some("not-a-real-seal".into());
                match handle_request(review, &provider, &grants) {
                    Ok(response) => response.status,
                    Err(_) => "invalid".into(),
                }
            })
            .collect();
        assert_eq!(statuses.last().unwrap(), "rate_limited");
        assert!(statuses[..LOGIN_CHECKS_PER_MINUTE].iter().all(|status| status != "rate_limited"));
    }

    #[test]
    fn untrusted_paths_are_not_pipe_servers() {
        let images = trusted_server_images();
        assert!(images.iter().any(|image| image.ends_with("nuvori.exe")));
        assert!(!images.iter().any(|image| same_path(image, Path::new(r"C:\\Windows\\System32\\notepad.exe"))));
        assert!(same_path(Path::new(r"C:\\A\\Nuvori.EXE"), Path::new(r"c:\\a\\nuvori.exe")));
    }
}
