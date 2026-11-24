//! Auto-lock (H-03). The backend decides when the vault locks, so it locks even when no window
//! is open: Nuvori keeps running in the tray, the small unlock window closes after an unlock, and
//! the browser extension can start the app with `--background`.
//!
//! - Idle: a background thread locks the vault once nothing has counted as user activity for the
//!   configured minutes. Activity is the app's windows reporting input (`note_user_activity`,
//!   throttled by the page) and browser requests that a user started (a fill, a save).
//! - Windows: the vault also locks when the Windows session locks (Win+L, lid, screen lock) and
//!   when the PC goes to sleep or hibernates.
//!
//! The minutes are a device-only preference in `auto-lock.json` next to the vault. Older builds
//! kept it in the main window's localStorage; until this file exists, the main window sends that
//! value once (`saved` is false until then). The main window's own timer still runs as a second,
//! weaker path.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};

use serde::Serialize;

const SETTINGS_FILE: &str = "auto-lock.json";
/// The main window's default before this setting moved to the backend.
pub const DEFAULT_MINUTES: u32 = 15;
/// The longest delay accepted (one day). 0 turns idle locking off; session lock and sleep still lock.
pub const MAX_MINUTES: u32 = 24 * 60;
const TICK: Duration = Duration::from_secs(5);

/// Why the backend locked the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Idle,
    SessionLocked,
    Suspend,
}

impl Reason {
    pub fn message(self) -> &'static str {
        match self {
            Reason::Idle => "Vault locked after inactivity",
            Reason::SessionLocked => "Vault locked because Windows was locked",
            Reason::Suspend => "Vault locked because the PC went to sleep",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub minutes: u32,
    /// False until a value was saved in the backend: the main window then sends its old one.
    pub saved: bool,
}

/// `{"minutes": n}`; anything else (or a value over `MAX_MINUTES`) is `None`.
pub fn parse_settings(text: &str) -> Option<u32> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let minutes = u32::try_from(value.get("minutes")?.as_u64()?).ok()?;
    (minutes <= MAX_MINUTES).then_some(minutes)
}

pub fn settings_json(minutes: u32) -> String {
    serde_json::json!({ "minutes": minutes }).to_string()
}

/// Idle time since the last activity. The larger of the monotonic and the wall-clock time, so time
/// the PC spent asleep counts even where the monotonic clock stops during sleep.
pub fn idle_for(last: (Instant, SystemTime), now: (Instant, SystemTime)) -> Duration {
    let monotonic = now.0.saturating_duration_since(last.0);
    let wall = now.1.duration_since(last.1).unwrap_or_default();
    monotonic.max(wall)
}

/// True when `minutes` of idle time are up. 0 never locks.
pub fn idle_expired(minutes: u32, idle: Duration) -> bool {
    minutes > 0 && idle >= Duration::from_secs(u64::from(minutes) * 60)
}

struct Inner {
    minutes: u32,
    saved: bool,
    last_activity: (Instant, SystemTime),
}

pub struct AutoLock {
    file: Option<PathBuf>,
    inner: Mutex<Inner>,
}

fn now() -> (Instant, SystemTime) {
    (Instant::now(), SystemTime::now())
}

impl AutoLock {
    /// Reads `auto-lock.json` from `directory`; without it, the default applies until the main
    /// window sends its old value.
    pub fn new(directory: PathBuf) -> Arc<Self> {
        let file = directory.join(SETTINGS_FILE);
        let saved = std::fs::read_to_string(&file).ok().and_then(|text| parse_settings(&text));
        Arc::new(Self {
            file: Some(file),
            inner: Mutex::new(Inner { minutes: saved.unwrap_or(DEFAULT_MINUTES), saved: saved.is_some(), last_activity: now() }),
        })
    }

    #[cfg(test)]
    fn in_memory(minutes: u32) -> Self {
        Self { file: None, inner: Mutex::new(Inner { minutes, saved: false, last_activity: now() }) }
    }

    pub fn status(&self) -> Status {
        let inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Status { minutes: inner.minutes, saved: inner.saved }
    }

    /// Saves a new delay. A value that can't be saved still applies until the app closes.
    pub fn set_minutes(&self, minutes: u32) -> Result<Status, String> {
        if minutes > MAX_MINUTES {
            return Err("Choose a shorter auto-lock delay".to_owned());
        }
        {
            let mut inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            inner.minutes = minutes;
            inner.saved = true;
            inner.last_activity = now();
        }
        if let Some(file) = &self.file {
            file.parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::write(file, settings_json(minutes)))
                .map_err(|_| "The auto-lock setting could not be saved".to_owned())?;
        }
        Ok(self.status())
    }

    /// Counts user activity now.
    pub fn touch(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.last_activity = now();
    }

    fn expired_at(&self, at: (Instant, SystemTime)) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        idle_expired(inner.minutes, idle_for(inner.last_activity, at))
    }

    /// One timer step. `unlocked` is `None` while the vault state is busy. While locked, the idle
    /// time starts over, so it counts from the unlock. Returns true when the vault should lock.
    fn step(&self, unlocked: Option<bool>, at: (Instant, SystemTime)) -> bool {
        match unlocked {
            Some(false) => {
                self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).last_activity = at;
                false
            }
            Some(true) => self.expired_at(at),
            None => false,
        }
    }

    /// Starts the idle timer, and on Windows the session lock and sleep watcher. `is_unlocked`
    /// answers `None` when it can't tell right now; `lock` locks the vault (and may block).
    pub fn start(
        self: &Arc<Self>,
        is_unlocked: impl Fn() -> Option<bool> + Send + 'static,
        lock: impl Fn(Reason) + Send + Sync + 'static,
    ) {
        let lock = Arc::new(lock);
        let timer = Arc::clone(self);
        let timer_lock = Arc::clone(&lock);
        let _ = thread::Builder::new().name("nuvori-auto-lock".to_owned()).spawn(move || loop {
            thread::sleep(TICK);
            if timer.step(is_unlocked(), now()) {
                timer_lock(Reason::Idle);
                timer.touch();
            }
        });
        #[cfg(windows)]
        session::watch(move |reason| lock(reason));
        #[cfg(not(windows))]
        drop(lock);
    }
}

/// Windows: a hidden top-level window (never shown) that hears session changes
/// (`WTSRegisterSessionNotification`) and power broadcasts. A message-only window would miss
/// `WM_POWERBROADCAST`, which Windows broadcasts to top-level windows.
#[cfg(windows)]
mod session {
    use std::{
        sync::{OnceLock, mpsc},
        thread,
        time::Duration,
    };

    use windows::{
        Win32::{
            Foundation::{HWND, LPARAM, LRESULT, WPARAM},
            System::{
                LibraryLoader::GetModuleHandleW,
                RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification},
            },
            UI::WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, MSG, PBT_APMSUSPEND,
                RegisterClassW, TranslateMessage, WINDOW_STYLE, WM_POWERBROADCAST,
                WM_WTSSESSION_CHANGE, WNDCLASSW, WS_EX_TOOLWINDOW, WTS_SESSION_LOCK,
            },
        },
        core::w,
    };

    use super::Reason;

    type Handler = Box<dyn Fn(Reason) + Send + Sync>;
    static HANDLER: OnceLock<Handler> = OnceLock::new();
    /// Sleep gives a program about two seconds; the lock waits at most this long.
    const SUSPEND_WAIT: Duration = Duration::from_millis(1500);

    pub fn watch(handler: impl Fn(Reason) + Send + Sync + 'static) {
        if HANDLER.set(Box::new(handler)).is_err() {
            return;
        }
        let _ = thread::Builder::new().name("nuvori-session-watch".to_owned()).spawn(run);
    }

    /// Locks on its own thread and waits up to `SUSPEND_WAIT`, so a vault held by a sync for a
    /// moment never stalls this window's messages for long.
    fn lock_now(reason: Reason) {
        let (done, finished) = mpsc::channel();
        let started = thread::Builder::new().name("nuvori-session-lock".to_owned()).spawn(move || {
            if let Some(handler) = HANDLER.get() {
                handler(reason);
            }
            let _ = done.send(());
        });
        if started.is_ok() {
            let _ = finished.recv_timeout(SUSPEND_WAIT);
        }
    }

    unsafe extern "system" fn window_proc(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        match message {
            WM_WTSSESSION_CHANGE if wparam.0 as u32 == WTS_SESSION_LOCK => {
                lock_now(Reason::SessionLocked);
                LRESULT(0)
            }
            WM_POWERBROADCAST => {
                if wparam.0 as u32 == PBT_APMSUSPEND {
                    lock_now(Reason::Suspend);
                }
                LRESULT(1)
            }
            _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
        }
    }

    fn run() {
        unsafe {
            let Ok(module) = GetModuleHandleW(None) else { return };
            let class = w!("NuvoriSessionWatch");
            let description = WNDCLASSW { lpfnWndProc: Some(window_proc), hInstance: module.into(), lpszClassName: class, ..Default::default() };
            if RegisterClassW(&description) == 0 {
                return;
            }
            let Ok(window) = CreateWindowExW(WS_EX_TOOLWINDOW, class, w!("Nuvori"), WINDOW_STYLE(0), 0, 0, 0, 0,
                None, None, Some(module.into()), None)
            else {
                return;
            };
            // Without session notifications, sleep and the idle timer still lock.
            let _ = WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION);
            let mut message = MSG::default();
            while GetMessageW(&mut message, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_parse_and_reject_bad_values() {
        assert_eq!(parse_settings(&settings_json(5)), Some(5));
        assert_eq!(parse_settings(r#"{"minutes":0}"#), Some(0));
        assert_eq!(parse_settings(r#"{"minutes":1440}"#), Some(1440));
        for text in ["", "not json", "{}", r#"{"minutes":-1}"#, r#"{"minutes":1441}"#, r#"{"minutes":"5"}"#, r#"{"minutes":2.5}"#] {
            assert_eq!(parse_settings(text), None, "{text}");
        }
    }

    #[test]
    fn idle_time_counts_the_larger_clock_and_zero_minutes_never_expires() {
        let start = (Instant::now(), SystemTime::now());
        let later = (start.0 + Duration::from_secs(30), start.1 + Duration::from_secs(600));
        assert_eq!(idle_for(start, later), Duration::from_secs(600), "time asleep counts");
        let clock_back = (start.0 + Duration::from_secs(30), start.1 - Duration::from_secs(600));
        assert_eq!(idle_for(start, clock_back), Duration::from_secs(30));
        assert!(idle_expired(1, Duration::from_secs(60)));
        assert!(!idle_expired(1, Duration::from_secs(59)));
        assert!(!idle_expired(0, Duration::from_secs(1_000_000)));
    }

    #[test]
    fn the_timer_locks_only_an_unlocked_vault_after_the_delay_and_activity_resets_it() {
        let auto = AutoLock::in_memory(1);
        let start = now();
        let after = |seconds: u64| (start.0 + Duration::from_secs(seconds), start.1 + Duration::from_secs(seconds));
        auto.inner.lock().unwrap().last_activity = start;
        assert!(!auto.step(Some(true), after(59)));
        assert!(auto.step(Some(true), after(60)));
        assert!(!auto.step(None, after(120)), "a busy vault is checked again on the next tick");
        // While locked, the idle time starts over.
        assert!(!auto.step(Some(false), after(200)));
        assert!(!auto.step(Some(true), after(230)));
        assert!(auto.step(Some(true), after(260)));
        auto.touch();
        assert!(!auto.step(Some(true), now()));
    }

    #[test]
    fn a_new_delay_is_saved_and_read_back() {
        let directory = std::env::temp_dir().join(format!("nuvori-auto-lock-{}", uuid::Uuid::new_v4()));
        let auto = AutoLock::new(directory.clone());
        assert_eq!(auto.status(), Status { minutes: DEFAULT_MINUTES, saved: false });
        assert_eq!(auto.set_minutes(5).unwrap(), Status { minutes: 5, saved: true });
        assert!(auto.set_minutes(MAX_MINUTES + 1).is_err());
        assert_eq!(AutoLock::new(directory.clone()).status(), Status { minutes: 5, saved: true });
        auto.set_minutes(0).unwrap();
        assert_eq!(AutoLock::new(directory.clone()).status(), Status { minutes: 0, saved: true });
        let _ = std::fs::remove_dir_all(directory);
    }
}
