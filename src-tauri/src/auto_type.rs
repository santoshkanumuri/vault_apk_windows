//! Auto-type: fill a login into any desktop app, not only the browser.
//!
//! 1. In the app's login window, the user presses the auto-type shortcut. Nuvori records that
//!    window (its handle, process and title) and opens a picker in the main window.
//! 2. The user picks a login. Nuvori brings the recorded window to the front and types the
//!    username, Tab, the password and (by default) Enter with `SendInput`.
//!
//! Safety rules:
//! - The shortcut is off until the user turns it on. A locked vault shows the unlock screen first.
//! - Typing happens only into the recorded window, only within [`TARGET_WINDOW`] of the key
//!   press, and only while it still has the same title: a window that closed, navigated or
//!   switched tab is refused, so a password never lands in a window the user did not choose.
//! - Nuvori checks that the window is in front before each field and stops if it is not.
//! - Windows blocks typing into apps that run as administrator; that is reported, not hidden.
//!
//! The choice (on or off, the key, Enter after typing) is a device-only preference in
//! `auto-type.json` next to the vault, like the quick search shortcut (quick_search.rs).

use std::{
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

use crate::{
    activity::{self, Category},
    desktop,
};

/// How long after the key press the picker may still type into the recorded window.
pub const TARGET_WINDOW: Duration = Duration::from_secs(120);
const SETTINGS_FILE: &str = "auto-type.json";
/// Sent to the main window with the recorded window's title and app name.
const EVENT: &str = "auto-type";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    CtrlAltA,
    CtrlAltK,
    CtrlShiftU,
}

impl Preset {
    pub const ALL: [Preset; 3] = [Preset::CtrlAltA, Preset::CtrlAltK, Preset::CtrlShiftU];

    pub fn id(self) -> &'static str {
        match self {
            Preset::CtrlAltA => "ctrl-alt-a",
            Preset::CtrlAltK => "ctrl-alt-k",
            Preset::CtrlShiftU => "ctrl-shift-u",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Preset::CtrlAltA => "Ctrl+Alt+A",
            Preset::CtrlAltK => "Ctrl+Alt+K",
            Preset::CtrlShiftU => "Ctrl+Shift+U",
        }
    }

    pub fn parse(id: &str) -> Option<Preset> {
        Preset::ALL.into_iter().find(|preset| preset.id() == id)
    }

    fn shortcut(self) -> Shortcut {
        match self {
            Preset::CtrlAltA => Shortcut::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyA),
            Preset::CtrlAltK => Shortcut::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyK),
            Preset::CtrlShiftU => Shortcut::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyU),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    pub preset: Preset,
    pub press_enter: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { enabled: false, preset: Preset::CtrlAltA, press_enter: true }
    }
}

impl Settings {
    /// Reads the file text. Anything unreadable or unknown falls back to the default, field by field.
    pub fn parse(text: &str) -> Settings {
        let defaults = Settings::default();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            return defaults;
        };
        Settings {
            enabled: value["enabled"].as_bool().unwrap_or(defaults.enabled),
            preset: value["preset"].as_str().and_then(Preset::parse).unwrap_or(defaults.preset),
            press_enter: value["pressEnter"].as_bool().unwrap_or(defaults.press_enter),
        }
    }

    pub fn to_json(self) -> String {
        serde_json::json!({ "enabled": self.enabled, "preset": self.preset.id(), "pressEnter": self.press_enter }).to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Registration {
    Off,
    Active,
    InUse,
}

#[derive(Serialize)]
pub struct PresetInfo {
    id: &'static str,
    label: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    enabled: bool,
    preset: &'static str,
    shortcut: &'static str,
    press_enter: bool,
    state: Registration,
    presets: Vec<PresetInfo>,
}

/// The window to type into, as shown to the user. No handle leaves Rust.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfo {
    pub title: String,
    /// The program's file name, for example "Teams.exe".
    pub app: String,
}

struct Target {
    window: isize,
    process: u32,
    info: TargetInfo,
    at: Instant,
}

struct Inner {
    settings: Settings,
    registered: Option<Shortcut>,
    state: Registration,
    target: Option<Target>,
}

pub struct AutoType {
    file: PathBuf,
    inner: Mutex<Inner>,
}

impl AutoType {
    pub fn new(directory: PathBuf) -> Self {
        let file = directory.join(SETTINGS_FILE);
        let settings = std::fs::read_to_string(&file).map(|text| Settings::parse(&text)).unwrap_or_default();
        AutoType { file, inner: Mutex::new(Inner { settings, registered: None, state: Registration::Off, target: None }) }
    }

    /// Registers or unregisters the shortcut to match the settings. A key that another app owns
    /// is reported in the status, not as a failure.
    pub fn apply(&self, app: &AppHandle) {
        let Ok(mut inner) = self.inner.lock() else { return };
        let manager = app.global_shortcut();
        if let Some(old) = inner.registered.take() {
            let _ = manager.unregister(old);
        }
        inner.state = Registration::Off;
        if !inner.settings.enabled {
            inner.target = None;
            return;
        }
        let shortcut = inner.settings.preset.shortcut();
        match manager.on_shortcut(shortcut, |app, _, event| {
            if event.state == ShortcutState::Pressed {
                pressed(app);
            }
        }) {
            Ok(()) => {
                inner.registered = Some(shortcut);
                inner.state = Registration::Active;
            }
            Err(error) => {
                inner.state = Registration::InUse;
                activity::diagnostic(Category::Vault, "Could not register the auto-type shortcut", error);
            }
        }
    }

    pub fn status(&self) -> Status {
        let inner = self.inner.lock().expect("auto-type state");
        Status {
            enabled: inner.settings.enabled,
            preset: inner.settings.preset.id(),
            shortcut: inner.settings.preset.label(),
            press_enter: inner.settings.press_enter,
            state: inner.state,
            presets: Preset::ALL.into_iter().map(|preset| PresetInfo { id: preset.id(), label: preset.label() }).collect(),
        }
    }

    pub fn change(&self, app: &AppHandle, enabled: bool, preset: Option<&str>, press_enter: Option<bool>) -> Result<Status, String> {
        let preset = match preset {
            Some(id) => Some(Preset::parse(id).ok_or_else(|| "Unknown shortcut".to_owned())?),
            None => None,
        };
        let text = {
            let mut inner = self.inner.lock().map_err(|_| "Auto-type is busy".to_owned())?;
            inner.settings.enabled = enabled;
            if let Some(preset) = preset {
                inner.settings.preset = preset;
            }
            if let Some(press_enter) = press_enter {
                inner.settings.press_enter = press_enter;
            }
            inner.settings.to_json()
        };
        let saved = self.file.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(&self.file, text));
        if let Err(error) = saved {
            activity::diagnostic(Category::Vault, "Could not save the auto-type setting", error);
        }
        self.apply(app);
        Ok(self.status())
    }

    /// The recorded window, while it may still be typed into.
    pub fn pending(&self) -> Option<TargetInfo> {
        let mut inner = self.inner.lock().ok()?;
        if inner.target.as_ref().is_some_and(|target| target.at.elapsed() > TARGET_WINDOW) {
            inner.target = None;
        }
        inner.target.as_ref().map(|target| target.info.clone())
    }

    pub fn cancel(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.target = None;
        }
    }

    /// Types `username`, Tab, `password` and maybe Enter into the recorded window. Takes the
    /// target, so one key press types at most once. Returns the app name for the activity log.
    pub fn type_login(&self, app: &AppHandle, username: &str, password: &str) -> Result<String, String> {
        let (target, press_enter) = {
            let mut inner = self.inner.lock().map_err(|_| "Auto-type is busy".to_owned())?;
            (inner.target.take(), inner.settings.press_enter)
        };
        let target = target
            .filter(|target| target.at.elapsed() <= TARGET_WINDOW)
            .ok_or_else(|| "Press the auto-type shortcut in the window you want to fill, then pick the login.".to_owned())?;
        if let Some(window) = app.get_webview_window(desktop::MAIN_WINDOW) {
            let _ = window.minimize();
        }
        platform::type_into(&target, username, password, press_enter)?;
        Ok(target.info.app)
    }
}

/// The key press. Records the window in front, then shows Nuvori's picker.
fn pressed(app: &AppHandle) {
    let Some((window, process, info)) = platform::foreground() else { return };
    if process == std::process::id() {
        // The shortcut inside Nuvori itself has nothing to fill.
        return;
    }
    let auto_type = app.state::<AutoType>();
    if let Ok(mut inner) = auto_type.inner.lock() {
        inner.target = Some(Target { window, process, info: info.clone(), at: Instant::now() });
    }
    let app = app.clone();
    let _ = app.clone().run_on_main_thread(move || {
        desktop::show_main(&app);
        let _ = app.emit_to(desktop::MAIN_WINDOW, EVENT, info);
    });
}

/// The keyboard events that type `text`: a key down and up per UTF-16 unit, as Unicode input,
/// so the user's keyboard layout does not change what arrives.
pub fn unicode_events(text: &str) -> Vec<(u16, bool)> {
    text.encode_utf16().flat_map(|unit| [(unit, false), (unit, true)]).collect()
}

mod platform {
    use std::time::{Duration, Instant};

    use windows::{
        Win32::{
            Foundation::{CloseHandle, HWND},
            System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW},
            UI::{
                Input::KeyboardAndMouse::{
                    INPUT, INPUT_0, INPUT_KEYBOARD, KEYBD_EVENT_FLAGS, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, SendInput,
                    VIRTUAL_KEY, VK_RETURN, VK_TAB,
                },
                WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, IsWindow, SetForegroundWindow},
            },
        },
        core::PWSTR,
    };
    use zeroize::Zeroize;

    use super::{Target, TargetInfo, unicode_events};

    fn handle(raw: isize) -> HWND {
        HWND(raw as *mut core::ffi::c_void)
    }

    fn title(window: HWND) -> String {
        let mut buffer = [0u16; 512];
        let length = unsafe { GetWindowTextW(window, &mut buffer) }.max(0) as usize;
        String::from_utf16_lossy(&buffer[..length.min(buffer.len())])
    }

    fn process_of(window: HWND) -> u32 {
        let mut process = 0u32;
        unsafe { GetWindowThreadProcessId(window, Some(&mut process)) };
        process
    }

    fn app_name(process: u32) -> String {
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process) }) else {
            return "an app".to_owned();
        };
        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut length) }.is_ok();
        unsafe {
            let _ = CloseHandle(handle);
        }
        if !ok {
            return "an app".to_owned();
        }
        let path = String::from_utf16_lossy(&buffer[..length as usize]);
        path.rsplit(['\\', '/']).next().unwrap_or("an app").to_owned()
    }

    /// The window in front: (handle, process ID, title and app name).
    pub fn foreground() -> Option<(isize, u32, TargetInfo)> {
        let window = unsafe { GetForegroundWindow() };
        if window.0.is_null() {
            return None;
        }
        let process = process_of(window);
        Some((window.0 as isize, process, TargetInfo { title: title(window), app: app_name(process) }))
    }

    fn in_front(target: &Target) -> bool {
        let window = unsafe { GetForegroundWindow() };
        window.0 as isize == target.window && process_of(window) == target.process
    }

    fn send(events: &[(u16, bool)], virtual_key: bool) -> Result<(), String> {
        let mut inputs: Vec<INPUT> = events
            .iter()
            .map(|&(code, up)| {
                let mut flags = if virtual_key { KEYBD_EVENT_FLAGS(0) } else { KEYEVENTF_UNICODE };
                if up {
                    flags |= KEYEVENTF_KEYUP;
                }
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: if virtual_key { VIRTUAL_KEY(code) } else { VIRTUAL_KEY(0) },
                            wScan: if virtual_key { 0 } else { code },
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            })
            .collect();
        let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) } as usize;
        // The typed characters were in these structures: wipe them.
        for input in &mut inputs {
            unsafe { input.Anonymous.ki.wScan.zeroize() };
        }
        if sent != inputs.len() {
            return Err("Windows blocked the typing. Apps that run as administrator can't receive it from Nuvori.".to_owned());
        }
        Ok(())
    }

    fn key(virtual_key: VIRTUAL_KEY) -> Result<(), String> {
        send(&[(virtual_key.0, false), (virtual_key.0, true)], true)
    }

    fn text(value: &str) -> Result<(), String> {
        let mut events = unicode_events(value);
        let result = send(&events, false);
        events.zeroize();
        result
    }

    pub fn type_into(target: &Target, username: &str, password: &str, press_enter: bool) -> Result<(), String> {
        let window = handle(target.window);
        if !unsafe { IsWindow(Some(window)) }.as_bool() || process_of(window) != target.process {
            return Err("That window is closed. Press the auto-type shortcut again.".to_owned());
        }
        if title(window) != target.info.title {
            return Err("That window changed since the shortcut. Press the auto-type shortcut again.".to_owned());
        }
        let _ = unsafe { SetForegroundWindow(window) };
        let deadline = Instant::now() + Duration::from_millis(1500);
        while !in_front(target) {
            if Instant::now() > deadline {
                return Err("Windows didn't bring that window to the front. Click it, then press the shortcut again.".to_owned());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Let the window settle its focus before the first key.
        std::thread::sleep(Duration::from_millis(150));
        let stop = || Err::<(), String>("Another window came to the front, so Nuvori stopped typing.".to_owned());
        if !username.is_empty() {
            text(username)?;
            key(VK_TAB)?;
        }
        if !in_front(target) {
            return stop();
        }
        text(password)?;
        if press_enter {
            if !in_front(target) {
                return stop();
            }
            key(VK_RETURN)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_to_off_and_parse_field_by_field() {
        let defaults = Settings::default();
        assert!(!defaults.enabled, "auto-type is opt-in");
        assert_eq!(Settings::parse("not json"), defaults);
        let parsed = Settings::parse(r#"{"enabled":true,"preset":"ctrl-alt-k","pressEnter":false}"#);
        assert_eq!(parsed, Settings { enabled: true, preset: Preset::CtrlAltK, press_enter: false });
        assert_eq!(Settings::parse(&parsed.to_json()), parsed);
        assert_eq!(Settings::parse(r#"{"enabled":true,"preset":"ctrl-alt-del"}"#).preset, Preset::CtrlAltA);
    }

    #[test]
    fn presets_do_not_collide_with_quick_search() {
        for preset in Preset::ALL {
            assert!(crate::quick_search::Preset::ALL.iter().all(|quick| quick.label() != preset.label()), "{}", preset.label());
        }
    }

    #[test]
    fn text_becomes_unicode_key_down_and_up_pairs() {
        assert_eq!(unicode_events("aé"), [(0x61, false), (0x61, true), (0xE9, false), (0xE9, true)]);
        // A character outside the basic plane is two UTF-16 units, each pressed and released.
        let emoji = unicode_events("🔑");
        assert_eq!(emoji.len(), 4);
        assert_eq!((emoji[0].0, emoji[2].0), (0xD83D, 0xDD11));
        assert!(unicode_events("").is_empty());
    }
}
