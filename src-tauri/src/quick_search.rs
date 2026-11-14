//! The system-wide quick search shortcut. Pressing it shows Nuvori and asks the main window to
//! open its search palette. It never unlocks, reveals, or copies anything: a locked vault only
//! shows the normal unlock screen, and the palette opens after a normal unlock if that happens
//! soon enough. The choice (on or off, and which key) is a device-only preference in
//! `quick-search.json` next to the vault, because the shortcut must work before any window exists.

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

/// How long after the key press an unlock still opens the palette.
pub const REQUEST_WINDOW: Duration = Duration::from_secs(60);
const SETTINGS_FILE: &str = "quick-search.json";
/// Sent to the main window. The payload is `true` when the window already had focus.
const EVENT: &str = "quick-search";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    CtrlShiftSpace,
    CtrlAltN,
    CtrlShiftL,
}

impl Preset {
    pub const ALL: [Preset; 3] = [Preset::CtrlShiftSpace, Preset::CtrlAltN, Preset::CtrlShiftL];

    pub fn id(self) -> &'static str {
        match self {
            Preset::CtrlShiftSpace => "ctrl-shift-space",
            Preset::CtrlAltN => "ctrl-alt-n",
            Preset::CtrlShiftL => "ctrl-shift-l",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Preset::CtrlShiftSpace => "Ctrl+Shift+Space",
            Preset::CtrlAltN => "Ctrl+Alt+N",
            Preset::CtrlShiftL => "Ctrl+Shift+L",
        }
    }

    pub fn parse(id: &str) -> Option<Preset> {
        Preset::ALL.into_iter().find(|preset| preset.id() == id)
    }

    fn shortcut(self) -> Shortcut {
        match self {
            Preset::CtrlShiftSpace => Shortcut::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::Space),
            Preset::CtrlAltN => Shortcut::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyN),
            Preset::CtrlShiftL => Shortcut::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyL),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    pub preset: Preset,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { enabled: true, preset: Preset::CtrlShiftSpace }
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
        }
    }

    pub fn to_json(self) -> String {
        serde_json::json!({ "enabled": self.enabled, "preset": self.preset.id() }).to_string()
    }
}

/// True when a key press this long ago may still open the palette after an unlock.
pub fn request_is_fresh(age: Duration) -> bool {
    age <= REQUEST_WINDOW
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
    state: Registration,
    presets: Vec<PresetInfo>,
}

struct Inner {
    settings: Settings,
    registered: Option<Shortcut>,
    state: Registration,
    requested_at: Option<Instant>,
}

pub struct QuickSearch {
    file: PathBuf,
    inner: Mutex<Inner>,
}

impl QuickSearch {
    pub fn new(directory: PathBuf) -> Self {
        let file = directory.join(SETTINGS_FILE);
        let settings = std::fs::read_to_string(&file).map(|text| Settings::parse(&text)).unwrap_or_default();
        QuickSearch {
            file,
            inner: Mutex::new(Inner { settings, registered: None, state: Registration::Off, requested_at: None }),
        }
    }

    /// Registers or unregisters the shortcut to match the settings. A key that another app owns
    /// is reported in the status, not as a failure.
    pub fn apply(&self, app: &AppHandle) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let manager = app.global_shortcut();
        if let Some(old) = inner.registered.take() {
            let _ = manager.unregister(old);
        }
        inner.state = Registration::Off;
        if !inner.settings.enabled {
            return;
        }
        let shortcut = inner.settings.preset.shortcut();
        let result = manager.on_shortcut(shortcut, |app, _, event| {
            if event.state == ShortcutState::Pressed {
                pressed(app);
            }
        });
        match result {
            Ok(()) => {
                inner.registered = Some(shortcut);
                inner.state = Registration::Active;
            }
            Err(error) => {
                inner.state = Registration::InUse;
                activity::diagnostic(Category::Vault, "Could not register the quick search shortcut", error);
            }
        }
    }

    pub fn status(&self) -> Status {
        let inner = self.inner.lock().expect("quick search state");
        Status {
            enabled: inner.settings.enabled,
            preset: inner.settings.preset.id(),
            shortcut: inner.settings.preset.label(),
            state: inner.state,
            presets: Preset::ALL.into_iter().map(|preset| PresetInfo { id: preset.id(), label: preset.label() }).collect(),
        }
    }

    pub fn change(&self, app: &AppHandle, enabled: bool, preset: Option<&str>) -> Result<Status, String> {
        let preset = match preset {
            Some(id) => Some(Preset::parse(id).ok_or_else(|| "Unknown shortcut".to_owned())?),
            None => None,
        };
        let text = {
            let mut inner = self.inner.lock().map_err(|_| "Quick search is busy".to_owned())?;
            inner.settings.enabled = enabled;
            if let Some(preset) = preset {
                inner.settings.preset = preset;
            }
            inner.settings.to_json()
        };
        let saved = self.file.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(&self.file, text));
        if let Err(error) = saved {
            activity::diagnostic(Category::Vault, "Could not save the quick search setting", error);
        }
        self.apply(app);
        Ok(self.status())
    }

    fn mark_requested(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.requested_at = Some(Instant::now());
        }
    }

    /// True once per key press, and only if the press is recent. The main window calls this when
    /// it is unlocked and ready to show the palette.
    pub fn take_request(&self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        inner.requested_at.take().is_some_and(|at| request_is_fresh(at.elapsed()))
    }
}

/// The key press. Runs off the main thread, so window work goes to the main thread.
fn pressed(app: &AppHandle) {
    app.state::<QuickSearch>().mark_requested();
    let app = app.clone();
    let _ = app.clone().run_on_main_thread(move || {
        let had_focus = app
            .get_webview_window(desktop::MAIN_WINDOW)
            .is_some_and(|window| window.is_visible().unwrap_or(false) && window.is_focused().unwrap_or(false));
        if !had_focus {
            desktop::show_main(&app);
        }
        let _ = app.emit_to(desktop::MAIN_WINDOW, EVENT, had_focus);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_round_trip_and_unknown_ids_are_rejected() {
        for preset in Preset::ALL {
            assert_eq!(Preset::parse(preset.id()), Some(preset));
        }
        assert_eq!(Preset::parse("ctrl-alt-delete"), None);
        assert_eq!(Preset::parse(""), None);
    }

    #[test]
    fn settings_default_to_on_with_the_main_shortcut() {
        let defaults = Settings::default();
        assert!(defaults.enabled);
        assert_eq!(defaults.preset.label(), "Ctrl+Shift+Space");
        assert_eq!(Settings::parse(""), defaults);
        assert_eq!(Settings::parse("not json"), defaults);
        assert_eq!(Settings::parse("{}"), defaults);
    }

    #[test]
    fn settings_survive_a_save_and_bad_fields_fall_back_one_by_one() {
        let saved = Settings { enabled: false, preset: Preset::CtrlAltN };
        assert_eq!(Settings::parse(&saved.to_json()), saved);
        let mixed = Settings::parse(r#"{"enabled":false,"preset":"nope"}"#);
        assert_eq!(mixed, Settings { enabled: false, preset: Preset::CtrlShiftSpace });
    }

    #[test]
    fn a_key_press_opens_the_palette_after_unlock_only_within_sixty_seconds() {
        assert!(request_is_fresh(Duration::from_secs(0)));
        assert!(request_is_fresh(Duration::from_secs(60)));
        assert!(!request_is_fresh(Duration::from_secs(61)));
    }

    #[test]
    fn a_request_is_used_once() {
        let search = QuickSearch::new(std::env::temp_dir().join("nuvori-quick-search-test-none"));
        assert!(!search.take_request());
        search.mark_requested();
        assert!(search.take_request());
        assert!(!search.take_request());
    }
}
