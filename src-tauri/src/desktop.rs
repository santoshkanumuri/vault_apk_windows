//! Background running: one app instance, a tray icon, the main window on demand, and the small
//! unlock window the browser extension asks for ("unlock_prompt").

use std::{thread, time::Duration};

use tauri::{
    AppHandle, Manager, WebviewUrl, WebviewWindowBuilder,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE},
        System::Threading::CreateMutexW,
        UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow},
    },
    core::w,
};

use crate::{
    activity::{self, Category},
    browser::{BROWSER_PROTOCOL_VERSION, BrowserAction, BrowserRequest},
    browser_ipc::send_to_app,
};

pub const MAIN_WINDOW: &str = "main";
pub const UNLOCK_WINDOW: &str = "unlock";
pub const CARD_CODE_WINDOW: &str = "card-code";
pub const TRAY_ID: &str = "nuvori";
/// Started by the native host: show only the unlock window, then keep running in the tray.
const BACKGROUND_ARG: &str = "--background";

/// Started by Windows to answer a passkey request (the MSIX `windows.comServer` entry): no
/// window opens until a sign-in needs the vault unlocked.
const PLUGIN_ARG: &str = "-PluginActivated";

pub fn background_launch() -> bool {
    std::env::args().skip(1).any(|arg| arg == BACKGROUND_ARG) || plugin_launch()
}

pub fn plugin_launch() -> bool {
    std::env::args().skip(1).any(|arg| arg.eq_ignore_ascii_case(PLUGIN_ARG))
}

/// Owns the per-session instance mutex until the process exits.
pub struct InstanceGuard(#[allow(dead_code)] HANDLE);

/// `None` when Nuvori is already running for this Windows session.
pub fn claim_instance() -> Option<InstanceGuard> {
    match unsafe { CreateMutexW(None, false, w!(r"Local\com.nuvori.desktop.instance")) } {
        Ok(handle) if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS => {
            // Close this handle: the mutex must vanish when the running copy exits, so a later
            // claim (after a hand-over) can succeed.
            unsafe {
                let _ = CloseHandle(handle);
            }
            None
        }
        Ok(handle) => Some(InstanceGuard(handle)),
        // Without the mutex, run anyway; the browser pipe still allows only one server.
        Err(_) => Some(InstanceGuard(HANDLE::default())),
    }
}

/// Waits up to `limit` for a running copy that agreed to close, then claims the instance.
pub fn claim_instance_within(limit: Duration) -> Option<InstanceGuard> {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if let Some(instance) = claim_instance() {
            return Some(instance);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// A second launch asks the running app to show itself, then exits. The first instance may
/// still be starting, so keep trying for a few seconds.
pub fn hand_over_to_running_app(background: bool) {
    // The user (or the browser) just started this process, so let the running app take focus.
    unsafe {
        let _ = AllowSetForegroundWindow(ASFW_ANY);
    }
    let request = BrowserRequest {
        version: BROWSER_PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        action: if background { BrowserAction::UnlockPrompt } else { BrowserAction::ShowApp },
        ..Default::default()
    };
    for _ in 0..50 {
        if send_to_app(&request).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Shows the main window, creating it from `tauri.conf.json` the first time. It has its own
/// unlock screen, so the small unlock window closes.
pub fn show_main(app: &AppHandle) {
    close_unlock_prompt(app);
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    let Some(config) = app.config().app.windows.iter().find(|window| window.label == MAIN_WINDOW).cloned() else {
        return;
    };
    match WebviewWindowBuilder::from_config(app, &config).and_then(|builder| builder.build()) {
        Ok(window) => {
            let _ = window.set_focus();
        }
        Err(error) => activity::diagnostic(Category::Vault, "Could not open the main window", error),
    }
}

/// The small unlock window. A visible main window already shows the unlock screen, so it is
/// brought forward instead.
pub fn show_unlock_prompt(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(UNLOCK_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    if app
        .get_webview_window(MAIN_WINDOW)
        .is_some_and(|window| window.is_visible().unwrap_or(false))
    {
        show_main(app);
        return;
    }
    let built = WebviewWindowBuilder::new(app, UNLOCK_WINDOW, WebviewUrl::App("index.html".into()))
        .title("Unlock Nuvori")
        .inner_size(400.0, 500.0)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .always_on_top(true)
        .center()
        .focused(true)
        .build();
    match built {
        Ok(window) => {
            let _ = window.set_focus();
        }
        Err(error) => activity::diagnostic(Category::Vault, "Could not open the unlock window", error),
    }
}

/// The small window that approves releasing a card's security code to the browser.
pub fn show_card_code_prompt(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(CARD_CODE_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    let built = WebviewWindowBuilder::new(app, CARD_CODE_WINDOW, WebviewUrl::App("index.html".into()))
        .title("Approve card security code")
        .inner_size(400.0, 460.0)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .always_on_top(true)
        .center()
        .focused(true)
        .build();
    match built {
        Ok(window) => {
            let _ = window.set_focus();
        }
        Err(error) => activity::diagnostic(Category::Vault, "Could not open the approval window", error),
    }
}

pub fn close_card_code_prompt(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(CARD_CODE_WINDOW) {
        let _ = window.destroy();
    }
}

pub fn close_unlock_prompt(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(UNLOCK_WINDOW) {
        let _ = window.destroy();
    }
}

/// Tray icon: left click opens Nuvori; the menu opens, locks, or quits.
pub fn create_tray(app: &AppHandle, lock: fn(&AppHandle)) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Nuvori", true, None::<&str>)?;
    let lock_item = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Nuvori", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &lock_item, &separator, &quit])?;
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Nuvori")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "lock" => lock(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}
