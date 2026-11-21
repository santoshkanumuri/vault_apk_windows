//! The Microsoft Store build (MSIX) and the installer build (MSI or setup EXE) on one PC.
//!
//! Both builds open the same vault folder, and only one Nuvori runs per Windows session. When
//! both are installed, the Store build runs, because only it can answer passkey requests:
//!
//! - At each start, the Store build writes its app ID to `store-build.json` in the vault folder.
//! - At start, the installer build reads that file. If that package is still installed for this
//!   user, the installer build starts the Store build with the same arguments and exits.
//! - When the Store build finds an installer-build copy running, it asks that copy to close
//!   (`hand_over` on the browser pipe) and then starts in its place. Installer builds 2.1.8 and
//!   earlier do not know the request; the Store build then brings the running copy forward.
//!
//! The running copy accepts `hand_over` only from a process of the recorded Store package, so
//! another program cannot use it to close Nuvori.

use std::{path::PathBuf, thread, time::Duration};

use windows::{
    Win32::{
        Foundation::ERROR_SUCCESS,
        Storage::Packaging::Appx::GetCurrentPackageFamilyName,
        UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow},
    },
    core::PWSTR,
};

pub use crate::store_launch::{installed_store_build, process_family};
use crate::{
    activity::{self, Category},
    browser::{BROWSER_PROTOCOL_VERSION, BrowserAction, BrowserRequest},
    browser_ipc::{BrowserIpcError, send_to_app},
    passkey_plugin::packaged,
    store_launch::{APP_ID, StoreBuild, from_wide, marker_path},
};

/// How long a Store build waits for an installer-build copy to close after it agreed.
const HAND_OVER_WAIT: Duration = Duration::from_secs(10);

/// This process's package family name, or `None` for the installer build.
fn current_family() -> Option<String> {
    let mut length = 0u32;
    let _ = unsafe { GetCurrentPackageFamilyName(&mut length, None) };
    if length == 0 {
        return None;
    }
    let mut name = vec![0u16; length as usize];
    (unsafe { GetCurrentPackageFamilyName(&mut length, Some(PWSTR(name.as_mut_ptr()))) } == ERROR_SUCCESS)
        .then(|| from_wide(&name))
}

/// Store build: records its app ID for the installer build. Called before anything else, so it
/// is in place even when this start hands over to a running copy.
pub fn record() {
    let (Some(family), Some(path)) = (current_family(), marker_path()) else { return };
    let marker = StoreBuild { family_name: family, app_id: APP_ID.to_owned() };
    let Ok(body) = serde_json::to_vec_pretty(&marker) else { return };
    if std::fs::read(&path).ok().as_deref() == Some(body.as_slice()) {
        return;
    }
    let written = path.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(&path, body));
    if let Err(error) = written {
        activity::diagnostic(Category::Vault, "Could not record the Store build", error);
    }
}

/// Installer build: when a Store build is installed, starts it instead and returns true. The
/// caller then exits without opening the vault. A development build always runs itself.
pub fn open_store_build_instead(background: bool) -> bool {
    if packaged() || cfg!(debug_assertions) {
        return false;
    }
    let Some(store) = installed_store_build() else { return false };
    // The user or the browser started this process, so the Store build may take the foreground.
    unsafe {
        let _ = AllowSetForegroundWindow(ASFW_ANY);
    }
    match crate::store_launch::activate(&store, if background { "--background" } else { "" }) {
        Ok(()) => true,
        Err(error) => {
            activity::diagnostic(Category::Vault, "Could not open the Microsoft Store build of Nuvori", error);
            false
        }
    }
}

/// Store build: asks a running installer-build copy to close. True when it agreed; the caller
/// then waits for the instance to come free. The running copy may still be starting, so the
/// request is retried for a few seconds while the pipe is missing.
pub fn ask_installer_build_to_close() -> bool {
    if !packaged() {
        return false;
    }
    let request = BrowserRequest {
        version: BROWSER_PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        action: BrowserAction::HandOver,
        ..Default::default()
    };
    for _ in 0..30 {
        match send_to_app(&request) {
            Ok(response) => return response.status == "ok",
            Err(BrowserIpcError::Io(_)) => thread::sleep(Duration::from_millis(100)),
            Err(_) => return false,
        }
    }
    false
}

/// Installer build, on the browser pipe: the Store build of this PC may take over. `client` is
/// the process ID of the program that sent `hand_over`.
pub fn hand_over_allowed(client: u32) -> bool {
    !packaged()
        && installed_store_build()
            .zip(process_family(client))
            .is_some_and(|(store, family)| store.family_name.eq_ignore_ascii_case(&family))
}

/// How long a Store build waits for the copy that agreed to close.
pub fn hand_over_wait() -> Duration {
    HAND_OVER_WAIT
}

/// Store build: true when an installer build is also installed in one of its standard folders
/// (MSI per machine, setup EXE per user).
pub fn installer_build_installed() -> bool {
    if !packaged() {
        return false;
    }
    [("ProgramW6432", r"Nuvori"), ("ProgramFiles", r"Nuvori"), ("LOCALAPPDATA", r"Nuvori"), ("LOCALAPPDATA", r"Programs\Nuvori")]
        .iter()
        .filter_map(|(variable, folder)| std::env::var_os(variable).map(|base| PathBuf::from(base).join(folder).join("nuvori.exe")))
        .any(|path| path.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_process_has_no_package_identity() {
        assert_eq!(current_family(), None);
        assert_eq!(process_family(std::process::id()), None);
        assert!(!hand_over_allowed(std::process::id()), "only the recorded Store package may take over");
        assert!(!ask_installer_build_to_close(), "the installer build never asks another copy to close");
    }
}
