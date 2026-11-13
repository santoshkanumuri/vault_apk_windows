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

use serde::{Deserialize, Serialize};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
        Storage::Packaging::Appx::{GetCurrentPackageFamilyName, GetPackageFamilyName, GetPackagesByPackageFamily},
        System::{
            Com::{CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize},
            Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        },
        UI::{
            Shell::{AO_NONE, ApplicationActivationManager, IApplicationActivationManager},
            WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow},
        },
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

use crate::{
    activity::{self, Category},
    browser::{BROWSER_PROTOCOL_VERSION, BrowserAction, BrowserRequest},
    browser_ipc::{BrowserIpcError, send_to_app},
    passkey_plugin::packaged,
};

/// The vault folder name under `%APPDATA%` (the Tauri identifier). Both builds use it.
const DATA_FOLDER: &str = "com.nuvori.desktop";
const MARKER: &str = "store-build.json";
/// `<Application Id>` of the app in the MSIX manifest (`scripts/package-msix.ps1`).
const APP_ID: &str = "Nuvori";
/// How long a Store build waits for an installer-build copy to close after it agreed.
const HAND_OVER_WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreBuild {
    pub family_name: String,
    pub app_id: String,
}

impl StoreBuild {
    /// The AppUserModelID Windows starts the app by: `<family>!<app>`.
    fn app_user_model_id(&self) -> String {
        format!("{}!{}", self.family_name, self.app_id)
    }

    /// A package family name is `<name>_<publisher hash>`; an app ID is letters and digits.
    fn valid(&self) -> bool {
        let family_ok = (3..=128).contains(&self.family_name.len())
            && self.family_name.contains('_')
            && self.family_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        let app_ok = (1..=64).contains(&self.app_id.len()) && self.app_id.bytes().all(|byte| byte.is_ascii_alphanumeric());
        family_ok && app_ok
    }
}

fn marker_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("APPDATA")?).join(DATA_FOLDER).join(MARKER))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn from_wide(buffer: &[u16]) -> String {
    String::from_utf16_lossy(&buffer[..buffer.iter().position(|unit| *unit == 0).unwrap_or(buffer.len())])
}

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

/// The package family of another process, or `None` when it has no package identity.
pub fn process_family(pid: u32) -> Option<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut length = 0u32;
    let _ = unsafe { GetPackageFamilyName(process, &mut length, None) };
    let mut name = vec![0u16; length.max(1) as usize];
    let found = length > 0 && unsafe { GetPackageFamilyName(process, &mut length, Some(PWSTR(name.as_mut_ptr()))) } == ERROR_SUCCESS;
    unsafe {
        let _ = CloseHandle(process);
    }
    found.then(|| from_wide(&name))
}

/// True while at least one package of `family` is installed for this user.
fn installed(family: &str) -> bool {
    let name = wide(family);
    let (mut count, mut length) = (0u32, 0u32);
    let status = unsafe { GetPackagesByPackageFamily(PCWSTR(name.as_ptr()), &mut count, None, &mut length, None) };
    (status == ERROR_SUCCESS || status == ERROR_INSUFFICIENT_BUFFER) && count > 0
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

/// The Store build recorded in the vault folder, if that package is still installed. A record
/// left by an uninstalled package is deleted.
pub fn installed_store_build() -> Option<StoreBuild> {
    let path = marker_path()?;
    let marker: StoreBuild = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
    if marker.valid() && installed(&marker.family_name) {
        return Some(marker);
    }
    let _ = std::fs::remove_file(&path);
    None
}

/// Installer build: when a Store build is installed, starts it instead and returns true. The
/// caller then exits without opening the vault. A development build always runs itself.
pub fn open_store_build_instead(background: bool) -> bool {
    if packaged() || cfg!(debug_assertions) {
        return false;
    }
    let Some(store) = installed_store_build() else { return false };
    let app = HSTRING::from(store.app_user_model_id());
    let arguments = HSTRING::from(if background { "--background" } else { "" });
    // The user or the browser started this process, so the Store build may take the foreground.
    unsafe {
        let _ = AllowSetForegroundWindow(ASFW_ANY);
    }
    // COM on its own thread, so the main thread's apartment stays free for the window code.
    let started = thread::spawn(move || unsafe {
        if CoInitializeEx(None, COINIT_MULTITHREADED).is_err() {
            return Err(windows::core::Error::from_win32());
        }
        let result = CoCreateInstance::<_, IApplicationActivationManager>(&ApplicationActivationManager, None, CLSCTX_LOCAL_SERVER)
            .and_then(|manager| manager.ActivateApplication(&app, &arguments, AO_NONE));
        CoUninitialize();
        result
    })
    .join();
    match started {
        Ok(Ok(_)) => true,
        Ok(Err(error)) => {
            activity::diagnostic(Category::Vault, "Could not open the Microsoft Store build of Nuvori", error);
            false
        }
        Err(_) => false,
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
    fn only_a_well_formed_record_is_used() {
        let store = StoreBuild { family_name: "Nuvori.Desktop.Test_1a2b3c4d5e6f7".into(), app_id: "Nuvori".into() };
        assert!(store.valid());
        assert_eq!(store.app_user_model_id(), "Nuvori.Desktop.Test_1a2b3c4d5e6f7!Nuvori");
        for family in ["", "NoPublisherHash", "Nuvori_x!Other", "Nuvori_x\\..\\y", "Nuvori_x y"] {
            assert!(!StoreBuild { family_name: family.into(), ..store.clone() }.valid(), "{family}");
        }
        assert!(!StoreBuild { app_id: "Nuvori Desktop".into(), ..store.clone() }.valid());
        let json = serde_json::to_string(&store).unwrap();
        assert_eq!(json, r#"{"familyName":"Nuvori.Desktop.Test_1a2b3c4d5e6f7","appId":"Nuvori"}"#);
    }

    #[test]
    fn a_family_that_is_not_installed_is_not_reported() {
        assert!(!installed("Nuvori.Desktop.NotInstalled_0000000000000"));
    }

    #[test]
    fn a_test_process_has_no_package_identity() {
        assert_eq!(current_family(), None);
        assert_eq!(process_family(std::process::id()), None);
        assert!(!hand_over_allowed(std::process::id()), "only the recorded Store package may take over");
        assert!(!ask_installer_build_to_close(), "the installer build never asks another copy to close");
    }
}
