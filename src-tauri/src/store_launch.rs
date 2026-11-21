//! Finding and starting the Microsoft Store build of Nuvori. Shared by the app
//! (`store_build.rs`) and the native host, which is a separate program.
//!
//! The Store build records its app ID in `store-build.json` in the vault folder
//! (`store_build.rs`). Anyone who needs the Store build reads that record, checks that the
//! package is still installed for this user, and starts it by its AppUserModelID. A program
//! never starts the package's `nuvori.exe` directly: it would run without package identity.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
        Storage::Packaging::Appx::{GetPackageFamilyName, GetPackagesByPackageFamily},
        System::{
            Com::{CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize},
            Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        },
        UI::Shell::{AO_NONE, ApplicationActivationManager, IApplicationActivationManager},
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

/// The vault folder name under `%APPDATA%` (the Tauri identifier). Both builds use it.
pub const DATA_FOLDER: &str = "com.nuvori.desktop";
pub const MARKER: &str = "store-build.json";
/// `<Application Id>` of the app in the MSIX manifest (`scripts/package-msix.ps1`).
pub const APP_ID: &str = "Nuvori";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreBuild {
    pub family_name: String,
    pub app_id: String,
}

impl StoreBuild {
    /// The AppUserModelID Windows starts the app by: `<family>!<app>`.
    pub fn app_user_model_id(&self) -> String {
        format!("{}!{}", self.family_name, self.app_id)
    }

    /// A package family name is `<name>_<publisher hash>`; an app ID is letters and digits.
    pub fn valid(&self) -> bool {
        let family_ok = (3..=128).contains(&self.family_name.len())
            && self.family_name.contains('_')
            && self.family_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        let app_ok = (1..=64).contains(&self.app_id.len()) && self.app_id.bytes().all(|byte| byte.is_ascii_alphanumeric());
        family_ok && app_ok
    }
}

pub fn marker_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("APPDATA")?).join(DATA_FOLDER).join(MARKER))
}

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

pub fn from_wide(buffer: &[u16]) -> String {
    String::from_utf16_lossy(&buffer[..buffer.iter().position(|unit| *unit == 0).unwrap_or(buffer.len())])
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
pub fn installed(family: &str) -> bool {
    let name = wide(family);
    let (mut count, mut length) = (0u32, 0u32);
    let status = unsafe { GetPackagesByPackageFamily(PCWSTR(name.as_ptr()), &mut count, None, &mut length, None) };
    (status == ERROR_SUCCESS || status == ERROR_INSUFFICIENT_BUFFER) && count > 0
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

/// Starts the Store build by its AppUserModelID. COM runs on its own thread, so the caller's
/// apartment stays free for its window code.
pub fn activate(store: &StoreBuild, arguments: &str) -> std::io::Result<()> {
    let app = HSTRING::from(store.app_user_model_id());
    let arguments = HSTRING::from(arguments);
    let started = std::thread::spawn(move || unsafe {
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
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(std::io::Error::other(error)),
        Err(_) => Err(std::io::Error::other("activation thread panicked")),
    }
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
        assert_eq!(process_family(std::process::id()), None);
    }
}
