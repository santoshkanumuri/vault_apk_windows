//! Tells a reinstall from an update, so a vault left by an earlier install gets the "Welcome
//! back" screen instead of the plain unlock screen.
//!
//! The vault folder (`%APPDATA%\com.nuvori.desktop`) and the device identity in it survive an
//! uninstall on purpose (`unvirtualizedResources` in `scripts/package-msix.ps1`). So after a
//! reinstall Nuvori finds a vault that this install never opened. Each install has an ID:
//!
//! - Store build (MSIX): the package family and the creation time of its data folder
//!   `%LOCALAPPDATA%\Packages\<family>`. Windows makes that folder when the package is installed
//!   for the user, keeps it through updates, and deletes it on uninstall.
//! - Installer build: the path and creation time of `nuvori.exe`. An update writes over the
//!   file and keeps its creation time; an uninstall deletes it.
//! - Development build: the path of the executable only, so a rebuild is not a reinstall.
//!
//! `install-marker-v1.json` in the vault folder keeps the ID of the install that last opened the
//! vault. It is written when the vault is unlocked or created, and at start when there is no
//! vault, so the "Welcome back" screen stays until the person unlocks or starts fresh. Builds
//! before this one wrote no marker. Then a vault last used before this install began came from an
//! earlier install. The marker and the checks read only file names and file times, never the
//! vault's contents.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

pub const MARKER_FILE: &str = "install-marker-v1.json";

/// The install that is running now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Install {
    /// The same on every start of one install, different after a reinstall.
    pub id: String,
    /// When this install began, in Unix milliseconds; 0 when Windows did not say.
    pub installed_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Marker {
    install: String,
    recorded_at: i64,
}

pub struct InstallMarker {
    path: PathBuf,
    current: Install,
}

impl InstallMarker {
    pub fn new(directory: &Path, current: Install) -> Self {
        Self { path: directory.join(MARKER_FILE), current }
    }

    /// The install ID saved by the install that last opened the vault.
    fn recorded(&self) -> Option<String> {
        let marker: Marker = serde_json::from_slice(&fs::read(&self.path).ok()?).ok()?;
        Some(marker.install)
    }

    /// True when the vault in this folder was last opened by another install. `vault_last_used`
    /// is the vault's newest file time (`VaultStore::last_used_millis`); call this only when a
    /// vault exists.
    pub fn is_new_install(&self, vault_last_used: Option<i64>) -> bool {
        match self.recorded() {
            Some(install) => install != self.current.id,
            // No marker: an older build used this vault. It belongs to an earlier install when it
            // was last used before this install began.
            None => self.current.installed_at > 0 && vault_last_used.is_some_and(|used| used < self.current.installed_at),
        }
    }

    /// Saves this install as the one that opened the vault. Does nothing when it is saved already.
    pub fn record(&self) -> std::io::Result<()> {
        if self.recorded().as_deref() == Some(self.current.id.as_str()) {
            return Ok(());
        }
        let body = serde_json::to_vec_pretty(&Marker { install: self.current.id.clone(), recorded_at: millis(SystemTime::now()) })
            .map_err(std::io::Error::other)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = self.path.with_extension("json.tmp");
        fs::write(&temporary, body)?;
        fs::rename(&temporary, &self.path)
    }
}

pub(crate) fn millis(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

fn created_millis(path: &Path) -> i64 {
    fs::metadata(path).and_then(|metadata| metadata.created()).map_or(0, millis)
}

/// The install that is running now (see the module comment).
pub fn detect() -> Install {
    if let Some(family) = crate::store_build::current_family() {
        let folder = std::env::var_os("LOCALAPPDATA").map(|local| PathBuf::from(local).join("Packages").join(&family));
        let installed_at = folder.as_deref().map_or(0, created_millis);
        return Install { id: format!("package:{family}:{installed_at}"), installed_at };
    }
    let exe = std::env::current_exe().unwrap_or_default();
    let path = exe.to_string_lossy().to_lowercase();
    let installed_at = created_millis(&exe);
    if cfg!(debug_assertions) {
        return Install { id: format!("dev:{path}"), installed_at };
    }
    Install { id: format!("exe:{path}:{installed_at}"), installed_at }
}

static INSTALLED: OnceLock<InstallMarker> = OnceLock::new();

/// Called once at start with the vault folder.
pub fn install(directory: &Path) {
    let _ = INSTALLED.set(InstallMarker::new(directory, detect()));
}

pub fn installed() -> Option<&'static InstallMarker> {
    INSTALLED.get()
}

/// The vault was unlocked or created by this install, or there is none: remember this install.
pub fn record_current() {
    if let Some(marker) = installed()
        && let Err(error) = marker.record()
    {
        crate::activity::diagnostic(crate::activity::Category::Vault, "Could not record this install", error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder() -> PathBuf {
        std::env::temp_dir().join(format!("nuvori-install-marker-{}", uuid::Uuid::new_v4()))
    }

    fn install(id: &str, installed_at: i64) -> Install {
        Install { id: id.to_owned(), installed_at }
    }

    #[test]
    fn a_vault_opened_by_another_install_is_new_until_this_install_records_itself() {
        let directory = folder();
        let earlier = InstallMarker::new(&directory, install("exe:c:\\nuvori\\nuvori.exe:100", 100));
        earlier.record().unwrap();
        assert!(!earlier.is_new_install(Some(5_000)), "the same install");

        let reinstalled = InstallMarker::new(&directory, install("exe:c:\\nuvori\\nuvori.exe:9000", 9_000));
        assert!(reinstalled.is_new_install(Some(5_000)));
        assert!(reinstalled.is_new_install(Some(5_000)), "checking does not record");
        reinstalled.record().unwrap();
        assert!(!reinstalled.is_new_install(Some(5_000)));
        // The marker holds only the install ID and a time.
        let saved = fs::read_to_string(directory.join(MARKER_FILE)).unwrap();
        assert!(saved.contains("nuvori.exe:9000") && saved.contains("recordedAt"));
        assert!(!directory.join("install-marker-v1.json.tmp").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn without_a_marker_only_a_vault_last_used_before_this_install_is_from_an_earlier_install() {
        let directory = folder();
        let marker = InstallMarker::new(&directory, install("package:Nuvori_abc:9000", 9_000));
        // An update from a build without markers: the vault was used after this install began.
        assert!(!marker.is_new_install(Some(12_000)));
        // A reinstall: the vault was last used before this install began.
        assert!(marker.is_new_install(Some(5_000)));
        // Unknown times never show the screen.
        assert!(!marker.is_new_install(None));
        assert!(!InstallMarker::new(&directory, install("exe:x", 0)).is_new_install(Some(5_000)));
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_damaged_marker_counts_as_missing() {
        let directory = folder();
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(MARKER_FILE), b"{not json").unwrap();
        let marker = InstallMarker::new(&directory, install("exe:x:9000", 9_000));
        assert!(marker.is_new_install(Some(5_000)));
        assert!(!marker.is_new_install(Some(10_000)));
        marker.record().unwrap();
        assert!(!marker.is_new_install(Some(5_000)));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn this_test_process_has_a_stable_install_id() {
        let first = detect();
        assert_eq!(first, detect());
        assert!(first.id.starts_with("dev:") || first.id.starts_with("exe:"), "{}", first.id);
        assert!(first.installed_at > 0, "the test executable has a creation time");
    }
}
