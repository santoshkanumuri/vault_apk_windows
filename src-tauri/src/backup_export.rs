//! "Create encrypted backup" in Settings: the vault in a `.pvault` file (pvault.rs) that Nuvori for
//! Android restores, encrypted with the master password.
//!
//! The command checks the master password first, then asks where to save the file, and only then
//! reads the vault. Only ciphertext reaches the disk: the archive is built and encrypted in memory,
//! one photo at a time, and written to a temporary file beside the chosen one, which replaces it
//! once complete. A failure removes the temporary file and leaves any earlier file as it was.

use std::{
    fs::{self, OpenOptions},
    io::BufWriter,
    path::{Path, PathBuf},
};

use serde::Serialize;
use windows::{
    Win32::{
        Foundation::{ERROR_CANCELLED, HWND},
        System::Com::{CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize},
        UI::Shell::{
            Common::COMDLG_FILTERSPEC, FOS_FORCEFILESYSTEM, FOS_NOREADONLYRETURN, FOS_OVERWRITEPROMPT, FOS_PATHMUSTEXIST,
            FileSaveDialog, IFileSaveDialog, SIGDN_FILESYSPATH,
        },
    },
    core::{HSTRING, PCWSTR},
};

use crate::{
    pvault::{self, BackupKey},
    vault::{UnlockedVault, VaultError},
};

/// What the toast reports once the file is saved.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Saved {
    pub file_name: String,
    pub items: usize,
    pub photos: usize,
}

/// The suggested name, "Nuvori backup 2026-11-25.pvault".
pub fn default_file_name(today: time::Date) -> String {
    format!(
        "Nuvori backup {:04}-{:02}-{:02}.{}",
        today.year(),
        u8::from(today.month()),
        today.day(),
        pvault::EXTENSION
    )
}

/// The local date the app sends, "2026-11-05". `None` for anything else.
pub fn parse_date(text: &str) -> Option<time::Date> {
    let mut parts = text.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    let digits = |part: &str, length: usize| part.len() == length && part.bytes().all(|byte| byte.is_ascii_digit());
    if parts.next().is_some() || !digits(year, 4) || !digits(month, 2) || !digits(day, 2) {
        return None;
    }
    let month = time::Month::try_from(month.parse::<u8>().ok()?).ok()?;
    time::Date::from_calendar_date(year.parse().ok()?, month, day.parse().ok()?).ok()
}

/// Asks where to save the backup with the Windows Save dialog over `owner`. `None` when the user
/// cancels. The dialog runs on a thread of its own, in the single-threaded COM apartment it needs.
pub fn choose_path(owner: isize, file_name: &str, title: &str) -> Result<Option<PathBuf>, String> {
    let file_name = HSTRING::from(file_name);
    let title = HSTRING::from(title);
    std::thread::spawn(move || {
        // SAFETY: COM is initialized on this thread for the dialog's lifetime and uninitialized
        // after it is released; the filter strings outlive the call that reads them.
        unsafe {
            let initialized = CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).is_ok();
            let chosen = (|| -> windows::core::Result<Option<PathBuf>> {
                let dialog: IFileSaveDialog = CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER)?;
                dialog.SetOptions(dialog.GetOptions()? | FOS_OVERWRITEPROMPT | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOREADONLYRETURN)?;
                let name = HSTRING::from("Nuvori backup (*.pvault)");
                let spec = HSTRING::from("*.pvault");
                dialog.SetFileTypes(&[COMDLG_FILTERSPEC { pszName: PCWSTR(name.as_ptr()), pszSpec: PCWSTR(spec.as_ptr()) }])?;
                dialog.SetDefaultExtension(&HSTRING::from(pvault::EXTENSION))?;
                dialog.SetFileName(&file_name)?;
                dialog.SetTitle(&title)?;
                if let Err(error) = dialog.Show(Some(HWND(owner as *mut _))) {
                    return if error.code() == ERROR_CANCELLED.to_hresult() { Ok(None) } else { Err(error) };
                }
                let path = dialog.GetResult()?.GetDisplayName(SIGDN_FILESYSPATH)?;
                let text = path.to_string();
                CoTaskMemFree(Some(path.0 as *const _));
                Ok(Some(PathBuf::from(text?)))
            })();
            if initialized {
                CoUninitialize();
            }
            chosen.map_err(|error| {
                crate::activity::diagnostic(crate::activity::Category::Vault, "The Save dialog failed", &error);
                "Couldn't open the Save dialog.".to_owned()
            })
        }
    })
    .join()
    .map_err(|_| "Couldn't open the Save dialog.".to_owned())?
}

/// Writes the vault to `path` as an encrypted backup under `key`.
pub fn save(vault: &UnlockedVault, path: &Path, key: &BackupKey, appearance: Option<(String, String)>) -> Result<Saved, VaultError> {
    let contents = vault.backup_contents(appearance)?;
    let items = contents.entries.len();
    let metadata = pvault::metadata(&contents)?;
    drop(contents);
    let file_name = path.file_name().and_then(|name| name.to_str()).ok_or(VaultError::Backup(pvault::BackupError::InvalidItem))?;
    let partial = path.with_file_name(format!("{file_name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let file = OpenOptions::new().write(true).create_new(true).open(&partial)?;
    let written = pvault::write(BufWriter::new(file), key, &metadata, |id| vault.backup_photo(id))
        .and_then(|out| out.into_inner().map_err(|error| VaultError::Io(error.into_error())))
        .and_then(|file| file.sync_all().map_err(VaultError::Io))
        .and_then(|()| fs::rename(&partial, path).map_err(VaultError::Io));
    if let Err(error) = written {
        let _ = fs::remove_file(&partial);
        return Err(error);
    }
    Ok(Saved { file_name: file_name.to_owned(), items, photos: metadata.photo_ids.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_suggested_name_has_the_date_and_extension() {
        let date = time::Date::from_calendar_date(2026, time::Month::November, 5).unwrap();
        assert_eq!(default_file_name(date), "Nuvori backup 2026-11-05.pvault");
    }

    #[test]
    fn only_a_plain_date_is_read() {
        let date = time::Date::from_calendar_date(2026, time::Month::November, 5).unwrap();
        assert_eq!(parse_date("2026-11-05"), Some(date));
        for text in ["", "2026-11-5", "2026-13-01", "2026-02-30", "2026-11-05-01", "+2026-11-05", "2026/11/05", "２０２６-11-05"] {
            assert_eq!(parse_date(text), None, "{text}");
        }
    }
}
