//! Copying secrets (L-17). A password or code copied from Nuvori goes on the Windows clipboard
//! with the formats that keep it out of clipboard history (Win+V), cloud clipboard sync and
//! clipboard monitors, and the backend clears it after the delay, also with no window open.
//! It clears only while the clipboard still holds that copy (same sequence number), so it never
//! wipes something the user copied since.

use std::{
    sync::Mutex,
    thread,
    time::Duration,
};

use zeroize::Zeroize;

/// The clipboard sequence number right after Nuvori's last secret copy, while it may still be there.
static OURS: Mutex<Option<u32>> = Mutex::new(None);
/// The longest clear delay accepted.
pub const MAX_CLEAR_SECONDS: u32 = 600;

/// Puts `text` on the clipboard as a secret and clears it after `clear_after_seconds` (0: never).
/// `text` is wiped from memory here.
pub fn copy_secret(mut text: String, clear_after_seconds: u32) -> Result<(), String> {
    if clear_after_seconds > MAX_CLEAR_SECONDS {
        text.zeroize();
        return Err("Choose a shorter clipboard delay".to_owned());
    }
    let result = platform::set_secret_text(&text);
    text.zeroize();
    let sequence = result?;
    *OURS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sequence);
    if clear_after_seconds > 0 {
        let _ = thread::Builder::new().name("nuvori-clipboard-clear".to_owned()).spawn(move || {
            thread::sleep(Duration::from_secs(u64::from(clear_after_seconds)));
            clear_if_unchanged(sequence);
        });
    }
    Ok(())
}

/// Clears the clipboard now if it still holds Nuvori's last secret copy (on lock or exit).
pub fn clear_secret_now() {
    let sequence = *OURS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(sequence) = sequence {
        clear_if_unchanged(sequence);
    }
}

/// True when the clipboard still holds the copy that had `ours` as its sequence number.
pub fn still_ours(ours: u32, current: u32) -> bool {
    ours != 0 && ours == current
}

fn clear_if_unchanged(sequence: u32) {
    let mut saved = OURS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if *saved != Some(sequence) {
        // A newer secret copy owns the clipboard now; its own timer clears it.
        return;
    }
    if still_ours(sequence, platform::sequence_number()) {
        platform::empty();
    }
    *saved = None;
}

#[cfg(windows)]
mod platform {
    use std::{thread, time::Duration};

    use windows::{
        Win32::{
            Foundation::{GlobalFree, HANDLE, HGLOBAL},
            System::{
                DataExchange::{CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW, SetClipboardData},
                Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
            },
        },
        core::{PCWSTR, w},
    };
    use zeroize::Zeroize;

    const CF_UNICODETEXT: u32 = 13;

    /// Another program may hold the clipboard for a moment.
    fn open() -> Result<(), String> {
        for _ in 0..20 {
            if unsafe { OpenClipboard(None) }.is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err("The clipboard is busy. Try again.".to_owned())
    }

    /// Moveable global memory holding `bytes`; SetClipboardData takes ownership once it succeeds.
    fn global_with(bytes: &[u8]) -> Result<HGLOBAL, String> {
        let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)) }.map_err(|_| "Out of memory".to_owned())?;
        let target = unsafe { GlobalLock(memory) } as *mut u8;
        if target.is_null() {
            unsafe {
                let _ = GlobalFree(Some(memory));
            }
            return Err("Out of memory".to_owned());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), target, bytes.len());
            let _ = GlobalUnlock(memory);
        }
        Ok(memory)
    }

    fn set(format: u32, bytes: &[u8]) -> Result<(), String> {
        let memory = global_with(bytes)?;
        if unsafe { SetClipboardData(format, Some(HANDLE(memory.0))) }.is_err() {
            unsafe {
                let _ = GlobalFree(Some(memory));
            }
            return Err("The clipboard could not be set".to_owned());
        }
        Ok(())
    }

    fn register(name: PCWSTR) -> u32 {
        unsafe { RegisterClipboardFormatW(name) }
    }

    /// Text plus "don't keep" formats: excluded from monitors, not in clipboard history, not
    /// uploaded to cloud clipboard. Returns the clipboard sequence number after the copy.
    pub fn set_secret_text(text: &str) -> Result<u32, String> {
        let mut wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let mut bytes: Vec<u8> = wide.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        wide.zeroize();
        open().inspect_err(|_| bytes.zeroize())?;
        let result = (|| {
            unsafe { EmptyClipboard() }.map_err(|_| "The clipboard could not be cleared".to_owned())?;
            // These formats must be set together with the text, inside the same open clipboard.
            let zero = 0u32.to_le_bytes();
            for name in [w!("ExcludeClipboardContentFromMonitorProcessing"), w!("CanIncludeInClipboardHistory"), w!("CanUploadToCloudClipboard")] {
                let format = register(name);
                if format == 0 {
                    return Err("The clipboard could not be set".to_owned());
                }
                set(format, &zero)?;
            }
            set(CF_UNICODETEXT, &bytes)
        })();
        bytes.zeroize();
        if result.is_err() {
            let _ = unsafe { EmptyClipboard() };
        }
        unsafe {
            let _ = CloseClipboard();
        }
        result.map(|()| sequence_number())
    }

    pub fn sequence_number() -> u32 {
        unsafe { GetClipboardSequenceNumber() }
    }

    pub fn empty() {
        if open().is_ok() {
            unsafe {
                let _ = EmptyClipboard();
                let _ = CloseClipboard();
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn set_secret_text(_text: &str) -> Result<u32, String> {
        Err("Secret copy needs Windows".to_owned())
    }

    pub fn sequence_number() -> u32 {
        0
    }

    pub fn empty() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_same_clipboard_copy_is_cleared() {
        assert!(still_ours(41, 41));
        assert!(!still_ours(41, 42), "something was copied since");
        assert!(!still_ours(0, 0), "no sequence number: never clear");
    }

    #[test]
    fn a_delay_over_the_limit_is_refused() {
        assert!(copy_secret("synthetic-secret".to_owned(), MAX_CLEAR_SECONDS + 1).is_err());
    }
}
