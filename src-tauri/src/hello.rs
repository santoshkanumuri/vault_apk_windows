use windows::{
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Win32::{
        Foundation::HWND,
        System::WinRT::IUserConsentVerifierInterop,
    },
    core::{HSTRING, factory},
};

use crate::dpapi;

pub fn available() -> bool {
    UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|operation| operation.get())
        .is_ok_and(|result| result == UserConsentVerifierAvailability::Available)
}

pub fn verify(hwnd: HWND) -> Result<(), String> {
    verify_for(hwnd, "Unlock Nuvori")
}

/// Windows Hello with `message` shown in the prompt.
pub fn verify_for(hwnd: HWND, message: &str) -> Result<(), String> {
    let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
        .map_err(|_| "Windows Hello is unavailable on this PC".to_owned())?;
    let operation = unsafe {
        interop.RequestVerificationForWindowAsync::<
            windows_future::IAsyncOperation<UserConsentVerificationResult>,
        >(hwnd, &HSTRING::from(message))
    }
    .map_err(|_| "Windows Hello could not open".to_owned())?;
    match operation.get() {
        Ok(result) if result == UserConsentVerificationResult::Verified => Ok(()),
        Ok(result) if result == UserConsentVerificationResult::Canceled => {
            Err("Windows Hello was canceled".to_owned())
        }
        _ => Err("Windows Hello could not verify you. Use your master password.".to_owned()),
    }
}

pub fn protect(key: &[u8; 32]) -> Result<Vec<u8>, String> {
    dpapi::protect(key, "Nuvori Windows Hello unlock")
}

pub fn unprotect(ciphertext: &[u8]) -> Result<[u8; 32], String> {
    let bytes = dpapi::unprotect(ciphertext)?;
    bytes.as_slice().try_into().map_err(|_| {
        "The saved unlock key is invalid. Use your master password.".to_owned()
    })
}
