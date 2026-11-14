//! Windows Hello unlock.
//!
//! The saved unlock file (format 2) needs a Windows Hello gesture to open:
//!
//! ```text
//! file  = "NVHK" | 0x02 | DPAPI( inner )
//! inner = challenge (32) | nonce (12) | AES-256-GCM(KEK, vault key) (32 + 16 tag)
//! KEK   = HKDF-SHA256(salt = challenge, ikm = Hello signature of challenge, info = KEK_INFO)
//! AAD   = "NVHK" | 0x02 | challenge
//! ```
//!
//! The Hello signature comes from a `KeyCredentialManager` key (RSA, PKCS#1 v1.5, so the same
//! challenge always gives the same signature). The private key never leaves Windows Hello, and
//! Windows signs only after the PIN, face or fingerprint. DPAPI stays as an outer layer that ties
//! the file to this Windows account.
//!
//! Format 1 (2.2.x and earlier) is a bare DPAPI blob of the vault key. Nuvori still opens it once
//! after a consent prompt and then saves the file again in format 2.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use windows::{
    Security::{
        Credentials::{
            KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
            UI::{UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability},
        },
        Cryptography::CryptographicBuffer,
    },
    Storage::Streams::IBuffer,
    Win32::{
        Foundation::HWND,
        System::WinRT::{IBufferByteAccess, IUserConsentVerifierInterop},
        UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow},
    },
    core::{HSTRING, Interface, PCWSTR, factory, w},
};
use zeroize::{Zeroize, Zeroizing};

use crate::dpapi;

const MAGIC: &[u8; 4] = b"NVHK";
const FORMAT_VERSION: u8 = 2;
const HEADER_LEN: usize = MAGIC.len() + 1;
const CHALLENGE_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SEALED_KEY_LEN: usize = 32 + 16;
const INNER_LEN: usize = CHALLENGE_LEN + NONCE_LEN + SEALED_KEY_LEN;
const KEK_INFO: &[u8] = b"nuvori-windows-hello-kek-v2";
/// An RSA-2048 signature is 256 bytes. A short or empty result would give a guessable KEK.
const MIN_SIGNATURE_LEN: usize = 128;
const CREDENTIAL_NAME: &str = "Nuvori vault unlock";
const DPAPI_DESCRIPTION: &str = "Nuvori Windows Hello unlock";
/// Window class of the Windows Security (Hello) prompt.
const PROMPT_WINDOW_CLASS: PCWSTR = w!("Credential Dialog Xaml Host");

const CANCELED: &str = "Windows Hello was canceled";
const NOT_VERIFIED: &str = "Windows Hello could not verify you. Use your master password.";
const NOT_SUPPORTED: &str =
    "Windows Hello can't protect the vault key on this PC. Set up a PIN, face, or fingerprint in Windows Settings, or use your master password.";
const ENABLE_AGAIN: &str =
    "Windows Hello can't open the saved unlock on this PC. Unlock with your master password, then turn Windows Hello off and on again in More.";
const INVALID_FILE: &str = "The saved unlock key is invalid. Use your master password.";

// ---------------------------------------------------------------------------------------------
// Platform: availability and consent prompt
// ---------------------------------------------------------------------------------------------

/// Hello unlock works only when Windows can both prompt and sign with a Hello key.
pub fn available() -> bool {
    let consent = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|operation| operation.get())
        .is_ok_and(|result| result == UserConsentVerifierAvailability::Available);
    consent && key_credentials_supported()
}

fn key_credentials_supported() -> bool {
    KeyCredentialManager::IsSupportedAsync()
        .and_then(|operation| operation.get())
        .unwrap_or(false)
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
            Err(CANCELED.to_owned())
        }
        _ => Err(NOT_VERIFIED.to_owned()),
    }
}

// ---------------------------------------------------------------------------------------------
// Platform: Hello key credential (thin boundary around KeyCredentialManager)
// ---------------------------------------------------------------------------------------------

/// Creates a new Hello key (replacing an older one) and saves `key` under it.
/// Shows the Hello prompt to create the key and again to sign, unless Windows reuses the gesture.
pub fn enroll(key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if !key_credentials_supported() {
        return Err(NOT_SUPPORTED.to_owned());
    }
    let credential = create_credential()?;
    seal(key, |challenge| sign(&credential, challenge))
}

/// Opens a format 2 file. Shows the Hello prompt.
pub fn unseal(file: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    if !matches!(saved_format(file)?, SavedFormat::Current(_)) {
        return Err(INVALID_FILE.to_owned());
    }
    let credential = open_credential()?;
    open(file, |challenge| sign(&credential, challenge))
}

/// Removes the Hello key. A missing key is fine.
pub fn delete_credential() -> Result<(), String> {
    match KeyCredentialManager::DeleteAsync(&HSTRING::from(CREDENTIAL_NAME))
        .and_then(|action| action.get())
    {
        Ok(()) => Ok(()),
        Err(error) if is_not_found(error.code().0) => Ok(()),
        Err(error) => Err(format!("Windows Hello key was not removed: {}", error.message())),
    }
}

fn is_not_found(code: i32) -> bool {
    // NTE_NOT_FOUND, NTE_BAD_KEYSET, HRESULT_FROM_WIN32(ERROR_NOT_FOUND),
    // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
    matches!(code as u32, 0x8009_0011 | 0x8009_0016 | 0x8007_0490 | 0x8007_0002)
}

fn create_credential() -> Result<KeyCredential, String> {
    let _focus = PromptFocus::start();
    let result = KeyCredentialManager::RequestCreateAsync(
        &HSTRING::from(CREDENTIAL_NAME),
        KeyCredentialCreationOption::ReplaceExisting,
    )
    .and_then(|operation| operation.get())
    .map_err(|_| "Windows Hello could not open".to_owned())?;
    status_result(result.Status())?;
    result.Credential().map_err(|_| NOT_VERIFIED.to_owned())
}

fn open_credential() -> Result<KeyCredential, String> {
    let result = KeyCredentialManager::OpenAsync(&HSTRING::from(CREDENTIAL_NAME))
        .and_then(|operation| operation.get())
        .map_err(|_| "Windows Hello could not open".to_owned())?;
    status_result(result.Status())?;
    result.Credential().map_err(|_| NOT_VERIFIED.to_owned())
}

/// Signs `challenge` with the Hello key. This is where Windows asks for the gesture.
fn sign(credential: &KeyCredential, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let data = CryptographicBuffer::CreateFromByteArray(challenge)
        .map_err(|_| "Windows Hello could not open".to_owned())?;
    let result = {
        let _focus = PromptFocus::start();
        credential
            .RequestSignAsync(&data)
            .and_then(|operation| operation.get())
            .map_err(|_| NOT_VERIFIED.to_owned())?
    };
    status_result(result.Status())?;
    let buffer = result.Result().map_err(|_| NOT_VERIFIED.to_owned())?;
    take_bytes(&buffer)
}

fn status_result(status: windows::core::Result<KeyCredentialStatus>) -> Result<(), String> {
    match status {
        Ok(KeyCredentialStatus::Success) => Ok(()),
        Ok(KeyCredentialStatus::UserCanceled) => Err(CANCELED.to_owned()),
        Ok(KeyCredentialStatus::NotFound) => Err(ENABLE_AGAIN.to_owned()),
        Ok(KeyCredentialStatus::SecurityDeviceLocked) => Err(
            "Windows Hello is locked after too many tries. Use your master password.".to_owned(),
        ),
        _ => Err(NOT_VERIFIED.to_owned()),
    }
}

/// Copies the bytes out of a WinRT buffer and wipes the buffer.
fn take_bytes(buffer: &IBuffer) -> Result<Zeroizing<Vec<u8>>, String> {
    let length = buffer.Length().map_err(|_| NOT_VERIFIED.to_owned())? as usize;
    let access = buffer
        .cast::<IBufferByteAccess>()
        .map_err(|_| NOT_VERIFIED.to_owned())?;
    unsafe {
        let pointer = access.Buffer().map_err(|_| NOT_VERIFIED.to_owned())?;
        if pointer.is_null() {
            return Err(NOT_VERIFIED.to_owned());
        }
        let bytes = Zeroizing::new(std::slice::from_raw_parts(pointer, length).to_vec());
        std::ptr::write_bytes(pointer, 0, length);
        Ok(bytes)
    }
}

/// The Hello prompt of a key credential cannot take an owner window like the consent prompt.
/// While it is open, this watcher brings it to the front once, the same way other desktop
/// password managers do. Nuvori is the foreground app here, so Windows allows the switch.
struct PromptFocus {
    stop: Arc<AtomicBool>,
}

impl PromptFocus {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let watcher = Arc::clone(&stop);
        let _ = thread::Builder::new()
            .name("hello-prompt-focus".into())
            .spawn(move || {
                for _ in 0..50 {
                    if watcher.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Ok(prompt) = unsafe { FindWindowW(PROMPT_WINDOW_CLASS, PCWSTR::null()) } {
                        if !prompt.is_invalid() {
                            let _ = unsafe { SetForegroundWindow(prompt) };
                            return;
                        }
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            });
        Self { stop }
    }
}

impl Drop for PromptFocus {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------------------------
// Pure part: file format, KEK, key wrap (tested without Windows Hello)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum SavedFormat<'a> {
    /// Format 1: DPAPI only. Opens after a consent prompt; saved again in format 2.
    Legacy,
    /// Format 2: the DPAPI blob after the header.
    Current(&'a [u8]),
}

pub fn saved_format(file: &[u8]) -> Result<SavedFormat<'_>, String> {
    match file.strip_prefix(MAGIC.as_slice()) {
        None => Ok(SavedFormat::Legacy),
        Some([FORMAT_VERSION, blob @ ..]) if !blob.is_empty() => Ok(SavedFormat::Current(blob)),
        Some([version, ..]) if *version > FORMAT_VERSION => Err(
            "This Windows Hello unlock was saved by a newer version of Nuvori. Use your master password."
                .to_owned(),
        ),
        Some(_) => Err(INVALID_FILE.to_owned()),
    }
}

pub fn is_legacy(file: &[u8]) -> bool {
    matches!(saved_format(file), Ok(SavedFormat::Legacy))
}

fn header() -> [u8; HEADER_LEN] {
    let mut header = [0; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()] = FORMAT_VERSION;
    header
}

fn aad(challenge: &[u8; CHALLENGE_LEN]) -> [u8; HEADER_LEN + CHALLENGE_LEN] {
    let mut aad = [0; HEADER_LEN + CHALLENGE_LEN];
    aad[..HEADER_LEN].copy_from_slice(&header());
    aad[HEADER_LEN..].copy_from_slice(challenge);
    aad
}

struct Inner {
    challenge: [u8; CHALLENGE_LEN],
    nonce: [u8; NONCE_LEN],
    sealed: [u8; SEALED_KEY_LEN],
}

impl Inner {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(INNER_LEN));
        bytes.extend_from_slice(&self.challenge);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.sealed);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != INNER_LEN {
            return Err(INVALID_FILE.to_owned());
        }
        let (challenge, rest) = bytes.split_at(CHALLENGE_LEN);
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        Ok(Self {
            challenge: challenge.try_into().expect("checked length"),
            nonce: nonce.try_into().expect("checked length"),
            sealed: sealed.try_into().expect("checked length"),
        })
    }
}

/// HKDF-SHA256 (RFC 5869) with one 32-byte output block.
fn derive_kek(signature: &[u8], challenge: &[u8; CHALLENGE_LEN]) -> Result<Zeroizing<[u8; 32]>, String> {
    if signature.len() < MIN_SIGNATURE_LEN {
        return Err(NOT_VERIFIED.to_owned());
    }
    Ok(hkdf_sha256(challenge, signature, KEK_INFO))
}

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("any HMAC key length");
    extract.update(ikm);
    let mut prk = Zeroizing::new([0u8; 32]);
    prk.copy_from_slice(&extract.finalize().into_bytes());
    let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&*prk).expect("any HMAC key length");
    expand.update(info);
    expand.update(&[1]);
    let mut okm = Zeroizing::new([0u8; 32]);
    okm.copy_from_slice(&expand.finalize().into_bytes());
    okm
}

fn wrap_key(
    key: &[u8; 32],
    signature: &[u8],
    challenge: &[u8; CHALLENGE_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<[u8; SEALED_KEY_LEN], String> {
    let kek = derive_kek(signature, challenge)?;
    let sealed = Aes256Gcm::new_from_slice(&*kek)
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(nonce), Payload { msg: key, aad: &aad(challenge) })
        .map_err(|_| "Windows Hello could not protect the vault key".to_owned())?;
    sealed
        .as_slice()
        .try_into()
        .map_err(|_| "Windows Hello could not protect the vault key".to_owned())
}

fn unwrap_key(
    sealed: &[u8; SEALED_KEY_LEN],
    signature: &[u8],
    challenge: &[u8; CHALLENGE_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let kek = derive_kek(signature, challenge)?;
    // A failure here means the Hello key changed or did not sign the same way as at setup.
    let mut plain = Aes256Gcm::new_from_slice(&*kek)
        .expect("32-byte key")
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad: &aad(challenge) })
        .map_err(|_| ENABLE_AGAIN.to_owned())?;
    let key = plain.as_slice().try_into().map(Zeroizing::new);
    plain.zeroize();
    key.map_err(|_| INVALID_FILE.to_owned())
}

/// Builds a format 2 file. `sign` returns the Hello signature of the challenge it gets.
pub fn seal(
    key: &[u8; 32],
    sign: impl FnOnce(&[u8]) -> Result<Zeroizing<Vec<u8>>, String>,
) -> Result<Vec<u8>, String> {
    let mut challenge = [0; CHALLENGE_LEN];
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut challenge).map_err(|_| "Windows could not make a random challenge".to_owned())?;
    getrandom::fill(&mut nonce).map_err(|_| "Windows could not make a random challenge".to_owned())?;
    let signature = sign(&challenge)?;
    let sealed = wrap_key(key, &signature, &challenge, &nonce)?;
    let inner = Inner { challenge, nonce, sealed }.encode();
    let blob = dpapi::protect(&inner, DPAPI_DESCRIPTION)?;
    let mut file = header().to_vec();
    file.extend_from_slice(&blob);
    Ok(file)
}

/// Opens a format 2 file. `sign` returns the Hello signature of the challenge it gets.
pub fn open(
    file: &[u8],
    sign: impl FnOnce(&[u8]) -> Result<Zeroizing<Vec<u8>>, String>,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let SavedFormat::Current(blob) = saved_format(file)? else {
        return Err(INVALID_FILE.to_owned());
    };
    let inner = dpapi::unprotect(blob).map_err(|_| ENABLE_AGAIN.to_owned())?;
    let inner = Inner::decode(&inner)?;
    let signature = sign(&inner.challenge)?;
    unwrap_key(&inner.sealed, &signature, &inner.challenge, &inner.nonce)
}

/// Opens a format 1 (DPAPI only) file. Call only after `verify` succeeds.
// Legacy path for files saved by Nuvori 2.2.3 and earlier. Remove it in a later release, once
// every Hello unlock has been saved again in format 2.
pub fn open_legacy(file: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    if !is_legacy(file) {
        return Err(INVALID_FILE.to_owned());
    }
    let bytes = dpapi::unprotect(file)?;
    bytes
        .as_slice()
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| INVALID_FILE.to_owned())
}

/// A stand-in for the Hello signature in tests: deterministic, 256 bytes, depends on `seed`.
#[cfg(test)]
pub(crate) fn test_signer(seed: u8) -> impl Fn(&[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    use sha2::Digest;
    move |challenge: &[u8]| {
        let mut signature = Zeroizing::new(Vec::with_capacity(256));
        for block in 0u8..8 {
            signature.extend_from_slice(&Sha256::new().chain_update([seed, block]).chain_update(challenge).finalize());
        }
        Ok(signature)
    }
}

#[cfg(test)]
pub(crate) fn protect_legacy_for_test(key: &[u8; 32]) -> Vec<u8> {
    dpapi::protect(key, DPAPI_DESCRIPTION).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        // RFC 5869 A.1: the first 32 bytes of OKM.
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        assert_eq!(
            hex::encode(*hkdf_sha256(&salt, &[0x0b; 22], &info)),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn kek_is_stable_and_depends_on_signature_and_challenge() {
        let signature = [1u8; 256];
        let challenge = [2u8; 32];
        let kek = derive_kek(&signature, &challenge).unwrap();
        assert_eq!(*kek, *derive_kek(&signature, &challenge).unwrap());
        assert_ne!(*kek, *derive_kek(&[3u8; 256], &challenge).unwrap());
        assert_ne!(*kek, *derive_kek(&signature, &[4u8; 32]).unwrap());
    }

    #[test]
    fn kek_refuses_short_signature() {
        assert!(derive_kek(&[], &[0; 32]).is_err());
        assert!(derive_kek(&[1; MIN_SIGNATURE_LEN - 1], &[0; 32]).is_err());
    }

    #[test]
    fn key_wrap_round_trips_and_rejects_wrong_signature_or_tampering() {
        let signature = [9u8; 256];
        let challenge = [5u8; 32];
        let nonce = [6u8; 12];
        let sealed = wrap_key(&KEY, &signature, &challenge, &nonce).unwrap();
        assert_eq!(*unwrap_key(&sealed, &signature, &challenge, &nonce).unwrap(), KEY);

        let mut other = signature;
        other[0] ^= 1;
        assert_eq!(unwrap_key(&sealed, &other, &challenge, &nonce).unwrap_err(), ENABLE_AGAIN);

        let mut tampered = sealed;
        tampered[0] ^= 1;
        assert!(unwrap_key(&tampered, &signature, &challenge, &nonce).is_err());
        let mut tampered_tag = sealed;
        tampered_tag[SEALED_KEY_LEN - 1] ^= 1;
        assert!(unwrap_key(&tampered_tag, &signature, &challenge, &nonce).is_err());
        assert!(unwrap_key(&sealed, &signature, &challenge, &[7u8; 12]).is_err());
    }

    #[test]
    fn inner_encoding_round_trips_and_checks_length() {
        let inner = Inner { challenge: [1; 32], nonce: [2; 12], sealed: [3; 48] };
        let bytes = inner.encode();
        assert_eq!(bytes.len(), INNER_LEN);
        let decoded = Inner::decode(&bytes).unwrap();
        assert_eq!((decoded.challenge, decoded.nonce, decoded.sealed), ([1; 32], [2; 12], [3; 48]));
        assert!(Inner::decode(&bytes[1..]).is_err());
    }

    #[test]
    fn file_header_is_versioned() {
        assert_eq!(saved_format(b"NVHK\x02blob").unwrap(), SavedFormat::Current(b"blob"));
        assert!(saved_format(b"NVHK\x02").is_err());
        assert!(saved_format(b"NVHK").is_err());
        assert!(saved_format(b"NVHK\x01blob").is_err());
        assert!(saved_format(b"NVHK\x03blob").unwrap_err().contains("newer version"));
    }

    #[test]
    fn legacy_dpapi_file_is_detected() {
        // Format 1 is a bare DPAPI blob; DPAPI blobs start with version 1 and the provider GUID.
        let legacy = protect_legacy_for_test(&KEY);
        assert_eq!(&legacy[..4], &[1, 0, 0, 0]);
        assert!(is_legacy(&legacy));
        assert_eq!(*open_legacy(&legacy).unwrap(), KEY);
        assert!(open(&legacy, test_signer(1)).is_err(), "format 2 reader refuses a legacy file");
    }

    #[test]
    fn sealed_file_opens_only_with_the_same_signer() {
        let file = seal(&KEY, test_signer(1)).unwrap();
        assert!(file.starts_with(b"NVHK\x02"));
        assert!(!is_legacy(&file));
        assert!(open_legacy(&file).is_err(), "legacy reader refuses a format 2 file");
        assert_eq!(*open(&file, test_signer(1)).unwrap(), KEY);
        assert_eq!(open(&file, test_signer(2)).unwrap_err(), ENABLE_AGAIN);
        // The vault key is not readable from the DPAPI layer alone.
        let SavedFormat::Current(blob) = saved_format(&file).unwrap() else { panic!() };
        let inner = dpapi::unprotect(blob).unwrap();
        assert!(!inner.windows(32).any(|window| window == KEY));
    }

    #[test]
    fn tampered_file_fails() {
        let mut file = seal(&KEY, test_signer(1)).unwrap();
        let last = file.len() - 1;
        file[last] ^= 1;
        assert!(open(&file, test_signer(1)).is_err());
    }

    #[test]
    fn each_enrollment_uses_a_new_challenge() {
        let seen = std::cell::RefCell::new(Vec::new());
        for _ in 0..2 {
            seal(&KEY, |challenge| {
                seen.borrow_mut().push(challenge.to_vec());
                test_signer(1)(challenge)
            })
            .unwrap();
        }
        let seen = seen.into_inner();
        assert_ne!(seen[0], seen[1]);
    }
}
