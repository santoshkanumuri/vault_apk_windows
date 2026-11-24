//! Security review M-07: Authenticode checks of Nuvori's own programs.
//!
//! A release built with `NUVORI_SIGNER_SHA256` or `NUVORI_SIGNER_NAME` set (`scripts/build-windows.ps1`
//! sets them when code signing is configured) trusts another Nuvori program only when Windows
//! verifies its Authenticode signature, chained to a trusted root, and its signing (leaf)
//! certificate either has a SHA-256 in that list or carries exactly that publisher name.
//!
//! - `NUVORI_SIGNER_SHA256`: certificate hashes, comma separated, for a certificate from a CA that
//!   lasts a year or more. Add a renewed certificate's hash a release before it is used.
//! - `NUVORI_SIGNER_NAME`: the certificate's display name (its common name). For Azure Trusted
//!   Signing, whose certificates change every few days; the CA still verified that identity.
//!
//! A build with neither (development, or unsigned installers) keeps the path checks alone, as before.
//!
//! Used for the browser pipe's client and server (M-05) and the pairing helper (L-19).

use std::path::Path;

/// The trusted signing certificates of this build, as the build environment gave them.
pub const BUILD_SIGNERS: Option<&str> = option_env!("NUVORI_SIGNER_SHA256");
/// The trusted publisher name of this build.
pub const BUILD_SIGNER_NAME: Option<&str> = option_env!("NUVORI_SIGNER_NAME");

/// What a signing certificate must match: a listed hash or the publisher name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expected {
    pub hashes: Vec<[u8; 32]>,
    pub name: Option<String>,
}

/// The verified signing certificate of a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub sha256: [u8; 32],
    pub name: String,
}

/// What a program's signature means for a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerCheck {
    /// This build trusts no certificate list: an unsigned build keeps its path checks alone.
    NotRequired,
    /// Signed by one of this build's certificates, and Windows verified the signature.
    Trusted,
    /// Unsigned, badly signed, or signed by anyone else.
    Untrusted,
}

impl SignerCheck {
    /// False only for [`SignerCheck::Untrusted`].
    pub fn allows(self) -> bool {
        self != SignerCheck::Untrusted
    }
}

/// Parses a comma or whitespace separated list of SHA-256 certificate hashes (64 hex digits, colons
/// and spaces inside a hash allowed, as `certutil` prints them). An empty list is no list; any bad
/// entry makes the whole list invalid, so a typo never silently trusts less or more.
pub fn parse_signers(list: &str) -> Result<Option<Vec<[u8; 32]>>, String> {
    let mut signers = Vec::new();
    for entry in list.split([',', ';', '\n']).map(str::trim).filter(|entry| !entry.is_empty()) {
        let digits: String = entry.chars().filter(|c| !matches!(c, ':' | ' ' | '\t')).collect();
        let bytes = hex::decode(&digits).map_err(|_| format!("not a SHA-256 certificate hash: {entry}"))?;
        let hash: [u8; 32] = bytes.try_into().map_err(|_| format!("not a SHA-256 certificate hash: {entry}"))?;
        if !signers.contains(&hash) {
            signers.push(hash);
        }
    }
    Ok((!signers.is_empty()).then_some(signers))
}

/// What `hashes` and `name` (as the build environment gave them) require, or `None` when they
/// require nothing. `build.rs` refuses a bad hash list, so one that still fails here trusts nothing.
pub fn expected_from(hashes: Option<&str>, name: Option<&str>) -> Option<Expected> {
    let name = name.map(str::trim).filter(|name| !name.is_empty()).map(str::to_owned);
    let hashes = match hashes.map(parse_signers) {
        None | Some(Ok(None)) => Vec::new(),
        Some(Ok(Some(list))) => list,
        Some(Err(_)) => return Some(Expected { hashes: Vec::new(), name: None }),
    };
    (!hashes.is_empty() || name.is_some()).then_some(Expected { hashes, name })
}

/// This build's requirement, or `None` for an unsigned build.
pub fn expected_signers() -> Option<Expected> {
    expected_from(BUILD_SIGNERS, BUILD_SIGNER_NAME)
}

/// The rule, apart from Windows: `actual` is the verified signing certificate, or `None` when
/// Windows did not verify a signature. Names compare exactly.
pub fn decide(expected: Option<&Expected>, actual: Option<&Signature>) -> SignerCheck {
    match (expected, actual) {
        (None, _) => SignerCheck::NotRequired,
        (Some(expected), Some(actual))
            if expected.hashes.contains(&actual.sha256) || expected.name.as_deref() == Some(actual.name.as_str()) =>
        {
            SignerCheck::Trusted
        }
        _ => SignerCheck::Untrusted,
    }
}

/// Checks the program at `path` against this build's signers.
pub fn check(path: &Path) -> SignerCheck {
    let Some(expected) = expected_signers() else {
        return SignerCheck::NotRequired;
    };
    decide(Some(&expected), verified_signer(path).as_ref())
}

/// The leaf certificate of `path`'s Authenticode signature, when Windows verifies the signature.
/// Results are kept for the process's life per file, size and write time, because the browser
/// host connects for every request.
#[cfg(windows)]
fn verified_signer(path: &Path) -> Option<Signature> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    type Cache = HashMap<(std::path::PathBuf, u64, u64), Option<Signature>>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let identity = file_identity(path)?;
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(found) = cache.lock().ok().and_then(|cache| cache.get(&identity).cloned()) {
        return found;
    }
    let found = windows_trust::leaf_certificate(path);
    if let Ok(mut cache) = cache.lock() {
        if cache.len() >= 32 {
            cache.clear();
        }
        cache.insert(identity, found.clone());
    }
    found
}

#[cfg(not(windows))]
fn verified_signer(_path: &Path) -> Option<Signature> {
    None
}

/// Canonical path, size and last write time (100 ns units) of `path`.
#[cfg(windows)]
fn file_identity(path: &Path) -> Option<(std::path::PathBuf, u64, u64)> {
    use std::os::windows::fs::MetadataExt;
    let canonical = std::fs::canonicalize(path).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    Some((canonical, metadata.file_size(), metadata.last_write_time()))
}

#[cfg(windows)]
mod windows_trust {
    use sha2::{Digest, Sha256};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows::Win32::Foundation::{HANDLE, HWND, INVALID_HANDLE_VALUE};
    use windows::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
    use windows::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust,
    };
    use windows::core::PCWSTR;

    /// Verifies `path`'s embedded Authenticode signature with the system's trust policy (a chain
    /// to a trusted root, a valid or timestamped certificate, an unmodified file) and returns the
    /// signing certificate's SHA-256 and display name. Revocation is not fetched over the network,
    /// so the check never waits on it.
    pub(super) fn leaf_certificate(path: &Path) -> Option<super::Signature> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let no_window = HWND(INVALID_HANDLE_VALUE.0);
        let status = unsafe { WinVerifyTrust(no_window, &mut action, &mut data as *mut _ as *mut _) };
        let found = if status == 0 {
            unsafe {
                let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
                let signer = if provider.is_null() { std::ptr::null_mut() } else { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
                let certificate = if signer.is_null() { std::ptr::null_mut() } else { WTHelperGetProvCertFromChain(signer, 0) };
                if certificate.is_null() || (*certificate).pCert.is_null() {
                    None
                } else {
                    let context = (*certificate).pCert;
                    let encoded = std::slice::from_raw_parts((*context).pbCertEncoded, (*context).cbCertEncoded as usize);
                    let mut name = vec![0u16; 512];
                    let length = CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut name)) as usize;
                    let name = String::from_utf16_lossy(&name[..length.saturating_sub(1).min(name.len())]);
                    Some(super::Signature { sha256: Sha256::digest(encoded).into(), name })
                }
            }
        } else {
            None
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            let _ = WinVerifyTrust(no_window, &mut action, &mut data as *mut _ as *mut _);
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const B: &str = "FE:DC:BA:98:76:54:32:10:FE:DC:BA:98:76:54:32:10:FE:DC:BA:98:76:54:32:10:FE:DC:BA:98:76:54:32:10";

    #[test]
    fn a_list_takes_plain_and_certutil_style_hashes() {
        let list = parse_signers(&format!(" {A} , {B} ")).unwrap().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0][0], 0x01);
        assert_eq!(list[1][0], 0xfe);
        assert_eq!(parse_signers(&format!("{A},{A}")).unwrap().unwrap().len(), 1);
    }

    #[test]
    fn an_empty_list_is_no_list_and_a_bad_entry_spoils_the_whole_list() {
        assert_eq!(parse_signers("").unwrap(), None);
        assert_eq!(parse_signers(" , ").unwrap(), None);
        assert!(parse_signers(&format!("{A},abc")).is_err());
        assert!(parse_signers(&A[..62]).is_err());
        assert!(parse_signers(&format!("{A}00")).is_err());
        assert!(parse_signers("zz").is_err());
    }

    fn signature(sha256: [u8; 32], name: &str) -> Signature {
        Signature { sha256, name: name.to_owned() }
    }

    #[test]
    fn an_unsigned_build_keeps_the_path_checks_alone() {
        assert_eq!(expected_from(None, None), None);
        assert_eq!(expected_from(Some(""), Some("  ")), None);
        assert_eq!(decide(None, None), SignerCheck::NotRequired);
        assert!(decide(None, None).allows());
    }

    #[test]
    fn with_hashes_only_a_verified_listed_certificate_is_trusted() {
        let expected = expected_from(Some(A), None).unwrap();
        let listed = expected.hashes[0];
        assert_eq!(decide(Some(&expected), Some(&signature(listed, "Anyone"))), SignerCheck::Trusted);
        assert_eq!(decide(Some(&expected), Some(&signature([9u8; 32], "Anyone"))), SignerCheck::Untrusted);
        assert_eq!(decide(Some(&expected), None), SignerCheck::Untrusted);
        assert!(!decide(Some(&expected), None).allows());
    }

    #[test]
    fn with_a_name_only_that_exact_publisher_is_trusted() {
        let expected = expected_from(None, Some(" Example Publisher ")).unwrap();
        assert_eq!(decide(Some(&expected), Some(&signature([1u8; 32], "Example Publisher"))), SignerCheck::Trusted);
        assert_eq!(decide(Some(&expected), Some(&signature([1u8; 32], "Example Publisher Ltd"))), SignerCheck::Untrusted);
        assert_eq!(decide(Some(&expected), Some(&signature([1u8; 32], "example publisher"))), SignerCheck::Untrusted);
        assert_eq!(decide(Some(&expected), None), SignerCheck::Untrusted);
    }

    #[test]
    fn a_hash_list_that_could_not_be_read_trusts_nothing() {
        let expected = expected_from(Some("not a hash"), Some("Example Publisher")).unwrap();
        assert_eq!(decide(Some(&expected), Some(&signature([1u8; 32], "Example Publisher"))), SignerCheck::Untrusted);
    }
}
