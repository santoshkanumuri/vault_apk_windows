//! Windows passkey provider (plugin authenticator). Windows 11 asks this COM class to sign in
//! with a passkey that synced from the phone. It works in every browser and app that uses the
//! Windows passkey prompt.
//!
//! Only the packaged (MSIX) build registers the provider: Windows activates the class through
//! the package's `windows.comServer` entry. The unpackaged installer build does nothing here.
//!
//! Shapes come from the Windows SDK headers `pluginauthenticator.idl`, `webauthnplugin.h` and
//! `webauthn.h` (10.0.26100). The plugin functions are loaded at run time, so the app still
//! starts on a Windows version whose `webauthn.dll` does not have them.
//!
//! Signing in and saving a new passkey both work. A passkey saved here is a signed change like
//! any other item, so it reaches the phone on the next sync.

// The COM methods keep the names from the Windows SDK.
#![allow(non_snake_case)]

use std::{
    ffi::c_void,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use windows::{
    Win32::{
        Foundation::{E_INVALIDARG, E_POINTER, HMODULE, HWND, S_OK},
        Security::Cryptography::{
            BCRYPT_PAD_PSS, BCRYPT_PSS_PADDING_INFO, BCRYPT_PUBLIC_KEY_BLOB, BCRYPT_SHA256_ALGORITHM,
            MS_KEY_STORAGE_PROVIDER, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCryptFreeObject,
            NCryptImportKey, NCryptOpenStorageProvider, NCryptVerifySignature,
        },
        Storage::Packaging::Appx::{GetCurrentPackageFamilyName, GetCurrentPackageFullName},
        System::{
            Com::{
                CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, CoInitializeEx, CoRegisterClassObject, IClassFactory,
                IClassFactory_Impl, REGCLS_MULTIPLEUSE,
            },
            LibraryLoader::{GetProcAddress, LoadLibraryW},
        },
    },
    core::{BOOL, GUID, HRESULT, IUnknown, IUnknown_Vtbl, Interface, PCSTR, PCWSTR, Ref, implement, interface, s, w},
};

use crate::{
    ManagedState,
    activity::{self, Category, Level},
    desktop,
    passkeys::VaultPasskey,
};

/// COM class of the Nuvori passkey provider. The MSIX manifest declares the same ID.
pub const CLSID: GUID = GUID::from_u128(0x6f2b8f0e_4c3a_4d7b_9a51_2e8d1c7f4b90);
/// Nuvori for Windows' authenticator model (73065c20-ccdd-4502-9803-318dc6594745). Windows
/// rejects a plugin registration with an all-zero AAGUID ("The parameter is incorrect"), so
/// this differs from the zero AAGUID the phone writes when it creates a passkey. A signature
/// never includes the AAGUID, so passkeys from either device sign in on both.
const AAGUID: [u8; 16] = [0x73, 0x06, 0x5c, 0x20, 0xcc, 0xdd, 0x45, 0x02, 0x98, 0x03, 0x31, 0x8d, 0xc6, 0x59, 0x47, 0x45];

const NTE_BAD_SIGNATURE: HRESULT = HRESULT(0x8009_0006_u32 as i32);
const NTE_EXISTS: HRESULT = HRESULT(0x8009_000F_u32 as i32);
const NTE_NOT_FOUND: HRESULT = HRESULT(0x8009_0011_u32 as i32);
const NTE_NOT_SUPPORTED: HRESULT = HRESULT(0x8009_0029_u32 as i32);
const NTE_USER_CANCELLED: HRESULT = HRESULT(0x8009_0036_u32 as i32);
const E_FAIL: HRESULT = HRESULT(0x8000_4005_u32 as i32);
const APPMODEL_ERROR_NO_PACKAGE: u32 = 15700;
const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x3141_5352;
const WEBAUTHN_ASSERTION_VERSION: u32 = 6;
const WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION: u32 = 8;
/// COSE ES256, the only algorithm the phone's passkeys use.
const COSE_ES256: i32 = -7;
const WEBAUTHN_CTAP_TRANSPORT_INTERNAL: u32 = 0x10;
/// How long a sign-in waits for the user to unlock the vault.
const UNLOCK_WAIT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------------------------
// SDK structures (pluginauthenticator.idl, webauthnplugin.h, webauthn.h)

#[repr(C)]
pub struct OperationRequest {
    hwnd: HWND,
    transaction_id: GUID,
    cb_request_signature: u32,
    pb_request_signature: *const u8,
    request_type: i32,
    cb_encoded_request: u32,
    pb_encoded_request: *const u8,
}

#[repr(C)]
pub struct OperationResponse {
    cb_encoded_response: u32,
    pb_encoded_response: *mut u8,
}

#[repr(C)]
pub struct CancelRequest {
    transaction_id: GUID,
    cb_request_signature: u32,
    pb_request_signature: *const u8,
}

#[repr(C)]
struct AddAuthenticatorOptions {
    name: PCWSTR,
    clsid: *const GUID,
    plugin_rp_id: PCWSTR,
    light_logo_svg: PCWSTR,
    dark_logo_svg: PCWSTR,
    cb_authenticator_info: u32,
    pb_authenticator_info: *const u8,
    supported_rp_id_count: u32,
    supported_rp_ids: *const PCWSTR,
}

#[repr(C)]
struct AddAuthenticatorResponse {
    cb_op_sign_pub_key: u32,
    pb_op_sign_pub_key: *mut u8,
}

#[repr(C)]
struct CredentialDetails {
    cb_credential_id: u32,
    pb_credential_id: *const u8,
    rp_id: PCWSTR,
    rp_name: PCWSTR,
    cb_user_id: u32,
    pb_user_id: *const u8,
    user_name: PCWSTR,
    user_display_name: PCWSTR,
}

#[repr(C)]
struct UserVerificationRequest {
    hwnd: HWND,
    transaction_id: *const GUID,
    username: PCWSTR,
    display_hint: PCWSTR,
}

#[repr(C)]
struct CredentialEx {
    version: u32,
    cb_id: u32,
    pb_id: *const u8,
    credential_type: PCWSTR,
    transports: u32,
}

#[repr(C)]
struct CredentialList {
    count: u32,
    credentials: *const *const CredentialEx,
}

/// The leading fields of `WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST`. Windows owns the structure;
/// only these fields are read.
#[repr(C)]
struct GetAssertionRequestHead {
    version: u32,
    rp_id_wide: PCWSTR,
    cb_rp_id: u32,
    pb_rp_id: *const u8,
    cb_client_data_hash: u32,
    pb_client_data_hash: *const u8,
    credential_list: CredentialList,
}

#[repr(C)]
struct Credential {
    version: u32,
    cb_id: u32,
    pb_id: *const u8,
    credential_type: PCWSTR,
}

#[repr(C)]
struct Extensions {
    count: u32,
    extensions: *const c_void,
}

/// `WEBAUTHN_ASSERTION`, version 6.
#[repr(C)]
struct Assertion {
    version: u32,
    cb_authenticator_data: u32,
    pb_authenticator_data: *const u8,
    cb_signature: u32,
    pb_signature: *const u8,
    credential: Credential,
    cb_user_id: u32,
    pb_user_id: *const u8,
    extensions: Extensions,
    cb_cred_large_blob: u32,
    pb_cred_large_blob: *const u8,
    cred_large_blob_status: u32,
    hmac_secret: *const c_void,
    used_transport: u32,
    cb_unsigned_extension_outputs: u32,
    pb_unsigned_extension_outputs: *const u8,
    cb_client_data_json: u32,
    pb_client_data_json: *const u8,
    cb_authentication_response_json: u32,
    pb_authentication_response_json: *const u8,
}

#[repr(C)]
struct UserEntity {
    version: u32,
    cb_id: u32,
    pb_id: *const u8,
    name: PCWSTR,
    icon: PCWSTR,
    display_name: PCWSTR,
}

#[repr(C)]
struct GetAssertionResponse {
    assertion: Assertion,
    user: *const UserEntity,
    number_of_credentials: u32,
    user_selected: i32,
    cb_large_blob_key: u32,
    pb_large_blob_key: *const u8,
    cb_unsigned_extension_outputs: u32,
    pb_unsigned_extension_outputs: *const u8,
}

#[repr(C)]
struct RpEntity {
    version: u32,
    id: PCWSTR,
    name: PCWSTR,
    icon: PCWSTR,
}

#[repr(C)]
struct CoseParameter {
    version: u32,
    credential_type: PCWSTR,
    alg: i32,
}

#[repr(C)]
struct CoseParameters {
    count: u32,
    parameters: *const CoseParameter,
}

/// The leading fields of `WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST`; only these are read.
#[repr(C)]
struct MakeCredentialRequestHead {
    version: u32,
    cb_rp_id: u32,
    pb_rp_id: *const u8,
    cb_client_data_hash: u32,
    pb_client_data_hash: *const u8,
    rp: *const RpEntity,
    user: *const UserEntity,
    parameters: CoseParameters,
    exclude: CredentialList,
}

/// `WEBAUTHN_CREDENTIAL_ATTESTATION`, version 8.
#[repr(C)]
struct CredentialAttestation {
    version: u32,
    format_type: PCWSTR,
    cb_authenticator_data: u32,
    pb_authenticator_data: *const u8,
    cb_attestation: u32,
    pb_attestation: *const u8,
    attestation_decode_type: u32,
    attestation_decode: *const c_void,
    cb_attestation_object: u32,
    pb_attestation_object: *const u8,
    cb_credential_id: u32,
    pb_credential_id: *const u8,
    extensions: Extensions,
    used_transport: u32,
    ep_att: i32,
    large_blob_supported: i32,
    resident_key: i32,
    prf_enabled: i32,
    cb_unsigned_extension_outputs: u32,
    pb_unsigned_extension_outputs: *const u8,
    hmac_secret: *const c_void,
    third_party_payment: i32,
    transports: u32,
    cb_client_data_json: u32,
    pb_client_data_json: *const u8,
    cb_registration_response_json: u32,
    pb_registration_response_json: *const u8,
}

#[interface("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
unsafe trait IPluginAuthenticator: IUnknown {
    unsafe fn MakeCredential(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT;
    unsafe fn GetAssertion(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT;
    unsafe fn CancelOperation(&self, request: *const CancelRequest) -> HRESULT;
    unsafe fn GetLockStatus(&self, status: *mut i32) -> HRESULT;
}

// ---------------------------------------------------------------------------------------------
// webauthn.dll plugin functions, loaded at run time

type GetStateFn = unsafe extern "system" fn(*const GUID, *mut i32) -> HRESULT;
type AddAuthenticatorFn =
    unsafe extern "system" fn(*const AddAuthenticatorOptions, *mut *mut AddAuthenticatorResponse) -> HRESULT;
type FreeAddResponseFn = unsafe extern "system" fn(*mut AddAuthenticatorResponse);
type AddCredentialsFn = unsafe extern "system" fn(*const GUID, u32, *const CredentialDetails) -> HRESULT;
type RemoveAllCredentialsFn = unsafe extern "system" fn(*const GUID) -> HRESULT;
type GetPublicKeyFn = unsafe extern "system" fn(*const GUID, *mut u32, *mut *mut u8) -> HRESULT;
type FreeBytesFn = unsafe extern "system" fn(*mut u8);
type PerformUvFn = unsafe extern "system" fn(*const UserVerificationRequest, *mut u32, *mut *mut u8) -> HRESULT;
type DecodeGetAssertionFn = unsafe extern "system" fn(u32, *const u8, *mut *mut GetAssertionRequestHead) -> HRESULT;
type FreeDecodedGetAssertionFn = unsafe extern "system" fn(*mut GetAssertionRequestHead);
type EncodeGetAssertionFn = unsafe extern "system" fn(*const GetAssertionResponse, *mut u32, *mut *mut u8) -> HRESULT;
type DecodeMakeCredentialFn = unsafe extern "system" fn(u32, *const u8, *mut *mut MakeCredentialRequestHead) -> HRESULT;
type FreeDecodedMakeCredentialFn = unsafe extern "system" fn(*mut MakeCredentialRequestHead);
type EncodeMakeCredentialFn = unsafe extern "system" fn(*const CredentialAttestation, *mut u32, *mut *mut u8) -> HRESULT;

struct Api {
    get_state: GetStateFn,
    add_authenticator: AddAuthenticatorFn,
    free_add_response: FreeAddResponseFn,
    add_credentials: AddCredentialsFn,
    remove_all_credentials: RemoveAllCredentialsFn,
    get_operation_signing_key: GetPublicKeyFn,
    free_public_key: FreeBytesFn,
    perform_user_verification: PerformUvFn,
    free_user_verification: FreeBytesFn,
    decode_get_assertion: DecodeGetAssertionFn,
    free_decoded_get_assertion: FreeDecodedGetAssertionFn,
    encode_get_assertion: EncodeGetAssertionFn,
    decode_make_credential: DecodeMakeCredentialFn,
    free_decoded_make_credential: FreeDecodedMakeCredentialFn,
    encode_make_credential: EncodeMakeCredentialFn,
}

/// `None` on a Windows version without the passkey plugin functions.
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| unsafe {
        let library = LoadLibraryW(w!("webauthn.dll")).ok()?;
        unsafe fn symbol<T: Copy>(library: HMODULE, name: PCSTR) -> Option<T> {
            let address = unsafe { GetProcAddress(library, name) }?;
            // Every `T` used here is a function pointer of the same size as `FARPROC`.
            Some(unsafe { std::mem::transmute_copy(&address) })
        }
        Some(Api {
            get_state: symbol(library, s!("WebAuthNPluginGetAuthenticatorState"))?,
            add_authenticator: symbol(library, s!("WebAuthNPluginAddAuthenticator"))?,
            free_add_response: symbol(library, s!("WebAuthNPluginFreeAddAuthenticatorResponse"))?,
            add_credentials: symbol(library, s!("WebAuthNPluginAuthenticatorAddCredentials"))?,
            remove_all_credentials: symbol(library, s!("WebAuthNPluginAuthenticatorRemoveAllCredentials"))?,
            get_operation_signing_key: symbol(library, s!("WebAuthNPluginGetOperationSigningPublicKey"))?,
            free_public_key: symbol(library, s!("WebAuthNPluginFreePublicKeyResponse"))?,
            perform_user_verification: symbol(library, s!("WebAuthNPluginPerformUserVerification"))?,
            free_user_verification: symbol(library, s!("WebAuthNPluginFreeUserVerificationResponse"))?,
            decode_get_assertion: symbol(library, s!("WebAuthNDecodeGetAssertionRequest"))?,
            free_decoded_get_assertion: symbol(library, s!("WebAuthNFreeDecodedGetAssertionRequest"))?,
            encode_get_assertion: symbol(library, s!("WebAuthNEncodeGetAssertionResponse"))?,
            decode_make_credential: symbol(library, s!("WebAuthNDecodeMakeCredentialRequest"))?,
            free_decoded_make_credential: symbol(library, s!("WebAuthNFreeDecodedMakeCredentialRequest"))?,
            encode_make_credential: symbol(library, s!("WebAuthNEncodeMakeCredentialResponse"))?,
        })
    })
    .as_ref()
}

/// True when this process runs from an installed package (the Store / MSIX build).
pub fn packaged() -> bool {
    let mut length = 0u32;
    unsafe { GetCurrentPackageFullName(&mut length, None) }.0 != APPMODEL_ERROR_NO_PACKAGE
}

/// True when Windows redirects this package's writes under `%APPDATA%` to a private copy.
///
/// The package manifest turns that redirection off, so the Store build and the installer build
/// share one vault. If it is on anyway, the app must not open the vault: changes would go to a
/// private copy that an uninstall deletes, and this PC's signed change history would split.
/// The check writes a marker into `data_directory` and looks for it in the package's private
/// folder (`%LOCALAPPDATA%\Packages\<family>\LocalCache\Roaming\<folder>`).
pub fn storage_is_redirected(data_directory: &std::path::Path) -> bool {
    if !packaged() {
        return false;
    }
    let mut length = 0u32;
    let _ = unsafe { GetCurrentPackageFamilyName(&mut length, None) };
    let mut name = vec![0u16; length as usize];
    if unsafe { GetCurrentPackageFamilyName(&mut length, Some(windows::core::PWSTR(name.as_mut_ptr()))) }.0 != 0 {
        return true;
    }
    let family = String::from_utf16_lossy(&name[..name.iter().position(|unit| *unit == 0).unwrap_or(name.len())]);
    let (Some(local), Some(folder)) = (std::env::var_os("LOCALAPPDATA"), data_directory.file_name()) else {
        return true;
    };
    let marker = format!("storage-check-{}", uuid::Uuid::new_v4());
    if std::fs::create_dir_all(data_directory).is_err() || std::fs::write(data_directory.join(&marker), b"").is_err() {
        return true;
    }
    let private = std::path::PathBuf::from(local)
        .join("Packages")
        .join(family)
        .join("LocalCache")
        .join("Roaming")
        .join(folder)
        .join(&marker);
    let redirected = private.exists();
    let _ = std::fs::remove_file(data_directory.join(&marker));
    redirected
}

// ---------------------------------------------------------------------------------------------
// Pure helpers

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    debug_assert!(text.len() < 24);
    out.push(0x60 | text.len() as u8);
    out.extend_from_slice(text.as_bytes());
}

/// CTAP2 `authenticatorGetInfo`: FIDO 2.0/2.1, this model's AAGUID, resident keys with user
/// presence and verification, the internal transport, and ES256.
fn authenticator_info() -> Vec<u8> {
    let mut out = vec![0xa5, 0x01, 0x82];
    cbor_text(&mut out, "FIDO_2_0");
    cbor_text(&mut out, "FIDO_2_1");
    out.extend_from_slice(&[0x03, 0x50]);
    out.extend_from_slice(&AAGUID);
    out.extend_from_slice(&[0x04, 0xa3]);
    for option in ["rk", "up", "uv"] {
        cbor_text(&mut out, option);
        out.push(0xf5);
    }
    out.extend_from_slice(&[0x09, 0x81]);
    cbor_text(&mut out, "internal");
    out.extend_from_slice(&[0x0a, 0x81, 0xa2]);
    cbor_text(&mut out, "alg");
    out.push(0x26);
    cbor_text(&mut out, "type");
    cbor_text(&mut out, "public-key");
    out
}

/// The passkeys that can answer: same RP ID and, when the site or the Windows picker names
/// credentials, one of those. Newest first.
fn matching<'a>(passkeys: &'a [VaultPasskey], rp_id: &str, allowed: &[Vec<u8>]) -> Vec<&'a VaultPasskey> {
    let mut found: Vec<&VaultPasskey> = passkeys
        .iter()
        .filter(|passkey| passkey.rp_id == rp_id)
        .filter(|passkey| {
            allowed.is_empty()
                || URL_SAFE_NO_PAD.decode(&passkey.id).is_ok_and(|id| allowed.iter().any(|allowed| *allowed == id))
        })
        .collect();
    found.sort_by(|left, right| right.created_at.cmp(&left.created_at).then_with(|| left.id.cmp(&right.id)));
    found
}

/// Asks which passkey to use when several match, in a Windows dialog over the caller's window.
/// `None` means the user canceled. Without the dialog (no common controls v6) the newest is used.
fn choose_passkey(hwnd: HWND, rp_id: &str, options: &[&VaultPasskey]) -> Option<usize> {
    use windows::Win32::UI::Controls::{
        TASKDIALOG_BUTTON, TASKDIALOGCONFIG, TDCBF_CANCEL_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION,
        TDF_POSITION_RELATIVE_TO_WINDOW, TDF_USE_COMMAND_LINKS,
    };
    type TaskDialogIndirectFn =
        unsafe extern "system" fn(*const TASKDIALOGCONFIG, *mut i32, *mut i32, *mut BOOL) -> HRESULT;
    const FIRST_BUTTON: i32 = 1000;
    if options.len() < 2 {
        return Some(0);
    }
    let dialog: Option<TaskDialogIndirectFn> = unsafe {
        LoadLibraryW(w!("comctl32.dll")).ok().and_then(|library| {
            GetProcAddress(library, s!("TaskDialogIndirect")).map(|address| std::mem::transmute_copy(&address))
        })
    };
    let Some(dialog) = dialog else { return Some(0) };
    // "Account\nName": a command link shows the second line as its note.
    let labels: Vec<Vec<u16>> = options
        .iter()
        .map(|passkey| {
            let note = if passkey.display_name.is_empty() || passkey.display_name == passkey.username {
                String::new()
            } else {
                format!("\n{}", passkey.display_name)
            };
            wide(&format!("{}{note}", passkey.username))
        })
        .collect();
    let buttons: Vec<TASKDIALOG_BUTTON> = labels
        .iter()
        .enumerate()
        .map(|(index, label)| TASKDIALOG_BUTTON { nButtonID: FIRST_BUTTON + index as i32, pszButtonText: PCWSTR(label.as_ptr()) })
        .collect();
    let (title, instruction, content) =
        (wide("Nuvori"), wide(&format!("Choose a passkey for {rp_id}")), wide("Windows Hello confirms it next."));
    let config = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: hwnd,
        dwFlags: TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW,
        dwCommonButtons: TDCBF_CANCEL_BUTTON,
        pszWindowTitle: PCWSTR(title.as_ptr()),
        pszMainInstruction: PCWSTR(instruction.as_ptr()),
        pszContent: PCWSTR(content.as_ptr()),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        nDefaultButton: FIRST_BUTTON,
        ..Default::default()
    };
    let mut pressed = 0i32;
    let shown = unsafe { dialog(&config, &mut pressed, std::ptr::null_mut(), std::ptr::null_mut()) };
    if shown.is_err() {
        return Some(0);
    }
    usize::try_from(pressed - FIRST_BUTTON).ok().filter(|index| *index < options.len())
}

/// COSE_Key for a P-256 public key (`kty` EC2, `alg` ES256, `crv` P-256, `x`, `y`).
fn cose_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    out.extend_from_slice(x);
    out.extend_from_slice(&[0x22, 0x58, 0x20]);
    out.extend_from_slice(y);
    out
}

/// Authenticator data for a new passkey, with the flags the phone uses when it creates one
/// (user present, user verified, backup eligible, attested credential data) and count 0.
fn creation_authenticator_data(rp_id: &[u8], credential_id: &[u8], x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id).to_vec();
    data.extend_from_slice(&[0x4d, 0, 0, 0, 0]);
    data.extend_from_slice(&AAGUID);
    data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(&cose_key(x, y));
    data
}

/// A new P-256 passkey in the phone's storage format (PKCS#8 and SPKI, base64url).
fn new_passkey(rp_id: &str, user_id: &[u8], username: &str, display_name: &str, now: i64)
    -> Result<(VaultPasskey, Vec<u8>, [u8; 32], [u8; 32]), HRESULT> {
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    let secret = loop {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut_slice()).map_err(|_| E_FAIL)?;
        if let Ok(secret) = p256::SecretKey::from_slice(seed.as_slice()) {
            break secret;
        }
    };
    let public = secret.public_key().to_public_key_der().map_err(|_| E_FAIL)?;
    // An SPKI for P-256 ends with the uncompressed point 0x04 || x || y.
    let spki = public.as_bytes();
    let point = spki.get(spki.len().saturating_sub(65)..).filter(|point| point.len() == 65 && point[0] == 4).ok_or(E_FAIL)?;
    let (x, y): ([u8; 32], [u8; 32]) = (point[1..33].try_into().map_err(|_| E_FAIL)?, point[33..].try_into().map_err(|_| E_FAIL)?);
    let mut credential_id = vec![0u8; 32];
    getrandom::fill(&mut credential_id).map_err(|_| E_FAIL)?;
    let private = secret.to_pkcs8_der().map_err(|_| E_FAIL)?;
    let passkey = VaultPasskey {
        id: URL_SAFE_NO_PAD.encode(&credential_id),
        rp_id: rp_id.to_owned(),
        user_handle: URL_SAFE_NO_PAD.encode(user_id),
        username: username.to_owned(),
        display_name: display_name.to_owned(),
        private_key: URL_SAFE_NO_PAD.encode(private.as_bytes()),
        public_key: URL_SAFE_NO_PAD.encode(spki),
        created_at: now,
    };
    passkey.validate().map_err(|_| E_INVALIDARG)?;
    Ok((passkey, credential_id, x, y))
}

/// Reads a NUL-terminated wide string Windows owns.
unsafe fn read_wide(text: PCWSTR) -> String {
    if text.is_null() { String::new() } else { unsafe { text.to_string() }.unwrap_or_default() }
}

/// Checks `signature` over SHA-256 of `data` with a CNG public key blob, as Microsoft's
/// PasskeyManager sample does: RSA keys use PSS with a 32-byte salt, ECDSA keys no padding.
fn verify_cng_signature(data: &[u8], public_key_blob: &[u8], signature: &[u8]) -> bool {
    if public_key_blob.len() < 8 || signature.is_empty() {
        return false;
    }
    let hash = Sha256::digest(data);
    let magic = u32::from_le_bytes([public_key_blob[0], public_key_blob[1], public_key_blob[2], public_key_blob[3]]);
    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        if NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0).is_err() {
            return false;
        }
        let mut key = NCRYPT_KEY_HANDLE::default();
        let imported =
            NCryptImportKey(provider, None, BCRYPT_PUBLIC_KEY_BLOB, None, &mut key, public_key_blob, NCRYPT_FLAGS(0));
        let verified = imported.is_ok() && {
            if magic == BCRYPT_RSAPUBLIC_MAGIC {
                let padding = BCRYPT_PSS_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM, cbSalt: 32 };
                NCryptVerifySignature(
                    key,
                    Some(&padding as *const _ as *const c_void),
                    &hash,
                    signature,
                    NCRYPT_FLAGS(BCRYPT_PAD_PSS.0),
                )
                .is_ok()
            } else {
                NCryptVerifySignature(key, None, &hash, signature, NCRYPT_FLAGS(0)).is_ok()
            }
        };
        if !key.is_invalid() {
            let _ = NCryptFreeObject(key.into());
        }
        let _ = NCryptFreeObject(provider.into());
        verified
    }
}

// ---------------------------------------------------------------------------------------------
// The provider

struct Provider {
    state: ManagedState,
    app: AppHandle,
    cancelled: AtomicBool,
}

impl Provider {
    fn unlocked(&self) -> bool {
        self.state.lock().is_ok_and(|app| app.unlocked.is_some())
    }

    /// Shows the small unlock window and waits until the vault is open.
    fn wait_for_unlock(&self) -> Result<(), HRESULT> {
        if self.unlocked() {
            return Ok(());
        }
        let app = self.app.clone();
        let _ = self.app.run_on_main_thread(move || desktop::show_unlock_prompt(&app));
        let deadline = Instant::now() + UNLOCK_WAIT;
        while Instant::now() < deadline {
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(NTE_USER_CANCELLED);
            }
            if self.unlocked() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(250));
        }
        Err(NTE_USER_CANCELLED)
    }

    /// Windows signs every request with the key it gave this provider at registration. A request
    /// from any other program does not carry that signature and is refused.
    fn request_is_from_windows(&self, api: &Api, encoded: &[u8], signature: &[u8]) -> bool {
        let (mut length, mut key) = (0u32, std::ptr::null_mut::<u8>());
        let fetched = unsafe { (api.get_operation_signing_key)(&CLSID, &mut length, &mut key) };
        if fetched.is_err() || key.is_null() {
            return false;
        }
        let blob = unsafe { std::slice::from_raw_parts(key, length as usize) };
        let verified = verify_cng_signature(encoded, blob, signature);
        unsafe { (api.free_public_key)(key) };
        verified
    }

    fn get_assertion(&self, request: &OperationRequest) -> Result<(u32, *mut u8), HRESULT> {
        let api = api().ok_or(NTE_NOT_SUPPORTED)?;
        if request.pb_encoded_request.is_null() || request.cb_encoded_request == 0 {
            return Err(E_INVALIDARG);
        }
        self.cancelled.store(false, Ordering::SeqCst);
        let encoded =
            unsafe { std::slice::from_raw_parts(request.pb_encoded_request, request.cb_encoded_request as usize) };
        let signature = if request.pb_request_signature.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(request.pb_request_signature, request.cb_request_signature as usize) }
        };
        if !self.request_is_from_windows(api, encoded, signature) {
            activity::diagnostic(Category::Security, "Passkey request refused", "the request signature did not verify");
            return Err(NTE_BAD_SIGNATURE);
        }

        // Copy what is needed out of the decoded request, then free it.
        let mut decoded = std::ptr::null_mut::<GetAssertionRequestHead>();
        unsafe { (api.decode_get_assertion)(request.cb_encoded_request, request.pb_encoded_request, &mut decoded) }
            .ok()
            .map_err(|error| error.code())?;
        if decoded.is_null() {
            return Err(E_FAIL);
        }
        let (rp_id_bytes, client_data_hash, allowed) = unsafe {
            let head = &*decoded;
            let bytes = |pointer: *const u8, length: u32| {
                if pointer.is_null() { Vec::new() } else { std::slice::from_raw_parts(pointer, length as usize).to_vec() }
            };
            let mut allowed = Vec::new();
            if !head.credential_list.credentials.is_null() {
                for index in 0..head.credential_list.count.min(64) as usize {
                    let credential = *head.credential_list.credentials.add(index);
                    if !credential.is_null() {
                        allowed.push(bytes((*credential).pb_id, (*credential).cb_id));
                    }
                }
            }
            let copied = (bytes(head.pb_rp_id, head.cb_rp_id), bytes(head.pb_client_data_hash, head.cb_client_data_hash), allowed);
            (api.free_decoded_get_assertion)(decoded);
            copied
        };
        let rp_id = String::from_utf8(rp_id_bytes).map_err(|_| E_INVALIDARG)?;
        if client_data_hash.len() != 32 {
            return Err(E_INVALIDARG);
        }

        self.wait_for_unlock()?;
        let candidates: Vec<VaultPasskey> = {
            let app = self.state.lock().map_err(|_| E_FAIL)?;
            let vault = app.unlocked.as_ref().ok_or(NTE_USER_CANCELLED)?;
            let passkeys = vault.passkey_records().map_err(|_| E_FAIL)?;
            matching(&passkeys, &rp_id, &allowed).into_iter().cloned().collect()
        };
        if candidates.is_empty() {
            return Err(NTE_NOT_FOUND);
        }
        // Several accounts for this site and no choice from the site: the user picks one.
        let options: Vec<&VaultPasskey> = candidates.iter().collect();
        let passkey = choose_passkey(request.hwnd, &rp_id, &options)
            .and_then(|index| candidates.get(index).cloned())
            .ok_or(NTE_USER_CANCELLED)?;

        // Windows Hello confirms the person at the PC before anything is signed.
        let (username, hint) = (wide(&passkey.username), wide("Sign in with your Nuvori passkey"));
        let verification = UserVerificationRequest {
            hwnd: request.hwnd,
            transaction_id: &request.transaction_id,
            username: PCWSTR(username.as_ptr()),
            display_hint: PCWSTR(hint.as_ptr()),
        };
        let (mut proof_length, mut proof) = (0u32, std::ptr::null_mut::<u8>());
        let verified = unsafe { (api.perform_user_verification)(&verification, &mut proof_length, &mut proof) };
        if !proof.is_null() {
            unsafe { (api.free_user_verification)(proof) };
        }
        verified.ok().map_err(|error| error.code())?;
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(NTE_USER_CANCELLED);
        }

        let (authenticator_data, der_signature) =
            passkey.sign_platform_assertion(rp_id.as_bytes(), &client_data_hash).map_err(|_| E_FAIL)?;
        let credential_id = URL_SAFE_NO_PAD.decode(&passkey.id).map_err(|_| E_FAIL)?;
        let user_id = URL_SAFE_NO_PAD.decode(&passkey.user_handle).map_err(|_| E_FAIL)?;
        let (user_name, display_name) = (wide(&passkey.username), wide(&passkey.display_name));
        let user = UserEntity {
            version: 1,
            cb_id: user_id.len() as u32,
            pb_id: user_id.as_ptr(),
            name: PCWSTR(user_name.as_ptr()),
            icon: PCWSTR::null(),
            display_name: PCWSTR(display_name.as_ptr()),
        };
        let response = GetAssertionResponse {
            assertion: Assertion {
                version: WEBAUTHN_ASSERTION_VERSION,
                cb_authenticator_data: authenticator_data.len() as u32,
                pb_authenticator_data: authenticator_data.as_ptr(),
                cb_signature: der_signature.len() as u32,
                pb_signature: der_signature.as_ptr(),
                credential: Credential {
                    version: 1,
                    cb_id: credential_id.len() as u32,
                    pb_id: credential_id.as_ptr(),
                    credential_type: w!("public-key"),
                },
                cb_user_id: user_id.len() as u32,
                pb_user_id: user_id.as_ptr(),
                extensions: Extensions { count: 0, extensions: std::ptr::null() },
                cb_cred_large_blob: 0,
                pb_cred_large_blob: std::ptr::null(),
                cred_large_blob_status: 0,
                hmac_secret: std::ptr::null(),
                used_transport: WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
                cb_unsigned_extension_outputs: 0,
                pb_unsigned_extension_outputs: std::ptr::null(),
                cb_client_data_json: 0,
                pb_client_data_json: std::ptr::null(),
                cb_authentication_response_json: 0,
                pb_authentication_response_json: std::ptr::null(),
            },
            user: &user,
            number_of_credentials: 1,
            user_selected: 0,
            cb_large_blob_key: 0,
            pb_large_blob_key: std::ptr::null(),
            cb_unsigned_extension_outputs: 0,
            pb_unsigned_extension_outputs: std::ptr::null(),
        };
        let (mut length, mut buffer) = (0u32, std::ptr::null_mut::<u8>());
        unsafe { (api.encode_get_assertion)(&response, &mut length, &mut buffer) }.ok().map_err(|error| error.code())?;
        // The site name is not a secret; the account name is never logged.
        activity::log(Level::Success, Category::Security, format!("Signed in to {rp_id} with a passkey"));
        Ok((length, buffer))
    }
}

impl Provider {
    fn make_credential(&self, request: &OperationRequest) -> Result<(u32, *mut u8), HRESULT> {
        let api = api().ok_or(NTE_NOT_SUPPORTED)?;
        if request.pb_encoded_request.is_null() || request.cb_encoded_request == 0 {
            return Err(E_INVALIDARG);
        }
        self.cancelled.store(false, Ordering::SeqCst);
        let encoded =
            unsafe { std::slice::from_raw_parts(request.pb_encoded_request, request.cb_encoded_request as usize) };
        let signature = if request.pb_request_signature.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(request.pb_request_signature, request.cb_request_signature as usize) }
        };
        if !self.request_is_from_windows(api, encoded, signature) {
            activity::diagnostic(Category::Security, "Passkey request refused", "the request signature did not verify");
            return Err(NTE_BAD_SIGNATURE);
        }
        let mut decoded = std::ptr::null_mut::<MakeCredentialRequestHead>();
        unsafe { (api.decode_make_credential)(request.cb_encoded_request, request.pb_encoded_request, &mut decoded) }
            .ok()
            .map_err(|error| error.code())?;
        if decoded.is_null() {
            return Err(E_FAIL);
        }
        // Copy what is needed, then free Windows' structure.
        let copied = unsafe {
            let head = &*decoded;
            let bytes = |pointer: *const u8, length: u32| {
                if pointer.is_null() { Vec::new() } else { std::slice::from_raw_parts(pointer, length as usize).to_vec() }
            };
            let es256 = !head.parameters.parameters.is_null()
                && (0..head.parameters.count.min(32) as usize).any(|index| {
                    let parameter = &*head.parameters.parameters.add(index);
                    parameter.alg == COSE_ES256 && read_wide(parameter.credential_type) == "public-key"
                });
            let mut excluded = Vec::new();
            if !head.exclude.credentials.is_null() {
                for index in 0..head.exclude.count.min(64) as usize {
                    let credential = *head.exclude.credentials.add(index);
                    if !credential.is_null() {
                        excluded.push(bytes((*credential).pb_id, (*credential).cb_id));
                    }
                }
            }
            let user = head.user.as_ref();
            let result = (
                bytes(head.pb_rp_id, head.cb_rp_id),
                es256,
                excluded,
                user.map(|user| bytes(user.pb_id, user.cb_id)).unwrap_or_default(),
                user.map(|user| read_wide(user.name)).unwrap_or_default(),
                user.map(|user| read_wide(user.display_name)).unwrap_or_default(),
            );
            (api.free_decoded_make_credential)(decoded);
            result
        };
        let (rp_id_bytes, es256, excluded, user_id, username, display_name) = copied;
        if !es256 {
            return Err(NTE_NOT_SUPPORTED);
        }
        let rp_id = String::from_utf8(rp_id_bytes).map_err(|_| E_INVALIDARG)?;
        let username = if username.trim().is_empty() { display_name.trim().to_owned() } else { username.trim().to_owned() };
        if username.is_empty() || !(1..=64).contains(&user_id.len()) {
            return Err(E_INVALIDARG);
        }

        self.wait_for_unlock()?;
        {
            let app = self.state.lock().map_err(|_| E_FAIL)?;
            let vault = app.unlocked.as_ref().ok_or(NTE_USER_CANCELLED)?;
            let saved = vault.passkey_records().map_err(|_| E_FAIL)?;
            // The site lists passkeys it already has for this account; never make a second one.
            if !excluded.is_empty() && !matching(&saved, &rp_id, &excluded).is_empty() {
                return Err(NTE_EXISTS);
            }
        }

        let (name, hint) = (wide(&username), wide("Save a passkey in Nuvori"));
        let verification = UserVerificationRequest {
            hwnd: request.hwnd,
            transaction_id: &request.transaction_id,
            username: PCWSTR(name.as_ptr()),
            display_hint: PCWSTR(hint.as_ptr()),
        };
        let (mut proof_length, mut proof) = (0u32, std::ptr::null_mut::<u8>());
        let verified = unsafe { (api.perform_user_verification)(&verification, &mut proof_length, &mut proof) };
        if !proof.is_null() {
            unsafe { (api.free_user_verification)(proof) };
        }
        verified.ok().map_err(|error| error.code())?;
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(NTE_USER_CANCELLED);
        }

        let now = activity::now_millis() as i64;
        let (passkey, credential_id, x, y) = new_passkey(&rp_id, &user_id, &username, &display_name, now)?;
        let all = {
            let mut app = self.state.lock().map_err(|_| E_FAIL)?;
            let vault = app.unlocked.as_mut().ok_or(NTE_USER_CANCELLED)?;
            vault.save_passkey(passkey).map_err(|_| E_FAIL)?;
            vault.passkey_records().unwrap_or_default()
        };
        publish_credentials(api, &all);

        let authenticator_data = creation_authenticator_data(rp_id.as_bytes(), &credential_id, &x, &y);
        let attestation = CredentialAttestation {
            version: WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION,
            format_type: w!("none"),
            cb_authenticator_data: authenticator_data.len() as u32,
            pb_authenticator_data: authenticator_data.as_ptr(),
            cb_attestation: 0,
            pb_attestation: std::ptr::null(),
            attestation_decode_type: 0,
            attestation_decode: std::ptr::null(),
            cb_attestation_object: 0,
            pb_attestation_object: std::ptr::null(),
            cb_credential_id: credential_id.len() as u32,
            pb_credential_id: credential_id.as_ptr(),
            extensions: Extensions { count: 0, extensions: std::ptr::null() },
            used_transport: WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
            ep_att: 0,
            large_blob_supported: 0,
            resident_key: 1,
            prf_enabled: 0,
            cb_unsigned_extension_outputs: 0,
            pb_unsigned_extension_outputs: std::ptr::null(),
            hmac_secret: std::ptr::null(),
            third_party_payment: 0,
            transports: WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
            cb_client_data_json: 0,
            pb_client_data_json: std::ptr::null(),
            cb_registration_response_json: 0,
            pb_registration_response_json: std::ptr::null(),
        };
        let (mut length, mut buffer) = (0u32, std::ptr::null_mut::<u8>());
        unsafe { (api.encode_make_credential)(&attestation, &mut length, &mut buffer) }.ok().map_err(|error| error.code())?;
        activity::log(Level::Success, Category::Security, format!("Saved a passkey for {rp_id}. It syncs to your phone"));
        Ok((length, buffer))
    }
}

#[implement(IPluginAuthenticator)]
struct Authenticator(Arc<Provider>);

impl IPluginAuthenticator_Impl for Authenticator_Impl {
    unsafe fn MakeCredential(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT {
        if request.is_null() || response.is_null() {
            return E_INVALIDARG;
        }
        unsafe { *response = OperationResponse { cb_encoded_response: 0, pb_encoded_response: std::ptr::null_mut() } };
        match self.0.make_credential(unsafe { &*request }) {
            Ok((length, buffer)) => {
                unsafe { *response = OperationResponse { cb_encoded_response: length, pb_encoded_response: buffer } };
                S_OK
            }
            Err(error) => {
                if error != NTE_USER_CANCELLED {
                    activity::diagnostic(Category::Security, "Saving a passkey failed", format!("0x{:08x}", error.0 as u32));
                }
                error
            }
        }
    }

    unsafe fn GetAssertion(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT {
        if request.is_null() || response.is_null() {
            return E_INVALIDARG;
        }
        unsafe { *response = OperationResponse { cb_encoded_response: 0, pb_encoded_response: std::ptr::null_mut() } };
        match self.0.get_assertion(unsafe { &*request }) {
            Ok((length, buffer)) => {
                unsafe { *response = OperationResponse { cb_encoded_response: length, pb_encoded_response: buffer } };
                S_OK
            }
            Err(error) => {
                if error != NTE_USER_CANCELLED {
                    activity::diagnostic(Category::Security, "Passkey sign-in failed", format!("0x{:08x}", error.0 as u32));
                }
                error
            }
        }
    }

    unsafe fn CancelOperation(&self, _request: *const CancelRequest) -> HRESULT {
        self.0.cancelled.store(true, Ordering::SeqCst);
        S_OK
    }

    unsafe fn GetLockStatus(&self, status: *mut i32) -> HRESULT {
        if status.is_null() {
            return E_POINTER;
        }
        // PLUGIN_LOCK_STATUS: PluginLocked = 0, PluginUnlocked = 1.
        unsafe { *status = i32::from(self.0.unlocked()) };
        S_OK
    }
}

#[implement(IClassFactory)]
struct Factory(Arc<Provider>);

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<'_, IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> windows::core::Result<()> {
        if object.is_null() || iid.is_null() {
            return Err(E_POINTER.into());
        }
        unsafe { *object = std::ptr::null_mut() };
        if outer.is_some() {
            // CLASS_E_NOAGGREGATION
            return Err(HRESULT(0x8004_0110_u32 as i32).into());
        }
        let authenticator: IPluginAuthenticator = Authenticator(self.0.clone()).into();
        unsafe { authenticator.query(iid, object).ok() }
    }

    fn LockServer(&self, _lock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

/// The plugin's own RP ID, for passkey calls the plugin itself would make. Nuvori makes none,
/// but Windows refuses a registration without one ("The parameter is incorrect"), although the
/// SDK header calls it optional. `.invalid` is reserved, so no one else can ever own this name.
const PLUGIN_RP_ID: PCWSTR = w!("nuvori.invalid");

fn add_options(clsid: &GUID, info: &[u8]) -> AddAuthenticatorOptions {
    AddAuthenticatorOptions {
        name: w!("Nuvori"),
        clsid,
        plugin_rp_id: PLUGIN_RP_ID,
        light_logo_svg: PCWSTR::null(),
        dark_logo_svg: PCWSTR::null(),
        cb_authenticator_info: info.len() as u32,
        pb_authenticator_info: info.as_ptr(),
        supported_rp_id_count: 0,
        supported_rp_ids: std::ptr::null(),
    }
}

/// Registers Nuvori with Windows the first time. The user then turns it on once under
/// Settings > Accounts > Passkeys > Advanced options. False when Windows refused it.
fn register_with_windows(api: &Api) -> bool {
    let mut state = 0i32;
    if unsafe { (api.get_state)(&CLSID, &mut state) }.is_ok() {
        return true;
    }
    let info = authenticator_info();
    let options = add_options(&CLSID, &info);
    let mut response = std::ptr::null_mut::<AddAuthenticatorResponse>();
    let added = unsafe { (api.add_authenticator)(&options, &mut response) };
    if !response.is_null() {
        unsafe { (api.free_add_response)(response) };
    }
    match added.ok() {
        Ok(()) => {
            activity::log(
                Level::Info,
                Category::Security,
                "Nuvori is available as a passkey provider. Turn it on in Windows Settings > Accounts > Passkeys > Advanced options",
            );
            true
        }
        Err(error) => {
            activity::diagnostic(Category::Security, "Could not register the passkey provider", error);
            false
        }
    }
}

/// What Settings shows about the passkey provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderState {
    /// The installer build (MSI or setup EXE) has no package identity, so Windows cannot use it.
    InstallerBuild,
    /// This Windows version has no passkey plugin functions.
    Unsupported,
    /// Windows refused the registration; the activity log has the error.
    NotRegistered,
    /// Registered, but the user has not turned Nuvori on in Windows Settings yet.
    Off,
    On,
}

/// `AUTHENTICATOR_STATE` in `webauthnplugin.h`: Disabled = 0, Enabled = 1.
const AUTHENTICATOR_STATE_ENABLED: i32 = 1;

pub fn provider_state() -> ProviderState {
    if !packaged() {
        return ProviderState::InstallerBuild;
    }
    let Some(api) = api() else { return ProviderState::Unsupported };
    let mut state = 0i32;
    match unsafe { (api.get_state)(&CLSID, &mut state) }.ok() {
        Err(_) => ProviderState::NotRegistered,
        Ok(()) if state == AUTHENTICATOR_STATE_ENABLED => ProviderState::On,
        Ok(()) => ProviderState::Off,
    }
}

/// Tells Windows which passkeys Nuvori holds (site, account name and IDs only, never keys), so
/// they show in the Windows passkey list. Returns the fingerprint of what was published.
fn publish_credentials(api: &Api, passkeys: &[VaultPasskey]) {
    struct Row {
        id: Vec<u8>,
        user: Vec<u8>,
        rp: Vec<u16>,
        name: Vec<u16>,
        display: Vec<u16>,
    }
    let rows: Vec<Row> = passkeys
        .iter()
        .filter_map(|passkey| {
            Some(Row {
                id: URL_SAFE_NO_PAD.decode(&passkey.id).ok()?,
                user: URL_SAFE_NO_PAD.decode(&passkey.user_handle).ok()?,
                rp: wide(&passkey.rp_id),
                name: wide(&passkey.username),
                display: wide(&passkey.display_name),
            })
        })
        .collect();
    let details: Vec<CredentialDetails> = rows
        .iter()
        .map(|row| CredentialDetails {
            cb_credential_id: row.id.len() as u32,
            pb_credential_id: row.id.as_ptr(),
            rp_id: PCWSTR(row.rp.as_ptr()),
            rp_name: PCWSTR(row.rp.as_ptr()),
            cb_user_id: row.user.len() as u32,
            pb_user_id: row.user.as_ptr(),
            user_name: PCWSTR(row.name.as_ptr()),
            user_display_name: PCWSTR(row.display.as_ptr()),
        })
        .collect();
    unsafe {
        let _ = (api.remove_all_credentials)(&CLSID);
        if !details.is_empty() {
            let added = (api.add_credentials)(&CLSID, details.len() as u32, details.as_ptr());
            if let Err(error) = added.ok() {
                activity::diagnostic(Category::Security, "Could not list passkeys in Windows", error);
            }
        }
    }
}

fn fingerprint(passkeys: &[VaultPasskey]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for passkey in passkeys {
        for part in [&passkey.id, &passkey.rp_id, &passkey.user_handle, &passkey.username, &passkey.display_name] {
            digest.update((part.len() as u64).to_le_bytes());
            digest.update(part.as_bytes());
        }
    }
    digest.finalize().into()
}

/// Starts the provider in the packaged build. The class object stays registered for the life
/// of the process, and the Windows passkey list follows the vault while it is unlocked. A locked
/// vault keeps its last list, so a passkey still shows and asks for unlock when used.
pub fn start(state: ManagedState, app: AppHandle) {
    if !packaged() {
        return;
    }
    let Some(api) = api() else {
        activity::diagnostic(Category::Security, "Passkey provider unavailable", "this Windows version has no passkey plugin support");
        return;
    };
    thread::spawn(move || {
        let provider = Arc::new(Provider { state: state.clone(), app, cancelled: AtomicBool::new(false) });
        let registered = unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let factory: IClassFactory = Factory(provider).into();
            CoRegisterClassObject(&CLSID, &factory, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE)
        };
        if let Err(error) = registered {
            activity::diagnostic(Category::Security, "Could not start the passkey provider", error);
            return;
        }
        if !register_with_windows(api) {
            // The COM class stays registered for a request already in flight; nothing is listed.
            return;
        }
        let mut published: Option<[u8; 32]> = None;
        loop {
            let passkeys = state
                .lock()
                .ok()
                .and_then(|app| app.unlocked.as_ref().map(|vault| vault.passkey_records()))
                .and_then(Result::ok);
            if let Some(passkeys) = passkeys {
                let current = fingerprint(&passkeys);
                if published != Some(current) {
                    publish_credentials(api, &passkeys);
                    published = Some(current);
                }
            }
            thread::sleep(Duration::from_secs(10));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passkey(id: &[u8], rp_id: &str, created_at: i64) -> VaultPasskey {
        VaultPasskey {
            id: URL_SAFE_NO_PAD.encode(id),
            rp_id: rp_id.into(),
            user_handle: URL_SAFE_NO_PAD.encode([1, 2, 3]),
            username: "sam".into(),
            display_name: "Sam".into(),
            private_key: String::new(),
            public_key: String::new(),
            created_at,
        }
    }

    #[test]
    fn selection_matches_the_site_and_the_named_credentials() {
        let passkeys = [passkey(&[1], "example.com", 10), passkey(&[2], "example.com", 20), passkey(&[3], "other.example", 30)];
        assert_eq!(matching(&passkeys, "example.com", &[])[0].created_at, 20, "the newest for the site");
        assert_eq!(matching(&passkeys, "example.com", &[vec![1]])[0].created_at, 10);
        assert!(matching(&passkeys, "example.com", &[vec![3]]).is_empty(), "another site's credential never matches");
    }

    #[test]
    fn authenticator_info_is_the_expected_ctap2_map() {
        let info = authenticator_info();
        let expected = [
            "a5", "01", "82", "68", &hex::encode("FIDO_2_0"), "68", &hex::encode("FIDO_2_1"),
            "03", "50", &hex::encode(AAGUID),
            "04", "a3", "62", &hex::encode("rk"), "f5", "62", &hex::encode("up"), "f5", "62", &hex::encode("uv"), "f5",
            "09", "81", "68", &hex::encode("internal"),
            "0a", "81", "a2", "63", &hex::encode("alg"), "26", "64", &hex::encode("type"), "6a", &hex::encode("public-key"),
        ]
        .concat();
        assert_eq!(hex::encode(info), expected);
    }

    #[test]
    fn structure_sizes_match_the_64_bit_sdk_layout() {
        // Sizes computed from the SDK headers for x64 (8-byte pointers, natural alignment).
        assert_eq!(std::mem::size_of::<OperationRequest>(), 56);
        assert_eq!(std::mem::size_of::<OperationResponse>(), 16);
        assert_eq!(std::mem::size_of::<CancelRequest>(), 32);
        assert_eq!(std::mem::size_of::<Credential>(), 24);
        assert_eq!(std::mem::size_of::<Assertion>(), 168);
        assert_eq!(std::mem::size_of::<UserEntity>(), 40);
        assert_eq!(std::mem::size_of::<GetAssertionResponse>(), 216);
        assert_eq!(std::mem::size_of::<CredentialDetails>(), 64);
        assert_eq!(std::mem::size_of::<AddAuthenticatorOptions>(), 72);
    }

    #[test]
    fn a_signature_that_windows_did_not_make_is_refused() {
        assert!(!verify_cng_signature(b"request", &[0; 4], &[1; 64]));
        assert!(!verify_cng_signature(b"request", &[0; 72], &[1; 64]), "a blob that is not a key does not verify");
        assert!(!verify_cng_signature(b"request", &[0; 72], &[]));
    }

    #[test]
    fn several_passkeys_for_a_site_are_offered_newest_first() {
        let passkeys = [passkey(&[1], "example.com", 10), passkey(&[2], "example.com", 20), passkey(&[3], "other.example", 30)];
        let found: Vec<i64> = matching(&passkeys, "example.com", &[]).iter().map(|passkey| passkey.created_at).collect();
        assert_eq!(found, [20, 10]);
        assert_eq!(matching(&passkeys, "example.com", &[vec![1]]).len(), 1, "a credential the site names is used without asking");
        assert!(matching(&passkeys, "login.example.com", &[]).is_empty(), "the RP ID must be equal, not a suffix");
    }

    #[test]
    fn a_new_passkey_has_the_phone_format_and_signs_for_its_site() {
        let (passkey, credential_id, x, y) = new_passkey("example.com", &[7; 16], "sam@example.com", "Sam", 1_000).unwrap();
        passkey.validate().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&passkey.id).unwrap(), credential_id);
        let data = creation_authenticator_data(b"example.com", &credential_id, &x, &y);
        assert_eq!(&data[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(data[32], 0x4d, "the flags the phone uses when it creates a passkey");
        assert_eq!(&data[37..53], &AAGUID);
        assert_eq!(u16::from_be_bytes([data[53], data[54]]) as usize, credential_id.len());
        let cose = &data[55 + credential_id.len()..];
        assert_eq!(cose.len(), 77);
        assert_eq!(&cose[..10], &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        // The saved key signs for the site, and the public key in the COSE map is the same key.
        let hash = Sha256::digest(b"client data");
        let (_, signature) = passkey.sign_platform_assertion(b"example.com", &hash).unwrap();
        assert!(!signature.is_empty());
        let spki = URL_SAFE_NO_PAD.decode(&passkey.public_key).unwrap();
        assert_eq!(&spki[spki.len() - 64..spki.len() - 32], &x);
        assert_eq!(&spki[spki.len() - 32..], &y);
    }

    /// Windows checks the registration data before the caller's package identity. A test process
    /// has no identity, so valid data gets "no package identity" and invalid data gets "The
    /// parameter is incorrect". Nothing is registered either way. Skipped where Windows lacks
    /// the plugin functions.
    #[test]
    fn windows_accepts_the_registration_data() {
        const APPMODEL_ERROR_NO_PACKAGE: u32 = 0x8007_3D54;
        let Some(api) = api() else { return };
        let probe = GUID::from_u128(0x6f2b8f0e_4c3a_4d7b_9a51_2e8d1c7f4b99);
        let info = authenticator_info();
        let options = add_options(&probe, &info);
        let mut response = std::ptr::null_mut::<AddAuthenticatorResponse>();
        let result = unsafe { (api.add_authenticator)(&options, &mut response) };
        if !response.is_null() {
            unsafe { (api.free_add_response)(response) };
        }
        assert_eq!(result.0 as u32, APPMODEL_ERROR_NO_PACKAGE, "0x80090027 means Windows rejected a field");
    }

    #[test]
    fn the_installer_build_reports_that_it_cannot_provide_passkeys() {
        assert_eq!(provider_state(), ProviderState::InstallerBuild, "a test process has no package identity");
        assert_eq!(serde_json::to_string(&ProviderState::NotRegistered).unwrap(), r#""notRegistered""#);
        assert_eq!(serde_json::to_string(&ProviderState::InstallerBuild).unwrap(), r#""installerBuild""#);
    }

    #[test]
    fn the_authenticator_model_id_is_never_zero() {
        assert_ne!(AAGUID, [0; 16], "Windows rejects a plugin registration with a zero AAGUID");
        assert_eq!(AAGUID[6] >> 4, 4, "a version 4 (random) UUID");
    }

    #[test]
    fn creation_structures_match_the_64_bit_sdk_layout() {
        assert_eq!(std::mem::size_of::<RpEntity>(), 32);
        assert_eq!(std::mem::size_of::<CoseParameter>(), 24);
        assert_eq!(std::mem::size_of::<MakeCredentialRequestHead>(), 80);
        assert_eq!(std::mem::size_of::<CredentialAttestation>(), 192);
    }
}
