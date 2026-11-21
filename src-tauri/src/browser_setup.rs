//! Connects the browser extension to Nuvori without manual steps.
//!
//! A browser starts a native messaging host only when HKCU names a host manifest that allows
//! the extension. Which key a browser reads depends on its family (see `browsers.rs`):
//! - Chromium browsers read a manifest that lists extension origins ("allowed_origins"). Two
//!   IDs are trusted: [`STORE_EXTENSION_ID`] (the Chrome Web Store item) and [`EXTENSION_ID`]
//!   (the unpacked extension, whose `manifest.json` carries a public `key`, so its ID is the
//!   same in every folder and on every PC).
//! - Firefox and its forks (Zen, LibreWolf, Waterfox ...) read `HKCU\Software\Mozilla\
//!   NativeMessagingHosts` and a manifest that lists add-on IDs ("allowed_extensions"):
//!   [`FIREFOX_EXTENSION_ID`], in its own file beside the Chromium one.
//!
//! Nuvori detects every installed browser (StartMenuInternet entries and profile folders),
//! then writes the manifests and the keys of the browsers the user kept connected: at start in
//! installed builds, and from Settings > Browser extension.
//!
//! The Store build runs the host through its app execution alias, which Chromium browsers start
//! with CreateProcess. Firefox rejects an alias (a reparse point), so the Store build copies the
//! host to `%LOCALAPPDATA%\Nuvori\BrowserHost` and the Firefox manifest names that copy.
//!
//! Allowed: the two fixed IDs, plus IDs a manifest already allowed (registered earlier by hand).
//! An extension is never trusted because of its name; any unpacked extension can copy a name.
//! A registry value that does not point at Nuvori's manifest is never changed or deleted.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    activity::{self, Category},
    browsers::{self, Browser, Browsers, Family, Key, Resolved, StartMenuEntry},
};

/// SHA-256 of the extension's public key, first 32 hex digits mapped to a-p (Chrome's rule).
pub const EXTENSION_ID: &str = "kapellkbongejlglcengbmjnpblemmjm";
/// Item ID of "Nuvori Password Fill" in the Chrome Web Store. The store signs the item with its
/// own key, so this differs from [`EXTENSION_ID`].
pub const STORE_EXTENSION_ID: &str = "lpohaakdindhljdhpofnfmggbfllgdil";
/// The Firefox add-on's ID (`browser_specific_settings.gecko.id`). Fixed forever by addons.mozilla.org.
pub const FIREFOX_EXTENSION_ID: &str = "password-fill@nuvori.santoshkanumuri.com";
const HOST_NAME: &str = "com.nuvori.desktop";
const HOST_FILE: &str = "nuvori-native-host.exe";
const CHROMIUM_MANIFEST: &str = "com.nuvori.desktop.json";
const FIREFOX_MANIFEST: &str = "com.nuvori.desktop.firefox.json";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectReport {
    /// Browser IDs whose registration points at this Nuvori now.
    pub browsers: Vec<String>,
    /// True when anything was written; the browser must restart to notice.
    pub changed: bool,
}

/// The registry, as far as registration needs it. Tests use an in-memory copy.
pub trait Registry {
    /// The default value of an HKCU native host key, as written (the file may not exist).
    fn value(&self, subkey: &str) -> Option<PathBuf>;
    /// Points an HKCU native host key at `manifest`.
    fn set(&self, subkey: &str, manifest: &Path) -> std::io::Result<()>;
    /// Deletes an HKCU native host key (the `com.nuvori.desktop` key only).
    fn remove(&self, subkey: &str) -> std::io::Result<()>;
    /// The StartMenuInternet entries of HKLM, HKCU and HKLM's 32-bit view.
    fn start_menu(&self) -> Vec<StartMenuEntry>;
}

/// The places registration reads and writes, so tests can use folders of their own.
pub struct Env {
    /// `%LOCALAPPDATA%`.
    pub local: PathBuf,
    /// `%APPDATA%`.
    pub roaming: PathBuf,
    /// The folder of `nuvori.exe` and the host that ships with it.
    pub app_dir: PathBuf,
    /// The Store build.
    pub packaged: bool,
}

impl Env {
    pub fn current() -> Option<Env> {
        Some(Env {
            local: PathBuf::from(std::env::var_os("LOCALAPPDATA")?),
            roaming: PathBuf::from(std::env::var_os("APPDATA")?),
            app_dir: std::env::current_exe().ok()?.parent()?.to_path_buf(),
            packaged: crate::passkey_plugin::packaged(),
        })
    }
}

/// The host program each kind of manifest names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPaths {
    pub chromium: PathBuf,
    pub firefox: PathBuf,
}

/// Installer build: the host next to `nuvori.exe` for both. Store build: Chromium browsers use
/// the app execution alias; Firefox needs a real file, so it gets the copy in `BrowserHost`
/// (an excluded folder, so it is the real folder and not the package's private copy).
pub fn host_paths(packaged: bool, local: &Path, app_dir: &Path) -> HostPaths {
    if packaged {
        HostPaths {
            chromium: local.join(r"Microsoft\WindowsApps").join(HOST_FILE),
            firefox: local.join(r"Nuvori\BrowserHost").join(HOST_FILE),
        }
    } else {
        let host = app_dir.join(HOST_FILE);
        HostPaths { chromium: host.clone(), firefox: host }
    }
}

/// Where a host manifest lives. The registration script uses the same files.
pub fn manifest_file(local: &Path, firefox: bool) -> PathBuf {
    local.join(r"Nuvori\BrowserHost").join(if firefox { FIREFOX_MANIFEST } else { CHROMIUM_MANIFEST })
}

/// A Firefox add-on ID: "name@domain" or a "{GUID}", as addons.mozilla.org accepts them.
pub fn valid_firefox_id(id: &str) -> bool {
    let guid = id.len() == 38 && id.starts_with('{') && id.ends_with('}')
        && id[1..37].bytes().enumerate().all(|(index, byte)| if [8, 13, 18, 23].contains(&index) { byte == b'-' } else { byte.is_ascii_hexdigit() });
    let email = id.len() <= 80 && id.split_once('@').is_some_and(|(name, domain)| {
        let part = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-+".contains(&byte));
        part(name) && part(domain) && domain.contains('.')
    });
    guid || email
}

/// Add-on IDs a Firefox host manifest allows.
pub fn manifest_extensions(text: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|json| json["allowed_extensions"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|id| id.as_str().filter(|id| valid_firefox_id(id)).map(str::to_owned))
        .collect()
}

pub fn firefox_manifest_json(host: &Path, extensions: &BTreeSet<String>) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "name": HOST_NAME,
        "description": "Nuvori browser bridge",
        "path": host,
        "type": "stdio",
        "allowed_extensions": extensions,
    }))
    .expect("manifest serializes")
}

fn valid_origin(origin: &str) -> bool {
    origin
        .strip_prefix("chrome-extension://")
        .and_then(|rest| rest.strip_suffix('/'))
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte)))
}

/// The origins of the two extensions that every registration allows.
pub fn trusted_origins() -> BTreeSet<String> {
    [STORE_EXTENSION_ID, EXTENSION_ID].iter().map(|id| format!("chrome-extension://{id}/")).collect()
}

/// Extension origins a host manifest allows.
pub fn manifest_origins(text: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|json| json["allowed_origins"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|origin| origin.as_str().filter(|origin| valid_origin(origin)).map(str::to_owned))
        .collect()
}

pub fn manifest_json(host: &Path, origins: &BTreeSet<String>) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "name": HOST_NAME,
        "description": "Nuvori browser bridge",
        "path": host,
        "type": "stdio",
        "allowed_origins": origins,
    }))
    .expect("manifest serializes")
}

fn same_file(left: &Path, right: &Path) -> bool {
    left.to_string_lossy().eq_ignore_ascii_case(&right.to_string_lossy())
}

/// True for a value that names one of Nuvori's own manifest files. Only such a value is ever
/// rewritten or deleted.
fn is_ours(value: &Path) -> bool {
    value.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
        name.eq_ignore_ascii_case(CHROMIUM_MANIFEST) || name.eq_ignore_ascii_case(FIREFOX_MANIFEST)
    })
}

fn points_at(value: Option<PathBuf>, manifest: &Path) -> bool {
    value.is_some_and(|value| same_file(&value, manifest))
}

fn digest(path: &Path) -> std::io::Result<[u8; 32]> {
    Ok(Sha256::digest(std::fs::read(path)?).into())
}

/// Copies the package's host to `dest` when `dest` is missing or different (size, then SHA-256).
/// The copy goes to a temporary name and is renamed over `dest`. A `dest` that a running host
/// holds open cannot be replaced; it stays, and the next start tries again. Returns true when
/// `dest` was replaced.
pub fn sync_host_copy(source: &Path, dest: &Path) -> std::io::Result<bool> {
    if let Ok(existing) = std::fs::metadata(dest)
        && existing.len() == std::fs::metadata(source)?.len()
        && digest(source)? == digest(dest)?
    {
        return Ok(false);
    }
    if let Some(directory) = dest.parent() {
        std::fs::create_dir_all(directory)?;
    }
    let staged = dest.with_file_name(format!("{HOST_FILE}.new"));
    std::fs::copy(source, &staged)?;
    match std::fs::rename(&staged, dest) {
        Ok(()) => Ok(true),
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            if dest.is_file() { Ok(false) } else { Err(error) }
        }
    }
}

/// Writes `body` to `manifest` when it differs. True when written.
fn write_manifest(manifest: &Path, body: &str) -> std::io::Result<bool> {
    if std::fs::read_to_string(manifest).ok().as_deref() == Some(body) {
        return Ok(false);
    }
    if let Some(directory) = manifest.parent() {
        std::fs::create_dir_all(directory)?;
    }
    std::fs::write(manifest, body)?;
    Ok(true)
}

/// Brings the registry in line with the browsers the user kept connected:
/// - Every key a connected browser reads points at the right manifest.
/// - A Nuvori key that no connected browser needs is deleted only when a browser that reads
///   it was disconnected, and only when it names Nuvori's manifest. Other Nuvori keys that no
///   detected browser reads (registered by an earlier version) are re-pointed, not deleted.
/// - `firefox_ok` false (the host copy is missing) leaves the Mozilla key alone.
pub fn apply(reg: &dyn Registry, local: &Path, hosts: &HostPaths, firefox_ok: bool, browsers: &[Resolved]) -> std::io::Result<ConnectReport> {
    let (chromium_manifest, firefox_manifest) = (manifest_file(local, false), manifest_file(local, true));
    let manifest_for = |key: Key| if key.is_firefox() { &firefox_manifest } else { &chromium_manifest };
    let needed: BTreeSet<Key> = browsers.iter().filter(|browser| browser.connected).flat_map(|browser| browser.keys.clone()).collect();
    let disabled: BTreeSet<Key> = browsers.iter().filter(|browser| !browser.connected).flat_map(|browser| browser.keys.clone())
        .filter(|key| !needed.contains(key)).collect();

    let (mut set, mut remove) = (Vec::new(), Vec::new());
    let (mut chromium_in_use, mut firefox_in_use) = (false, false);
    for key in Key::ALL {
        if key.is_firefox() && !firefox_ok {
            continue;
        }
        let value = reg.value(key.subkey());
        let ours = value.as_deref().is_some_and(is_ours);
        if needed.contains(&key) || (ours && !disabled.contains(&key)) {
            if key.is_firefox() { firefox_in_use = true } else { chromium_in_use = true }
            if !points_at(value, manifest_for(key)) {
                set.push(key);
            }
        } else if ours && disabled.contains(&key) {
            remove.push(key);
        }
    }

    let mut changed = false;
    if chromium_in_use {
        // Keep origins that an earlier registration allowed by hand.
        let mut origins = trusted_origins();
        for key in Key::ALL.into_iter().filter(|key| !key.is_firefox()) {
            if let Some(text) = reg.value(key.subkey()).and_then(|path| std::fs::read_to_string(path).ok()) {
                origins.extend(manifest_origins(&text));
            }
        }
        changed |= write_manifest(&chromium_manifest, &manifest_json(&hosts.chromium, &origins))?;
    }
    if firefox_in_use {
        let mut extensions: BTreeSet<String> = [FIREFOX_EXTENSION_ID.to_owned()].into();
        if let Some(text) = reg.value(Key::Mozilla.subkey()).and_then(|path| std::fs::read_to_string(path).ok()) {
            extensions.extend(manifest_extensions(&text));
        }
        changed |= write_manifest(&firefox_manifest, &firefox_manifest_json(&hosts.firefox, &extensions))?;
    }
    for key in set {
        reg.set(key.subkey(), manifest_for(key))?;
        changed = true;
    }
    for key in remove {
        reg.remove(key.subkey())?;
        changed = true;
    }

    let browsers = browsers
        .iter()
        .filter(|browser| browser.connected && !browser.keys.is_empty())
        .filter(|browser| browser.keys.iter().all(|key| (firefox_ok || !key.is_firefox()) && points_at(reg.value(key.subkey()), manifest_for(*key))))
        .map(|browser| browser.id.clone())
        .collect();
    Ok(ConnectReport { browsers, changed })
}

/// Detects the browsers on this PC and applies the user's choices.
pub fn connect_with(reg: &dyn Registry, env: &Env, store: &Browsers) -> std::io::Result<ConnectReport> {
    let source = env.app_dir.join(HOST_FILE);
    if !source.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "The browser host is missing. Reinstall Nuvori."));
    }
    let hosts = host_paths(env.packaged, &env.local, &env.app_dir);
    // Never fail the start over the copy: a host that a running browser holds open stays, and
    // the next start tries again.
    let mut firefox_ok = true;
    if env.packaged
        && let Err(error) = sync_host_copy(&source, &hosts.firefox)
    {
        activity::diagnostic(Category::Browser, "Could not copy the browser host for Firefox", error);
        firefox_ok = hosts.firefox.is_file();
    }
    let found = browsers::detect(&reg.start_menu(), &env.local, &env.roaming);
    let resolved = browsers::resolve(&found, &store.entries());
    apply(reg, &env.local, &hosts, firefox_ok, &resolved)
}

/// The browsers for the UI, with whether each one's keys point at Nuvori now.
pub fn list_with(reg: &dyn Registry, env: &Env, store: &Browsers) -> Vec<Browser> {
    let found = browsers::detect(&reg.start_menu(), &env.local, &env.roaming);
    let resolved = browsers::resolve(&found, &store.entries());
    browsers::to_list(&resolved, |key| points_at(reg.value(key.subkey()), &manifest_file(&env.local, key.is_firefox())))
}

/// Changes one browser's choices, applies them at once, and returns the new list. `family`
/// counts only for a browser Nuvori could not classify.
pub fn set_with(
    reg: &dyn Registry,
    env: &Env,
    store: &Browsers,
    id: &str,
    connected: Option<bool>,
    ask_at_start: Option<bool>,
    family: Option<Family>,
) -> std::io::Result<Vec<Browser>> {
    if !list_with(reg, env, store).iter().any(|browser| browser.id == id) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unknown browser"));
    }
    store.update(id, |entry| {
        if let Some(connected) = connected {
            entry.connected = connected;
        }
        if let Some(ask_at_start) = ask_at_start {
            entry.ask_at_start = ask_at_start;
        }
        if let Some(family @ (Family::Chromium | Family::Firefox)) = family {
            entry.family = Some(family);
        }
    });
    connect_with(reg, env, store)?;
    Ok(list_with(reg, env, store))
}

/// The real registry.
pub struct WindowsRegistry;

mod windows_registry {
    use std::path::{Path, PathBuf};

    use windows::{
        Win32::{
            Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
            System::Registry::{
                HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegCloseKey, RegDeleteKeyW,
                RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
            },
        },
        core::{PCWSTR, PWSTR},
    };

    use crate::browsers::StartMenuEntry;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    /// A key's default value as text, or `None` when the key or the value is missing.
    fn read_default(hive: HKEY, subkey: &str) -> Option<String> {
        let key = wide(subkey);
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
        let mut size = 0_u32;
        let status = unsafe { RegGetValueW(hive, PCWSTR(key.as_ptr()), PCWSTR::null(), flags, None, None, Some(&mut size)) };
        if status != ERROR_SUCCESS || !(2..=65_536).contains(&size) {
            return None;
        }
        let mut buffer = vec![0_u16; (size as usize).div_ceil(2)];
        let status = unsafe {
            RegGetValueW(hive, PCWSTR(key.as_ptr()), PCWSTR::null(), flags, None, Some(buffer.as_mut_ptr().cast()), Some(&mut size))
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        let end = buffer.iter().position(|&unit| unit == 0).unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..end]))
    }

    fn subkeys(hive: HKEY, path: &str) -> Vec<String> {
        let key = wide(path);
        let mut opened = HKEY::default();
        if unsafe { RegOpenKeyExW(hive, PCWSTR(key.as_ptr()), None, KEY_READ, &mut opened) } != ERROR_SUCCESS {
            return Vec::new();
        }
        let mut names = Vec::new();
        for index in 0..512 {
            let mut name = [0_u16; 256];
            let mut length = name.len() as u32;
            let status = unsafe { RegEnumKeyExW(opened, index, Some(PWSTR(name.as_mut_ptr())), &mut length, None, None, None, None) };
            if status != ERROR_SUCCESS {
                break;
            }
            names.push(String::from_utf16_lossy(&name[..length as usize]));
        }
        unsafe {
            let _ = RegCloseKey(opened);
        }
        names
    }

    pub fn value(subkey: &str) -> Option<PathBuf> {
        let text = read_default(HKEY_CURRENT_USER, subkey)?;
        let path = PathBuf::from(text.trim().trim_matches('"'));
        (!path.as_os_str().is_empty()).then_some(path)
    }

    pub fn set(subkey: &str, manifest: &Path) -> std::io::Result<()> {
        crate::browser_ipc::set_native_host_manifest(subkey, manifest)
    }

    pub fn remove(subkey: &str) -> std::io::Result<()> {
        let key = wide(subkey);
        let status = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(key.as_ptr())) };
        if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(status.0 as i32))
        }
    }

    pub fn start_menu() -> Vec<StartMenuEntry> {
        const PATH: &str = r"SOFTWARE\Clients\StartMenuInternet";
        const WOW: &str = r"SOFTWARE\WOW6432Node\Clients\StartMenuInternet";
        let mut entries = Vec::new();
        for (hive, path) in [(HKEY_LOCAL_MACHINE, PATH), (HKEY_CURRENT_USER, PATH), (HKEY_LOCAL_MACHINE, WOW)] {
            for name in subkeys(hive, path) {
                let key = format!(r"{path}\{name}");
                let Some(command) = read_default(hive, &format!(r"{key}\shell\open\command")) else { continue };
                let display = read_default(hive, &key).unwrap_or_default();
                entries.push(StartMenuEntry { name: display, command });
            }
        }
        entries
    }
}

impl Registry for WindowsRegistry {
    fn value(&self, subkey: &str) -> Option<PathBuf> {
        windows_registry::value(subkey)
    }
    fn set(&self, subkey: &str, manifest: &Path) -> std::io::Result<()> {
        windows_registry::set(subkey, manifest)
    }
    fn remove(&self, subkey: &str) -> std::io::Result<()> {
        windows_registry::remove(subkey)
    }
    fn start_menu(&self) -> Vec<StartMenuEntry> {
        windows_registry::start_menu()
    }
}

fn no_environment() -> std::io::Error {
    std::io::Error::other("LOCALAPPDATA or APPDATA is not set")
}

/// The saved choices, or the defaults when the app did not install them (it always does).
fn settings() -> &'static Browsers {
    static FALLBACK: std::sync::OnceLock<Browsers> = std::sync::OnceLock::new();
    browsers::installed().unwrap_or_else(|| FALLBACK.get_or_init(|| Browsers::new(&std::env::temp_dir().join("nuvori-no-browser-settings"))))
}

/// Registers this copy's browser host for every connected browser. Returns which browsers
/// point at it now.
pub fn connect() -> std::io::Result<ConnectReport> {
    connect_with(&WindowsRegistry, &Env::current().ok_or_else(no_environment)?, settings())
}

/// Settings > Browser extension: the detected browsers.
pub fn list() -> std::io::Result<Vec<Browser>> {
    Ok(list_with(&WindowsRegistry, &Env::current().ok_or_else(no_environment)?, settings()))
}

/// Settings > Browser extension: change one browser's choices.
pub fn set(id: &str, connected: Option<bool>, ask_at_start: Option<bool>, family: Option<Family>) -> std::io::Result<Vec<Browser>> {
    set_with(&WindowsRegistry, &Env::current().ok_or_else(no_environment)?, settings(), id, connected, ask_at_start, family)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    use std::{cell::RefCell, collections::BTreeMap};

    #[test]
    fn the_fixed_id_comes_from_the_extensions_public_key() {
        let manifest: serde_json::Value = serde_json::from_str(include_str!("../../extension/manifest.json")).unwrap();
        let key = STANDARD.decode(manifest["key"].as_str().expect("manifest.json has a key")).unwrap();
        let id: String = hex::encode(Sha256::digest(key))[..32]
            .chars()
            .map(|digit| (b'a' + digit.to_digit(16).unwrap() as u8) as char)
            .collect();
        assert_eq!(id, EXTENSION_ID);
    }

    #[test]
    fn manifests_keep_registered_ids_and_drop_anything_else() {
        let text = r#"{"allowed_origins":["chrome-extension://hmmalanefcgmkidfjjkiajaadknkpdob/","https://evil.example/",
            "chrome-extension://short/","chrome-extension://ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP/"]}"#;
        assert_eq!(manifest_origins(text), ["chrome-extension://hmmalanefcgmkidfjjkiajaadknkpdob/"]);
        assert!(manifest_origins("not json").is_empty());
        let origins = trusted_origins();
        let json: serde_json::Value = serde_json::from_str(&manifest_json(Path::new(r"C:\Program Files\Nuvori\nuvori-native-host.exe"), &origins)).unwrap();
        assert_eq!(json["name"], "com.nuvori.desktop");
        assert_eq!(json["type"], "stdio");
        assert_eq!(json["path"], r"C:\Program Files\Nuvori\nuvori-native-host.exe");
        assert_eq!(json["allowed_origins"], serde_json::json!([
            "chrome-extension://kapellkbongejlglcengbmjnpblemmjm/",
            "chrome-extension://lpohaakdindhljdhpofnfmggbfllgdil/",
        ]));
    }

    #[test]
    fn firefox_manifests_list_add_on_ids_and_drop_anything_else() {
        assert!(valid_firefox_id(FIREFOX_EXTENSION_ID));
        assert!(valid_firefox_id("{3f1c2a4b-1111-4a2b-9c3d-0123456789ab}"));
        for bad in ["", "no-at-sign", "a@b", "@example.com", "x@exa mple.com", "{not-a-guid}", "chrome-extension://kapellkbongejlglcengbmjnpblemmjm/"] {
            assert!(!valid_firefox_id(bad), "{bad}");
        }
        let text = r#"{"allowed_extensions":["password-fill@nuvori.santoshkanumuri.com","https://evil.example/","x@b"]}"#;
        assert_eq!(manifest_extensions(text), ["password-fill@nuvori.santoshkanumuri.com"]);
        let ids: BTreeSet<String> = [FIREFOX_EXTENSION_ID.to_owned()].into();
        let json: serde_json::Value = serde_json::from_str(&firefox_manifest_json(Path::new(r"C:\Program Files\Nuvori\nuvori-native-host.exe"), &ids)).unwrap();
        assert_eq!(json["name"], "com.nuvori.desktop");
        assert_eq!(json["allowed_extensions"], serde_json::json!(["password-fill@nuvori.santoshkanumuri.com"]));
        assert!(json.get("allowed_origins").is_none(), "Firefox manifests name add-on IDs only");
    }

    #[test]
    fn the_firefox_id_matches_the_firefox_package() {
        let script = include_str!("../../scripts/package-extension.ps1");
        assert!(script.contains(FIREFOX_EXTENSION_ID), "scripts/package-extension.ps1 must build the Firefox package with this ID");
    }

    /// The Store package leaves only these locations unvirtualized on Windows 11. A path that the
    /// code writes but the manifest misses goes to the package's private copy, where the browsers
    /// never see it.
    #[test]
    fn the_store_package_unvirtualizes_exactly_the_paths_the_code_writes() {
        let script = include_str!("../../scripts/package-msix.ps1");
        let listed = |tag: &str| -> Vec<String> {
            let (open, close) = (format!("<virtualization:{tag}>"), format!("</virtualization:{tag}>"));
            script.split(open.as_str()).skip(1).filter_map(|rest| rest.split_once(close.as_str())).map(|(value, _)| value.to_owned()).collect()
        };
        let mut keys: Vec<String> = Key::ALL.iter().map(|key| format!(r"HKEY_CURRENT_USER\{}", key.subkey())).collect();
        assert_eq!(keys.len(), 5, "Chrome, Edge, Brave, Chromium and Mozilla");
        let mut manifest_keys = listed("ExcludedKey");
        keys.sort();
        manifest_keys.sort();
        assert_eq!(manifest_keys, keys);

        let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is set"));
        let host_folder = |path: PathBuf| path.strip_prefix(&local).unwrap().parent().unwrap().to_string_lossy().into_owned();
        assert_eq!(host_folder(manifest_file(&local, false)), r"Nuvori\BrowserHost");
        assert_eq!(host_folder(manifest_file(&local, true)), r"Nuvori\BrowserHost");
        // The Firefox host copy sits in the same excluded folder, so it is a real file.
        assert_eq!(host_folder(host_paths(true, &local, Path::new("app")).firefox), r"Nuvori\BrowserHost");
        assert_eq!(listed("ExcludedDirectory"), [
            r"`$(KnownFolder:RoamingAppData)\com.nuvori.desktop",
            r"`$(KnownFolder:LocalAppData)\Nuvori\BrowserHost",
        ]);
        let tauri: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(tauri["identifier"], "com.nuvori.desktop", "the vault folder under %APPDATA% is the Tauri identifier");
    }

    #[test]
    fn the_store_and_unpacked_extensions_are_both_trusted() {
        let origins = trusted_origins();
        assert_eq!(origins.len(), 2);
        // Both pass the same check as an origin read back from a registered manifest.
        assert!(origins.iter().all(|origin| valid_origin(origin)));
        assert!(origins.contains("chrome-extension://lpohaakdindhljdhpofnfmggbfllgdil/"));
        assert!(origins.contains(&format!("chrome-extension://{EXTENSION_ID}/")));
    }

    /// An in-memory registry: tests never touch the real one.
    #[derive(Default)]
    struct MemoryRegistry {
        values: RefCell<BTreeMap<String, PathBuf>>,
        start_menu: Vec<StartMenuEntry>,
    }

    impl Registry for MemoryRegistry {
        fn value(&self, subkey: &str) -> Option<PathBuf> {
            self.values.borrow().get(subkey).cloned()
        }
        fn set(&self, subkey: &str, manifest: &Path) -> std::io::Result<()> {
            self.values.borrow_mut().insert(subkey.to_owned(), manifest.to_path_buf());
            Ok(())
        }
        fn remove(&self, subkey: &str) -> std::io::Result<()> {
            self.values.borrow_mut().remove(subkey);
            Ok(())
        }
        fn start_menu(&self) -> Vec<StartMenuEntry> {
            self.start_menu.clone()
        }
    }

    fn menu(entries: &[(&str, &str)]) -> Vec<StartMenuEntry> {
        entries.iter().map(|(name, command)| StartMenuEntry { name: (*name).into(), command: (*command).into() }).collect()
    }

    /// Folders of one test, with a stub host in the "app" folder.
    fn sandbox(packaged: bool) -> (PathBuf, Env) {
        let root = std::env::temp_dir().join(format!("nuvori-setup-{}", uuid::Uuid::new_v4()));
        let app_dir = root.join("app");
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::write(app_dir.join(HOST_FILE), b"host build 1").unwrap();
        let env = Env { local: root.join("local"), roaming: root.join("roaming"), app_dir, packaged };
        (root, env)
    }

    fn manifest_path_of(env: &Env, firefox: bool) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(manifest_file(&env.local, firefox)).unwrap()).unwrap()
    }

    #[test]
    fn the_store_build_points_firefox_at_a_real_copy_and_chromium_at_the_alias() {
        let (root, env) = sandbox(true);
        let reg = MemoryRegistry { start_menu: menu(&[("Zen", r#""C:\Zen\zen.exe""#), ("Google Chrome", r#""C:\Chrome\chrome.exe""#)]), ..Default::default() };
        let report = connect_with(&reg, &env, &Browsers::in_memory()).unwrap();
        assert!(report.changed);
        assert_eq!(report.browsers.len(), 2);
        let copy = env.local.join(r"Nuvori\BrowserHost").join(HOST_FILE);
        assert_eq!(manifest_path_of(&env, true)["path"], copy.to_string_lossy().as_ref());
        assert_eq!(std::fs::read(&copy).unwrap(), b"host build 1", "the Firefox host is a real file");
        let alias = env.local.join(r"Microsoft\WindowsApps").join(HOST_FILE);
        assert_eq!(manifest_path_of(&env, false)["path"], alias.to_string_lossy().as_ref());
        assert_eq!(reg.value(Key::Mozilla.subkey()).unwrap(), manifest_file(&env.local, true));
        assert_eq!(reg.value(Key::Chrome.subkey()).unwrap(), manifest_file(&env.local, false));
        // A second run changes nothing, and a new host build replaces the copy.
        assert!(!connect_with(&reg, &env, &Browsers::in_memory()).unwrap().changed);
        std::fs::write(env.app_dir.join(HOST_FILE), b"host build 2, longer").unwrap();
        connect_with(&reg, &env, &Browsers::in_memory()).unwrap();
        assert_eq!(std::fs::read(&copy).unwrap(), b"host build 2, longer");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_installer_build_uses_the_host_beside_nuvori_for_every_browser() {
        let (root, env) = sandbox(false);
        let reg = MemoryRegistry { start_menu: menu(&[("Zen", r#""C:\Zen\zen.exe""#), ("Vivaldi", r#""C:\V\vivaldi.exe""#)]), ..Default::default() };
        connect_with(&reg, &env, &Browsers::in_memory()).unwrap();
        let host = env.app_dir.join(HOST_FILE);
        assert_eq!(manifest_path_of(&env, true)["path"], host.to_string_lossy().as_ref());
        assert_eq!(manifest_path_of(&env, false)["path"], host.to_string_lossy().as_ref());
        assert!(!env.local.join(r"Nuvori\BrowserHost").join(HOST_FILE).exists(), "no copy is made");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_chromium_fork_writes_chromes_key_and_the_chromium_key() {
        let (root, env) = sandbox(false);
        let reg = MemoryRegistry { start_menu: menu(&[("Vivaldi", r#""C:\V\vivaldi.exe""#), ("Microsoft Edge", r#""C:\E\msedge.exe""#)]), ..Default::default() };
        let report = connect_with(&reg, &env, &Browsers::in_memory()).unwrap();
        let chromium = manifest_file(&env.local, false);
        for key in [Key::Chrome, Key::Chromium, Key::Edge] {
            assert_eq!(reg.value(key.subkey()).as_deref(), Some(chromium.as_path()), "{key:?}");
        }
        assert_eq!(reg.value(Key::Brave.subkey()), None);
        assert_eq!(reg.value(Key::Mozilla.subkey()), None);
        assert_eq!(report.browsers, ["msedge", "vivaldi"]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn disconnecting_removes_only_keys_that_name_nuvoris_manifest_and_no_connected_browser_needs() {
        let (root, env) = sandbox(false);
        let reg = MemoryRegistry { start_menu: menu(&[("Vivaldi", r#""C:\V\vivaldi.exe""#), ("Zen", r#""C:\Z\zen.exe""#), ("Brave", r#""C:\B\brave.exe""#)]), ..Default::default() };
        let store = Browsers::in_memory();
        connect_with(&reg, &env, &store).unwrap();
        // Someone else's value under the Brave key must survive Brave being disconnected.
        reg.set(Key::Brave.subkey(), Path::new(r"C:\Other\their-manifest.json")).unwrap();
        store.update("brave", |entry| entry.connected = false);
        store.update("vivaldi", |entry| entry.connected = false);
        store.update("zen", |entry| entry.connected = false);
        let report = connect_with(&reg, &env, &store).unwrap();
        assert!(report.browsers.is_empty());
        assert_eq!(reg.value(Key::Brave.subkey()).as_deref(), Some(Path::new(r"C:\Other\their-manifest.json")), "not Nuvori's value");
        assert_eq!(reg.value(Key::Chrome.subkey()), None);
        assert_eq!(reg.value(Key::Chromium.subkey()), None);
        assert_eq!(reg.value(Key::Mozilla.subkey()), None);
        // Another browser that still needs Chrome's key keeps it.
        let reg_chrome = MemoryRegistry { start_menu: menu(&[("Google Chrome", r#""C:\C\chrome.exe""#), ("Vivaldi", r#""C:\V\vivaldi.exe""#)]), ..Default::default() };
        let store = Browsers::in_memory();
        connect_with(&reg_chrome, &env, &store).unwrap();
        store.update("vivaldi", |entry| entry.connected = false);
        connect_with(&reg_chrome, &env, &store).unwrap();
        assert!(reg_chrome.value(Key::Chrome.subkey()).is_some(), "Chrome still needs its key");
        assert_eq!(reg_chrome.value(Key::Chromium.subkey()), None, "only Vivaldi read the Chromium key");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_old_nuvori_key_without_a_detected_browser_is_repointed_not_deleted() {
        let (root, env) = sandbox(false);
        let reg = MemoryRegistry::default();
        reg.set(Key::Brave.subkey(), Path::new(r"C:\Old Nuvori\com.nuvori.desktop.json")).unwrap();
        connect_with(&reg, &env, &Browsers::in_memory()).unwrap();
        assert_eq!(reg.value(Key::Brave.subkey()).as_deref(), Some(manifest_file(&env.local, false).as_path()));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn set_browser_applies_at_once_and_unknown_browsers_need_a_family() {
        let (root, env) = sandbox(false);
        let reg = MemoryRegistry { start_menu: menu(&[("Thorium Nightly", r#""C:\T\nightly.exe""#), ("Zen", r#""C:\Z\zen.exe""#)]), ..Default::default() };
        let store = Browsers::in_memory();
        let list = list_with(&reg, &env, &store);
        assert_eq!(list.iter().map(|browser| (browser.id.as_str(), browser.connected, browser.registered)).collect::<Vec<_>>(),
            [("nightly", false, false), ("zen", true, false)], "nothing is registered before a connect");
        let list = set_with(&reg, &env, &store, "nightly", None, None, Some(Family::Chromium)).unwrap();
        assert!(list[0].connected && list[0].registered && list[0].family == Family::Chromium);
        assert!(reg.value(Key::Chromium.subkey()).is_some());
        let list = set_with(&reg, &env, &store, "zen", Some(false), Some(false), Some(Family::Chromium)).unwrap();
        let zen = list.iter().find(|browser| browser.id == "zen").unwrap();
        assert_eq!((zen.connected, zen.ask_at_start, zen.family, zen.registered), (false, false, Family::Firefox, false));
        assert_eq!(reg.value(Key::Mozilla.subkey()), None);
        assert!(set_with(&reg, &env, &store, "not-installed", Some(true), None, None).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_host_copy_is_replaced_only_when_it_differs() {
        let root = std::env::temp_dir().join(format!("nuvori-copy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let (source, dest) = (root.join("source.exe"), root.join("sub").join(HOST_FILE));
        std::fs::write(&source, b"one").unwrap();
        assert!(sync_host_copy(&source, &dest).unwrap(), "missing: copied");
        assert!(!sync_host_copy(&source, &dest).unwrap(), "same: kept");
        std::fs::write(&source, b"two").unwrap();
        assert!(sync_host_copy(&source, &dest).unwrap(), "same size, other bytes: replaced");
        assert_eq!(std::fs::read(&dest).unwrap(), b"two");
        assert!(!dest.with_file_name(format!("{HOST_FILE}.new")).exists(), "no temporary file is left");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
