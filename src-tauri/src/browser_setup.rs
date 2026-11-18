//! Connects the browser extension to Nuvori without manual steps.
//!
//! Chrome, Brave and Edge start a native messaging host only when HKCU names a host manifest
//! that allows the extension's ID. Two IDs are trusted:
//! - [`STORE_EXTENSION_ID`]: the Chrome Web Store item (Chrome, Brave, and Edge with
//!   extensions from other stores allowed).
//! - [`EXTENSION_ID`]: the unpacked extension. Its `manifest.json` carries a public `key`, so
//!   its ID is the same in every folder and on every PC.
//!
//! Nuvori writes the manifest and the registry keys itself: at start in installed builds, and
//! from Settings > Browser extension > Connect browsers.
//!
//! Firefox reads `HKCU\Software\Mozilla\NativeMessagingHosts` and a manifest that lists add-on
//! IDs ("allowed_extensions"): [`FIREFOX_EXTENSION_ID`], in its own file beside the Chrome one.
//!
//! Allowed: the two fixed IDs, plus IDs a manifest already allowed (registered earlier by hand).
//! An extension is never trusted because of its name; any unpacked extension can copy a name.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::browser_ipc::NATIVE_HOST_KEYS;

/// SHA-256 of the extension's public key, first 32 hex digits mapped to a-p (Chrome's rule).
pub const EXTENSION_ID: &str = "kapellkbongejlglcengbmjnpblemmjm";
/// Item ID of "Nuvori Password Fill" in the Chrome Web Store. The store signs the item with its
/// own key, so this differs from [`EXTENSION_ID`].
pub const STORE_EXTENSION_ID: &str = "lpohaakdindhljdhpofnfmggbfllgdil";
/// The Firefox add-on's ID (`browser_specific_settings.gecko.id`). Fixed forever by addons.mozilla.org.
pub const FIREFOX_EXTENSION_ID: &str = "password-fill@nuvori.santoshkanumuri.com";
const HOST_NAME: &str = "com.nuvori.desktop";

/// Browser name, its native host key, and its user data folder under %LOCALAPPDATA%.
const BROWSERS: [(&str, &str); 3] = [
    ("chrome", r"Google\Chrome\User Data"),
    ("brave", r"BraveSoftware\Brave-Browser\User Data"),
    ("edge", r"Microsoft\Edge\User Data"),
];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectReport {
    /// Browsers whose registration points at this Nuvori now.
    pub browsers: Vec<String>,
    /// True when anything was written; the browser must restart to notice.
    pub changed: bool,
}

/// The browser host this copy of Nuvori ships: next to `nuvori.exe`, or for the Store build
/// the package's app execution alias, which a browser can start.
pub fn host_executable() -> Option<PathBuf> {
    if crate::passkey_plugin::packaged() {
        let local = std::env::var_os("LOCALAPPDATA")?;
        return Some(PathBuf::from(local).join(r"Microsoft\WindowsApps\nuvori-native-host.exe"));
    }
    let host = std::env::current_exe().ok()?.parent()?.join("nuvori-native-host.exe");
    host.is_file().then_some(host)
}

/// Where the host manifest lives. The registration script uses the same file.
fn manifest_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join(r"Nuvori\BrowserHost\com.nuvori.desktop.json"))
}

/// Firefox's host manifest: same host, but it names add-on IDs instead of extension origins.
pub fn firefox_manifest_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join(r"Nuvori\BrowserHost\com.nuvori.desktop.firefox.json"))
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

/// Firefox keeps its profiles under %APPDATA%\Mozilla\Firefox.
fn firefox_installed() -> bool {
    std::env::var_os("APPDATA").is_some_and(|roaming| PathBuf::from(roaming).join(r"Mozilla\Firefox").is_dir())
}

/// Writes the Firefox manifest and its registry key when Firefox is installed or was registered.
fn connect_firefox(host: &Path) -> std::io::Result<Option<bool>> {
    use crate::browser_ipc::FIREFOX_HOST_KEY;
    let registered = crate::browser_ipc::native_host_manifest(FIREFOX_HOST_KEY);
    if registered.is_none() && !firefox_installed() {
        return Ok(None);
    }
    let manifest = firefox_manifest_path().ok_or_else(|| std::io::Error::other("LOCALAPPDATA is not set"))?;
    let mut extensions: BTreeSet<String> = [FIREFOX_EXTENSION_ID.to_owned()].into();
    if let Some(text) = registered.as_ref().and_then(|path| std::fs::read_to_string(path).ok()) {
        extensions.extend(manifest_extensions(&text));
    }
    let body = firefox_manifest_json(host, &extensions);
    let mut changed = false;
    if std::fs::read_to_string(&manifest).ok().as_deref() != Some(body.as_str()) {
        if let Some(directory) = manifest.parent() {
            std::fs::create_dir_all(directory)?;
        }
        std::fs::write(&manifest, &body)?;
        changed = true;
    }
    if !registered.is_some_and(|path| same_file(&path, &manifest)) {
        crate::browser_ipc::set_native_host_manifest(FIREFOX_HOST_KEY, &manifest)?;
        changed = true;
    }
    Ok(Some(changed))
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

/// Registers this copy's browser host for every installed browser and every browser that was
/// registered before. Returns which browsers point at it now.
pub fn connect() -> std::io::Result<ConnectReport> {
    let host = host_executable().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound,
        "The browser host is missing. Reinstall Nuvori."))?;
    let manifest = manifest_path().ok_or_else(|| std::io::Error::other("LOCALAPPDATA is not set"))?;
    let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default());

    let mut origins = trusted_origins();
    let mut keys = Vec::new();
    for (browser, folder) in BROWSERS {
        let key = NATIVE_HOST_KEYS.iter().find(|(name, _)| *name == browser).map(|(_, key)| *key).expect("known browser");
        let registered = crate::browser_ipc::native_host_manifest(key);
        if let Some(text) = registered.as_ref().and_then(|path| std::fs::read_to_string(path).ok()) {
            origins.extend(manifest_origins(&text));
        }
        if registered.is_some() || local.join(folder).is_dir() {
            keys.push((browser, key, registered));
        }
    }

    let body = manifest_json(&host, &origins);
    let mut changed = false;
    if std::fs::read_to_string(&manifest).ok().as_deref() != Some(body.as_str()) {
        if let Some(directory) = manifest.parent() {
            std::fs::create_dir_all(directory)?;
        }
        std::fs::write(&manifest, &body)?;
        changed = true;
    }
    let mut browsers = Vec::new();
    for (browser, key, registered) in keys {
        if !registered.is_some_and(|path| same_file(&path, &manifest)) {
            crate::browser_ipc::set_native_host_manifest(key, &manifest)?;
            changed = true;
        }
        browsers.push(browser.to_owned());
    }
    if let Some(firefox_changed) = connect_firefox(&host)? {
        changed |= firefox_changed;
        browsers.push("firefox".to_owned());
    }
    Ok(ConnectReport { browsers, changed })
}

fn same_file(left: &Path, right: &Path) -> bool {
    left.to_string_lossy().eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};

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

    #[test]
    fn the_store_and_unpacked_extensions_are_both_trusted() {
        let origins = trusted_origins();
        assert_eq!(origins.len(), 2);
        // Both pass the same check as an origin read back from a registered manifest.
        assert!(origins.iter().all(|origin| valid_origin(origin)));
        assert!(origins.contains("chrome-extension://lpohaakdindhljdhpofnfmggbfllgdil/"));
        assert!(origins.contains(&format!("chrome-extension://{EXTENSION_ID}/")));
    }
}
