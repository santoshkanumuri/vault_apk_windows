//! Which browsers are on this PC, which of them are connected to Nuvori, and the per-browser
//! choices (connected, ask for the password when the browser starts, last use).
//!
//! The registration itself lives in `browser_setup.rs`. This file holds the parts that need no
//! registry: classifying a browser by its program name, reading a StartMenuInternet command,
//! merging what was detected with what the user chose, and the `browsers.json` settings file
//! next to the vault (same pattern as `auto-type.json`).
//!
//! A browser family decides which native host keys it reads:
//! - Firefox and its forks read `HKCU\Software\Mozilla\NativeMessagingHosts`.
//! - Chrome, Edge and Brave read their own key.
//! - Other Chromium forks (Vivaldi, Opera ...) read Chrome's key or `Software\Chromium`, so
//!   Nuvori writes both.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use serde::{Deserialize, Serialize};

use crate::{
    activity::{self, Category},
    browser_ipc::NATIVE_HOST_KEYS,
};

const SETTINGS_FILE: &str = "browsers.json";
/// A browser's last use is written to the file at most this often.
const SEEN_WRITE_INTERVAL_MS: i64 = 60_000;
/// Entries kept in the file, so a program that starts the host cannot grow it without limit.
const MAX_ENTRIES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Chromium,
    Firefox,
    Unknown,
}

impl Family {
    fn parse(text: &str) -> Option<Family> {
        match text {
            "chromium" => Some(Family::Chromium),
            "firefox" => Some(Family::Firefox),
            _ => None,
        }
    }

    fn name(self) -> Option<&'static str> {
        match self {
            Family::Chromium => Some("chromium"),
            Family::Firefox => Some("firefox"),
            Family::Unknown => None,
        }
    }
}

/// One native host registry key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    Mozilla,
    Chrome,
    Edge,
    Brave,
    Chromium,
}

impl Key {
    pub const ALL: [Key; 5] = [Key::Mozilla, Key::Chrome, Key::Edge, Key::Brave, Key::Chromium];

    /// The key under HKCU, ending in the host name.
    pub fn subkey(self) -> &'static str {
        let name = match self {
            Key::Mozilla => return crate::browser_ipc::FIREFOX_HOST_KEY,
            Key::Chrome => "chrome",
            Key::Edge => "edge",
            Key::Brave => "brave",
            Key::Chromium => "chromium",
        };
        NATIVE_HOST_KEYS.iter().find(|(browser, _)| *browser == name).map(|(_, key)| *key).expect("known key")
    }

    /// Firefox reads its own manifest (add-on IDs); every other key reads the Chromium one.
    pub fn is_firefox(self) -> bool {
        self == Key::Mozilla
    }
}

/// The keys a browser of `family` reads when its exact browser is not known.
pub fn family_keys(family: Family) -> Vec<Key> {
    match family {
        Family::Chromium => vec![Key::Chrome, Key::Chromium],
        Family::Firefox => vec![Key::Mozilla],
        Family::Unknown => Vec::new(),
    }
}

/// What the program name says about a browser. `None`: not a browser Nuvori supports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    pub family: Family,
    pub keys: Vec<Key>,
}

/// Classifies by the exe file name (any case) and, for Tor Browser, the display name.
pub fn classify(exe: &str, display_name: &str) -> Option<Class> {
    let exe = exe.rsplit(['\\', '/']).next().unwrap_or(exe).to_ascii_lowercase();
    let chromium = |keys: &[Key]| Some(Class { family: Family::Chromium, keys: keys.to_vec() });
    let fork = [Key::Chrome, Key::Chromium];
    match exe.as_str() {
        // Pale Moon's engine is too old for the add-on; Internet Explorer is not a browser to connect.
        "palemoon.exe" | "iexplore.exe" => None,
        "firefox.exe" | "zen.exe" | "librewolf.exe" | "waterfox.exe" | "floorp.exe" | "tor.exe" | "mullvadbrowser.exe" => {
            Some(Class { family: Family::Firefox, keys: vec![Key::Mozilla] })
        }
        // Forks that keep Chromium's "chrome.exe" (Helium, ungoogled-chromium, Supermium) read
        // SOFTWARE\Chromium\NativeMessagingHosts as well, so only Google Chrome itself gets one key.
        "chrome.exe" if is_google_chrome(display_name) => chromium(&[Key::Chrome]),
        "chrome.exe" => chromium(&fork),
        "msedge.exe" => chromium(&[Key::Edge]),
        "brave.exe" => chromium(&[Key::Brave]),
        "vivaldi.exe" | "opera.exe" | "launcher.exe" | "thorium.exe" | "arc.exe" | "browser.exe" | "chromium.exe" | "comet.exe" => {
            chromium(&fork)
        }
        _ if display_name.to_ascii_lowercase().contains("tor browser") => Some(Class { family: Family::Firefox, keys: vec![Key::Mozilla] }),
        _ => Some(Class { family: Family::Unknown, keys: Vec::new() }),
    }
}

/// True for Google Chrome's own Start menu name ("Google Chrome", "Google Chrome Beta" ...), or no name.
fn is_google_chrome(display_name: &str) -> bool {
    let name = display_name.trim().to_ascii_lowercase();
    name.is_empty() || name.starts_with("google chrome")
}

/// A name for a browser the registry gave none for.
fn known_name(id: &str) -> String {
    match id {
        "chrome" => "Google Chrome",
        "msedge" => "Microsoft Edge",
        "brave" => "Brave",
        "firefox" => "Firefox",
        "vivaldi" => "Vivaldi",
        "opera" => "Opera",
        "zen" => "Zen Browser",
        "librewolf" => "LibreWolf",
        "waterfox" => "Waterfox",
        "floorp" => "Floorp",
        "tor" => "Tor Browser",
        "mullvadbrowser" => "Mullvad Browser",
        "thorium" => "Thorium",
        "arc" => "Arc",
        "comet" => "Comet",
        "browser" => "Yandex Browser",
        "chromium" => "Chromium",
        other => {
            let mut chars = other.chars();
            return chars.next().map(|first| first.to_ascii_uppercase().to_string() + chars.as_str()).unwrap_or_default();
        }
    }
    .to_owned()
}

/// One `HKLM|HKCU\SOFTWARE\Clients\StartMenuInternet\<name>` entry: its display name and the
/// default value of `shell\open\command`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartMenuEntry {
    pub name: String,
    pub command: String,
}

/// The program in a command line: `"C:\A B\x.exe" --flag`, or an unquoted `C:\A B\x.exe -flag`.
pub fn command_program(command: &str) -> Option<PathBuf> {
    let command = command.trim();
    let program = if let Some(rest) = command.strip_prefix('"') {
        rest.split('"').next()?
    } else {
        let end = command.to_ascii_lowercase().find(".exe")? + 4;
        &command[..end]
    };
    let path = PathBuf::from(program.trim());
    path.file_name()?.to_str()?.to_ascii_lowercase().ends_with(".exe").then_some(path)
}

/// A browser found on this PC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detected {
    /// The exe file name without ".exe": the same id the native host reports.
    pub id: String,
    pub name: String,
    pub family: Family,
    /// The native host keys this browser reads; empty for an unknown browser.
    pub keys: Vec<Key>,
}

fn detected(exe: &str, name: &str) -> Option<Detected> {
    let id = crate::browser_ipc::browser_id_from_exe(exe)?;
    let class = classify(exe, name)?;
    let name = if name.trim().is_empty() { known_name(&id) } else { name.trim().chars().take(80).collect() };
    Some(Detected { id, name, family: class.family, keys: class.keys })
}

/// Browsers from the StartMenuInternet entries, plus the profile folders of Chrome, Brave, Edge
/// and Firefox (a per-user install may not write StartMenuInternet). One entry per browser id.
///
/// Two browsers can share an id: Helium's program is also "chrome.exe". The native host tells them
/// apart only by that id, so they stay one entry, with both names and the keys of both.
pub fn detect(entries: &[StartMenuEntry], local: &Path, roaming: &Path) -> Vec<Detected> {
    let mut found: Vec<Detected> = Vec::new();
    let mut add = |browser: Option<Detected>| {
        let Some(browser) = browser else { return };
        let Some(known) = found.iter_mut().find(|known| known.id == browser.id) else {
            found.push(browser);
            return;
        };
        if known.family != browser.family {
            return;
        }
        for key in browser.keys {
            if !known.keys.contains(&key) {
                known.keys.push(key);
            }
        }
        if !known.name.to_lowercase().contains(&browser.name.to_lowercase()) {
            known.name = format!("{} and {}", known.name, browser.name).chars().take(120).collect();
        }
    };
    for entry in entries {
        if let Some(program) = command_program(&entry.command) {
            add(detected(&program.to_string_lossy(), &entry.name));
        }
    }
    for (exe, folder, base) in [
        ("chrome.exe", r"Google\Chrome\User Data", local),
        ("brave.exe", r"BraveSoftware\Brave-Browser\User Data", local),
        ("msedge.exe", r"Microsoft\Edge\User Data", local),
        ("firefox.exe", r"Mozilla\Firefox", roaming),
    ] {
        if base.join(folder).is_dir() {
            add(detected(exe, ""));
        }
    }
    found
}

/// The choices for one browser. A browser without an entry has the defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub connected: bool,
    pub ask_at_start: bool,
    /// Chosen by the user for a browser Nuvori could not classify.
    pub family: Option<Family>,
    /// Unix milliseconds of the last request.
    pub last_seen: Option<i64>,
}

impl Default for Entry {
    fn default() -> Self {
        Entry { connected: true, ask_at_start: true, family: None, last_seen: None }
    }
}

/// Reads the file text; anything unreadable falls back to the defaults, field by field.
pub fn parse_settings(text: &str) -> BTreeMap<String, Entry> {
    let value: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    let defaults = Entry::default();
    value["browsers"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(id, _)| crate::browser_ipc::valid_browser_id(id))
        .take(MAX_ENTRIES)
        .map(|(id, entry)| {
            (id.clone(), Entry {
                connected: entry["connected"].as_bool().unwrap_or(defaults.connected),
                ask_at_start: entry["askAtStart"].as_bool().unwrap_or(defaults.ask_at_start),
                family: entry["family"].as_str().and_then(Family::parse),
                last_seen: entry["lastSeen"].as_i64(),
            })
        })
        .collect()
}

pub fn settings_json(entries: &BTreeMap<String, Entry>) -> String {
    let browsers: serde_json::Map<String, serde_json::Value> = entries
        .iter()
        .map(|(id, entry)| {
            (id.clone(), serde_json::json!({
                "connected": entry.connected,
                "askAtStart": entry.ask_at_start,
                "family": entry.family.and_then(Family::name),
                "lastSeen": entry.last_seen,
            }))
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "browsers": browsers })).expect("settings serialize")
}

struct Inner {
    entries: BTreeMap<String, Entry>,
    /// Unix milliseconds of the last write of a last-use time.
    seen_saved_at: i64,
}

/// The settings file. `file` may be `None` (tests that need no file).
pub struct Browsers {
    file: Option<PathBuf>,
    inner: Mutex<Inner>,
}

impl Browsers {
    pub fn new(directory: &Path) -> Self {
        let file = directory.join(SETTINGS_FILE);
        let entries = std::fs::read_to_string(&file).map(|text| parse_settings(&text)).unwrap_or_default();
        Browsers { file: Some(file), inner: Mutex::new(Inner { entries, seen_saved_at: 0 }) }
    }

    /// Settings that are never written to disk.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Browsers { file: None, inner: Mutex::new(Inner { entries: BTreeMap::new(), seen_saved_at: 0 }) }
    }

    pub fn entries(&self) -> BTreeMap<String, Entry> {
        self.inner.lock().map(|inner| inner.entries.clone()).unwrap_or_default()
    }

    /// False only when the user turned "ask when the browser starts" off for this browser.
    pub fn ask_at_start(&self, id: &str) -> bool {
        self.entries().get(id).is_none_or(|entry| entry.ask_at_start)
    }

    fn save(&self, inner: &Inner) {
        let Some(file) = &self.file else { return };
        let written = file.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(file, settings_json(&inner.entries)));
        if let Err(error) = written {
            activity::diagnostic(Category::Browser, "Could not save the browser settings", error);
        }
    }

    /// Changes one browser's entry and writes the file.
    pub fn update(&self, id: &str, change: impl FnOnce(&mut Entry)) {
        let Ok(mut inner) = self.inner.lock() else { return };
        if !inner.entries.contains_key(id) && inner.entries.len() >= MAX_ENTRIES {
            return;
        }
        change(inner.entries.entry(id.to_owned()).or_default());
        self.save(&inner);
    }

    /// Records that a browser used Nuvori. The time is kept in memory at once; the file is
    /// written at most once a minute.
    pub fn note_seen(&self, id: &str) {
        self.note_seen_at(id, activity::now_millis() as i64);
    }

    fn note_seen_at(&self, id: &str, now: i64) {
        if !crate::browser_ipc::valid_browser_id(id) {
            return;
        }
        let Ok(mut inner) = self.inner.lock() else { return };
        if !inner.entries.contains_key(id) && inner.entries.len() >= MAX_ENTRIES {
            return;
        }
        inner.entries.entry(id.to_owned()).or_default().last_seen = Some(now);
        if now - inner.seen_saved_at >= SEEN_WRITE_INTERVAL_MS {
            inner.seen_saved_at = now;
            self.save(&inner);
        }
    }
}

static STORE: OnceLock<Browsers> = OnceLock::new();

/// Opens the settings in the vault folder. Call once at startup.
pub fn install(directory: &Path) {
    let _ = STORE.set(Browsers::new(directory));
}

pub fn installed() -> Option<&'static Browsers> {
    STORE.get()
}

/// A browser as the UI shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Browser {
    pub id: String,
    pub name: String,
    pub family: Family,
    pub connected: bool,
    pub ask_at_start: bool,
    pub last_seen: Option<i64>,
    /// Every key this browser reads points at Nuvori now.
    pub registered: bool,
}

/// A detected browser with the user's choices applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub id: String,
    pub name: String,
    pub family: Family,
    pub keys: Vec<Key>,
    /// Chosen to connect, and its family is known.
    pub connected: bool,
    pub ask_at_start: bool,
    pub last_seen: Option<i64>,
}

/// Merges detection with the saved choices. A browser that used Nuvori but was not detected is
/// listed too when its program name is a known browser.
pub fn resolve(found: &[Detected], entries: &BTreeMap<String, Entry>) -> Vec<Resolved> {
    let mut all: Vec<Detected> = found.to_vec();
    for (id, entry) in entries {
        if entry.last_seen.is_some()
            && !all.iter().any(|known| &known.id == id)
            && let Some(browser) = detected(&format!("{id}.exe"), "")
            && browser.family != Family::Unknown
        {
            all.push(browser);
        }
    }
    let mut resolved: Vec<Resolved> = all
        .into_iter()
        .map(|browser| {
            let entry = entries.get(&browser.id).cloned().unwrap_or_default();
            // The user's choice applies only to a browser Nuvori could not classify.
            let (family, keys) = if browser.family == Family::Unknown {
                let family = entry.family.unwrap_or(Family::Unknown);
                (family, family_keys(family))
            } else {
                (browser.family, browser.keys.clone())
            };
            Resolved {
                connected: entry.connected && family != Family::Unknown,
                ask_at_start: entry.ask_at_start,
                last_seen: entry.last_seen,
                id: browser.id,
                name: browser.name,
                family,
                keys,
            }
        })
        .collect();
    // Seen browsers first, then by name.
    resolved.sort_by(|left, right| {
        right.last_seen.is_some().cmp(&left.last_seen.is_some()).then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });
    resolved
}

/// The list for the UI. `registered` says whether one key points at Nuvori's manifest.
pub fn to_list(resolved: &[Resolved], registered: impl Fn(Key) -> bool) -> Vec<Browser> {
    resolved
        .iter()
        .map(|browser| Browser {
            id: browser.id.clone(),
            name: browser.name.clone(),
            family: browser.family,
            connected: browser.connected,
            ask_at_start: browser.ask_at_start,
            last_seen: browser.last_seen,
            registered: !browser.keys.is_empty() && browser.keys.iter().all(|key| registered(*key)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, command: &str) -> StartMenuEntry {
        StartMenuEntry { name: name.into(), command: command.into() }
    }

    #[test]
    fn programs_are_classified_by_their_exe_name() {
        let class = |exe: &str| classify(exe, "").unwrap();
        assert_eq!(class("zen.exe"), Class { family: Family::Firefox, keys: vec![Key::Mozilla] });
        assert_eq!(class(r"C:\Program Files\Mozilla Firefox\FIREFOX.EXE").family, Family::Firefox);
        assert_eq!(class("vivaldi.exe"), Class { family: Family::Chromium, keys: vec![Key::Chrome, Key::Chromium] });
        assert_eq!(class("msedge.exe").keys, [Key::Edge]);
        assert_eq!(class("chrome.exe").keys, [Key::Chrome]);
        assert_eq!(classify("chrome.exe", "Google Chrome Beta").unwrap().keys, [Key::Chrome]);
        // Helium keeps Chromium's program name and also reads the Chromium key.
        assert_eq!(classify(r"C:\Users\a\AppData\Local\imput\Helium\Application\chrome.exe", "Helium").unwrap().keys,
            [Key::Chrome, Key::Chromium]);
        assert_eq!(class("comet.exe"), Class { family: Family::Chromium, keys: vec![Key::Chrome, Key::Chromium] });
        assert_eq!(class("brave.exe").keys, [Key::Brave]);
        assert_eq!(class("opera.exe").keys, [Key::Chrome, Key::Chromium]);
        assert_eq!(class("unknown.exe"), Class { family: Family::Unknown, keys: vec![] });
        assert_eq!(classify("firefox.exe", "Tor Browser").unwrap().family, Family::Firefox);
        assert_eq!(classify("start-tor-browser.exe", "Tor Browser").unwrap().keys, [Key::Mozilla]);
        assert_eq!(classify("palemoon.exe", "Pale Moon"), None);
        assert_eq!(classify("iexplore.exe", "Internet Explorer"), None);
    }

    #[test]
    fn a_start_menu_command_names_its_program() {
        let program = |text: &str| command_program(text).map(|path| path.to_string_lossy().into_owned());
        assert_eq!(program(r#""C:\Program Files\Zen Browser\zen.exe" -osint"#).as_deref(), Some(r"C:\Program Files\Zen Browser\zen.exe"));
        assert_eq!(program(r"C:\Program Files\Vivaldi\vivaldi.exe --flag").as_deref(), Some(r"C:\Program Files\Vivaldi\vivaldi.exe"));
        assert_eq!(program(r#""C:\x\Chrome.EXE""#).as_deref(), Some(r"C:\x\Chrome.EXE"));
        assert_eq!(program(""), None);
        assert_eq!(program(r"C:\x\readme.txt"), None);
    }

    fn temp_dir() -> PathBuf {
        let directory = std::env::temp_dir().join(format!("nuvori-browsers-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn detection_reads_start_menu_entries_and_profile_folders_once_per_browser() {
        let directory = temp_dir();
        let (local, roaming) = (directory.join("local"), directory.join("roaming"));
        std::fs::create_dir_all(local.join(r"Google\Chrome\User Data")).unwrap();
        std::fs::create_dir_all(roaming.join(r"Mozilla\Firefox")).unwrap();
        let entries = [
            entry("Zen", r#""C:\Program Files\Zen Browser\zen.exe""#),
            entry("Vivaldi", r"C:\Users\a\AppData\Local\Vivaldi\Application\vivaldi.exe"),
            entry("Google Chrome", r#""C:\Program Files\Google\Chrome\Application\chrome.exe""#),
            entry("Thorium Nightly", r#""C:\t\nightly.exe""#),
            entry("Internet Explorer", r#""C:\Program Files\Internet Explorer\iexplore.exe""#),
            entry("Helium", r#""C:\Users\a\AppData\Local\imput\Helium\Application\chrome.exe""#),
            entry("Google Chrome", r#""D:\other\chrome.exe""#),
        ];
        let found = detect(&entries, &local, &roaming);
        let ids: Vec<&str> = found.iter().map(|browser| browser.id.as_str()).collect();
        assert_eq!(ids, ["zen", "vivaldi", "chrome", "nightly", "firefox"]);
        assert_eq!(found[0].family, Family::Firefox);
        assert_eq!(found[1].keys, [Key::Chrome, Key::Chromium]);
        // Chrome and Helium share the id "chrome": one entry with both names and both keys.
        assert_eq!(found[2].name, "Google Chrome and Helium");
        assert_eq!(found[2].keys, [Key::Chrome, Key::Chromium]);
        assert_eq!(found[3].family, Family::Unknown);
        assert_eq!(found[4].name, "Firefox", "a profile folder alone counts");
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn an_unknown_browser_needs_a_chosen_family_before_it_connects() {
        let found = [Detected { id: "nightly".into(), name: "Thorium Nightly".into(), family: Family::Unknown, keys: vec![] }];
        let mut entries = BTreeMap::new();
        let before = resolve(&found, &entries);
        assert!(!before[0].connected && before[0].keys.is_empty());
        entries.insert("nightly".to_owned(), Entry { family: Some(Family::Chromium), ..Entry::default() });
        let after = resolve(&found, &entries);
        assert!(after[0].connected);
        assert_eq!((after[0].family, after[0].keys.clone()), (Family::Chromium, vec![Key::Chrome, Key::Chromium]));
        // A classified browser ignores a family choice.
        let known = [Detected { id: "zen".into(), name: "Zen".into(), family: Family::Firefox, keys: vec![Key::Mozilla] }];
        entries.insert("zen".to_owned(), Entry { family: Some(Family::Chromium), ..Entry::default() });
        assert_eq!(resolve(&known, &entries)[0].family, Family::Firefox);
    }

    #[test]
    fn the_list_puts_seen_browsers_first_then_sorts_by_name() {
        let found = vec![
            Detected { id: "zen".into(), name: "Zen".into(), family: Family::Firefox, keys: vec![Key::Mozilla] },
            Detected { id: "chrome".into(), name: "Google Chrome".into(), family: Family::Chromium, keys: vec![Key::Chrome] },
            Detected { id: "vivaldi".into(), name: "Vivaldi".into(), family: Family::Chromium, keys: vec![Key::Chrome, Key::Chromium] },
        ];
        let mut entries = BTreeMap::new();
        entries.insert("vivaldi".to_owned(), Entry { last_seen: Some(5), ..Entry::default() });
        entries.insert("opera".to_owned(), Entry { last_seen: Some(9), ..Entry::default() });
        entries.insert("zen".to_owned(), Entry { connected: false, ask_at_start: false, ..Entry::default() });
        let list = to_list(&resolve(&found, &entries), |key| key == Key::Chrome);
        let ids: Vec<&str> = list.iter().map(|browser| browser.id.as_str()).collect();
        assert_eq!(ids, ["opera", "vivaldi", "chrome", "zen"], "an undetected but seen, known browser is listed");
        assert!(list[2].registered && !list[1].registered, "all of a browser's keys must point at Nuvori");
        assert!(!list[3].connected && !list[3].ask_at_start);
        let json = serde_json::to_value(&list[3]).unwrap();
        assert_eq!(json, serde_json::json!({"id": "zen", "name": "Zen", "family": "firefox", "connected": false,
            "askAtStart": false, "lastSeen": null, "registered": false}));
    }

    #[test]
    fn settings_round_trip_and_bad_files_fall_back_to_defaults() {
        let mut entries = BTreeMap::new();
        entries.insert("zen".to_owned(), Entry { connected: false, ask_at_start: false, family: Some(Family::Firefox), last_seen: Some(1_700_000_000_000) });
        assert_eq!(parse_settings(&settings_json(&entries)), entries);
        assert!(parse_settings("not json").is_empty());
        let partial = parse_settings(r#"{"browsers":{"a":{"connected":false},"BAD ID":{},"b":{"family":"unknown"}}}"#);
        assert_eq!(partial.len(), 2);
        assert_eq!(partial["a"], Entry { connected: false, ..Entry::default() });
        assert_eq!(partial["b"].family, None);
    }

    #[test]
    fn last_use_is_written_at_most_once_a_minute_and_ask_at_start_defaults_on() {
        let directory = temp_dir();
        let store = Browsers::new(&directory);
        assert!(store.ask_at_start("zen"));
        store.note_seen_at("zen", 1_000_000);
        let file = directory.join(SETTINGS_FILE);
        assert_eq!(parse_settings(&std::fs::read_to_string(&file).unwrap())["zen"].last_seen, Some(1_000_000));
        store.note_seen_at("zen", 1_030_000);
        assert_eq!(store.entries()["zen"].last_seen, Some(1_030_000), "memory is current");
        assert_eq!(parse_settings(&std::fs::read_to_string(&file).unwrap())["zen"].last_seen, Some(1_000_000), "the file waits");
        store.note_seen_at("zen", 1_070_000);
        assert_eq!(parse_settings(&std::fs::read_to_string(&file).unwrap())["zen"].last_seen, Some(1_070_000));
        store.update("zen", |entry| entry.ask_at_start = false);
        assert!(!store.ask_at_start("zen"));
        assert!(!Browsers::new(&directory).ask_at_start("zen"), "the choice is stored");
        store.note_seen("Not An Id!");
        assert!(!store.entries().contains_key("Not An Id!"));
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
