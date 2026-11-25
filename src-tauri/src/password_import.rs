//! Import logins from a browser or password manager export, as Android's `BrowserPasswords.kt`:
//! a CSV from Chrome, Edge, Brave, Firefox, Safari, Bitwarden, 1Password, LastPass or KeePass,
//! or an unencrypted Bitwarden JSON export.
//!
//! The file is read in memory on this PC only and never stored. Comma, semicolon and tab CSV are
//! detected from the header (Excel's `sep=` line too). Known exports map their columns by
//! themselves; for any other header the user picks the website, username and password columns,
//! shown with masked sample values. Rows without a password are skipped, as are Bitwarden items
//! that aren't logins.
//!
//! The review compares each login with the saved ones by website and username (Android
//! `sameImportedAccount`): new logins are added, identical ones skipped, and for a saved login whose
//! password differs the user keeps the saved password or uses the imported one. A login that
//! matches more than one saved login is left alone.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Android reads at most 4 Mi characters (UTF-16 units) and 5,000 logins.
pub const MAX_CHARS: usize = 4 * 1024 * 1024;
pub const MAX_LOGINS: usize = 5000;
/// A larger file always holds more than `MAX_CHARS` characters, so it's refused before decoding.
pub const MAX_FILE_BYTES: usize = 4 * MAX_CHARS;
/// Windows keeps item titles to 500 bytes (`vault.rs` `validate_entry`); a longer one, often a
/// website used as the title, is shortened. Android has no such limit.
const MAX_TITLE_BYTES: usize = 500;

/// Windows saves a login only with a password that isn't blank, so a password of only spaces
/// counts as missing here, where Android would import it.
fn usable_password(password: &str) -> bool {
    !password.trim().is_empty()
}

fn titled(mut title: String) -> String {
    if title.len() > MAX_TITLE_BYTES {
        let mut end = MAX_TITLE_BYTES;
        while !title.is_char_boundary(end) {
            end -= 1;
        }
        title.truncate(end);
    }
    title
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("The password export is empty.")]
    Empty,
    #[error("The password export is larger than 4 million characters.")]
    TooLarge,
    #[error("Could not detect separate CSV columns. Export passwords as comma, semicolon, or tab-separated CSV.")]
    NoColumns,
    #[error("The CSV export has no header row.")]
    NoHeader,
    #[error("A CSV row does not match the header columns. Export the file again without editing it in a spreadsheet.")]
    RowMismatch,
    #[error("No non-empty passwords were found in the export.")]
    NoPasswords,
    /// Parser details could hold a fragment of a secret, so the message is fixed (Android).
    #[error("Could not read password export. Use a supported UTF-8 CSV or an unencrypted Bitwarden JSON export with up to 5,000 logins and 4 million characters.")]
    Unreadable,
    #[error("Choose the website, username, and password columns.")]
    MappingRequired { columns: Vec<ColumnPreview>, suggested: ColumnMapping },
}

/// Which CSV header holds each field. Website, username and password are required.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ColumnMapping {
    pub title: Option<String>,
    pub website: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
}

/// A header and the shape of its first value, never the value itself.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ColumnPreview {
    pub header: String,
    pub sample_shape: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedLogin {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

impl Drop for ImportedLogin {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// The logins of an export file, one per website and username, and how many rows it had.
pub fn open(bytes: &[u8], mapping: Option<&ColumnMapping>) -> Result<(usize, Vec<ImportedLogin>), ImportError> {
    let text = decode(bytes)?;
    let logins = read(&text, mapping)?;
    Ok((logins.len(), deduplicate(logins)))
}

/// Text of an export: UTF-8, or UTF-16 after its byte order mark, decoded strictly (Android).
pub fn decode(bytes: &[u8]) -> Result<Zeroizing<String>, ImportError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ImportError::TooLarge);
    }
    let text = if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        std::str::from_utf8(rest).map_err(|_| ImportError::Unreadable)?.to_owned()
    } else if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        let little = bytes[0] == 0xFF;
        let body = &bytes[2..];
        if body.len() % 2 != 0 {
            return Err(ImportError::Unreadable);
        }
        let mut units: Vec<u16> = body
            .chunks_exact(2)
            .map(|pair| if little { u16::from_le_bytes([pair[0], pair[1]]) } else { u16::from_be_bytes([pair[0], pair[1]]) })
            .collect();
        let text = String::from_utf16(&units).map_err(|_| ImportError::Unreadable);
        units.zeroize();
        text?
    } else {
        std::str::from_utf8(bytes).map_err(|_| ImportError::Unreadable)?.to_owned()
    };
    let text = Zeroizing::new(text);
    if text.encode_utf16().count() > MAX_CHARS {
        return Err(ImportError::TooLarge);
    }
    Ok(text)
}

/// The logins in an export. `mapping` is the user's choice of columns after `MappingRequired`.
pub fn read(text: &str, mapping: Option<&ColumnMapping>) -> Result<Vec<ImportedLogin>, ImportError> {
    let start = text.char_indices().find(|(_, c)| *c != '\u{FEFF}' && !c.is_whitespace()).map(|(index, _)| index);
    let Some(start) = start else { return Err(ImportError::Empty) };
    let content = &text[start..];
    if content.starts_with('{') { read_bitwarden_json(content) } else { read_csv(content, mapping) }
}

// ---- CSV, read as Apache Commons CSV reads RFC 4180 on Android ----

/// Records of `text`. A quoted field may hold the delimiter, line breaks and doubled quotes, and
/// only spaces may follow its closing quote; a quote inside an unquoted field is an ordinary
/// character. Lines with nothing on them are skipped.
fn parse_csv(text: &str, delimiter: char) -> Result<Vec<Vec<String>>, ImportError> {
    #[derive(PartialEq)]
    enum At {
        Start,
        Plain,
        Quoted,
        AfterQuote,
    }
    let mut records = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut at = At::Start;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if at == At::Quoted {
            if c != '"' {
                field.push(c);
            } else if chars.peek() == Some(&'"') {
                chars.next();
                field.push('"');
            } else {
                at = At::AfterQuote;
            }
        } else if c == delimiter {
            record.push(std::mem::take(&mut field));
            at = At::Start;
        } else if c == '\r' || c == '\n' {
            if c == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            if !(at == At::Start && record.is_empty()) {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            at = At::Start;
        } else if at == At::AfterQuote {
            if !c.is_whitespace() {
                field.zeroize();
                record.zeroize();
                records.zeroize();
                return Err(ImportError::Unreadable);
            }
        } else if at == At::Start && c == '"' {
            at = At::Quoted;
        } else {
            field.push(c);
            at = At::Plain;
        }
    }
    if at == At::Quoted {
        field.zeroize();
        record.zeroize();
        records.zeroize();
        return Err(ImportError::Unreadable);
    }
    if !(at == At::Start && record.is_empty()) {
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

fn column_count(line: &str, delimiter: char) -> usize {
    parse_csv(line, delimiter).ok().and_then(|records| records.first().map(Vec::len)).unwrap_or(0)
}

/// The CSV without Excel's `sep=` line, and its delimiter.
fn prepare(text: &str) -> Result<(&str, char), ImportError> {
    let line = text.split(['\r', '\n']).next().unwrap_or_default();
    let trimmed = line.trim();
    let mut separator = trimmed.chars();
    if trimmed.chars().count() == 5 && separator.by_ref().take(4).collect::<String>().eq_ignore_ascii_case("sep=") {
        let delimiter = separator.next().unwrap_or_default();
        if [',', ';', '\t'].contains(&delimiter) {
            let body = text[line.len()..].trim_start_matches(['\r', '\n']);
            if body.is_empty() {
                return Err(ImportError::NoHeader);
            }
            return Ok((body, delimiter));
        }
    }
    // The first delimiter with the most columns, as Kotlin's maxByOrNull.
    let mut best = (',', column_count(line, ','));
    for candidate in [';', '\t'] {
        let count = column_count(line, candidate);
        if count > best.1 {
            best = (candidate, count);
        }
    }
    if best.1 < 2 {
        return Err(ImportError::NoColumns);
    }
    Ok((text, best.0))
}

/// Android `normalizePasswordHeader`: "Login_URI", "login uri" and "login-uri" are one header.
pub fn normalize_header(value: &str) -> String {
    value
        .strip_prefix('\u{FEFF}')
        .unwrap_or(value)
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
        .collect()
}

/// Header names each field goes by (Android `PASSWORD_FIELD_ALIASES`), in field order:
/// title, website, username, password, notes.
const ALIASES: [&[&str]; 5] = [
    &["name", "title", "account", "account name"],
    &["url", "website", "web site", "login_uri", "login_url", "hostname"],
    &["username", "user name", "login_username", "login name", "login", "email"],
    &["password", "login_password"],
    &["note", "notes", "extra", "extra notes", "comments"],
];
const PASSWORD: usize = 3;

struct Profile {
    provider: &'static str,
    /// Headers in field order: title, website, username, password, notes.
    columns: [Option<&'static str>; 5],
    markers: &'static [&'static str],
}

/// Specific profiles precede the shared Chromium and Firefox shape (Android `PASSWORD_PROVIDER_PROFILES`).
const PROFILES: [Profile; 8] = [
    Profile { provider: "Bitwarden", columns: [Some("name"), Some("login_uri"), Some("login_username"), Some("login_password"), Some("notes")], markers: &["type"] },
    Profile { provider: "Bitwarden", columns: [Some("name"), Some("login_url"), Some("login_username"), Some("login_password"), Some("notes")], markers: &["type"] },
    Profile { provider: "KeePass", columns: [Some("account"), Some("web site"), Some("login name"), Some("password"), Some("comments")], markers: &["account"] },
    Profile { provider: "LastPass", columns: [Some("name"), Some("url"), Some("username"), Some("password"), Some("extra")], markers: &["extra"] },
    Profile { provider: "1Password", columns: [Some("title"), Some("website"), Some("username"), Some("password"), Some("notes")], markers: &["website"] },
    Profile { provider: "Safari", columns: [Some("title"), Some("url"), Some("username"), Some("password"), Some("notes")], markers: &["title", "notes"] },
    Profile { provider: "Chromium", columns: [Some("name"), Some("url"), Some("username"), Some("password"), Some("note")], markers: &["name"] },
    Profile { provider: "Firefox", columns: [None, Some("url"), Some("username"), Some("password"), None], markers: &["httpRealm"] },
];

impl ColumnMapping {
    fn from_fields([title, website, username, password, notes]: [Option<String>; 5]) -> Self {
        Self { title, website, username, password, notes }
    }

    fn fields(&self) -> [&Option<String>; 5] {
        [&self.title, &self.website, &self.username, &self.password, &self.notes]
    }

    fn complete(&self) -> bool {
        self.website.is_some() && self.username.is_some() && self.password.is_some()
    }
}

impl Profile {
    fn matching(&self, headers: &BTreeMap<String, String>) -> Option<ColumnMapping> {
        if self.markers.iter().any(|marker| !headers.contains_key(&normalize_header(marker))) {
            return None;
        }
        let mapping = ColumnMapping::from_fields(self.columns.map(|name| name.and_then(|name| headers.get(&normalize_header(name)).cloned())));
        mapping.complete().then_some(mapping)
    }
}

/// How a sample value looks, without showing it (Android `maskedSampleShape`).
fn masked_shape(value: &str, password: bool) -> &'static str {
    let starts = |prefix: &str| value.get(..prefix.len()).is_some_and(|start| start.eq_ignore_ascii_case(prefix));
    if value.is_empty() {
        "Empty"
    } else if password {
        "Hidden"
    } else if starts("https://") {
        "https://••••"
    } else if starts("http://") {
        "http://••••"
    } else if value.contains('@') {
        "••••@••••"
    } else {
        "••••"
    }
}

fn read_csv(text: &str, mapping: Option<&ColumnMapping>) -> Result<Vec<ImportedLogin>, ImportError> {
    let (body, delimiter) = prepare(text)?;
    let mut records = parse_csv(body, delimiter)?;
    let result = logins_of(&mut records, mapping);
    records.zeroize();
    result
}

fn logins_of(records: &mut [Vec<String>], mapping: Option<&ColumnMapping>) -> Result<Vec<ImportedLogin>, ImportError> {
    let Some((header_row, rows)) = records.split_first_mut() else { return Err(ImportError::NoHeader) };
    let header_row: &[String] = header_row;
    // Commons CSV refuses a blank or repeated header name, and Android one repeated once normalized.
    let mut headers = BTreeMap::new();
    for name in header_row {
        if name.trim().is_empty() || headers.insert(normalize_header(name), name.clone()).is_some() {
            return Err(ImportError::Unreadable);
        }
    }
    let header = |name: &str| headers.get(&normalize_header(name)).cloned();
    let candidates: [Vec<String>; 5] = ALIASES.map(|names| {
        let mut found: Vec<String> = Vec::new();
        for name in names.iter().filter_map(|name| header(name)) {
            if !found.contains(&name) {
                found.push(name);
            }
        }
        found
    });
    let matched = PROFILES.iter().find_map(|profile| profile.matching(&headers).map(|mapping| (profile.provider, mapping)));
    let ambiguous = candidates.iter().any(|found| found.len() > 1);
    let suggested = matched.as_ref().map(|(_, mapping)| mapping.clone()).unwrap_or_else(|| {
        ColumnMapping::from_fields(candidates.clone().map(|found| if found.len() == 1 { found.into_iter().next() } else { None }))
    });
    let chosen = match mapping {
        Some(mapping) => ColumnMapping::from_fields(mapping.fields().map(|name| name.clone().filter(|name| header_row.contains(name)))),
        None => suggested.clone(),
    };
    let picked: Vec<&String> = chosen.fields().into_iter().flatten().collect();
    if !chosen.complete() || picked.iter().collect::<BTreeSet<_>>().len() != picked.len()
        || (mapping.is_none() && matched.is_none() && ambiguous)
    {
        let first = rows.first().filter(|row| row.len() == header_row.len());
        let columns = header_row
            .iter()
            .enumerate()
            .map(|(index, name)| ColumnPreview {
                header: name.clone(),
                sample_shape: masked_shape(first.map_or("", |row| row[index].as_str()), candidates[PASSWORD].contains(name)).to_owned(),
            })
            .collect();
        return Err(ImportError::MappingRequired { columns, suggested: if mapping.is_none() { suggested } else { chosen } });
    }
    let index = |name: &Option<String>| name.as_ref().and_then(|name| header_row.iter().position(|header| header == name));
    let [title, website, username, password, notes] = chosen.fields().map(index);
    let (website, username, password) = (website.ok_or(ImportError::Unreadable)?, username.ok_or(ImportError::Unreadable)?, password.ok_or(ImportError::Unreadable)?);
    let kind = matched.filter(|(provider, _)| *provider == "Bitwarden").and_then(|_| index(&header("type")));
    let value = |row: &[String], index: Option<usize>| index.and_then(|index| row.get(index)).cloned().unwrap_or_default();
    let mut logins = Vec::new();
    for row in rows.iter() {
        if row.iter().skip(header_row.len()).any(|value| !value.is_empty()) {
            return Err(ImportError::RowMismatch);
        }
        if let Some(kind) = kind {
            // Commons CSV can't read a value past the end of a row.
            let Some(kind) = row.get(kind) else { return Err(ImportError::Unreadable) };
            if !kind.eq_ignore_ascii_case("login") {
                continue;
            }
        }
        let secret = value(row, Some(password));
        if !usable_password(&secret) {
            continue;
        }
        if row.len() <= website.max(username) {
            return Err(ImportError::RowMismatch);
        }
        if logins.len() >= MAX_LOGINS {
            return Err(ImportError::Unreadable);
        }
        let url = row[website].clone();
        let mut title = value(row, title);
        if title.trim().is_empty() {
            title = if url.trim().is_empty() { "Imported login".to_owned() } else { url.clone() };
        }
        logins.push(ImportedLogin { title: titled(title), username: row[username].clone(), password: secret, url, notes: value(row, notes) });
    }
    if logins.is_empty() {
        return Err(ImportError::NoPasswords);
    }
    Ok(logins)
}

// ---- Bitwarden JSON, read as Android reads it with Gson ----

/// A JSON value as Gson's `asString` gives it, for strings, numbers and true or false.
fn text_of(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(serde_json::Value::Number(number)) => number.to_string(),
        Some(serde_json::Value::Bool(flag)) => flag.to_string(),
        _ => String::new(),
    }
}

/// Gson's `asInt`, which truncates a number and parses a string.
fn int_of(value: Option<&serde_json::Value>) -> Option<i64> {
    match value? {
        serde_json::Value::Number(number) => number.as_i64().or_else(|| number.as_f64().map(|number| number as i64)),
        serde_json::Value::String(text) => text.parse::<i32>().ok().map(i64::from),
        _ => None,
    }
}

fn read_bitwarden_json(text: &str) -> Result<Vec<ImportedLogin>, ImportError> {
    let mut root: serde_json::Value = serde_json::from_str(text).map_err(|_| ImportError::Unreadable)?;
    let result = bitwarden_logins(&root);
    wipe(&mut root);
    result
}

fn bitwarden_logins(root: &serde_json::Value) -> Result<Vec<ImportedLogin>, ImportError> {
    let root = root.as_object().ok_or(ImportError::Unreadable)?;
    if text_of(root.get("encrypted")).eq_ignore_ascii_case("true") {
        return Err(ImportError::Unreadable);
    }
    let items = root.get("items").and_then(serde_json::Value::as_array).ok_or(ImportError::Unreadable)?;
    let mut logins = Vec::new();
    for item in items {
        let item = item.as_object().ok_or(ImportError::Unreadable)?;
        if int_of(item.get("type")) != Some(1) {
            continue;
        }
        let login = item.get("login").and_then(serde_json::Value::as_object).ok_or(ImportError::Unreadable)?;
        let password = text_of(login.get("password"));
        if !usable_password(&password) {
            continue;
        }
        if logins.len() >= MAX_LOGINS {
            return Err(ImportError::Unreadable);
        }
        // Android stops at `"uris": null`; Bitwarden writes it for a login without a website.
        let url = login
            .get("uris")
            .and_then(serde_json::Value::as_array)
            .and_then(|uris| uris.iter().filter(|uri| uri.is_object()).map(|uri| text_of(uri.get("uri"))).find(|uri| !uri.trim().is_empty()))
            .unwrap_or_default();
        let name = text_of(item.get("name"));
        if name.trim().is_empty() {
            return Err(ImportError::Unreadable);
        }
        logins.push(ImportedLogin { title: titled(name), username: text_of(login.get("username")), password, url, notes: text_of(item.get("notes")) });
    }
    if logins.is_empty() { Err(ImportError::Unreadable) } else { Ok(logins) }
}

fn wipe(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe),
        serde_json::Value::Object(fields) => fields.values_mut().for_each(wipe),
        _ => {}
    }
}

// ---- Matching with saved logins ----

/// The host of an `https://` address as `java.net.URI` reads one, so logins match as on Android:
/// a dotted IPv4 address, or ASCII labels of letters, digits and inner hyphens with the last
/// starting with a letter. Anything else, a user name or an unreadable port gives no origin.
fn uri_authority(value: &str) -> Option<(&str, Option<u32>)> {
    let rest = value.get(..8).filter(|scheme| scheme.eq_ignore_ascii_case("https://")).map(|_| &value[8..])?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, "")) => (host, None),
        Some((host, port)) if port.len() <= 9 && port.bytes().all(|byte| byte.is_ascii_digit()) => (host, Some(port.parse().ok()?)),
        Some(_) => return None,
        None => (authority, None),
    };
    let labels: Vec<&str> = host.split('.').collect();
    let ipv4 = labels.len() == 4 && labels.iter().all(|part| !part.is_empty() && part.len() <= 3 && part.bytes().all(|byte| byte.is_ascii_digit()) && part.parse::<u16>().is_ok_and(|part| part <= 255));
    let named = labels.iter().all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty() && bytes.len() <= 63 && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            && bytes[0].is_ascii_alphanumeric() && bytes[bytes.len() - 1].is_ascii_alphanumeric()
    }) && labels.last().is_some_and(|label| label.as_bytes()[0].is_ascii_alphabetic());
    (ipv4 || named).then_some((host, port))
}

/// Whether `java.net.URI` would read `value` at all: ASCII outside its allowed set, a bad `%`
/// escape, a second `#` or a bracket in the path make it throw, and Android then finds no origin.
fn uri_readable(value: &str) -> bool {
    let bytes = value.as_bytes();
    let path_start = value.get(8..).and_then(|rest| rest.find(['/', '?', '#'])).map_or(bytes.len(), |index| index + 8);
    let query_start = value.find(['?', '#']).unwrap_or(bytes.len());
    let mut fragments = 0;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'%' => {
                if !(bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit) && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)) {
                    return false;
                }
            }
            b'#' => {
                fragments += 1;
                if fragments > 1 {
                    return false;
                }
            }
            b'[' | b']' if index >= path_start && index < query_start => return false,
            byte if byte.is_ascii() => {
                if !(byte.is_ascii_alphanumeric() || b"-_.!~*'();/?:@&=+$,[]".contains(byte)) {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Android `httpsOrigin`: the exact HTTPS origin, with no subdomain or title guessing.
pub fn https_origin(value: &str) -> Option<String> {
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) || value.contains('\\') || !uri_readable(value) {
        return None;
    }
    let (host, port) = uri_authority(value)?;
    let host = host.to_ascii_lowercase();
    if host.ends_with('.') || !host.contains('.') {
        return None;
    }
    match port {
        None | Some(443) => Some(format!("https://{host}")),
        Some(port @ 1..=65535) => Some(format!("https://{host}:{port}")),
        Some(_) => None,
    }
}

/// Website and username of a login, or `None` without a website (Android `importedLoginKey`).
pub fn login_key(url: &str, username: &str) -> Option<(String, String)> {
    let raw = url.trim();
    let site = https_origin(raw).unwrap_or_else(|| raw.to_lowercase());
    (!site.trim().is_empty()).then(|| (site, username.to_owned()))
}

/// One login per website and username, where a later row wins; logins without a website are
/// kept unless repeated exactly (Android `deduplicateImportedLogins`).
pub fn deduplicate(logins: Vec<ImportedLogin>) -> Vec<ImportedLogin> {
    let mut keyed: Vec<((String, String), ImportedLogin)> = Vec::new();
    let mut unkeyed: Vec<ImportedLogin> = Vec::new();
    for login in logins {
        match login_key(&login.url, &login.username) {
            Some(key) => match keyed.iter_mut().find(|(existing, _)| *existing == key) {
                Some(slot) => slot.1 = login,
                None => keyed.push((key, login)),
            },
            None => {
                if !unkeyed.contains(&login) {
                    unkeyed.push(login);
                }
            }
        }
    }
    keyed.into_iter().map(|(_, login)| login).chain(unkeyed).collect()
}

/// A saved login, as the review compares it.
pub struct SavedLogin {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub updated_at: i64,
}

impl SavedLogin {
    /// A saved item of the vault, if it's a login.
    pub fn from_entry(entry: &serde_json::Value) -> Option<Self> {
        if entry["type"] != "PASSWORD" {
            return None;
        }
        let text = |name: &str| entry[name].as_str().unwrap_or_default().to_owned();
        Some(Self {
            id: entry["id"].as_str()?.to_owned(),
            title: text("title"),
            username: text("primaryValue"),
            password: Zeroizing::new(text("secondaryValue")),
            url: text("tertiaryValue"),
            updated_at: entry["updatedAt"].as_i64().unwrap_or_default(),
        })
    }
}

/// Android `sameImportedAccount`: the same website and username, or for logins without a website
/// the same title, username and website text.
fn same_account(saved: &SavedLogin, login: &ImportedLogin) -> bool {
    match (login_key(&saved.url, &saved.username), login_key(&login.url, &login.username)) {
        (Some(first), Some(second)) => first == second,
        _ => saved.title == login.title && saved.username == login.username && saved.url == login.url,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    New,
    AlreadySaved,
    PasswordDiffers,
    /// More than one saved login has this website and username: left alone.
    Ambiguous,
}

/// What the import would do with each login, the saved login a changed password goes to, and a
/// token of the saved logins it found, which changes when one of them is edited, deleted or synced.
pub fn plan(logins: &[ImportedLogin], saved: &[SavedLogin]) -> (Vec<(Status, Option<String>)>, String) {
    let mut digest = Sha256::new();
    let mut part = |text: &[u8]| {
        digest.update((text.len() as u64).to_be_bytes());
        digest.update(text);
    };
    let mut planned = Vec::with_capacity(logins.len());
    for login in logins {
        let mut matches: Vec<&SavedLogin> = saved.iter().filter(|saved| same_account(saved, login)).collect();
        matches.sort_by(|first, second| first.id.cmp(&second.id));
        let step = match matches.as_slice() {
            [] => (Status::New, None),
            [one] if *one.password == login.password => (Status::AlreadySaved, None),
            [one] => (Status::PasswordDiffers, Some(one.id.clone())),
            _ => (Status::Ambiguous, None),
        };
        for text in [&login.title, &login.username, &login.password, &login.url, &login.notes] {
            part(text.as_bytes());
        }
        // Android `LoginImportMatch`: each match's id, last change and password fingerprint.
        part(&(matches.len() as u64).to_be_bytes());
        for found in matches {
            part(found.id.as_bytes());
            part(&found.updated_at.to_be_bytes());
            part(&Sha256::digest(found.password.as_bytes()));
        }
        planned.push(step);
    }
    (planned, hex::encode(digest.finalize()))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewItem {
    /// The login's place in the file once repeated logins are merged.
    pub row: usize,
    pub title: String,
    pub username: String,
    pub status: Status,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    pub rows: usize,
    pub duplicate_rows: usize,
    pub new: usize,
    pub already_saved: usize,
    pub password_differs: usize,
    pub ambiguous: usize,
    pub items: Vec<ReviewItem>,
    /// The import is refused unless the file and the saved logins still give this token.
    pub token: String,
}

/// What the import dialog shows next: the columns to choose, or the review.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Preview {
    #[serde(rename_all = "camelCase")]
    Mapping { columns: Vec<ColumnPreview>, suggested: ColumnMapping },
    Review(Review),
}

pub fn review(rows: usize, logins: &[ImportedLogin], saved: &[SavedLogin]) -> Review {
    let (planned, token) = plan(logins, saved);
    let count = |status| planned.iter().filter(|(found, _)| *found == status).count();
    Review {
        rows,
        duplicate_rows: rows - logins.len(),
        new: count(Status::New),
        already_saved: count(Status::AlreadySaved),
        password_differs: count(Status::PasswordDiffers),
        ambiguous: count(Status::Ambiguous),
        items: logins
            .iter()
            .zip(&planned)
            .enumerate()
            .map(|(row, (login, (status, _)))| ReviewItem { row, title: login.title.clone(), username: login.username.clone(), status: *status })
            .collect(),
        token,
    }
}

/// The user's choices in the review.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Choices {
    pub token: String,
    /// New logins the user unticked.
    #[serde(default)]
    pub skip_new: Vec<usize>,
    /// Changed logins whose imported password replaces the saved one; the rest keep the saved one.
    #[serde(default)]
    pub use_imported: Vec<usize>,
}

/// Android `LoginImportResult`, with the repeated rows the review merged.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub added: usize,
    pub updated: usize,
    pub skipped_exact: usize,
    /// Kept saved passwords and logins that matched more than one saved login.
    pub skipped_conflicts: usize,
    pub duplicate_rows: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_text(text: &str) -> Result<Vec<ImportedLogin>, ImportError> {
        read(text, None)
    }

    fn login(url: &str, username: &str, password: &str) -> ImportedLogin {
        ImportedLogin { title: "t".into(), username: username.into(), password: password.into(), url: url.into(), notes: String::new() }
    }

    fn saved(id: &str, url: &str, username: &str, password: &str) -> SavedLogin {
        SavedLogin::from_entry(&serde_json::json!({"id": id, "type": "PASSWORD", "title": "Saved", "primaryValue": username,
            "secondaryValue": password, "tertiaryValue": url, "updatedAt": 5})).unwrap()
    }

    #[test]
    fn chrome_edge_and_brave_exports_map_by_themselves() {
        let logins = read_text("name,url,username,password,note\nMail,https://mail.example.com/login,alice,s3cret,personal\n,https://bank.example.com,bob,\"p,\"\"q\"\"\",\n").unwrap();
        assert_eq!(logins.len(), 2);
        assert_eq!((logins[0].title.as_str(), logins[0].username.as_str(), logins[0].password.as_str(), logins[0].url.as_str(), logins[0].notes.as_str()),
            ("Mail", "alice", "s3cret", "https://mail.example.com/login", "personal"));
        assert_eq!(logins[1].title, "https://bank.example.com", "a missing title uses the website");
        assert_eq!(logins[1].password, "p,\"q\"");
        assert_eq!(read_text("name,url,username,password\n,,me,pw\n").unwrap()[0].title, "Imported login");
        let long = format!("https://a.example/{}", "é".repeat(300));
        let title = &read_text(&format!("url,username,password\n{long},me,pw\n")).unwrap()[0].title;
        assert!(title.len() <= 500 && long.starts_with(title.as_str()), "a long website title is shortened on a character boundary");
        assert_eq!(read_text("url,username,password\nhttps://a.example,me,\"  \"\nhttps://b.example,me,pw\n").unwrap().len(), 1,
            "Windows can't save a password of only spaces");
    }

    #[test]
    fn each_known_export_is_recognized() {
        let firefox = read_text("\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\"https://example.com\",\"a\",\"pw\",,\"https://example.com\",\"{x}\",\"1\",\"1\",\"1\"\n").unwrap();
        assert_eq!((firefox[0].title.as_str(), firefox[0].username.as_str()), ("https://example.com", "a"));
        let bitwarden = read_text("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,Site,n,,0,https://site.example,me,pw,\n,,note,Secure note,body,,0,,,secret,\n").unwrap();
        assert_eq!(bitwarden.len(), 1, "Bitwarden items that aren't logins are skipped");
        assert_eq!(bitwarden[0].notes, "n");
        let keepass = read_text("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\"Shop\",\"me\",\"pw\",\"https://shop.example\",\"c\"\n").unwrap();
        assert_eq!((keepass[0].title.as_str(), keepass[0].url.as_str(), keepass[0].notes.as_str()), ("Shop", "https://shop.example", "c"));
        let lastpass = read_text("url,username,password,totp,extra,name,grouping,fav\nhttps://lp.example,me,pw,,x,LP,,0\n").unwrap();
        assert_eq!((lastpass[0].title.as_str(), lastpass[0].notes.as_str()), ("LP", "x"));
        let one_password = read_text("Title,Website,Username,Password,Notes\nOne,https://one.example,me,pw,n\n").unwrap();
        assert_eq!(one_password[0].title, "One");
        let safari = read_text("Title,URL,Username,Password,Notes,OTPAuth\nSafari,https://s.example,me,pw,n,\n").unwrap();
        assert_eq!(safari[0].url, "https://s.example");
    }

    #[test]
    fn semicolon_tab_and_excel_separator_lines_are_read() {
        assert_eq!(read_text("url;username;password\nhttps://a.example;me;pw\n").unwrap()[0].password, "pw");
        assert_eq!(read_text("url\tusername\tpassword\r\nhttps://a.example\tme\tpw\r\n").unwrap()[0].username, "me");
        assert_eq!(read_text("sep=;\r\nurl;username;password\r\nhttps://a.example;me;p,w\r\n").unwrap()[0].password, "p,w");
        assert_eq!(read_text("SEP=,\nurl,username,password\nhttps://a.example,me,pw").unwrap()[0].password, "pw", "no final line break");
        assert_eq!(read_text("sep=;\r\n\r\n"), Err(ImportError::NoHeader));
        assert_eq!(read_text("\u{FEFF}url,username,password\n\nhttps://a.example,me,pw\n\n").unwrap().len(), 1, "a byte order mark and empty lines are fine");
        assert_eq!(read_text("url,username,password\nhttps://a.example,me,\"two\nlines\"\n").unwrap()[0].password, "two\nlines");
        assert_eq!(read_text("url,username,password\nhttps://a.example,me,pa\"ss\n").unwrap()[0].password, "pa\"ss", "a quote inside a field is a character");
        assert_eq!(read_text("url,username,password\nhttps://a.example,me,\"pw\"  \n").unwrap()[0].password, "pw", "spaces after a closing quote");
    }

    #[test]
    fn unclear_headers_ask_for_columns_with_masked_samples() {
        let error = read_text("site,email,login,secret\nhttps://a.example,me@example.com,me,hunter2\n").unwrap_err();
        let ImportError::MappingRequired { columns, suggested } = error else { panic!("columns must be chosen") };
        assert_eq!(columns.iter().map(|c| (c.header.as_str(), c.sample_shape.as_str())).collect::<Vec<_>>(),
            [("site", "https://••••"), ("email", "••••@••••"), ("login", "••••"), ("secret", "••••")]);
        assert_eq!(suggested, ColumnMapping::default(), "email and login could both be the username");
        let chosen = ColumnMapping { website: Some("site".into()), username: Some("login".into()), password: Some("secret".into()), ..Default::default() };
        let logins = read("site,email,login,secret\nhttps://a.example,me@example.com,me,hunter2\n", Some(&chosen)).unwrap();
        assert_eq!((logins[0].username.as_str(), logins[0].password.as_str()), ("me", "hunter2"));
        let twice = ColumnMapping { website: Some("site".into()), username: Some("site".into()), password: Some("secret".into()), ..Default::default() };
        let Err(ImportError::MappingRequired { suggested, .. }) = read("site,email,login,secret\nx,y,z,w\n", Some(&twice)) else { panic!("one column can't be two fields") };
        assert_eq!(suggested, twice, "the user's choice comes back to correct");
        let missing = ColumnMapping { website: Some("nope".into()), ..chosen.clone() };
        assert!(matches!(read("site,email,login,secret\nx,y,z,w\n", Some(&missing)), Err(ImportError::MappingRequired { .. })));
        let Err(ImportError::MappingRequired { columns, suggested }) = read_text("url,username,password,login_password\nhttps://a.example,me,a,b\n") else { panic!("two password columns") };
        assert_eq!((columns[2].sample_shape.as_str(), columns[3].sample_shape.as_str()), ("Hidden", "Hidden"));
        assert_eq!((suggested.website.as_deref(), suggested.password), (Some("url"), None));
        let Err(ImportError::MappingRequired { columns, .. }) = read_text("a,b\n1\n") else { panic!("unknown columns") };
        assert_eq!(columns[0].sample_shape, "Empty", "a short first row shows no samples");
    }

    #[test]
    fn broken_or_empty_exports_are_refused_without_their_contents() {
        assert_eq!(read_text("  \n"), Err(ImportError::Empty));
        assert_eq!(read_text("just one column\nvalue\n"), Err(ImportError::NoColumns));
        assert_eq!(read_text("url,username,password\nhttps://a.example,me,\n"), Err(ImportError::NoPasswords));
        assert_eq!(read_text("url,username,password\nhttps://a.example,me,pw,extra\n"), Err(ImportError::RowMismatch));
        assert_eq!(read_text("url,username,password\nhttps://a.example,me,pw,\n").unwrap().len(), 1, "an empty extra value is fine");
        assert_eq!(read_text("url,username,password\nonly a website\n"), Err(ImportError::NoPasswords), "a short row without a password is skipped");
        assert_eq!(read_text("password,url,username\npw,https://a.example\n"), Err(ImportError::RowMismatch), "a short row with a password");
        assert_eq!(read_text("url,username,password\nhttps://a.example,\"me\"x,pw\n"), Err(ImportError::Unreadable));
        assert_eq!(read_text("url,username,password\nhttps://a.example,\"me,pw\n"), Err(ImportError::Unreadable), "an unclosed quote");
        assert_eq!(read_text("url,URL,password\na,b,c\n"), Err(ImportError::Unreadable), "headers repeated once normalized");
        assert_eq!(read_text("url, ,password\na,b,c\n"), Err(ImportError::Unreadable), "a blank header");
        assert_eq!(read_text("type,name,login_uri,login_username,login_password\nlogin,a,https://a.example,me,pw\n\n"), Ok(vec![
            ImportedLogin { title: "a".into(), username: "me".into(), password: "pw".into(), url: "https://a.example".into(), notes: String::new() }]));
        assert!(read_text(&format!("url,username,password\n{}", "https://a.example,me,pw\n".repeat(MAX_LOGINS))).is_ok());
        assert_eq!(read_text(&format!("url,username,password\n{}", "https://a.example,me,pw\n".repeat(MAX_LOGINS + 1))), Err(ImportError::Unreadable));
        let message = ImportError::Unreadable.to_string();
        assert!(!message.contains("me,pw"));
    }

    #[test]
    fn bitwarden_json_keeps_logins_with_passwords() {
        let json = r#"{"encrypted": false, "items": [
            {"type": 1, "name": "Site", "notes": "n", "login": {"username": "me", "password": "pw", "uris": [{"uri": ""}, "x", {"uri": "https://site.example"}]}},
            {"type": 1, "name": "No website", "notes": null, "login": {"username": null, "password": 1234, "uris": null}},
            {"type": 1, "name": "No password", "login": {"username": "me", "password": ""}},
            {"type": 2, "name": "Note", "secureNote": {}}
        ]}"#;
        let logins = read_text(json).unwrap();
        assert_eq!(logins.len(), 2);
        assert_eq!((logins[0].title.as_str(), logins[0].url.as_str(), logins[0].notes.as_str()), ("Site", "https://site.example", "n"));
        assert_eq!((logins[1].username.as_str(), logins[1].password.as_str(), logins[1].url.as_str()), ("", "1234", ""));
        for refused in [r#"{"encrypted": true, "items": []}"#, r#"{"encrypted": "true", "items": [{"type": 1, "name": "a", "login": {"password": "p"}}]}"#,
            r#"{"items": [{"type": 1, "name": " ", "login": {"password": "p"}}]}"#, r#"{"items": [{"type": 1, "name": "a"}]}"#,
            r#"{"items": [7]}"#, r#"{"items": []}"#, r#"{"items": {}}"#, "{not json"] {
            assert_eq!(read_text(refused), Err(ImportError::Unreadable), "{refused}");
        }
    }

    #[test]
    fn utf16_exports_with_a_byte_order_mark_decode() {
        let text = "url,username,password\nhttps://a.example,mé,pw\n";
        let mut little = vec![0xFF, 0xFE];
        little.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let mut big = vec![0xFE, 0xFF];
        big.extend(text.encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(decode(&little).unwrap().as_str(), text);
        assert_eq!(decode(&big).unwrap().as_str(), text);
        assert_eq!(decode(&[0xEF, 0xBB, 0xBF, b'a']).unwrap().as_str(), "a");
        assert_eq!(decode(&[0xC3, 0x28]), Err(ImportError::Unreadable));
        assert_eq!(decode(&[0xFF, 0xFE, 0x61]), Err(ImportError::Unreadable), "half a character");
        assert_eq!(decode(&[0xFF, 0xFE, 0x00, 0xD8]), Err(ImportError::Unreadable), "half a surrogate pair");
        assert_eq!(decode(&vec![b'a'; MAX_CHARS]).map(|text| text.len()), Ok(MAX_CHARS));
        assert_eq!(decode(&vec![b'a'; MAX_CHARS + 1]), Err(ImportError::TooLarge));
        let (rows, logins) = open(&little, None).unwrap();
        assert_eq!((rows, logins[0].username.as_str()), (1, "mé"));
    }

    #[test]
    fn origins_match_android_exactly() {
        assert_eq!(https_origin("https://Mail.Example.com:443/inbox?x=1").as_deref(), Some("https://mail.example.com"));
        assert_eq!(https_origin("HTTPS://example.com:8443/").as_deref(), Some("https://example.com:8443"));
        assert_eq!(https_origin("https://example.com:/a#b").as_deref(), Some("https://example.com"));
        assert_eq!(https_origin("https://10.0.0.1/admin").as_deref(), Some("https://10.0.0.1"));
        assert_eq!(https_origin("https://example.com/ü?q=[1]%20").as_deref(), Some("https://example.com"));
        for refused in ["http://example.com", "https://user@example.com", "https://localhost", "https://example.com./", "https://[::1]/",
            "https://exa mple.com", "https:\\\\example.com", "https://bücher.example/", "https://my_host.example", "https://-a.example",
            "https://example.123", "https://a..example", "https://example.com:0", "https://example.com:65536", "https://example.com:x",
            "https://example.com/a|b", "https://example.com/%zz", "https://example.com/a#b#c", "https://example.com/[x]", "https:example.com"] {
            assert_eq!(https_origin(refused), None, "{refused}");
        }
        assert_eq!(login_key("  Example.com/Login ", "Me"), Some(("example.com/login".to_owned(), "Me".to_owned())));
        assert_eq!(login_key("https://Example.com/x", "Me"), Some(("https://example.com".to_owned(), "Me".to_owned())));
        assert_eq!(login_key(" ", "me"), None);
    }

    #[test]
    fn later_rows_win_per_website_and_username() {
        let unique = deduplicate(vec![
            login("https://a.example/one", "me", "old"),
            login("https://A.example/two", "me", "new"),
            login("https://a.example", "you", "pw"),
            login("", "me", "x"),
            login("", "me", "x"),
            login("", "me", "y"),
        ]);
        assert_eq!(unique.iter().map(|l| l.password.as_str()).collect::<Vec<_>>(), ["new", "pw", "x", "y"]);
    }

    #[test]
    fn the_review_sorts_logins_by_what_the_import_would_do() {
        let logins = vec![
            login("https://new.example", "me", "pw"),
            login("https://same.example/login", "me", "same"),
            login("https://changed.example", "me", "fresh"),
            login("https://twice.example", "me", "pw"),
        ];
        let vault = vec![
            saved("s1", "https://same.example", "me", "same"),
            saved("s2", "https://changed.example/", "me", "stale"),
            saved("s3", "https://twice.example", "me", "a"),
            saved("s4", "https://twice.example/x", "me", "b"),
            saved("s5", "https://elsewhere.example", "me", "c"),
        ];
        let (planned, token) = plan(&logins, &vault);
        assert_eq!(planned, [(Status::New, None), (Status::AlreadySaved, None), (Status::PasswordDiffers, Some("s2".to_owned())), (Status::Ambiguous, None)]);
        let review = review(5, &logins, &vault);
        assert_eq!((review.rows, review.duplicate_rows, review.new, review.already_saved, review.password_differs, review.ambiguous), (5, 1, 1, 1, 1, 1));
        assert_eq!(review.items.iter().map(|item| (item.row, item.status)).collect::<Vec<_>>(),
            [(0, Status::New), (1, Status::AlreadySaved), (2, Status::PasswordDiffers), (3, Status::Ambiguous)]);
        assert_eq!(review.token, token);
        let changed = |edit: &dyn Fn(&mut Vec<SavedLogin>)| {
            let mut copy: Vec<SavedLogin> = vault.iter().map(|login| saved(&login.id, &login.url, &login.username, &login.password)).collect();
            edit(&mut copy);
            plan(&logins, &copy).1
        };
        assert_eq!(changed(&|_| {}), token);
        assert_ne!(changed(&|vault| vault[1].password = Zeroizing::new("edited".into())), token, "a matched password changed");
        assert_ne!(changed(&|vault| vault[0].updated_at = 6), token, "a matched login was edited");
        assert_ne!(changed(&|vault| { vault.remove(3); }), token, "a match was deleted");
        assert_ne!(changed(&|vault| vault.push(saved("s6", "https://new.example", "me", "x"))), token, "a match was added");
        assert_eq!(changed(&|vault| vault[4].password = Zeroizing::new("other".into())), token, "an unrelated login doesn't matter");
        assert!(SavedLogin::from_entry(&serde_json::json!({"id": "c", "type": "CARD"})).is_none());
    }

    #[test]
    fn logins_without_a_website_match_by_title_and_username() {
        let mut imported = login("", "me", "pw");
        imported.title = "Router".into();
        let mut stored = saved("s1", "", "me", "old");
        stored.title = "Router".into();
        assert_eq!(plan(&[imported], &[stored]).0, [(Status::PasswordDiffers, Some("s1".to_owned()))]);
    }

    #[test]
    fn previews_serialize_for_the_dialog() {
        let mapping = Preview::Mapping { columns: vec![ColumnPreview { header: "site".into(), sample_shape: "••••".into() }], suggested: ColumnMapping::default() };
        assert_eq!(serde_json::to_value(&mapping).unwrap(), serde_json::json!({"kind": "mapping",
            "columns": [{"header": "site", "sampleShape": "••••"}], "suggested": {"title": null, "website": null, "username": null, "password": null, "notes": null}}));
        let review = Preview::Review(review(1, &[login("https://a.example", "me", "pw")], &[]));
        let value = serde_json::to_value(&review).unwrap();
        assert_eq!((value["kind"].as_str(), value["new"].as_u64(), value["items"][0]["status"].as_str()), (Some("review"), Some(1), Some("new")));
        let choices: Choices = serde_json::from_value(serde_json::json!({"token": "t", "useImported": [2]})).unwrap();
        assert_eq!((choices.skip_new.len(), choices.use_imported.as_slice()), (0, &[2][..]));
    }
}
