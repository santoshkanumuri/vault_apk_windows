//! Authenticator import, ported from Android's `AuthenticatorTransfer.kt`, `AuthenticatorImport.kt`
//! and `Totp.parse`, with the same limits and messages:
//!
//! - a text file with one `otpauth://totp` link per line (1 to 100 lines),
//! - a Google Authenticator transfer QR (`otpauth-migration://offline?data=...`, one page of a
//!   batch) or a standard TOTP setup QR,
//! - a Zoho OneAuth encrypted export (`oneauth_04`: PBKDF2-HMAC-SHA256, 100,000 rounds, AES-GCM).
//!
//! Nothing here keeps state: the dialog sends every page it has read each time, so the review and
//! the import read the same pages. Parser errors never quote what they read, since it can hold a
//! setup key.

use std::collections::BTreeMap;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::Aead,
};
use base64::{
    Engine,
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Android imports up to 100 codes at a time.
pub const MAX_ACCOUNTS: usize = 100;
/// Android reads export files up to 1 MiB.
pub const MAX_FILE_CHARS: usize = 1_048_576;
const MAX_QR_CHARS: usize = 16_384;
const MAX_URI_CHARS: usize = 4096;
const MAX_NAME: usize = 200;
const ONE_AUTH_ROUNDS: u32 = 100_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("Couldn't read this transfer QR. HOTP and unsupported code formats cannot be imported.")]
    Qr,
    #[error("Use a OneAuth oneauth_04 JSON export or a text file with one otpauth://totp link per line.")]
    File,
    #[error("Couldn't decrypt this OneAuth export. Check its password and format.")]
    OneAuth,
    #[error("This import belongs to a different transfer. Clear the current batch first.")]
    OtherTransfer,
    #[error("Import up to 100 codes at a time. Export a smaller set.")]
    TooMany,
    #[error("Scan the remaining QR pages to continue.")]
    Incomplete,
    #[error("Choose an export first.")]
    Empty,
}

/// One account to import (Android `TotpSetup`). The setup key is wiped when it's dropped.
pub struct Setup {
    pub issuer: String,
    pub account: String,
    /// Base32, upper case, without padding.
    pub secret: Zeroizing<String>,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
}

impl std::fmt::Debug for Setup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Setup(redacted)")
    }
}

/// One QR page or file (Android `AuthenticatorTransferPage`). A file or a single QR is a whole
/// batch of one page.
#[derive(Debug)]
pub struct Page {
    pub accounts: Vec<Setup>,
    pub batch_id: i32,
    pub batch_size: i32,
    pub batch_index: i32,
}

impl Page {
    fn single(accounts: Vec<Setup>) -> Self {
        Self { accounts, batch_id: 0, batch_size: 1, batch_index: 0 }
    }
}

/// What the dialog read: a QR's text, a text file, or a OneAuth export and its password.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Source {
    Qr { text: String },
    Text { text: String },
    #[serde(rename = "oneAuth")]
    OneAuth { text: String, password: String },
}

impl Drop for Source {
    fn drop(&mut self) {
        match self {
            Source::Qr { text } | Source::Text { text } => text.zeroize(),
            Source::OneAuth { text, password } => {
                text.zeroize();
                password.zeroize();
            }
        }
    }
}

/// The pages read so far, in batch order.
#[derive(Debug)]
pub struct Collected {
    pub accounts: Vec<Setup>,
    pub pages: usize,
    pub expected: usize,
}

impl Collected {
    pub fn complete(&self) -> bool {
        self.pages == self.expected
    }
}

/// Reads every source and puts the pages together as Android's settings page does: every page
/// must come from the same batch, a later page with the same index replaces the earlier one, and
/// all pages together hold at most 100 codes.
pub fn collect(sources: &[Source]) -> Result<Collected, ImportError> {
    if sources.is_empty() {
        return Err(ImportError::Empty);
    }
    let mut pages: BTreeMap<i32, Page> = BTreeMap::new();
    let mut batch = (0, 1);
    for source in sources {
        let page = match source {
            Source::Qr { text } => parse_qr(text).ok_or(ImportError::Qr)?,
            Source::Text { text } => parse_text(text).ok_or(ImportError::File)?,
            Source::OneAuth { text, password } => parse_one_auth(text, password).ok_or(ImportError::OneAuth)?,
        };
        if !pages.is_empty() && (page.batch_id != batch.0 || page.batch_size != batch.1) {
            return Err(ImportError::OtherTransfer);
        }
        let others: usize = pages.iter().filter(|(index, _)| **index != page.batch_index).map(|(_, page)| page.accounts.len()).sum();
        if others + page.accounts.len() > MAX_ACCOUNTS {
            return Err(ImportError::TooMany);
        }
        batch = (page.batch_id, page.batch_size);
        pages.insert(page.batch_index, page);
    }
    let count = pages.len();
    Ok(Collected {
        accounts: pages.into_values().flat_map(|page| page.accounts).collect(),
        pages: count,
        expected: batch.1 as usize,
    })
}

/// Android `parseAuthenticatorTransferText`: one `otpauth://totp` link per line.
pub fn parse_text(value: &str) -> Option<Page> {
    if utf16_len(value) > MAX_FILE_CHARS {
        return None;
    }
    let lines: Vec<&str> = kotlin_lines(value).map(str::trim).filter(|line| !line.is_empty()).collect();
    if !(1..=MAX_ACCOUNTS).contains(&lines.len()) {
        return None;
    }
    Some(Page::single(lines.into_iter().map(parse_otpauth).collect::<Option<_>>()?))
}

/// Android `parseAuthenticatorTransferQr`: a standard setup QR, or one page of a Google
/// Authenticator transfer.
pub fn parse_qr(value: &str) -> Option<Page> {
    if utf16_len(value) > MAX_QR_CHARS {
        return None;
    }
    if value.get(..10).is_some_and(|start| start.eq_ignore_ascii_case("otpauth://")) {
        return Some(Page::single(vec![parse_otpauth(value)?]));
    }
    let uri = Uri::parse(kotlin_trim(value))?;
    if uri.scheme != "otpauth-migration" || uri.host != Some("offline") || uri.fragment {
        return None;
    }
    let query = uri.query.unwrap_or("");
    let (key, data) = query.split_once('=')?;
    if query.contains('&') || key != "data" {
        return None;
    }
    let encoded = Zeroizing::new(url_decode(&data.replace('+', "%2B"))?);
    let bytes = Zeroizing::new(java_base64().decode(encoded.as_bytes()).ok()?);
    if bytes.len() > MAX_QR_CHARS {
        return None;
    }
    let mut input = Protobuf::new(&bytes);
    let mut accounts = Vec::new();
    let (mut version, mut batch_size, mut batch_index, mut batch_id) = (0, 1, 0, 0);
    loop {
        match input.tag()? {
            0 => break,
            10 => {
                if accounts.len() >= MAX_ACCOUNTS {
                    return None;
                }
                accounts.push(parse_transfer_account(input.bytes()?)?);
            }
            16 => version = input.int32()?,
            24 => batch_size = input.int32()?,
            32 => batch_index = input.int32()?,
            40 => batch_id = input.int32()?,
            tag => {
                if !input.skip(tag, 0)? {
                    return None;
                }
            }
        }
    }
    let valid = version == 1 && !accounts.is_empty() && (1..=100).contains(&batch_size) && (0..batch_size).contains(&batch_index);
    valid.then_some(Page { accounts, batch_id, batch_size, batch_index })
}

/// One `OtpParameters` message of a transfer QR.
fn parse_transfer_account(bytes: &[u8]) -> Option<Setup> {
    let mut input = Protobuf::new(bytes);
    let mut secret = Zeroizing::new(Vec::new());
    let (mut name, mut issuer) = (String::new(), String::new());
    let (mut algorithm, mut digits, mut kind) = (1, 1, 0);
    loop {
        match input.tag()? {
            0 => break,
            10 => secret = Zeroizing::new(input.bytes()?.to_vec()),
            18 => name = std::str::from_utf8(input.bytes()?).ok()?.to_owned(),
            26 => issuer = std::str::from_utf8(input.bytes()?).ok()?.to_owned(),
            32 => algorithm = input.int32()?,
            40 => digits = input.int32()?,
            48 => kind = input.int32()?,
            tag => {
                if !input.skip(tag, 0)? {
                    return None;
                }
            }
        }
    }
    // Type 2 is TOTP; HOTP counters can't be imported.
    if kind != 2 || !(10..=640).contains(&secret.len()) || name.trim().is_empty() || utf16_len(&name) > MAX_NAME || utf16_len(&issuer) > MAX_NAME {
        return None;
    }
    if name.chars().chain(issuer.chars()).any(iso_control) {
        return None;
    }
    // Kotlin `substringAfter(':')`: after the first colon, even when the issuer holds one.
    let account = match name.split_once(':') {
        Some((_, rest)) if !issuer.trim().is_empty() && name.starts_with(&format!("{issuer}:")) => rest.trim(),
        _ => name.trim(),
    };
    if account.is_empty() {
        return None;
    }
    let algorithm = match algorithm {
        0 | 1 => "SHA1",
        2 => "SHA256",
        3 => "SHA512",
        _ => return None,
    };
    let digits = match digits {
        0 | 1 => 6,
        2 => 8,
        _ => return None,
    };
    let secret = Zeroizing::new(encode_base32(&secret));
    validate(&secret, algorithm, digits, 30)?;
    Some(Setup { issuer, account: account.to_owned(), secret, algorithm: algorithm.to_owned(), digits, period: 30 })
}

/// Android `Totp.parse`: a standard `otpauth://totp` setup link.
pub fn parse_otpauth(value: &str) -> Option<Setup> {
    if utf16_len(value) > MAX_URI_CHARS {
        return None;
    }
    let uri = Uri::parse(kotlin_trim(value))?;
    if !uri.scheme.eq_ignore_ascii_case("otpauth") || !uri.host.is_some_and(|host| host.eq_ignore_ascii_case("totp")) || uri.fragment {
        return None;
    }
    let mut params: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    for part in uri.query.unwrap_or("").split('&') {
        let (key, value) = part.split_once('=')?;
        if params.insert(url_decode(key)?, Zeroizing::new(url_decode(value)?)).is_some() {
            return None;
        }
    }
    let label = url_decode(&uri.path.strip_prefix('/').unwrap_or(uri.path).replace('+', "%2B"))?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (issuer.trim(), account.trim()),
        None => ("", label.trim()),
    };
    let issuer = params.get("issuer").map(|issuer| issuer.trim()).filter(|issuer| !issuer.is_empty()).unwrap_or(label_issuer);
    if !label_issuer.is_empty() && label_issuer != issuer {
        return None;
    }
    if account.is_empty() || utf16_len(account) > MAX_NAME || utf16_len(issuer) > MAX_NAME {
        return None;
    }
    if issuer.chars().chain(account.chars()).any(iso_control) {
        return None;
    }
    let secret = Zeroizing::new(normalize_secret(params.get("secret")?)?);
    let algorithm = params.get("algorithm").map_or("SHA1".to_owned(), |algorithm| algorithm.to_uppercase());
    let digits = params.get("digits").map_or(Some(6), |digits| digits.parse::<i32>().ok())?;
    let period = params.get("period").map_or(Some(30), |period| period.parse::<i32>().ok())?;
    let (digits, period) = (u32::try_from(digits).ok()?, u32::try_from(period).ok()?);
    validate(&secret, &algorithm, digits, period)?;
    Some(Setup { issuer: issuer.to_owned(), account: account.to_owned(), secret, algorithm, digits, period })
}

/// Android `isEncryptedOneAuthExport`.
pub fn is_one_auth_export(value: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(value)
        .ok()
        .is_some_and(|envelope| envelope.get("format").and_then(serde_json::Value::as_str) == Some("oneauth_04"))
}

/// Android `parseEncryptedOneAuthExport`.
pub fn parse_one_auth(value: &str, password: &str) -> Option<Page> {
    if utf16_len(value) > MAX_FILE_CHARS {
        return None;
    }
    let envelope: serde_json::Value = serde_json::from_str(value).ok()?;
    if envelope.get("format")?.as_str()? != "oneauth_04" || !non_negative_long(envelope.get("nonce")?) {
        return None;
    }
    let salt = Zeroizing::new(java_base64().decode(envelope.get("enc_salt")?.as_str()?).ok()?);
    let data = Zeroizing::new(java_base64().decode(envelope.get("data")?.as_str()?).ok()?);
    if salt.len() != 12 || !(29..=MAX_FILE_CHARS).contains(&data.len()) {
        return None;
    }
    let key = pbkdf2_sha256(password.as_bytes(), &salt, ONE_AUTH_ROUNDS);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).ok()?;
    let plain = Zeroizing::new(cipher.decrypt(Nonce::from_slice(&data[..12]), &data[12..]).ok()?);
    let root: serde_json::Value = serde_json::from_slice(&plain).ok()?;
    let mut accounts = Vec::new();
    for group in root.get("groups")?.as_array()? {
        for item in group.as_object()?.get("tpa_secrets")?.as_array()? {
            if accounts.len() >= MAX_ACCOUNTS {
                return None;
            }
            let text = |name: &str| item.get(name).and_then(json_text);
            if !text("type")?.eq_ignore_ascii_case("totp") {
                return None;
            }
            let issuer = text("issuer")?.trim().to_owned();
            let label = text("label")?.trim().to_owned();
            if label.is_empty() || utf16_len(&label) > MAX_NAME || utf16_len(&issuer) > MAX_NAME {
                return None;
            }
            if issuer.chars().chain(label.chars()).any(iso_control) {
                return None;
            }
            let secret = Zeroizing::new(normalize_secret(&Zeroizing::new(text("secret")?))?);
            let algorithm = text("algorithm")?.to_uppercase();
            let digits = u32::try_from(json_int(item.get("digits")?)?).ok()?;
            let period = u32::try_from(json_int(item.get("period")?)?).ok()?;
            validate(&secret, &algorithm, digits, period)?;
            accounts.push(Setup { issuer, account: label, secret, algorithm, digits, period });
        }
    }
    (!accounts.is_empty()).then(|| Page::single(accounts))
}

fn non_negative_long(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Number(number) => number.as_i64().map(|n| n >= 0).or(number.as_f64().map(|n| n >= 0.0)).unwrap_or(false),
        serde_json::Value::String(text) => text.trim().parse::<i64>().is_ok_and(|n| n >= 0),
        _ => false,
    }
}

/// Gson `getAsString` on a primitive.
fn json_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Gson `getAsInt` on a primitive.
fn json_int(value: &serde_json::Value) -> Option<i32> {
    match value {
        serde_json::Value::Number(number) => i32::try_from(number.as_i64()?).ok(),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

/// Android `Totp.normalizeSecret`: Base32 with whitespace, case and padding ignored, 16 to 1024
/// characters, in its one canonical spelling.
pub fn normalize_secret(value: &str) -> Option<String> {
    let mut text: String = value.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    let trimmed = text.trim_end_matches('=').len();
    text.truncate(trimmed);
    if !(16..=1024).contains(&text.len()) || !text.bytes().all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte)) {
        text.zeroize();
        return None;
    }
    let decoded = Zeroizing::new(decode_base32(&text)?);
    let canonical = Zeroizing::new(encode_base32(&decoded));
    if *canonical != text {
        text.zeroize();
        return None;
    }
    Some(text)
}

/// Android `Totp.validate`.
fn validate(secret: &str, algorithm: &str, digits: u32, period: u32) -> Option<()> {
    let ok = normalize_secret(secret).map(Zeroizing::new).is_some()
        && matches!(algorithm, "SHA1" | "SHA256" | "SHA512")
        && (6..=8).contains(&digits)
        && (1..=300).contains(&period);
    ok.then_some(())
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn encode_base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    buffer.zeroize();
    out
}

/// Whole bytes only; a length a padded Base32 string can't have is refused, as BouncyCastle does.
fn decode_base32(text: &str) -> Option<Vec<u8>> {
    if matches!(text.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let digit = BASE32.iter().position(|letter| *letter == byte)? as u32;
        buffer = ((buffer << 5) | digit) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    buffer.zeroize();
    Some(out)
}

/// PBKDF2-HMAC-SHA256 with a 32-byte result: one block, as Java's `PBKDF2WithHmacSHA256` makes a
/// 256-bit key (the password as UTF-8).
fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> Zeroizing<[u8; 32]> {
    let mac = <Hmac<Sha256> as Mac>::new_from_slice(password).expect("HMAC takes any key length");
    let mut first = mac.clone();
    first.update(salt);
    first.update(&1u32.to_be_bytes());
    let mut block = Zeroizing::new(<[u8; 32]>::from(first.finalize().into_bytes()));
    let mut result = Zeroizing::new(*block);
    for _ in 1..rounds {
        let mut next = mac.clone();
        next.update(block.as_slice());
        *block = next.finalize().into_bytes().into();
        for (out, byte) in result.iter_mut().zip(block.iter()) {
            *out ^= byte;
        }
    }
    result
}

/// Java's `Base64.getDecoder()`: the standard alphabet, padding optional.
fn java_base64() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent).with_decode_allow_trailing_bits(true),
    )
}

/// Java `URLDecoder.decode(value, "UTF-8")`: `+` is a space and `%XX` runs are UTF-8 bytes. A `%`
/// without two hex digits is refused.
fn url_decode(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut bytes: Vec<u8> = Vec::new();
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let high = chars.next()?.to_digit(16)?;
            let low = chars.next()?.to_digit(16)?;
            bytes.push((high * 16 + low) as u8);
            if chars.peek() == Some(&'%') {
                continue;
            }
            out.push_str(&String::from_utf8_lossy(&bytes));
            bytes.zeroize();
            bytes.clear();
        } else {
            out.push(if c == '+' { ' ' } else { c });
        }
    }
    if !bytes.is_empty() {
        out.push_str(&String::from_utf8_lossy(&bytes));
        bytes.zeroize();
    }
    Some(out)
}

/// The parts of `scheme://authority/path?query#fragment` that Android's checks read from
/// `java.net.URI`, with the characters `java.net.URI` refuses refused.
struct Uri<'a> {
    scheme: &'a str,
    /// `None` when the authority holds user info or a port, as `URI.getHost` checks fail then.
    host: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
    fragment: bool,
}

impl<'a> Uri<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        if !value.chars().all(uri_char) || !escapes_valid(value) {
            return None;
        }
        let (scheme, rest) = value.split_once(':')?;
        let mut scheme_chars = scheme.chars();
        if !scheme_chars.next()?.is_ascii_alphabetic() || !scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            return None;
        }
        let (rest, fragment) = match rest.split_once('#') {
            Some((rest, _)) => (rest, true),
            None => (rest, false),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((rest, query)) => (rest, Some(query)),
            None => (rest, None),
        };
        let rest = rest.strip_prefix("//")?;
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, ""),
        };
        let host = (!authority.is_empty() && !authority.contains(['@', ':'])).then_some(authority);
        Some(Self { scheme, host, path, query, fragment })
    }
}

/// Characters `java.net.URI` accepts: its ASCII set, and other characters that aren't controls or
/// spaces. Brackets belong only to an IPv6 host, which these links never have.
fn uri_char(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric() || "-_.!~*'();/?:@&=+$,%#".contains(c)
    } else {
        !iso_control(c) && !c.is_whitespace()
    }
}

fn escapes_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.iter().enumerate().all(|(index, byte)| {
        *byte != b'%' || (bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit) && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit))
    })
}

/// Kotlin `Char.isISOControl`.
fn iso_control(c: char) -> bool {
    c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c)
}

/// Kotlin `String.length`: UTF-16 code units.
fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

/// Kotlin `String.trim()` on a URI string: drops leading and trailing characters up to a space.
fn kotlin_trim(value: &str) -> &str {
    value.trim_matches(|c: char| c <= ' ')
}

/// Kotlin `lineSequence`: lines end with `\r\n`, `\n` or `\r`.
fn kotlin_lines(value: &str) -> impl Iterator<Item = &str> {
    value.split('\n').flat_map(|line| line.split('\r'))
}

/// A minimal protobuf reader with `CodedInputStream`'s rules for what it reads here.
struct Protobuf<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Protobuf<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in 0..10 {
            let byte = *self.data.get(self.position)?;
            self.position += 1;
            value |= u64::from(byte & 0x7f) << (7 * shift);
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    /// 0 at the end; a tag with field number 0 is malformed.
    fn tag(&mut self) -> Option<u32> {
        if self.position == self.data.len() {
            return Some(0);
        }
        let tag = self.varint()? as u32;
        (tag >> 3 != 0).then_some(tag)
    }

    fn int32(&mut self) -> Option<i32> {
        Some(self.varint()? as i32)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        // `readRawVarint32`: the low 32 bits; a negative length is malformed.
        let length = usize::try_from(self.varint()? as u32 as i32).ok()?;
        let end = self.position.checked_add(length)?;
        let slice = self.data.get(self.position..end)?;
        self.position = end;
        Some(slice)
    }

    /// `CodedInputStream.skipField`: false for an end-group tag, `None` for malformed data.
    fn skip(&mut self, tag: u32, depth: u32) -> Option<bool> {
        match tag & 7 {
            0 => self.varint().map(|_| true),
            1 => self.advance(8),
            2 => self.bytes().map(|_| true),
            3 => {
                if depth >= 100 {
                    return None;
                }
                loop {
                    let inner = self.tag()?;
                    if inner == 0 {
                        return None;
                    }
                    if !self.skip(inner, depth + 1)? {
                        return (inner == ((tag >> 3) << 3 | 4)).then_some(true);
                    }
                }
            }
            4 => Some(false),
            5 => self.advance(4),
            _ => None,
        }
    }

    fn advance(&mut self, count: usize) -> Option<bool> {
        let end = self.position.checked_add(count)?;
        (end <= self.data.len()).then(|| self.position = end).map(|()| true)
    }
}

/// How Android's `authenticatorImportStatuses` sees one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    New,
    AlreadySaved,
    /// A saved code with the same name has a different setup key: skipped.
    Conflict,
}

/// A saved code, as the import compares it.
pub struct Saved {
    title: String,
    account: String,
    secret: Zeroizing<String>,
    algorithm: String,
    digits: u64,
    period: u64,
}

impl Saved {
    pub fn from_entry(entry: &serde_json::Value) -> Option<Self> {
        if entry.get("type")?.as_str()? != "AUTHENTICATOR" {
            return None;
        }
        let text = |name: &str| entry.get(name).and_then(serde_json::Value::as_str).unwrap_or("");
        Some(Self {
            title: normalized(text("title")),
            account: normalized(text("primaryValue")),
            secret: Zeroizing::new(compare_secret(text("secondaryValue"))),
            algorithm: text("totpAlgorithm").to_uppercase(),
            digits: entry.get("totpDigits").and_then(serde_json::Value::as_u64).unwrap_or(6),
            period: entry.get("totpPeriod").and_then(serde_json::Value::as_u64).unwrap_or(30),
        })
    }
}

fn normalized(value: &str) -> String {
    value.trim().to_lowercase()
}

fn compare_secret(value: &str) -> String {
    let mut text: String = value.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    let trimmed = text.trim_end_matches('=').len();
    text.truncate(trimmed);
    text
}

/// Android `authenticatorImportStatuses`: already saved when a code has the same setup key and
/// settings; a conflict when a code with the same name and account has another key; otherwise new.
/// A new account counts as saved for the accounts after it, so a repeat in the same import is
/// already saved.
pub fn statuses(saved: Vec<Saved>, incoming: &[Setup]) -> Vec<Status> {
    let mut known = saved;
    incoming
        .iter()
        .map(|account| {
            let title = if account.issuer.trim().is_empty() { &account.account } else { &account.issuer };
            let candidate = Saved {
                title: normalized(title),
                account: normalized(&account.account),
                secret: Zeroizing::new(compare_secret(&account.secret)),
                algorithm: account.algorithm.to_uppercase(),
                digits: u64::from(account.digits),
                period: u64::from(account.period),
            };
            let status = if known.iter().any(|it| {
                *it.secret == *candidate.secret && it.algorithm == candidate.algorithm && it.digits == candidate.digits && it.period == candidate.period
            }) {
                Status::AlreadySaved
            } else if known.iter().any(|it| it.title == candidate.title && it.account == candidate.account) {
                Status::Conflict
            } else {
                Status::New
            };
            if status == Status::New {
                known.push(candidate);
            }
            status
        })
        .collect()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewItem {
    pub issuer: String,
    pub account: String,
    pub status: Status,
}

/// What the dialog shows before the import: no setup keys.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    pub pages: usize,
    pub expected: usize,
    pub items: Vec<ReviewItem>,
    pub new: usize,
    pub already_saved: usize,
    pub conflicts: usize,
}

pub fn review(collected: &Collected, saved: Vec<Saved>) -> Review {
    let statuses = statuses(saved, &collected.accounts);
    let count = |status| statuses.iter().filter(|it| **it == status).count();
    Review {
        pages: collected.pages,
        expected: collected.expected,
        new: count(Status::New),
        already_saved: count(Status::AlreadySaved),
        conflicts: count(Status::Conflict),
        items: collected
            .accounts
            .iter()
            .zip(&statuses)
            .map(|(account, status)| ReviewItem { issuer: account.issuer.clone(), account: account.account.clone(), status: *status })
            .collect(),
    }
}

/// Android `AuthenticatorImportResult`.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub added: usize,
    pub already_saved: usize,
    pub conflicts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "JBSWY3DPEHPK3PXP";

    fn varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn field(number: u64, bytes: &[u8], out: &mut Vec<u8>) {
        varint(number << 3 | 2, out);
        varint(bytes.len() as u64, out);
        out.extend_from_slice(bytes);
    }

    fn number(number: u64, value: u64, out: &mut Vec<u8>) {
        varint(number << 3, out);
        varint(value, out);
    }

    /// A Google Authenticator transfer QR's text, as the app writes it.
    fn transfer(accounts: &[(&[u8], &str, &str, u64)], batch: (u64, u64, u64)) -> String {
        let mut payload = Vec::new();
        for (secret, name, issuer, kind) in accounts {
            let mut account = Vec::new();
            field(1, secret, &mut account);
            field(2, name.as_bytes(), &mut account);
            field(3, issuer.as_bytes(), &mut account);
            number(4, 1, &mut account);
            number(5, 1, &mut account);
            number(6, *kind, &mut account);
            field(1, &account, &mut payload);
        }
        number(2, 1, &mut payload);
        number(3, batch.1, &mut payload);
        number(4, batch.2, &mut payload);
        number(5, batch.0, &mut payload);
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        format!("otpauth-migration://offline?data={}", encoded.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D"))
    }

    #[test]
    fn setup_links_read_as_on_android() {
        let setup = parse_otpauth(&format!("otpauth://totp/Example:me@example.com?secret={}&issuer=Example&digits=8&period=60&algorithm=sha256", KEY.to_lowercase())).unwrap();
        assert_eq!((setup.issuer.as_str(), setup.account.as_str(), setup.secret.as_str()), ("Example", "me@example.com", KEY));
        assert_eq!((setup.algorithm.as_str(), setup.digits, setup.period), ("SHA256", 8, 60));

        let plain = parse_otpauth(&format!("  OTPAUTH://TOTP/Mail%20Box?secret={KEY}  ")).unwrap();
        assert_eq!((plain.issuer.as_str(), plain.account.as_str(), plain.algorithm.as_str(), plain.digits, plain.period), ("", "Mail Box", "SHA1", 6, 30));
        // A "+" in the label is a plus, as Android reads it; in the query it's a space.
        let plus = parse_otpauth(&format!("otpauth://totp/a+b?secret={KEY}&issuer=Big+Co")).unwrap();
        assert_eq!((plus.issuer.as_str(), plus.account.as_str()), ("Big Co", "a+b"));

        for refused in [
            format!("otpauth://hotp/Example?secret={KEY}&counter=1"),
            format!("otpauth://totp/Other:me?secret={KEY}&issuer=Example"),
            format!("otpauth://totp/me?secret={KEY}#fragment"),
            format!("otpauth://totp:80/me?secret={KEY}"),
            format!("otpauth://user@totp/me?secret={KEY}"),
            format!("otpauth://totp/me?secret={KEY}&secret={KEY}"),
            format!("otpauth://totp/me?secret={KEY}&digits=9"),
            format!("otpauth://totp/me?secret={KEY}&period=0"),
            format!("otpauth://totp/me?secret={KEY}&algorithm=MD5"),
            format!("otpauth://totp/me?secret={KEY}&flag"),
            format!("otpauth://totp/me me?secret={KEY}"),
            format!("otpauth://totp/me%2?secret={KEY}"),
            format!("otpauth://totp/?secret={KEY}"),
            "otpauth://totp/me?secret=SHORT".to_owned(),
            "otpauth://totp/me?secret=JBSWY3DPEHPK3PXPAB".to_owned(),
            "otpauth://totp/me?issuer=Example".to_owned(),
        ] {
            assert!(parse_otpauth(&refused).is_none(), "{refused}");
        }
    }

    #[test]
    fn setup_keys_must_be_canonical_base32() {
        assert_eq!(normalize_secret("jbsw y3dp ehpk 3pxp====").as_deref(), Some(KEY));
        assert!(normalize_secret("JBSWY3DPEHPK3PX").is_none(), "15 characters");
        assert!(normalize_secret("JBSWY3DPEHPK3PXPAB").is_none(), "trailing bits set");
        assert_eq!(normalize_secret("JBSWY3DPEHPK3PXPAA").as_deref(), Some("JBSWY3DPEHPK3PXPAA"));
        assert!(normalize_secret("JBSWY3DPEHPK3PX1").is_none(), "not Base32");
        assert!(normalize_secret("JBSWY3DPEHPK3PXPA").is_none(), "a length padding can't make");
        assert_eq!(encode_base32(b"Hello!\xde\xad\xbe\xef"), "JBSWY3DPEHPK3PXP");
        assert_eq!(decode_base32(KEY).unwrap(), b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn a_text_file_has_one_link_per_line() {
        let file = format!("\r\notpauth://totp/A:one?secret={KEY}\r\n\n  otpauth://totp/two?secret=GEZDGNBVGY3TQOJQ&issuer=B\r");
        let page = parse_text(&file).unwrap();
        assert_eq!(page.accounts.len(), 2);
        assert_eq!((page.batch_size, page.batch_index), (1, 0));
        assert_eq!(page.accounts[1].issuer, "B");
        assert!(parse_text(&format!("otpauth://totp/A:one?secret={KEY}\nnot a link")).is_none());
        assert!(parse_text("  \n ").is_none());
        let many = (0..101).map(|i| format!("otpauth://totp/n{i}?secret={KEY}")).collect::<Vec<_>>().join("\n");
        assert!(parse_text(&many).is_none());
    }

    #[test]
    fn google_authenticator_transfer_pages_read_and_join() {
        let secret = b"Hello!\xde\xad\xbe\xef";
        let first = transfer(&[(secret, "Example:me@example.com", "Example", 2), (b"0123456789", "plain", "", 2)], (7, 2, 0));
        let page = parse_qr(&first).unwrap();
        assert_eq!((page.batch_id, page.batch_size, page.batch_index), (7, 2, 0));
        assert_eq!((page.accounts[0].issuer.as_str(), page.accounts[0].account.as_str(), page.accounts[0].secret.as_str()), ("Example", "me@example.com", KEY));
        assert_eq!((page.accounts[1].issuer.as_str(), page.accounts[1].account.as_str()), ("", "plain"));

        let second = transfer(&[(b"abcdefghij", "Second", "Two", 2)], (7, 2, 1));
        let qr = |text: &str| Source::Qr { text: text.to_owned() };
        let half = collect(&[qr(&first)]).unwrap();
        assert!(!half.complete());
        let whole = collect(&[qr(&second), qr(&first), qr(&first)]).unwrap();
        assert!(whole.complete());
        assert_eq!(whole.accounts.iter().map(|a| a.account.as_str()).collect::<Vec<_>>(), ["me@example.com", "plain", "Second"]);

        let other = transfer(&[(b"abcdefghij", "Other", "", 2)], (8, 2, 1));
        assert_eq!(collect(&[qr(&first), qr(&other)]).unwrap_err(), ImportError::OtherTransfer);
        let file = Source::Text { text: format!("otpauth://totp/x?secret={KEY}") };
        assert_eq!(collect(&[qr(&first), file]).unwrap_err(), ImportError::OtherTransfer);

        // HOTP (type 1) can't be imported, and neither can a short key.
        assert!(parse_qr(&transfer(&[(secret, "hotp", "", 1)], (1, 1, 0))).is_none());
        assert!(parse_qr(&transfer(&[(b"short", "x", "", 2)], (1, 1, 0))).is_none());
        assert!(parse_qr(&transfer(&[(secret, "x", "", 2)], (1, 1, 1))).is_none(), "index outside the batch");
        assert!(parse_qr("otpauth-migration://offline?data=%%%").is_none());
        assert!(parse_qr("otpauth-migration://online?data=AA").is_none());
        assert_eq!(collect(&[qr("not a QR")]).unwrap_err(), ImportError::Qr);
        // A standard setup QR is a whole batch of one.
        assert_eq!(parse_qr(&format!("otpauth://totp/x?secret={KEY}")).unwrap().accounts.len(), 1);
    }

    #[test]
    fn unknown_protobuf_fields_are_skipped_and_bad_ones_refused() {
        let mut data = vec![0x50, 0x05]; // field 10, varint
        data.extend([0x5a, 0x01, 0x00]); // field 11, length 1
        data.extend([0x63, 0x08, 0x01, 0x64]); // field 12 group holding field 1 varint
        data.extend([0x6d, 1, 2, 3, 4]); // field 13, fixed32
        let mut input = Protobuf::new(&data);
        while let Some(tag) = input.tag().filter(|tag| *tag != 0) {
            assert_eq!(input.skip(tag, 0), Some(true));
        }
        assert_eq!(input.position, data.len());
        assert_eq!(Protobuf::new(&[0x63, 0x6c]).skip(0x63, 0), None, "group closed by another field");
        assert_eq!(Protobuf::new(&[0x0a, 0x05, 1]).bytes(), None, "length past the end");
        assert_eq!(Protobuf::new(&[0x02]).tag(), None, "field number 0");
    }

    /// A OneAuth `oneauth_04` export, sealed as the app does.
    fn one_auth(password: &str, plain: &str) -> String {
        let salt = [3u8; 12];
        let key = pbkdf2_sha256(password.as_bytes(), &salt, ONE_AUTH_ROUNDS);
        let nonce = [9u8; 12];
        let mut data = nonce.to_vec();
        data.extend(Aes256Gcm::new_from_slice(key.as_slice()).unwrap().encrypt(Nonce::from_slice(&nonce), plain.as_bytes()).unwrap());
        let engine = base64::engine::general_purpose::STANDARD;
        serde_json::json!({ "format": "oneauth_04", "nonce": 1, "enc_salt": engine.encode(salt), "data": engine.encode(data) }).to_string()
    }

    #[test]
    fn a_one_auth_export_opens_with_its_password() {
        let plain = serde_json::json!({ "groups": [
            { "tpa_secrets": [{ "type": "TOTP", "issuer": " Zoho ", "label": "me@zoho.com", "secret": KEY.to_lowercase(), "algorithm": "sha1", "digits": 6, "period": 30 }] },
            { "tpa_secrets": [{ "type": "totp", "issuer": "", "label": "plain", "secret": "GEZDGNBVGY3TQOJQ", "algorithm": "SHA512", "digits": "8", "period": 60 }] }
        ] }).to_string();
        let export = one_auth("export password", &plain);
        assert!(is_one_auth_export(&export));
        assert!(!is_one_auth_export("{\"format\":\"other\"}"));
        let page = parse_one_auth(&export, "export password").unwrap();
        assert_eq!(page.accounts.len(), 2);
        assert_eq!((page.accounts[0].issuer.as_str(), page.accounts[0].account.as_str(), page.accounts[0].secret.as_str()), ("Zoho", "me@zoho.com", KEY));
        assert_eq!((page.accounts[1].algorithm.as_str(), page.accounts[1].digits, page.accounts[1].period), ("SHA512", 8, 60));
        assert!(parse_one_auth(&export, "wrong password").is_none());
        let source = Source::OneAuth { text: export, password: "wrong password".to_owned() };
        assert_eq!(collect(&[source]).unwrap_err(), ImportError::OneAuth);
        let hotp = serde_json::json!({ "groups": [{ "tpa_secrets": [{ "type": "hotp", "issuer": "", "label": "x", "secret": KEY, "algorithm": "SHA1", "digits": 6, "period": 30 }] }] });
        assert!(parse_one_auth(&one_auth("p", &hotp.to_string()), "p").is_none());
    }

    #[test]
    fn pbkdf2_matches_the_rfc_7914_vector() {
        // RFC 7914 section 11: PBKDF2-HMAC-SHA256("passwd", "salt", 1), first 32 bytes.
        let key = pbkdf2_sha256(b"passwd", b"salt", 1);
        assert_eq!(hex::encode(key.as_slice()), "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
    }

    #[test]
    fn statuses_match_android() {
        let saved = |title: &str, account: &str, secret: &str| {
            Saved::from_entry(&serde_json::json!({
                "type": "AUTHENTICATOR", "title": title, "primaryValue": account, "secondaryValue": secret,
                "totpAlgorithm": "SHA1", "totpDigits": 6, "totpPeriod": 30
            }))
            .unwrap()
        };
        assert!(Saved::from_entry(&serde_json::json!({ "type": "PASSWORD" })).is_none());
        let setup = |issuer: &str, account: &str, secret: &str| Setup {
            issuer: issuer.to_owned(),
            account: account.to_owned(),
            secret: Zeroizing::new(secret.to_owned()),
            algorithm: "SHA1".to_owned(),
            digits: 6,
            period: 30,
        };
        let incoming = [
            setup("GitHub", "me", "jbsw y3dp ehpk 3pxp"),
            setup("github", " ME ", "GEZDGNBVGY3TQOJQ"),
            setup("", "new@example.com", "MFRGGZDFMZTWQ2LK"),
            setup("Other", "new@example.com", "MFRGGZDFMZTWQ2LK"),
            setup("", "new@example.com", "GEZDGNBVGY3TQOJQ"),
        ];
        let result = statuses(vec![saved("GitHub", "me", KEY)], &incoming);
        assert_eq!(result, [Status::AlreadySaved, Status::Conflict, Status::New, Status::AlreadySaved, Status::Conflict]);
    }
}
