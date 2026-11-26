//! "Restore from backup" in Settings: replaces this vault with what a `.pvault` backup holds
//! (pvault.rs), as Nuvori for Android's restore does (`VaultBackupManager.prepareRestore`, `parse`
//! and `commitRestore`).
//!
//! Opening a backup reads and checks the whole file before anything changes: the password opens
//! its key, every segment is authenticated through the end of the file, the archive holds
//! `vault.json` first and then exactly the photos it lists, and every item, folder, link, photo
//! and passkey passes the checks Android makes. Authenticators pass the checks this PC makes for
//! its own (totp.rs), which take every key Android does and the shorter keys this PC's editor
//! takes. Android writes the archive with Java's
//! `ZipOutputStream` (deflated members, their sizes after the data); this PC writes stored members.
//! Both are read. What the backup holds then waits in memory, in buffers that are wiped when
//! dropped, until the user replaces the vault or cancels, or the vault locks ([`forget`]).
//!
//! Replacing (`UnlockedVault::replace_with_backup`) keeps the items' IDs, as Android does, and
//! gives the vault a new vault ID. A PC in a sync group leaves it first
//! (`UnlockedVault::leave_group_before_restore`), so the old items can't sync back.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufRead, Read},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use rusqlite::{Connection, params};
use serde::Serialize;
use serde_json::{Map, Value, json};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{passkeys::VaultPasskey, pvault};

/// The largest backup file opened: the largest contents below, encrypted, with room to spare.
const MAX_FILE: u64 = 640 * 1024 * 1024;
/// As on Android: `vault.json`, one photo, and everything in the archive.
const MAX_METADATA: usize = 16 * 1024 * 1024;
const MAX_PHOTO: usize = 128 * 1024 * 1024;
const MAX_CONTENTS: usize = 512 * 1024 * 1024;
const ENTRY_TYPES: [&str; 6] = ["CARD", "QUESTION", "PASSWORD", "NOTE", "AUTHENTICATOR", "AUTOFILL"];
/// Item and folder IDs are UUIDs; anything much longer isn't from Nuvori.
const MAX_ID: usize = 256;
const CHUNK: usize = 1 << 20;

// ZIP: local file headers, then the central directory, which nothing here needs.
const LOCAL_HEADER: u32 = 0x0403_4b50;
const CENTRAL_HEADER: u32 = 0x0201_4b50;
const END_OF_ARCHIVE: u32 = 0x0605_4b50;
const DATA_DESCRIPTOR: u32 = 0x0807_4b50;
const FLAG_ENCRYPTED: u16 = 1;
const FLAG_DESCRIPTOR: u16 = 1 << 3;
const FLAG_STRONG_ENCRYPTION: u16 = 1 << 6;
const FLAG_MASKED_HEADER: u16 = 1 << 13;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const MAX_NAME: usize = 300;

const ITEM: &str = "an item in it is incomplete";
const FOLDER: &str = "a folder in it is incomplete";
const LINK: &str = "a folder link in it is incomplete";
const PHOTO: &str = "a photo in it is incomplete";
const PASSKEY: &str = "a passkey in it isn't valid";

#[derive(Debug, Error)]
pub enum RestoreError {
    #[error("This isn't a Nuvori backup, or a newer Nuvori made it.")]
    Unsupported,
    #[error("Wrong password, or the backup is damaged.")]
    WrongPasswordOrDamaged,
    #[error("The backup is damaged or incomplete.")]
    Damaged,
    #[error("The backup is too large to restore on this PC.")]
    TooLarge,
    #[error("This backup can't be restored: {0}.")]
    Invalid(&'static str),
    #[error("Couldn't read the backup file.")]
    Io(io::Error),
}

impl From<io::Error> for RestoreError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            // A segment that fails to authenticate, a file that ends early, a broken deflate stream.
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidInput => Self::Damaged,
            _ => Self::Io(error),
        }
    }
}

impl From<pvault::BackupError> for RestoreError {
    fn from(error: pvault::BackupError) -> Self {
        match error {
            pvault::BackupError::Unsupported => Self::Unsupported,
            pvault::BackupError::WrongPasswordOrDamaged => Self::WrongPasswordOrDamaged,
            pvault::BackupError::Io(error) => error.into(),
            _ => Self::Damaged,
        }
    }
}

/// What the backup holds, as the review shows it. Authenticators are items too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub items: usize,
    pub codes: usize,
    pub folders: usize,
    pub photos: usize,
    pub passkeys: usize,
}

/// What a restore does to this PC's sync group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncRole {
    /// Not in a sync group: nothing to tell anyone.
    None,
    /// A member: it leaves first, with a signed leave request the managing phone receives.
    Member,
    /// The managing device: it has nobody to leave to, so the restore is refused.
    Manager,
}

/// The review before anything is replaced.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    pub file_name: String,
    #[serde(flatten)]
    pub summary: Summary,
    pub sync: SyncRole,
}

struct Note {
    title: Zeroizing<String>,
    body: Zeroizing<String>,
    created_at: i64,
}

struct Entry {
    id: String,
    kind: &'static str,
    /// Android's `VaultEntry` JSON with exactly its fields, as this PC stores items.
    data_json: Zeroizing<String>,
    /// Notes also get their own row (`local_notes`).
    note: Option<Note>,
    updated_at: i64,
}

struct Group {
    id: String,
    name: String,
    notes: String,
    folder_type: &'static str,
}

struct Photo {
    id: String,
    entry_id: String,
    is_cover: bool,
    added_at: i64,
    mime_type: &'static str,
    bytes: Zeroizing<Vec<u8>>,
}

struct Passkey {
    id: String,
    rp_id: String,
    data_json: Zeroizing<String>,
}

/// A backup that passed every check, ready to replace the vault.
pub struct Plan {
    entries: Vec<Entry>,
    groups: Vec<Group>,
    /// (item ID, folder ID).
    links: Vec<(String, String)>,
    photos: Vec<Photo>,
    passkeys: Vec<Passkey>,
    appearance: Option<(String, String)>,
}

impl Plan {
    pub fn summary(&self) -> Summary {
        Summary {
            items: self.entries.len(),
            codes: self.entries.iter().filter(|entry| entry.kind == "AUTHENTICATOR").count(),
            folders: self.groups.len(),
            photos: self.photos.len(),
            passkeys: self.passkeys.len(),
        }
    }

    /// The backup's accent and background, when it has both (Android writes them since 2.2.4).
    pub fn appearance(&self) -> Option<(&str, &str)> {
        self.appearance.as_ref().map(|(accent, surface)| (accent.as_str(), surface.as_str()))
    }

    /// Writes everything into the item tables, which the caller has emptied in the same
    /// transaction, so a failure leaves the vault as it was.
    pub(crate) fn insert(&self, db: &Connection) -> rusqlite::Result<()> {
        for group in &self.groups {
            db.execute(
                "INSERT INTO local_groups (id, name, notes, folder_type) VALUES (?1, ?2, ?3, ?4)",
                params![group.id, group.name, group.notes, group.folder_type],
            )?;
        }
        for entry in &self.entries {
            match &entry.note {
                Some(note) => {
                    db.execute(
                        "INSERT INTO local_notes (id, title, body, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![entry.id, note.title.as_str(), note.body.as_str(), note.created_at, entry.updated_at],
                    )?;
                    db.execute(
                        "INSERT INTO local_note_details (id, data_json) VALUES (?1, ?2)",
                        params![entry.id, entry.data_json.as_str()],
                    )?;
                }
                None => {
                    db.execute(
                        "INSERT INTO local_entries (id, type, data_json, updated_at) VALUES (?1, ?2, ?3, ?4)",
                        params![entry.id, entry.kind, entry.data_json.as_str(), entry.updated_at],
                    )?;
                }
            }
        }
        for (entry_id, group_id) in &self.links {
            db.execute("INSERT INTO entry_groups (entry_id, group_id) VALUES (?1, ?2)", params![entry_id, group_id])?;
        }
        for passkey in &self.passkeys {
            db.execute(
                "INSERT INTO local_passkeys (id, rp_id, data_json) VALUES (?1, ?2, ?3)",
                params![passkey.id, passkey.rp_id, passkey.data_json.as_str()],
            )?;
        }
        for photo in &self.photos {
            db.execute(
                "INSERT INTO local_entry_photos (id, entry_id, mime_type, data, is_cover, added_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![photo.id, photo.entry_id, photo.mime_type, photo.bytes.as_slice(), photo.is_cover, photo.added_at],
            )?;
        }
        Ok(())
    }
}

// The file the user chose and the backup opened from it, between the steps of the dialog.

struct Pending {
    file: Option<PathBuf>,
    plan: Option<Plan>,
}

static PENDING: Mutex<Pending> = Mutex::new(Pending { file: None, plan: None });

fn pending() -> MutexGuard<'static, Pending> {
    PENDING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A new file: any backup opened before goes.
pub fn choose(file: PathBuf) {
    let mut pending = pending();
    pending.plan = None;
    pending.file = Some(file);
}

pub fn chosen() -> Option<PathBuf> {
    pending().file.clone()
}

/// Keeps `plan` for the replace step, if `file` is still the chosen one. Returns whether it did.
pub fn hold(file: &Path, plan: Plan) -> bool {
    let mut pending = pending();
    let chosen = pending.file.as_deref() == Some(file);
    if chosen {
        pending.plan = Some(plan);
    }
    chosen
}

/// The name the review shows, without the folder.
pub fn file_name(path: &Path) -> String {
    path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
}

pub fn has_plan() -> bool {
    pending().plan.is_some()
}

pub fn take() -> Option<Plan> {
    pending().plan.take()
}

/// Gives back a plan that [`take`] returned, after a replace that failed, so the user can try
/// again without opening the backup again. Kept only while a file is still chosen.
pub fn put_back(plan: Plan) {
    let mut pending = pending();
    if pending.file.is_some() {
        pending.plan = Some(plan);
    }
}

/// Drops the chosen file and the opened backup. Called on cancel and when the vault locks.
pub fn forget() {
    let mut pending = pending();
    pending.plan = None;
    pending.file = None;
}

/// Opens the backup at `path` with `password` and checks all of it. Slow on purpose (one Argon2id
/// run, then the whole file): call it off the UI thread.
pub fn open_file(path: &Path, password: &str) -> Result<Plan, RestoreError> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_FILE {
        return Err(RestoreError::TooLarge);
    }
    // Only ciphertext passes through this buffer.
    read(io::BufReader::new(file), password)
}

/// Reads a whole backup: `vault.json` first, then exactly the photos it lists, then the rest of
/// the file, so its last segment is authenticated too (ZIP stops at its directory before that).
pub fn read(input: impl Read, password: &str) -> Result<Plan, RestoreError> {
    let mut body = SecretReader::new(pvault::read::open(input, password)?);
    let first = next_member(&mut body)?.ok_or(RestoreError::Damaged)?;
    if first.name != "vault.json" {
        return Err(RestoreError::Invalid("its vault data doesn't come first"));
    }
    let json = read_member(&mut body, &first, MAX_METADATA)?;
    let mut total = json.len();
    let mut plan = parse(&json)?;
    drop(json);
    let mut wanted: HashMap<String, usize> =
        plan.photos.iter().enumerate().map(|(index, photo)| (photo.id.clone(), index)).collect();
    while let Some(member) = next_member(&mut body)? {
        let index = member
            .name
            .strip_prefix("photos/")
            .and_then(|id| wanted.remove(id))
            .ok_or(RestoreError::Invalid("it holds a file that its vault data doesn't list"))?;
        let bytes = read_member(&mut body, &member, MAX_PHOTO.min(MAX_CONTENTS - total))?;
        total += bytes.len();
        let photo = &mut plan.photos[index];
        photo.mime_type = photo_type(&bytes).ok_or(RestoreError::Invalid("a photo in it isn't a JPEG, PNG, WebP or GIF image"))?;
        photo.bytes = bytes;
    }
    if !wanted.is_empty() {
        return Err(RestoreError::Invalid("photos that its vault data lists are missing"));
    }
    io::copy(&mut body, &mut io::sink())?;
    Ok(plan)
}

/// A buffered reader whose buffer is wiped when dropped: it holds decrypted vault data.
struct SecretReader<R> {
    inner: R,
    buffer: Zeroizing<Vec<u8>>,
    start: usize,
    end: usize,
}

impl<R: Read> SecretReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, buffer: Zeroizing::new(vec![0; 64 * 1024]), start: 0, end: 0 }
    }
}

impl<R: Read> Read for SecretReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(out.len());
        out[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}

impl<R: Read> BufRead for SecretReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.start == self.end {
            self.end = self.inner.read(&mut self.buffer)?;
            self.start = 0;
        }
        Ok(&self.buffer[self.start..self.end])
    }

    fn consume(&mut self, amount: usize) {
        self.start = (self.start + amount).min(self.end);
    }
}

/// A local file header.
struct Member {
    name: String,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: u32,
    size: u32,
}

/// The next member's header, or `None` at the central directory or the end of the data, as
/// Java's `ZipInputStream` reads an archive.
fn next_member(input: &mut impl BufRead) -> Result<Option<Member>, RestoreError> {
    if input.fill_buf()?.is_empty() {
        return Ok(None);
    }
    let mut signature = [0; 4];
    input.read_exact(&mut signature)?;
    match u32::from_le_bytes(signature) {
        LOCAL_HEADER => {}
        CENTRAL_HEADER | END_OF_ARCHIVE => return Ok(None),
        _ => return Err(RestoreError::Damaged),
    }
    let mut header = [0; 26];
    input.read_exact(&mut header)?;
    let u16_at = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
    let u32_at = |at: usize| u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]]);
    let flags = u16_at(2);
    if flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION | FLAG_MASKED_HEADER) != 0 {
        return Err(RestoreError::Invalid("its archive is encrypted a second way"));
    }
    let name_length = usize::from(u16_at(22));
    if !(1..=MAX_NAME).contains(&name_length) {
        return Err(RestoreError::Invalid("it holds a file that its vault data doesn't list"));
    }
    let mut name = vec![0; name_length];
    input.read_exact(&mut name)?;
    let name = String::from_utf8(name).map_err(|_| RestoreError::Invalid("it holds a file that its vault data doesn't list"))?;
    let extra = u64::from(u16_at(24));
    if io::copy(&mut (&mut *input).take(extra), &mut io::sink())? != extra {
        return Err(RestoreError::Damaged);
    }
    Ok(Some(Member { name, flags, method: u16_at(4), crc: u32_at(10), compressed: u32_at(14), size: u32_at(18) }))
}

/// One member's data, at most `limit` bytes, checked against its CRC-32 and sizes.
fn read_member(input: &mut impl BufRead, member: &Member, limit: usize) -> Result<Zeroizing<Vec<u8>>, RestoreError> {
    let described = member.flags & FLAG_DESCRIPTOR != 0;
    let (data, compressed) = match member.method {
        // Java's ZipInputStream refuses a stored member whose sizes come after it, too.
        STORED if !described && member.compressed == member.size => {
            if member.size as usize > limit {
                return Err(RestoreError::TooLarge);
            }
            let data = read_limited(&mut (&mut *input).take(u64::from(member.size)), limit)?;
            (data, u64::from(member.size))
        }
        STORED => return Err(RestoreError::Damaged),
        DEFLATED => {
            let mut decoder = flate2::bufread::DeflateDecoder::new(&mut *input);
            let data = read_limited(&mut decoder, limit)?;
            (data, decoder.total_in())
        }
        _ => return Err(RestoreError::Invalid("it uses a compression that Nuvori doesn't read")),
    };
    let (crc, compressed_size, size) = if described { descriptor(input)? } else { (member.crc, member.compressed, member.size) };
    if crc != pvault::crc32(&data) || u64::from(compressed_size) != compressed || size as usize != data.len() {
        return Err(RestoreError::Damaged);
    }
    Ok(data)
}

/// The CRC-32 and sizes after a member's data, with or without their signature.
fn descriptor(input: &mut impl BufRead) -> Result<(u32, u32, u32), RestoreError> {
    let mut word = || -> io::Result<u32> {
        let mut bytes = [0; 4];
        input.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    };
    let first = word()?;
    let crc = if first == DATA_DESCRIPTOR { word()? } else { first };
    Ok((crc, word()?, word()?))
}

/// Reads to the end, refusing more than `limit` bytes. Fills buffers of its own and copies them
/// once into one of the exact size, so no growing buffer leaves copies of the data behind.
fn read_limited(input: &mut impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, RestoreError> {
    let mut chunks: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut total = 0usize;
    loop {
        let mut chunk = Zeroizing::new(vec![0; CHUNK]);
        let mut filled = 0;
        while filled < CHUNK {
            match input.read(&mut chunk[filled..])? {
                0 => break,
                count => filled += count,
            }
        }
        total += filled;
        if total > limit {
            return Err(RestoreError::TooLarge);
        }
        chunk.truncate(filled);
        let ended = filled < CHUNK;
        chunks.push(chunk);
        if ended {
            break;
        }
    }
    let mut data = Zeroizing::new(Vec::with_capacity(total));
    for chunk in &chunks {
        data.extend_from_slice(chunk);
    }
    Ok(data)
}

/// The image types this PC shows, by their first bytes.
fn photo_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Some("image/webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else {
        None
    }
}

// `vault.json`, as Android's `VaultBackupManager.parse` reads it: versions 1 to 9, the fields
// older versions lack filled with Android's defaults. A field of the wrong type is refused.

fn text<'a>(object: &'a Map<String, Value>, key: &str, what: &'static str) -> Result<&'a str, RestoreError> {
    object.get(key).and_then(Value::as_str).ok_or(RestoreError::Invalid(what))
}

fn optional_text<'a>(object: &'a Map<String, Value>, key: &str, default: &'a str, what: &'static str) -> Result<&'a str, RestoreError> {
    match object.get(key) {
        None => Ok(default),
        Some(value) => value.as_str().ok_or(RestoreError::Invalid(what)),
    }
}

fn long(object: &Map<String, Value>, key: &str, what: &'static str) -> Result<i64, RestoreError> {
    object.get(key).and_then(Value::as_i64).ok_or(RestoreError::Invalid(what))
}

fn optional_long(object: &Map<String, Value>, key: &str, default: i64, what: &'static str) -> Result<i64, RestoreError> {
    match object.get(key) {
        None => Ok(default),
        Some(value) => value.as_i64().ok_or(RestoreError::Invalid(what)),
    }
}

/// An Android `Int`.
fn optional_int(object: &Map<String, Value>, key: &str, default: i64, what: &'static str) -> Result<i64, RestoreError> {
    let value = optional_long(object, key, default, what)?;
    if i32::try_from(value).is_err() {
        return Err(RestoreError::Invalid(what));
    }
    Ok(value)
}

fn optional_bool(object: &Map<String, Value>, key: &str, what: &'static str) -> Result<bool, RestoreError> {
    match object.get(key) {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or(RestoreError::Invalid(what)),
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID && !id.chars().any(char::is_control)
}

fn entry_type(name: &str) -> Option<&'static str> {
    ENTRY_TYPES.into_iter().find(|kind| *kind == name)
}

/// An authenticator this PC shows codes for (totp.rs): a Base32 setup key, SHA1, SHA256 or SHA512,
/// 6 to 8 digits, 1 to 300 seconds. Android's own check (`Totp.validate`) is stricter, with a key
/// of at least 16 letters, so every backup Android makes passes, and so does one this PC made
/// with a shorter key that its editor accepted.
fn valid_totp(secret: &str, algorithm: &str, digits: i64, period: i64) -> bool {
    const MAX_SECRET: usize = 4096;
    match (u32::try_from(digits), u64::try_from(period)) {
        (Ok(digits), Ok(period)) if secret.len() <= MAX_SECRET => crate::totp::code_at(secret, algorithm, digits, period, 0).is_some(),
        _ => false,
    }
}

/// One item as Android's `VaultEntry`, with every field Android writes and nothing else.
fn entry(value: &Value) -> Result<Entry, RestoreError> {
    let object = value.as_object().ok_or(RestoreError::Invalid(ITEM))?;
    let id = text(object, "id", ITEM)?;
    let kind = entry_type(text(object, "type", ITEM)?).ok_or(RestoreError::Invalid(ITEM))?;
    if !valid_id(id) {
        return Err(RestoreError::Invalid(ITEM));
    }
    let card_kind = optional_text(object, "cardKind", "CREDIT", ITEM)?;
    if !matches!(card_kind, "CREDIT" | "DEBIT") {
        return Err(RestoreError::Invalid(ITEM));
    }
    let title = text(object, "title", ITEM)?;
    let notes = text(object, "notes", ITEM)?;
    let created_at = long(object, "createdAt", ITEM)?;
    let updated_at = long(object, "updatedAt", ITEM)?;
    let secret = text(object, "secondaryValue", ITEM)?;
    let algorithm = optional_text(object, "totpAlgorithm", "SHA1", ITEM)?;
    let digits = optional_int(object, "totpDigits", 6, ITEM)?;
    let period = optional_int(object, "totpPeriod", 30, ITEM)?;
    if kind == "AUTHENTICATOR" && !valid_totp(secret, algorithm, digits, period) {
        return Err(RestoreError::Invalid("an authenticator in it has a setup key or settings that aren't valid"));
    }
    let normalized = json!({
        "id": id,
        "type": kind,
        "title": title,
        "primaryValue": text(object, "primaryValue", ITEM)?,
        "secondaryValue": secret,
        "tertiaryValue": text(object, "tertiaryValue", ITEM)?,
        "fourthValue": text(object, "fourthValue", ITEM)?,
        "cardKind": card_kind,
        "network": optional_text(object, "network", "", ITEM)?,
        "totpAlgorithm": algorithm,
        "totpDigits": digits,
        "totpPeriod": period,
        "linkedApps": optional_text(object, "linkedApps", "", ITEM)?,
        "autofillSignatures": optional_text(object, "autofillSignatures", "", ITEM)?,
        "autofillOrigins": optional_text(object, "autofillOrigins", "", ITEM)?,
        "linkedAuthenticatorId": optional_text(object, "linkedAuthenticatorId", "", ITEM)?,
        "notes": notes,
        "color": long(object, "color", ITEM)?,
        "tags": optional_text(object, "tags", "", ITEM)?,
        "favorite": optional_bool(object, "favorite", ITEM)?,
        "lastOpenedAt": optional_long(object, "lastOpenedAt", 0, ITEM)?,
        "sortOrder": optional_long(object, "sortOrder", 0, ITEM)?,
        "createdAt": created_at,
        "updatedAt": updated_at,
    });
    let data_json = Zeroizing::new(serde_json::to_string(&normalized).map_err(|_| RestoreError::Invalid(ITEM))?);
    let note = (kind == "NOTE").then(|| Note {
        title: Zeroizing::new(title.to_owned()),
        body: Zeroizing::new(notes.to_owned()),
        created_at,
    });
    Ok(Entry { id: id.to_owned(), kind, data_json, note, updated_at })
}

fn group(value: &Value) -> Result<Group, RestoreError> {
    let object = value.as_object().ok_or(RestoreError::Invalid(FOLDER))?;
    let id = text(object, "id", FOLDER)?;
    if !valid_id(id) {
        return Err(RestoreError::Invalid(FOLDER));
    }
    // Android: a blank folder type is a plain folder; anything else must name an item type.
    let folder = optional_text(object, "folderType", "", FOLDER)?;
    let folder_type = if folder.trim().is_empty() { "" } else { entry_type(folder).ok_or(RestoreError::Invalid(FOLDER))? };
    Ok(Group {
        id: id.to_owned(),
        name: text(object, "name", FOLDER)?.to_owned(),
        notes: text(object, "notes", FOLDER)?.to_owned(),
        folder_type,
    })
}

fn photo(value: &Value) -> Result<Photo, RestoreError> {
    let object = value.as_object().ok_or(RestoreError::Invalid(PHOTO))?;
    let id = text(object, "id", PHOTO)?;
    if !pvault::valid_photo_id(id) {
        return Err(RestoreError::Invalid(PHOTO));
    }
    Ok(Photo {
        id: id.to_owned(),
        entry_id: text(object, "entryId", PHOTO)?.to_owned(),
        is_cover: optional_bool(object, "isCover", PHOTO)?,
        added_at: long(object, "addedAt", PHOTO)?,
        mime_type: "",
        bytes: Zeroizing::new(Vec::new()),
    })
}

fn passkey(value: &Value) -> Result<Passkey, RestoreError> {
    let passkey: VaultPasskey = serde_json::from_value(value.clone()).map_err(|_| RestoreError::Invalid(PASSKEY))?;
    passkey.validate().map_err(|_| RestoreError::Invalid(PASSKEY))?;
    let data_json = Zeroizing::new(serde_json::to_string(&passkey).map_err(|_| RestoreError::Invalid(PASSKEY))?);
    Ok(Passkey { id: passkey.id.clone(), rp_id: passkey.rp_id.clone(), data_json })
}

fn parse(json: &[u8]) -> Result<Plan, RestoreError> {
    let root: Value = serde_json::from_slice(json).map_err(|_| RestoreError::Invalid("its vault data isn't readable"))?;
    let root = root.as_object().ok_or(RestoreError::Invalid("its vault data isn't readable"))?;
    let version = root.get("version").and_then(Value::as_i64).ok_or(RestoreError::Unsupported)?;
    if !(1..=9).contains(&version) {
        return Err(RestoreError::Unsupported);
    }
    let array = |key: &str| root.get(key).and_then(Value::as_array).ok_or(RestoreError::Invalid("its vault data is incomplete"));
    // Android reads the vault ID from version 7 on, and refuses a backup without one.
    if version >= 7 && !root.get("vaultId").is_some_and(Value::is_string) {
        return Err(RestoreError::Invalid("its vault data is incomplete"));
    }
    let entries = array("entries")?.iter().map(entry).collect::<Result<Vec<_>, _>>()?;
    let groups = array("groups")?.iter().map(group).collect::<Result<Vec<_>, _>>()?;
    let links = array("links")?
        .iter()
        .map(|link| {
            let object = link.as_object().ok_or(RestoreError::Invalid(LINK))?;
            Ok((text(object, "entryId", LINK)?.to_owned(), text(object, "groupId", LINK)?.to_owned()))
        })
        .collect::<Result<Vec<_>, RestoreError>>()?;
    let photos = array("photos")?.iter().map(photo).collect::<Result<Vec<_>, _>>()?;
    // Passkeys came with version 5.
    let passkeys = if version >= 5 { array("passkeys")?.iter().map(passkey).collect::<Result<Vec<_>, _>>()? } else { Vec::new() };
    let appearance_id = |key: &str| root.get(key).and_then(Value::as_str).filter(|id| crate::appearance::valid_id(id)).map(str::to_owned);
    let appearance = appearance_id("appearanceAccent").zip(appearance_id("appearanceSurface"));

    // The checks of Android's parse, in its order.
    let mut passkey_ids = HashSet::new();
    if !passkeys.iter().all(|passkey| passkey_ids.insert(passkey.id.as_str())) {
        return Err(RestoreError::Invalid("two passkeys in it share an ID"));
    }
    let mut types = HashMap::new();
    if !entries.iter().all(|entry| types.insert(entry.id.as_str(), entry.kind).is_none()) {
        return Err(RestoreError::Invalid("two items in it share an ID"));
    }
    let mut folders = HashMap::new();
    if !groups.iter().all(|group| folders.insert(group.id.as_str(), group.folder_type).is_none()) {
        return Err(RestoreError::Invalid("two folders in it share an ID"));
    }
    let mut photo_ids = HashSet::new();
    if !photos.iter().all(|photo| photo_ids.insert(photo.id.as_str())) {
        return Err(RestoreError::Invalid("two photos in it share an ID"));
    }
    let mut seen = HashSet::new();
    if !links.iter().all(|(entry_id, group_id)| seen.insert((entry_id.as_str(), group_id.as_str()))) {
        return Err(RestoreError::Invalid("a folder link in it is repeated"));
    }
    let mut typed_folders: HashMap<&str, usize> = HashMap::new();
    for (entry_id, group_id) in &links {
        let (Some(kind), Some(folder_type)) = (types.get(entry_id.as_str()), folders.get(group_id.as_str())) else {
            return Err(RestoreError::Invalid("a folder link in it points to something missing"));
        };
        if !folder_type.is_empty() {
            if folder_type != kind {
                return Err(RestoreError::Invalid("an item in it is in a folder for another type"));
            }
            let count = typed_folders.entry(entry_id.as_str()).or_default();
            *count += 1;
            if *count > 1 {
                return Err(RestoreError::Invalid("an item in it is in two typed folders"));
            }
        }
    }
    if !photos.iter().all(|photo| types.contains_key(photo.entry_id.as_str())) {
        return Err(RestoreError::Invalid("a photo in it belongs to no item"));
    }
    for entry in &entries {
        let linked: Value = serde_json::from_str(&entry.data_json).map_err(|_| RestoreError::Invalid(ITEM))?;
        let linked = linked["linkedAuthenticatorId"].as_str().unwrap_or_default();
        if !linked.trim().is_empty() && (entry.kind != "PASSWORD" || types.get(linked) != Some(&"AUTHENTICATOR")) {
            return Err(RestoreError::Invalid("a login in it links to an authenticator that isn't there"));
        }
    }
    Ok(Plan { entries, groups, links, photos, passkeys, appearance })
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;

    const PASSWORD: &str = "correct horse battery staple";

    fn item(id: &str, kind: &str, title: &str) -> Value {
        json!({
            "id": id, "type": kind, "title": title, "primaryValue": "sam", "secondaryValue": "hunter2",
            "tertiaryValue": "https://example.com", "fourthValue": "", "cardKind": "CREDIT", "network": "",
            "totpAlgorithm": "SHA1", "totpDigits": 6, "totpPeriod": 30, "linkedApps": "", "autofillSignatures": "",
            "autofillOrigins": "", "linkedAuthenticatorId": "", "notes": "", "color": 4278743114_u64, "tags": "",
            "favorite": false, "lastOpenedAt": 0, "sortOrder": 1, "createdAt": 1, "updatedAt": 2
        })
    }

    fn code(id: &str) -> Value {
        let mut code = item(id, "AUTHENTICATOR", "Example code");
        code["secondaryValue"] = "JBSWY3DPEHPK3PXP".into();
        code
    }

    fn vault_json() -> Value {
        let mut login = item("login-1", "PASSWORD", "Example");
        login["linkedAuthenticatorId"] = "code-1".into();
        let mut note = item("note-1", "NOTE", "Plans");
        note["notes"] = "Body".into();
        json!({
            "version": 9, "vaultId": "vault-a",
            "entries": [login, code("code-1"), note],
            "groups": [{"id": "group-1", "name": "Work", "notes": "", "folderType": ""},
                       {"id": "group-2", "name": "Logins", "notes": "", "folderType": "PASSWORD"}],
            "links": [{"entryId": "login-1", "groupId": "group-1"}, {"entryId": "login-1", "groupId": "group-2"}],
            "photos": [{"id": "photo-1", "entryId": "note-1", "isCover": true, "addedAt": 5}],
            "passkeys": [],
            "appearanceAccent": "green", "appearanceSurface": "sage"
        })
    }

    const JPEG: &[u8] = &[0xff, 0xd8, 0xff, 0xe0, 1, 2, 3];

    /// A stored-member backup, as this PC writes one.
    fn windows_file(json: &Value, photos: &[(&str, &[u8])]) -> Vec<u8> {
        let key = pvault::BackupKey::new(PASSWORD, pvault::Kdf::LEGACY).unwrap();
        let metadata = pvault::Metadata {
            json: Zeroizing::new(serde_json::to_vec(json).unwrap()),
            photo_ids: photos.iter().map(|(id, _)| (*id).to_owned()).collect(),
        };
        pvault::write::<_, pvault::BackupError>(Vec::new(), &key, &metadata, |id| {
            Ok(Zeroizing::new(photos.iter().find(|(photo, _)| *photo == id).unwrap().1.to_vec()))
        })
        .unwrap()
    }

    /// A deflated archive with sizes after the data, as Java's `ZipOutputStream` writes one.
    fn java_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in members {
            out.extend_from_slice(&LOCAL_HEADER.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&(FLAG_DESCRIPTOR | 1 << 11).to_le_bytes());
            out.extend_from_slice(&DEFLATED.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&[0; 12]);
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data).unwrap();
            let compressed = encoder.finish().unwrap();
            out.extend_from_slice(&compressed);
            out.extend_from_slice(&DATA_DESCRIPTOR.to_le_bytes());
            out.extend_from_slice(&pvault::crc32(data).to_le_bytes());
            out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        }
        out.extend_from_slice(&CENTRAL_HEADER.to_le_bytes());
        out.extend_from_slice(b"directory that nothing reads");
        out
    }

    fn encrypt(archive: &[u8]) -> Vec<u8> {
        let key = pvault::BackupKey::new(PASSWORD, pvault::Kdf::LEGACY).unwrap();
        let mut writer = pvault::EncryptingWriter::new(Vec::new(), &key).unwrap();
        writer.write_all(archive).unwrap();
        writer.finish().unwrap()
    }

    fn invalid(result: Result<Plan, RestoreError>) -> &'static str {
        match result {
            Err(RestoreError::Invalid(reason)) => reason,
            Err(other) => panic!("expected a refused backup, got {other:?}"),
            Ok(_) => panic!("expected a refused backup"),
        }
    }

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE local_notes (id TEXT PRIMARY KEY, title TEXT, body TEXT, created_at INTEGER, updated_at INTEGER);
             CREATE TABLE local_entries (id TEXT PRIMARY KEY, type TEXT, data_json TEXT, updated_at INTEGER);
             CREATE TABLE local_note_details (id TEXT PRIMARY KEY, data_json TEXT);
             CREATE TABLE local_entry_photos (id TEXT PRIMARY KEY, entry_id TEXT, mime_type TEXT, data BLOB,
                 is_cover INTEGER NOT NULL DEFAULT 0, added_at INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE local_groups (id TEXT PRIMARY KEY, name TEXT, notes TEXT, folder_type TEXT);
             CREATE TABLE entry_groups (entry_id TEXT, group_id TEXT, PRIMARY KEY (entry_id, group_id));
             CREATE TABLE local_passkeys (id TEXT PRIMARY KEY, rp_id TEXT, data_json TEXT);",
        )
        .unwrap();
        db
    }

    #[test]
    fn reads_a_backup_made_on_this_pc_and_writes_every_part() {
        let plan = read(Cursor::new(windows_file(&vault_json(), &[("photo-1", JPEG)])), PASSWORD).unwrap();
        assert_eq!(plan.summary(), Summary { items: 3, codes: 1, folders: 2, photos: 1, passkeys: 0 });
        assert_eq!(plan.appearance(), Some(("green", "sage")));
        let db = database();
        plan.insert(&db).unwrap();
        let count = |table: &str| db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get::<_, i64>(0)).unwrap();
        assert_eq!((count("local_entries"), count("local_notes"), count("local_note_details")), (2, 1, 1));
        assert_eq!((count("local_groups"), count("entry_groups"), count("local_entry_photos")), (2, 2, 1));
        let (title, body): (String, String) =
            db.query_row("SELECT title, body FROM local_notes WHERE id = 'note-1'", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!((title.as_str(), body.as_str()), ("Plans", "Body"));
        let (mime, data, cover): (String, Vec<u8>, bool) = db
            .query_row("SELECT mime_type, data, is_cover FROM local_entry_photos", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap();
        assert_eq!((mime.as_str(), data.as_slice(), cover), ("image/jpeg", JPEG, true));
        let folder: String = db.query_row("SELECT folder_type FROM local_groups WHERE id = 'group-2'", [], |row| row.get(0)).unwrap();
        assert_eq!(folder, "PASSWORD");
    }

    #[test]
    fn reads_a_deflated_archive_with_sizes_after_the_data_as_android_writes() {
        let json = serde_json::to_vec(&vault_json()).unwrap();
        let file = encrypt(&java_archive(&[("vault.json", &json), ("photos/photo-1", JPEG)]));
        let plan = read(Cursor::new(file), PASSWORD).unwrap();
        assert_eq!(plan.summary().photos, 1);
        assert_eq!(plan.photos[0].bytes.as_slice(), JPEG);
    }

    #[test]
    fn opens_the_backup_that_android_made() {
        let file = include_bytes!("../fixtures/android-backup-v2.pvault");
        let plan = read(Cursor::new(&file[..]), "synthetic fixture password").unwrap();
        assert_eq!(plan.summary(), Summary { items: 0, codes: 0, folders: 0, photos: 0, passkeys: 0 });
    }

    /// Written by Nuvori for Android's `BackupCipher` and Java's `ZipOutputStream` (the Android
    /// repository's cross test): every item type, a plain and a typed folder, three links, two
    /// photos, a P-256 passkey and the appearance.
    #[test]
    fn restores_everything_in_a_full_backup_from_android() {
        let file = include_bytes!("../fixtures/android-backup-full.pvault");
        let plan = read(Cursor::new(&file[..]), "synthetic fixture password").unwrap();
        assert_eq!(plan.summary(), Summary { items: 6, codes: 1, folders: 2, photos: 2, passkeys: 1 });
        assert_eq!(plan.appearance(), Some(("teal", "midnight")));
        let db = database();
        plan.insert(&db).unwrap();
        let entry = |id: &str| -> Value {
            let json: String = db.query_row("SELECT data_json FROM local_entries WHERE id = ?1", [id], |row| row.get(0)).unwrap();
            serde_json::from_str(&json).unwrap()
        };
        let card = entry("e-card");
        assert_eq!((card["cardKind"].as_str(), card["network"].as_str(), card["fourthValue"].as_str()), (Some("DEBIT"), Some("VISA"), Some("123")));
        let code = entry("e-code");
        assert_eq!((code["totpAlgorithm"].as_str(), code["totpDigits"].as_i64(), code["totpPeriod"].as_i64()), (Some("SHA256"), Some(8), Some(60)));
        let login = entry("e-login");
        assert_eq!((login["linkedAuthenticatorId"].as_str(), login["favorite"].as_bool()), (Some("e-code"), Some(true)));
        let body: String = db.query_row("SELECT body FROM local_notes WHERE id = 'e-note'", [], |row| row.get(0)).unwrap();
        assert_eq!(body, "Synthetic note body");
        let photos: Vec<(String, String, i64)> = db
            .prepare("SELECT id, mime_type, length(data) FROM local_entry_photos ORDER BY id").unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap()
            .collect::<Result<_, _>>().unwrap();
        assert_eq!(photos, [("p-card".to_owned(), "image/jpeg".to_owned(), 300_004), ("p-note".to_owned(), "image/png".to_owned(), 5_008)]);
        let links: i64 = db.query_row("SELECT count(*) FROM entry_groups", [], |row| row.get(0)).unwrap();
        assert_eq!(links, 3);
        let passkey: String = db.query_row("SELECT data_json FROM local_passkeys", [], |row| row.get(0)).unwrap();
        let passkey: VaultPasskey = serde_json::from_str(&passkey).unwrap();
        assert!(passkey.validate().is_ok());
        assert_eq!(passkey.rp_id, "example.com");
    }

    #[test]
    fn keeps_only_the_fields_android_has_and_fills_older_versions_defaults() {
        let mut old = json!({"id": "a", "type": "PASSWORD", "title": "T", "primaryValue": "", "secondaryValue": "",
            "tertiaryValue": "", "fourthValue": "", "notes": "", "color": 1, "createdAt": 1, "updatedAt": 1,
            "groupIds": ["planted"], "extra": "dropped"});
        let parsed = entry(&old).unwrap();
        let stored: Value = serde_json::from_str(&parsed.data_json).unwrap();
        assert_eq!(stored.as_object().unwrap().len(), 24);
        assert!(stored.get("groupIds").is_none() && stored.get("extra").is_none());
        assert_eq!((stored["cardKind"].as_str(), stored["totpDigits"].as_i64(), stored["favorite"].as_bool()), (Some("CREDIT"), Some(6), Some(false)));
        old["favorite"] = "yes".into();
        assert!(entry(&old).is_err(), "a field of the wrong type");
        let no_vault_id = json!({"version": 7, "entries": [], "groups": [], "links": [], "photos": [], "passkeys": []});
        assert!(matches!(parse(&serde_json::to_vec(&no_vault_id).unwrap()), Err(RestoreError::Invalid(_))));
        let version_four = json!({"version": 4, "entries": [], "groups": [], "links": [], "photos": []});
        assert_eq!(parse(&serde_json::to_vec(&version_four).unwrap()).unwrap().summary().passkeys, 0);
        let newer = json!({"version": 10, "entries": [], "groups": [], "links": [], "photos": [], "passkeys": []});
        assert!(matches!(parse(&serde_json::to_vec(&newer).unwrap()), Err(RestoreError::Unsupported)));
    }

    #[test]
    fn refuses_what_android_refuses() {
        let refused = |change: &dyn Fn(&mut Value)| {
            let mut json = vault_json();
            change(&mut json);
            invalid(parse(&serde_json::to_vec(&json).unwrap()))
        };
        refused(&|json| json["entries"][2]["id"] = "login-1".into());
        refused(&|json| json["groups"][1]["id"] = "group-1".into());
        refused(&|json| json["links"][1] = json!({"entryId": "login-1", "groupId": "group-1"}));
        refused(&|json| json["links"][0]["groupId"] = "gone".into());
        refused(&|json| json["links"][0] = json!({"entryId": "note-1", "groupId": "group-2"}));
        refused(&|json| {
            json["groups"][0]["folderType"] = "PASSWORD".into();
        });
        refused(&|json| json["photos"][0]["entryId"] = "gone".into());
        refused(&|json| json["photos"][0]["id"] = "../photo".into());
        refused(&|json| json["entries"][0]["linkedAuthenticatorId"] = "note-1".into());
        refused(&|json| json["entries"][1]["secondaryValue"] = "not base32!".into());
        refused(&|json| json["entries"][1]["totpDigits"] = 9.into());
        refused(&|json| json["groups"][0]["folderType"] = "SECRET".into());
        refused(&|json| json["passkeys"] = json!([{"id": "AA"}]));
    }

    #[test]
    fn refuses_an_archive_that_differs_from_its_vault_data() {
        let json = serde_json::to_vec(&vault_json()).unwrap();
        let open = |members: &[(&str, &[u8])]| read(Cursor::new(encrypt(&java_archive(members))), PASSWORD);
        assert!(invalid(open(&[("vault.json", &json)])).contains("missing"));
        assert!(invalid(open(&[("vault.json", &json), ("photos/photo-1", JPEG), ("photos/photo-1", JPEG)])).contains("doesn't list"));
        assert!(invalid(open(&[("vault.json", &json), ("photos/photo-1", JPEG), ("notes.txt", b"x")])).contains("doesn't list"));
        assert!(invalid(open(&[("vault.json", &json), ("photos/photo-1", JPEG), ("vault.json", &json)])).contains("doesn't list"));
        assert!(invalid(open(&[("photos/photo-1", JPEG), ("vault.json", &json)])).contains("first"));
        assert!(invalid(open(&[("vault.json", &json), ("photos/photo-1", b"<svg/>")])).contains("image"));
    }

    #[test]
    fn refuses_a_wrong_password_and_a_damaged_or_cut_file() {
        let file = windows_file(&vault_json(), &[("photo-1", JPEG)]);
        assert!(matches!(read(Cursor::new(&file), "wrong password"), Err(RestoreError::WrongPasswordOrDamaged)));
        let mut flipped = file.clone();
        let last = flipped.len() - 20;
        flipped[last] ^= 1;
        assert!(matches!(read(Cursor::new(flipped), PASSWORD), Err(RestoreError::Damaged)));
        let cut = &file[..file.len() - 5];
        assert!(matches!(read(Cursor::new(cut), PASSWORD), Err(RestoreError::Damaged)));
        assert!(matches!(read(Cursor::new(b"PK\x03\x04 not a backup".to_vec()), PASSWORD), Err(RestoreError::Unsupported)));
    }

    #[test]
    fn checks_each_member_against_its_crc_and_size_limit() {
        let data = b"some member data";
        let mut archive = java_archive(&[("vault.json", data)]);
        let mut input = Cursor::new(archive.clone());
        let member = next_member(&mut input).unwrap().unwrap();
        assert!(matches!(read_member(&mut input, &member, data.len() - 1), Err(RestoreError::TooLarge)));
        let mut input = Cursor::new(archive.clone());
        let member = next_member(&mut input).unwrap().unwrap();
        assert_eq!(read_member(&mut input, &member, data.len()).unwrap().as_slice(), data);
        assert!(next_member(&mut input).unwrap().is_none(), "stops at the directory");
        let crc_at = archive.len() - 28 - 12;
        archive[crc_at] ^= 1;
        let mut input = Cursor::new(archive);
        let member = next_member(&mut input).unwrap().unwrap();
        assert!(matches!(read_member(&mut input, &member, 1024), Err(RestoreError::Damaged)));
    }

    #[test]
    fn checks_setup_keys_as_this_pc_shows_them() {
        for key in ["JBSWY3DPEHPK3PXP", "jbsw y3dp ehpk 3pxp", "JBSWY3DPEHPK3PXP====", "JBSWY3DP"] {
            assert!(valid_totp(key, "SHA1", 6, 30), "{key}");
        }
        for key in ["", "====", "A", "JBSWY3DPEHPK3PX1", "JBSW!3DP"] {
            assert!(!valid_totp(key, "SHA1", 6, 30), "{key}");
        }
        assert!(!valid_totp(&"A".repeat(4097), "SHA1", 6, 30));
        assert!(valid_totp("JBSWY3DPEHPK3PXP", "SHA512", 8, 300));
        assert!(!valid_totp("JBSWY3DPEHPK3PXP", "MD5", 6, 30));
        for (digits, period) in [(5, 30), (9, 30), (-6, 30), (6, 0), (6, 301), (6, -30), (i64::from(u32::MAX) + 6, 30)] {
            assert!(!valid_totp("JBSWY3DPEHPK3PXP", "SHA1", digits, period), "{digits} {period}");
        }
    }

    #[test]
    fn restores_what_this_pc_exports() {
        let mut login = item("login", "PASSWORD", "Example");
        login["linkedAuthenticatorId"] = "code".into();
        let mut code = code("code");
        // Shorter than Android takes, but this PC's editor accepts it.
        code["secondaryValue"] = "JBSWY3DP".into();
        let contents = pvault::Contents {
            vault_id: "vault-1".into(),
            entries: vec![login, code, item("note", "NOTE", "Plans")],
            groups: vec![pvault::Group { id: "work".into(), name: "Work".into(), notes: String::new(), folder_type: String::new() }],
            links: vec![("login".into(), "work".into())],
            photos: vec![pvault::Photo { id: "p-1".into(), entry_id: "note".into(), is_cover: true, added_at: 5 }],
            passkeys: Vec::new(),
            appearance: Some(("blue".into(), "slate".into())),
        };
        let metadata = pvault::metadata(&contents).unwrap();
        let key = pvault::BackupKey::new(PASSWORD, pvault::Kdf::LEGACY).unwrap();
        let file = pvault::write::<_, pvault::BackupError>(Vec::new(), &key, &metadata, |_| Ok(Zeroizing::new(JPEG.to_vec()))).unwrap();
        let plan = read(Cursor::new(file), PASSWORD).unwrap();
        assert_eq!(plan.summary(), Summary { items: 3, codes: 1, folders: 1, photos: 1, passkeys: 0 });
        assert_eq!(plan.appearance(), Some(("blue", "slate")));
        plan.insert(&database()).unwrap();
    }

    #[test]
    fn a_new_file_drops_the_backup_opened_before() {
        let plan = read(Cursor::new(windows_file(&vault_json(), &[("photo-1", JPEG)])), PASSWORD).unwrap();
        choose(PathBuf::from("a.pvault"));
        assert!(!hold(Path::new("b.pvault"), plan));
        assert!(!has_plan(), "kept only for the chosen file");
        let plan = read(Cursor::new(windows_file(&vault_json(), &[("photo-1", JPEG)])), PASSWORD).unwrap();
        assert!(hold(Path::new("a.pvault"), plan));
        assert!(has_plan());
        assert_eq!(file_name(&chosen().unwrap()), "a.pvault");
        choose(PathBuf::from("b.pvault"));
        assert!(!has_plan());
        forget();
        assert!(chosen().is_none());
    }
}
