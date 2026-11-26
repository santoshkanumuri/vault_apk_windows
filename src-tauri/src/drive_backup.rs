//! Google Drive backup: a whole copy of the vault as a `.pvault` file (`pvault.rs`), uploaded to
//! the same hidden Drive folder sync uses, on a schedule, so a PC that is lost, reset or stolen can
//! be restored from a backup even when it was never paired with a phone.
//!
//! - A backup is an ordinary encrypted backup, the same file "Export encrypted backup" writes. It
//!   opens with the master password that was current when backups were turned on, on this PC or in
//!   Nuvori for Android. Nothing but that password opens it.
//! - The key is made once, from that password (one Argon2id run), and kept in the encrypted vault
//!   database, so the backups that follow need no password and no prompt. It is readable only while
//!   the vault is unlocked, like the Drive sign-in itself (`cloud_sync.rs`).
//! - Changing the master password leaves the saved key wrapped with the old one. The pass notices
//!   (the vault key file has a new salt), stops, and the card asks for the password once. After the
//!   first backup with the new key, this PC's backups that open with the old password are deleted.
//! - Only this PC writes and deletes its own files; another device's backups are never touched.
//!   `drive_backup_plan.rs` holds the naming and scheduling rules, as Android has them.
//!
//! Restoring a backup is Android's job for now: this PC writes them and the phone reads them.

use std::{
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use tauri::State;
use zeroize::Zeroizing;

use crate::{
    ManagedState,
    activity::{self, Category, Level},
    backup_export, google_drive,
    lan_sync::cloud::{self, CloudError, CloudFile, CloudStore},
    pvault::BackupKey,
    public_vault_error,
};

#[path = "drive_backup_plan.rs"]
pub mod plan;

impl plan::Listed for CloudFile {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// How often the background thread looks for a backup that is due. The schedule itself is hours or
/// days apart; this only decides how soon after unlocking, or after the interval, a backup starts.
const TICK: Duration = Duration::from_secs(60);

/// True while a pass runs. It keeps the passes one at a time, whether the thread or "Back up now"
/// asked for one, and it is what the card's "Backing up" chip reads.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Holds [`RUNNING`] for one pass and clears it however the pass ends, a panic included.
struct Running;

impl Running {
    /// `None` while another pass runs.
    fn start() -> Option<Self> {
        (!RUNNING.swap(true, Ordering::SeqCst)).then_some(Self)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

/// What the Google Drive backup card shows. Every sentence in `last_error` is fixed and holds no
/// account, file or path.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// This build of Nuvori has a Google client.
    pub available: bool,
    /// This PC is signed in to Google Drive (the same sign-in sync uses).
    pub connected: bool,
    pub account: String,
    pub enabled: bool,
    pub interval_ms: i64,
    pub last_backup_at: i64,
    pub running: bool,
    /// The master password changed after the backup key was made, so it is needed once more.
    pub needs_password: bool,
    /// The Drive sign-in no longer works, so the card offers to connect again.
    pub needs_sign_in: bool,
    /// When the password that opens these backups was entered.
    pub password_set_at: i64,
    pub last_error: String,
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS drive_backup_settings (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL,
    interval_ms INTEGER NOT NULL,
    backup_id TEXT NOT NULL,
    key_header BLOB NOT NULL,
    key_material BLOB NOT NULL,
    password_salt TEXT NOT NULL,
    password_set_at INTEGER NOT NULL,
    password_changed_at INTEGER NOT NULL,
    last_backup_at INTEGER NOT NULL,
    last_attempt_at INTEGER NOT NULL,
    last_error TEXT NOT NULL)";

/// The settings of this PC's Drive backups. The table is made on the first read or write, as the
/// other settings tables of this PC are, so an older vault needs no migration.
struct Saved {
    enabled: bool,
    interval_ms: i64,
    /// Names this PC's own files in the Drive. Kept when backups are turned off, so turning them on
    /// again keeps replacing the same files.
    backup_id: String,
    /// `None` once backups are off: the key is dropped with them.
    key: Option<BackupKey>,
    /// The salt of the vault key file when the key was made. A different salt means the master
    /// password changed.
    password_salt: String,
    password_set_at: i64,
    /// When the master password was noticed to have changed, while backups with the old one may
    /// still be in the Drive.
    password_changed_at: i64,
    last_backup_at: i64,
    last_attempt_at: i64,
    last_error: String,
}

fn storage(error: rusqlite::Error) -> String {
    activity::diagnostic(Category::Vault, "Drive backup settings failed", &error);
    "Couldn't read this PC's backup settings.".to_owned()
}

fn read(db: &Connection) -> Result<Option<Saved>, rusqlite::Error> {
    db.execute_batch(SCHEMA)?;
    db.query_row(
        "SELECT enabled, interval_ms, backup_id, key_header, key_material, password_salt, password_set_at,
            password_changed_at, last_backup_at, last_attempt_at, last_error
         FROM drive_backup_settings WHERE id = 1",
        [],
        |row| {
            let header: Vec<u8> = row.get(3)?;
            let material = Zeroizing::new(row.get::<_, Vec<u8>>(4)?);
            Ok(Saved {
                enabled: row.get(0)?,
                interval_ms: row.get(1)?,
                backup_id: row.get(2)?,
                key: BackupKey::from_parts(header, &material).ok(),
                password_salt: row.get(5)?,
                password_set_at: row.get(6)?,
                password_changed_at: row.get(7)?,
                last_backup_at: row.get(8)?,
                last_attempt_at: row.get(9)?,
                last_error: row.get(10)?,
            })
        },
    )
    .optional()
}

/// Turns backups on, or takes the master password again after it changed. The key is made by the
/// caller, which has the password; this only saves it.
fn save_key(db: &Connection, key: &BackupKey, salt: &str, interval_ms: i64, now: i64) -> Result<(), rusqlite::Error> {
    db.execute_batch(SCHEMA)?;
    let (header, material) = key.parts();
    let saved = read(db)?;
    // A password change is only worth recording when a backup with the old password may be in the
    // Drive: there is nothing to delete before the first one.
    let changed_at = match &saved {
        Some(saved) if saved.password_salt != salt && saved.last_backup_at > 0 => now,
        Some(saved) => saved.password_changed_at,
        None => 0,
    };
    let backup_id = match saved {
        Some(saved) if plan::valid_backup_id(&saved.backup_id) => saved.backup_id,
        _ => new_backup_id(),
    };
    db.execute(
        "INSERT OR REPLACE INTO drive_backup_settings (id, enabled, interval_ms, backup_id, key_header, key_material,
            password_salt, password_set_at, password_changed_at, last_backup_at, last_attempt_at, last_error)
         VALUES (1, 1, ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            COALESCE((SELECT last_backup_at FROM drive_backup_settings WHERE id = 1), 0), 0, '')",
        params![interval_ms, backup_id, header, &*material, salt, now, changed_at],
    )?;
    Ok(())
}

/// Stops backups and drops the key, so nothing on this PC can write another backup that opens with
/// that password. The files already in the Drive stay; they are the point of a backup.
fn forget_key(db: &Connection) -> Result<(), rusqlite::Error> {
    db.execute_batch(SCHEMA)?;
    db.execute(
        "UPDATE drive_backup_settings SET enabled = 0, key_header = x'', key_material = x'', last_error = '',
            last_attempt_at = 0 WHERE id = 1",
        [],
    )?;
    Ok(())
}

/// 16 hexadecimal characters, 64 bits, as Android's `newBackupId`.
fn new_backup_id() -> String {
    uuid::Uuid::new_v4().as_bytes()[..8].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The Drive operations a backup needs, so the tests can stand in for Google Drive.
trait BackupStore {
    fn list(&mut self) -> Result<Vec<CloudFile>, CloudError>;
    fn upload(&mut self, name: &str, size: u64, path: &Path) -> Result<CloudFile, CloudError>;
    fn delete(&mut self, id: &str) -> Result<(), CloudError>;
}

/// The Drive itself, as the backup uses it.
struct Drive<'a>(&'a mut dyn CloudStore);

impl BackupStore for Drive<'_> {
    fn list(&mut self) -> Result<Vec<CloudFile>, CloudError> {
        self.0.list(None)
    }

    fn upload(&mut self, name: &str, size: u64, path: &Path) -> Result<CloudFile, CloudError> {
        let file = File::open(path).map_err(|error| CloudError::Other(format!("backup file: {error}")))?;
        self.0.upload(name, size, &mut BufReader::new(file))
    }

    fn delete(&mut self, id: &str) -> Result<(), CloudError> {
        self.0.delete(id)
    }
}

/// Uploads the file at `path` as this PC's newest backup, then deletes the copies the plan calls
/// obsolete. A failed upload removes nothing, so a backup that fails never costs the user a good
/// one. Returns the uploaded file and whether a backup with the old master password is left.
fn upload(
    store: &mut dyn BackupStore,
    backup_id: &str,
    now: i64,
    path: &Path,
    password_changed_at: i64,
) -> Result<(plan::BackupFile, bool), CloudError> {
    let size = fs::metadata(path).map(|data| data.len()).map_err(|error| CloudError::Other(format!("backup file: {error}")))?;
    if size == 0 {
        return Err(CloudError::Other("the backup is empty".into()));
    }
    let name = plan::name(backup_id, now).ok_or_else(|| CloudError::Other("backup name".into()))?;
    let uploaded = store.upload(&name, size, path)?;
    if uploaded.size != size || uploaded.name != name {
        return Err(CloudError::Other("the upload did not finish".into()));
    }
    let made = plan::BackupFile { file_id: uploaded.id.clone(), backup_id: backup_id.to_owned(), created_at: now, size };
    // Best effort from here: a copy left behind is removed after the next backup.
    let Ok(files) = store.list() else { return Ok((made, password_changed_at > 0)) };
    for stale in plan::obsolete(&files, backup_id, password_changed_at, Some(&uploaded.id)) {
        let _ = store.delete(&stale.file_id);
    }
    let left = match store.list() {
        Ok(files) => plan::old_password_backups_left(&files, backup_id, password_changed_at, Some(&uploaded.id)),
        Err(_) => password_changed_at > 0,
    };
    Ok((made, left))
}

/// A sentence for the card. Android's wording, for a backup rather than a sync pass.
fn message(error: &CloudError) -> String {
    match error {
        CloudError::Auth => cloud::AUTH_NEEDED.to_owned(),
        CloudError::Offline => "Can't reach Google Drive. The backup runs again later.".to_owned(),
        CloudError::Quota => "Your Google Drive is full. Free some space, then back up again.".to_owned(),
        CloudError::Busy => "Google Drive is busy. The backup runs again later.".to_owned(),
        CloudError::NotFound | CloudError::Other(_) => "The backup didn't finish. It runs again later.".to_owned(),
    }
}

/// The temporary file a backup is written to before it is uploaded. Only ciphertext, and gone
/// whichever way the pass ends.
struct Temporary(PathBuf);

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl Temporary {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("nuvori-drive-backup-{}.pvault", uuid::Uuid::new_v4().simple())))
    }
}

/// What one pass found to do.
enum Pass {
    /// Another pass is already running.
    Busy,
    /// Nothing to do: backups are off, not due, the vault is locked or the Drive is not connected.
    Idle,
    Done,
    Failed(String),
}

/// When the next backup is due. A master password that changed after the last backup makes one due
/// at once: the backups in the Drive still open with the old password, and the plan deletes them
/// once a new one is up. A failed attempt still holds the next try for `RETRY_AFTER`.
fn due_now(now: i64, last_backup_at: i64, last_attempt_at: i64, password_changed_at: i64, interval_ms: i64) -> bool {
    let last_backup_at = if password_changed_at > last_backup_at { 0 } else { last_backup_at };
    plan::due(now, last_backup_at, last_attempt_at, interval_ms)
}

/// One pass: write the backup while the vault is open, then upload it with the vault free again.
/// `force` is "Back up now", which ignores the schedule.
fn pass(state: &ManagedState, force: bool) -> Pass {
    let Some(_running) = Running::start() else { return Pass::Busy };
    write_then_upload(state, force)
}

fn write_then_upload(state: &ManagedState, force: bool) -> Pass {
    let now = activity::now_millis() as i64;
    let temporary = Temporary::new();
    // The vault stays locked for the write only: the upload can take minutes on a slow line.
    let prepared = {
        let Ok(mut app) = state.lock() else { return Pass::Idle };
        let Some(vault) = app.unlocked.as_mut() else { return Pass::Idle };
        let Ok(Some(saved)) = read(vault.connection()) else { return Pass::Idle };
        let Some(key) = saved.key else { return Pass::Idle };
        if !saved.enabled {
            return Pass::Idle;
        }
        if !force && !due_now(now, saved.last_backup_at, saved.last_attempt_at, saved.password_changed_at, saved.interval_ms) {
            return Pass::Idle;
        }
        let Some(account) = cloud::account(vault.connection()) else { return Pass::Idle };
        // The master password changed, so this key would write a backup only the old one opens.
        // The card asks for the password; nothing is uploaded until it has it.
        if app.store.password_salt().ok().as_deref() != Some(saved.password_salt.as_str()) {
            return Pass::Idle;
        }
        let appearance = crate::appearance::installed().map(|store| {
            let stored = store.load();
            (stored.accent, stored.surface)
        });
        let Some(vault) = app.unlocked.as_mut() else { return Pass::Idle };
        let _ = vault.connection().execute("UPDATE drive_backup_settings SET last_attempt_at = ?1 WHERE id = 1", [now]);
        let written = backup_export::save(vault, &temporary.0, &key, appearance);
        (written, saved.backup_id, saved.password_changed_at, account)
    };
    let (written, backup_id, password_changed_at, account) = prepared;
    let written = match written {
        Ok(written) => written,
        Err(error) => {
            activity::diagnostic(Category::Vault, "Drive backup could not be written", &error);
            return finish(state, now, Err("Couldn't write the backup on this PC. Check free disk space.".to_owned()));
        }
    };
    let mut drive = google_drive::GoogleDrive::new(account.refresh_token.clone());
    match upload(&mut Drive(&mut drive), &backup_id, now, &temporary.0, password_changed_at) {
        Ok((_, old_left)) => {
            if password_changed_at > 0 && !old_left {
                let _ = with_vault(state, |db| {
                    db.execute("UPDATE drive_backup_settings SET password_changed_at = 0 WHERE id = 1", []).map(|_| ())
                });
            }
            finish(state, now, Ok((written.items, written.photos)))
        }
        Err(error) => {
            if !matches!(error, CloudError::Auth | CloudError::Offline | CloudError::Busy) {
                activity::diagnostic(Category::Vault, "Drive backup failed", format!("{error:?}"));
            }
            finish(state, now, Err(message(&error)))
        }
    }
}

/// Writes the outcome of a pass to the settings and the activity log.
fn finish(state: &ManagedState, now: i64, outcome: Result<(usize, usize), String>) -> Pass {
    match outcome {
        Ok((items, photos)) => {
            let _ = with_vault(state, |db| {
                db.execute(
                    "UPDATE drive_backup_settings SET last_backup_at = ?1, last_error = '' WHERE id = 1",
                    [now],
                )
                .map(|_| ())
            });
            activity::log(
                Level::Success,
                Category::Vault,
                format!("Backed up to Google Drive with {items} items and {photos} photos"),
            );
            Pass::Done
        }
        Err(error) => {
            let _ = with_vault(state, |db| {
                db.execute("UPDATE drive_backup_settings SET last_error = ?1 WHERE id = 1", [&error]).map(|_| ())
            });
            activity::log(Level::Warning, Category::Vault, "A Google Drive backup didn't finish");
            Pass::Failed(error)
        }
    }
}

/// Runs `work` on the unlocked vault's database. The vault may have locked while a pass ran, and
/// then the outcome is simply not recorded.
fn with_vault<T>(state: &ManagedState, work: impl FnOnce(&Connection) -> Result<T, rusqlite::Error>) -> Result<T, String> {
    let mut app = state.lock().map_err(|_| "Vault state unavailable".to_owned())?;
    let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
    work(vault.connection()).map_err(storage)
}

/// The card's state, read fresh each time it polls.
fn read_status(state: &ManagedState) -> Result<Status, String> {
    let mut app = state.lock().map_err(|_| "Vault state unavailable".to_owned())?;
    let salt = app.store.password_salt().map_err(public_vault_error)?;
    let vault = app.unlocked.as_mut().ok_or("Unlock the vault first")?;
    let account = cloud::account(vault.connection());
    let saved = read(vault.connection()).map_err(storage)?;
    let saved = saved.unwrap_or(Saved {
        enabled: false,
        interval_ms: plan::DEFAULT_INTERVAL,
        backup_id: String::new(),
        key: None,
        password_salt: String::new(),
        password_set_at: 0,
        password_changed_at: 0,
        last_backup_at: 0,
        last_attempt_at: 0,
        last_error: String::new(),
    });
    let enabled = saved.enabled && saved.key.is_some();
    Ok(Status {
        available: google_drive::client().is_some(),
        connected: account.is_some(),
        account: account.map(|account| account.account).unwrap_or_default(),
        enabled,
        interval_ms: saved.interval_ms,
        last_backup_at: saved.last_backup_at,
        running: RUNNING.load(Ordering::SeqCst),
        needs_password: enabled && saved.password_salt != salt,
        needs_sign_in: saved.last_error == cloud::AUTH_NEEDED,
        password_set_at: saved.password_set_at,
        last_error: saved.last_error,
    })
}

#[tauri::command]
pub fn drive_backup_status(state: State<'_, ManagedState>) -> Result<Status, String> {
    read_status(state.inner())
}

/// Turns backups on, and takes the master password again after it changed. Checks the password
/// first, then makes the backup key from it (one Argon2id run, so off the UI thread).
#[tauri::command]
pub async fn set_drive_backup(
    password: String,
    interval_ms: i64,
    state: State<'_, ManagedState>,
) -> Result<Status, String> {
    if !plan::valid_interval(interval_ms) {
        return Err("Choose how often to back up.".into());
    }
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let password = Zeroizing::new(password);
        let (kdf, salt) = {
            let app = state.lock().map_err(|_| "Vault state unavailable")?;
            if app.unlocked.is_none() {
                return Err("Unlock the vault first".to_owned());
            }
            app.store.verify_password(&password).map_err(|error| {
                activity::log(Level::Warning, Category::Security, "Google Drive backup blocked: wrong password");
                public_vault_error(error)
            })?;
            (app.store.backup_kdf().map_err(public_vault_error)?, app.store.password_salt().map_err(public_vault_error)?)
        };
        // No vault lock while the key is derived.
        let key = BackupKey::new(&password, kdf).map_err(|error| {
            activity::diagnostic(Category::Vault, "Drive backup key failed", &error);
            "Couldn't prepare the backup key. Try again.".to_owned()
        })?;
        drop(password);
        let now = activity::now_millis() as i64;
        with_vault(&state, |db| {
            save_key(db, &key, &salt, interval_ms, now)?;
            Ok(())
        })?;
        activity::log(Level::Success, Category::Vault, "Google Drive backup is on for this PC");
        read_status(&state)
    })
    .await
    .map_err(|_| "Couldn't turn on Google Drive backup. Try again.".to_owned())?
}

#[tauri::command]
pub fn set_drive_backup_interval(interval_ms: i64, state: State<'_, ManagedState>) -> Result<Status, String> {
    if !plan::valid_interval(interval_ms) {
        return Err("Choose how often to back up.".into());
    }
    let state = state.inner();
    with_vault(state, |db| {
        db.execute_batch(SCHEMA)?;
        db.execute("UPDATE drive_backup_settings SET interval_ms = ?1 WHERE id = 1", [interval_ms]).map(|_| ())
    })?;
    read_status(state)
}

#[tauri::command]
pub fn turn_off_drive_backup(state: State<'_, ManagedState>) -> Result<Status, String> {
    let state = state.inner();
    with_vault(state, forget_key)?;
    activity::log(Level::Info, Category::Vault, "Google Drive backup is off for this PC");
    read_status(state)
}

/// "Back up now": one pass whatever the schedule says.
#[tauri::command]
pub async fn back_up_to_drive_now(state: State<'_, ManagedState>) -> Result<Status, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let status = read_status(&state)?;
        if !status.enabled {
            return Err("Turn on Google Drive backup first.".to_owned());
        }
        if status.needs_password {
            return Err("Enter your master password to back up with it.".to_owned());
        }
        if !status.connected {
            return Err("Connect Google Drive on this PC first.".to_owned());
        }
        match pass(&state, true) {
            Pass::Failed(error) => Err(error),
            Pass::Busy => Err("A backup is already running.".to_owned()),
            Pass::Idle => Err("Couldn't start the backup. Unlock the vault and try again.".to_owned()),
            Pass::Done => read_status(&state),
        }
    })
    .await
    .map_err(|_| "The backup stopped unexpectedly.".to_owned())?
}

/// Looks every [`TICK`] for a backup that is due. A thread of its own: the sync loop only runs for
/// a PC that is paired with a phone, and a backup is most useful for one that is not.
pub fn start(state: ManagedState) {
    if google_drive::client().is_none() {
        return;
    }
    thread::spawn(move || {
        loop {
            thread::sleep(TICK);
            let _ = pass(&state, false);
        }
    });
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[derive(Default)]
    struct FakeDrive {
        files: Vec<(CloudFile, Vec<u8>)>,
        next: usize,
        fail_upload: Option<CloudError>,
        deleted: Vec<String>,
    }

    impl FakeDrive {
        fn with(&mut self, name: &str, body: &[u8]) -> String {
            self.next += 1;
            let id = format!("drive-{}", self.next);
            self.files.push((
                CloudFile { id: id.clone(), name: name.to_owned(), size: body.len() as u64, modified: String::new() },
                body.to_vec(),
            ));
            id
        }

        fn names(&self) -> Vec<String> {
            self.files.iter().map(|(file, _)| file.name.clone()).collect()
        }
    }

    impl BackupStore for FakeDrive {
        fn list(&mut self) -> Result<Vec<CloudFile>, CloudError> {
            Ok(self.files.iter().map(|(file, _)| file.clone()).collect())
        }

        fn upload(&mut self, name: &str, size: u64, path: &Path) -> Result<CloudFile, CloudError> {
            if let Some(error) = self.fail_upload.take() {
                return Err(error);
            }
            let mut body = Vec::new();
            File::open(path).unwrap().read_to_end(&mut body).unwrap();
            assert_eq!(body.len() as u64, size, "the size the uploader reported");
            let id = self.with(name, &body);
            Ok(self.files.iter().find(|(file, _)| file.id == id).unwrap().0.clone())
        }

        fn delete(&mut self, id: &str) -> Result<(), CloudError> {
            self.deleted.push(id.to_owned());
            self.files.retain(|(file, _)| file.id != id);
            Ok(())
        }
    }

    const THIS: &str = "0123456789abcdef";
    const OTHER: &str = "fedcba9876543210";

    /// A file of `body` to upload, removed when the test ends.
    fn file(body: &[u8]) -> Temporary {
        let temporary = Temporary::new();
        File::create(&temporary.0).unwrap().write_all(body).unwrap();
        temporary
    }

    #[test]
    fn a_backup_is_uploaded_under_this_pcs_name() {
        let mut drive = FakeDrive::default();
        let backup = file(b"ciphertext");
        let (made, old_left) = upload(&mut drive, THIS, 1_764_000_000_000, &backup.0, 0).unwrap();
        assert_eq!(drive.names(), ["nvbak1.0123456789abcdef.1764000000000"]);
        assert_eq!(made.size, 10);
        assert!(!old_left);
    }

    #[test]
    fn an_empty_backup_is_never_uploaded() {
        let mut drive = FakeDrive::default();
        let backup = file(b"");
        assert!(upload(&mut drive, THIS, 1, &backup.0, 0).is_err());
        assert!(drive.names().is_empty());
    }

    #[test]
    fn a_missing_file_is_never_uploaded() {
        let mut drive = FakeDrive::default();
        let gone = Temporary::new();
        assert!(upload(&mut drive, THIS, 1, &gone.0, 0).is_err());
        assert!(drive.names().is_empty());
    }

    #[test]
    fn only_this_pcs_older_backups_are_removed() {
        let mut drive = FakeDrive::default();
        for (device, at) in [(THIS, 300), (THIS, 200), (THIS, 100), (OTHER, 100)] {
            drive.with(&plan::name(device, at).unwrap(), b"older");
        }
        let backup = file(b"ciphertext");
        upload(&mut drive, THIS, 400, &backup.0, 0).unwrap();
        assert_eq!(
            drive.names(),
            [
                plan::name(THIS, 300).unwrap(),
                plan::name(OTHER, 100).unwrap(),
                plan::name(THIS, 400).unwrap(),
            ],
            "the newest two of this PC's, and the other device's"
        );
    }

    #[test]
    fn a_failed_upload_leaves_every_older_backup_alone() {
        let mut drive = FakeDrive { fail_upload: Some(CloudError::Offline), ..FakeDrive::default() };
        for at in [300, 200, 100] {
            drive.with(&plan::name(THIS, at).unwrap(), b"older");
        }
        let backup = file(b"ciphertext");
        assert!(matches!(upload(&mut drive, THIS, 400, &backup.0, 0), Err(CloudError::Offline)));
        assert_eq!(drive.names().len(), 3);
        assert!(drive.deleted.is_empty());
    }

    #[test]
    fn backups_with_the_old_master_password_go_once_a_new_one_is_up() {
        let mut drive = FakeDrive::default();
        drive.with(&plan::name(THIS, 100).unwrap(), b"old password");
        let backup = file(b"ciphertext");
        let (_, old_left) = upload(&mut drive, THIS, 400, &backup.0, 200).unwrap();
        assert_eq!(drive.names(), [plan::name(THIS, 400).unwrap()]);
        assert!(!old_left, "nothing with the old password is left, so the app stops saying so");
    }

    #[test]
    fn an_old_password_backup_that_could_not_be_deleted_is_still_reported() {
        struct Stubborn(FakeDrive);
        impl BackupStore for Stubborn {
            fn list(&mut self) -> Result<Vec<CloudFile>, CloudError> {
                self.0.list()
            }
            fn upload(&mut self, name: &str, size: u64, path: &Path) -> Result<CloudFile, CloudError> {
                self.0.upload(name, size, path)
            }
            fn delete(&mut self, _id: &str) -> Result<(), CloudError> {
                Err(CloudError::Busy)
            }
        }
        let mut drive = Stubborn(FakeDrive::default());
        drive.0.with(&plan::name(THIS, 100).unwrap(), b"old password");
        let backup = file(b"ciphertext");
        let (_, old_left) = upload(&mut drive, THIS, 400, &backup.0, 200).unwrap();
        assert!(old_left, "the card keeps asking until the file is gone");
    }

    #[test]
    fn the_temporary_file_goes_with_the_pass() {
        let path = {
            let backup = file(b"ciphertext");
            assert!(backup.0.is_file());
            backup.0.clone()
        };
        assert!(!path.is_file(), "only ciphertext, and only while the pass runs");
    }

    #[test]
    fn a_new_backup_id_is_sixteen_hexadecimal_characters() {
        let first = new_backup_id();
        assert!(plan::valid_backup_id(&first), "{first}");
        assert_ne!(first, new_backup_id());
    }

    #[test]
    fn a_master_password_that_changed_makes_a_backup_due_at_once() {
        let (last_backup, interval) = (1_000_000, plan::WEEK);
        let now = last_backup + plan::DAY;
        assert!(!due_now(now, last_backup, 0, 0, interval), "the week is not up");
        assert!(due_now(now, last_backup, 0, last_backup + 1, interval), "the password changed after the last backup");
        assert!(!due_now(now, last_backup, 0, last_backup - 1, interval), "that change is already in the newest backup");
    }

    #[test]
    fn a_failed_backup_after_a_password_change_still_waits_before_the_next_try() {
        let (last_backup, changed) = (1_000_000, 1_000_001);
        let attempt = changed + 10;
        assert!(!due_now(attempt + 60_000, last_backup, attempt, changed, plan::DAY), "a minute later, no");
        assert!(due_now(attempt + plan::RETRY_AFTER, last_backup, attempt, changed, plan::DAY));
    }

    #[test]
    fn every_failure_has_a_sentence_without_account_or_file_data() {
        for error in [
            CloudError::Auth,
            CloudError::Offline,
            CloudError::Quota,
            CloudError::Busy,
            CloudError::NotFound,
            CloudError::Other("nvbak1.0123456789abcdef.1764000000000 at user@example.com".into()),
        ] {
            let message = message(&error);
            assert!(message.ends_with('.') && message.len() > 20, "{message}");
            assert!(!message.contains('@') && !message.contains("nvbak"), "{message}");
        }
    }
}
