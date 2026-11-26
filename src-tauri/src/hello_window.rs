//! How long Windows Hello may open the vault after the master password was last typed. This is
//! Android's "Require the master password again" (`LockTiming.kt`, `biometricSessionValid`):
//! every unlock, after 1 day (the default) or after 1 week, and never longer (Android's security
//! review L-04).
//!
//! The window lives in the encrypted database, so only the vault key can read or change it, and
//! [crate::vault::VaultStore::unlock_hello] checks it before the vault opens. Typing the master
//! password (creating the vault, unlocking with it, turning on Windows Hello) starts a new window.
//! A wall clock set back to before the last unlock closes the window, as on Android.
//!
//! Unlike Android, the window survives a restart, as Windows Hello unlock always has here: the
//! Hello key is bound to this PC's Windows Hello, not to one boot.
//!
//! The lock screen can't read the database, so it reads a plain [HINT_FILE] that holds only when
//! the window closes, or `0` for every unlock. The hint decides whether the Windows Hello button
//! shows; it never opens the vault. Editing it can only show or hide the button, and the database
//! still decides.

use rusqlite::{params, Connection, OptionalExtension};
use std::fs;
use std::io;
use std::path::Path;

pub const DAY_MS: i64 = 86_400_000;
pub const WEEK_MS: i64 = 604_800_000;
/// Every unlock, 1 day or 1 week, as on Android (`masterPasswordIntervals`).
pub const INTERVALS: [i64; 3] = [0, DAY_MS, WEEK_MS];
pub const DEFAULT_INTERVAL_MS: i64 = DAY_MS;
/// When the window closes, in Unix milliseconds, as decimal text, or `0` for every unlock. Never
/// anything secret.
pub const HINT_FILE: &str = "hello-unlock-v1.until";
/// What a Windows Hello unlock says once the window has closed.
pub const CLOSED: &str = "Enter your master password. Windows Hello works again after that.";
/// What a Windows Hello unlock says while the master password is asked for at every unlock.
pub const EVERY_UNLOCK: &str = "Enter your master password. Nuvori asks for it at every unlock, as set in Settings.";

/// What a refused Windows Hello unlock says for a window with `interval_ms`.
pub fn refusal(interval_ms: i64) -> &'static str {
    if interval_ms == 0 { EVERY_UNLOCK } else { CLOSED }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// How often the master password is asked for again: one of [INTERVALS].
    pub interval_ms: i64,
    /// When the master password was last typed, in Unix milliseconds; 0 when never, or when a new
    /// choice of interval ended the window.
    pub password_at: i64,
    /// The latest unlock time seen, so a clock set back is noticed.
    pub last_seen_at: i64,
}

impl Default for Window {
    /// A vault from before this setting: 1 day, and the master password once before Hello works.
    fn default() -> Self {
        Self { interval_ms: DEFAULT_INTERVAL_MS, password_at: 0, last_seen_at: 0 }
    }
}

/// A stored interval brought within [INTERVALS], like Android's `capMasterPasswordInterval`.
pub fn cap(interval_ms: i64) -> i64 {
    match interval_ms {
        value if INTERVALS.contains(&value) => value,
        value if value <= 0 => 0,
        value if value >= WEEK_MS => WEEK_MS,
        _ => DAY_MS,
    }
}

/// Whether Windows Hello may open the vault at `now`.
pub fn allows(window: &Window, now: i64) -> bool {
    INTERVALS.contains(&window.interval_ms)
        && window.interval_ms > 0
        && window.password_at > 0
        && now >= window.password_at
        && now >= window.last_seen_at
        && now - window.password_at < window.interval_ms
}

/// When the window closes, in Unix milliseconds; 0 when Windows Hello is not to be offered.
pub fn closes_at(window: &Window) -> i64 {
    if INTERVALS.contains(&window.interval_ms) && window.interval_ms > 0 && window.password_at > 0 {
        window.password_at.saturating_add(window.interval_ms)
    } else {
        0
    }
}

fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS hello_window (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
            interval_ms INTEGER NOT NULL CHECK (interval_ms IN (0, 86400000, 604800000)),
            password_at INTEGER NOT NULL DEFAULT 0,
            last_seen_at INTEGER NOT NULL DEFAULT 0
        );",
    )
}

/// The saved window. Reads only: a vault that has none yet gets [Window::default].
pub fn read(connection: &Connection) -> rusqlite::Result<Window> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'hello_window')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Window::default());
    }
    Ok(connection
        .query_row("SELECT interval_ms, password_at, last_seen_at FROM hello_window WHERE id = 1", [], |row| {
            Ok(Window { interval_ms: row.get(0)?, password_at: row.get(1)?, last_seen_at: row.get(2)? })
        })
        .optional()?
        .unwrap_or_default())
}

/// The master password was typed at `now`: a new window starts, and the clock check starts over.
pub fn record_password(connection: &Connection, now: i64) -> rusqlite::Result<Window> {
    initialize(connection)?;
    connection.execute(
        "INSERT INTO hello_window (id, interval_ms, password_at, last_seen_at) VALUES (1, ?1, ?2, ?2)
         ON CONFLICT (id) DO UPDATE SET password_at = excluded.password_at, last_seen_at = excluded.last_seen_at",
        params![DEFAULT_INTERVAL_MS, now],
    )?;
    read(connection)
}

/// Windows Hello opened the vault at `now`. The window keeps its start.
pub fn record_hello(connection: &Connection, now: i64) -> rusqlite::Result<()> {
    initialize(connection)?;
    connection.execute("UPDATE hello_window SET last_seen_at = max(last_seen_at, ?1) WHERE id = 1", [now])?;
    Ok(())
}

/// Saves a new choice from [INTERVALS]. A different choice ends the current window, as Android
/// ends its fingerprint session: the next unlock asks for the master password. Returns whether the
/// choice changed.
pub fn set_interval(connection: &Connection, interval_ms: i64) -> rusqlite::Result<bool> {
    if !INTERVALS.contains(&interval_ms) {
        return Err(rusqlite::Error::InvalidParameterName("interval_ms".to_owned()));
    }
    if read(connection)?.interval_ms == interval_ms {
        return Ok(false);
    }
    initialize(connection)?;
    connection.execute(
        "INSERT INTO hello_window (id, interval_ms, password_at, last_seen_at) VALUES (1, ?1, 0, 0)
         ON CONFLICT (id) DO UPDATE SET interval_ms = excluded.interval_ms, password_at = 0",
        [interval_ms],
    )?;
    Ok(true)
}

/// What the lock screen does about Windows Hello, from [HINT_FILE].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hint {
    /// Offer Windows Hello.
    Open,
    /// Ask for the master password, then Windows Hello works again.
    Closed,
    /// The master password at every unlock: Windows Hello is never offered.
    EveryUnlock,
}

/// Saves the lock-screen hint for `window`. A window that a new choice ended has none, which
/// reads as [Hint::Closed].
pub fn write_hint(directory: &Path, window: &Window) -> io::Result<()> {
    if window.interval_ms == 0 {
        return fs::write(directory.join(HINT_FILE), "0");
    }
    match closes_at(window) {
        0 => remove_hint(directory),
        until => fs::write(directory.join(HINT_FILE), until.to_string()),
    }
}

pub fn remove_hint(directory: &Path) -> io::Result<()> {
    match fs::remove_file(directory.join(HINT_FILE)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// What the lock screen does about Windows Hello at `now`. A missing, unreadable or odd hint reads
/// as [Hint::Closed]: the master password is always offered.
pub fn read_hint(directory: &Path, now: i64) -> Hint {
    let Ok(text) = fs::read(directory.join(HINT_FILE)) else { return Hint::Closed };
    if text.len() > 20 {
        return Hint::Closed;
    }
    match std::str::from_utf8(&text).ok().and_then(|text| text.trim().parse::<i64>().ok()) {
        Some(0) => Hint::EveryUnlock,
        Some(until) if now < until && until - now <= WEEK_MS => Hint::Open,
        _ => Hint::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000_000;

    fn window(interval_ms: i64, password_at: i64, last_seen_at: i64) -> Window {
        Window { interval_ms, password_at, last_seen_at }
    }

    #[test]
    fn hello_opens_only_inside_the_chosen_window() {
        assert!(allows(&window(DAY_MS, NOW, NOW), NOW));
        assert!(allows(&window(DAY_MS, NOW, NOW), NOW + DAY_MS - 1));
        assert!(!allows(&window(DAY_MS, NOW, NOW), NOW + DAY_MS));
        assert!(allows(&window(WEEK_MS, NOW, NOW), NOW + 6 * DAY_MS));
        assert!(!allows(&window(WEEK_MS, NOW, NOW), NOW + WEEK_MS));
        // Every unlock: never.
        assert!(!allows(&window(0, NOW, NOW), NOW));
        // Never typed, or a new choice ended the window.
        assert!(!allows(&window(DAY_MS, 0, 0), NOW));
        assert!(!allows(&Window::default(), NOW));
    }

    #[test]
    fn a_clock_set_back_closes_the_window() {
        assert!(!allows(&window(DAY_MS, NOW, NOW), NOW - 1));
        // Hello opened the vault at NOW + 1 h; the clock then went back 30 min.
        assert!(!allows(&window(DAY_MS, NOW, NOW + 3_600_000), NOW + 1_800_000));
        assert!(allows(&window(DAY_MS, NOW, NOW + 3_600_000), NOW + 3_600_000));
    }

    #[test]
    fn only_the_three_choices_count() {
        // 2.3.x Android offered 1 month: it never stretches the window here.
        assert!(!allows(&window(2_592_000_000, NOW, NOW), NOW + 1));
        assert!(!allows(&window(3_600_000, NOW, NOW), NOW + 1));
        assert_eq!(cap(2_592_000_000), WEEK_MS);
        assert_eq!(cap(-5), 0);
        assert_eq!(cap(3_600_000), DAY_MS);
        assert_eq!(cap(WEEK_MS), WEEK_MS);
        assert_eq!(closes_at(&window(2_592_000_000, NOW, NOW)), 0);
        assert_eq!(closes_at(&window(0, NOW, NOW)), 0);
        assert_eq!(closes_at(&window(DAY_MS, 0, 0)), 0);
        assert_eq!(closes_at(&window(WEEK_MS, NOW, NOW)), NOW + WEEK_MS);
        assert_eq!(refusal(0), EVERY_UNLOCK);
        assert_eq!(refusal(DAY_MS), CLOSED);
        assert_eq!(refusal(WEEK_MS), CLOSED);
    }

    #[test]
    fn database_keeps_the_window_and_a_new_choice_ends_it() {
        let connection = Connection::open_in_memory().unwrap();
        assert_eq!(read(&connection).unwrap(), Window::default());

        let started = record_password(&connection, NOW).unwrap();
        assert_eq!(started, window(DAY_MS, NOW, NOW));
        record_hello(&connection, NOW + 1000).unwrap();
        // An earlier time never moves the clock check back.
        record_hello(&connection, NOW + 10).unwrap();
        assert_eq!(read(&connection).unwrap(), window(DAY_MS, NOW, NOW + 1000));

        // The same choice changes nothing.
        assert!(!set_interval(&connection, DAY_MS).unwrap());
        assert!(allows(&read(&connection).unwrap(), NOW + 2000));
        // A new choice ends the window until the master password is typed again.
        assert!(set_interval(&connection, WEEK_MS).unwrap());
        assert!(!allows(&read(&connection).unwrap(), NOW + 2000));
        assert_eq!(record_password(&connection, NOW + 3000).unwrap(), window(WEEK_MS, NOW + 3000, NOW + 3000));
        assert!(allows(&read(&connection).unwrap(), NOW + 6 * DAY_MS));

        assert!(set_interval(&connection, 0).unwrap());
        assert!(!allows(&record_password(&connection, NOW + 4000).unwrap(), NOW + 4000));

        // Anything else is refused, by this check and by the table.
        assert!(set_interval(&connection, 2_592_000_000).is_err());
        assert!(connection.execute("UPDATE hello_window SET interval_ms = 2592000000 WHERE id = 1", []).is_err());
        assert_eq!(read(&connection).unwrap().interval_ms, 0);
    }

    #[test]
    fn a_first_choice_on_an_older_vault_is_saved() {
        let connection = Connection::open_in_memory().unwrap();
        assert!(!set_interval(&connection, DAY_MS).unwrap());
        assert!(set_interval(&connection, WEEK_MS).unwrap());
        assert_eq!(read(&connection).unwrap(), window(WEEK_MS, 0, 0));
        // record_hello on a vault without the table changes nothing.
        let other = Connection::open_in_memory().unwrap();
        record_hello(&other, NOW).unwrap();
        assert_eq!(read(&other).unwrap(), Window::default());
    }

    #[test]
    fn hint_only_says_what_the_lock_screen_shows() {
        let directory = std::env::temp_dir().join(format!("nuvori-hello-window-{}-{}", std::process::id(), NOW));
        fs::create_dir_all(&directory).unwrap();
        assert_eq!(read_hint(&directory, NOW), Hint::Closed);

        write_hint(&directory, &window(DAY_MS, NOW, NOW)).unwrap();
        assert_eq!(fs::read_to_string(directory.join(HINT_FILE)).unwrap(), (NOW + DAY_MS).to_string());
        assert_eq!(read_hint(&directory, NOW + 1), Hint::Open);
        assert_eq!(read_hint(&directory, NOW + DAY_MS), Hint::Closed);

        // Every unlock says so, before and after the master password.
        write_hint(&directory, &window(0, 0, 0)).unwrap();
        assert_eq!(read_hint(&directory, NOW), Hint::EveryUnlock);
        write_hint(&directory, &window(0, NOW, NOW)).unwrap();
        assert_eq!(read_hint(&directory, NOW), Hint::EveryUnlock);
        // A window a new choice ended has no hint.
        write_hint(&directory, &window(WEEK_MS, NOW, NOW)).unwrap();
        write_hint(&directory, &window(WEEK_MS, 0, 0)).unwrap();
        assert!(!directory.join(HINT_FILE).exists());
        assert_eq!(read_hint(&directory, NOW), Hint::Closed);

        // An edited hint never claims more than a week, and junk means the master password.
        fs::write(directory.join(HINT_FILE), (NOW + 30 * DAY_MS).to_string()).unwrap();
        assert_eq!(read_hint(&directory, NOW), Hint::Closed);
        fs::write(directory.join(HINT_FILE), "soon").unwrap();
        assert_eq!(read_hint(&directory, NOW), Hint::Closed);
        fs::write(directory.join(HINT_FILE), "-5").unwrap();
        assert_eq!(read_hint(&directory, NOW), Hint::Closed);
        fs::write(directory.join(HINT_FILE), "9".repeat(64)).unwrap();
        assert_eq!(read_hint(&directory, NOW), Hint::Closed);

        remove_hint(&directory).unwrap();
        remove_hint(&directory).unwrap();
        assert!(!directory.join(HINT_FILE).exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
