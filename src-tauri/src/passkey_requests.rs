//! "Passkey requests": what Windows asked this PC's passkey provider, newest first.
//!
//! Windows decides by itself whether Nuvori appears in a passkey prompt, so when it does not
//! appear there is nothing on screen to go by. This log answers the two questions that follow:
//! did Windows ask Nuvori at all, and if it did, why did Nuvori not offer a passkey? Android
//! answers them the same way (`passkeys/PasskeyRequestLog.kt`).
//!
//! The lines live in the encrypted vault database, like previous passwords and the trash
//! (`local_recovery`), so they have the same protection as the items themselves and nothing about
//! them sits anywhere else on the PC. They are never synced and are not part of a backup.
//!
//! A line holds the time, whether Windows wanted a new passkey or a sign-in, the site, whether
//! Nuvori offered a passkey and the reason it did not. It never holds a challenge, a user handle,
//! an account name, a credential or any key material.
//!
//! Windows can ask while the vault is locked, which is one of the answers worth having. There is
//! nowhere to write then, so such a line waits in memory ([`hold`]) and is written at the next
//! unlock, keeping the time it happened. A line held when Nuvori closes is lost: it is a
//! convenience, and the vault's own protection comes first.

use std::sync::Mutex;

use rusqlite::{Connection, params};

/// The newest requests that are kept. The oldest line goes when a new one arrives.
pub const CAPACITY: i64 = 100;
/// A hostname is at most 253 characters; a reason is one short sentence.
const MAX_SITE: usize = 253;
const MAX_REASON: usize = 160;

/// Lines that arrived while the vault was locked, oldest first.
static HELD: Mutex<Vec<Request>> = Mutex::new(Vec::new());

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// Unix time in milliseconds.
    pub at: i64,
    /// True when Windows wanted to save a new passkey, false for a sign-in.
    pub create: bool,
    /// The website the passkey is for, empty when the request never named one.
    pub site: String,
    pub offered: bool,
    /// Why Nuvori did not offer a passkey. Empty when it did.
    pub reason: String,
}

impl Request {
    /// Keeps a line within its lengths, whatever the request held.
    pub fn new(at: i64, create: bool, site: &str, offered: bool, reason: &str) -> Self {
        Self {
            at,
            create,
            site: cut(site, MAX_SITE),
            offered,
            reason: if offered { String::new() } else { cut(reason, MAX_REASON) },
        }
    }
}

fn cut(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

pub fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS local_passkey_requests (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            at INTEGER NOT NULL,
            create_request INTEGER NOT NULL,
            site TEXT NOT NULL,
            offered INTEGER NOT NULL,
            reason TEXT NOT NULL
        );",
    )
}

/// Keeps a line until the vault is open, for a request that arrived while it was locked.
pub fn hold(request: Request) {
    if let Ok(mut held) = HELD.lock() {
        if held.len() >= CAPACITY as usize {
            held.remove(0);
        }
        held.push(request);
    }
}

/// Writes a line, after any that waited in memory, and keeps the newest [`CAPACITY`].
pub fn record(connection: &Connection, request: Request) -> rusqlite::Result<()> {
    write_held(connection)?;
    insert(connection, &request)?;
    trim(connection)
}

/// The saved requests, newest first. Lines that waited in memory are written first, so the page
/// shows the request that found the vault locked as soon as it is open.
pub fn recent(connection: &Connection) -> rusqlite::Result<Vec<Request>> {
    write_held(connection)?;
    let mut statement = connection.prepare(
        "SELECT at, create_request, site, offered, reason FROM local_passkey_requests
         ORDER BY at DESC, seq DESC LIMIT ?1",
    )?;
    let rows = statement.query_map([CAPACITY], |row| {
        Ok(Request::new(
            row.get(0)?,
            row.get(1)?,
            &row.get::<_, String>(2)?,
            row.get(3)?,
            &row.get::<_, String>(4)?,
        ))
    })?;
    rows.collect()
}

/// Forgets every line, the ones still waiting in memory too. "Clear history" in the app.
pub fn clear(connection: &Connection) -> rusqlite::Result<()> {
    if let Ok(mut held) = HELD.lock() {
        held.clear();
    }
    connection.execute("DELETE FROM local_passkey_requests", [])?;
    Ok(())
}

fn write_held(connection: &Connection) -> rusqlite::Result<()> {
    let waiting = match HELD.lock() {
        Ok(mut held) => std::mem::take(&mut *held),
        Err(_) => return Ok(()),
    };
    if waiting.is_empty() {
        return Ok(());
    }
    for request in &waiting {
        insert(connection, request)?;
    }
    trim(connection)
}

fn insert(connection: &Connection, request: &Request) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO local_passkey_requests (at, create_request, site, offered, reason)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![request.at, request.create, request.site, request.offered, request.reason],
    )?;
    Ok(())
}

fn trim(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute(
        "DELETE FROM local_passkey_requests WHERE seq NOT IN
         (SELECT seq FROM local_passkey_requests ORDER BY seq DESC LIMIT ?1)",
        [CAPACITY],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What waits in memory belongs to the process, so these tests take turns over it.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn vault() -> (Connection, std::sync::MutexGuard<'static, ()>) {
        let turn = ONE_AT_A_TIME.lock().unwrap_or_else(|held| held.into_inner());
        if let Ok(mut held) = HELD.lock() {
            held.clear();
        }
        let connection = Connection::open_in_memory().unwrap();
        initialize(&connection).unwrap();
        (connection, turn)
    }

    fn refused(at: i64) -> Request {
        Request::new(at, false, "example.com", false, "No passkey for this site is saved on this PC")
    }

    #[test]
    fn a_line_comes_back_as_it_was_written_newest_first() {
        let (connection, _turn) = vault();
        record(&connection, refused(1_000)).unwrap();
        record(&connection, Request::new(2_000, true, "shop.example", true, "ignored")).unwrap();
        let read = recent(&connection).unwrap();
        assert_eq!(read.iter().map(|line| line.at).collect::<Vec<_>>(), vec![2_000, 1_000]);
        assert_eq!(
            (read[0].create, read[0].offered, read[0].site.as_str(), read[0].reason.as_str()),
            (true, true, "shop.example", ""),
        );
        assert_eq!(read[1].reason, "No passkey for this site is saved on this PC");
    }

    #[test]
    fn only_the_newest_hundred_are_kept() {
        let (connection, _turn) = vault();
        for at in 0..(CAPACITY + 10) {
            record(&connection, refused(at)).unwrap();
        }
        let read = recent(&connection).unwrap();
        assert_eq!(read.len(), CAPACITY as usize);
        assert_eq!((read.first().map(|line| line.at), read.last().map(|line| line.at)), (Some(CAPACITY + 9), Some(10)));
    }

    #[test]
    fn a_request_that_found_the_vault_locked_is_written_at_the_next_unlock() {
        let (connection, _turn) = vault();
        hold(refused(5_000));
        hold(Request::new(6_000, true, "late.example", true, ""));
        // Nothing reached the vault while it was locked.
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM local_passkey_requests", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        // Reading once the vault is open writes them, each with the time it happened.
        let read = recent(&connection).unwrap();
        assert_eq!(read.iter().map(|line| line.at).collect::<Vec<_>>(), vec![6_000, 5_000]);
        // And they are written once, not again on the next read.
        assert_eq!(recent(&connection).unwrap().len(), 2);
    }

    #[test]
    fn what_waits_in_memory_is_bounded_like_the_log() {
        let (connection, _turn) = vault();
        for at in 0..(CAPACITY + 10) {
            hold(refused(at));
        }
        let read = recent(&connection).unwrap();
        assert_eq!(read.len(), CAPACITY as usize);
        assert_eq!(read.last().map(|line| line.at), Some(10));
    }

    #[test]
    fn clearing_forgets_the_lines_and_what_was_waiting() {
        let (connection, _turn) = vault();
        record(&connection, refused(1)).unwrap();
        hold(refused(2));
        clear(&connection).unwrap();
        assert!(recent(&connection).unwrap().is_empty());
        // Clearing an empty log is not an error either.
        clear(&connection).unwrap();
        assert!(recent(&connection).unwrap().is_empty());
    }

    #[test]
    fn a_long_site_or_reason_is_cut_to_its_length() {
        let (connection, _turn) = vault();
        let long = Request::new(1, false, &"a".repeat(400), false, &"b".repeat(400));
        assert_eq!((long.site.len(), long.reason.len()), (MAX_SITE, MAX_REASON));
        // And again when the row holds a longer one, whatever wrote it.
        connection
            .execute(
                "INSERT INTO local_passkey_requests (at, create_request, site, offered, reason)
                 VALUES (2, 0, ?1, 0, ?2)",
                params!["c".repeat(400), "d".repeat(400)],
            )
            .unwrap();
        let read = recent(&connection).unwrap();
        assert_eq!((read[0].site.len(), read[0].reason.len()), (MAX_SITE, MAX_REASON));
    }
}
