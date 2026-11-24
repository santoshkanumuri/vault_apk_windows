//! Previous passwords and recently deleted items, kept only on this PC.
//!
//! Nothing here is synced, and the sync protocol does not change: older Nuvori versions and
//! paired devices see the same signed changes as before. Each device records what it observes:
//! - its own edits and deletes;
//! - incoming changes from paired devices, just before they are applied.
//!
//! A restored item is a new item with a new ID, so it syncs as an ordinary new item. The deleted
//! ID keeps its tombstone everywhere. The Android app has the same rules (`PasswordHistory` and
//! `TrashedEntry` in `data/VaultDatabase.kt`).
//!
//! Both tables live in the encrypted vault database, so they have the same protection as the
//! items themselves. Photos and passkeys are not kept in the trash.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use uuid::Uuid;

/// Recently deleted items stay this long, then they are gone for good.
pub const TRASH_DAYS: i64 = 30;
const TRASH_MILLIS: i64 = TRASH_DAYS * 24 * 60 * 60 * 1000;
/// Previous passwords kept per login, newest first. KeePassXC keeps 10 by default.
pub const HISTORY_LIMIT: i64 = 10;

pub fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS local_password_history (
            entry_id TEXT NOT NULL,
            password TEXT NOT NULL,
            replaced_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS local_password_history_entry ON local_password_history (entry_id, replaced_at);
        CREATE TABLE IF NOT EXISTS local_trash (
            id TEXT NOT NULL PRIMARY KEY,
            item_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            item_type TEXT NOT NULL,
            title TEXT NOT NULL,
            data_json TEXT NOT NULL,
            group_ids TEXT NOT NULL,
            deleted_at INTEGER NOT NULL,
            deleted_elsewhere INTEGER NOT NULL
        );",
    )?;
    // Added later: why an item is here. "" = deleted; [`REASON_JOIN`] = kept aside at a join.
    let has_reason = connection
        .prepare("SELECT 1 FROM pragma_table_info('local_trash') WHERE name = 'reason'")?
        .exists([])?;
    if !has_reason {
        connection.execute("ALTER TABLE local_trash ADD COLUMN reason TEXT NOT NULL DEFAULT ''", [])?;
    }
    Ok(())
}

/// A PC's version that the group already had in another version, kept aside when this PC joined
/// the group (`join_match.rs`). It stays until the person restores or deletes it.
pub const REASON_JOIN: &str = "join";

/// A version received from a paired device that had not applied when this PC learned it was
/// removed (`UnlockedVault::leave_after_removal`). The leave drops the group's key, so the change
/// could never apply later. It stays [`TRASH_DAYS`] like a deleted item, as on Android
/// (`RemovalArchive`), and the person can restore it as a new item.
pub const REASON_REMOVAL: &str = "removal";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviousPassword {
    pub password: String,
    pub replaced_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashedItem {
    pub id: String,
    /// The deleted item's ID: the item page's Undo finds its copy by it.
    pub item_id: String,
    /// "entry" or "note".
    pub kind: String,
    /// The entry type ("PASSWORD", "CARD", ...) or "NOTE".
    pub item_type: String,
    pub title: String,
    pub deleted_at: i64,
    /// Deleted on a paired device; this PC kept its copy.
    pub deleted_elsewhere: bool,
    /// When the item is deleted for good. A join copy ([`REASON_JOIN`]) never expires: 0.
    pub expires_at: i64,
    /// "" (deleted) or [`REASON_JOIN`].
    pub reason: String,
}

/// Before an entry is written: when a login's password changes, keeps the old one.
pub fn note_entry_write(connection: &Connection, id: &str, new_entry: &serde_json::Value, now: i64) -> rusqlite::Result<()> {
    // A connection that skipped the vault's setup (an older vault mid-sync, a test fixture) must
    // never fail a sync because of this local extra.
    initialize(connection)?;
    let old: Option<String> = connection
        .query_row("SELECT data_json FROM local_entries WHERE id = ?1", [id], |row| row.get(0))
        .optional()?;
    let Some(old) = old.and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok()) else {
        return Ok(());
    };
    let old_password = old["secondaryValue"].as_str().unwrap_or_default();
    let new_password = new_entry["secondaryValue"].as_str().unwrap_or_default();
    if old["type"] != "PASSWORD" || old_password.is_empty() || old_password == new_password {
        return Ok(());
    }
    connection.execute(
        "INSERT INTO local_password_history (entry_id, password, replaced_at) VALUES (?1, ?2, ?3)",
        params![id, old_password, now],
    )?;
    connection.execute(
        "DELETE FROM local_password_history WHERE entry_id = ?1 AND rowid NOT IN (
             SELECT rowid FROM local_password_history WHERE entry_id = ?1
             ORDER BY replaced_at DESC, rowid DESC LIMIT ?2)",
        params![id, HISTORY_LIMIT],
    )?;
    Ok(())
}

/// Before an entry or a note is deleted: keeps a copy in the trash. Does nothing when the item
/// is not here (a delete for an item this PC never had).
pub fn keep_deleted(connection: &Connection, id: &str, now: i64, elsewhere: bool) -> rusqlite::Result<()> {
    initialize(connection)?;
    let group_ids: Vec<String> = connection
        .prepare("SELECT group_id FROM entry_groups WHERE entry_id = ?1 ORDER BY group_id")?
        .query_map([id], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let groups = serde_json::to_string(&group_ids).unwrap_or_else(|_| "[]".to_owned());
    let entry: Option<(String, String)> = connection
        .query_row("SELECT type, data_json FROM local_entries WHERE id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    let (kind, item_type, title, data) = if let Some((item_type, data)) = entry {
        let title = serde_json::from_str::<serde_json::Value>(&data).ok()
            .and_then(|value| value["title"].as_str().map(str::to_owned))
            .unwrap_or_default();
        ("entry", item_type, title, data)
    } else {
        let note: Option<(String, String)> = connection
            .query_row("SELECT title, body FROM local_notes WHERE id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let Some((title, body)) = note else { return Ok(()) };
        let data = serde_json::json!({"title": title, "body": body}).to_string();
        ("note", "NOTE".to_owned(), title, data)
    };
    connection.execute(
        "INSERT INTO local_trash (id, item_id, kind, item_type, title, data_json, group_ids, deleted_at, deleted_elsewhere)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![Uuid::new_v4().to_string(), id, kind, item_type, title, data, groups, now, elsewhere],
    )?;
    Ok(())
}

/// Keeps this PC's version of an item that the group holds in another version (a join). The
/// person compares it with the group's version and restores it (as a new item) or deletes it.
#[allow(clippy::too_many_arguments)]
pub fn keep_join_copy(
    connection: &Connection,
    item_id: &str,
    kind: &str,
    item_type: &str,
    title: &str,
    data: &serde_json::Value,
    group_ids: &[String],
    now: i64,
) -> rusqlite::Result<()> {
    initialize(connection)?;
    connection.execute(
        "INSERT INTO local_trash (id, item_id, kind, item_type, title, data_json, group_ids, deleted_at, deleted_elsewhere, reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
        params![Uuid::new_v4().to_string(), item_id, kind, item_type, title, data.to_string(),
            serde_json::to_string(group_ids).unwrap_or_else(|_| "[]".to_owned()), now, REASON_JOIN],
    )?;
    Ok(())
}

/// Keeps a version that could not apply before this PC left after a removal ([`REASON_REMOVAL`]).
/// `trash_id` comes from the change, so a retried leave adds no second copy. True when it added one.
#[allow(clippy::too_many_arguments)]
pub fn keep_removal_copy(
    connection: &Connection,
    trash_id: &str,
    item_id: &str,
    kind: &str,
    item_type: &str,
    title: &str,
    data: &serde_json::Value,
    group_ids: &[String],
    now: i64,
) -> rusqlite::Result<bool> {
    initialize(connection)?;
    Ok(connection.execute(
        "INSERT OR IGNORE INTO local_trash (id, item_id, kind, item_type, title, data_json, group_ids, deleted_at, deleted_elsewhere, reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
        params![trash_id, item_id, kind, item_type, title, data.to_string(),
            serde_json::to_string(group_ids).unwrap_or_else(|_| "[]".to_owned()), now, REASON_REMOVAL],
    )? == 1)
}

/// Removes trash older than [`TRASH_DAYS`], and the previous passwords of logins that are gone.
/// Join copies stay: nobody chose to delete them. Removal copies go after [`TRASH_DAYS`].
pub fn purge(connection: &Connection, now: i64) -> rusqlite::Result<()> {
    initialize(connection)?;
    connection.execute("DELETE FROM local_trash WHERE deleted_at < ?1 AND reason IN ('', ?2)",
        params![now - TRASH_MILLIS, REASON_REMOVAL])?;
    connection.execute(
        "DELETE FROM local_password_history WHERE entry_id NOT IN (SELECT id FROM local_entries)
             AND entry_id NOT IN (SELECT item_id FROM local_trash)",
        [],
    )?;
    Ok(())
}

pub fn previous_passwords(connection: &Connection, entry_id: &str) -> rusqlite::Result<Vec<PreviousPassword>> {
    connection
        .prepare(
            "SELECT password, replaced_at FROM local_password_history WHERE entry_id = ?1
             ORDER BY replaced_at DESC, rowid DESC",
        )?
        .query_map([entry_id], |row| Ok(PreviousPassword { password: row.get(0)?, replaced_at: row.get(1)? }))?
        .collect()
}

pub fn clear_previous_passwords(connection: &Connection, entry_id: &str) -> rusqlite::Result<()> {
    connection.execute("DELETE FROM local_password_history WHERE entry_id = ?1", [entry_id])?;
    Ok(())
}

pub fn trashed_items(connection: &Connection) -> rusqlite::Result<Vec<TrashedItem>> {
    connection
        .prepare(
            "SELECT id, kind, item_type, title, deleted_at, deleted_elsewhere, item_id, reason FROM local_trash
             ORDER BY deleted_at DESC, rowid DESC",
        )?
        .query_map([], |row| {
            let deleted_at: i64 = row.get(4)?;
            let reason: String = row.get(7)?;
            Ok(TrashedItem {
                id: row.get(0)?,
                kind: row.get(1)?,
                item_type: row.get(2)?,
                title: row.get(3)?,
                deleted_at,
                deleted_elsewhere: row.get(5)?,
                item_id: row.get(6)?,
                expires_at: if reason == REASON_JOIN { 0 } else { deleted_at + TRASH_MILLIS },
                reason,
            })
        })?
        .collect()
}

/// A trashed item, as stored: (item ID, kind, data JSON, folder IDs).
pub fn trashed(connection: &Connection, id: &str) -> rusqlite::Result<Option<(String, String, serde_json::Value, Vec<String>)>> {
    connection
        .query_row("SELECT item_id, kind, data_json, group_ids FROM local_trash WHERE id = ?1", [id], |row| {
            let data: String = row.get(2)?;
            let groups: String = row.get(3)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                serde_json::from_str(&data).unwrap_or(serde_json::Value::Null),
                serde_json::from_str(&groups).unwrap_or_default(),
            ))
        })
        .optional()
}

/// After a restore: the new item keeps the old item's previous passwords.
pub fn move_history(connection: &Connection, from: &str, to: &str) -> rusqlite::Result<()> {
    connection.execute("UPDATE local_password_history SET entry_id = ?2 WHERE entry_id = ?1", params![from, to])?;
    Ok(())
}

/// Deletes one trashed item for good, with its previous passwords.
pub fn forget(connection: &Connection, id: &str) -> rusqlite::Result<bool> {
    let item_id: Option<String> = connection
        .query_row("SELECT item_id FROM local_trash WHERE id = ?1", [id], |row| row.get(0))
        .optional()?;
    let Some(item_id) = item_id else { return Ok(false) };
    connection.execute("DELETE FROM local_trash WHERE id = ?1", [id])?;
    connection.execute(
        "DELETE FROM local_password_history WHERE entry_id = ?1 AND ?1 NOT IN (SELECT id FROM local_entries)
             AND ?1 NOT IN (SELECT item_id FROM local_trash)",
        [&item_id],
    )?;
    Ok(true)
}

pub fn empty(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute("DELETE FROM local_trash", [])?;
    connection.execute("DELETE FROM local_password_history WHERE entry_id NOT IN (SELECT id FROM local_entries)", [])?;
    Ok(())
}
