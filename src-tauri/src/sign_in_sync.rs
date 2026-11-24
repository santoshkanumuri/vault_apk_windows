//! Synced sign-in methods (protocol `sign-in-methods-v1`, shared with Android `SignInMethodSyncRules.kt`).
//!
//! `sign_ins.rs` keeps the rows this PC's browser extension recorded. This module shares them with the
//! sync group, so the phone can remind the user how they signed in to a site last time.
//!
//! - Sync entity [ENTITY_TYPE], one per (site, provider, account key). The entity id is an HMAC under the
//!   group's content key ([crate::sign_ins::sync_entity_id]), because entity ids travel in plain text.
//! - Upsert plaintext `{"signInMethod":{"site","provider","account","firstUsedAt","lastUsedAt","useCount"}}`;
//!   delete plaintext `{"deleted":true}` with a tombstone, as for entries. The receiver checks every field
//!   ([parse_payload]) and recomputes the id.
//! - Never a conflict to review. Concurrent upserts merge field by field ([merge]); an upsert concurrent
//!   with a delete is decided by last writer wins (later `occurredAtUtc`, then the greater device ID).
//! - Released builds stop a writer's chain at an unknown entity type, so changes are written only while
//!   every other active member announced [FEATURE] ([crate::appearance::gate_open_for]). Until then they
//!   wait, and [flush] writes them later.
//! - `sign_in_method_sync_state` remembers what was last written or received per entity, so an unchanged
//!   row writes nothing and a received row is never sent back. A quiet re-record (the extension saw a known
//!   method again) only moves the times and the count: it is written at most once per [QUIET_INTERVAL_MS].
//! - `sign_in_method_sync_deletes` remembers rows the user deleted or merged away while the change could
//!   not be written yet. The 5000-row eviction in `sign_ins.rs` writes no delete: it is housekeeping.
//!
//! Shared test vectors: `fixtures/sign-in-methods-v1.json` (Android `scripts/sync-vectors/sign_in_methods.py`).

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    appearance::{Stamp, incoming_wins},
    change_store::{ChangeStore, StoredVaultRecord},
    identity::{DeviceIdentity, DeviceIdentityStore},
    membership, payload,
    protocol::{RecordVersion, VersionRelation},
    sync::{ChangeKind, ChangeRecord, GENESIS_HASH},
    vault::UnlockedVault,
};

pub const FEATURE: &str = crate::protocol::SIGN_IN_METHODS_FEATURE;
pub const ENTITY_TYPE: &str = "sign_in_method";
/// Highest use count a change may carry.
pub const MAX_USE_COUNT: i64 = 1_000_000_000;
/// A quiet re-record of one method is written at most once in this time.
pub const QUIET_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;
/// Most changes one flush writes, so one sync session stays small. The rest go next time.
const FLUSH_LIMIT: usize = 50;
/// `payload_sha256` of an entity whose last synced change is a delete.
pub(crate) const DELETED: &str = "deleted";

pub(crate) const STATE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sign_in_method_sync_state (
    entity_id TEXT PRIMARY KEY NOT NULL,
    payload_sha256 TEXT NOT NULL,
    account TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    updated_by_device TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sign_in_method_sync_deletes (
    site TEXT NOT NULL,
    provider TEXT NOT NULL,
    account_key TEXT NOT NULL,
    deleted_at_utc TEXT NOT NULL,
    PRIMARY KEY (site, provider, account_key)
);";

/// One sign-in method as it travels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Method {
    pub site: String,
    pub provider: String,
    /// Trimmed; "" when not known.
    pub account: String,
    pub first_used_at: i64,
    pub last_used_at: i64,
    pub use_count: i64,
}

impl Method {
    pub fn account_key(&self) -> String {
        self.account.trim().to_lowercase()
    }

    pub fn entity_id(&self, content_key: &[u8]) -> String {
        crate::sign_ins::sync_entity_id(content_key, &self.site, &self.provider, &self.account)
    }

    /// The hash `sign_in_method_sync_state` keeps for this value.
    pub(crate) fn hash(&self) -> String {
        hex::encode(Sha256::digest(payload_json(self).to_string().as_bytes()))
    }

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(String, Method)> {
        Ok((
            row.get(0)?,
            Method {
                site: row.get(1)?,
                provider: row.get(2)?,
                account: row.get(3)?,
                first_used_at: row.get(4)?,
                last_used_at: row.get(5)?,
                use_count: row.get(6)?,
            },
        ))
    }
}

/// The plaintext of one upsert.
pub fn payload_json(method: &Method) -> Value {
    json!({"signInMethod": {
        "site": method.site, "provider": method.provider, "account": method.account,
        "firstUsedAt": method.first_used_at, "lastUsedAt": method.last_used_at, "useCount": method.use_count,
    }})
}

/// Section 1 of the spec: a registrable domain, a known provider, a clean account, ordered times and a
/// count within range.
pub fn valid(method: &Method) -> bool {
    crate::site_icon_sync::valid_site(&method.site)
        && crate::sign_ins::provider(&method.provider).is_some()
        && crate::sign_ins::clean_account(Some(&method.account)).is_ok()
        && 0 <= method.first_used_at
        && method.first_used_at <= method.last_used_at
        && (1..=MAX_USE_COUNT).contains(&method.use_count)
}

/// The method of a decrypted upsert, or `None` when a field is missing, of the wrong JSON type or out
/// of range. Extra keys are ignored. The account is trimmed.
pub fn parse_method(payload: &Value) -> Option<Method> {
    let body = payload.get("signInMethod")?.as_object()?;
    let text = |name: &str| body.get(name).and_then(Value::as_str);
    // Integers only: a string or a fraction is refused.
    let number = |name: &str| body.get(name).filter(|value| value.is_i64() || value.is_u64()).and_then(Value::as_i64);
    let method = Method {
        site: text("site")?.to_owned(),
        provider: text("provider")?.to_owned(),
        account: text("account")?.trim().to_owned(),
        first_used_at: number("firstUsedAt")?,
        last_used_at: number("lastUsedAt")?,
        use_count: number("useCount")?,
    };
    valid(&method).then_some(method)
}

/// [parse_method], and the entity id must be the one of the method's site, provider and account.
pub fn parse_payload(payload: &Value, entity_id: &str, content_key: &[u8]) -> Option<Method> {
    parse_method(payload).filter(|method| method.entity_id(content_key) == entity_id)
}

/// Concurrent upserts of one entity: first use = min, last use = max, count = max (both sides may count
/// the same use after a restore), and the account text of the later writer. Both sides compute the same.
pub fn merge(current: &Method, current_stamp: &Stamp, incoming: &Method, incoming_stamp: &Stamp) -> Method {
    let later = if incoming_wins(current_stamp, incoming_stamp) { incoming } else { current };
    Method {
        site: current.site.clone(),
        provider: current.provider.clone(),
        account: later.account.clone(),
        first_used_at: current.first_used_at.min(incoming.first_used_at),
        last_used_at: current.last_used_at.max(incoming.last_used_at),
        use_count: current.use_count.max(incoming.use_count),
    }
}

/// An upsert concurrent with a delete: true when the upsert is the later writer.
pub fn upsert_beats_delete(delete: &Stamp, upsert: &Stamp) -> bool {
    incoming_wins(delete, upsert)
}

fn now_utc() -> Result<String, String> {
    OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| "The system clock is unavailable".to_owned())
}

/// Unix milliseconds of an RFC 3339 instant.
pub(crate) fn millis(at: &str) -> Option<i64> {
    OffsetDateTime::parse(at, &Rfc3339).ok().map(|time| (time.unix_timestamp_nanos() / 1_000_000) as i64)
}

/// What was last written or received for one entity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Synced {
    pub hash: String,
    pub account: String,
    pub at: String,
    pub device: String,
}

impl Synced {
    pub(crate) fn stamp(&self) -> Stamp {
        Stamp::new(Some(&self.at), Some(&self.device))
    }
}

pub(crate) fn synced_state(db: &Connection, entity_id: &str) -> rusqlite::Result<Option<Synced>> {
    db.execute_batch(STATE_SCHEMA)?;
    db.query_row(
        "SELECT payload_sha256, account, updated_at_utc, updated_by_device FROM sign_in_method_sync_state WHERE entity_id = ?1",
        [entity_id],
        |row| Ok(Synced { hash: row.get(0)?, account: row.get(1)?, at: row.get(2)?, device: row.get(3)? }),
    )
    .optional()
}

pub(crate) fn remember_synced(db: &Connection, entity_id: &str, hash: &str, account: &str, at: &str, device: &str) -> rusqlite::Result<()> {
    db.execute_batch(STATE_SCHEMA)?;
    db.execute(
        "INSERT INTO sign_in_method_sync_state (entity_id, payload_sha256, account, updated_at_utc, updated_by_device)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(entity_id) DO UPDATE SET payload_sha256 = excluded.payload_sha256, account = excluded.account,
             updated_at_utc = excluded.updated_at_utc, updated_by_device = excluded.updated_by_device",
        params![entity_id, hash, account, at, device],
    )?;
    Ok(())
}

/// Notes that the row (site, provider, account key) left this PC through the user: a delete on the
/// Sign-ins page, or an edit or a new account that merged it into another row. [flush] writes the delete
/// when the group has the entity. Outside a sync group nothing is noted.
pub(crate) fn note_local_delete(db: &Connection, site: &str, provider: &str, account_key: &str) -> rusqlite::Result<()> {
    let enrolled = db.query_row("SELECT EXISTS(SELECT 1 FROM sync_group_state)", [], |row| row.get::<_, bool>(0)).unwrap_or(false);
    if !enrolled {
        return Ok(());
    }
    db.execute_batch(STATE_SCHEMA)?;
    db.execute(
        "INSERT OR REPLACE INTO sign_in_method_sync_deletes (site, provider, account_key, deleted_at_utc) VALUES (?1, ?2, ?3, ?4)",
        params![site, provider, account_key, now_utc().unwrap_or_default()],
    )?;
    Ok(())
}

/// The time of a delete of this row that is still waiting to be written.
pub(crate) fn pending_delete(db: &Connection, method: &Method) -> rusqlite::Result<Option<String>> {
    db.execute_batch(STATE_SCHEMA)?;
    db.query_row(
        "SELECT deleted_at_utc FROM sign_in_method_sync_deletes WHERE site = ?1 AND provider = ?2 AND account_key = ?3",
        params![method.site, method.provider, method.account_key()],
        |row| row.get(0),
    )
    .optional()
}

fn forget_pending_delete(db: &Connection, method: &Method) -> rusqlite::Result<()> {
    db.execute_batch(STATE_SCHEMA)?;
    db.execute(
        "DELETE FROM sign_in_method_sync_deletes WHERE site = ?1 AND provider = ?2 AND account_key = ?3",
        params![method.site, method.provider, method.account_key()],
    )?;
    Ok(())
}

const COLUMNS: &str = "id, site, provider, account, first_used_at, last_used_at, use_count";

/// This PC's row for the method's (site, provider, account key).
pub(crate) fn local_by_key(db: &Connection, method: &Method) -> rusqlite::Result<Option<(String, Method)>> {
    db.query_row(
        &format!("SELECT {COLUMNS} FROM local_sign_ins WHERE site = ?1 AND provider = ?2 AND account_key = ?3"),
        params![method.site, method.provider, method.account_key()],
        Method::from_row,
    )
    .optional()
}

/// This PC's row whose entity id is `entity_id`. A delete carries no site, so the ids are recomputed.
pub(crate) fn local_by_entity(db: &Connection, content_key: &[u8], entity_id: &str) -> rusqlite::Result<Option<(String, Method)>> {
    let rows: Vec<(String, Method)> =
        db.prepare(&format!("SELECT {COLUMNS} FROM local_sign_ins"))?.query_map([], Method::from_row)?.collect::<rusqlite::Result<_>>()?;
    Ok(rows.into_iter().find(|(_, method)| method.entity_id(content_key) == entity_id))
}

/// Stores a method that came from the group into `local_sign_ins`, whatever the "Remember sign-in methods"
/// setting: each row was confirmed by the user on some device. Returns true when the row changed.
pub(crate) fn store_received(db: &Connection, method: &Method) -> rusqlite::Result<bool> {
    let key = method.account_key();
    let changed = match local_by_key(db, method)? {
        Some((_, existing)) if existing == *method => false,
        Some((id, _)) => {
            db.execute(
                "UPDATE local_sign_ins SET account = ?2, account_key = ?3, first_used_at = ?4, last_used_at = ?5, use_count = ?6 WHERE id = ?1",
                params![id, method.account, key, method.first_used_at, method.last_used_at, method.use_count],
            )?;
            true
        }
        None => {
            db.execute(
                "INSERT INTO local_sign_ins (id, site, provider, account, account_key, first_used_at, last_used_at, use_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![uuid::Uuid::new_v4().to_string(), method.site, method.provider, method.account, key,
                    method.first_used_at, method.last_used_at, method.use_count],
            )?;
            db.execute(
                "DELETE FROM local_sign_ins WHERE id NOT IN
                    (SELECT id FROM local_sign_ins ORDER BY last_used_at DESC, rowid DESC LIMIT ?1)",
                [crate::sign_ins::MAX_ROWS],
            )?;
            true
        }
    };
    if changed {
        forget_pending_delete(db, method)?;
    }
    Ok(changed)
}

/// The row as it would travel: the count is capped and the times kept in order, so a valid row always
/// passes the receiver's checks.
fn travelling(method: Method) -> Method {
    let first = method.first_used_at.max(0);
    Method {
        first_used_at: first,
        last_used_at: method.last_used_at.max(first),
        use_count: method.use_count.clamp(1, MAX_USE_COUNT),
        ..method
    }
}

/// One change [flush] writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Waiting {
    Upsert { entity_id: String, method: Method },
    /// (site, provider, account key) of the pending delete.
    Delete { entity_id: String, key: (String, String, String) },
}

/// The changes to write, at most `limit`: deletes first, then rows whose value differs from the last
/// synced one, most recently used first. A row whose only change is a quiet re-record waits until
/// [QUIET_INTERVAL_MS] after the last synced change of its entity. Pending deletes that need no change
/// (the row came back, or the group never had it) are dropped here.
pub(crate) fn waiting(db: &Connection, content_key: &[u8], limit: usize, now_millis: i64) -> rusqlite::Result<Vec<Waiting>> {
    db.execute_batch(STATE_SCHEMA)?;
    let mut out = Vec::new();
    let deletes: Vec<(String, String, String)> = db
        .prepare("SELECT site, provider, account_key FROM sign_in_method_sync_deletes ORDER BY deleted_at_utc, site")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (site, provider, account_key) in deletes {
        let probe = Method { site: site.clone(), provider: provider.clone(), account: account_key.clone(), first_used_at: 0, last_used_at: 0, use_count: 1 };
        let entity_id = probe.entity_id(content_key);
        let back = local_by_key(db, &probe)?.is_some();
        let synced = synced_state(db, &entity_id)?.is_some_and(|state| state.hash != DELETED);
        if back || !synced {
            forget_pending_delete(db, &probe)?;
            continue;
        }
        if out.len() < limit {
            out.push(Waiting::Delete { entity_id, key: (site, provider, account_key) });
        }
    }
    let rows: Vec<(String, Method)> = db
        .prepare(&format!("SELECT {COLUMNS} FROM local_sign_ins ORDER BY last_used_at DESC, site, provider, account_key"))?
        .query_map([], Method::from_row)?
        .collect::<rusqlite::Result<_>>()?;
    for (_, method) in rows {
        if out.len() >= limit {
            break;
        }
        let method = travelling(method);
        if !valid(&method) {
            continue;
        }
        let entity_id = method.entity_id(content_key);
        let send = match synced_state(db, &entity_id)? {
            None => true,
            Some(state) if state.hash == DELETED || state.account != method.account => true,
            Some(state) if state.hash == method.hash() => false,
            Some(state) => !millis(&state.at).is_some_and(|at| (0..QUIET_INTERVAL_MS).contains(&(now_millis - at))),
        };
        if send {
            out.push(Waiting::Upsert { entity_id, method });
        }
    }
    Ok(out)
}

/// Writes a signed change for each [waiting] row when the gate is open. Returns how many it wrote.
/// The vault lock must be held.
pub(crate) fn flush(vault: &mut UnlockedVault, identity_store: &DeviceIdentityStore) -> Result<usize, String> {
    let events = vault.stored_membership().map_err(|error| error.to_string())?;
    flush_with(vault.connection(), &events, identity_store, FLUSH_LIMIT, crate::activity::now_millis() as i64)
}

/// [flush], with failures only logged: the changes wait for the next sync.
pub(crate) fn flush_installed(vault: &mut UnlockedVault, identity_store: &DeviceIdentityStore) {
    if let Err(error) = flush(vault, identity_store) {
        crate::activity::diagnostic(crate::activity::Category::Sync, "Sign-in methods kept for a later sync", error);
    }
}

pub(crate) fn flush_with(
    db: &mut Connection,
    events: &[membership::MembershipEvent],
    identity_store: &DeviceIdentityStore,
    limit: usize,
    now_millis: i64,
) -> Result<usize, String> {
    if events.is_empty() || !identity_store.exists() {
        return Ok(0);
    }
    let membership = membership::verify(events).map_err(|error| error.to_string())?;
    let local = identity_store.get_or_create().map_err(|error| error.to_string())?;
    if !crate::appearance::gate_open_for(db, &membership, &local.device_id, FEATURE) {
        return Ok(0);
    }
    write_waiting(db, identity_store, &local, &membership.vault_id, limit, now_millis)
}

/// Writes the [waiting] changes as this device's next links. The caller checked the gate.
pub(crate) fn write_waiting(
    db: &mut Connection,
    identity_store: &DeviceIdentityStore,
    local: &DeviceIdentity,
    vault_id: &str,
    limit: usize,
    now_millis: i64,
) -> Result<usize, String> {
    let content_key: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(
        db.query_row("SELECT content_key FROM sync_group_state WHERE vault_id = ?1", [vault_id], |row| row.get(0))
            .map_err(|error| error.to_string())?,
    );
    let waiting = waiting(db, &content_key, limit, now_millis).map_err(|error| error.to_string())?;
    let mut written = 0;
    for change in waiting {
        let at = now_utc()?;
        match change {
            Waiting::Upsert { entity_id, method } => {
                write_change(db, identity_store, local, vault_id, &content_key, &entity_id, Some(&method), &at)
                    .map_err(|error| error.to_string())?;
                remember_synced(db, &entity_id, &method.hash(), &method.account, &at, &local.device_id).map_err(|error| error.to_string())?;
            }
            Waiting::Delete { entity_id, key } => {
                write_change(db, identity_store, local, vault_id, &content_key, &entity_id, None, &at)
                    .map_err(|error| error.to_string())?;
                remember_synced(db, &entity_id, DELETED, "", &at, &local.device_id).map_err(|error| error.to_string())?;
                db.execute(
                    "DELETE FROM sign_in_method_sync_deletes WHERE site = ?1 AND provider = ?2 AND account_key = ?3",
                    params![key.0, key.1, key.2],
                )
                .map_err(|error| error.to_string())?;
            }
        }
        written += 1;
    }
    Ok(written)
}

/// Signs one change as the next link of this device's chain. The version is the current one (the live
/// record, or else the tombstone) with this device's counter + 1, so an upsert after a delete dominates
/// the delete. An upsert removes the tombstone in the same transaction.
#[allow(clippy::too_many_arguments)]
fn write_change(
    db: &mut Connection,
    identity_store: &DeviceIdentityStore,
    local: &DeviceIdentity,
    vault_id: &str,
    content_key: &[u8],
    entity_id: &str,
    method: Option<&Method>,
    occurred_at: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let head: Option<(i64, String)> = db
        .query_row(
            "SELECT sequence, hash FROM sync_device_heads WHERE vault_id = ?1 AND device_id = ?2",
            params![vault_id, local.device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (sequence, previous_hash) =
        head.map_or((1, GENESIS_HASH.to_owned()), |(sequence, hash)| (sequence as u64 + 1, hash));
    let current = ChangeStore::record(db, ENTITY_TYPE, entity_id)?;
    if method.is_none() && current.is_none() {
        // The group holds no live record of it: nothing to delete.
        return Ok(());
    }
    let tombstone: Option<String> = db
        .query_row(
            "SELECT record_version_json FROM sync_tombstones WHERE entity_type = ?1 AND entity_id = ?2",
            params![ENTITY_TYPE, entity_id],
            |row| row.get(0),
        )
        .optional()?;
    let base_revision = current.as_ref().map_or(0, |record| record.revision);
    let current_json = current.as_ref().map(|record| record.record_version_json.clone()).or(tombstone);
    let mut counters: BTreeMap<String, u64> = current_json
        .map(|json| serde_json::from_str::<RecordVersion>(&json))
        .transpose()?
        .unwrap_or_default()
        .counters()
        .clone();
    *counters.entry(local.device_id.clone()).or_default() += 1;
    let version = RecordVersion::new(counters);
    let mutation_id = uuid::Uuid::new_v4().to_string();
    let plaintext = match method {
        Some(method) => payload_json(method),
        None => json!({"deleted": true}),
    };
    let encrypted = payload::encrypt_in(db, content_key, ENTITY_TYPE, vault_id, &mutation_id, entity_id, &serde_json::to_vec(&plaintext)?)?;
    let kind = if method.is_some() { ChangeKind::Upsert } else { ChangeKind::Delete };
    let operation = ChangeRecord::create_signed_with(
        vault_id,
        &local.device_id,
        sequence,
        previous_hash,
        mutation_id,
        ENTITY_TYPE,
        entity_id,
        kind,
        base_revision,
        version.clone(),
        occurred_at,
        encrypted.ciphertext,
        encrypted.nonce,
        |message| identity_store.sign(message),
    )?;
    if method.is_some() {
        let record = StoredVaultRecord {
            entity_type: ENTITY_TYPE.to_owned(),
            entity_id: entity_id.to_owned(),
            payload_ciphertext: operation.payload_ciphertext.clone(),
            revision: base_revision + 1,
            record_version_json: serde_json::to_string(&version)?,
        };
        ChangeStore::save_record_and_operation_with(db, &record, &operation, local, |transaction| {
            transaction.execute(
                "DELETE FROM sync_tombstones WHERE entity_type = ?1 AND entity_id = ?2",
                params![ENTITY_TYPE, entity_id],
            )?;
            Ok(())
        })?;
    } else {
        ChangeStore::delete_record_and_operation(db, &operation, local)?;
    }
    Ok(())
}

/// What one sign-in entity of a snapshot settles on.
pub(crate) struct SnapshotChoice<'a> {
    pub entity_id: String,
    /// The latest writer's change: the record's payload when the method lives.
    pub operation: &'a ChangeRecord,
    /// `None` when the entity is deleted.
    pub method: Option<Method>,
}

/// Of the readable changes of each entity that no other change of the entity includes: the merge of the
/// upserts ([merge], oldest writer first), unless a delete is the latest writer.
pub(crate) fn snapshot_choices<'a>(operations: &[&'a ChangeRecord], content_key: &[u8]) -> Vec<SnapshotChoice<'a>> {
    let readable: Vec<(&ChangeRecord, Option<Method>)> = operations
        .iter()
        .filter(|operation| operation.entity_type == ENTITY_TYPE)
        .filter_map(|operation| {
            let plaintext = zeroize::Zeroizing::new(payload::decrypt(content_key, operation).ok()?);
            let value: Value = serde_json::from_slice(&plaintext).ok()?;
            match operation.kind {
                ChangeKind::Upsert => Some((*operation, Some(parse_payload(&value, &operation.entity_id, content_key)?))),
                ChangeKind::Delete => (value.get("deleted").and_then(Value::as_bool) == Some(true)).then_some((*operation, None)),
            }
        })
        .collect();
    let mut by_entity: BTreeMap<&str, Vec<&(&ChangeRecord, Option<Method>)>> = BTreeMap::new();
    for change in &readable {
        by_entity.entry(&change.0.entity_id).or_default().push(change);
    }
    let stamp = |operation: &ChangeRecord| Stamp::new(Some(&operation.occurred_at_utc), Some(&operation.device_id));
    let mut chosen = Vec::new();
    for (entity_id, group) in by_entity {
        let mut maximal: Vec<&(&ChangeRecord, Option<Method>)> = group
            .iter()
            .copied()
            .filter(|(operation, _)| {
                !group.iter().any(|(other, _)| {
                    other.hash != operation.hash && operation.record_version.relation_to(&other.record_version) == VersionRelation::Before
                })
            })
            .collect();
        maximal.sort_by_key(|(operation, _)| stamp(operation));
        let mut merged: Option<(Method, Stamp, &ChangeRecord)> = None;
        let mut deleted: Option<(Stamp, &ChangeRecord)> = None;
        for (operation, method) in maximal {
            let here = stamp(operation);
            match method {
                Some(method) => {
                    merged = Some(match merged {
                        None => (method.clone(), here, operation),
                        Some((current, current_stamp, _)) => (merge(&current, &current_stamp, method, &here), here, operation),
                    })
                }
                None => deleted = Some((here, operation)),
            }
        }
        match (merged, deleted) {
            (Some((method, upsert, operation)), delete) if delete.as_ref().is_none_or(|(at, _)| upsert_beats_delete(at, &upsert)) => {
                chosen.push(SnapshotChoice { entity_id: entity_id.to_owned(), operation, method: Some(method) })
            }
            (_, Some((_, operation))) => chosen.push(SnapshotChoice { entity_id: entity_id.to_owned(), operation, method: None }),
            _ => {}
        }
    }
    chosen
}

/// After a snapshot import: this PC takes the group's methods and remembers them as synced. A row of its
/// own for the same method keeps its history (min and max) and is written later when it adds to the
/// group's. A row the group deleted goes, unless this PC used it after the delete.
pub(crate) fn adopt_from_snapshot(db: &Connection, content_key: &[u8], choices: &[SnapshotChoice<'_>]) -> rusqlite::Result<()> {
    db.execute_batch(STATE_SCHEMA)?;
    // Entity ids belong to the content key: anything noted for an earlier group means nothing now.
    db.execute_batch("DELETE FROM sign_in_method_sync_state; DELETE FROM sign_in_method_sync_deletes;")?;
    for choice in choices {
        let (at, device) = (&choice.operation.occurred_at_utc, &choice.operation.device_id);
        match &choice.method {
            Some(method) => {
                let value = match local_by_key(db, method)? {
                    Some((_, own)) => Method {
                        first_used_at: own.first_used_at.min(method.first_used_at),
                        last_used_at: own.last_used_at.max(method.last_used_at),
                        use_count: own.use_count.max(method.use_count),
                        ..method.clone()
                    },
                    None => method.clone(),
                };
                store_received(db, &value)?;
                remember_synced(db, &choice.entity_id, &method.hash(), &method.account, at, device)?;
            }
            None => {
                if let Some((id, own)) = local_by_entity(db, content_key, &choice.entity_id)?
                    && millis(at).is_none_or(|deleted| own.last_used_at <= deleted)
                {
                    db.execute("DELETE FROM local_sign_ins WHERE id = ?1", [id])?;
                }
                remember_synced(db, &choice.entity_id, DELETED, "", at, device)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appearance::Stamp;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../fixtures/sign-in-methods-v1.json")).unwrap()
    }

    fn method_of(value: &Value) -> Method {
        Method {
            site: value["site"].as_str().unwrap().to_owned(),
            provider: value["provider"].as_str().unwrap().to_owned(),
            account: value["account"].as_str().unwrap().to_owned(),
            first_used_at: value["firstUsedAt"].as_i64().unwrap(),
            last_used_at: value["lastUsedAt"].as_i64().unwrap(),
            use_count: value["useCount"].as_i64().unwrap(),
        }
    }

    #[test]
    fn the_vector_file_describes_this_protocol() {
        let vectors = vectors();
        assert_eq!(vectors["feature"], FEATURE);
        assert_eq!(vectors["entityType"], ENTITY_TYPE);
        assert_eq!(vectors["idPrefix"], crate::sign_ins::SYNC_ID_PREFIX);
        assert_eq!(vectors["maxUseCount"], MAX_USE_COUNT);
        assert!(crate::protocol::SYNC_FEATURES.contains(&FEATURE));
        for site in vectors["sites"]["valid"].as_array().unwrap() {
            assert!(crate::site_icon_sync::valid_site(site.as_str().unwrap()), "{site}");
        }
        for site in vectors["sites"]["invalid"].as_array().unwrap() {
            assert!(!crate::site_icon_sync::valid_site(site.as_str().unwrap()), "{site}");
        }
    }

    #[test]
    fn every_payload_case_decrypts_and_parses_or_is_refused() {
        let vectors = vectors();
        let key = hex::decode(vectors["contentKeyHex"].as_str().unwrap()).unwrap();
        let vault_id = vectors["vaultId"].as_str().unwrap();
        let mutation_id = vectors["mutationId"].as_str().unwrap();
        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 18);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let entity = case["entityId"].as_str().unwrap();
            let kind = if case["kind"] == "delete" { ChangeKind::Delete } else { ChangeKind::Upsert };
            let change = ChangeRecord::create(
                vault_id, "device-a", 1, GENESIS_HASH, mutation_id, ENTITY_TYPE, entity, kind.clone(), 0,
                RecordVersion::from_entries([("device-a", 1)]), "2026-11-21T10:00:00Z",
                case["payloadCiphertext"].as_str().unwrap(), case["payloadNonce"].as_str().unwrap(), "unsigned",
            );
            let plaintext = payload::decrypt(&key, &change).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(plaintext, case["plaintext"].as_str().unwrap().as_bytes(), "{name}");
            let value: Value = serde_json::from_slice(&plaintext).unwrap();
            let valid = case["valid"].as_bool().unwrap();
            if kind == ChangeKind::Delete {
                assert_eq!(value.get("deleted").and_then(Value::as_bool) == Some(true), valid, "{name}");
                continue;
            }
            let parsed = parse_payload(&value, entity, &key);
            if valid {
                assert_eq!(parsed, Some(method_of(&case["expected"])), "{name}");
            } else {
                assert!(parsed.is_none(), "{name}");
            }
        }
    }

    #[test]
    fn concurrent_upserts_merge_field_by_field_and_deletes_follow_the_last_writer() {
        let vectors = vectors();
        for case in vectors["concurrentUpserts"].as_array().unwrap() {
            let (current, incoming) = (&case["current"], &case["incoming"]);
            let current_stamp = Stamp::new(current["at"].as_str(), current["device"].as_str());
            let incoming_stamp = Stamp::new(incoming["at"].as_str(), incoming["device"].as_str());
            let merged = merge(&method_of(&current["method"]), &current_stamp, &method_of(&incoming["method"]), &incoming_stamp);
            assert_eq!(merged, method_of(&case["merged"]), "{}", case["name"]);
            // The other side computes the same value.
            let mirrored = merge(&method_of(&incoming["method"]), &incoming_stamp, &method_of(&current["method"]), &current_stamp);
            assert_eq!(mirrored, merged, "{}", case["name"]);
        }
        for case in vectors["upsertVersusDelete"].as_array().unwrap() {
            let delete = Stamp::new(case["deleteAt"].as_str(), case["deleteDevice"].as_str());
            let upsert = Stamp::new(case["upsertAt"].as_str(), case["upsertDevice"].as_str());
            let expected = case["result"] == "upsert";
            assert_eq!(upsert_beats_delete(&delete, &upsert), expected, "{case}");
        }
    }

    #[test]
    fn the_writer_payload_round_trips_and_bad_rows_are_never_sent() {
        let key = [7u8; 32];
        let method = Method { site: "example.com".into(), provider: "github".into(), account: "OctoCat".into(),
            first_used_at: 1, last_used_at: 2, use_count: 3 };
        assert_eq!(parse_payload(&payload_json(&method), &method.entity_id(&key), &key), Some(method.clone()));
        assert_eq!(method.entity_id(&key), crate::sign_ins::sync_entity_id(&key, "example.com", "github", "octocat"));
        let capped = travelling(Method { use_count: MAX_USE_COUNT + 5, first_used_at: -3, last_used_at: -4, ..method.clone() });
        assert_eq!((capped.first_used_at, capped.last_used_at, capped.use_count), (0, 0, MAX_USE_COUNT));
        assert!(valid(&capped));
        assert!(!valid(&Method { site: "localhost".into(), ..method.clone() }));
        assert!(!valid(&Method { provider: "okta".into(), ..method }));
    }

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        ChangeStore::initialize(&db).unwrap();
        crate::sign_ins::initialize(&db).unwrap();
        db.execute_batch("CREATE TABLE sync_group_state (vault_id TEXT NOT NULL PRIMARY KEY, content_key BLOB NOT NULL, transport_secret BLOB NOT NULL);
            INSERT INTO sync_group_state VALUES ('vault-a', x'0505050505050505050505050505050505050505050505050505050505050505', x'00');").unwrap();
        db
    }

    const KEY: [u8; 32] = [5; 32];
    const DAY: i64 = QUIET_INTERVAL_MS;

    fn upserts(db: &Connection, now: i64) -> Vec<(String, i64)> {
        waiting(db, &KEY, 50, now)
            .unwrap()
            .into_iter()
            .filter_map(|change| match change {
                Waiting::Upsert { method, .. } => Some((method.account, method.use_count)),
                Waiting::Delete { .. } => None,
            })
            .collect()
    }

    fn sync_all(db: &Connection, now: i64, at: &str) {
        for change in waiting(db, &KEY, 50, now).unwrap() {
            match change {
                Waiting::Upsert { entity_id, method } => remember_synced(db, &entity_id, &method.hash(), &method.account, at, "pc").unwrap(),
                Waiting::Delete { entity_id, key } => {
                    remember_synced(db, &entity_id, DELETED, "", at, "pc").unwrap();
                    db.execute("DELETE FROM sign_in_method_sync_deletes WHERE site = ?1 AND provider = ?2 AND account_key = ?3",
                        params![key.0, key.1, key.2]).unwrap();
                }
            }
        }
    }

    #[test]
    fn quiet_re_records_wait_a_day_but_new_rows_accounts_and_deletes_go_at_once() {
        let mut db = database();
        let start = millis("2026-11-21T10:00:00Z").unwrap();
        let first = crate::sign_ins::record(&mut db, "https://example.com", "github", Some("octocat"), true, start).unwrap();
        assert_eq!(upserts(&db, start), [("octocat".to_owned(), 1)], "a new row goes at once");
        sync_all(&db, start, "2026-11-21T10:00:00Z");
        assert!(upserts(&db, start).is_empty(), "nothing changed");

        // The extension saw the same method again an hour later: only the times and the count move.
        crate::sign_ins::record(&mut db, "https://example.com", "github", Some("octocat"), true, start + 3_600_000).unwrap();
        assert!(upserts(&db, start + 3_600_000).is_empty(), "throttled");
        assert!(upserts(&db, start + DAY - 1).is_empty(), "still throttled");
        assert_eq!(upserts(&db, start + DAY), [("octocat".to_owned(), 2)], "a day after the last synced change");

        // An edit of the account text is never throttled.
        crate::sign_ins::set_account(&mut db, &first.id, Some("OctoCat")).unwrap();
        assert_eq!(upserts(&db, start + 3_600_000), [("OctoCat".to_owned(), 2)]);
        sync_all(&db, start + 3_600_000, "2026-11-21T11:00:00Z");

        // Renaming to another account: a delete of the old entity and an upsert of the new one.
        crate::sign_ins::set_account(&mut db, &first.id, Some("hubot")).unwrap();
        let changes = waiting(&db, &KEY, 50, start + 3_600_000).unwrap();
        assert_eq!(changes.len(), 2);
        assert!(matches!(&changes[0], Waiting::Delete { key, .. } if key.2 == "octocat"));
        assert!(matches!(&changes[1], Waiting::Upsert { method, .. } if method.account == "hubot"));
        sync_all(&db, start + 3_600_000, "2026-11-21T11:00:00Z");

        // A delete on the Sign-ins page goes at once; a row that was never synced writes no delete.
        let never = crate::sign_ins::record(&mut db, "https://other.example", "google", None, true, start).unwrap();
        crate::sign_ins::delete(&db, &never.id).unwrap();
        let hubot = crate::sign_ins::list(&db).unwrap().into_iter().find(|row| row.account == "hubot").unwrap();
        crate::sign_ins::delete(&db, &hubot.id).unwrap();
        let changes = waiting(&db, &KEY, 50, start).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Waiting::Delete { key, .. } if key.2 == "hubot"));
        let pending: i64 = db.query_row("SELECT count(*) FROM sign_in_method_sync_deletes", [], |row| row.get(0)).unwrap();
        assert_eq!(pending, 1, "the delete of a row the group never had is dropped");

        // Recording the deleted method again before the delete went out: the delete is dropped, the row goes.
        crate::sign_ins::record(&mut db, "https://example.com", "github", Some("hubot"), true, start + 10).unwrap();
        let changes = waiting(&db, &KEY, 50, start).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Waiting::Upsert { method, .. } if method.account == "hubot"));
    }

    #[test]
    fn the_eviction_and_rows_outside_a_group_write_no_delete() {
        let mut db = database();
        db.execute_batch("DELETE FROM sync_group_state").unwrap();
        let row = crate::sign_ins::record(&mut db, "https://example.com", "github", Some("octocat"), true, 1).unwrap();
        crate::sign_ins::delete(&db, &row.id).unwrap();
        let pending: i64 = db.query_row("SELECT count(*) FROM sign_in_method_sync_deletes", [], |row| row.get(0)).unwrap_or(0);
        assert_eq!(pending, 0);
    }

    #[test]
    fn the_gate_needs_every_other_member_to_announce_sign_in_methods() {
        let db = database();
        let group = crate::appearance::tests::membership(&[("pc", true), ("phone", true)]);
        let announce = |list: &[&str]| {
            let list: Vec<String> = list.iter().map(|feature| (*feature).to_owned()).collect();
            crate::appearance::record_peer_features(&db, "vault-a", "phone", &list).unwrap();
        };
        announce(&[crate::protocol::APPEARANCE_FEATURE, crate::protocol::SITE_ICONS_FEATURE]);
        assert!(!crate::appearance::gate_open_for(&db, &group, "pc", FEATURE), "a 2.3.x phone: closed");
        announce(&crate::protocol::SYNC_FEATURES);
        assert!(crate::appearance::gate_open_for(&db, &group, "pc", FEATURE));
        let lone = crate::appearance::tests::membership(&[("pc", true)]);
        assert!(!crate::appearance::gate_open_for(&db, &lone, "pc", FEATURE), "a lone device never writes");
    }

    fn signed(device: &str, sequence: u64, version: RecordVersion, at: &str, entity_id: &str, method: Option<&Method>) -> ChangeRecord {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let mutation = format!("m-{device}-{sequence}");
        let body = serde_json::to_vec(&method.map_or(json!({"deleted": true}), payload_json)).unwrap();
        let encrypted = payload::encrypt(&KEY, ENTITY_TYPE, "vault-a", &mutation, entity_id, &body).unwrap();
        let kind = if method.is_some() { ChangeKind::Upsert } else { ChangeKind::Delete };
        ChangeRecord::create_signed_with("vault-a", device, sequence, GENESIS_HASH, mutation, ENTITY_TYPE, entity_id,
            kind, 0, version, at, encrypted.ciphertext, encrypted.nonce,
            |bytes| Ok::<_, ()>(ed25519_dalek::Signer::sign(&signer, bytes).to_bytes()))
            .unwrap()
    }

    #[test]
    fn a_snapshot_merges_concurrent_upserts_and_honours_a_later_delete() {
        let octo = Method { site: "example.com".into(), provider: "github".into(), account: "octocat".into(),
            first_used_at: 100, last_used_at: 500, use_count: 7 };
        let id = octo.entity_id(&KEY);
        let old = signed("pc", 1, RecordVersion::from_entries([("pc", 1)]), "2026-11-20T09:00:00Z", &id, Some(&Method { use_count: 1, ..octo.clone() }));
        let pc = signed("pc", 2, RecordVersion::from_entries([("pc", 2)]), "2026-11-20T10:00:00Z", &id, Some(&octo));
        let laptop = signed("laptop", 1, RecordVersion::from_entries([("pc", 1), ("laptop", 1)]), "2026-11-20T10:00:05Z", &id,
            Some(&Method { account: "OctoCat".into(), first_used_at: 50, last_used_at: 400, use_count: 9, ..octo.clone() }));
        let google = Method { site: "example.com".into(), provider: "google".into(), account: "me@example.com".into(),
            first_used_at: 1, last_used_at: 2, use_count: 1 };
        let google_id = google.entity_id(&KEY);
        let kept = signed("pc", 3, RecordVersion::from_entries([("pc", 3)]), "2026-11-20T10:00:00Z", &google_id, Some(&google));
        let removed = signed("phone", 1, RecordVersion::from_entries([("phone", 1)]), "2026-11-20T11:00:00Z", &google_id, None);
        let chosen = snapshot_choices(&[&old, &pc, &laptop, &kept, &removed], &KEY);
        assert_eq!(chosen.len(), 2);
        let github = chosen.iter().find(|choice| choice.entity_id == id).unwrap();
        assert_eq!(github.method, Some(Method { account: "OctoCat".into(), first_used_at: 50, last_used_at: 500, use_count: 9, ..octo }));
        assert_eq!(github.operation.hash, laptop.hash, "the record keeps the latest writer's change");
        let deleted = chosen.iter().find(|choice| choice.entity_id == google_id).unwrap();
        assert!(deleted.method.is_none());

        // Adoption: this PC's own row of the same method keeps its history; a deleted one goes.
        let mut db = database();
        crate::sign_ins::record(&mut db, "https://example.com", "github", Some("octocat"), true, 600).unwrap();
        crate::sign_ins::record(&mut db, "https://example.com", "google", Some("me@example.com"), true, 2).unwrap();
        adopt_from_snapshot(&db, &KEY, &chosen).unwrap();
        let rows = crate::sign_ins::list(&db).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].account.as_str(), rows[0].first_used_at, rows[0].last_used_at, rows[0].use_count), ("OctoCat", 50, 600, 9));
        // The later local use is written later; the deleted entity is remembered as deleted.
        assert_eq!(upserts(&db, millis("2026-11-20T12:00:00Z").unwrap()).len(), 0, "a quiet change waits a day");
        assert_eq!(synced_state(&db, &google_id).unwrap().unwrap().hash, DELETED);
    }
}
