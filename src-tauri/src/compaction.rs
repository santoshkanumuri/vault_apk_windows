//! History compaction on this PC (no wire change; Android `HistoryCompaction.kt`). A change of
//! author A is deleted when every active member already applied it (its sequence is at or below
//! floor(A)) and it is not in the keep set (`checkpoint::keep_set`). A member that still needs a
//! change pins the floor, so it stays. Shared vectors: `fixtures/compaction-v1.json`.
//!
//! Nothing is deleted on Google Drive here, and no device is removed automatically: a member that
//! has not synced for months only gets a suggestion (`blocking_hint`).

use std::collections::{BTreeMap, HashSet};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    checkpoint::{ConflictRef, HeldChange, RecordRef, TombstoneRef, keep_set},
    membership::VerifiedMembership,
    progress::SyncProgress,
};

pub const BATCH: usize = 2_000;
pub const INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;
const RESOLVED_CONFLICT_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const HINT_AFTER_MS: i64 = 90 * 24 * 60 * 60 * 1000;
const HINT_CHANGES: u64 = 5_000;

type Applied = BTreeMap<String, u64>;

/// floor(A) = min over the active members (this PC included) of the head of A each one applied; a
/// member that never reported gives 0. With Drive sync on (`drive` is `Some`) it is also at most the
/// drive's gap-free coverage of A, so the drive can still get every change from someone.
pub fn floors(local: &str, active: &[&str], local_applied: &Applied, peer_applied: &BTreeMap<String, Applied>, drive: Option<&Applied>) -> Applied {
    local_applied
        .keys()
        .map(|author| {
            let pinned = active
                .iter()
                .map(|member| {
                    if *member == local {
                        local_applied.get(author).copied().unwrap_or(0)
                    } else {
                        peer_applied.get(*member).and_then(|applied| applied.get(author)).copied().unwrap_or(0)
                    }
                })
                .min()
                .unwrap_or(0);
            let floor = drive.map_or(pinned, |covered| pinned.min(covered.get(author).copied().unwrap_or(0)));
            (author.clone(), floor)
        })
        .collect()
}

/// The hashes to delete: at or below the floor, not kept, and not this PC's own applied head (the
/// progress report reads its hash).
pub fn deletable(changes: &[HeldChange], keep: &HashSet<String>, floors: &Applied, local_applied: &Applied) -> Vec<String> {
    changes
        .iter()
        .filter(|change| {
            change.sequence <= floors.get(&change.device_id).copied().unwrap_or(0)
                && !keep.contains(&change.hash)
                && Some(change.sequence) != local_applied.get(&change.device_id).copied()
        })
        .map(|change| change.hash.clone())
        .collect()
}

/// This PC's compaction record: when it last ran, and per author the highest change it deleted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub at: i64,
    pub floor: BTreeMap<String, (u64, String)>,
}

pub fn encode(record: &Record) -> String {
    let floor: serde_json::Map<String, Value> =
        record.floor.iter().map(|(author, (sequence, hash))| (author.clone(), json!([sequence, hash]))).collect();
    json!({"at": record.at, "floor": floor}).to_string()
}

/// An empty or unreadable record counts as "never ran".
pub fn parse(text: &str) -> Record {
    let Ok(value) = serde_json::from_str::<Value>(text) else { return Record::default() };
    let floor = value["floor"]
        .as_object()
        .map(|floor| {
            floor
                .iter()
                .filter_map(|(author, pair)| Some((author.clone(), (pair[0].as_u64()?, pair[1].as_str()?.to_owned()))))
                .collect()
        })
        .unwrap_or_default();
    Record { at: value["at"].as_i64().unwrap_or(0), floor }
}

fn now_millis() -> i64 {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

fn stored_record(db: &Connection, vault_id: &str) -> rusqlite::Result<Record> {
    db.execute_batch(crate::change_store::CHECKPOINTS_SCHEMA)?;
    let text: Option<String> = db
        .query_row("SELECT floor_json FROM sync_checkpoints WHERE vault_id = ?1", [vault_id], |row| row.get(0))
        .optional()?;
    Ok(text.map(|text| parse(&text)).unwrap_or_default())
}

fn save_record(db: &Connection, vault_id: &str, record: &Record) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO sync_checkpoints (vault_id, checkpoint_json, floor_json, updated_at) VALUES (?1, '', ?2, ?3)
         ON CONFLICT(vault_id) DO UPDATE SET floor_json = excluded.floor_json, updated_at = excluded.updated_at",
        params![vault_id, encode(record), now_millis()],
    )?;
    Ok(())
}

/// Drive compaction (feature `history-compaction-v1`, Android `DriveCompaction.kt`). Shared vectors:
/// `compaction-v1.json` `drive`. A floor marker `c.<author>` counts only at or below this reader's
/// own floor(A); coverage starts after it; `o.` files at or below floor(A) go, the marker first.
pub mod drive {
    pub const FEATURE: &str = "history-compaction-v1";
    pub const MAX_DELETES: usize = 64;
    pub const INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
    pub struct Marker {
        pub author: String,
        pub floor: u64,
        pub hash: String,
        pub writer: String,
        pub at: i64,
    }

    /// The end of the gap-free run of files that starts right after `floor`.
    pub fn coverage(ranges: &[(u64, u64)], floor: u64) -> u64 {
        let mut sorted = ranges.to_vec();
        sorted.sort_unstable();
        let mut covered = floor;
        for (first, last) in sorted {
            if first > covered + 1 {
                break;
            }
            covered = covered.max(last);
        }
        covered
    }

    pub fn counted_floor(marker: Option<u64>, reader_floor: u64) -> u64 {
        marker.filter(|marker| *marker <= reader_floor).unwrap_or(0)
    }

    /// The files to delete for one author, and the new marker floor.
    pub fn cleanup(ranges: &[(u64, u64)], marker: u64, floor: u64) -> (u64, Vec<(u64, u64)>) {
        let reach = floor.min(coverage(ranges, marker));
        let mut gone: Vec<(u64, u64)> = ranges.iter().copied().filter(|(_, last)| *last <= reach).collect();
        gone.sort_unstable();
        (gone.iter().map(|(_, last)| *last).max().unwrap_or(0).max(marker), gone)
    }
}

/// floor(A) for each author this PC applied, from its own and its peers' applied heads (no drive term).
pub fn own_floors(db: &Connection, vault_id: &str, local: &str, membership: &VerifiedMembership) -> rusqlite::Result<Applied> {
    let local_applied: Applied = crate::lan_sync::progress(db, vault_id)
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        .applied
        .into_iter()
        .map(|(author, (sequence, _))| (author, sequence))
        .collect();
    let active: Vec<&str> = membership.members.values().filter(|m| m.active).map(|m| m.device_id.as_str()).collect();
    Ok(floors(local, &active, &local_applied, &peer_applied(db, vault_id)?, None))
}

/// What each peer last reported as applied (`sync_peer_progress`).
fn peer_applied(db: &Connection, vault_id: &str) -> rusqlite::Result<BTreeMap<String, Applied>> {
    db.execute("CREATE TABLE IF NOT EXISTS sync_peer_progress (vault_id TEXT NOT NULL, peer_device_id TEXT NOT NULL, progress_json TEXT NOT NULL, PRIMARY KEY (vault_id, peer_device_id))", [])?;
    let mut query = db.prepare("SELECT peer_device_id, progress_json FROM sync_peer_progress WHERE vault_id = ?1")?;
    let rows = query.query_map([vault_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
    let mut result = BTreeMap::new();
    for row in rows {
        let (peer, json) = row?;
        // An unreadable report pins everything: it counts as no report.
        if let Ok(progress) = SyncProgress::parse(json.as_bytes()) {
            result.insert(peer, progress.applied.into_iter().map(|(author, (sequence, _))| (author, sequence)).collect());
        }
    }
    Ok(result)
}

/// With a Google Drive account connected: the drive's gap-free coverage per author, from the cached
/// file list (an empty list covers nothing, so nothing is deleted). `None` without Drive sync.
fn drive_coverage(db: &Connection, vault_id: &str, membership: &VerifiedMembership) -> rusqlite::Result<Option<Applied>> {
    let account: bool = db.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'cloud_sync_account')",
        [],
        |row| row.get(0),
    )? && db.query_row("SELECT EXISTS (SELECT 1 FROM cloud_sync_account)", [], |row| row.get(0))?;
    if !account {
        return Ok(None);
    }
    let secret: Option<Vec<u8>> = db
        .query_row("SELECT transport_secret FROM sync_group_state WHERE vault_id = ?1", [vault_id], |row| row.get(0))
        .optional()?;
    let Some(keys) = secret.and_then(|secret| crate::lan_sync::cloud::CloudKeys::derive(&secret, vault_id)) else {
        return Ok(Some(Applied::new()));
    };
    let tags: BTreeMap<String, String> =
        membership.members.keys().map(|device| (keys.device_tag(device), device.clone())).collect();
    let files_table: bool = db.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'cloud_sync_files')",
        [],
        |row| row.get(0),
    )?;
    let mut ranges: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
    if files_table {
        let mut query = db.prepare("SELECT name FROM cloud_sync_files WHERE vault_id = ?1")?;
        let names = query.query_map([vault_id], |row| row.get::<_, String>(0))?;
        for name in names {
            if let Some(crate::lan_sync::cloud::CloudName::Operations { device, first, last }) = keys.parse(&name?)
                && let Some(author) = tags.get(&device)
            {
                ranges.entry(author.clone()).or_default().push((first, last));
            }
        }
    }
    Ok(Some(
        ranges
            .into_iter()
            .map(|(author, mut list)| {
                list.sort_unstable();
                let mut covered = 0;
                for (first, last) in list {
                    if first > covered + 1 {
                        break;
                    }
                    covered = covered.max(last);
                }
                (author, covered)
            })
            .collect(),
    ))
}

/// Runs once per [`INTERVAL_MS`] (or when `force`) while the vault is unlocked. Deletes in
/// transactions of [`BATCH`] changes, marks first (they reference the changes); each batch records
/// the raised floor in the same transaction, so a crash between batches leaves a smaller history
/// that still follows the rule. Returns the number of changes deleted.
pub fn run(db: &mut Connection, vault_id: &str, local: &str, membership: &VerifiedMembership, force: bool) -> rusqlite::Result<usize> {
    let now = now_millis();
    let mut record = stored_record(db, vault_id)?;
    if !force && (0..INTERVAL_MS).contains(&(now - record.at)) {
        return Ok(0);
    }
    // Resolved conflicts older than 30 days go, so their changes can go too.
    let expired: Vec<String> = {
        let mut query = db.prepare("SELECT conflict_id, resolved_at_utc FROM sync_conflicts WHERE resolved_at_utc != ''")?;
        let rows = query.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut expired = Vec::new();
        for row in rows {
            let (id, resolved) = row?;
            if let Ok(at) = OffsetDateTime::parse(&resolved, &Rfc3339)
                && ((at.unix_timestamp_nanos() / 1_000_000) as i64) < now - RESOLVED_CONFLICT_MS
            {
                expired.push(id);
            }
        }
        expired
    };
    let tx = db.transaction()?;
    for id in &expired {
        tx.execute("DELETE FROM sync_conflicts WHERE conflict_id = ?1", [id])?;
    }
    tx.commit()?;

    let local_applied: Applied = crate::lan_sync::progress(db, vault_id)
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        .applied
        .into_iter()
        .map(|(author, (sequence, _))| (author, sequence))
        .collect();
    let active: Vec<&str> = membership.members.values().filter(|m| m.active).map(|m| m.device_id.as_str()).collect();
    let floors = floors(local, &active, &local_applied, &peer_applied(db, vault_id)?, drive_coverage(db, vault_id, membership)?.as_ref());
    let changes = held_changes(db, vault_id)?;
    let keep = {
        let records: Vec<(String, String, u64, String)> = db
            .prepare("SELECT entity_type, entity_id, revision, record_version_json FROM vault_records")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? as u64, row.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let tombstones: Vec<(String, String, String)> = db
            .prepare("SELECT entity_type, entity_id, change_hash FROM sync_tombstones")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let conflicts: Vec<(String, String, String, bool)> = db
            .prepare("SELECT conflict_id, local_change_hash, remote_change_hash, resolved_at_utc != '' FROM sync_conflicts")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        // A record whose version can't be read is kept whole: no change counts as its witness.
        let records: Vec<RecordRef> = records
            .iter()
            .map(|(entity_type, entity_id, revision, json)| RecordRef {
                entity_type,
                entity_id,
                revision: *revision,
                version: serde_json::from_str(json).unwrap_or_default(),
            })
            .collect();
        let tombstones: Vec<TombstoneRef> =
            tombstones.iter().map(|(t, i, h)| TombstoneRef { entity_type: t, entity_id: i, change_hash: h }).collect();
        let conflicts: Vec<ConflictRef> = conflicts
            .iter()
            .map(|(id, local, remote, resolved)| ConflictRef {
                conflict_id: id,
                local_change_hash: local,
                remote_change_hash: remote,
                resolved: *resolved,
            })
            .collect();
        keep_set(&changes, &records, &tombstones, &conflicts)
    };
    let by_hash: BTreeMap<&str, &HeldChange> = changes.iter().map(|change| (change.hash.as_str(), change)).collect();
    let plan = deletable(&changes, &keep, &floors, &local_applied);
    let mut deleted = 0;
    for batch in plan.chunks(BATCH) {
        let tx = db.transaction()?;
        for hash in batch {
            // A change that became a tombstone's or an open conflict's meanwhile stays.
            let referenced: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM sync_tombstones WHERE change_hash = ?1)
                     OR EXISTS (SELECT 1 FROM sync_conflicts WHERE resolved_at_utc = ''
                                AND (local_change_hash = ?1 OR remote_change_hash = ?1))",
                [hash],
                |row| row.get(0),
            )?;
            if referenced {
                continue;
            }
            for table in ["sync_applied_operations", "sync_received_operations", "sync_set_aside_operations"] {
                let exists: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                    [table],
                    |row| row.get(0),
                )?;
                if exists {
                    tx.execute(
                        &format!("DELETE FROM {table} WHERE mutation_id IN (SELECT mutation_id FROM sync_operations WHERE hash = ?1)"),
                        [hash],
                    )?;
                }
            }
            deleted += tx.execute("DELETE FROM sync_operations WHERE hash = ?1", [hash])?;
            let change = by_hash[hash.as_str()];
            if record.floor.get(&change.device_id).is_none_or(|(sequence, _)| change.sequence > *sequence) {
                record.floor.insert(change.device_id.clone(), (change.sequence, change.hash.clone()));
            }
        }
        save_record(&tx, vault_id, &record)?;
        tx.commit()?;
    }
    record.at = now;
    save_record(db, vault_id, &record)?;
    Ok(deleted)
}

fn held_changes(db: &Connection, vault_id: &str) -> rusqlite::Result<Vec<HeldChange>> {
    let mut query = db.prepare(
        "SELECT device_id, sequence, hash, entity_type, entity_id, kind, record_version_json, occurred_at_utc
         FROM sync_operations WHERE vault_id = ?1 ORDER BY device_id, sequence",
    )?;
    let rows = query.query_map([vault_id], |row| {
        Ok(HeldChange {
            device_id: row.get(0)?,
            sequence: row.get::<_, i64>(1)? as u64,
            hash: row.get(2)?,
            entity_type: row.get(3)?,
            entity_id: row.get(4)?,
            delete: row.get::<_, String>(5)? == "delete",
            version: serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or_default(),
            occurred_at_utc: row.get(7)?,
        })
    })?;
    rows.collect()
}

/// The suggestion for the devices list, or `None`: an active member that last synced more than 90
/// days ago and alone keeps more than 5,000 changes from being cleaned up. Never an automatic action.
/// [`blocking_hint`] for the current group of this vault, with the device it is about.
pub fn cleanup_suggestion(db: &Connection, vault_id: &str, local: &str, membership: &VerifiedMembership,
    names: &BTreeMap<String, String>, now: i64) -> rusqlite::Result<Option<(String, String)>> {
    let local_applied: Applied = crate::lan_sync::progress(db, vault_id)
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        .applied
        .into_iter()
        .map(|(author, (sequence, _))| (author, sequence))
        .collect();
    let active: Vec<(&str, &str)> = membership.members.values().filter(|m| m.active)
        .map(|m| (m.device_id.as_str(), names.get(&m.device_id).map(String::as_str).unwrap_or(""))).collect();
    let mut seen = BTreeMap::new();
    for (id, _) in &active {
        seen.insert((*id).to_owned(), crate::membership_exit::peer_seen(db, id)?);
    }
    let peers = peer_applied(db, vault_id)?;
    Ok(active.iter().filter(|(id, _)| *id != local).find_map(|(id, name)| {
        blocking_hint(local, &[(local, ""), (id, name)].iter().copied()
            .chain(active.iter().copied().filter(|(other, _)| other != id && *other != local)).collect::<Vec<_>>(),
            &local_applied, &peers, &seen, now)
            .filter(|text| text.starts_with(if name.is_empty() { "A device" } else { name }))
            .map(|text| ((*id).to_owned(), text))
    }))
}

pub fn blocking_hint(local: &str, members: &[(&str, &str)], local_applied: &Applied, peer_applied: &BTreeMap<String, Applied>,
    last_seen: &BTreeMap<String, i64>, now: i64) -> Option<String> {
    let ids: Vec<&str> = members.iter().map(|(id, _)| *id).collect();
    let with_all = floors(local, &ids, local_applied, peer_applied, None);
    members.iter().filter(|(id, _)| *id != local).find_map(|(id, name)| {
        let seen = last_seen.get(*id).copied().unwrap_or(0);
        if now - seen <= HINT_AFTER_MS {
            return None;
        }
        let others: Vec<&str> = ids.iter().copied().filter(|other| other != id).collect();
        let without = floors(local, &others, local_applied, peer_applied, None);
        let pinned: u64 = without.iter().map(|(author, value)| value - with_all.get(author).copied().unwrap_or(0)).sum();
        if pinned <= HINT_CHANGES {
            return None;
        }
        let when = if seen == 0 { "a long time".to_owned() } else { format!("{} months", ((now - seen) / (30 * 24 * 60 * 60 * 1000)).max(3)) };
        let name = if name.is_empty() { "A device" } else { name };
        Some(format!("{name} last synced {when} ago. Nuvori keeps older sync history until it syncs. Remove it if you no longer use it."))
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::params;
    use serde_json::Value;

    use super::*;
    use crate::{membership::VerifiedMember, vault::VaultStore};

    fn fixture(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    fn applied(value: &Value) -> Applied {
        value.as_object().map(|map| map.iter().map(|(k, v)| (k.clone(), v.as_u64().unwrap())).collect()).unwrap_or_default()
    }

    fn held(change: &Value) -> HeldChange {
        HeldChange {
            device_id: change["deviceId"].as_str().unwrap().to_owned(),
            sequence: change["sequence"].as_u64().unwrap(),
            hash: change["hash"].as_str().unwrap().to_owned(),
            entity_type: change["entityType"].as_str().unwrap().to_owned(),
            entity_id: change["entityId"].as_str().unwrap().to_owned(),
            delete: change["kind"] == "delete",
            version: serde_json::from_str(change["recordVersionJson"].as_str().unwrap()).unwrap(),
            occurred_at_utc: change["occurredAtUtc"].as_str().unwrap().to_owned(),
        }
    }

    #[test]
    fn floors_and_deletions_match_the_shared_vectors() {
        let vectors = fixture(include_str!("../fixtures/compaction-v1.json"));
        let history = fixture(include_str!("../fixtures/checkpoint-v1.json"));
        let input = &history["keepSetInput"];
        let changes: Vec<HeldChange> = input["operations"].as_array().unwrap().iter().map(held).collect();
        let records: Vec<RecordRef> = input["records"].as_array().unwrap().iter().map(|r| RecordRef {
            entity_type: r["entityType"].as_str().unwrap(),
            entity_id: r["entityId"].as_str().unwrap(),
            revision: r["revision"].as_u64().unwrap(),
            version: serde_json::from_str(r["recordVersionJson"].as_str().unwrap()).unwrap(),
        }).collect();
        let tombstones: Vec<TombstoneRef> = input["tombstones"].as_array().unwrap().iter().map(|t| TombstoneRef {
            entity_type: t["entityType"].as_str().unwrap(),
            entity_id: t["entityId"].as_str().unwrap(),
            change_hash: t["changeHash"].as_str().unwrap(),
        }).collect();
        let conflicts: Vec<ConflictRef> = input["conflicts"].as_array().unwrap().iter().map(|c| ConflictRef {
            conflict_id: c["conflictId"].as_str().unwrap(),
            local_change_hash: c["localChangeHash"].as_str().unwrap(),
            remote_change_hash: c["remoteChangeHash"].as_str().unwrap(),
            resolved: !c["resolvedAtUtc"].as_str().unwrap().is_empty(),
        }).collect();
        let keep = keep_set(&changes, &records, &tombstones, &conflicts);
        let local = vectors["localDeviceId"].as_str().unwrap();
        let active: Vec<&str> = vectors["members"].as_array().unwrap().iter()
            .filter(|m| m["status"] == "ACTIVE").map(|m| m["deviceId"].as_str().unwrap()).collect();
        let local_applied = applied(&vectors["localApplied"]);
        let scenarios = vectors["scenarios"].as_array().unwrap();
        assert_eq!(scenarios.len(), 5);
        for scenario in scenarios {
            let name = scenario["name"].as_str().unwrap();
            let peers: BTreeMap<String, Applied> =
                scenario["applied"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), applied(v))).collect();
            let drive = (!scenario["driveCovered"].is_null()).then(|| applied(&scenario["driveCovered"]));
            let floors = floors(local, &active, &local_applied, &peers, drive.as_ref());
            assert_eq!(floors, applied(&scenario["floors"]), "{name}");
            let deleted: HashSet<String> = deletable(&changes, &keep, &floors, &local_applied).into_iter().collect();
            let expected: HashSet<String> = scenario["deleted"].as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_owned()).collect();
            assert_eq!(deleted, expected, "{name}");
        }
    }

    #[test]
    fn drive_markers_coverage_and_cleanup_match_the_shared_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!("../fixtures/compaction-v1.json")).unwrap();
        let drive_vectors = &vectors["drive"];
        assert_eq!(drive_vectors["feature"], drive::FEATURE);
        assert!(crate::protocol::SYNC_FEATURES.contains(&drive::FEATURE));
        let ranges = |value: &serde_json::Value| -> Vec<(u64, u64)> {
            value.as_array().unwrap().iter().map(|r| (r[0].as_u64().unwrap(), r[1].as_u64().unwrap())).collect()
        };
        for case in drive_vectors["coverage"].as_array().unwrap() {
            let counted = drive::counted_floor(case["marker"].as_u64(), case["readerFloor"].as_u64().unwrap());
            assert_eq!(drive::coverage(&ranges(&case["ranges"]), counted), case["coverage"].as_u64().unwrap(), "{}", case["name"]);
        }
        for case in drive_vectors["cleanup"].as_array().unwrap() {
            let (marker, gone) = drive::cleanup(&ranges(&case["ranges"]), case["marker"].as_u64().unwrap(), case["floor"].as_u64().unwrap());
            assert_eq!(marker, case["newMarker"].as_u64().unwrap(), "{}", case["name"]);
            assert_eq!(gone, ranges(&case["deleted"]), "{}", case["name"]);
        }
        let marker: drive::Marker = serde_json::from_str(drive_vectors["marker"]["bodyJson"].as_str().unwrap()).unwrap();
        assert_eq!(marker.floor, 256);
    }

    #[test]
    fn the_record_round_trips_and_an_unreadable_one_means_never_ran() {
        let record = Record { at: 1_795_000_000_000, floor: BTreeMap::from([("pc".to_owned(), (12, "a".repeat(64)))]) };
        assert_eq!(parse(&encode(&record)), record);
        assert_eq!(parse(""), Record::default());
        assert_eq!(parse("{}"), Record::default());
    }

    #[test]
    fn a_member_silent_for_months_only_gets_a_suggestion() {
        let day = 24 * 60 * 60 * 1000;
        let now = 400 * day;
        let heads = BTreeMap::from([("phone".to_owned(), 6_000), ("pc".to_owned(), 10)]);
        let peers = BTreeMap::from([("pc".to_owned(), heads.clone()),
            ("tablet".to_owned(), BTreeMap::from([("phone".to_owned(), 100), ("pc".to_owned(), 10)]))]);
        let members = [("phone", "Phone"), ("pc", "PC"), ("tablet", "Tablet")];
        let seen = BTreeMap::from([("pc".to_owned(), now), ("tablet".to_owned(), now - 125 * day)]);
        assert_eq!(blocking_hint("phone", &members, &heads, &peers, &seen, now).as_deref(),
            Some("Tablet last synced 4 months ago. Nuvori keeps older sync history until it syncs. Remove it if you no longer use it."));
        let recent = BTreeMap::from([("pc".to_owned(), now), ("tablet".to_owned(), now - 60 * day)]);
        assert_eq!(blocking_hint("phone", &members, &heads, &peers, &recent, now), None);
    }

    fn member(device: &str, key: [u8; 32], active: bool) -> VerifiedMember {
        VerifiedMember {
            device_id: device.to_owned(),
            public_key: key,
            active,
            added_by_device_id: device.to_owned(),
            membership_sequence: 1,
            key_epoch: 1,
            removal_cutoff: None,
        }
    }

    #[test]
    fn a_vault_keeps_witnesses_waits_for_an_offline_member_and_paces_itself() {
        let directory = std::env::temp_dir().join(format!("nuvori-compaction-{}", uuid::Uuid::new_v4()));
        let store = VaultStore::new(&directory);
        let mut vault = store.create("twelve-character-password").unwrap();
        let local = store.identity_store().get_or_create().unwrap();
        let db = vault.connection();
        db.execute("UPDATE local_sync_settings SET vault_id = 'vault-a' WHERE id = 1", []).unwrap();
        db.execute("INSERT INTO sync_group_state (vault_id, content_key, transport_secret) VALUES ('vault-a', ?1, ?2)",
            params![&[4u8; 32], &[5u8; 32]]).unwrap();
        let first = vault.save_note(None, "First", "1", Some(vec![])).unwrap();
        for index in 2..=5 {
            vault.save_note(Some(&first.id), "First", &index.to_string(), None).unwrap();
        }
        let second = vault.save_note(None, "Second", "1", Some(vec![])).unwrap();
        for index in 2..=3 {
            vault.save_note(Some(&second.id), "Second", &index.to_string(), None).unwrap();
        }
        let db = vault.connection();
        let sequences = |db: &Connection| -> Vec<u64> {
            db.prepare("SELECT sequence FROM sync_operations ORDER BY sequence").unwrap()
                .query_map([], |row| row.get::<_, i64>(0)).unwrap().map(|s| s.unwrap() as u64).collect()
        };
        assert_eq!(sequences(db), (1..=8).collect::<Vec<_>>());
        let membership = VerifiedMembership {
            vault_id: "vault-a".to_owned(),
            manager_device_id: "phone".to_owned(),
            key_epoch: 1,
            head: "0".repeat(64),
            members: BTreeMap::from([
                (local.device_id.clone(), member(&local.device_id, local.public_key, true)),
                ("phone".to_owned(), member("phone", [9; 32], true)),
                ("old".to_owned(), member("old", [8; 32], false)),
            ]),
            pending_transfer: None,
            transfer_accepted: false,
        };
        // The phone never reported: nothing goes.
        assert_eq!(run(db, "vault-a", &local.device_id, &membership, true).unwrap(), 0);
        let progress = crate::lan_sync::progress(db, "vault-a").unwrap();
        let report = String::from_utf8(progress.encode().unwrap()).unwrap();
        db.execute("INSERT INTO sync_peer_progress (vault_id, peer_device_id, progress_json) VALUES ('vault-a', 'phone', ?1)",
            [&report]).unwrap();
        // A removed member pins nothing; every active member applied everything.
        assert_eq!(run(db, "vault-a", &local.device_id, &membership, true).unwrap(), 6);
        assert_eq!(sequences(db), vec![5, 8], "each note's witness stays; 8 is also the head");
        let record = stored_record(db, "vault-a").unwrap();
        assert_eq!(record.floor[&local.device_id].0, 7);
        // Paced: a second run the same day does nothing.
        assert_eq!(run(db, "vault-a", &local.device_id, &membership, false).unwrap(), 0);
        // The vault still reads, and the own change counter still shows every change written.
        assert_eq!(vault.local_change_count().unwrap(), 8);
        assert_eq!(vault.list_notes().unwrap().len(), 2);
        // The next change chains onto the kept head.
        vault.save_note(Some(&first.id), "First", "after", None).unwrap();
        assert_eq!(sequences(vault.connection()), vec![5, 8, 9]);
        drop(vault);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
