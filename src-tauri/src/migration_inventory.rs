//! Read-only view of local vault data before an Android enrollment import.

use std::collections::HashSet;

use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::passkeys::VaultPasskey;

#[derive(Debug)]
pub struct MigrationInventory {
    pub notes: Vec<LocalNote>,
    pub entries: Vec<Value>,
    pub groups: Vec<LocalGroup>,
    pub links: Vec<EntryGroupLink>,
    pub passkeys: Vec<VaultPasskey>,
    pub photos: Vec<LocalPhoto>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNote {
    pub id: String,
    pub title: String,
    pub body: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub details: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalGroup {
    pub id: String,
    pub name: String,
    pub notes: String,
    pub folder_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryGroupLink {
    pub entry_id: String,
    pub group_id: String,
}

#[derive(Debug)]
pub struct LocalPhoto {
    pub id: String,
    pub entry_id: String,
    pub mime_type: String,
    pub data: Zeroizing<Vec<u8>>,
}

pub fn read(connection: &Connection) -> Result<MigrationInventory, InventoryError> {
    let mut notes = Vec::new();
    {
        let mut statement = connection.prepare(
            "SELECT id, title, body, created_at, updated_at FROM local_notes ORDER BY id",
        )?;
        for row in statement.query_map([], |row| {
            Ok(LocalNote {
                id: row.get(0)?,
                title: row.get(1)?,
                body: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                details: None,
            })
        })? {
            let note = row?;
            if note.id.is_empty()
                || note.title.trim().is_empty()
                || note.title.len() > 500
                || note.body.len() > 1_048_576
                || note.created_at < 0
                || note.updated_at < note.created_at
            {
                return Err(InventoryError::InvalidData);
            }
            notes.push(note);
        }
    }
    for note in &mut notes {
        let raw: Option<String> = connection
            .query_row(
                "SELECT data_json FROM local_note_details WHERE id = ?1",
                [&note.id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(raw) = raw {
            let details: Value = serde_json::from_str(&raw)?;
            if details["id"] != note.id
                || details["type"] != "NOTE"
                || details["title"] != note.title
                || details["notes"] != note.body
                || details["createdAt"].as_i64() != Some(note.created_at)
                || details["updatedAt"].as_i64() != Some(note.updated_at)
            {
                return Err(InventoryError::InvalidData);
            }
            note.details = Some(details);
        }
    }

    let mut entries = Vec::new();
    {
        let mut statement = connection
            .prepare("SELECT id, type, data_json, updated_at FROM local_entries ORDER BY id")?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })? {
            let (id, kind, raw, updated_at) = row?;
            let entry: Value = serde_json::from_str(&raw)?;
            if id.is_empty()
                || entry["id"] != id
                || entry["type"] != kind
                || entry["updatedAt"].as_i64() != Some(updated_at)
                || !matches!(
                    kind.as_str(),
                    "CARD" | "PASSWORD" | "QUESTION" | "AUTHENTICATOR" | "AUTOFILL"
                )
            {
                return Err(InventoryError::InvalidData);
            }
            entries.push(entry);
        }
    }

    let mut groups = Vec::new();
    {
        let mut statement = connection
            .prepare("SELECT id, name, notes, folder_type FROM local_groups ORDER BY id")?;
        for row in statement.query_map([], |row| {
            Ok(LocalGroup {
                id: row.get(0)?,
                name: row.get(1)?,
                notes: row.get(2)?,
                folder_type: row.get(3)?,
            })
        })? {
            let group = row?;
            if group.id.is_empty()
                || group.name.trim().is_empty()
                || group.name.len() > 500
                || group.notes.len() > 1_048_576
                || !matches!(
                    group.folder_type.as_str(),
                    "" | "CARD" | "PASSWORD" | "QUESTION" | "NOTE" | "AUTHENTICATOR" | "AUTOFILL"
                )
            {
                return Err(InventoryError::InvalidData);
            }
            groups.push(group);
        }
    }

    let entry_ids: HashSet<&str> = entries
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .chain(notes.iter().map(|note| note.id.as_str()))
        .collect();
    let group_ids: HashSet<&str> = groups.iter().map(|group| group.id.as_str()).collect();
    let mut links = Vec::new();
    {
        let mut statement = connection
            .prepare("SELECT entry_id, group_id FROM entry_groups ORDER BY entry_id, group_id")?;
        let mut unique = HashSet::new();
        for row in statement.query_map([], |row| {
            Ok(EntryGroupLink {
                entry_id: row.get(0)?,
                group_id: row.get(1)?,
            })
        })? {
            let link = row?;
            if !entry_ids.contains(link.entry_id.as_str())
                || !group_ids.contains(link.group_id.as_str())
                || !unique.insert((link.entry_id.clone(), link.group_id.clone()))
            {
                return Err(InventoryError::InvalidData);
            }
            links.push(link);
        }
    }

    let mut passkeys = Vec::new();
    {
        let mut statement =
            connection.prepare("SELECT id, rp_id, data_json FROM local_passkeys ORDER BY id")?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (id, rp_id, raw) = row?;
            let passkey: VaultPasskey = serde_json::from_str(&raw)?;
            passkey
                .validate()
                .map_err(|_| InventoryError::InvalidData)?;
            if passkey.id != id || passkey.rp_id != rp_id {
                return Err(InventoryError::InvalidData);
            }
            passkeys.push(passkey);
        }
    }

    let mut photos = Vec::new();
    {
        let mut statement = connection
            .prepare("SELECT id, entry_id, mime_type, data FROM local_entry_photos ORDER BY id")?;
        for row in statement.query_map([], |row| {
            Ok(LocalPhoto {
                id: row.get(0)?,
                entry_id: row.get(1)?,
                mime_type: row.get(2)?,
                data: Zeroizing::new(row.get(3)?),
            })
        })? {
            let photo = row?;
            if photo.id.is_empty()
                || !entry_ids.contains(photo.entry_id.as_str())
                || !valid_photo(&photo.mime_type, &photo.data)
            {
                return Err(InventoryError::InvalidData);
            }
            photos.push(photo);
        }
    }

    Ok(MigrationInventory {
        notes,
        entries,
        groups,
        links,
        passkeys,
        photos,
    })
}

fn valid_photo(mime: &str, bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > 10_000_000 {
        return false;
    }
    match mime {
        "image/jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/webp" => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"),
        "image/gif" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        _ => false,
    }
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("local vault data is invalid")]
    InvalidData,
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use p256::{
        SecretKey,
        pkcs8::{EncodePrivateKey, EncodePublicKey},
    };
    use rusqlite::params;

    fn schema(connection: &Connection) {
        connection.execute_batch(
            "CREATE TABLE local_notes(id TEXT PRIMARY KEY, title TEXT, body TEXT, created_at INTEGER, updated_at INTEGER);
             CREATE TABLE local_note_details(id TEXT PRIMARY KEY, data_json TEXT);
             CREATE TABLE local_entries(id TEXT PRIMARY KEY, type TEXT, data_json TEXT, updated_at INTEGER);
             CREATE TABLE local_groups(id TEXT PRIMARY KEY, name TEXT, notes TEXT, folder_type TEXT);
             CREATE TABLE entry_groups(entry_id TEXT, group_id TEXT);
             CREATE TABLE local_passkeys(id TEXT PRIMARY KEY, rp_id TEXT, data_json TEXT);
             CREATE TABLE local_entry_photos(id TEXT PRIMARY KEY, entry_id TEXT, mime_type TEXT, data BLOB);",
        ).unwrap();
    }

    fn passkey() -> VaultPasskey {
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        VaultPasskey {
            id: STANDARD
                .encode([7; 32])
                .replace('+', "-")
                .replace('/', "_")
                .trim_end_matches('=')
                .to_owned(),
            rp_id: "example.com".into(),
            user_handle: "AwMDAwMDAwMDAwMDAwMDAw".into(),
            username: "alice".into(),
            display_name: "Alice".into(),
            private_key: STANDARD
                .encode(secret.to_pkcs8_der().unwrap().as_bytes())
                .replace('+', "-")
                .replace('/', "_")
                .trim_end_matches('=')
                .to_owned(),
            public_key: STANDARD
                .encode(secret.public_key().to_public_key_der().unwrap().as_bytes())
                .replace('+', "-")
                .replace('/', "_")
                .trim_end_matches('=')
                .to_owned(),
            created_at: 10,
        }
    }

    #[test]
    fn reads_and_validates_all_local_item_tables_without_mutating_them() {
        let connection = Connection::open_in_memory().unwrap();
        schema(&connection);
        let note = serde_json::json!({"id":"note-1","type":"NOTE","title":"Note","notes":"Body","createdAt":1,"updatedAt":2});
        connection
            .execute(
                "INSERT INTO local_notes VALUES('note-1','Note','Body',1,2)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO local_note_details VALUES('note-1',?1)",
                [note.to_string()],
            )
            .unwrap();
        let entry =
            serde_json::json!({"id":"entry-1","type":"PASSWORD","title":"Mail","updatedAt":2});
        connection
            .execute(
                "INSERT INTO local_entries VALUES('entry-1','PASSWORD',?1,2)",
                [entry.to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO local_groups VALUES('group-1','Personal','','PASSWORD')",
                [],
            )
            .unwrap();
        connection
            .execute("INSERT INTO entry_groups VALUES('entry-1','group-1')", [])
            .unwrap();
        let key = passkey();
        connection
            .execute(
                "INSERT INTO local_passkeys VALUES(?1,?2,?3)",
                params![key.id, key.rp_id, serde_json::to_string(&key).unwrap()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO local_entry_photos VALUES('photo-1','entry-1','image/png',?1)",
                [b"\x89PNG\r\n\x1a\nbody".as_slice()],
            )
            .unwrap();

        let inventory = read(&connection).unwrap();
        assert_eq!(inventory.notes.len(), 1);
        assert_eq!(inventory.entries, vec![entry]);
        assert_eq!(inventory.groups.len(), 1);
        assert_eq!(inventory.links.len(), 1);
        assert_eq!(inventory.passkeys.len(), 1);
        assert_eq!(&*inventory.photos[0].data, b"\x89PNG\r\n\x1a\nbody");
        let count: i64 = connection
            .query_row("SELECT count(*) FROM local_entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn rejects_orphan_links_and_invalid_photos() {
        let connection = Connection::open_in_memory().unwrap();
        schema(&connection);
        connection
            .execute("INSERT INTO entry_groups VALUES('missing','missing')", [])
            .unwrap();
        assert!(matches!(
            read(&connection),
            Err(InventoryError::InvalidData)
        ));
    }
}
