//! Parses the logical vault body sent by Android to a Windows pairing peer.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Read,
};

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::passkeys::{PasskeyError, VaultPasskey};

const MAGIC: &[u8; 8] = b"NUVPORT1";
const MAX_JSON: usize = 16 * 1024 * 1024;
const MAX_PHOTO: u64 = 128 * 1024 * 1024;
const MAX_BODY: u64 = 512 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AndroidBackup {
    version: u32,
    vault_id: String,
    entries: Vec<Value>,
    groups: Vec<Value>,
    links: Vec<Value>,
    photos: Vec<PhotoMetadata>,
    passkeys: Vec<VaultPasskey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhotoMetadata {
    pub id: String,
    pub entry_id: String,
    pub is_cover: bool,
    pub added_at: i64,
}

pub struct PortablePhoto {
    pub metadata: PhotoMetadata,
    pub bytes: Zeroizing<Vec<u8>>,
}

pub struct PortableBackup {
    pub vault_id: String,
    pub entries: Vec<Value>,
    pub groups: Vec<Value>,
    pub links: Vec<Value>,
    pub passkeys: Vec<VaultPasskey>,
    pub photos: Vec<PortablePhoto>,
}

pub fn read_portable_backup<R: Read>(
    input: &mut R,
    expected_vault_id: &str,
) -> Result<PortableBackup, BackupError> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(BackupError::InvalidFormat);
    }
    let json_size = read_u32(input)? as usize;
    if json_size == 0 || json_size > MAX_JSON {
        return Err(BackupError::InvalidFormat);
    }
    let mut json = Zeroizing::new(vec![0; json_size]);
    input.read_exact(&mut json)?;
    let body: AndroidBackup = serde_json::from_slice(&json)?;
    validate(&body, expected_vault_id)?;

    let photo_count = read_u32(input)? as usize;
    if photo_count != body.photos.len() {
        return Err(BackupError::InvalidPhoto);
    }
    let photo_metadata: HashMap<_, _> = body
        .photos
        .into_iter()
        .map(|photo| (photo.id.clone(), photo))
        .collect();
    let mut photo_bytes = BTreeMap::new();
    let mut total = json_size as u64;
    for _ in 0..photo_count {
        let id_size = read_u16(input)? as usize;
        if !(1..=128).contains(&id_size) {
            return Err(BackupError::InvalidPhoto);
        }
        let mut id_bytes = vec![0; id_size];
        input.read_exact(&mut id_bytes)?;
        let id = String::from_utf8(id_bytes).map_err(|_| BackupError::InvalidPhoto)?;
        if !valid_photo_id(&id)
            || !photo_metadata.contains_key(&id)
            || photo_bytes.contains_key(&id)
        {
            return Err(BackupError::InvalidPhoto);
        }
        let size = read_u64(input)?;
        total = total.checked_add(size).ok_or(BackupError::InvalidPhoto)?;
        if size == 0 || size > MAX_PHOTO || total > MAX_BODY {
            return Err(BackupError::InvalidPhoto);
        }
        let mut bytes = Zeroizing::new(vec![0; size as usize]);
        input.read_exact(&mut bytes)?;
        photo_bytes.insert(id, bytes);
    }
    let mut end = [0];
    if input.read(&mut end)? != 0 {
        return Err(BackupError::TrailingData);
    }
    let mut photos = Vec::with_capacity(photo_metadata.len());
    for (id, metadata) in photo_metadata {
        let bytes = photo_bytes.remove(&id).ok_or(BackupError::InvalidPhoto)?;
        photos.push(PortablePhoto { metadata, bytes });
    }
    Ok(PortableBackup {
        vault_id: body.vault_id,
        entries: body.entries,
        groups: body.groups,
        links: body.links,
        passkeys: body.passkeys,
        photos,
    })
}

fn validate(body: &AndroidBackup, expected_vault_id: &str) -> Result<(), BackupError> {
    if body.version != 9 || body.vault_id != expected_vault_id {
        return Err(BackupError::InvalidFormat);
    }
    let mut entry_types = HashMap::new();
    for entry in &body.entries {
        let id = field(entry, "id")?;
        let entry_type = field(entry, "type")?;
        if !matches!(
            entry_type,
            "CARD" | "PASSWORD" | "QUESTION" | "NOTE" | "AUTHENTICATOR" | "AUTOFILL"
        ) || field(entry, "title")?.trim().is_empty()
            || !valid_entry_fields(entry)
            || entry_types.insert(id, entry_type).is_some()
        {
            return Err(BackupError::InvalidEntry);
        }
    }
    let mut groups = HashMap::new();
    for group in &body.groups {
        let id = field(group, "id")?;
        let folder_type = field(group, "folderType")?;
        if !folder_type.is_empty()
            && !matches!(
                folder_type,
                "CARD" | "PASSWORD" | "QUESTION" | "NOTE" | "AUTHENTICATOR" | "AUTOFILL"
            )
        {
            return Err(BackupError::InvalidGroup);
        }
        if field(group, "name")?.is_empty()
            || field(group, "notes").is_err()
            || groups.insert(id, folder_type).is_some()
        {
            return Err(BackupError::InvalidGroup);
        }
    }
    let mut links = HashSet::new();
    let mut typed_per_entry = HashSet::new();
    for link in &body.links {
        let entry_id = field(link, "entryId")?;
        let group_id = field(link, "groupId")?;
        let entry_type = entry_types.get(entry_id).ok_or(BackupError::InvalidGroup)?;
        let folder_type = groups.get(group_id).ok_or(BackupError::InvalidGroup)?;
        if !folder_type.is_empty()
            && (folder_type != entry_type || !typed_per_entry.insert(entry_id))
            || !links.insert((entry_id, group_id))
        {
            return Err(BackupError::InvalidGroup);
        }
    }
    let mut photo_ids = HashSet::new();
    for photo in &body.photos {
        if !valid_photo_id(&photo.id)
            || !photo_ids.insert(&photo.id)
            || !entry_types.contains_key(photo.entry_id.as_str())
            || photo.added_at < 0
        {
            return Err(BackupError::InvalidPhoto);
        }
    }
    let mut passkey_ids = HashSet::new();
    for passkey in &body.passkeys {
        passkey.validate()?;
        if !passkey_ids.insert(&passkey.id) {
            return Err(BackupError::InvalidPasskey);
        }
    }
    for entry in &body.entries {
        let linked = field(entry, "linkedAuthenticatorId")?;
        if !linked.is_empty()
            && (field(entry, "type")? != "PASSWORD"
                || entry_types.get(linked) != Some(&"AUTHENTICATOR"))
        {
            return Err(BackupError::InvalidEntry);
        }
    }
    Ok(())
}

fn valid_entry_fields(entry: &Value) -> bool {
    for name in [
        "primaryValue",
        "secondaryValue",
        "tertiaryValue",
        "fourthValue",
        "cardKind",
        "network",
        "totpAlgorithm",
        "linkedApps",
        "autofillSignatures",
        "autofillOrigins",
        "linkedAuthenticatorId",
        "notes",
        "tags",
    ] {
        if entry.get(name).and_then(Value::as_str).is_none() {
            return false;
        }
    }
    matches!(entry["cardKind"].as_str(), Some("CREDIT" | "DEBIT"))
        && matches!(
            entry["totpAlgorithm"].as_str(),
            Some("SHA1" | "SHA256" | "SHA512")
        )
        && entry["totpDigits"].as_i64().is_some()
        && entry["totpPeriod"].as_i64().is_some()
        && entry["color"].as_i64().is_some()
        && entry["favorite"].as_bool().is_some()
        && ["lastOpenedAt", "sortOrder", "createdAt", "updatedAt"]
            .iter()
            .all(|name| entry[*name].as_i64().is_some())
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, BackupError> {
    value[name]
        .as_str()
        .filter(|value| {
            !value.is_empty() || matches!(name, "folderType" | "notes" | "linkedAuthenticatorId")
        })
        .ok_or(BackupError::InvalidFormat)
}

fn valid_photo_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn read_u16(input: &mut impl Read) -> Result<u16, std::io::Error> {
    let mut bytes = [0; 2];
    input.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(input: &mut impl Read) -> Result<u32, std::io::Error> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(input: &mut impl Read) -> Result<u64, std::io::Error> {
    let mut bytes = [0; 8];
    input.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("portable backup read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("portable backup JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("portable backup format is invalid")]
    InvalidFormat,
    #[error("portable backup entry is invalid")]
    InvalidEntry,
    #[error("portable backup folder links are invalid")]
    InvalidGroup,
    #[error("portable backup photo data is invalid")]
    InvalidPhoto,
    #[error("portable backup has trailing data")]
    TrailingData,
    #[error("portable backup passkey is invalid")]
    InvalidPasskey,
    #[error("portable backup passkey key material is invalid: {0}")]
    Passkey(#[from] PasskeyError),
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::*;

    fn body(with_photo: bool) -> Vec<u8> {
        let metadata = json!({
            "version": 9, "vaultId": "vault-a",
            "entries": [{"id": "entry-a", "type": "NOTE", "title": "Example",
                "primaryValue": "", "secondaryValue": "", "tertiaryValue": "", "fourthValue": "",
                "cardKind": "CREDIT", "network": "", "totpAlgorithm": "SHA1",
                "totpDigits": 6, "totpPeriod": 30, "linkedApps": "",
                "autofillSignatures": "", "autofillOrigins": "",
                "linkedAuthenticatorId": "", "notes": "A note", "color": 4278743114_u64,
                "tags": "", "favorite": false, "lastOpenedAt": 0,
                "sortOrder": 123, "createdAt": 123, "updatedAt": 123}],
            "groups": [{"id": "group-a", "name": "Personal", "notes": "", "folderType": "NOTE"}],
            "links": [{"entryId": "entry-a", "groupId": "group-a"}],
            "photos": if with_photo { json!([{"id": "photo-a", "entryId": "entry-a",
                "isCover": true, "addedAt": 123}]) } else { json!([]) },
            "passkeys": []
        });
        let json = serde_json::to_vec(&metadata).unwrap();
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&(json.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&json);
        bytes.extend_from_slice(&(if with_photo { 1_u32 } else { 0 }).to_be_bytes());
        if with_photo {
            bytes.extend_from_slice(&7_u16.to_be_bytes());
            bytes.extend_from_slice(b"photo-a");
            bytes.extend_from_slice(&3_u64.to_be_bytes());
            bytes.extend_from_slice(b"png");
        }
        bytes
    }

    #[test]
    fn reads_android_logical_backup_and_photo_bytes() {
        let backup = read_portable_backup(&mut Cursor::new(body(true)), "vault-a").unwrap();
        assert_eq!(backup.entries.len(), 1);
        assert_eq!(backup.links.len(), 1);
        assert_eq!(backup.photos.len(), 1);
        assert_eq!(backup.photos[0].metadata.id, "photo-a");
        assert_eq!(&*backup.photos[0].bytes, b"png");
    }

    #[test]
    fn refuses_missing_or_extra_photo_data() {
        let mut truncated = body(true);
        truncated.truncate(truncated.len() - 2);
        assert!(matches!(
            read_portable_backup(&mut Cursor::new(truncated), "vault-a"),
            Err(BackupError::Io(_))
        ));
        let mut extra = body(false);
        extra.push(1);
        assert!(matches!(
            read_portable_backup(&mut Cursor::new(extra), "vault-a"),
            Err(BackupError::TrailingData)
        ));
    }

    #[test]
    fn rejects_entry_missing_android_fields_before_import() {
        let mut bytes = body(false);
        let size = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let mut metadata: Value = serde_json::from_slice(&bytes[12..12 + size]).unwrap();
        metadata["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("favorite");
        let json = serde_json::to_vec(&metadata).unwrap();
        bytes.splice(
            8..12 + size,
            [
                (json.len() as u32).to_be_bytes().as_slice(),
                json.as_slice(),
            ]
            .concat(),
        );
        assert!(matches!(
            read_portable_backup(&mut Cursor::new(bytes), "vault-a"),
            Err(BackupError::InvalidEntry)
        ));
    }
}
