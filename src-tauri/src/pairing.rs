use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    identity::DeviceIdentity,
    wire::{HANDSHAKE_FRAME, SyncFrames, WireError},
};

const WIRE_VERSION: u64 = 2;

pub struct PairingSession {
    pub peer: DeviceIdentity,
    pub key: [u8; 32],
    pub confirmation: String,
    /// What the peer announced in its hello; advisory, never trusted for access.
    pub peer_features: Vec<String>,
}

impl Drop for PairingSession {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Runs Android's wire-v2 J-PAKE rounds through the bundled Bouncy Castle helper.
#[allow(clippy::too_many_arguments)]
pub fn handshake<R: Read, W: Write>(
    frames: &mut SyncFrames<R, W>,
    helper_path: &Path,
    local: &DeviceIdentity,
    secret: &str,
    session_id: &str,
    vault_id: &str,
    creator: bool,
    expected_peer: Option<&DeviceIdentity>,
) -> Result<PairingSession, PairingError> {
    if !valid_field(session_id)
        || !valid_field(vault_id)
        || !valid_field(&local.device_id)
        || secret.is_empty()
        || secret.len() > 8192
    {
        return Err(PairingError::InvalidHandshake);
    }
    let peer_hello = exchange(
        frames,
        json!({
            "protocol": WIRE_VERSION, "session": session_id, "vault": vault_id,
            "creator": creator, "device": local.device_id, "key": local.public_key_base64_url(),
            "platform": "windows",
            // Older builds ignore this list; a peer without it supports none of these features.
            "features": crate::protocol::SYNC_FEATURES
        }),
    )?;
    if peer_hello["protocol"].as_u64() != Some(WIRE_VERSION)
        || peer_hello["session"] != session_id
        || peer_hello["vault"] != vault_id
        || peer_hello["creator"].as_bool() != Some(!creator)
    {
        return Err(PairingError::InvalidHandshake);
    }
    let peer_id = peer_hello["device"]
        .as_str()
        .ok_or(PairingError::InvalidHandshake)?;
    if !valid_field(peer_id) || peer_id == local.device_id {
        return Err(PairingError::InvalidHandshake);
    }
    let peer_public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            peer_hello["key"]
                .as_str()
                .ok_or(PairingError::InvalidHandshake)?,
        )
        .map_err(|_| PairingError::InvalidHandshake)?
        .try_into()
        .map_err(|_| PairingError::InvalidHandshake)?;
    let peer = DeviceIdentity {
        device_id: peer_id.to_owned(),
        public_key: peer_public_key,
    };
    let peer_features: Vec<String> = peer_hello["features"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|feature| feature.as_str().filter(|feature| feature.len() <= 40).map(str::to_owned))
        .take(32)
        .collect();
    if expected_peer.is_some_and(|expected| expected != &peer) {
        return Err(PairingError::PeerChanged);
    }

    let mut jpake = JpakeHelper::start(helper_path, &local.device_id, secret)?;
    let first = jpake.read()?;
    let first_peer = exchange(frames, first)?;
    check_round(&first_peer, &peer.device_id, &["gx1", "gx2", "p1", "p2"])?;
    let second = jpake.exchange(first_peer)?;
    let second_peer = exchange(frames, second)?;
    check_round(&second_peer, &peer.device_id, &["a", "proof"])?;
    let third = jpake.exchange(second_peer)?;
    let third_peer = exchange(frames, third)?;
    check_round(&third_peer, &peer.device_id, &["mac"])?;
    let mut material_reply = jpake.exchange(third_peer)?;
    let encoded = Zeroizing::new(
        material_reply
            .as_object_mut()
            .and_then(|object| object.remove("material"))
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or(PairingError::InvalidHandshake)?,
    );
    let material = Zeroizing::new(
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| PairingError::InvalidHandshake)?,
    );
    if material.is_empty() || material.len() > 512 {
        return Err(PairingError::InvalidHandshake);
    }

    let (source, target) = if creator {
        (local, &peer)
    } else {
        (&peer, local)
    };
    let transcript = transcript(session_id, vault_id, source, target)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&material)
        .map_err(|_| PairingError::InvalidHandshake)?;
    mac.update(&transcript);
    let key: [u8; 32] = mac.finalize().into_bytes().into();
    let code = hex::encode_upper(&Sha256::digest(key)[..4]);
    Ok(PairingSession {
        peer,
        key,
        confirmation: format!("{} {}", &code[..4], &code[4..]),
        peer_features,
    })
}

fn valid_field(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256
}

fn check_round(value: &Value, peer_id: &str, fields: &[&str]) -> Result<(), PairingError> {
    if value["id"] != peer_id || fields.iter().any(|field| value.get(*field).is_none()) {
        return Err(PairingError::InvalidHandshake);
    }
    Ok(())
}

fn transcript(
    session_id: &str,
    vault_id: &str,
    source: &DeviceIdentity,
    target: &DeviceIdentity,
) -> Result<Vec<u8>, PairingError> {
    let fields = [
        "nuvori-pairing-v1",
        session_id,
        vault_id,
        &source.device_id,
        &source.public_key_base64_url(),
        &target.device_id,
        &target.public_key_base64_url(),
    ];
    let mut bytes = Vec::new();
    for value in fields {
        if !valid_field(value) {
            return Err(PairingError::InvalidHandshake);
        }
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    Ok(bytes)
}

fn exchange<R: Read, W: Write>(
    frames: &mut SyncFrames<R, W>,
    local: Value,
) -> Result<Value, PairingError> {
    frames.send(&serde_json::to_vec(&local)?, HANDSHAKE_FRAME)?;
    let peer = frames.receive(HANDSHAKE_FRAME)?;
    Ok(serde_json::from_slice(&peer)?)
}

struct JpakeHelper {
    process: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl JpakeHelper {
    fn start(path: &Path, id: &str, secret: &str) -> Result<Self, PairingError> {
        let mut command = if path.extension().is_some_and(|extension| extension == "dll") {
            let mut command = Command::new("dotnet");
            command.arg(path);
            command
        } else {
            Command::new(path)
        };
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut process = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = process
            .stdin
            .take()
            .ok_or(PairingError::HelperUnavailable)?;
        let output = BufReader::new(
            process
                .stdout
                .take()
                .ok_or(PairingError::HelperUnavailable)?,
        );
        let mut helper = Self {
            process,
            input,
            output,
        };
        helper.send(&json!({"action": "init", "id": id, "secret": secret}))?;
        if helper.read()?["ready"] != true {
            return Err(PairingError::HelperUnavailable);
        }
        Ok(helper)
    }

    fn send(&mut self, value: &Value) -> Result<(), PairingError> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        self.input.write_all(&bytes)?;
        self.input.flush()?;
        bytes.zeroize();
        Ok(())
    }

    fn read(&mut self) -> Result<Value, PairingError> {
        let mut line = Zeroizing::new(String::new());
        self.output.read_line(&mut line)?;
        if line.len() < 3 || line.len() > 32768 {
            return Err(PairingError::InvalidHandshake);
        }
        let value: Value = serde_json::from_str(&line)?;
        if value.get("error").is_some() {
            return Err(PairingError::InvalidHandshake);
        }
        Ok(value)
    }

    fn exchange(&mut self, value: Value) -> Result<Value, PairingError> {
        self.send(&value)?;
        self.read()
    }
}

impl Drop for JpakeHelper {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("pairing I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("pairing frame failed: {0}")]
    Wire(#[from] WireError),
    #[error("pairing message failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("pairing helper is unavailable")]
    HelperUnavailable,
    #[error("peer identity changed")]
    PeerChanged,
    #[error("pairing handshake failed")]
    InvalidHandshake,
}

#[cfg(test)]
mod tests {
    use std::{
        net::{TcpListener, TcpStream},
        time::Duration,
    };

    use super::*;

    #[test]
    #[ignore = "build pairing-helper first, then set NUVORI_PAIRING_HELPER to its DLL or EXE"]
    fn rust_wire_and_bouncy_castle_helper_complete_both_pairing_roles() {
        let helper = std::env::var("NUVORI_PAIRING_HELPER").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let first = std::thread::spawn({
            let helper = helper.clone();
            move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut frames = SyncFrames::new(socket.try_clone().unwrap(), socket);
                handshake(
                    &mut frames,
                    Path::new(&helper),
                    &DeviceIdentity {
                        device_id: "android".to_owned(),
                        public_key: [1; 32],
                    },
                    "123456789012345678901234",
                    "session-a",
                    "vault-a",
                    true,
                    None,
                )
                .unwrap()
            }
        });
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut frames = SyncFrames::new(socket.try_clone().unwrap(), socket);
        let second = handshake(
            &mut frames,
            Path::new(&helper),
            &DeviceIdentity {
                device_id: "windows".to_owned(),
                public_key: [2; 32],
            },
            "123456789012345678901234",
            "session-a",
            "vault-a",
            false,
            None,
        )
        .unwrap();
        let first = first.join().unwrap();
        assert_eq!(first.key, second.key);
        assert_eq!(first.confirmation, second.confirmation);
    }
}
