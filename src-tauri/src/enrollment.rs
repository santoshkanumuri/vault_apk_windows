//! Joins an Android-managed vault using the phone's existing pairing link.

use std::{
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::Path,
    thread,
    time::Duration,
    time::Instant,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    identity::{DeviceIdentity, DeviceIdentityStore, IdentityError},
    pairing::{self, PairingError},
    snapshot::SnapshotError,
    snapshot_import::{ImportError, PreparedEnrollment},
    vault::UnlockedVault,
    wire::{EncryptedSyncChannel, SyncFrames, WireError},
};

const PREFIX: &str = "nuvori-pair://v3/";
const REVERSE_PREFIX: &str = "nuvori-pair-reverse://v2/";
const MAX_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
pub(crate) const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(120);

pub struct ReverseOffer {
    listener: TcpListener,
    session: String,
    code: Zeroizing<String>,
    link: Zeroizing<String>,
}

impl ReverseOffer {
    pub fn bind() -> Result<Self, EnrollmentError> {
        let addresses: Vec<_> = crate::discovery::local_addresses().into_iter()
            .filter(|ip| ip.is_ipv4()).collect();
        if addresses.is_empty() { return Err(EnrollmentError::NoLocalAddress); }
        Self::bind_at(IpAddr::V4(Ipv4Addr::UNSPECIFIED), &addresses)
    }

    fn bind_at(address: IpAddr, addresses: &[IpAddr]) -> Result<Self, EnrollmentError> {
        let listener = TcpListener::bind((address, 0))?;
        listener.set_nonblocking(true)?;
        let mut code = Zeroizing::new(String::with_capacity(24));
        while code.len() < 24 {
            let mut byte = [0_u8];
            getrandom::fill(&mut byte).map_err(|_| EnrollmentError::NoRandomness)?;
            if byte[0] < 250 {
                code.push(char::from(b'0' + byte[0] % 10));
            }
        }
        let session = uuid::Uuid::new_v4().to_string();
        let link = Zeroizing::new(format!(
            "{REVERSE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(
                serde_json::json!({"addresses": addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "port": listener.local_addr()?.port(), "session": session, "code": code.as_str()})
                    .to_string()
            )
        ));
        Ok(Self {
            listener,
            session,
            code,
            link,
        })
    }

    pub fn link(&self) -> &str {
        &self.link
    }

    pub fn accept(&self, canceled: impl Fn() -> bool) -> Result<TcpStream, EnrollmentError> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if canceled() {
                return Err(EnrollmentError::Canceled);
            }
            if Instant::now() >= deadline {
                return Err(EnrollmentError::OfferExpired);
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false)?;
                    return Ok(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100))
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[derive(Deserialize)]
struct InvitationFields {
    address: String,
    port: u16,
    session: String,
    vault: String,
    code: String,
}

pub struct PairingInvitation {
    address: SocketAddr,
    session: String,
    vault: String,
    code: Zeroizing<String>,
}

impl PairingInvitation {
    pub fn parse(link: &str) -> Result<Self, EnrollmentError> {
        if link.len() > 2048 {
            return Err(EnrollmentError::InvalidInvitation);
        }
        let encoded = link
            .strip_prefix(PREFIX)
            .ok_or(EnrollmentError::InvalidInvitation)?;
        let mut bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| EnrollmentError::InvalidInvitation)?,
        );
        let mut fields: InvitationFields =
            serde_json::from_slice(&bytes).map_err(|_| EnrollmentError::InvalidInvitation)?;
        bytes.zeroize();
        let ip: IpAddr = fields
            .address
            .parse()
            .map_err(|_| EnrollmentError::InvalidInvitation)?;
        let private = match ip {
            IpAddr::V4(address) => address.is_private(),
            IpAddr::V6(address) => address.segments()[0] & 0xfe00 == 0xfc00,
        };
        if !private
            || fields.port < 1024
            || !(1..=128).contains(&fields.session.len())
            || !(1..=128).contains(&fields.vault.len())
            || fields.code.len() != 24
            || !fields.code.bytes().all(|digit| digit.is_ascii_digit())
        {
            fields.code.zeroize();
            return Err(EnrollmentError::InvalidInvitation);
        }
        Ok(Self {
            address: SocketAddr::new(ip, fields.port),
            session: fields.session,
            vault: fields.vault,
            code: Zeroizing::new(fields.code),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

pub struct JoinSession {
    invitation: PairingInvitation,
    channel: EncryptedSyncChannel<TcpStream, TcpStream>,
    socket: TcpStream,
    local: DeviceIdentity,
    peer: DeviceIdentity,
    pairing_key: Zeroizing<[u8; 32]>,
    confirmation: String,
}

impl JoinSession {
    pub fn connect(
        invitation: PairingInvitation,
        master_password: &str,
        helper_path: &Path,
        identity_store: &DeviceIdentityStore,
        socket: impl FnOnce(&TcpStream) -> io::Result<()>,
    ) -> Result<Self, EnrollmentError> {
        if master_password.chars().count() < 12 {
            return Err(EnrollmentError::InvalidPassword);
        }
        let stream = TcpStream::connect_timeout(&invitation.address, Duration::from_secs(10))
            .map_err(|error| match error.kind() {
                io::ErrorKind::TimedOut => EnrollmentError::ConnectionTimedOut(invitation.address),
                _ => EnrollmentError::ConnectionFailed(invitation.address, error),
            })?;
        socket(&stream)?;
        Self::from_stream(
            stream,
            invitation,
            master_password,
            helper_path,
            identity_store,
        )
    }

    pub fn accept(
        stream: TcpStream,
        offer: &ReverseOffer,
        master_password: &str,
        helper_path: &Path,
        identity_store: &DeviceIdentityStore,
    ) -> Result<Self, EnrollmentError> {
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut frames = SyncFrames::new(stream.try_clone()?, stream.try_clone()?);
        let vault = read_reverse_vault(&mut frames)?;
        let invitation = PairingInvitation {
            address: stream.peer_addr()?,
            session: offer.session.clone(),
            vault,
            code: Zeroizing::new(offer.code.to_string()),
        };
        Self::from_stream(
            stream,
            invitation,
            master_password,
            helper_path,
            identity_store,
        )
    }

    fn from_stream(
        stream: TcpStream,
        invitation: PairingInvitation,
        master_password: &str,
        helper_path: &Path,
        identity_store: &DeviceIdentityStore,
    ) -> Result<Self, EnrollmentError> {
        if master_password.chars().count() < 12 {
            return Err(EnrollmentError::InvalidPassword);
        }
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let local = identity_store.get_or_create()?;
        let mut frames = SyncFrames::new(stream.try_clone()?, stream.try_clone()?);
        let result = pairing::handshake(
            &mut frames,
            helper_path,
            &local,
            &invitation.code,
            &invitation.session,
            &invitation.vault,
            false,
            None,
        )?;
        let password_check = pairing::handshake(
            &mut frames,
            helper_path,
            &local,
            master_password,
            &format!("{}-master", invitation.session),
            &invitation.vault,
            false,
            Some(&result.peer),
        )
        .map_err(|error| match error {
            PairingError::Io(_) | PairingError::Wire(_) => EnrollmentError::Pairing(error),
            _ => EnrollmentError::PasswordMismatch,
        })?;
        drop(password_check);
        stream.set_read_timeout(Some(CONFIRMATION_TIMEOUT))?;
        let channel = EncryptedSyncChannel::new(frames, &result.key, false)?;
        Ok(Self {
            invitation,
            channel,
            socket: stream,
            local,
            peer: result.peer.clone(),
            pairing_key: Zeroizing::new(result.key),
            confirmation: result.confirmation.clone(),
        })
    }

    pub fn confirmation(&self) -> &str {
        &self.confirmation
    }

    pub fn approve(&mut self) -> Result<(), EnrollmentError> {
        self.channel.send(b"approved")?;
        if self.channel.receive()? != b"approved" {
            return Err(EnrollmentError::ConfirmationFailed);
        }
        self.socket
            .set_read_timeout(Some(Duration::from_secs(300)))?;
        self.socket
            .set_write_timeout(Some(Duration::from_secs(300)))?;
        Ok(())
    }

    pub fn prepare(&mut self) -> Result<PreparedEnrollment, EnrollmentError> {
        let mut input = ChannelReader::new(&mut self.channel);
        PreparedEnrollment::read(
            &mut input,
            &self.pairing_key,
            &self.invitation.vault,
            &self.local,
            &self.peer,
        )
        .map_err(|error| match error {
            ImportError::Snapshot(SnapshotError::PhoneFailed(reason)) => {
                EnrollmentError::PhoneFailed(reason)
            }
            ImportError::Snapshot(SnapshotError::PhoneSentNothing) => {
                EnrollmentError::PhoneSentNothing
            }
            other => EnrollmentError::Import(other),
        })
    }

    pub fn commit(
        &mut self,
        prepared: PreparedEnrollment,
        vault: &mut UnlockedVault,
        identity_store: &DeviceIdentityStore,
    ) -> Result<bool, EnrollmentError> {
        self.channel.send(b"ready")?;
        if self.channel.receive()? != b"commit" {
            return Err(EnrollmentError::CommitFailed);
        }
        prepared.commit_preserving_local(vault.connection(), identity_store)?;
        let address = SocketAddr::new(self.socket.peer_addr()?.ip(), crate::lan_sync::sync_port(&self.invitation.vault));
        crate::lan_sync::remember_peer_endpoint(vault, &self.invitation.vault, &self.peer.device_id, address)?;
        Ok(self.channel.send(b"committed").is_ok())
    }
}

fn read_reverse_vault<R: Read, W: io::Write>(
    frames: &mut SyncFrames<R, W>,
) -> Result<String, EnrollmentError> {
    let vault =
        String::from_utf8(frames.receive(128)?).map_err(|_| EnrollmentError::InvalidInvitation)?;
    if vault.is_empty()
        || vault.len() > 128
        || !vault
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(EnrollmentError::InvalidInvitation);
    }
    Ok(vault)
}

struct ChannelReader<'a, R, W> {
    channel: &'a mut EncryptedSyncChannel<R, W>,
    buffer: Zeroizing<Vec<u8>>,
    position: usize,
    total: usize,
    ended: bool,
}

impl<'a, R: Read, W: io::Write> ChannelReader<'a, R, W> {
    fn new(channel: &'a mut EncryptedSyncChannel<R, W>) -> Self {
        Self {
            channel,
            buffer: Zeroizing::new(Vec::new()),
            position: 0,
            total: 0,
            ended: false,
        }
    }
}

impl<R: Read, W: io::Write> Read for ChannelReader<'_, R, W> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.ended {
            return Ok(0);
        }
        if self.position == self.buffer.len() {
            self.buffer.zeroize();
            self.buffer = Zeroizing::new(self.channel.receive().map_err(io::Error::other)?);
            self.position = 0;
            self.total = self
                .total
                .checked_add(self.buffer.len())
                .ok_or_else(|| io::Error::other("vault copy is too large"))?;
            if self.total > MAX_SNAPSHOT_BYTES {
                return Err(io::Error::other("vault copy is too large"));
            }
            if self.buffer.is_empty() {
                self.ended = true;
                return Ok(0);
            }
        }
        let count = output.len().min(self.buffer.len() - self.position);
        output[..count].copy_from_slice(&self.buffer[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("Pairing was canceled.")]
    Canceled,
    #[error("The Windows QR expired. Create a new one.")]
    OfferExpired,
    #[error("Windows needs a private local IPv4 address to show a pairing QR.")]
    NoLocalAddress,
    #[error("Could not create a pairing secret.")]
    NoRandomness,
    #[error("The setup link is invalid or expired. Create a new QR on the phone.")]
    InvalidInvitation,
    #[error("Enter the Android vault's master password.")]
    InvalidPassword,
    #[error("The master passwords do not match.")]
    PasswordMismatch,
    #[error("The other device did not approve the matching code.")]
    ConfirmationFailed,
    #[error("The phone did not finish enrollment.")]
    CommitFailed,
    #[error("Could not reach the phone on this Wi-Fi network: {0}")]
    Io(#[from] io::Error),
    #[error(
        "The phone at {0} did not answer within 10 seconds. Keep its QR open and check that this PC and phone can reach each other on the same local network; guest Wi-Fi may block connections."
    )]
    ConnectionTimedOut(SocketAddr),
    #[error(
        "Could not connect to the phone at {0}: {1}. Keep its QR open and try a new invitation."
    )]
    ConnectionFailed(SocketAddr, io::Error),
    #[error("Secure pairing failed: {0}")]
    Pairing(#[from] PairingError),
    #[error("Encrypted transfer failed: {0}")]
    Wire(#[from] WireError),
    #[error("Vault copy could not be imported: {0}")]
    Import(#[from] ImportError),
    #[error("The phone could not send the vault copy: {0}")]
    PhoneFailed(String),
    #[error(
        "The phone stopped before sending the vault copy. Check the message on the phone, keep it unlocked, and pair again with a new QR."
    )]
    PhoneSentNothing,
    #[error("Could not save the paired device address: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("Device identity is unavailable: {0}")]
    Identity(#[from] IdentityError),
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;
    use serde_json::json;

    #[test]
    fn reverse_offer_accepts_phone_dial_and_bounded_vault_preface() {
        let offer = ReverseOffer::bind_at(IpAddr::V4(Ipv4Addr::LOCALHOST), &[IpAddr::V4(Ipv4Addr::LOCALHOST)]).unwrap();
        let encoded = offer.link().strip_prefix(REVERSE_PREFIX).unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        assert_eq!(body["addresses"], serde_json::json!(["127.0.0.1"]));
        assert_eq!(body["port"], offer.listener.local_addr().unwrap().port());
        assert_eq!(body["code"].as_str().unwrap().len(), 24);
        assert!(
            body["code"]
                .as_str()
                .unwrap()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        );

        let client = TcpStream::connect(offer.listener.local_addr().unwrap()).unwrap();
        let server = offer.accept(|| false).unwrap();
        let mut sender = SyncFrames::new(client.try_clone().unwrap(), client);
        sender.send(b"vault-123", 128).unwrap();
        let mut receiver = SyncFrames::new(server.try_clone().unwrap(), server);
        assert_eq!(read_reverse_vault(&mut receiver).unwrap(), "vault-123");
        sender.send(b"vault/invalid", 128).unwrap();
        assert!(matches!(
            read_reverse_vault(&mut receiver),
            Err(EnrollmentError::InvalidInvitation)
        ));
    }

    #[test]
    fn accepts_android_invitation_and_rejects_non_local_addresses() {
        let encode = |address: &str| {
            format!(
                "{PREFIX}{}",
                URL_SAFE_NO_PAD.encode(
                    json!({"address":address,"port":41234,"session":"session-a",
                        "vault":"vault-a","code":"123456789012345678901234"})
                    .to_string()
                )
            )
        };
        assert_eq!(
            PairingInvitation::parse(&encode("192.168.1.4"))
                .unwrap()
                .address(),
            "192.168.1.4:41234".parse().unwrap()
        );
        assert!(PairingInvitation::parse(&encode("127.0.0.1")).is_err());
        assert!(PairingInvitation::parse(&encode("8.8.8.8")).is_err());
        assert!(PairingInvitation::parse(&encode("fe80::1")).is_err());
        assert!(PairingInvitation::parse("nuvori-pair://v3/invalid").is_err());
    }

    #[test]
    fn snapshot_reader_stops_at_end_frame_without_consuming_commit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            let frames = SyncFrames::new(socket.try_clone().unwrap(), socket);
            let mut channel = EncryptedSyncChannel::new(frames, &[7; 32], true).unwrap();
            channel.send(b"vault copy").unwrap();
            channel.send(b"").unwrap();
            channel.send(b"commit").unwrap();
        });
        let (socket, _) = listener.accept().unwrap();
        let frames = SyncFrames::new(socket.try_clone().unwrap(), socket);
        let mut channel = EncryptedSyncChannel::new(frames, &[7; 32], false).unwrap();
        let mut body = Vec::new();
        ChannelReader::new(&mut channel)
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, b"vault copy");
        assert_eq!(channel.receive().unwrap(), b"commit");
        sender.join().unwrap();
    }
}
