use std::io::{Read, Write};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_FRAME: usize = 2 * 1024 * 1024;
pub const HANDSHAKE_FRAME: usize = 16 * 1024;
const FRAME_AAD: &[u8] = b"nuvori-sync-frame-v1";

pub struct SyncFrames<R, W> {
    input: R,
    output: W,
}

impl<R: Read, W: Write> SyncFrames<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self { input, output }
    }

    pub fn send(&mut self, bytes: &[u8], maximum: usize) -> Result<(), WireError> {
        if bytes.is_empty() || bytes.len() > maximum || bytes.len() > MAX_FRAME {
            return Err(WireError::InvalidFrameSize);
        }
        self.output.write_all(&(bytes.len() as u32).to_be_bytes())?;
        self.output.write_all(bytes)?;
        self.output.flush()?;
        Ok(())
    }

    pub fn receive(&mut self, maximum: usize) -> Result<Vec<u8>, WireError> {
        let mut length = [0; 4];
        self.input.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > maximum || length > MAX_FRAME {
            return Err(WireError::InvalidFrameSize);
        }
        let mut bytes = vec![0; length];
        self.input.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    pub fn into_inner(self) -> (R, W) {
        (self.input, self.output)
    }
}

pub struct EncryptedSyncChannel<R, W> {
    frames: SyncFrames<R, W>,
    send_key: [u8; 32],
    receive_key: [u8; 32],
    send_sequence: u64,
    receive_sequence: u64,
}

impl<R: Read, W: Write> EncryptedSyncChannel<R, W> {
    pub fn new(
        frames: SyncFrames<R, W>,
        session_key: &[u8],
        creator: bool,
    ) -> Result<Self, WireError> {
        if session_key.len() != 32 {
            return Err(WireError::InvalidSessionKey);
        }
        let send_label: &[u8] = if creator {
            b"creator-send"
        } else {
            b"joiner-send"
        };
        let receive_label: &[u8] = if creator {
            b"joiner-send"
        } else {
            b"creator-send"
        };
        Ok(Self {
            frames,
            send_key: derive(session_key, send_label),
            receive_key: derive(session_key, receive_label),
            send_sequence: 0,
            receive_sequence: 0,
        })
    }

    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), WireError> {
        if plaintext.len() > MAX_FRAME - 16 {
            return Err(WireError::InvalidFrameSize);
        }
        let nonce = nonce(self.send_sequence)?;
        let cipher = Aes256Gcm::new_from_slice(&self.send_key).expect("32-byte key");
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: FRAME_AAD,
                },
            )
            .map_err(|_| WireError::AuthenticationFailed)?;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(WireError::SequenceExhausted)?;
        self.frames.send(&ciphertext, MAX_FRAME)?;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Vec<u8>, WireError> {
        let ciphertext = self.frames.receive(MAX_FRAME)?;
        let nonce = nonce(self.receive_sequence)?;
        let cipher = Aes256Gcm::new_from_slice(&self.receive_key).expect("32-byte key");
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or(WireError::SequenceExhausted)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: FRAME_AAD,
                },
            )
            .map_err(|_| WireError::AuthenticationFailed)?;
        Ok(plaintext)
    }
}

impl<R, W> Drop for EncryptedSyncChannel<R, W> {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.receive_key.zeroize();
    }
}

fn derive(session_key: &[u8], label: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key).expect("32-byte key");
    mac.update(b"nuvori-sync-channel-v1:");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

fn nonce(sequence: u64) -> Result<[u8; 12], WireError> {
    if sequence == i64::MAX as u64 {
        return Err(WireError::SequenceExhausted);
    }
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&1_u32.to_be_bytes());
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    Ok(bytes)
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("sync I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid sync frame size")]
    InvalidFrameSize,
    #[error("session key must be 32 bytes")]
    InvalidSessionKey,
    #[error("sync frame authentication failed")]
    AuthenticationFailed,
    #[error("sync frame sequence exhausted")]
    SequenceExhausted,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn creator_frame_matches_android_channel_format() {
        let key: Vec<u8> = (0..32).collect();
        let mut output = Vec::new();
        {
            let frames = SyncFrames::new(Cursor::new(Vec::new()), &mut output);
            let mut channel = EncryptedSyncChannel::new(frames, &key, true).unwrap();
            channel.send(b"windows-android-sync").unwrap();
        }
        assert_eq!(
            hex::encode(&output[4..]),
            "c6bf8d52186446c6a0760af477e17f3612ffb6790074337508693195cc8a3233e63802a7"
        );
        let mut joiner = EncryptedSyncChannel::new(
            SyncFrames::new(Cursor::new(output), Vec::new()),
            &key,
            false,
        )
        .unwrap();
        assert_eq!(joiner.receive().unwrap(), b"windows-android-sync");
    }

    #[test]
    fn replay_and_wrong_direction_fail_authentication() {
        let key = [1; 32];
        let mut frame = Vec::new();
        {
            let mut creator = EncryptedSyncChannel::new(
                SyncFrames::new(Cursor::new(Vec::new()), &mut frame),
                &key,
                true,
            )
            .unwrap();
            creator.send(b"message").unwrap();
        }
        let mut repeated = frame.clone();
        repeated.extend_from_slice(&frame);
        let mut joiner = EncryptedSyncChannel::new(
            SyncFrames::new(Cursor::new(repeated), Vec::new()),
            &key,
            false,
        )
        .unwrap();
        assert_eq!(joiner.receive().unwrap(), b"message");
        assert!(matches!(
            joiner.receive(),
            Err(WireError::AuthenticationFailed)
        ));
        let mut wrong_direction =
            EncryptedSyncChannel::new(SyncFrames::new(Cursor::new(frame), Vec::new()), &key, true)
                .unwrap();
        assert!(matches!(
            wrong_direction.receive(),
            Err(WireError::AuthenticationFailed)
        ));
    }

    #[test]
    fn rejects_oversized_frame_before_reading_payload() {
        let length = (MAX_FRAME as u32 + 1).to_be_bytes();
        let mut frames = SyncFrames::new(Cursor::new(length), Vec::new());
        assert!(matches!(
            frames.receive(MAX_FRAME),
            Err(WireError::InvalidFrameSize)
        ));
    }
}
