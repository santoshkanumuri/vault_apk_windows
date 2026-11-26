//! M12 and M11: two small additions to the Wi-Fi exchange, shared with Android (`SyncRefusal.kt`,
//! `PhotoSyncBlobs.kt`). The rules and vectors are in the Android repository's
//! `scripts/sync-vectors/sync_refusal.py`; `fixtures/sync-session-v1.json` here is the same file
//! byte for byte.
//!
//! Refusal (`sync-refusal-v1`): after both devices proved who they are, the one that refuses what
//! the other sent says so in one encrypted frame before the session ends. The sender then shows it
//! on that device and stops retrying at once, instead of reading a closed connection and retrying it
//! as a Wi-Fi problem. The frame is [MAGIC] and a code, nothing else: no error text and no data from
//! the session. It goes only to a peer that announced [FEATURE] (an older build would read it as a
//! bad frame), only inside the authenticated channel after both identity proofs, and never in answer
//! to a refusal. The receiver shows its own words for every code, never words from the peer.
//!
//! Photo receipts (`photo-receipts-v1`), used when both devices announced it: the device receiving
//! a photo confirms after every [RECEIPT_EVERY] chunks how many of the photo's bytes it holds, and
//! the sending device waits for that receipt. A device that left the network mid-photo then shows
//! as a read timeout within seconds, and the sender is never more than about 1 MB ahead.

pub const FEATURE: &str = "sync-refusal-v1";
pub const PHOTO_RECEIPTS_FEATURE: &str = "photo-receipts-v1";

/// A change failed verification: its signature, its chain, its sender or the reported history.
pub const CHANGE: &str = "change";
/// A frame this build can't read, or that breaks the exchange's rules.
pub const PROTOCOL: &str = "protocol";
const CODES: [&str; 2] = [CHANGE, PROTOCOL];

/// Starts with a NUL byte and is longer than any code, so no JSON, number or hash frame matches.
const MAGIC: &[u8] = b"\x00nuvori-sync-refused-v1:";
const MAX_CODE: usize = 16;

/// Chunks of one photo between two receipts.
pub const RECEIPT_EVERY: u64 = 16;

pub fn encode(code: &str) -> Vec<u8> {
    debug_assert!(CODES.contains(&code));
    let code = if CODES.contains(&code) { code } else { PROTOCOL };
    [MAGIC, code.as_bytes()].concat()
}

/// The code of a refusal frame (an unknown code reads as [PROTOCOL]), or `None` for any other frame.
pub fn decode(frame: &[u8]) -> Option<&'static str> {
    if frame.len() <= MAGIC.len() || frame.len() > MAGIC.len() + MAX_CODE || !frame.starts_with(MAGIC) {
        return None;
    }
    let code = &frame[MAGIC.len()..];
    Some(CODES.into_iter().find(|known| known.as_bytes() == code).unwrap_or(PROTOCOL))
}

/// True after the `chunks`th chunk of a photo when a receipt follows it.
pub fn receipt_due(chunks: u64) -> bool {
    chunks > 0 && chunks % RECEIPT_EVERY == 0
}

/// The receipt for `held` bytes of the photo (the request's offset and the bytes received since).
pub fn receipt(held: u64) -> Vec<u8> {
    held.to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../fixtures/sync-session-v1.json")).unwrap()
    }

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2).map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap()).collect()
    }

    #[test]
    fn refusal_frames_match_the_shared_vectors() {
        let vectors = vectors();
        assert_eq!(vectors["rules"], serde_json::json!([FEATURE, PHOTO_RECEIPTS_FEATURE]));
        assert!(crate::protocol::SYNC_FEATURES.contains(&FEATURE));
        assert!(crate::protocol::SYNC_FEATURES.contains(&PHOTO_RECEIPTS_FEATURE));
        for frame in vectors["refusalFrames"].as_array().unwrap() {
            assert_eq!(encode(frame["code"].as_str().unwrap()), bytes(frame["hex"].as_str().unwrap()));
        }
        for case in vectors["refusalDecoding"].as_array().unwrap() {
            assert_eq!(decode(&bytes(case["hex"].as_str().unwrap())), case["code"].as_str(), "{case}");
        }
    }

    #[test]
    fn photo_receipts_follow_the_shared_schedule() {
        let vectors = vectors();
        assert_eq!(vectors["receiptEvery"].as_u64(), Some(RECEIPT_EVERY));
        for case in vectors["photoReceipts"].as_array().unwrap() {
            let mut held = case["offset"].as_u64().unwrap();
            let mut receipts = Vec::new();
            for (index, size) in case["chunks"].as_array().unwrap().iter().enumerate() {
                held += size.as_u64().unwrap();
                let chunk = index as u64 + 1;
                if receipt_due(chunk) {
                    receipts.push(serde_json::json!({"afterChunk": chunk, "frame": String::from_utf8(receipt(held)).unwrap()}));
                }
            }
            assert_eq!(Value::Array(receipts), case["receipts"]);
        }
    }
}
