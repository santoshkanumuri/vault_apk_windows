//! Time-based one-time codes (RFC 6238) for browser filling. The setup key never leaves the app;
//! only the current code does.

use hmac::{Hmac, Mac};
use zeroize::Zeroize;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The code for `unix_seconds` and the seconds it stays valid, or `None` for a bad setup key or
/// settings outside what the app allows (6 to 8 digits, 1 to 300 second periods).
pub fn code_at(secret: &str, algorithm: &str, digits: u32, period: u64, unix_seconds: u64) -> Option<(String, u64)> {
    if !(6..=8).contains(&digits) || !(1..=300).contains(&period) {
        return None;
    }
    let mut key = decode_base32(secret)?;
    let counter = (unix_seconds / period).to_be_bytes();
    macro_rules! mac {
        ($hash:ty) => {
            <Hmac<$hash> as Mac>::new_from_slice(&key).ok().map(|mut mac| {
                mac.update(&counter);
                mac.finalize().into_bytes().to_vec()
            })
        };
    }
    let digest = match algorithm.to_ascii_uppercase().as_str() {
        "" | "SHA1" => mac!(sha1::Sha1),
        "SHA256" => mac!(sha2::Sha256),
        "SHA512" => mac!(sha2::Sha512),
        _ => None,
    };
    key.zeroize();
    let mut digest = digest?;
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
    digest.zeroize();
    let value = binary % 10u32.pow(digits);
    Some((format!("{value:0width$}", width = digits as usize), period - unix_seconds % period))
}

/// RFC 4648 base32 without padding; spaces, dashes and `=` are ignored, case-insensitive.
fn decode_base32(secret: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut buffer = 0u32;
    let mut bytes = Vec::new();
    for char in secret.bytes().filter(|byte| !matches!(byte, b' ' | b'-' | b'=')) {
        let digit = ALPHABET.iter().position(|letter| *letter == char.to_ascii_uppercase())? as u32;
        buffer = ((buffer << 5) | digit) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    (!bytes.is_empty()).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B keys, base32-encoded.
    const SHA1_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"
    const SHA256_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SHA512_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    #[test]
    fn matches_rfc_6238_vectors() {
        assert_eq!(code_at(SHA1_KEY, "SHA1", 8, 30, 59).unwrap().0, "94287082");
        assert_eq!(code_at(SHA256_KEY, "SHA256", 8, 30, 59).unwrap().0, "46119246");
        assert_eq!(code_at(SHA512_KEY, "SHA512", 8, 30, 59).unwrap().0, "90693936");
        assert_eq!(code_at(SHA1_KEY, "sha1", 8, 30, 1_111_111_109).unwrap().0, "07081804");
        assert_eq!(code_at(SHA1_KEY, "SHA1", 6, 30, 59).unwrap(), ("287082".to_owned(), 1));
    }

    #[test]
    fn rejects_bad_keys_and_settings() {
        assert!(code_at("not base32!", "SHA1", 6, 30, 0).is_none());
        assert!(code_at("", "SHA1", 6, 30, 0).is_none());
        assert!(code_at(SHA1_KEY, "MD5", 6, 30, 0).is_none());
        assert!(code_at(SHA1_KEY, "SHA1", 5, 30, 0).is_none());
        assert!(code_at(SHA1_KEY, "SHA1", 6, 0, 0).is_none());
        assert_eq!(code_at("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq", "SHA1", 8, 30, 59).unwrap().0, "94287082");
    }
}
