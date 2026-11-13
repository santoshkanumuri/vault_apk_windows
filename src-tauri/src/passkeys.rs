use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    PublicKey, SecretKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::browser;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPasskey {
    pub id: String,
    pub rp_id: String,
    pub user_handle: String,
    pub username: String,
    pub display_name: String,
    pub private_key: String,
    pub public_key: String,
    pub created_at: i64,
}

impl VaultPasskey {
    pub fn validate(&self) -> Result<(), PasskeyError> {
        let id = decode(&self.id)?;
        let user_handle = decode(&self.user_handle)?;
        let rp_origin = format!("https://{}", self.rp_id);
        if !(1..=1023).contains(&id.len())
            || !(1..=64).contains(&user_handle.len())
            || self.username.is_empty()
            || self.username.len() > 1024
            || self.display_name.len() > 1024
            || self.created_at < 0
            || self.rp_id.is_empty()
            || self.rp_id.contains(['/', ':', '@'])
            || browser::canonical_https_origin(&rp_origin).as_deref() != Some(rp_origin.as_str())
            || (self.rp_id != "localhost" && psl::domain(self.rp_id.as_bytes()).is_none())
            || self.rp_id.parse::<std::net::IpAddr>().is_ok()
        {
            return Err(PasskeyError::InvalidRecord);
        }
        let private = Zeroizing::new(decode(&self.private_key)?);
        let public = decode(&self.public_key)?;
        let secret =
            SecretKey::from_pkcs8_der(&private).map_err(|_| PasskeyError::InvalidRecord)?;
        let expected =
            PublicKey::from_public_key_der(&public).map_err(|_| PasskeyError::InvalidRecord)?;
        if secret.public_key() != expected {
            return Err(PasskeyError::InvalidRecord);
        }
        Ok(())
    }

    pub fn sign_assertion(
        &self,
        origin: &str,
        client_data_json: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {
        self.validate()?;
        if client_data_json.is_empty()
            || client_data_json.len() > 65_536
            || browser::canonical_https_origin(origin).as_deref() != Some(origin)
        {
            return Err(PasskeyError::InvalidRequest);
        }
        if !browser::rp_id_matches_origin(&self.rp_id, origin) {
            return Err(PasskeyError::InvalidRequest);
        }
        let client: serde_json::Value =
            serde_json::from_slice(client_data_json).map_err(|_| PasskeyError::InvalidRequest)?;
        let challenge = client["challenge"]
            .as_str()
            .ok_or(PasskeyError::InvalidRequest)?;
        let challenge_bytes = decode(challenge).map_err(|_| PasskeyError::InvalidRequest)?;
        if client["type"] != "webauthn.get"
            || client["origin"] != origin
            || client["crossOrigin"] != false
            || !(16..=1024).contains(&challenge_bytes.len())
        {
            return Err(PasskeyError::InvalidRequest);
        }
        let mut authenticator_data = Vec::with_capacity(37);
        authenticator_data.extend_from_slice(&Sha256::digest(self.rp_id.as_bytes()));
        authenticator_data.extend_from_slice(&[0x0d, 0, 0, 0, 0]);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data_json));
        let private = Zeroizing::new(decode(&self.private_key)?);
        let secret =
            SecretKey::from_pkcs8_der(&private).map_err(|_| PasskeyError::InvalidRecord)?;
        use p256::ecdsa::signature::Signer;
        let signing_key = p256::ecdsa::SigningKey::from(secret);
        let signature: p256::ecdsa::Signature = signing_key.sign(&signed);
        Ok((authenticator_data, signature.to_der().as_bytes().to_vec()))
    }
}

impl VaultPasskey {
    /// Signs for the Windows passkey prompt. Windows and the browser already checked the site
    /// against the RP ID and hashed the client data; Windows Hello verified the user just before.
    /// Returns the authenticator data and the DER signature over it and `client_data_hash`.
    pub fn sign_platform_assertion(
        &self,
        rp_id: &[u8],
        client_data_hash: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {
        self.validate()?;
        if rp_id != self.rp_id.as_bytes() || client_data_hash.len() != 32 {
            return Err(PasskeyError::InvalidRequest);
        }
        let mut authenticator_data = Vec::with_capacity(37);
        authenticator_data.extend_from_slice(&Sha256::digest(rp_id));
        // The flags the phone signs with (user present, user verified, backup eligible); count 0.
        authenticator_data.extend_from_slice(&[0x0d, 0, 0, 0, 0]);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(client_data_hash);
        let private = Zeroizing::new(decode(&self.private_key)?);
        let secret =
            SecretKey::from_pkcs8_der(&private).map_err(|_| PasskeyError::InvalidRecord)?;
        use p256::ecdsa::signature::Signer;
        let signing_key = p256::ecdsa::SigningKey::from(secret);
        let signature: p256::ecdsa::Signature = signing_key.sign(&signed);
        Ok((authenticator_data, signature.to_der().as_bytes().to_vec()))
    }
}

fn decode(value: &str) -> Result<Vec<u8>, PasskeyError> {
    if value.is_empty()
        || value.len() > 8192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(PasskeyError::InvalidRecord);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PasskeyError::InvalidRecord)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(PasskeyError::InvalidRecord);
    }
    Ok(bytes)
}

#[derive(Debug, Error)]
pub enum PasskeyError {
    #[error("stored passkey is invalid")]
    InvalidRecord,
    #[error("passkey request is invalid")]
    InvalidRequest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

    fn key(seed: u8) -> VaultPasskey {
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        VaultPasskey {
            id: URL_SAFE_NO_PAD.encode([7; 32]),
            rp_id: "example.com".to_owned(),
            user_handle: URL_SAFE_NO_PAD.encode([3; 16]),
            username: "alice".to_owned(),
            display_name: "Alice".to_owned(),
            private_key: URL_SAFE_NO_PAD.encode(secret.to_pkcs8_der().unwrap().as_bytes()),
            public_key: URL_SAFE_NO_PAD
                .encode(secret.public_key().to_public_key_der().unwrap().as_bytes()),
            created_at: 100,
        }
    }

    #[test]
    fn validates_android_key_material_and_signs_an_assertion() {
        let key = key(1);
        key.validate().unwrap();
        let client = br#"{"type":"webauthn.get","challenge":"AAECAwQFBgcICQoLDA0ODw","origin":"https://example.com","crossOrigin":false}"#;
        let (auth, signature) = key.sign_assertion("https://example.com", client).unwrap();
        assert_eq!(&auth[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(&auth[32..], &[0x0d, 0, 0, 0, 0]);
        let mut signed = auth;
        signed.extend_from_slice(&Sha256::digest(client));
        use p256::ecdsa::signature::Verifier;
        let public =
            PublicKey::from_public_key_der(&URL_SAFE_NO_PAD.decode(&key.public_key).unwrap())
                .unwrap();
        let verifier = p256::ecdsa::VerifyingKey::from(public);
        verifier
            .verify(
                &signed,
                &p256::ecdsa::Signature::from_der(&signature).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            key.sign_assertion("https://other.example", client),
            Err(PasskeyError::InvalidRequest)
        ));
    }

    #[test]
    fn signs_for_the_windows_passkey_prompt_with_the_phone_flags() {
        let key = key(1);
        let hash = Sha256::digest(b"client data");
        let (auth, signature) = key.sign_platform_assertion(b"example.com", &hash).unwrap();
        assert_eq!(&auth[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(&auth[32..], &[0x0d, 0, 0, 0, 0]);
        let mut signed = auth;
        signed.extend_from_slice(&hash);
        use p256::ecdsa::signature::Verifier;
        let public =
            PublicKey::from_public_key_der(&URL_SAFE_NO_PAD.decode(&key.public_key).unwrap()).unwrap();
        p256::ecdsa::VerifyingKey::from(public)
            .verify(&signed, &p256::ecdsa::Signature::from_der(&signature).unwrap())
            .unwrap();
        assert!(matches!(key.sign_platform_assertion(b"other.example", &hash), Err(PasskeyError::InvalidRequest)));
        assert!(matches!(key.sign_platform_assertion(b"example.com", &hash[..31]), Err(PasskeyError::InvalidRequest)));
    }

    #[test]
    fn rejects_mismatched_key_pair_and_noncanonical_rp_id() {
        let mut record = key(1);
        record.public_key = key(2).public_key;
        assert!(matches!(
            record.validate(),
            Err(PasskeyError::InvalidRecord)
        ));
        record = key(1);
        record.rp_id = "EXAMPLE.com".to_owned();
        assert!(matches!(
            record.validate(),
            Err(PasskeyError::InvalidRecord)
        ));
    }
}
