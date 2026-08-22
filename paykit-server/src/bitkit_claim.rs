//! Server-owned Bitkit companion-claim protocol validation.
//!
//! This deliberately owns only Bitkit's application payload and the companion
//! relay envelope specified in `paykit-rs/specs/pubky-auth-companion-claims.md`.
//! Normal Pubky AUTH remains owned by `paykit-sdk`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crypto_secretbox::{
    XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use paykit_lib::PaykitReceiverPath;
use paykit_sdk::PaykitSdkConfig;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const QUERY_PARAMETER: &str = "x-bitkit-claim";
pub const CLAIM_TYPE: &str = "watch-only-account-v1";
pub const LOCAL_DEMO_CAPABILITIES: &str =
    "/pub/paykit/v0/bitkit/server/:rw,/pub/paykit/v0/private/bitkit/server/:rw";
pub const UNSIGNED_PAYLOAD_LEN: usize = 84;
const SIGNED_PAYLOAD_LEN: usize = UNSIGNED_PAYLOAD_LEN + 64;
const NONCE_LEN: usize = 24;

#[derive(Clone, PartialEq, Eq)]
pub struct AuthRequest {
    relay: Url,
    secret: [u8; 32],
}

impl core::fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequest")
            .field("relay", &self.relay)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl AuthRequest {
    pub fn relay(&self) -> &Url {
        &self.relay
    }
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchOnlyAccountClaim {
    pub account_index: u32,
    /// Exact serialized 78-byte BIP account xpub. It is kept binary until the
    /// configured Bitcoin-network validator turns it into a persisted form.
    pub serialized_xpub: [u8; 78],
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ClaimError {
    #[error("invalid companion auth request")]
    InvalidAuthRequest,
    #[error("invalid companion payload")]
    InvalidPayload,
    #[error("invalid companion envelope")]
    InvalidEnvelope,
    #[error("companion authentication failed")]
    AuthenticationFailed,
    /// A re-claim presented a different account xpub or index than the one
    /// already persisted for this creator. The stored watch-only account is
    /// immutable (existing invoices watch addresses derived from it), so the
    /// claim is refused instead of replaced.
    #[error("claimed account does not match the persisted account")]
    AccountMismatch,
}

pub fn required_capabilities(receiver_path: &PaykitReceiverPath) -> String {
    PaykitSdkConfig::new(receiver_path.clone()).required_session_capabilities()
}

/// Validates the exact request binding required before a relay body is read.
pub fn parse_auth_request(
    value: &str,
    expected_capabilities: &str,
) -> Result<AuthRequest, ClaimError> {
    let url = Url::parse(value).map_err(|_| ClaimError::InvalidAuthRequest)?;
    if url.scheme() != "pubkyauth" || !matches!(url.host_str(), Some("signin") | Some("signup")) {
        return Err(ClaimError::InvalidAuthRequest);
    }
    let claim_type = unique_query(&url, QUERY_PARAMETER)?;
    if claim_type != CLAIM_TYPE || unique_query(&url, "caps")? != expected_capabilities {
        return Err(ClaimError::InvalidAuthRequest);
    }
    let secret_text = unique_query(&url, "secret")?;
    let secret: [u8; 32] = URL_SAFE_NO_PAD
        .decode(secret_text)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(ClaimError::InvalidAuthRequest)?;
    let relay =
        Url::parse(&unique_query(&url, "relay")?).map_err(|_| ClaimError::InvalidAuthRequest)?;
    if !matches!(relay.scheme(), "http" | "https")
        || relay.host_str().is_none()
        || relay.cannot_be_a_base()
    {
        return Err(ClaimError::InvalidAuthRequest);
    }
    Ok(AuthRequest { relay, secret })
}

fn unique_query(url: &Url, name: &str) -> Result<String, ClaimError> {
    let mut found = None;
    for (key, value) in url.query_pairs() {
        if key == name && found.replace(value.into_owned()).is_some() {
            return Err(ClaimError::InvalidAuthRequest);
        }
    }
    found
        .filter(|v| !v.is_empty())
        .ok_or(ClaimError::InvalidAuthRequest)
}

pub fn derive_channel_id(secret: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CLAIM_TYPE.as_bytes());
    hasher.update(b"|");
    hasher.update(secret);
    URL_SAFE_NO_PAD.encode(hasher.finalize().as_bytes())
}

/// Encodes the canonical version-1 BIP84 watch-only account payload.
pub fn encode_unsigned_payload(
    account_index: u32,
    serialized_xpub: &[u8; 78],
) -> [u8; UNSIGNED_PAYLOAD_LEN] {
    let mut payload = [0; UNSIGNED_PAYLOAD_LEN];
    payload[0] = 1;
    payload[1..5].copy_from_slice(&account_index.to_be_bytes());
    payload[5] = 0;
    payload[6..].copy_from_slice(serialized_xpub);
    payload
}

pub fn parse_unsigned_payload(value: &[u8]) -> Result<WatchOnlyAccountClaim, ClaimError> {
    if value.len() != UNSIGNED_PAYLOAD_LEN || value[0] != 1 || value[5] != 0 {
        return Err(ClaimError::InvalidPayload);
    }
    let account_index = u32::from_be_bytes(value[1..5].try_into().expect("checked length"));
    let serialized_xpub = value[6..].try_into().expect("checked length");
    Ok(WatchOnlyAccountClaim {
        account_index,
        serialized_xpub,
    })
}

/// Decrypts and verifies the complete Bitkit relay body before callers can
/// invoke a durable repository or marker transport.
pub fn decrypt_and_verify(
    relay_body: &[u8],
    secret: &[u8; 32],
    creator: &VerifyingKey,
) -> Result<WatchOnlyAccountClaim, ClaimError> {
    if relay_body.len() < NONCE_LEN + 16 {
        return Err(ClaimError::InvalidEnvelope);
    }
    let cipher = XSalsa20Poly1305::new(secret.into());
    let plaintext = cipher
        .decrypt((&relay_body[..NONCE_LEN]).into(), &relay_body[NONCE_LEN..])
        .map_err(|_| ClaimError::AuthenticationFailed)?;
    if plaintext.len() != SIGNED_PAYLOAD_LEN {
        return Err(ClaimError::InvalidEnvelope);
    }
    let claim = parse_unsigned_payload(&plaintext[..UNSIGNED_PAYLOAD_LEN])?;
    let signature = Signature::from_slice(&plaintext[UNSIGNED_PAYLOAD_LEN..])
        .map_err(|_| ClaimError::InvalidEnvelope)?;
    let mut signable = Vec::with_capacity(
        QUERY_PARAMETER.len() + CLAIM_TYPE.len() + 2 + 32 + UNSIGNED_PAYLOAD_LEN,
    );
    signable.extend_from_slice(format!("{QUERY_PARAMETER}|{CLAIM_TYPE}|").as_bytes());
    signable.extend_from_slice(&Sha256::digest(secret));
    signable.extend_from_slice(&plaintext[..UNSIGNED_PAYLOAD_LEN]);
    creator
        .verify(&signable, &signature)
        .map_err(|_| ClaimError::AuthenticationFailed)?;
    Ok(claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_secretbox::aead::Aead;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn companion_capabilities_follow_configured_server_receiver_path() {
        let local_receiver_path = PaykitReceiverPath::new("bitkit/server").unwrap();
        assert_eq!(
            LOCAL_DEMO_CAPABILITIES,
            PaykitSdkConfig::new(local_receiver_path).required_session_capabilities()
        );
        for path in ["bitkit/server", "merchant/server"] {
            let receiver_path = PaykitReceiverPath::new(path).unwrap();
            assert_eq!(
                required_capabilities(&receiver_path),
                PaykitSdkConfig::new(receiver_path).required_session_capabilities()
            );
        }
    }

    fn auth(secret: &[u8; 32]) -> String {
        format!(
            "pubkyauth://signin?caps={LOCAL_DEMO_CAPABILITIES}&relay=https%3A%2F%2Frelay.example%2Finbox&secret={}&{QUERY_PARAMETER}={CLAIM_TYPE}",
            URL_SAFE_NO_PAD.encode(secret)
        )
    }
    fn unsigned() -> [u8; UNSIGNED_PAYLOAD_LEN] {
        let mut v = [0; UNSIGNED_PAYLOAD_LEN];
        v[0] = 1;
        v[1..5].copy_from_slice(&7u32.to_be_bytes());
        v[5] = 0;
        v[6..].copy_from_slice(&[9; 78]);
        v
    }
    fn envelope(secret: &[u8; 32], key: &SigningKey) -> Vec<u8> {
        let payload = unsigned();
        let mut input = format!("{QUERY_PARAMETER}|{CLAIM_TYPE}|").into_bytes();
        input.extend_from_slice(&Sha256::digest(secret));
        input.extend_from_slice(&payload);
        let mut plain = payload.to_vec();
        plain.extend_from_slice(&key.sign(&input).to_bytes());
        let nonce = [3; 24];
        let ciphertext = XSalsa20Poly1305::new(secret.into())
            .encrypt((&nonce).into(), plain.as_slice())
            .unwrap();
        [nonce.to_vec(), ciphertext].concat()
    }

    #[test]
    fn parses_exact_url_and_derives_spec_channel() {
        let secret = [7; 32];
        assert_eq!(
            parse_auth_request(&auth(&secret), LOCAL_DEMO_CAPABILITIES)
                .unwrap()
                .secret(),
            &secret
        );
        assert_eq!(
            derive_channel_id(&secret),
            URL_SAFE_NO_PAD
                .encode(blake3::hash(&[CLAIM_TYPE.as_bytes(), b"|", &secret].concat()).as_bytes())
        );
    }
    #[test]
    fn rejects_missing_duplicate_or_mismatched_request_values() {
        let secret = [7; 32];
        for changed in [
            auth(&secret).replace("caps=", "caps=/:rw&caps="),
            auth(&secret).replace(CLAIM_TYPE, "wrong"),
            auth(&secret).replace("secret=", "secret=&secret="),
        ] {
            assert_eq!(
                parse_auth_request(&changed, LOCAL_DEMO_CAPABILITIES),
                Err(ClaimError::InvalidAuthRequest)
            );
        }
    }
    #[test]
    fn verifies_equivalent_crypto_envelope_and_exact_payload() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let secret = [7; 32];
        let claim =
            decrypt_and_verify(&envelope(&secret, &key), &secret, &key.verifying_key()).unwrap();
        assert_eq!(claim.account_index, 7);
        assert_eq!(claim.serialized_xpub, [9; 78]);
    }
    #[test]
    fn rejects_malformed_and_signature_mismatch() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let secret = [7; 32];
        assert_eq!(
            decrypt_and_verify(&[0; 24], &secret, &key.verifying_key()),
            Err(ClaimError::InvalidEnvelope)
        );
        let wrong = SigningKey::from_bytes(&[6; 32]);
        assert_eq!(
            decrypt_and_verify(&envelope(&secret, &key), &secret, &wrong.verifying_key()),
            Err(ClaimError::AuthenticationFailed)
        );
        let mut payload = unsigned();
        payload[0] = 2;
        assert_eq!(
            parse_unsigned_payload(&payload),
            Err(ClaimError::InvalidPayload)
        );
    }
}
