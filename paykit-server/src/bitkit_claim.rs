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
use paykit_sdk::{PAYKIT_SESSION_CAPABILITIES, PaykitIdentitySecretKey, parse_pubky_auth_url};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

pub const QUERY_PARAMETER: &str = "x-bitkit-claim";
pub const PAYKIT_ACCESS_CLAIM: &str = "paykit-access-v1";
pub const WATCH_ONLY_ACCOUNT_CLAIM: &str = "watch-only-account-v1";
pub const LOCAL_DEMO_CAPABILITIES: &str = PAYKIT_SESSION_CAPABILITIES;
pub const UNSIGNED_PAYLOAD_LEN: usize = 124;
pub const RECONNECT_PAYLOAD_LEN: usize = 41;
const NONCE_LEN: usize = 24;

#[derive(Clone, PartialEq, Eq)]
pub struct AuthRequest {
    relay: Url,
    secret: Zeroizing<[u8; 32]>,
    claim_type: String,
}

impl core::fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequest")
            .field("relay", &self.relay)
            .field("secret", &"<redacted>")
            .field("claim_type", &self.claim_type)
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
    /// Borrows the exact validated permission list used by the SDK signature and channel.
    pub fn claim_type(&self) -> &str {
        &self.claim_type
    }
}

/// Both permissions required by server setup, decoded from one signed companion payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupCompanionClaim {
    pub account_index: u32,
    /// Exact serialized 78-byte BIP account xpub. It is kept binary until the
    /// configured Bitcoin-network validator turns it into a persisted form.
    pub serialized_xpub: [u8; 78],
    pub paykit_identity_secret_key: PaykitIdentitySecretKey,
}

/// Verified authority for an initial account binding or an explicit reconnect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedCompanionClaim {
    /// Initial setup includes a new watch-only account binding.
    Setup(SetupCompanionClaim),
    /// Reconnect replaces only Paykit authority for a server-held account binding.
    Reconnect(PaykitIdentitySecretKey),
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
}

pub fn required_capabilities() -> String {
    PAYKIT_SESSION_CAPABILITIES.to_owned()
}

/// Composes the independent permissions required by setup, in canonical request order.
pub fn setup_claim_selection() -> String {
    [PAYKIT_ACCESS_CLAIM, WATCH_ONLY_ACCOUNT_CLAIM].join(".")
}

/// Validates a setup request requiring both permissions and retains their received order.
pub fn parse_auth_request(
    value: &str,
    expected_capabilities: &str,
) -> Result<AuthRequest, ClaimError> {
    parse_request(value, expected_capabilities, false)
}

/// Validates an explicit reconnect requesting Paykit access and no account material.
pub fn parse_reconnect_auth_request(
    value: &str,
    expected_capabilities: &str,
) -> Result<AuthRequest, ClaimError> {
    parse_request(value, expected_capabilities, true)
}

fn parse_request(
    value: &str,
    expected_capabilities: &str,
    reconnect: bool,
) -> Result<AuthRequest, ClaimError> {
    let url = Url::parse(value).map_err(|_| ClaimError::InvalidAuthRequest)?;
    if url.scheme() != "pubkyauth" {
        return Err(ClaimError::InvalidAuthRequest);
    }
    let auth = parse_pubky_auth_url(value).map_err(|_| ClaimError::InvalidAuthRequest)?;
    let claim_type = unique_query(&url, QUERY_PARAMETER)?;
    if reconnect {
        if claim_type != PAYKIT_ACCESS_CLAIM {
            return Err(ClaimError::InvalidAuthRequest);
        }
    } else {
        validate_setup_claim_selection(&claim_type)?;
    }
    if unique_query(&url, "caps")? != expected_capabilities
        || auth.capabilities != expected_capabilities
    {
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
    Ok(AuthRequest {
        relay,
        secret: Zeroizing::new(secret),
        claim_type,
    })
}

fn validate_setup_claim_selection(value: &str) -> Result<(), ClaimError> {
    let mut paykit_access = false;
    let mut watch_only_account = false;
    for item in value.split('.') {
        match item {
            PAYKIT_ACCESS_CLAIM if !paykit_access => paykit_access = true,
            WATCH_ONLY_ACCOUNT_CLAIM if !watch_only_account => watch_only_account = true,
            _ => return Err(ClaimError::InvalidAuthRequest),
        }
    }
    // Single-permission selections are valid in Bitkit, but cannot authorize server setup.
    if !paykit_access || !watch_only_account {
        return Err(ClaimError::InvalidAuthRequest);
    }
    Ok(())
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

/// Derives the relay channel from the exact validated request, without sorting its list.
pub fn derive_channel_id(request: &AuthRequest) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(request.claim_type().as_bytes());
    hasher.update(b"|");
    hasher.update(request.secret());
    URL_SAFE_NO_PAD.encode(hasher.finalize().as_bytes())
}

/// Encodes both setup permissions in fixed watch-only-then-Paykit payload order.
pub fn encode_unsigned_payload(
    account_index: u32,
    serialized_xpub: &[u8; 78],
    key: &PaykitIdentitySecretKey,
) -> Zeroizing<[u8; UNSIGNED_PAYLOAD_LEN]> {
    let mut payload = Zeroizing::new([0; UNSIGNED_PAYLOAD_LEN]);
    payload[0] = 1;
    payload[1..5].copy_from_slice(&account_index.to_be_bytes());
    payload[5] = 0;
    payload[6..84].copy_from_slice(serialized_xpub);
    payload[84..92].copy_from_slice(&key.key_generation().to_be_bytes());
    payload[92..].copy_from_slice(key.as_bytes());
    payload
}

pub fn parse_unsigned_payload(value: &[u8]) -> Result<SetupCompanionClaim, ClaimError> {
    if value.len() != UNSIGNED_PAYLOAD_LEN || value[0] != 1 || value[5] != 0 {
        return Err(ClaimError::InvalidPayload);
    }
    let account_index = u32::from_be_bytes(value[1..5].try_into().expect("checked length"));
    if account_index >= (1 << 31) {
        return Err(ClaimError::InvalidPayload);
    }
    let serialized_xpub = value[6..84].try_into().expect("checked length");
    let generation = u64::from_be_bytes(value[84..92].try_into().expect("checked length"));
    let paykit_identity_secret_key =
        PaykitIdentitySecretKey::new(value[92..].try_into().expect("checked length"), generation)
            .map_err(|_| ClaimError::InvalidPayload)?;
    Ok(SetupCompanionClaim {
        account_index,
        serialized_xpub,
        paykit_identity_secret_key,
    })
}

/// Decrypts and verifies the complete Bitkit relay body before callers can
/// invoke a durable repository or App Registry publication. The validated request
/// binds the exact permission list and AUTH secret; neither can be substituted.
pub fn decrypt_and_verify(
    relay_body: &[u8],
    request: &AuthRequest,
    creator: &VerifyingKey,
) -> Result<SetupCompanionClaim, ClaimError> {
    validate_setup_claim_selection(request.claim_type())?;
    let plaintext = verify_envelope(relay_body, request, creator, UNSIGNED_PAYLOAD_LEN)?;
    parse_unsigned_payload(&plaintext)
}

/// Verifies the exact 41-byte Paykit-only reconnect payload against its AUTH identity.
pub fn decrypt_and_verify_reconnect(
    relay_body: &[u8],
    request: &AuthRequest,
    creator: &VerifyingKey,
) -> Result<PaykitIdentitySecretKey, ClaimError> {
    if request.claim_type() != PAYKIT_ACCESS_CLAIM {
        return Err(ClaimError::InvalidAuthRequest);
    }
    let payload = verify_envelope(relay_body, request, creator, RECONNECT_PAYLOAD_LEN)?;
    if payload[0] != 1 {
        return Err(ClaimError::InvalidPayload);
    }
    let generation = u64::from_be_bytes(payload[1..9].try_into().expect("checked length"));
    PaykitIdentitySecretKey::new(payload[9..].try_into().expect("checked length"), generation)
        .map_err(|_| ClaimError::InvalidPayload)
}

fn verify_envelope(
    relay_body: &[u8],
    request: &AuthRequest,
    creator: &VerifyingKey,
    unsigned_len: usize,
) -> Result<Zeroizing<Vec<u8>>, ClaimError> {
    if relay_body.len() < NONCE_LEN + 16 {
        return Err(ClaimError::InvalidEnvelope);
    }
    let cipher = XSalsa20Poly1305::new(request.secret().into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt((&relay_body[..NONCE_LEN]).into(), &relay_body[NONCE_LEN..])
            .map_err(|_| ClaimError::AuthenticationFailed)?,
    );
    if plaintext.len() != unsigned_len + 64 {
        return Err(ClaimError::InvalidEnvelope);
    }
    let signature = Signature::from_slice(&plaintext[unsigned_len..])
        .map_err(|_| ClaimError::InvalidEnvelope)?;
    let mut signable = Zeroizing::new(Vec::with_capacity(
        QUERY_PARAMETER.len() + request.claim_type().len() + 2 + 32 + unsigned_len,
    ));
    signable.extend_from_slice(format!("{QUERY_PARAMETER}|{}|", request.claim_type()).as_bytes());
    signable.extend_from_slice(&Sha256::digest(request.secret()));
    signable.extend_from_slice(&plaintext[..unsigned_len]);
    creator
        .verify(&signable, &signature)
        .map_err(|_| ClaimError::AuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext[..unsigned_len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_secretbox::aead::Aead;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn reconnect_verifies_only_paykit_access_and_binds_the_authorizer() {
        let secret = [7; 32];
        let signer = SigningKey::from_bytes(&[5; 32]);
        let key = PaykitIdentitySecretKey::new([11; 32], 3).unwrap();
        let request = parse_reconnect_auth_request(
            &auth_with_selection(&secret, PAYKIT_ACCESS_CLAIM),
            LOCAL_DEMO_CAPABILITIES,
        )
        .unwrap();
        let payload = [
            vec![1],
            key.key_generation().to_be_bytes().to_vec(),
            key.as_bytes().to_vec(),
        ]
        .concat();
        let body = signed_envelope(
            &secret,
            &secret,
            &signer,
            QUERY_PARAMETER,
            PAYKIT_ACCESS_CLAIM,
            &payload,
        );
        assert_eq!(
            decrypt_and_verify_reconnect(&body, &request, &signer.verifying_key()),
            Ok(key)
        );
        assert_eq!(
            decrypt_and_verify_reconnect(
                &body,
                &request,
                &SigningKey::from_bytes(&[6; 32]).verifying_key()
            ),
            Err(ClaimError::AuthenticationFailed)
        );
        assert!(decrypt_and_verify(&body, &request, &signer.verifying_key()).is_err());
        assert!(parse_reconnect_auth_request(&auth(&secret), LOCAL_DEMO_CAPABILITIES).is_err());
    }

    #[test]
    fn reconnect_rejects_account_bytes_wrong_schema_and_zero_generation() {
        let secret = [7; 32];
        let signer = SigningKey::from_bytes(&[5; 32]);
        let request = parse_reconnect_auth_request(
            &auth_with_selection(&secret, PAYKIT_ACCESS_CLAIM),
            LOCAL_DEMO_CAPABILITIES,
        )
        .unwrap();
        for payload in [
            vec![1; 84],
            unsigned().to_vec(),
            vec![0; RECONNECT_PAYLOAD_LEN],
            [vec![1], vec![0; 40]].concat(),
        ] {
            let body = signed_envelope(
                &secret,
                &secret,
                &signer,
                QUERY_PARAMETER,
                PAYKIT_ACCESS_CLAIM,
                &payload,
            );
            assert!(
                decrypt_and_verify_reconnect(&body, &request, &signer.verifying_key()).is_err()
            );
        }
    }

    fn auth(secret: &[u8; 32]) -> String {
        auth_with_selection(secret, &setup_claim_selection())
    }

    fn auth_with_selection(secret: &[u8; 32], selection: &str) -> String {
        let client_public_key = pubky::Keypair::from_secret(&[8; 32]).public_key();
        format!(
            "pubkyauth://signin_grant?caps={LOCAL_DEMO_CAPABILITIES}&relay=https%3A%2F%2Frelay.example%2Finbox&secret={}&cid=app.paykit.server&cpk={}&{QUERY_PARAMETER}={selection}",
            URL_SAFE_NO_PAD.encode(secret),
            client_public_key.as_inner(),
        )
    }

    fn request(secret: &[u8; 32]) -> AuthRequest {
        parse_auth_request(&auth(secret), LOCAL_DEMO_CAPABILITIES).unwrap()
    }

    fn unsigned() -> [u8; UNSIGNED_PAYLOAD_LEN] {
        let mut v = [0; UNSIGNED_PAYLOAD_LEN];
        v[0] = 1;
        v[1..5].copy_from_slice(&7u32.to_be_bytes());
        v[5] = 0;
        v[6..84].copy_from_slice(&[9; 78]);
        v[84..92].copy_from_slice(&3u64.to_be_bytes());
        v[92..].copy_from_slice(&[11; 32]);
        v
    }
    fn envelope(secret: &[u8; 32], key: &SigningKey) -> Vec<u8> {
        signed_envelope(
            secret,
            secret,
            key,
            QUERY_PARAMETER,
            &setup_claim_selection(),
            &unsigned(),
        )
    }

    fn signed_envelope(
        encryption_secret: &[u8; 32],
        signing_secret: &[u8; 32],
        key: &SigningKey,
        query_parameter: &str,
        claim_type: &str,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut input = format!("{query_parameter}|{claim_type}|").into_bytes();
        input.extend_from_slice(&Sha256::digest(signing_secret));
        input.extend_from_slice(payload);
        let mut plain = payload.to_vec();
        plain.extend_from_slice(&key.sign(&input).to_bytes());
        let nonce = [3; 24];
        let ciphertext = XSalsa20Poly1305::new(encryption_secret.into())
            .encrypt((&nonce).into(), plain.as_slice())
            .unwrap();
        [nonce.to_vec(), ciphertext].concat()
    }

    #[test]
    fn parses_both_list_orders_and_derives_distinct_exact_channels() {
        let secret = [7; 32];
        assert_eq!(
            setup_claim_selection(),
            "paykit-access-v1.watch-only-account-v1"
        );
        let mut channels = Vec::new();
        for selection in [
            setup_claim_selection(),
            "watch-only-account-v1.paykit-access-v1".into(),
        ] {
            let parsed = parse_auth_request(
                &auth_with_selection(&secret, &selection),
                LOCAL_DEMO_CAPABILITIES,
            )
            .unwrap();
            assert_eq!(parsed.secret(), &secret);
            assert_eq!(parsed.claim_type(), selection);
            let channel = derive_channel_id(&parsed);
            assert_eq!(
                channel,
                URL_SAFE_NO_PAD.encode(
                    blake3::hash(&[selection.as_bytes(), b"|", &secret].concat()).as_bytes()
                )
            );
            channels.push(channel);
        }
        assert_ne!(channels[0], channels[1]);
    }
    #[test]
    fn rejects_legacy_pubkyring_scheme() {
        let legacy = auth(&[7; 32]).replacen("pubkyauth://", "pubkyring://", 1);
        assert_eq!(
            parse_auth_request(&legacy, LOCAL_DEMO_CAPABILITIES),
            Err(ClaimError::InvalidAuthRequest)
        );
    }
    #[test]
    fn rejects_missing_duplicate_or_mismatched_request_values() {
        let secret = [7; 32];
        let selection = setup_claim_selection();
        for changed in [
            auth(&secret).replace("caps=", "caps=/:rw&caps="),
            auth(&secret).replace(LOCAL_DEMO_CAPABILITIES, "/:rw"),
            auth(&secret).replace(&format!("&{QUERY_PARAMETER}={selection}"), ""),
            format!("{}&{QUERY_PARAMETER}={selection}", auth(&secret)),
            format!("{}&x-bitkit-%63laim=watch-only-account-v1", auth(&secret)),
            auth(&secret).replace("secret=", "secret=&secret="),
            format!("{}&relay=https://other.example/inbox", auth(&secret)),
        ] {
            assert_eq!(
                parse_auth_request(&changed, LOCAL_DEMO_CAPABILITIES),
                Err(ClaimError::InvalidAuthRequest)
            );
        }
    }

    #[test]
    fn rejects_empty_duplicate_unknown_and_incomplete_selections() {
        for selection in [
            "",
            ".",
            "paykit-access-v1.",
            ".watch-only-account-v1",
            "paykit-access-v1..watch-only-account-v1",
            "paykit-access-v1.watch-only-account-v1.",
            "paykit-access-v1.paykit-access-v1",
            "watch-only-account-v1.watch-only-account-v1",
            "paykit-access-v1.watch-only-account-v1.paykit-access-v1",
            "paykit-access-v1.watch-only-account-v1.watch-only-account-v1",
            "wrong",
            "paykit-access-v1.wrong",
            "paykit-access-v1.watch-only-account-v1.wrong",
            "paykit-access-v1,watch-only-account-v1",
            "paykit-access-v1. watch-only-account-v1",
            PAYKIT_ACCESS_CLAIM,
            WATCH_ONLY_ACCOUNT_CLAIM,
        ] {
            assert_eq!(
                parse_auth_request(
                    &auth_with_selection(&[7; 32], selection),
                    LOCAL_DEMO_CAPABILITIES
                ),
                Err(ClaimError::InvalidAuthRequest),
                "{selection}"
            );
        }
    }

    #[test]
    fn verifies_both_list_orders_with_the_same_fixed_payload_order() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let secret = [7; 32];
        for selection in [
            setup_claim_selection(),
            "watch-only-account-v1.paykit-access-v1".into(),
        ] {
            let parsed = parse_auth_request(
                &auth_with_selection(&secret, &selection),
                LOCAL_DEMO_CAPABILITIES,
            )
            .unwrap();
            let body = signed_envelope(
                &secret,
                &secret,
                &key,
                QUERY_PARAMETER,
                &selection,
                &unsigned(),
            );
            let claim = decrypt_and_verify(&body, &parsed, &key.verifying_key()).unwrap();
            assert_eq!(claim.account_index, 7);
            assert_eq!(claim.serialized_xpub, [9; 78]);
            assert_eq!(
                claim.paykit_identity_secret_key,
                PaykitIdentitySecretKey::new([11; 32], 3).unwrap()
            );
        }
    }
    #[test]
    fn rejects_zero_generation_and_wrong_payload_lengths() {
        let mut payload = unsigned();
        for length in [0, 41, 84, 123] {
            assert_eq!(
                parse_unsigned_payload(&payload[..length]),
                Err(ClaimError::InvalidPayload)
            );
        }
        assert_eq!(
            parse_unsigned_payload(&[0; 125]),
            Err(ClaimError::InvalidPayload)
        );
        payload[84..92].fill(0);
        assert_eq!(
            parse_unsigned_payload(&payload),
            Err(ClaimError::InvalidPayload)
        );
    }

    #[test]
    fn rejects_unknown_payload_schema_and_hardened_index_encoding() {
        for (offset, value) in [(0, 0), (0, 2), (5, 1), (1, 128)] {
            let mut payload = unsigned();
            payload[offset] = value;
            assert_eq!(
                parse_unsigned_payload(&payload),
                Err(ClaimError::InvalidPayload)
            );
        }
    }

    #[test]
    fn rejects_single_purpose_and_noncanonical_signed_payload_lengths() {
        let secret = [7; 32];
        let key = SigningKey::from_bytes(&[5; 32]);
        for length in [0, 41, 84, 123, 125] {
            let payload = vec![1; length];
            let body = signed_envelope(
                &secret,
                &secret,
                &key,
                QUERY_PARAMETER,
                &setup_claim_selection(),
                &payload,
            );
            assert_eq!(
                decrypt_and_verify(&body, &request(&secret), &key.verifying_key()),
                Err(ClaimError::InvalidEnvelope)
            );
        }
    }

    #[test]
    fn signature_binds_query_exact_list_order_and_auth_secret() {
        let secret = [7; 32];
        let key = SigningKey::from_bytes(&[5; 32]);
        let selection = setup_claim_selection();
        for (query, claim_type, signing_secret) in [
            ("x-other-claim", selection.as_str(), secret),
            (QUERY_PARAMETER, "watch-only-account-v1", secret),
            (QUERY_PARAMETER, "paykit-access-v1", secret),
            (
                QUERY_PARAMETER,
                "watch-only-account-v1.paykit-access-v1",
                secret,
            ),
            (QUERY_PARAMETER, selection.as_str(), [8; 32]),
        ] {
            // Re-encrypting a signed payload cannot rebind its type or AUTH attempt.
            let body = signed_envelope(
                &secret,
                &signing_secret,
                &key,
                query,
                claim_type,
                &unsigned(),
            );
            assert_eq!(
                decrypt_and_verify(&body, &request(&secret), &key.verifying_key()),
                Err(ClaimError::AuthenticationFailed)
            );
        }
        assert_eq!(
            decrypt_and_verify(
                &envelope(&secret, &key),
                &request(&[8; 32]),
                &key.verifying_key()
            ),
            Err(ClaimError::AuthenticationFailed)
        );
        let reversed_request = parse_auth_request(
            &auth_with_selection(&secret, "watch-only-account-v1.paykit-access-v1"),
            LOCAL_DEMO_CAPABILITIES,
        )
        .unwrap();
        assert_eq!(
            decrypt_and_verify(
                &envelope(&secret, &key),
                &reversed_request,
                &key.verifying_key()
            ),
            Err(ClaimError::AuthenticationFailed)
        );
    }

    #[test]
    fn tampering_with_payload_or_ciphertext_fails_authentication() {
        let secret = [7; 32];
        let key = SigningKey::from_bytes(&[5; 32]);
        let body = envelope(&secret, &key);
        let cipher = XSalsa20Poly1305::new((&secret).into());
        let mut plaintext = cipher.decrypt((&body[..24]).into(), &body[24..]).unwrap();
        plaintext[92] ^= 1;
        let changed = [
            body[..24].to_vec(),
            cipher
                .encrypt((&body[..24]).into(), plaintext.as_slice())
                .unwrap(),
        ]
        .concat();
        assert_eq!(
            decrypt_and_verify(&changed, &request(&secret), &key.verifying_key()),
            Err(ClaimError::AuthenticationFailed)
        );
        let mut changed = body;
        changed[24] ^= 1;
        assert_eq!(
            decrypt_and_verify(&changed, &request(&secret), &key.verifying_key()),
            Err(ClaimError::AuthenticationFailed)
        );
    }

    #[test]
    fn setup_payload_matches_cross_language_wire_fixture() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            query_parameter: String,
            claim_type: String,
            capabilities: String,
            account_index: u32,
            key_generation: u64,
            serialized_xpub_hex: String,
            paykit_secret_hex: String,
            unsigned_payload_hex: String,
        }
        fn hex(value: &str) -> Vec<u8> {
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        }
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../tests/fixtures/bitkit-combined-claim-v1.json"
        ))
        .unwrap();
        assert_eq!(fixture.query_parameter, QUERY_PARAMETER);
        assert_eq!(fixture.claim_type, setup_claim_selection());
        assert_eq!(fixture.capabilities, required_capabilities());
        let xpub = hex(&fixture.serialized_xpub_hex).try_into().unwrap();
        let key = PaykitIdentitySecretKey::new(
            hex(&fixture.paykit_secret_hex).try_into().unwrap(),
            fixture.key_generation,
        )
        .unwrap();
        let expected = hex(&fixture.unsigned_payload_hex);
        assert_eq!(
            encode_unsigned_payload(fixture.account_index, &xpub, &key).as_slice(),
            expected
        );
        let decoded = parse_unsigned_payload(&expected).unwrap();
        assert_eq!(decoded.account_index, fixture.account_index);
        assert_eq!(decoded.serialized_xpub, xpub);
        assert_eq!(decoded.paykit_identity_secret_key, key);
        assert!(format!("{decoded:?}").contains("<redacted>"));
        assert!(!format!("{decoded:?}").contains("11, 11"));
    }

    #[test]
    fn rejects_malformed_and_signature_mismatch() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let secret = [7; 32];
        assert_eq!(
            decrypt_and_verify(&[0; 24], &request(&secret), &key.verifying_key()),
            Err(ClaimError::InvalidEnvelope)
        );
        let wrong = SigningKey::from_bytes(&[6; 32]);
        assert_eq!(
            decrypt_and_verify(
                &envelope(&secret, &key),
                &request(&secret),
                &wrong.verifying_key()
            ),
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
