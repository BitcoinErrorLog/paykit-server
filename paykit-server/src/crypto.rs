//! Versioned authenticated encryption for private persisted server state.
//!
//! The stored envelope format is a one-byte version, a 24-byte XChaCha20 nonce,
//! and the ciphertext with its authentication tag. Its associated data binds an
//! envelope to its supported type, creator keyed lookup hash, and row UUID.

use std::fmt;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const ENVELOPE_VERSION: u8 = 1;
const NONCE_LENGTH: usize = 24;
const TAG_LENGTH: usize = 16;
const DERIVED_KEY_LENGTH: usize = 32;
const AEAD_LABEL: &[u8] = b"paykit-server/aead/v1";
const LOOKUP_HMAC_LABEL: &[u8] = b"paykit-server/lookup-hmac/v1";

/// In-memory cryptographic material derived from a deployment master key.
pub struct Crypto {
    aead_key: Zeroizing<[u8; DERIVED_KEY_LENGTH]>,
    lookup_hmac_key: Zeroizing<[u8; DERIVED_KEY_LENGTH]>,
}

impl fmt::Debug for Crypto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Crypto(<redacted>)")
    }
}

impl Crypto {
    /// Derives independent AEAD and lookup-HMAC keys from a 32-byte master key.
    pub fn from_master_key(master_key: &[u8]) -> Result<Self, CryptoError> {
        if master_key.len() != DERIVED_KEY_LENGTH {
            return Err(CryptoError::InvalidConfiguration);
        }

        let hkdf = Hkdf::<Sha256>::new(None, master_key);
        let mut aead_key = Zeroizing::new([0_u8; DERIVED_KEY_LENGTH]);
        let mut lookup_hmac_key = Zeroizing::new([0_u8; DERIVED_KEY_LENGTH]);
        hkdf.expand(AEAD_LABEL, &mut *aead_key)
            .map_err(|_| CryptoError::InvalidConfiguration)?;
        hkdf.expand(LOOKUP_HMAC_LABEL, &mut *lookup_hmac_key)
            .map_err(|_| CryptoError::InvalidConfiguration)?;

        Ok(Self {
            aead_key,
            lookup_hmac_key,
        })
    }

    /// Encrypts plaintext using a newly generated XChaCha20 nonce.
    pub fn encrypt(
        &self,
        context: &EnvelopeContext,
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, CryptoError> {
        let cipher = self.cipher()?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &context.associated_data(),
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        let mut stored = Vec::with_capacity(1 + NONCE_LENGTH + ciphertext.len());
        stored.push(ENVELOPE_VERSION);
        stored.extend_from_slice(&nonce);
        stored.extend_from_slice(&ciphertext);
        Ok(EncryptedEnvelope(stored))
    }

    /// Decrypts an envelope after validating its exact supported stored layout.
    pub fn decrypt(
        &self,
        context: &EnvelopeContext,
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>, CryptoError> {
        let stored = envelope.as_bytes();
        if stored.len() < 1 + NONCE_LENGTH + TAG_LENGTH || stored.first() != Some(&ENVELOPE_VERSION)
        {
            return Err(CryptoError::InvalidEnvelope);
        }

        let nonce = XNonce::from_slice(&stored[1..=NONCE_LENGTH]);
        self.cipher()?
            .decrypt(
                nonce,
                Payload {
                    msg: &stored[1 + NONCE_LENGTH..],
                    aad: &context.associated_data(),
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    /// Produces the raw 32-byte keyed lookup value for supplied logical bytes.
    pub fn lookup_hash(&self, logical_bytes: &[u8]) -> LookupHash {
        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(&*self.lookup_hmac_key) {
            Ok(mac) => mac,
            Err(_) => unreachable!("a fixed-length HMAC-SHA256 key is valid"),
        };
        mac.update(logical_bytes);
        LookupHash(mac.finalize().into_bytes().into())
    }

    /// Produces a keyed lookup hash scoped exclusively to Bitcoin addresses.
    pub fn bitcoin_address_lookup_hash(&self, address: &[u8]) -> LookupHash {
        self.domain_separated_lookup_hash(b"paykit-server:bitcoin-address:v1", address)
    }

    /// Produces a Creator-scoped keyed hash for a Bitcoin derivation index.
    pub fn bitcoin_derivation_index_lookup_hash(
        &self,
        creator_hash: LookupHash,
        derivation_index: i64,
    ) -> LookupHash {
        let mut value = [0_u8; 40];
        value[..32].copy_from_slice(creator_hash.as_bytes());
        value[32..].copy_from_slice(&derivation_index.to_be_bytes());
        self.domain_separated_lookup_hash(b"paykit-server:bitcoin-derivation-index:v1", &value)
    }

    /// Produces a keyed lookup hash scoped exclusively to Bitcoin outpoints.
    pub fn bitcoin_outpoint_lookup_hash(&self, outpoint: &[u8]) -> LookupHash {
        self.domain_separated_lookup_hash(b"paykit-server:bitcoin-outpoint:v1", outpoint)
    }

    fn domain_separated_lookup_hash(&self, domain: &[u8], logical_bytes: &[u8]) -> LookupHash {
        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(&*self.lookup_hmac_key) {
            Ok(mac) => mac,
            Err(_) => unreachable!("a fixed-length HMAC-SHA256 key is valid"),
        };
        mac.update(domain);
        mac.update(&[0]);
        mac.update(logical_bytes);
        LookupHash(mac.finalize().into_bytes().into())
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, CryptoError> {
        XChaCha20Poly1305::new_from_slice(&*self.aead_key)
            .map_err(|_| CryptoError::InvalidConfiguration)
    }
}

/// The supported kinds of encrypted persisted state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeType {
    /// The creator's encrypted session, receiver-secret, and account credentials.
    CreatorCredentials,
    /// A creator's encrypted Paykit SDK state snapshot.
    SdkState,
    /// A reader's permanent encrypted assignment.
    ReaderAssignment,
    /// An encrypted invoice payload.
    Invoice,
    /// An invoice's encrypted Bitcoin address, derivation index, and required amount.
    InvoicePaymentRecord,
    /// An encrypted Bitcoin outpoint and observed amount.
    BitcoinObservation,
    /// Versioned server-owned semantic inputs for an outbound SDK handoff.
    OutboxSemanticIntent,
    /// Canonical addressed lock resource bound to one operational drain.
    PaymentDrain,
}

impl EnvelopeType {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::CreatorCredentials => b"creator-credentials",
            Self::SdkState => b"sdk-state",
            Self::ReaderAssignment => b"reader-assignment",
            Self::Invoice => b"invoice",
            Self::InvoicePaymentRecord => b"invoice-payment-record",
            Self::BitcoinObservation => b"bitcoin-observation",
            Self::OutboxSemanticIntent => b"outbox-semantic-intent",
            Self::PaymentDrain => b"payment-drain",
        }
    }
}

/// Typed associated-data context for a persisted envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeContext {
    envelope_type: EnvelopeType,
    creator_lookup_hash: LookupHash,
    row_id: Uuid,
    parent_row_id: Option<Uuid>,
}

impl fmt::Debug for EnvelopeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeContext")
            .field("envelope_type", &self.envelope_type)
            .field("binding", &"<redacted>")
            .finish()
    }
}

impl EnvelopeContext {
    /// Creates the binding context for a creator credential envelope.
    pub fn creator_credentials(creator_lookup_hash: LookupHash, row_id: Uuid) -> Self {
        Self::new(
            EnvelopeType::CreatorCredentials,
            creator_lookup_hash,
            row_id,
        )
    }

    /// Creates the binding context for a creator SDK-state envelope.
    pub fn sdk_state(creator_lookup_hash: LookupHash, row_id: Uuid) -> Self {
        Self::new(EnvelopeType::SdkState, creator_lookup_hash, row_id)
    }
    /// Creates the binding context for a reader assignment.
    pub fn reader_assignment(creator_lookup_hash: LookupHash, row_id: Uuid) -> Self {
        Self::new(EnvelopeType::ReaderAssignment, creator_lookup_hash, row_id)
    }
    /// Creates the binding context for an invoice.
    pub fn invoice(creator_lookup_hash: LookupHash, row_id: Uuid) -> Self {
        Self::new(EnvelopeType::Invoice, creator_lookup_hash, row_id)
    }
    /// Creates the binding context for an invoice's Bitcoin payment record.
    pub fn invoice_payment_record(creator_lookup_hash: LookupHash, row_id: Uuid) -> Self {
        Self::new(
            EnvelopeType::InvoicePaymentRecord,
            creator_lookup_hash,
            row_id,
        )
    }
    /// Creates the binding context for one Bitcoin observation row.
    pub fn bitcoin_observation(creator_lookup_hash: LookupHash, row_id: Uuid) -> Self {
        Self::new(
            EnvelopeType::BitcoinObservation,
            creator_lookup_hash,
            row_id,
        )
    }
    /// Binds one Bitcoin observation row to its owning invoice row.
    pub fn bitcoin_observation_for_invoice(
        creator_lookup_hash: LookupHash,
        row_id: Uuid,
        invoice_id: Uuid,
    ) -> Self {
        let mut context = Self::bitcoin_observation(creator_lookup_hash, row_id);
        context.parent_row_id = Some(invoice_id);
        context
    }
    /// Creates the binding context for an outbox semantic intent.
    pub fn outbox_semantic_intent(creator_lookup_hash: LookupHash, row_id: Uuid) -> Self {
        Self::new(
            EnvelopeType::OutboxSemanticIntent,
            creator_lookup_hash,
            row_id,
        )
    }
    /// Creates the binding context for one operational payment drain.
    pub fn payment_drain(creator_lookup_hash: LookupHash, row_id: Uuid) -> Self {
        Self::new(EnvelopeType::PaymentDrain, creator_lookup_hash, row_id)
    }

    fn new(envelope_type: EnvelopeType, creator_lookup_hash: LookupHash, row_id: Uuid) -> Self {
        Self {
            envelope_type,
            creator_lookup_hash,
            row_id,
            parent_row_id: None,
        }
    }

    fn associated_data(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            4 + b"paykit-server".len()
                + 4
                + 1
                + 4
                + self.envelope_type.as_bytes().len()
                + 4
                + self.creator_lookup_hash.as_bytes().len()
                + 4
                + 16,
        );
        append_length_prefixed(&mut aad, b"paykit-server");
        append_length_prefixed(&mut aad, &[ENVELOPE_VERSION]);
        append_length_prefixed(&mut aad, self.envelope_type.as_bytes());
        append_length_prefixed(&mut aad, self.creator_lookup_hash.as_bytes());
        append_length_prefixed(&mut aad, self.row_id.as_bytes());
        if let Some(parent_row_id) = self.parent_row_id {
            append_length_prefixed(&mut aad, parent_row_id.as_bytes());
        }
        aad
    }
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("AAD field lengths fit in u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

/// Opaque bytes stored in a `BYTEA` envelope column.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedEnvelope(Vec<u8>);

impl fmt::Debug for EncryptedEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedEnvelope(<redacted>)")
    }
}

impl EncryptedEnvelope {
    /// Reconstitutes stored bytes for validation and decryption.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the exact bytes to persist in a `BYTEA` column.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Raw 32-byte HMAC-SHA256 value suitable for a keyed lookup column.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LookupHash([u8; 32]);

impl fmt::Debug for LookupHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LookupHash(<redacted>)")
    }
}

impl LookupHash {
    /// Reconstitutes a raw 32-byte HMAC-SHA256 lookup hash from trusted storage bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw HMAC-SHA256 output for persistence or comparison.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Safe, secret-free failures from cryptographic configuration or envelope handling.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// The provided master-key material cannot initialize the required subkeys.
    #[error("invalid cryptographic configuration")]
    InvalidConfiguration,
    /// Persisted envelope bytes do not match the supported layout.
    #[error("invalid encrypted envelope")]
    InvalidEnvelope,
    /// An envelope could not be authenticated for its supplied context or key.
    #[error("unable to decrypt encrypted envelope")]
    AuthenticationFailed,
}
