//! Atomic encrypted reader allocation, invoice, and delivery-intent persistence.
//!
//! The caller supplies closed, versioned semantic delivery intents. This
//! repository persists those complete SDK inputs inside Creator-bound AEAD
//! envelopes before reporting invoice success.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    application::payment_status::PersistedPaymentStatus,
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    bitcoin::{DirectBinding, ObservationAction, ObservationTarget, TrackedOutput},
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::locks::{CreatorPubky, ReaderPubky},
    domain::payment::BitcoinOutpoint,
    persistence::PersistenceError,
};

/// Opaque inputs for one transactional invoice-allocation operation.
///
/// `endpoint_publication_payload` is persisted only when the reader has no
/// assignment yet. In that case the payment-request intent depends on its
/// outbox row. For an existing reader, no new endpoint publication is invented:
/// the application must have established that the existing reader endpoint is
/// ready before it asks this store to enqueue a payment request.
pub struct AtomicInvoiceInput<'a> {
    pub creator: &'a CreatorPubky,
    pub reader: &'a ReaderPubky,
    /// Creator-scoped idempotency key for the Locks bundle.
    pub bundle_binding: &'a [u8],
    /// Exact payment-request binding for idempotent replay detection.
    pub payment_request_binding: &'a [u8],
    /// Derives the encrypted assignment and endpoint payloads only after this
    /// transaction has selected the permanent child index.
    pub new_reader_payloads: &'a dyn NewReaderPayloadFactory,
    /// Complete Payment Request proposal intent. Exact replay does not rebuild it.
    pub payment_request_intent: DeliveryIntentV1,
    /// Settlement-authoritative integer satoshi amount captured from the lock.
    pub required_sats: u64,
    /// Positive whole-hour payment window bound into the signed request.
    pub payment_in_hours: u64,
}

/// Private payloads for a newly allocated `(creator, reader)` assignment.
pub struct NewReaderPayloads {
    pub endpoint_intent: DeliveryIntentV1,
    /// Invoice-specific BIP84 P2WPKH address derived at the allocated index.
    pub bitcoin_address: String,
}

#[derive(Serialize, Deserialize)]
struct InvoicePaymentRecordV1 {
    version: u8,
    derivation_index: i64,
    bitcoin_address: String,
    required_sats: u64,
}

#[derive(Serialize, Deserialize)]
struct BitcoinObservationV1 {
    version: u8,
    outpoint: String,
    observed_sats: u64,
}

pub(crate) struct BitcoinObservationInput {
    pub address: String,
    pub outpoint: BitcoinOutpoint,
    pub observed_sats: u64,
    pub confirmations: u32,
    pub present: bool,
}

/// Produces payloads after the creator-row lock determines the child index.
pub trait NewReaderPayloadFactory: Send + Sync {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError>;
}

/// Secret-free identifiers returned by an atomic allocation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicInvoiceResult {
    invoice_id: Uuid,
    payment_request_outbox_id: Uuid,
    endpoint_publication_outbox_id: Option<Uuid>,
    reader_assignment_id: Uuid,
    reader_child_index: i64,
    invoice_created_at: OffsetDateTime,
    payment_deadline: OffsetDateTime,
    replayed: bool,
}

/// Result of a side-effect-free invoice replay lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvoicePreflight {
    New,
    ExactReplay,
    Conflict,
}

impl AtomicInvoiceResult {
    /// Builds the secret-free result returned by an invoice persistence adapter.
    ///
    /// This is public because [`crate::application::create_invoice::InvoicePersistence`]
    /// is an injected port; alternate adapters must be able to report a completed
    /// allocation without depending on this module's private fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invoice_id: Uuid,
        payment_request_outbox_id: Uuid,
        endpoint_publication_outbox_id: Option<Uuid>,
        reader_assignment_id: Uuid,
        reader_child_index: i64,
        invoice_created_at: OffsetDateTime,
        payment_deadline: OffsetDateTime,
        replayed: bool,
    ) -> Self {
        Self {
            invoice_id,
            payment_request_outbox_id,
            endpoint_publication_outbox_id,
            reader_assignment_id,
            reader_child_index,
            invoice_created_at,
            payment_deadline,
            replayed,
        }
    }

    pub fn invoice_id(&self) -> Uuid {
        self.invoice_id
    }

    pub fn payment_request_outbox_id(&self) -> Uuid {
        self.payment_request_outbox_id
    }

    /// Returns the endpoint-publication intent that gates this payment request,
    /// when this invoice required one.
    pub fn endpoint_publication_outbox_id(&self) -> Option<Uuid> {
        self.endpoint_publication_outbox_id
    }

    pub fn reader_assignment_id(&self) -> Uuid {
        self.reader_assignment_id
    }

    pub fn reader_child_index(&self) -> i64 {
        self.reader_child_index
    }

    pub fn invoice_created_at(&self) -> OffsetDateTime {
        self.invoice_created_at
    }

    pub fn payment_deadline(&self) -> OffsetDateTime {
        self.payment_deadline
    }

    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Encrypted invoice persistence with creator-row serialization.
#[derive(Clone, Debug)]
pub struct InvoiceStore {
    pool: PgPool,
    crypto: Arc<Crypto>,
}

impl InvoiceStore {
    pub fn new(pool: &PgPool, crypto: Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    /// Authenticates all final encrypted Bitcoin values and their keyed lookup hashes.
    pub async fn scan_payment_record_integrity(&self) -> Result<(), PersistenceError> {
        let invoices = sqlx::query_as::<_, (Uuid, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT invoices.id, creators.creator_lookup_hash,
                    invoices.payment_record_envelope, invoices.bitcoin_address_lookup_hash,
                    invoices.derivation_index_lookup_hash
             FROM invoices JOIN creators ON creators.id = invoices.creator_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for (id, creator_hash, envelope, address_hash, index_hash) in invoices {
            let creator_hash = lookup_hash_from_storage(&creator_hash)?;
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::invoice_payment_record(creator_hash, id),
                    &EncryptedEnvelope::from_bytes(envelope),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let record: InvoicePaymentRecordV1 =
                postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
            if record.version != 1
                || address_hash
                    != self
                        .crypto
                        .bitcoin_address_lookup_hash(record.bitcoin_address.as_bytes())
                        .as_bytes()
                || index_hash
                    != self
                        .crypto
                        .bitcoin_derivation_index_lookup_hash(creator_hash, record.derivation_index)
                        .as_bytes()
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
        }

        let observations = sqlx::query_as::<_, (Uuid, Uuid, Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT observations.id, observations.invoice_id, creators.creator_lookup_hash,
                    observations.observation_envelope, observations.outpoint_lookup_hash
             FROM bitcoin_observations AS observations
             JOIN invoices ON invoices.id = observations.invoice_id
             JOIN creators ON creators.id = invoices.creator_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for (id, invoice_id, creator_hash, envelope, outpoint_hash) in observations {
            let creator_hash = lookup_hash_from_storage(&creator_hash)?;
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::bitcoin_observation_for_invoice(creator_hash, id, invoice_id),
                    &EncryptedEnvelope::from_bytes(envelope),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let record: BitcoinObservationV1 =
                postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
            if record.version != 1
                || outpoint_hash
                    != self
                        .crypto
                        .bitcoin_outpoint_lookup_hash(record.outpoint.as_bytes())
                        .as_bytes()
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
        }
        Ok(())
    }

    /// Loads every non-final invoice as an authenticated Electrum observation target.
    pub async fn observation_targets(&self) -> Result<Vec<ObservationTarget>, PersistenceError> {
        self.observation_targets_at(OffsetDateTime::now_utc()).await
    }

    /// Loads observation targets after durably expiring invoices whose inclusive
    /// payment deadline has passed without an amount-matched observation.
    pub async fn observation_targets_at(
        &self,
        observed_at: OffsetDateTime,
    ) -> Result<Vec<ObservationTarget>, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query(
            "UPDATE invoices SET payment_expired_at = $1, updated_at = NOW()
             WHERE payment_expired_at IS NULL
               AND first_amount_matched_observed_at IS NULL
               AND payment_deadline < $1",
        )
        .bind(observed_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let rows = sqlx::query_as::<_, ObservationTargetRow>(
            "SELECT invoices.id AS invoice_id, creators.creator_lookup_hash, \
                    invoices.payment_record_envelope, invoices.bitcoin_address_lookup_hash, \
                    invoices.derivation_index_lookup_hash, observations.id AS observation_id, \
                    observations.observation_envelope, observations.outpoint_lookup_hash \
             FROM invoices JOIN creators ON creators.id = invoices.creator_id \
             LEFT JOIN bitcoin_observations AS observations \
               ON observations.invoice_id = invoices.id AND observations.active \
             WHERE invoices.payment_expired_at IS NULL \
               AND NOT (invoices.payment_status = 'confirmed' \
                        AND invoices.confirmation_count = 6 AND invoices.amount_matched) \
             ORDER BY invoices.id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;

        rows.into_iter()
            .map(|row| {
                let creator_hash = lookup_hash_from_storage(&row.creator_lookup_hash)?;
                let plaintext = self
                    .crypto
                    .decrypt(
                        &EnvelopeContext::invoice_payment_record(creator_hash, row.invoice_id),
                        &EncryptedEnvelope::from_bytes(row.payment_record_envelope),
                    )
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                let payment: InvoicePaymentRecordV1 = postcard::from_bytes(&plaintext)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                if payment.version != 1
                    || row.bitcoin_address_lookup_hash
                        != self
                            .crypto
                            .bitcoin_address_lookup_hash(payment.bitcoin_address.as_bytes())
                            .as_bytes()
                    || row.derivation_index_lookup_hash
                        != self
                            .crypto
                            .bitcoin_derivation_index_lookup_hash(
                                creator_hash,
                                payment.derivation_index,
                            )
                            .as_bytes()
                {
                    return Err(PersistenceError::CorruptOrMissing);
                }

                let current = match (
                    row.observation_id,
                    row.observation_envelope,
                    row.outpoint_lookup_hash,
                ) {
                    (None, None, None) => None,
                    (Some(id), Some(envelope), Some(outpoint_hash)) => {
                        let plaintext = self
                            .crypto
                            .decrypt(
                                &EnvelopeContext::bitcoin_observation_for_invoice(
                                    creator_hash,
                                    id,
                                    row.invoice_id,
                                ),
                                &EncryptedEnvelope::from_bytes(envelope),
                            )
                            .map_err(|_| PersistenceError::CorruptOrMissing)?;
                        let observation: BitcoinObservationV1 = postcard::from_bytes(&plaintext)
                            .map_err(|_| PersistenceError::CorruptOrMissing)?;
                        if observation.version != 1
                            || outpoint_hash
                                != self
                                    .crypto
                                    .bitcoin_outpoint_lookup_hash(observation.outpoint.as_bytes())
                                    .as_bytes()
                        {
                            return Err(PersistenceError::CorruptOrMissing);
                        }
                        let outpoint = observation
                            .outpoint
                            .parse::<bitcoin::OutPoint>()
                            .map_err(|_| PersistenceError::CorruptOrMissing)?;
                        if outpoint.to_string() != observation.outpoint {
                            return Err(PersistenceError::CorruptOrMissing);
                        }
                        Some(TrackedOutput::new(outpoint, observation.observed_sats))
                    }
                    _ => return Err(PersistenceError::CorruptOrMissing),
                };
                Ok(ObservationTarget::new(payment.bitcoin_address, current))
            })
            .collect()
    }

    /// Checks durable invoice idempotency before mutable external validation.
    pub async fn preflight(
        &self,
        creator: &CreatorPubky,
        bundle_binding: &[u8],
        payment_request_binding: &[u8],
    ) -> Result<InvoicePreflight, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_binding);
        let payment_hash = self.crypto.lookup_hash(payment_request_binding);
        let existing = sqlx::query_as::<_, PreflightInvoice>(
            "SELECT invoices.payment_request_lookup_hash FROM invoices \
             JOIN creators ON creators.id = invoices.creator_id \
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(match existing {
            None => InvoicePreflight::New,
            Some(existing) if existing.payment_request_lookup_hash == payment_hash.as_bytes() => {
                InvoicePreflight::ExactReplay
            }
            Some(_) => InvoicePreflight::Conflict,
        })
    }

    /// Loads an exact replay without rebuilding delivery intent or repeating
    /// external validation and discovery work.
    pub async fn exact_replay(
        &self,
        creator: &CreatorPubky,
        reader: &ReaderPubky,
        bundle_binding: &[u8],
        payment_binding: &[u8],
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let reader_hash = self.crypto.lookup_hash(reader.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_binding);
        let payment_hash = self.crypto.lookup_hash(payment_binding);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let creator = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, next_child_index FROM creators \
             WHERE creator_lookup_hash = $1 FOR UPDATE",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if lookup_hash(&creator.creator_lookup_hash)? != creator_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let existing = sqlx::query_as::<_, ExistingInvoice>(
            "SELECT id, payment_request_lookup_hash, invoice_created_at, payment_deadline, payment_in_hours FROM invoices \
             WHERE creator_id = $1 AND bundle_lookup_hash = $2 FOR UPDATE",
        )
        .bind(creator.id)
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if existing.payment_request_lookup_hash != payment_hash.as_bytes() {
            return Err(PersistenceError::Conflict);
        }
        let assignment = self
            .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
            .await?
            .ok_or(PersistenceError::CorruptOrMissing)?;
        let payment_outbox = sqlx::query_as::<_, ExistingPaymentOutbox>(
            "SELECT id, depends_on_id FROM outbox WHERE invoice_id = $1 \
             AND depends_on_id IS NOT NULL ORDER BY created_at, id LIMIT 1",
        )
        .bind(existing.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(AtomicInvoiceResult {
            invoice_id: existing.id,
            payment_request_outbox_id: payment_outbox.id,
            endpoint_publication_outbox_id: payment_outbox.depends_on_id,
            reader_assignment_id: assignment.id,
            reader_child_index: assignment.child_index,
            invoice_created_at: existing.invoice_created_at,
            payment_deadline: existing.payment_deadline,
            replayed: true,
        })
    }

    /// Reads only the durable payment facts for one creator-scoped bundle.
    ///
    /// Invoice envelopes are deliberately not selected or decrypted. A row with
    /// an unknown status or invalid confirmation count is a safe persistence
    /// failure rather than a value exposed to the caller.
    pub async fn payment_status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &crate::domain::locks::BundleId,
    ) -> Result<Option<PersistedPaymentStatus>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_id.to_string().as_bytes());
        let row = sqlx::query_as::<_, PaymentStatusRow>(
            "SELECT invoices.payment_status, invoices.confirmation_count, invoices.amount_matched \
             FROM invoices JOIN creators ON creators.id = invoices.creator_id \
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        row.map(PersistedPaymentStatus::try_from).transpose()
    }

    /// Records one direct, invoice-address-specific output observation. The
    /// database resolves the address; callers cannot nominate an invoice.
    pub async fn apply_bitcoin_observation(
        &self,
        address: &str,
        outpoint: &BitcoinOutpoint,
        observed_sats: u64,
        confirmations: u32,
        present: bool,
    ) -> Result<bool, PersistenceError> {
        self.apply_bitcoin_observation_at(
            address,
            outpoint,
            observed_sats,
            confirmations,
            present,
            OffsetDateTime::now_utc(),
        )
        .await
    }

    pub async fn apply_bitcoin_observation_at(
        &self,
        address: &str,
        outpoint: &BitcoinOutpoint,
        observed_sats: u64,
        confirmations: u32,
        present: bool,
        observed_at: OffsetDateTime,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let applied = self
            .apply_bitcoin_observation_in_tx(
                &mut tx,
                &BitcoinObservationInput {
                    address: address.to_owned(),
                    outpoint: outpoint.clone(),
                    observed_sats,
                    confirmations,
                    present,
                },
                observed_at,
            )
            .await?;
        self.expire_unmatched_at_deadline_in_tx(&mut tx, address, observed_at)
            .await?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(applied)
    }

    pub(crate) async fn apply_bitcoin_observation_batch_at(
        &self,
        observations: &[BitcoinObservationInput],
        observed_at: OffsetDateTime,
    ) -> Result<usize, PersistenceError> {
        if observations.is_empty() {
            return Ok(0);
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let mut applied = 0;
        for observation in observations {
            if self
                .apply_bitcoin_observation_in_tx(&mut tx, observation, observed_at)
                .await?
            {
                applied += 1;
            }
        }
        for observation in observations {
            self.expire_unmatched_at_deadline_in_tx(&mut tx, &observation.address, observed_at)
                .await?;
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(applied)
    }

    async fn apply_bitcoin_observation_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        observation: &BitcoinObservationInput,
        observed_at: OffsetDateTime,
    ) -> Result<bool, PersistenceError> {
        let BitcoinObservationInput {
            address,
            outpoint,
            observed_sats,
            confirmations,
            present,
        } = observation;
        let address = address.as_str();
        let observed_sats = *observed_sats;
        let confirmations = *confirmations;
        let present = *present;
        let incoming_confirmations = confirmations;
        let confirmations = i32::try_from(incoming_confirmations)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let outpoint = outpoint.canonical_text();
        let address_lookup_hash = self.crypto.bitcoin_address_lookup_hash(address.as_bytes());
        let invoice = sqlx::query_as::<_, BitcoinInvoiceRow>(
            "SELECT invoices.id, invoices.payment_record_envelope,
                    invoices.bitcoin_address_lookup_hash, invoices.payment_status,
                    invoices.confirmation_count, invoices.amount_matched,
                    invoices.payment_deadline, invoices.first_amount_matched_observed_at,
                    invoices.payment_expired_at,
                    creators.creator_lookup_hash
             FROM invoices JOIN creators ON creators.id = invoices.creator_id
             WHERE invoices.bitcoin_address_lookup_hash = $1 FOR UPDATE OF invoices",
        )
        .bind(address_lookup_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(invoice) = invoice else {
            return Ok(false);
        };
        let creator_hash = lookup_hash_from_storage(&invoice.creator_lookup_hash)?;
        let payment_record_plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::invoice_payment_record(creator_hash, invoice.id),
                &EncryptedEnvelope::from_bytes(invoice.payment_record_envelope),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment_record: InvoicePaymentRecordV1 =
            postcard::from_bytes(&payment_record_plaintext)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if payment_record.version != 1
            || payment_record.bitcoin_address != address
            || invoice.bitcoin_address_lookup_hash != address_lookup_hash.as_bytes()
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let required = payment_record.required_sats;
        let amount_matched = present && observed_sats >= required;
        if invoice.payment_expired_at.is_some() {
            return Ok(true);
        }
        if invoice.first_amount_matched_observed_at.is_none()
            && observed_at > invoice.payment_deadline
        {
            sqlx::query(
                "UPDATE invoices SET payment_expired_at = $1, updated_at = NOW()
                 WHERE id = $2 AND payment_expired_at IS NULL
                   AND first_amount_matched_observed_at IS NULL",
            )
            .bind(observed_at)
            .bind(invoice.id)
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(true);
        }

        // Final matching outputs are no longer monitored. Keep their persisted
        // six-confirmation fact immutable even if a stale observer reports later.
        if invoice.payment_status == "confirmed"
            && invoice.confirmation_count == 6
            && invoice.amount_matched
        {
            return Ok(true);
        }

        let outpoint_lookup_hash = self
            .crypto
            .bitcoin_outpoint_lookup_hash(outpoint.as_bytes());
        let existing_outpoint = sqlx::query_as::<_, BitcoinObservationRow>(
            "SELECT id, invoice_id, observation_envelope, outpoint_lookup_hash,
                    confirmations, present
             FROM bitcoin_observations WHERE outpoint_lookup_hash = $1 FOR UPDATE",
        )
        .bind(outpoint_lookup_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if existing_outpoint
            .as_ref()
            .is_some_and(|row| row.invoice_id != invoice.id)
        {
            return Err(PersistenceError::Conflict);
        }
        if let Some(row) = existing_outpoint.as_ref() {
            let record = self.decrypt_observation(creator_hash, row)?;
            if record.outpoint != outpoint
                || row.outpoint_lookup_hash != outpoint_lookup_hash.as_bytes()
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
        }
        let active = sqlx::query_as::<_, BitcoinObservationRow>(
            "SELECT id, invoice_id, observation_envelope, outpoint_lookup_hash,
                    confirmations, present
             FROM bitcoin_observations WHERE invoice_id = $1 AND active FOR UPDATE",
        )
        .bind(invoice.id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let active_record = active
            .as_ref()
            .map(|row| self.decrypt_observation(creator_hash, row))
            .transpose()?;

        let action = active
            .as_ref()
            .zip(active_record.as_ref())
            .map(|(row, record)| {
                DirectBinding::new(
                    &record.outpoint,
                    record.observed_sats,
                    u32::try_from(row.confirmations).unwrap_or_default(),
                    row.present,
                )
                .action_for_values(
                    &outpoint,
                    observed_sats,
                    incoming_confirmations,
                    present,
                    required,
                )
            });
        if action == Some(ObservationAction::Ignore) {
            return Ok(true);
        }
        // An unseen output with no existing binding is not an observation and
        // must not manufacture a binding for an otherwise undetected invoice.
        if active.is_none() && !present {
            return Ok(true);
        }
        if action == Some(ObservationAction::Replace) {
            sqlx::query(
                "UPDATE bitcoin_observations SET active = FALSE, updated_at = NOW() \
                 WHERE invoice_id = $1 AND active",
            )
            .bind(invoice.id)
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        let observation_id = existing_outpoint
            .as_ref()
            .map_or_else(Uuid::new_v4, |row| row.id);
        let observation_plaintext = postcard::to_allocvec(&BitcoinObservationV1 {
            version: 1,
            outpoint: outpoint.to_owned(),
            observed_sats,
        })
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let observation_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::bitcoin_observation_for_invoice(
                    creator_hash,
                    observation_id,
                    invoice.id,
                ),
                &observation_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let observation_write = sqlx::query(
            "INSERT INTO bitcoin_observations \
            (id, invoice_id, observation_envelope, outpoint_lookup_hash,
            confirmations, present, active) \
            VALUES ($1, $2, $3, $4, $5, $6, TRUE) \
            ON CONFLICT (outpoint_lookup_hash) DO UPDATE SET
            observation_envelope = EXCLUDED.observation_envelope,
            confirmations = EXCLUDED.confirmations, present = EXCLUDED.present, active = TRUE, \
            updated_at = NOW() WHERE bitcoin_observations.invoice_id = EXCLUDED.invoice_id",
        )
        .bind(observation_id)
        .bind(invoice.id)
        .bind(observation_envelope.as_bytes())
        .bind(outpoint_lookup_hash.as_bytes().as_slice())
        .bind(confirmations)
        .bind(present)
        .execute(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Conflict)?;
        if observation_write.rows_affected() != 1 {
            return Err(PersistenceError::Conflict);
        }
        let reported_confirmations = if amount_matched {
            incoming_confirmations.min(6)
        } else if present {
            incoming_confirmations
        } else {
            0
        };
        let status = if !present {
            "undetected"
        } else if reported_confirmations == 0 {
            "detected"
        } else {
            "confirmed"
        };
        let first_amount_matched_observed_at = (amount_matched
            && invoice.first_amount_matched_observed_at.is_none())
        .then_some(observed_at);
        sqlx::query("UPDATE invoices SET payment_status = $1, confirmation_count = $2, amount_matched = $3,
                     first_amount_matched_observed_at = COALESCE(first_amount_matched_observed_at, $4),
                     updated_at = NOW() WHERE id = $5")
            .bind(status).bind(i32::try_from(reported_confirmations).map_err(|_| PersistenceError::CorruptOrMissing)?).bind(amount_matched)
            .bind(first_amount_matched_observed_at).bind(invoice.id)
            .execute(&mut **tx).await.map_err(|_| PersistenceError::Unavailable)?;
        Ok(true)
    }

    async fn expire_unmatched_at_deadline_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        address: &str,
        observed_at: OffsetDateTime,
    ) -> Result<(), PersistenceError> {
        let address_lookup_hash = self.crypto.bitcoin_address_lookup_hash(address.as_bytes());
        sqlx::query(
            "UPDATE invoices SET payment_expired_at = $1, updated_at = NOW()
             WHERE bitcoin_address_lookup_hash = $2
               AND payment_deadline = $1
               AND first_amount_matched_observed_at IS NULL
               AND payment_expired_at IS NULL",
        )
        .bind(observed_at)
        .bind(address_lookup_hash.as_bytes().as_slice())
        .execute(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(())
    }

    /// Atomically resolves the creator, checks replay, allocates/reuses a
    /// reader, persists an invoice, and inserts ordered encrypted outbox work.
    pub async fn create_atomic(
        &self,
        mut input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        let creator_hash = self
            .crypto
            .lookup_hash(input.creator.to_string().as_bytes());
        let reader_hash = self.crypto.lookup_hash(input.reader.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(input.bundle_binding);
        let payment_request_hash = self.crypto.lookup_hash(input.payment_request_binding);

        let payment_in_hours =
            i64::try_from(input.payment_in_hours).map_err(|_| PersistenceError::InvalidInput)?;
        if payment_in_hours == 0 {
            return Err(PersistenceError::InvalidInput);
        }
        let payment_duration = Duration::seconds(
            payment_in_hours
                .checked_mul(60 * 60)
                .ok_or(PersistenceError::InvalidInput)?,
        );
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let invoice_created_at: OffsetDateTime =
            sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
        let payment_deadline = invoice_created_at
            .checked_add(payment_duration)
            .ok_or(PersistenceError::InvalidInput)?;
        input
            .payment_request_intent
            .set_proposal_expires_at(
                payment_deadline
                    .format(&Rfc3339)
                    .map_err(|_| PersistenceError::InvalidInput)?,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let creator = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, next_child_index \
             FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if lookup_hash(&creator.creator_lookup_hash)? != creator_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }

        if let Some(existing) = sqlx::query_as::<_, ExistingInvoice>(
            "SELECT id, payment_request_lookup_hash, invoice_created_at, payment_deadline, payment_in_hours FROM invoices \
             WHERE creator_id = $1 AND bundle_lookup_hash = $2 FOR UPDATE",
        )
        .bind(creator.id)
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        {
            if existing.payment_request_lookup_hash != payment_request_hash.as_bytes()
                || existing.payment_in_hours != payment_in_hours
            {
                return Err(PersistenceError::Conflict);
            }
            let assignment = self
                .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
                .await?
                .ok_or(PersistenceError::CorruptOrMissing)?;
            let payment_request_outbox = sqlx::query_as::<_, ExistingPaymentOutbox>(
                "SELECT id, depends_on_id FROM outbox \
                 WHERE invoice_id = $1 AND depends_on_id IS NOT NULL \
                 ORDER BY created_at, id LIMIT 1",
            )
            .bind(existing.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?
            .ok_or(PersistenceError::CorruptOrMissing)?;
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(AtomicInvoiceResult {
                invoice_id: existing.id,
                payment_request_outbox_id: payment_request_outbox.id,
                endpoint_publication_outbox_id: payment_request_outbox.depends_on_id,
                reader_assignment_id: assignment.id,
                reader_child_index: assignment.child_index,
                invoice_created_at: existing.invoice_created_at,
                payment_deadline: existing.payment_deadline,
                replayed: true,
            });
        }

        validate_intent(&input.payment_request_intent, input.reader, false)?;
        let (assignment, endpoint_publication_outbox_id, bitcoin_address) = match self
            .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
            .await?
        {
            // A row for this triple must have been returned by the replay lookup
            // above. Anything else is legacy/corrupt state, never a reusable address.
            Some(_) => return Err(PersistenceError::CorruptOrMissing),
            None => {
                let payloads = input
                    .new_reader_payloads
                    .for_child_index(creator.next_child_index)?;
                validate_intent(&payloads.endpoint_intent, input.reader, true)?;
                let assignment_id = Uuid::new_v4();
                let endpoint_plaintext = postcard::to_allocvec(&payloads.endpoint_intent)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                let envelope = encrypt_assignment(
                    &self.crypto,
                    creator_hash,
                    assignment_id,
                    creator.next_child_index,
                    &endpoint_plaintext,
                )?;
                sqlx::query(
                    "INSERT INTO reader_assignments \
                     (id, creator_id, reader_lookup_hash, bundle_lookup_hash, assignment_envelope) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(assignment_id)
                .bind(creator.id)
                .bind(reader_hash.as_bytes().as_slice())
                .bind(bundle_hash.as_bytes().as_slice())
                .bind(envelope.as_bytes())
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Conflict)?;
                sqlx::query(
                    "UPDATE creators SET next_child_index = next_child_index + 1, updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(creator.id)
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;

                let endpoint_id = Uuid::new_v4();
                let endpoint_envelope = self
                    .crypto
                    .encrypt(
                        &EnvelopeContext::outbox_semantic_intent(creator_hash, endpoint_id),
                        &endpoint_plaintext,
                    )
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;

                insert_outbox(
                    &mut tx,
                    OutboxInsert {
                        id: endpoint_id,
                        creator_id: creator.id,
                        invoice_id: None,
                        intent_envelope: endpoint_envelope.as_bytes(),
                        depends_on_id: None,
                        reader_assignment_id: Some(assignment_id),
                    },
                )
                .await?;
                (
                    Assignment {
                        id: assignment_id,
                        child_index: creator.next_child_index,
                    },
                    Some(endpoint_id),
                    payloads.bitcoin_address,
                )
            }
        };

        let payment_request_plaintext = postcard::to_allocvec(&input.payment_request_intent)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let invoice_id = Uuid::new_v4();
        let payment_record_plaintext = postcard::to_allocvec(&InvoicePaymentRecordV1 {
            version: 1,
            derivation_index: assignment.child_index,
            bitcoin_address: bitcoin_address.clone(),
            required_sats: input.required_sats,
        })
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment_record_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::invoice_payment_record(creator_hash, invoice_id),
                &payment_record_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let bitcoin_address_lookup_hash = self
            .crypto
            .bitcoin_address_lookup_hash(bitcoin_address.as_bytes());
        let derivation_index_lookup_hash = self
            .crypto
            .bitcoin_derivation_index_lookup_hash(creator_hash, assignment.child_index);
        let invoice_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::invoice(creator_hash, invoice_id),
                &payment_request_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        sqlx::query(
            "INSERT INTO invoices \
             (id, creator_id, reader_lookup_hash, bundle_lookup_hash, payment_request_lookup_hash, invoice_envelope, payment_record_envelope, bitcoin_address_lookup_hash, derivation_index_lookup_hash, payment_status, invoice_created_at, payment_deadline, payment_in_hours) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'undetected', $10, $11, $12)",
        )
        .bind(invoice_id)
        .bind(creator.id)
        .bind(reader_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .bind(payment_request_hash.as_bytes().as_slice())
        .bind(invoice_envelope.as_bytes())
        .bind(payment_record_envelope.as_bytes())
        .bind(bitcoin_address_lookup_hash.as_bytes().as_slice())
        .bind(derivation_index_lookup_hash.as_bytes().as_slice())
        .bind(invoice_created_at)
        .bind(payment_deadline)
        .bind(payment_in_hours)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Conflict)?;
        // Endpoint publication is invoice-scoped, not a reusable reader assignment.
        sqlx::query("UPDATE outbox SET invoice_id = $1 WHERE id = $2")
            .bind(invoice_id)
            .bind(endpoint_publication_outbox_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;

        let payment_request_outbox_id = Uuid::new_v4();
        let payment_request_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::outbox_semantic_intent(creator_hash, payment_request_outbox_id),
                &payment_request_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;

        insert_outbox(
            &mut tx,
            OutboxInsert {
                id: payment_request_outbox_id,
                creator_id: creator.id,
                invoice_id: Some(invoice_id),
                intent_envelope: payment_request_envelope.as_bytes(),
                depends_on_id: endpoint_publication_outbox_id,
                reader_assignment_id: None,
            },
        )
        .await?;

        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(AtomicInvoiceResult {
            invoice_id,
            payment_request_outbox_id,
            endpoint_publication_outbox_id,
            reader_assignment_id: assignment.id,
            reader_child_index: assignment.child_index,
            invoice_created_at,
            payment_deadline,
            replayed: false,
        })
    }

    fn decrypt_observation(
        &self,
        creator_hash: LookupHash,
        row: &BitcoinObservationRow,
    ) -> Result<BitcoinObservationV1, PersistenceError> {
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::bitcoin_observation_for_invoice(
                    creator_hash,
                    row.id,
                    row.invoice_id,
                ),
                &EncryptedEnvelope::from_bytes(row.observation_envelope.clone()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let record: BitcoinObservationV1 =
            postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
        if record.version != 1
            || parse_canonical_bitcoin_outpoint(&record.outpoint).is_err()
            || row.outpoint_lookup_hash
                != self
                    .crypto
                    .bitcoin_outpoint_lookup_hash(record.outpoint.as_bytes())
                    .as_bytes()
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok(record)
    }

    async fn load_assignment(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        creator_id: Uuid,
        reader_hash: LookupHash,
        bundle_hash: LookupHash,
        creator_hash: LookupHash,
    ) -> Result<Option<Assignment>, PersistenceError> {
        let row = sqlx::query_as::<_, AssignmentRow>(
            "SELECT id, assignment_envelope FROM reader_assignments \
             WHERE creator_id = $1 AND reader_lookup_hash = $2 AND bundle_lookup_hash = $3 FOR UPDATE",
        )
        .bind(creator_id)
        .bind(reader_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        row.map(|row| {
            decrypt_assignment(&self.crypto, creator_hash, row.id, &row.assignment_envelope).map(
                |child_index| Assignment {
                    id: row.id,
                    child_index,
                },
            )
        })
        .transpose()
    }
}

struct OutboxInsert<'a> {
    id: Uuid,
    creator_id: Uuid,
    invoice_id: Option<Uuid>,
    intent_envelope: &'a [u8],
    depends_on_id: Option<Uuid>,
    reader_assignment_id: Option<Uuid>,
}

async fn insert_outbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: OutboxInsert<'_>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        "INSERT INTO outbox \
         (id, creator_id, invoice_id, intent_envelope, status, depends_on_id, reader_assignment_id) \
         VALUES ($1, $2, $3, $4, 'queued', $5, $6)",
    )
    .bind(row.id)
    .bind(row.creator_id)
    .bind(row.invoice_id)
    .bind(row.intent_envelope)
    .bind(row.depends_on_id)
    .bind(row.reader_assignment_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| PersistenceError::Unavailable)?;
    Ok(())
}

fn validate_intent(
    intent: &DeliveryIntentV1,
    reader: &ReaderPubky,
    endpoint: bool,
) -> Result<(), PersistenceError> {
    intent
        .validate()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    if intent.reader_pubky() != reader.to_string() {
        return Err(PersistenceError::CorruptOrMissing);
    }
    match (endpoint, intent.operation()) {
        (true, DeliveryOperationV1::EndpointPublication { .. })
        | (false, DeliveryOperationV1::PaymentRequestProposal { .. }) => Ok(()),
        _ => Err(PersistenceError::CorruptOrMissing),
    }
}

fn lookup_hash_from_storage(bytes: &[u8]) -> Result<LookupHash, PersistenceError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    Ok(LookupHash::from_bytes(bytes))
}

fn lookup_hash(bytes: &[u8]) -> Result<LookupHash, PersistenceError> {
    lookup_hash_from_storage(bytes)
}

#[derive(sqlx::FromRow)]
struct CreatorRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    next_child_index: i64,
}

fn parse_canonical_bitcoin_outpoint(value: &str) -> Result<BitcoinOutpoint, PersistenceError> {
    let outpoint = value
        .parse::<bitcoin::OutPoint>()
        .map(BitcoinOutpoint::from_bitcoin)
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    if outpoint.canonical_text() != value {
        return Err(PersistenceError::CorruptOrMissing);
    }
    Ok(outpoint)
}

#[derive(sqlx::FromRow)]
struct BitcoinInvoiceRow {
    id: Uuid,
    payment_record_envelope: Vec<u8>,
    bitcoin_address_lookup_hash: Vec<u8>,
    payment_status: String,
    confirmation_count: i32,
    amount_matched: bool,
    payment_deadline: OffsetDateTime,
    first_amount_matched_observed_at: Option<OffsetDateTime>,
    payment_expired_at: Option<OffsetDateTime>,
    creator_lookup_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct BitcoinObservationRow {
    id: Uuid,
    invoice_id: Uuid,
    observation_envelope: Vec<u8>,
    outpoint_lookup_hash: Vec<u8>,
    confirmations: i32,
    present: bool,
}

#[derive(sqlx::FromRow)]
struct ObservationTargetRow {
    invoice_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    payment_record_envelope: Vec<u8>,
    bitcoin_address_lookup_hash: Vec<u8>,
    derivation_index_lookup_hash: Vec<u8>,
    observation_id: Option<Uuid>,
    observation_envelope: Option<Vec<u8>>,
    outpoint_lookup_hash: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct ExistingInvoice {
    id: Uuid,
    payment_request_lookup_hash: Vec<u8>,
    invoice_created_at: OffsetDateTime,
    payment_deadline: OffsetDateTime,
    payment_in_hours: i64,
}

#[derive(sqlx::FromRow)]
struct PreflightInvoice {
    payment_request_lookup_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct ExistingPaymentOutbox {
    id: Uuid,
    depends_on_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct PaymentStatusRow {
    payment_status: String,
    confirmation_count: i32,
    amount_matched: bool,
}

impl TryFrom<PaymentStatusRow> for PersistedPaymentStatus {
    type Error = PersistenceError;

    fn try_from(row: PaymentStatusRow) -> Result<Self, Self::Error> {
        let confirmations = u32::try_from(row.confirmation_count)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        match row.payment_status.as_str() {
            "undetected" => Ok(Self::Undetected),
            "detected" => Ok(Self::Detected {
                confirmations,
                amount_matched: row.amount_matched,
            }),
            "confirmed" => Ok(Self::Confirmed {
                confirmations,
                amount_matched: row.amount_matched,
            }),
            _ => Err(PersistenceError::CorruptOrMissing),
        }
    }
}

#[derive(sqlx::FromRow)]
struct AssignmentRow {
    id: Uuid,
    assignment_envelope: Vec<u8>,
}

struct Assignment {
    id: Uuid,
    child_index: i64,
}

#[derive(Serialize)]
struct ReaderAssignmentV1Ref<'a> {
    version: u8,
    child_index: i64,
    opaque_payload: &'a [u8],
}

#[derive(Deserialize)]
struct ReaderAssignmentV1 {
    version: u8,
    child_index: i64,
    opaque_payload: Vec<u8>,
}

fn encrypt_assignment(
    crypto: &Crypto,
    creator_hash: LookupHash,
    id: Uuid,
    child_index: i64,
    opaque_payload: &[u8],
) -> Result<EncryptedEnvelope, PersistenceError> {
    let bytes = Zeroizing::new(
        postcard::to_allocvec(&ReaderAssignmentV1Ref {
            version: 1,
            child_index,
            opaque_payload,
        })
        .map_err(|_| PersistenceError::CorruptOrMissing)?,
    );
    crypto
        .encrypt(
            &EnvelopeContext::reader_assignment(creator_hash, id),
            &bytes,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)
}

fn decrypt_assignment(
    crypto: &Crypto,
    creator_hash: LookupHash,
    id: Uuid,
    envelope: &[u8],
) -> Result<i64, PersistenceError> {
    let bytes = Zeroizing::new(
        crypto
            .decrypt(
                &EnvelopeContext::reader_assignment(creator_hash, id),
                &EncryptedEnvelope::from_bytes(envelope.to_vec()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?,
    );
    let assignment: ReaderAssignmentV1 =
        postcard::from_bytes(&bytes).map_err(|_| PersistenceError::CorruptOrMissing)?;
    if assignment.version != 1 || assignment.child_index < 0 {
        return Err(PersistenceError::CorruptOrMissing);
    }
    // The opaque payload is intentionally never inspected or returned here.
    let _ = assignment.opaque_payload;
    Ok(assignment.child_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_status_rejects_unknown_text_and_invalid_confirmation_counts() {
        for row in [
            PaymentStatusRow {
                payment_status: "unexpected".into(),
                confirmation_count: 0,
                amount_matched: false,
            },
            PaymentStatusRow {
                payment_status: "confirmed".into(),
                confirmation_count: -1,
                amount_matched: true,
            },
        ] {
            assert_eq!(
                PersistedPaymentStatus::try_from(row),
                Err(PersistenceError::CorruptOrMissing)
            );
        }
    }

    #[test]
    fn persisted_observations_accept_only_exact_canonical_outpoints() {
        let txid = "ab".repeat(32);
        assert!(parse_canonical_bitcoin_outpoint(&format!("{txid}:0")).is_ok());
        for malformed in [
            "legacy-outpoint:0".to_owned(),
            format!("{}:0", txid.to_ascii_uppercase()),
            format!("{txid}:00"),
            format!("{txid}:0:1"),
        ] {
            assert_eq!(
                parse_canonical_bitcoin_outpoint(&malformed),
                Err(PersistenceError::CorruptOrMissing)
            );
        }
    }
}
