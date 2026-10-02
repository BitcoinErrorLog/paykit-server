//! Atomic encrypted reader allocation, invoice, and delivery-intent persistence.
//!
//! The caller supplies closed, versioned semantic delivery intents. This
//! repository persists those complete SDK inputs inside Creator-bound AEAD
//! envelopes before reporting invoice success.

use std::sync::Arc;

use async_trait::async_trait;

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    application::{
        connection_status::ConnectionBinding,
        payment_request_status::{
            PaymentRequestStatusError, PaymentRequestStatusOperations, PaymentRequestStatusSummary,
            PaymentState,
        },
        payment_status::PersistedPaymentStatus,
        semantic_intent::DeliveryIntentV1,
    },
    bitcoin::{DirectBinding, ObservationAction, ObservationTarget, TrackedOutput},
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::{
        locks::{BundleId, CreatorPubky, ReaderPubky, parse_reader},
        payment::BitcoinOutpoint,
        payment_request_lifecycle::PaymentRequestLifecycleState,
    },
    persistence::{PaymentRequestLifecycleStore, PersistenceError, RequiredReceiveTarget},
};

/// Opaque inputs for one transactional invoice-allocation operation.
///
/// The allocation callback binds the invoice address into the complete Payment
/// Request before either the invoice or its outbox intent is persisted.
pub struct AtomicInvoiceInput<'a> {
    pub creator: &'a CreatorPubky,
    pub reader: &'a ReaderPubky,
    /// Creator-scoped idempotency key for the Locks bundle.
    pub bundle_binding: &'a [u8],
    /// Canonical addressed lock resource used for lock-wide drain membership.
    pub lock_resource_binding: &'a [u8],
    /// Exact payment-request binding for idempotent replay detection.
    pub payment_request_binding: &'a [u8],
    /// Derives the address and complete request only after this
    /// transaction has selected the permanent child index.
    pub invoice_payloads: &'a dyn InvoicePayloadFactory,
    /// Settlement-authoritative integer satoshi amount captured from the lock.
    pub required_sats: u64,
    /// Deployment-owned proposal acceptance window sampled from validated config.
    pub proposal_acceptance_seconds: u64,
    /// Deployment-owned payment window sampled from validated config.
    pub payment_window_seconds: u64,
}

/// Private payloads for a newly allocated invoice.
pub struct InvoicePayloads {
    pub payment_request_intent: DeliveryIntentV1,
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
pub trait InvoicePayloadFactory: Send + Sync {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError>;
}

/// Secret-free identifiers returned by an atomic allocation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicInvoiceResult {
    invoice_id: Uuid,
    payment_request_outbox_id: Uuid,
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
    /// Builds the result returned by an invoice persistence adapter.
    ///
    /// This is public because [`crate::application::create_invoice::InvoicePersistence`]
    /// is an injected port; alternate adapters must be able to report a completed
    /// allocation without depending on this module's private fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invoice_id: Uuid,
        payment_request_outbox_id: Uuid,
        reader_assignment_id: Uuid,
        reader_child_index: i64,
        invoice_created_at: OffsetDateTime,
        payment_deadline: OffsetDateTime,
        replayed: bool,
    ) -> Self {
        Self {
            invoice_id,
            payment_request_outbox_id,
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
        self.observation_targets_with_time(None).await
    }

    /// Loads non-final observation targets after durably expiring invoices whose
    /// inclusive payment deadline has passed without an amount-matched observation.
    /// Expiry is a business decision and does not stop factual reconciliation.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn observation_targets_at(
        &self,
        observed_at: OffsetDateTime,
    ) -> Result<Vec<ObservationTarget>, PersistenceError> {
        self.observation_targets_with_time(Some(observed_at)).await
    }

    async fn observation_targets_with_time(
        &self,
        observed_at: Option<OffsetDateTime>,
    ) -> Result<Vec<ObservationTarget>, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query(
            "SELECT id FROM invoices
             WHERE payment_expired_at IS NULL
               AND first_amount_matched_observed_at IS NULL
             ORDER BY id FOR UPDATE",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let observed_at = match observed_at {
            Some(observed_at) => observed_at,
            None => sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?,
        };
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
             WHERE NOT (invoices.payment_status = 'confirmed' \
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
        let existing = sqlx::query_as::<_, ExistingInvoice>(
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

    /// Loads the accepted Reader identity for one persisted invoice.
    ///
    /// This is a read-only lookup. It does not lock rows, replay invoice creation,
    /// or invoke any Paykit SDK operation.
    pub async fn connection_binding(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<ConnectionBinding>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_id.to_string().as_bytes());
        let row = sqlx::query_as::<_, ConnectionBindingRow>(
            "SELECT invoices.id, creators.creator_lookup_hash, invoices.invoice_envelope \
             FROM invoices JOIN creators ON creators.id = invoices.creator_id \
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        row.map(|row| {
            if lookup_hash(&row.creator_lookup_hash)? != creator_hash {
                return Err(PersistenceError::CorruptOrMissing);
            }
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::invoice(creator_hash, row.id),
                    &EncryptedEnvelope::from_bytes(row.invoice_envelope),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let intent = DeliveryIntentV1::decode(&plaintext)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let reader = parse_reader(intent.reader_pubky())
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            Ok(ConnectionBinding::new(reader))
        })
        .transpose()
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
        let existing = sqlx::query_as::<_, ReplayInvoice>(
            "SELECT id, payment_request_lookup_hash, invoice_envelope, invoice_created_at,
                    payment_deadline
             FROM invoices \
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
        self.validate_replay_intent(creator_hash, existing.id, existing.invoice_envelope, reader)?;
        let assignment = self
            .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
            .await?
            .ok_or(PersistenceError::CorruptOrMissing)?;
        let payment_outbox = sqlx::query_as::<_, ExistingPaymentOutbox>(
            "SELECT id FROM outbox
             WHERE invoice_id = $1 AND intent_kind = 'payment_request_proposal'",
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
            reader_assignment_id: assignment.id,
            reader_child_index: assignment.child_index,
            invoice_created_at: existing.invoice_created_at,
            payment_deadline: existing.payment_deadline,
            replayed: true,
        })
    }

    /// Reads only durable Bitcoin facts for one creator-scoped bundle.
    pub async fn payment_status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
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

    /// Checks invoice existence without requiring a lifecycle projection.
    pub async fn invoice_exists(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<bool, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_id.to_string().as_bytes());
        sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                 FROM invoices
                 JOIN creators ON creators.id = invoices.creator_id
                 WHERE creators.creator_lookup_hash = $1
                   AND invoices.bundle_lookup_hash = $2
             )",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    pub async fn payment_request_status_after_receive(
        &self,
        lifecycles: &PaymentRequestLifecycleStore,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
        evidence: &[RequiredReceiveTarget],
    ) -> Result<Option<PaymentRequestStatusSummary>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_id.to_string().as_bytes());
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let creator_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE")
                .bind(creator_hash.as_bytes().as_slice())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
        let Some(creator_id) = creator_id else {
            transaction
                .commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(None);
        };
        let invoice: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT id, lock_resource_lookup_hash
             FROM invoices
             WHERE creator_id = $1 AND bundle_lookup_hash = $2",
        )
        .bind(creator_id)
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some((invoice_id, lock_hash)) = invoice else {
            transaction
                .commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(None);
        };
        let _: i64 = sqlx::query_scalar(
            "SELECT current_generation
             FROM lock_payment_generations
             WHERE creator_id = $1 AND lock_resource_lookup_hash = $2
             FOR UPDATE",
        )
        .bind(creator_id)
        .bind(&lock_hash)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let _: Uuid = sqlx::query_scalar("SELECT id FROM invoices WHERE id = $1 FOR UPDATE")
            .bind(invoice_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;

        let current = lifecycles
            .required_receive_targets_for_bundle_in_transaction(
                &mut transaction,
                creator_id,
                &bundle_hash,
            )
            .await?;
        if !PaymentRequestLifecycleStore::receive_evidence_covers(&current, evidence) {
            return Err(PersistenceError::Unavailable);
        }
        let summary = self
            .payment_request_status_by_invoice(&mut transaction, invoice_id)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(summary)
    }

    async fn payment_request_status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<PaymentRequestStatusSummary>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_id.to_string().as_bytes());
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let invoice_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT invoices.id
             FROM invoices
             JOIN creators ON creators.id = invoices.creator_id
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let summary = match invoice_id {
            Some(invoice_id) => {
                self.payment_request_status_by_invoice(&mut transaction, invoice_id)
                    .await?
            }
            None => None,
        };
        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(summary)
    }

    async fn payment_request_status_by_invoice(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        invoice_id: Uuid,
    ) -> Result<Option<PaymentRequestStatusSummary>, PersistenceError> {
        let row = sqlx::query_as::<_, PaymentRequestStatusRow>(
            "SELECT lifecycle.request_state, invoices.payment_status,
                    invoices.confirmation_count, invoices.amount_matched,
                    invoices.invoice_created_at, invoices.payment_deadline,
                    invoices.payment_expired_at
             FROM invoices
             JOIN creators ON creators.id = invoices.creator_id
             LEFT JOIN LATERAL (
                 SELECT request_state
                 FROM payment_request_lifecycles
                 WHERE invoice_id = invoices.id
                 ORDER BY CASE request_state
                     WHEN 'invalid_conflict' THEN 9
                     WHEN 'recovery_required' THEN 8
                     WHEN 'proof_submitted' THEN 7
                     WHEN 'active_recurring' THEN 6
                     WHEN 'accepted' THEN 5
                     WHEN 'proposed' THEN 4
                     WHEN 'proposal_expired' THEN 0
                     WHEN 'rejected' THEN 0
                     WHEN 'canceled' THEN 0
                     ELSE -1
                 END DESC, last_event_at DESC, request_state DESC
                 LIMIT 1
             ) AS lifecycle ON TRUE
             WHERE invoices.id = $1",
        )
        .bind(invoice_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        row.map(PaymentRequestStatusSummary::try_from).transpose()
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
        self.apply_bitcoin_observation_with_time(
            address,
            outpoint,
            observed_sats,
            confirmations,
            present,
            None,
        )
        .await
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub async fn apply_bitcoin_observation_at(
        &self,
        address: &str,
        outpoint: &BitcoinOutpoint,
        observed_sats: u64,
        confirmations: u32,
        present: bool,
        observed_at: OffsetDateTime,
    ) -> Result<bool, PersistenceError> {
        self.apply_bitcoin_observation_with_time(
            address,
            outpoint,
            observed_sats,
            confirmations,
            present,
            Some(observed_at),
        )
        .await
    }

    async fn apply_bitcoin_observation_with_time(
        &self,
        address: &str,
        outpoint: &BitcoinOutpoint,
        observed_sats: u64,
        confirmations: u32,
        present: bool,
        observed_at: Option<OffsetDateTime>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let address_lookup_hash = self.crypto.bitcoin_address_lookup_hash(address.as_bytes());
        sqlx::query("SELECT id FROM invoices WHERE bitcoin_address_lookup_hash = $1 FOR UPDATE")
            .bind(address_lookup_hash.as_bytes().as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let observed_at = match observed_at {
            Some(observed_at) => observed_at,
            None => sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?,
        };
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

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) async fn apply_bitcoin_observation_batch_at(
        &self,
        observations: &[BitcoinObservationInput],
        observed_at: OffsetDateTime,
    ) -> Result<usize, PersistenceError> {
        self.apply_bitcoin_observation_batch_with_time(observations, Some(observed_at))
            .await
    }

    pub(crate) async fn apply_bitcoin_observation_batch(
        &self,
        observations: &[BitcoinObservationInput],
    ) -> Result<usize, PersistenceError> {
        self.apply_bitcoin_observation_batch_with_time(observations, None)
            .await
    }

    async fn apply_bitcoin_observation_batch_with_time(
        &self,
        observations: &[BitcoinObservationInput],
        observed_at: Option<OffsetDateTime>,
    ) -> Result<usize, PersistenceError> {
        if observations.is_empty() {
            return Ok(0);
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let address_lookup_hashes = observations
            .iter()
            .map(|observation| {
                self.crypto
                    .bitcoin_address_lookup_hash(observation.address.as_bytes())
                    .as_bytes()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        sqlx::query(
            "SELECT id FROM invoices
             WHERE bitcoin_address_lookup_hash = ANY($1::bytea[])
             ORDER BY id FOR UPDATE",
        )
        .bind(&address_lookup_hashes)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let observed_at = match observed_at {
            Some(observed_at) => observed_at,
            None => sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?,
        };
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
        let outpoint_lookup_hash = self
            .crypto
            .bitcoin_outpoint_lookup_hash(outpoint.as_bytes());
        let late_unmatched = invoice.first_amount_matched_observed_at.is_none();
        let known_timely_outpoint = if amount_matched && observed_at > invoice.payment_deadline {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (
                     SELECT 1 FROM invoice_timely_amount_matched_outpoints
                     WHERE invoice_id = $1 AND outpoint_lookup_hash = $2
                 )",
            )
            .bind(invoice.id)
            .bind(outpoint_lookup_hash.as_bytes().as_slice())
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?
        } else {
            false
        };
        let late_different_match = amount_matched && !known_timely_outpoint;
        let should_expire =
            observed_at > invoice.payment_deadline && (late_unmatched || late_different_match);

        // Final matching outputs are no longer monitored. Keep their persisted
        // six-confirmation fact immutable even if a stale observer reports later.
        if invoice.payment_status == "confirmed"
            && invoice.confirmation_count == 6
            && invoice.amount_matched
        {
            return Ok(true);
        }

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

        // Provider batches may report a replacement before the stale absence
        // of the previously tracked output. That absence must not reactivate
        // the historical row or overwrite the replacement's current facts.
        if !present
            && active_record
                .as_ref()
                .is_some_and(|record| record.outpoint != outpoint)
        {
            return Ok(true);
        }

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
        if amount_matched && observed_at <= invoice.payment_deadline {
            sqlx::query(
                "INSERT INTO invoice_timely_amount_matched_outpoints (
                     invoice_id, outpoint_lookup_hash
                 ) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(invoice.id)
            .bind(outpoint_lookup_hash.as_bytes().as_slice())
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        sqlx::query("UPDATE invoices SET payment_status = $1, confirmation_count = $2, amount_matched = $3,
                     first_amount_matched_observed_at = COALESCE(first_amount_matched_observed_at, $4),
                     first_amount_matched_outpoint_lookup_hash = CASE WHEN $3 THEN COALESCE(first_amount_matched_outpoint_lookup_hash, $5) ELSE first_amount_matched_outpoint_lookup_hash END,
                     updated_at = NOW() WHERE id = $6")
            .bind(status).bind(i32::try_from(reported_confirmations).map_err(|_| PersistenceError::CorruptOrMissing)?).bind(amount_matched)
            .bind(first_amount_matched_observed_at).bind(outpoint_lookup_hash.as_bytes().as_slice()).bind(invoice.id)
            .execute(&mut **tx).await.map_err(|_| PersistenceError::Unavailable)?;
        if should_expire {
            sqlx::query(
                "UPDATE invoices
                 SET payment_expired_at = COALESCE(payment_expired_at, $1), updated_at = NOW()
                 WHERE id = $2",
            )
            .bind(observed_at)
            .bind(invoice.id)
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
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
        input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        let creator_hash = self
            .crypto
            .lookup_hash(input.creator.to_string().as_bytes());
        let reader_hash = self.crypto.lookup_hash(input.reader.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(input.bundle_binding);
        let lock_resource_hash = self.crypto.lookup_hash(input.lock_resource_binding);
        let payment_request_hash = self.crypto.lookup_hash(input.payment_request_binding);

        let proposal_acceptance_seconds = i64::try_from(input.proposal_acceptance_seconds)
            .map_err(|_| PersistenceError::InvalidInput)?;
        let payment_window_seconds = i64::try_from(input.payment_window_seconds)
            .map_err(|_| PersistenceError::InvalidInput)?;
        if proposal_acceptance_seconds == 0 || proposal_acceptance_seconds >= payment_window_seconds
        {
            return Err(PersistenceError::InvalidInput);
        }
        let proposal_duration = Duration::seconds(proposal_acceptance_seconds);
        let payment_duration = Duration::seconds(payment_window_seconds);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
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
        let invoice_created_at: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let proposal_expires_at = invoice_created_at
            .checked_add(proposal_duration)
            .ok_or(PersistenceError::InvalidInput)?;
        let payment_deadline = invoice_created_at
            .checked_add(payment_duration)
            .ok_or(PersistenceError::InvalidInput)?;

        if let Some(existing) = sqlx::query_as::<_, ReplayInvoice>(
            "SELECT id, payment_request_lookup_hash, invoice_envelope, invoice_created_at,
                    payment_deadline
             FROM invoices \
             WHERE creator_id = $1 AND bundle_lookup_hash = $2 FOR UPDATE",
        )
        .bind(creator.id)
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        {
            if existing.payment_request_lookup_hash != payment_request_hash.as_bytes() {
                return Err(PersistenceError::Conflict);
            }
            self.validate_replay_intent(
                creator_hash,
                existing.id,
                existing.invoice_envelope,
                input.reader,
            )?;
            let assignment = self
                .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
                .await?
                .ok_or(PersistenceError::CorruptOrMissing)?;
            let payment_request_outbox = sqlx::query_as::<_, ExistingPaymentOutbox>(
                "SELECT id FROM outbox
                 WHERE invoice_id = $1 AND intent_kind = 'payment_request_proposal'",
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
                reader_assignment_id: assignment.id,
                reader_child_index: assignment.child_index,
                invoice_created_at: existing.invoice_created_at,
                payment_deadline: existing.payment_deadline,
                replayed: true,
            });
        }

        sqlx::query(
            "INSERT INTO lock_payment_generations
                 (creator_id, lock_resource_lookup_hash)
             VALUES ($1, $2)
             ON CONFLICT (creator_id, lock_resource_lookup_hash) DO NOTHING",
        )
        .bind(creator.id)
        .bind(lock_resource_hash.as_bytes().as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let (lock_resource_generation, active_drain_id): (i64, Option<Uuid>) = sqlx::query_as(
            "SELECT current_generation, active_drain_id
                 FROM lock_payment_generations
                 WHERE creator_id = $1 AND lock_resource_lookup_hash = $2
                 FOR UPDATE",
        )
        .bind(creator.id)
        .bind(lock_resource_hash.as_bytes().as_slice())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if lock_resource_generation < 0 {
            return Err(PersistenceError::CorruptOrMissing);
        }
        if active_drain_id.is_some() {
            return Err(PersistenceError::Conflict);
        }

        let (assignment, payloads) = match self
            .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
            .await?
        {
            // A row for this triple must have been returned by the replay lookup
            // above. Anything else is inconsistent state, never a reusable address.
            Some(_) => return Err(PersistenceError::CorruptOrMissing),
            None => {
                let mut payloads = input
                    .invoice_payloads
                    .for_child_index(creator.next_child_index)?;
                payloads
                    .payment_request_intent
                    .set_deadlines(
                        proposal_expires_at
                            .format(&Rfc3339)
                            .map_err(|_| PersistenceError::InvalidInput)?,
                        payment_deadline
                            .format(&Rfc3339)
                            .map_err(|_| PersistenceError::InvalidInput)?,
                    )
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                validate_intent(&payloads.payment_request_intent, input.reader)?;
                let terms = payloads
                    .payment_request_intent
                    .terms()
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                if terms.payment_endpoints.len() != 1
                    || terms.payment_endpoints.values().any(|payload| {
                        serde_json::from_str::<serde_json::Value>(payload).ok()
                            != Some(serde_json::json!({ "value": payloads.bitcoin_address }))
                    })
                {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                let assignment_id = Uuid::new_v4();
                let envelope = encrypt_assignment(
                    &self.crypto,
                    creator_hash,
                    assignment_id,
                    creator.next_child_index,
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

                (
                    Assignment {
                        id: assignment_id,
                        child_index: creator.next_child_index,
                    },
                    payloads,
                )
            }
        };

        let proposal_lookup_hash = self.crypto.payment_request_proposal_lookup_hash(
            payloads
                .payment_request_intent
                .proposal_payment_reference()
                .map_err(|_| PersistenceError::CorruptOrMissing)?
                .as_bytes(),
        );
        let payment_request_plaintext = postcard::to_allocvec(&payloads.payment_request_intent)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let invoice_id = Uuid::new_v4();
        let payment_record_plaintext = postcard::to_allocvec(&InvoicePaymentRecordV1 {
            version: 1,
            derivation_index: assignment.child_index,
            bitcoin_address: payloads.bitcoin_address.clone(),
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
            .bitcoin_address_lookup_hash(payloads.bitcoin_address.as_bytes());
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
             (id, creator_id, reader_lookup_hash, bundle_lookup_hash, lock_resource_lookup_hash,
              lock_resource_generation, payment_request_lookup_hash, invoice_envelope,
              payment_record_envelope, bitcoin_address_lookup_hash,
              derivation_index_lookup_hash, payment_status, invoice_created_at,
              proposal_expires_at, payment_deadline, proposal_acceptance_seconds,
              payment_window_seconds) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'undetected',
                     $12, $13, $14, $15, $16)",
        )
        .bind(invoice_id)
        .bind(creator.id)
        .bind(reader_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .bind(lock_resource_hash.as_bytes().as_slice())
        .bind(lock_resource_generation)
        .bind(payment_request_hash.as_bytes().as_slice())
        .bind(invoice_envelope.as_bytes())
        .bind(payment_record_envelope.as_bytes())
        .bind(bitcoin_address_lookup_hash.as_bytes().as_slice())
        .bind(derivation_index_lookup_hash.as_bytes().as_slice())
        .bind(invoice_created_at)
        .bind(proposal_expires_at)
        .bind(payment_deadline)
        .bind(proposal_acceptance_seconds)
        .bind(payment_window_seconds)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Conflict)?;
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
                invoice_id,
                intent_envelope: payment_request_envelope.as_bytes(),
                intent_kind: "payment_request_proposal",
                proposal_lookup_hash: Some(proposal_lookup_hash.as_bytes()),
            },
        )
        .await?;

        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(AtomicInvoiceResult {
            invoice_id,
            payment_request_outbox_id,
            reader_assignment_id: assignment.id,
            reader_child_index: assignment.child_index,
            invoice_created_at,
            payment_deadline,
            replayed: false,
        })
    }

    fn validate_replay_intent(
        &self,
        creator_hash: LookupHash,
        invoice_id: Uuid,
        invoice_envelope: Vec<u8>,
        reader: &ReaderPubky,
    ) -> Result<(), PersistenceError> {
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::invoice(creator_hash, invoice_id),
                &EncryptedEnvelope::from_bytes(invoice_envelope),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let intent =
            DeliveryIntentV1::decode(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
        validate_intent(&intent, reader)?;
        Ok(())
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

#[async_trait]
impl PaymentRequestStatusOperations for InvoiceStore {
    async fn lookup(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<PaymentRequestStatusSummary>, PaymentRequestStatusError> {
        self.payment_request_status(creator, bundle_id)
            .await
            .map_err(|_| PaymentRequestStatusError::Unavailable)
    }
}

struct OutboxInsert<'a> {
    id: Uuid,
    creator_id: Uuid,
    invoice_id: Uuid,
    intent_envelope: &'a [u8],
    intent_kind: &'static str,
    proposal_lookup_hash: Option<&'a [u8; 32]>,
}

async fn insert_outbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: OutboxInsert<'_>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        "INSERT INTO outbox \
         (id, creator_id, invoice_id, intent_envelope, intent_kind, status, proposal_lookup_hash) \
         VALUES ($1, $2, $3, $4, $5, 'queued', $6)",
    )
    .bind(row.id)
    .bind(row.creator_id)
    .bind(row.invoice_id)
    .bind(row.intent_envelope)
    .bind(row.intent_kind)
    .bind(row.proposal_lookup_hash.map(<[u8; 32]>::as_slice))
    .execute(&mut **tx)
    .await
    .map_err(|_| PersistenceError::Unavailable)?;
    Ok(())
}

fn validate_intent(
    intent: &DeliveryIntentV1,
    reader: &ReaderPubky,
) -> Result<(), PersistenceError> {
    intent
        .validate()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    if intent.reader_pubky() != reader.to_string() {
        return Err(PersistenceError::CorruptOrMissing);
    }
    Ok(())
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
    payment_request_lookup_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct ReplayInvoice {
    id: Uuid,
    payment_request_lookup_hash: Vec<u8>,
    invoice_envelope: Vec<u8>,
    invoice_created_at: OffsetDateTime,
    payment_deadline: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct ExistingPaymentOutbox {
    id: Uuid,
}

#[derive(sqlx::FromRow)]
struct PaymentStatusRow {
    payment_status: String,
    confirmation_count: i32,
    amount_matched: bool,
}

#[derive(sqlx::FromRow)]
struct ConnectionBindingRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    invoice_envelope: Vec<u8>,
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
struct PaymentRequestStatusRow {
    request_state: Option<String>,
    payment_status: String,
    confirmation_count: i32,
    amount_matched: bool,
    invoice_created_at: OffsetDateTime,
    payment_deadline: OffsetDateTime,
    payment_expired_at: Option<OffsetDateTime>,
}

impl TryFrom<PaymentRequestStatusRow> for PaymentRequestStatusSummary {
    type Error = PersistenceError;

    fn try_from(row: PaymentRequestStatusRow) -> Result<Self, Self::Error> {
        let request_state = row
            .request_state
            .as_deref()
            .and_then(PaymentRequestLifecycleState::parse)
            .ok_or(PersistenceError::CorruptOrMissing)?;
        let payment_state = if row.payment_expired_at.is_some() {
            PaymentState::Expired
        } else {
            match row.payment_status.as_str() {
                "undetected" => PaymentState::Undetected,
                "detected" => PaymentState::Detected,
                "confirmed" => PaymentState::Confirmed,
                _ => return Err(PersistenceError::CorruptOrMissing),
            }
        };
        let confirmations = u32::try_from(row.confirmation_count)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        Ok(PaymentRequestStatusSummary::new(
            request_state,
            payment_state,
            row.invoice_created_at,
            row.payment_deadline,
            confirmations,
            row.amount_matched,
        ))
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

#[derive(Serialize, Deserialize)]
struct ReaderAssignmentV1 {
    version: u8,
    child_index: i64,
}

fn encrypt_assignment(
    crypto: &Crypto,
    creator_hash: LookupHash,
    id: Uuid,
    child_index: i64,
) -> Result<EncryptedEnvelope, PersistenceError> {
    let bytes = Zeroizing::new(
        postcard::to_allocvec(&ReaderAssignmentV1 {
            version: 1,
            child_index,
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
