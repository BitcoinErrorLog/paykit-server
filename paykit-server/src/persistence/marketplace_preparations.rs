//! Durable unpublished Marketplace invoice preparation.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

mod usdt;

use crate::{
    application::{
        marketplace_status::{
            MarketplaceBitcoinStatus, MarketplaceInvoiceStatus, MarketplaceStatusError,
            MarketplaceStatusPersistence,
        },
        marketplace_terms::{MarketplaceQuote, MarketplaceTerms},
        semantic_intent::DeliveryIntentV1,
        setup_status::AcceptedAsset,
    },
    bitcoin::{DirectBinding, ObservationAction, ObservationTarget, TrackedOutput},
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::{
        invoice::CriterionAsset,
        locks::{CreatorPubky, ReaderPubky, parse_reader},
    },
    persistence::{BitcoinObservationInput, InvoicePaymentRecordV1, PersistenceError},
};

const OPERATION_BINDING_UNIQUE_CONSTRAINT: &str = "marketplace_preparation_operation_binding_key";

/// Opaque inputs for one atomic Marketplace preparation.
pub struct MarketplacePreparationInput<'a> {
    pub creator: &'a CreatorPubky,
    pub reader: &'a ReaderPubky,
    pub reference: &'a str,
    pub operation_id: &'a str,
    pub request_binding: &'a [u8],
    /// Exact amount in `asset`'s base units.
    pub amount: u64,
    /// Denomination of `amount`.
    pub asset: CriterionAsset,
    pub payment_window_seconds: u64,
    pub prepare_ttl_seconds: u64,
    /// Absolute end of the preparation on the database clock, fixed by the caller when
    /// it accepted the quote. `None` only for an exact replay, which creates nothing.
    pub prepare_deadline: Option<OffsetDateTime>,
    pub payloads: &'a dyn MarketplacePreparationPayloadFactory,
}

/// Immutable caller binding used to activate one prepared Marketplace invoice.
pub struct MarketplaceActivationInput<'a> {
    pub creator: &'a CreatorPubky,
    pub invoice_id: Uuid,
    pub amount: u64,
    pub asset: CriterionAsset,
    pub proposal_acceptance_window: std::time::Duration,
}

/// Closed lifecycle failures used to preserve caller recovery semantics.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MarketplaceLifecyclePersistenceError {
    /// Prepared invoice expired before activation and needs a new attempt.
    #[error("marketplace payment preparation expired")]
    PrepareExpired,
    /// A terminal lifecycle transition already won.
    #[error("marketplace payment lifecycle is terminal")]
    LifecycleTerminal,
    /// Void lost to activation; payment remains live and must still be observed.
    #[error("marketplace invoice is already active")]
    InvoiceActive,
    /// Caller amount or asset differs from the authoritative prepared terms.
    #[error("marketplace payment total does not match")]
    TotalMismatch,
    /// A different immutable business outcome was already recorded.
    #[error("marketplace business resolution conflicts with persisted outcome")]
    ResolutionConflict,
    /// Generic persistence or validation failure.
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

/// Complete private proposal material derived after the transaction reserves an address index.
pub struct MarketplacePreparationPayloads {
    pub payment_request_intent: DeliveryIntentV1,
}

/// Derives immutable proposal material from a transaction-reserved child index.
pub trait MarketplacePreparationPayloadFactory: Send + Sync {
    fn for_child_index(
        &self,
        child_index: i64,
    ) -> Result<MarketplacePreparationPayloads, PersistenceError>;
}

/// Side-effect-free result of checking one scoped operation identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarketplacePreparationPreflight {
    New,
    ExactReplay,
    Conflict,
}

/// Secret-free result of preparing an unpublished Marketplace invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketplacePreparationResult {
    invoice_id: Uuid,
    terms: MarketplaceTerms,
    quote: MarketplaceQuote,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
    replayed: bool,
}

impl MarketplacePreparationResult {
    /// Builds a result returned by an injected persistence adapter.
    pub fn new(
        invoice_id: Uuid,
        terms: MarketplaceTerms,
        quote: MarketplaceQuote,
        prepared_at: OffsetDateTime,
        prepare_expires_at: OffsetDateTime,
        replayed: bool,
    ) -> Self {
        Self {
            invoice_id,
            terms,
            quote,
            prepared_at,
            prepare_expires_at,
            replayed,
        }
    }

    pub fn invoice_id(&self) -> Uuid {
        self.invoice_id
    }

    pub fn terms(&self) -> &MarketplaceTerms {
        &self.terms
    }

    pub fn quote(&self) -> &MarketplaceQuote {
        &self.quote
    }

    pub fn prepared_at(&self) -> OffsetDateTime {
        self.prepared_at
    }

    pub fn prepare_expires_at(&self) -> OffsetDateTime {
        self.prepare_expires_at
    }

    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Secret-free stored activation response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketplaceActivationResult {
    invoice_id: Uuid,
    activated_at: OffsetDateTime,
    payment_deadline: OffsetDateTime,
    terms: MarketplaceTerms,
    quote: MarketplaceQuote,
    replayed: bool,
}

impl MarketplaceActivationResult {
    /// Builds a result returned by an injected persistence adapter.
    pub fn new(
        invoice_id: Uuid,
        activated_at: OffsetDateTime,
        payment_deadline: OffsetDateTime,
        terms: MarketplaceTerms,
        quote: MarketplaceQuote,
        replayed: bool,
    ) -> Self {
        Self {
            invoice_id,
            activated_at,
            payment_deadline,
            terms,
            quote,
            replayed,
        }
    }

    pub fn invoice_id(&self) -> Uuid {
        self.invoice_id
    }
    pub fn activated_at(&self) -> OffsetDateTime {
        self.activated_at
    }
    pub fn payment_deadline(&self) -> OffsetDateTime {
        self.payment_deadline
    }
    pub fn terms(&self) -> &MarketplaceTerms {
        &self.terms
    }
    pub fn quote(&self) -> &MarketplaceQuote {
        &self.quote
    }
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Secret-free stored void response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketplaceVoidResult {
    invoice_id: Uuid,
    voided_at: OffsetDateTime,
    replayed: bool,
}

impl MarketplaceVoidResult {
    /// Builds a result returned by an injected persistence adapter.
    pub fn new(invoice_id: Uuid, voided_at: OffsetDateTime, replayed: bool) -> Self {
        Self {
            invoice_id,
            voided_at,
            replayed,
        }
    }

    pub fn invoice_id(&self) -> Uuid {
        self.invoice_id
    }
    pub fn voided_at(&self) -> OffsetDateTime {
        self.voided_at
    }
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Closed Marketplace business outcome vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarketplaceResolutionOutcome {
    PaidManually,
    Refunded,
    Abandoned,
}

impl MarketplaceResolutionOutcome {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "paid_manually" => Some(Self::PaidManually),
            "refunded" => Some(Self::Refunded),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PaidManually => "paid_manually",
            Self::Refunded => "refunded",
            Self::Abandoned => "abandoned",
        }
    }
}

/// Secret-free stored Marketplace resolution response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketplaceResolutionResult {
    invoice_id: Uuid,
    outcome: MarketplaceResolutionOutcome,
    resolved_at: OffsetDateTime,
    replayed: bool,
}

impl MarketplaceResolutionResult {
    /// Builds a result returned by an injected persistence adapter.
    pub fn new(
        invoice_id: Uuid,
        outcome: MarketplaceResolutionOutcome,
        resolved_at: OffsetDateTime,
        replayed: bool,
    ) -> Self {
        Self {
            invoice_id,
            outcome,
            resolved_at,
            replayed,
        }
    }

    pub fn invoice_id(&self) -> Uuid {
        self.invoice_id
    }
    pub fn outcome(&self) -> MarketplaceResolutionOutcome {
        self.outcome
    }
    pub fn resolved_at(&self) -> OffsetDateTime {
        self.resolved_at
    }
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

/// PostgreSQL-backed Marketplace preparation store.
#[derive(Clone, Debug)]
pub struct MarketplacePreparationStore {
    pool: PgPool,
    crypto: Arc<Crypto>,
}

/// Preparation envelope as written by rc11 through rc16: Bitcoin only, sats total.
#[derive(Serialize, Deserialize)]
struct PreparationEnvelopeV1 {
    version: u8,
    operation_id: String,
    request_binding: Vec<u8>,
    reader: String,
    reference: String,
    total_sats: u64,
    payment_window_seconds: u64,
    prepare_ttl_seconds: u64,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
    child_index: i64,
    payment_request_intent: DeliveryIntentV1,
}

/// Current preparation envelope. `version` is the stored version: 2 is written, 1
/// is only read, as `{BTC, total_sats, [BTC]}`.
#[derive(Serialize, Deserialize)]
struct PreparationEnvelope {
    version: u8,
    operation_id: String,
    request_binding: Vec<u8>,
    reader: String,
    reference: String,
    terms: MarketplaceTerms,
    payment_window_seconds: u64,
    prepare_ttl_seconds: u64,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
    child_index: i64,
    payment_request_intent: DeliveryIntentV1,
}

impl PreparationEnvelope {
    fn terms_match(&self, amount: u64, asset: CriterionAsset) -> bool {
        self.terms.amount() == amount && self.terms.asset() == asset
    }

    fn quote(&self) -> Result<MarketplaceQuote, PersistenceError> {
        MarketplaceQuote::from_intent(&self.payment_request_intent, &self.terms)
            .map_err(|_| PersistenceError::CorruptOrMissing)
    }

    fn decode(plaintext: &[u8]) -> Result<Self, PersistenceError> {
        match plaintext.first() {
            Some(1) => {
                let legacy: PreparationEnvelopeV1 = postcard::from_bytes(plaintext)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                Ok(Self {
                    version: 1,
                    operation_id: legacy.operation_id,
                    request_binding: legacy.request_binding,
                    reader: legacy.reader,
                    reference: legacy.reference,
                    terms: MarketplaceTerms::new(
                        legacy.total_sats,
                        CriterionAsset::Btc,
                        [AcceptedAsset::Btc],
                    )
                    .map_err(|_| PersistenceError::CorruptOrMissing)?,
                    payment_window_seconds: legacy.payment_window_seconds,
                    prepare_ttl_seconds: legacy.prepare_ttl_seconds,
                    prepared_at: legacy.prepared_at,
                    prepare_expires_at: legacy.prepare_expires_at,
                    child_index: legacy.child_index,
                    payment_request_intent: legacy.payment_request_intent,
                })
            }
            Some(2) => {
                postcard::from_bytes(plaintext).map_err(|_| PersistenceError::CorruptOrMissing)
            }
            _ => Err(PersistenceError::CorruptOrMissing),
        }
    }
}

struct CreatorRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    next_child_index: i64,
}

struct PreparationRow {
    id: Uuid,
    operation_lookup_hash: Vec<u8>,
    request_lookup_hash: Vec<u8>,
    reader_lookup_hash: Vec<u8>,
    preparation_envelope: Vec<u8>,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
}

struct LifecycleRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    preparation_envelope: Vec<u8>,
    state: String,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
    activated_at: Option<OffsetDateTime>,
    payment_deadline: Option<OffsetDateTime>,
    voided_at: Option<OffsetDateTime>,
    business_outcome: Option<String>,
    resolved_at: Option<OffsetDateTime>,
}

#[derive(sqlx::FromRow)]
struct MarketplaceObservationTargetRow {
    preparation_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    payment_record_envelope: Vec<u8>,
    bitcoin_address_lookup_hash: Vec<u8>,
    derivation_index_lookup_hash: Vec<u8>,
    activated_at: OffsetDateTime,
    observation_id: Option<Uuid>,
    observation_envelope: Option<Vec<u8>>,
    outpoint_lookup_hash: Option<Vec<u8>>,
    confirmations: Option<i32>,
    present: Option<bool>,
    first_observed_at: Option<OffsetDateTime>,
}

#[derive(sqlx::FromRow)]
struct StoredSettlement {
    payment_record_envelope: Vec<u8>,
    bitcoin_address_lookup_hash: Option<Vec<u8>>,
    derivation_index_lookup_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct MarketplaceSettlementRow {
    preparation_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    payment_record_envelope: Vec<u8>,
    bitcoin_address_lookup_hash: Option<Vec<u8>>,
    derivation_index_lookup_hash: Vec<u8>,
    activated_at: OffsetDateTime,
    payment_deadline: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct MarketplaceStatusRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    preparation_envelope: Vec<u8>,
    state: String,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
    activated_at: Option<OffsetDateTime>,
    payment_deadline: Option<OffsetDateTime>,
    voided_at: Option<OffsetDateTime>,
    business_outcome: Option<String>,
    resolved_at: Option<OffsetDateTime>,
    settlement_count: i64,
    payment_record_envelope: Option<Vec<u8>>,
    bitcoin_address_lookup_hash: Option<Vec<u8>>,
    derivation_index_lookup_hash: Option<Vec<u8>>,
    payment_status: Option<String>,
    confirmation_count: Option<i32>,
    amount_matched: Option<bool>,
    outbox_count: i64,
    outbox_status: Option<String>,
    lifecycle_count: i64,
    request_state: Option<String>,
    observation_id: Option<Uuid>,
    observation_envelope: Option<Vec<u8>>,
    outpoint_lookup_hash: Option<Vec<u8>>,
    confirmations: Option<i32>,
    present: Option<bool>,
    first_observed_at: Option<OffsetDateTime>,
    active_outpoint_timely: bool,
    observed_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct MarketplaceObservationRow {
    id: Uuid,
    invoice_id: Option<Uuid>,
    marketplace_preparation_id: Option<Uuid>,
    observation_envelope: Vec<u8>,
    outpoint_lookup_hash: Vec<u8>,
    confirmations: i32,
    present: bool,
    first_observed_at: OffsetDateTime,
}

#[derive(Serialize, Deserialize)]
struct MarketplaceBitcoinObservationV1 {
    version: u8,
    outpoint: String,
    observed_sats: u64,
}

impl MarketplacePreparationStore {
    pub fn new(pool: &PgPool, crypto: Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    /// Loads every non-final activated Marketplace settlement as an authenticated target.
    pub async fn observation_targets(&self) -> Result<Vec<ObservationTarget>, PersistenceError> {
        self.observation_targets_with_time(None).await
    }

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
            "SELECT settlement.preparation_id
             FROM marketplace_settlements settlement
             JOIN marketplace_payment_preparations preparation
               ON preparation.id = settlement.preparation_id
              AND preparation.creator_id = settlement.creator_id
             WHERE preparation.state = 'active'
               AND settlement.bitcoin_address_lookup_hash IS NOT NULL
               AND settlement.payment_expired_at IS NULL
               AND NOT EXISTS (
                   SELECT 1
                   FROM marketplace_timely_amount_matched_outpoints timely
                   JOIN bitcoin_observations observation
                     ON observation.marketplace_preparation_id = timely.preparation_id
                    AND observation.outpoint_lookup_hash = timely.outpoint_lookup_hash
                    AND observation.active
                    AND observation.present
                   WHERE timely.preparation_id = settlement.preparation_id
               )
             ORDER BY settlement.preparation_id
             FOR UPDATE OF settlement",
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
            "UPDATE marketplace_settlements settlement
             SET payment_expired_at = $1, updated_at = clock_timestamp()
             FROM marketplace_payment_preparations preparation
             WHERE preparation.id = settlement.preparation_id
               AND preparation.creator_id = settlement.creator_id
               AND preparation.state = 'active'
               AND settlement.bitcoin_address_lookup_hash IS NOT NULL
               AND preparation.payment_deadline < $1
               AND settlement.payment_expired_at IS NULL
               AND NOT EXISTS (
                   SELECT 1
                   FROM marketplace_timely_amount_matched_outpoints timely
                   JOIN bitcoin_observations observation
                     ON observation.marketplace_preparation_id = timely.preparation_id
                    AND observation.outpoint_lookup_hash = timely.outpoint_lookup_hash
                    AND observation.active
                    AND observation.present
                   WHERE timely.preparation_id = settlement.preparation_id
               )",
        )
        .bind(observed_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let rows = sqlx::query_as::<_, MarketplaceObservationTargetRow>(
            "SELECT settlement.preparation_id, creators.creator_lookup_hash,
                    settlement.payment_record_envelope,
                    settlement.bitcoin_address_lookup_hash,
                    settlement.derivation_index_lookup_hash,
                    preparation.activated_at,
                    observation.id AS observation_id,
                    observation.observation_envelope,
                    observation.outpoint_lookup_hash,
                    observation.confirmations, observation.present,
                    observation.first_observed_at
             FROM marketplace_settlements settlement
             JOIN marketplace_payment_preparations preparation
               ON preparation.id = settlement.preparation_id
              AND preparation.creator_id = settlement.creator_id
             JOIN creators ON creators.id = settlement.creator_id
             LEFT JOIN bitcoin_observations observation
               ON observation.marketplace_preparation_id = settlement.preparation_id
              AND observation.active
             WHERE preparation.state = 'active'
               AND settlement.bitcoin_address_lookup_hash IS NOT NULL
             ORDER BY settlement.preparation_id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;

        rows.into_iter()
            .map(|row| {
                let creator_hash = stored_hash(&row.creator_lookup_hash)?;
                let payment = self.decrypt_settlement_payment_record(
                    creator_hash,
                    row.preparation_id,
                    row.payment_record_envelope,
                )?;
                let required = payment.bitcoin_required_amount()?;
                let address = payment.bitcoin_address()?.to_owned();
                if row.bitcoin_address_lookup_hash
                    != self
                        .crypto
                        .bitcoin_address_lookup_hash(address.as_bytes())
                        .as_bytes()
                    || row.derivation_index_lookup_hash
                        != self
                            .crypto
                            .bitcoin_derivation_index_lookup_hash(
                                creator_hash,
                                payment.derivation_index(),
                            )
                            .as_bytes()
                {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                let current = match (
                    row.observation_id,
                    row.observation_envelope,
                    row.outpoint_lookup_hash,
                    row.confirmations,
                    row.present,
                    row.first_observed_at,
                ) {
                    (None, None, None, None, None, None) => None,
                    (
                        Some(id),
                        Some(envelope),
                        Some(outpoint_hash),
                        Some(confirmations),
                        Some(present),
                        Some(first_observed_at),
                    ) => {
                        let observation = self.decrypt_marketplace_observation(
                            creator_hash,
                            row.preparation_id,
                            id,
                            envelope,
                        )?;
                        if outpoint_hash
                            != self
                                .crypto
                                .bitcoin_outpoint_lookup_hash(observation.outpoint.as_bytes())
                                .as_bytes()
                            || confirmations < 0
                            || (!present && confirmations != 0)
                            || first_observed_at < row.activated_at
                        {
                            return Err(PersistenceError::CorruptOrMissing);
                        }
                        if present && confirmations >= 6 && observation.observed_sats >= required {
                            return Ok(None);
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
                Ok(Some(ObservationTarget::new(address, current)))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|targets| targets.into_iter().flatten().collect())
    }

    /// Authenticates every Marketplace settlement and historical Bitcoin evidence row.
    pub async fn scan_observation_integrity(&self) -> Result<(), PersistenceError> {
        let settlements = sqlx::query_as::<_, MarketplaceSettlementRow>(
            "SELECT settlement.preparation_id, creators.creator_lookup_hash,
                    settlement.payment_record_envelope,
                    settlement.bitcoin_address_lookup_hash,
                    settlement.derivation_index_lookup_hash,
                    preparation.activated_at, preparation.payment_deadline
             FROM marketplace_settlements settlement
             JOIN marketplace_payment_preparations preparation
               ON preparation.id = settlement.preparation_id
              AND preparation.creator_id = settlement.creator_id
             JOIN creators ON creators.id = settlement.creator_id
             WHERE preparation.state = 'active'
             ORDER BY settlement.preparation_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for settlement in settlements {
            let creator_hash = stored_hash(&settlement.creator_lookup_hash)?;
            let payment = self.decrypt_settlement_payment_record(
                creator_hash,
                settlement.preparation_id,
                settlement.payment_record_envelope,
            )?;
            if payment.has_bitcoin() {
                payment.bitcoin_required_amount()?;
            }
            if settlement.bitcoin_address_lookup_hash != self.settlement_address_hash(&payment)?
                || settlement.derivation_index_lookup_hash
                    != self
                        .crypto
                        .bitcoin_derivation_index_lookup_hash(
                            creator_hash,
                            payment.derivation_index(),
                        )
                        .as_bytes()
                || settlement.activated_at >= settlement.payment_deadline
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
        }
        let observations = sqlx::query_as::<
            _,
            (
                Uuid,
                Option<Uuid>,
                Option<Uuid>,
                Vec<u8>,
                Vec<u8>,
                i32,
                bool,
                OffsetDateTime,
                OffsetDateTime,
                Vec<u8>,
            ),
        >(
            "SELECT observation.id, observation.invoice_id,
                    observation.marketplace_preparation_id,
                    observation.observation_envelope,
                    observation.outpoint_lookup_hash,
                    observation.confirmations, observation.present,
                    observation.first_observed_at, preparation.activated_at,
                    creators.creator_lookup_hash
             FROM bitcoin_observations observation
             JOIN marketplace_settlements settlement
               ON settlement.preparation_id = observation.marketplace_preparation_id
             JOIN marketplace_payment_preparations preparation
               ON preparation.id = settlement.preparation_id
              AND preparation.creator_id = settlement.creator_id
             JOIN creators ON creators.id = settlement.creator_id
             WHERE observation.marketplace_preparation_id IS NOT NULL
             ORDER BY observation.id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for (
            id,
            invoice_id,
            marketplace_preparation_id,
            envelope,
            outpoint_hash,
            confirmations,
            present,
            first_observed_at,
            activated_at,
            creator_hash,
        ) in observations
        {
            let Some(preparation_id) = marketplace_preparation_id else {
                return Err(PersistenceError::CorruptOrMissing);
            };
            let creator_hash = stored_hash(&creator_hash)?;
            let observation =
                self.decrypt_marketplace_observation(creator_hash, preparation_id, id, envelope)?;
            if invoice_id.is_some()
                || outpoint_hash
                    != self
                        .crypto
                        .bitcoin_outpoint_lookup_hash(observation.outpoint.as_bytes())
                        .as_bytes()
                || confirmations < 0
                || (!present && confirmations != 0)
                || first_observed_at < activated_at
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
        }
        self.scan_usdt_observation_integrity().await
    }

    pub(crate) async fn apply_bitcoin_observation_batch(
        &self,
        observations: &[BitcoinObservationInput],
    ) -> Result<usize, PersistenceError> {
        self.apply_bitcoin_observation_batch_with_time(observations, None)
            .await
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
            "SELECT settlement.preparation_id
             FROM marketplace_settlements settlement
             JOIN marketplace_payment_preparations preparation
               ON preparation.id = settlement.preparation_id
              AND preparation.creator_id = settlement.creator_id
             WHERE settlement.bitcoin_address_lookup_hash = ANY($1::bytea[])
               AND preparation.state = 'active'
             ORDER BY settlement.preparation_id
             FOR UPDATE OF settlement",
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
        let mut ordered: Vec<_> = observations.iter().collect();
        ordered.sort_by(|left, right| left.cmp_for_batch(right));
        let mut applied = 0;
        for observation in ordered {
            if self
                .apply_marketplace_observation(&mut tx, observation, observed_at)
                .await?
            {
                applied += 1;
            }
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(applied)
    }

    /// The database clock, for fixing a preparation's expiry on the clock that judges it.
    pub async fn database_time(&self) -> Result<OffsetDateTime, PersistenceError> {
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)
    }

    /// Resolves replay or changed binding before mutable external work.
    pub async fn preflight(
        &self,
        creator: &CreatorPubky,
        operation_id: &str,
        request_binding: &[u8],
    ) -> Result<MarketplacePreparationPreflight, PersistenceError> {
        if operation_id.is_empty() || request_binding.is_empty() {
            return Err(PersistenceError::InvalidInput);
        }
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let operation_hash = self.crypto.lookup_hash(operation_id.as_bytes());
        let request_hash = self.crypto.lookup_hash(request_binding);
        let stored: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT preparations.request_lookup_hash
             FROM marketplace_payment_preparations AS preparations
             JOIN creators ON creators.id = preparations.creator_id
             WHERE creators.creator_lookup_hash = $1
               AND preparations.operation_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(operation_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(match stored {
            None => MarketplacePreparationPreflight::New,
            Some(stored) if stored_hash(&stored)? == request_hash => {
                MarketplacePreparationPreflight::ExactReplay
            }
            Some(_) => MarketplacePreparationPreflight::Conflict,
        })
    }

    /// Creates or exactly replays one Creator-scoped Marketplace operation.
    pub async fn prepare(
        &self,
        input: MarketplacePreparationInput<'_>,
    ) -> Result<MarketplacePreparationResult, PersistenceError> {
        if input.operation_id.is_empty()
            || input.request_binding.is_empty()
            || input.payment_window_seconds == 0
            || input.prepare_ttl_seconds == 0
        {
            return Err(PersistenceError::InvalidInput);
        }
        let ttl_seconds =
            i64::try_from(input.prepare_ttl_seconds).map_err(|_| PersistenceError::InvalidInput)?;
        let ttl = Duration::seconds(ttl_seconds);
        let creator_hash = self
            .crypto
            .lookup_hash(input.creator.to_string().as_bytes());
        let operation_hash = self.crypto.lookup_hash(input.operation_id.as_bytes());
        let request_hash = self.crypto.lookup_hash(input.request_binding);
        let reader_hash = self.crypto.lookup_hash(input.reader.to_string().as_bytes());

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let creator = sqlx::query_as::<_, (Uuid, Vec<u8>, i64)>(
            "SELECT id, creator_lookup_hash, next_child_index
             FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .map(|(id, creator_lookup_hash, next_child_index)| CreatorRow {
            id,
            creator_lookup_hash,
            next_child_index,
        })
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if stored_hash(&creator.creator_lookup_hash)? != creator_hash
            || creator.next_child_index < 0
        {
            return Err(PersistenceError::CorruptOrMissing);
        }

        if let Some(row) = self
            .load_locked(&mut tx, creator.id, operation_hash)
            .await?
        {
            let result = self.validate_replay(
                creator_hash,
                operation_hash,
                request_hash,
                reader_hash,
                input,
                row,
            )?;
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(result);
        }

        // The Creator lock may have been waited on for a long time. The preparation
        // keeps the life fixed when the quote was accepted; it never starts a new one.
        let prepare_expires_at = input
            .prepare_deadline
            .ok_or(PersistenceError::InvalidInput)
            .and_then(|deadline| {
                // PostgreSQL stores microseconds; the envelope must hold the same instant.
                deadline
                    .replace_nanosecond(deadline.nanosecond() / 1_000 * 1_000)
                    .map_err(|_| PersistenceError::InvalidInput)
            })?;
        let locked_at: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        if locked_at >= prepare_expires_at {
            return Err(PersistenceError::DeadlineElapsed);
        }
        // `prepared_at` is the instant the quote was fixed, so the stored lifetime
        // stays exactly the configured TTL.
        let prepared_at = prepare_expires_at
            .checked_sub(ttl)
            .ok_or(PersistenceError::InvalidInput)?;
        let payloads = input.payloads.for_child_index(creator.next_child_index)?;
        let terms = MarketplaceTerms::from_intent(
            &payloads.payment_request_intent,
            input.amount,
            input.asset,
        )?;
        let quote = validate_intent(
            &payloads.payment_request_intent,
            input.reader,
            input.reference,
            &terms,
        )?;
        let invoice_id = Uuid::new_v4();
        let envelope = PreparationEnvelope {
            version: 2,
            operation_id: input.operation_id.to_owned(),
            request_binding: input.request_binding.to_vec(),
            reader: input.reader.to_string(),
            reference: input.reference.to_owned(),
            terms: terms.clone(),
            payment_window_seconds: input.payment_window_seconds,
            prepare_ttl_seconds: input.prepare_ttl_seconds,
            prepared_at,
            prepare_expires_at,
            child_index: creator.next_child_index,
            payment_request_intent: payloads.payment_request_intent,
        };
        let plaintext =
            postcard::to_allocvec(&envelope).map_err(|_| PersistenceError::CorruptOrMissing)?;
        let encrypted = self
            .crypto
            .encrypt(
                &EnvelopeContext::marketplace_preparation(creator_hash, invoice_id),
                &plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        sqlx::query(
            "INSERT INTO marketplace_payment_preparations
             (id, creator_id, operation_lookup_hash, request_lookup_hash,
              reader_lookup_hash, preparation_envelope, prepared_at, prepare_expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(invoice_id)
        .bind(creator.id)
        .bind(operation_hash.as_bytes().as_slice())
        .bind(request_hash.as_bytes().as_slice())
        .bind(reader_hash.as_bytes().as_slice())
        .bind(encrypted.as_bytes())
        .bind(prepared_at)
        .bind(prepare_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(classify_preparation_insert_error)?;
        sqlx::query(
            "UPDATE creators SET next_child_index = next_child_index + 1, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(creator.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(MarketplacePreparationResult {
            invoice_id,
            terms,
            quote,
            prepared_at,
            prepare_expires_at,
            replayed: false,
        })
    }

    /// Atomically activates a preparation and admits exactly one proposal intent.
    pub async fn activate(
        &self,
        input: MarketplaceActivationInput<'_>,
    ) -> Result<Option<MarketplaceActivationResult>, MarketplaceLifecyclePersistenceError> {
        if input.amount == 0 || input.proposal_acceptance_window.is_zero() {
            return Err(PersistenceError::InvalidInput.into());
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let creator_hash = self
            .crypto
            .lookup_hash(input.creator.to_string().as_bytes());
        let creator_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE")
                .bind(creator_hash.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
        if creator_id.is_none() {
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(None);
        }
        let Some(row) = self
            .load_lifecycle_locked(&mut tx, input.creator, input.invoice_id)
            .await?
        else {
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(None);
        };
        let creator_hash = stored_hash(&row.creator_lookup_hash)?;
        let mut envelope = self.decode_lifecycle_envelope(creator_hash, &row)?;
        match row.state.as_str() {
            "active" => {
                if !envelope.terms_match(input.amount, input.asset) {
                    return Err(MarketplaceLifecyclePersistenceError::TotalMismatch);
                }
                let (Some(activated_at), Some(payment_deadline)) =
                    (row.activated_at, row.payment_deadline)
                else {
                    return Err(PersistenceError::CorruptOrMissing.into());
                };
                let outbox_count: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM outbox
                     WHERE marketplace_preparation_id = $1
                       AND creator_id = (
                           SELECT creator_id FROM marketplace_payment_preparations WHERE id = $1
                       )
                       AND intent_kind = 'payment_request_proposal'",
                )
                .bind(row.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
                if outbox_count != 1 {
                    return Err(PersistenceError::CorruptOrMissing.into());
                }
                self.validate_settlement(&mut tx, creator_hash, &row, &envelope)
                    .await?;
                tx.commit()
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                let quote = envelope.quote()?;
                return Ok(Some(MarketplaceActivationResult {
                    invoice_id: row.id,
                    activated_at,
                    payment_deadline,
                    terms: envelope.terms,
                    quote,
                    replayed: true,
                }));
            }
            "prepared" => {}
            "voided" => return Err(MarketplaceLifecyclePersistenceError::LifecycleTerminal),
            _ => return Err(PersistenceError::CorruptOrMissing.into()),
        }
        if row.activated_at.is_some()
            || row.payment_deadline.is_some()
            || row.voided_at.is_some()
            || row.resolved_at.is_some()
        {
            return Err(if row.resolved_at.is_some() {
                MarketplaceLifecyclePersistenceError::LifecycleTerminal
            } else {
                PersistenceError::CorruptOrMissing.into()
            });
        }
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        if now >= row.prepare_expires_at {
            return Err(MarketplaceLifecyclePersistenceError::PrepareExpired);
        }
        if !envelope.terms_match(input.amount, input.asset) {
            return Err(MarketplaceLifecyclePersistenceError::TotalMismatch);
        }
        let window_seconds = i64::try_from(envelope.payment_window_seconds)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment_deadline = now
            .checked_add(Duration::seconds(window_seconds))
            .ok_or(PersistenceError::InvalidInput)?;
        let configured_proposal_duration = Duration::try_from(input.proposal_acceptance_window)
            .map_err(|_| PersistenceError::InvalidInput)?;
        let proposal_duration =
            configured_proposal_duration.min(Duration::seconds(window_seconds) / 2);
        let proposal_expires_at = now
            .checked_add(proposal_duration)
            .ok_or(PersistenceError::InvalidInput)?;
        envelope
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
        let quote = validate_intent(
            &envelope.payment_request_intent,
            &parse_reader(&envelope.reader).map_err(|_| PersistenceError::CorruptOrMissing)?,
            &envelope.reference,
            &envelope.terms,
        )?;
        let outbox_id = Uuid::new_v4();
        let intent_plaintext = postcard::to_allocvec(&envelope.payment_request_intent)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let intent_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::outbox_semantic_intent(creator_hash, outbox_id),
                &intent_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let proposal_lookup_hash = self.crypto.payment_request_proposal_lookup_hash(
            envelope
                .payment_request_intent
                .proposal_payment_reference()
                .map_err(|_| PersistenceError::CorruptOrMissing)?
                .as_bytes(),
        );
        sqlx::query(
            "UPDATE marketplace_payment_preparations
             SET state = 'active', activated_at = $2, payment_deadline = $3,
                 updated_at = clock_timestamp()
             WHERE id = $1",
        )
        .bind(row.id)
        .bind(now)
        .bind(payment_deadline)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let payment_record = InvoicePaymentRecordV1::from_intent(
            envelope.child_index,
            &envelope.payment_request_intent,
        )?;
        let bitcoin_address_hash = self.settlement_address_hash(&payment_record)?;
        let derivation_index_hash = self
            .crypto
            .bitcoin_derivation_index_lookup_hash(creator_hash, payment_record.derivation_index());
        let payment_record_plaintext = postcard::to_allocvec(&payment_record)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment_record_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::marketplace_settlement_payment_record(creator_hash, row.id),
                &payment_record_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        sqlx::query(
            "INSERT INTO marketplace_settlements (
                 preparation_id, creator_id, payment_record_envelope,
                 bitcoin_address_lookup_hash, derivation_index_lookup_hash,
                 payment_status, confirmation_count, amount_matched
             )
             SELECT id, creator_id, $2, $3, $4, 'undetected', 0, FALSE
             FROM marketplace_payment_preparations WHERE id = $1",
        )
        .bind(row.id)
        .bind(payment_record_envelope.as_bytes())
        .bind(bitcoin_address_hash)
        .bind(derivation_index_hash.as_bytes().as_slice())
        .execute(&mut *tx)
        .await
        .map_err(classify_settlement_insert_error)?;
        let inserted = sqlx::query(
            "INSERT INTO outbox
             (id, creator_id, marketplace_preparation_id, intent_envelope, intent_kind,
              status, proposal_lookup_hash)
             SELECT $1, creator_id, id, $2, 'payment_request_proposal', 'queued', $3
             FROM marketplace_payment_preparations WHERE id = $4",
        )
        .bind(outbox_id)
        .bind(intent_envelope.as_bytes())
        .bind(proposal_lookup_hash.as_bytes().as_slice())
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if inserted.rows_affected() != 1 {
            return Err(PersistenceError::CorruptOrMissing.into());
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(Some(MarketplaceActivationResult {
            invoice_id: row.id,
            activated_at: now,
            payment_deadline,
            terms: envelope.terms,
            quote,
            replayed: false,
        }))
    }

    /// Atomically voids a still-prepared invoice without creating SDK work.
    pub async fn void(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<MarketplaceVoidResult>, MarketplaceLifecyclePersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let Some(row) = self
            .load_lifecycle_locked(&mut tx, creator, invoice_id)
            .await?
        else {
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(None);
        };
        let creator_hash = stored_hash(&row.creator_lookup_hash)?;
        self.decode_lifecycle_envelope(creator_hash, &row)?;
        match row.state.as_str() {
            "voided" => {
                let Some(voided_at) = row.voided_at else {
                    return Err(PersistenceError::CorruptOrMissing.into());
                };
                tx.commit()
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                return Ok(Some(MarketplaceVoidResult {
                    invoice_id: row.id,
                    voided_at,
                    replayed: true,
                }));
            }
            "prepared" => {}
            "active" => return Err(MarketplaceLifecyclePersistenceError::InvoiceActive),
            _ => return Err(PersistenceError::CorruptOrMissing.into()),
        }
        if row.activated_at.is_some() || row.payment_deadline.is_some() || row.voided_at.is_some() {
            return Err(PersistenceError::CorruptOrMissing.into());
        }
        let voided_at: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query(
            "UPDATE marketplace_payment_preparations
             SET state = 'voided', voided_at = $2, updated_at = clock_timestamp()
             WHERE id = $1",
        )
        .bind(row.id)
        .bind(voided_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(Some(MarketplaceVoidResult {
            invoice_id: row.id,
            voided_at,
            replayed: false,
        }))
    }

    /// Records one immutable business outcome without changing protocol or payment facts.
    pub async fn resolve(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
        outcome: MarketplaceResolutionOutcome,
    ) -> Result<Option<MarketplaceResolutionResult>, MarketplaceLifecyclePersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let Some(row) = self
            .load_lifecycle_locked(&mut tx, creator, invoice_id)
            .await?
        else {
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(None);
        };
        let creator_hash = stored_hash(&row.creator_lookup_hash)?;
        self.decode_lifecycle_envelope(creator_hash, &row)?;
        if !matches!(row.state.as_str(), "prepared" | "active" | "voided") {
            return Err(PersistenceError::CorruptOrMissing.into());
        }
        match (&row.business_outcome, row.resolved_at) {
            (Some(existing), Some(resolved_at)) => {
                let existing = MarketplaceResolutionOutcome::parse(existing)
                    .ok_or(PersistenceError::CorruptOrMissing)?;
                if existing != outcome {
                    return Err(MarketplaceLifecyclePersistenceError::ResolutionConflict);
                }
                tx.commit()
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                return Ok(Some(MarketplaceResolutionResult::new(
                    row.id,
                    existing,
                    resolved_at,
                    true,
                )));
            }
            (None, None) => {}
            _ => return Err(PersistenceError::CorruptOrMissing.into()),
        }
        let resolved_at: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let updated = sqlx::query(
            "UPDATE marketplace_payment_preparations
             SET business_outcome = $2, resolved_at = $3, updated_at = clock_timestamp()
             WHERE id = $1 AND business_outcome IS NULL AND resolved_at IS NULL",
        )
        .bind(row.id)
        .bind(outcome.as_str())
        .bind(resolved_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if updated.rows_affected() != 1 {
            return Err(PersistenceError::CorruptOrMissing.into());
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(Some(MarketplaceResolutionResult::new(
            row.id,
            outcome,
            resolved_at,
            false,
        )))
    }

    async fn load_locked(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        creator_id: Uuid,
        operation_hash: LookupHash,
    ) -> Result<Option<PreparationRow>, PersistenceError> {
        sqlx::query_as::<
            _,
            (
                Uuid,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                OffsetDateTime,
                OffsetDateTime,
            ),
        >(
            "SELECT id, operation_lookup_hash, request_lookup_hash, reader_lookup_hash,
                    preparation_envelope, prepared_at, prepare_expires_at
             FROM marketplace_payment_preparations
             WHERE creator_id = $1 AND operation_lookup_hash = $2 FOR UPDATE",
        )
        .bind(creator_id)
        .bind(operation_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map(|row| {
            row.map(
                |(
                    id,
                    operation_lookup_hash,
                    request_lookup_hash,
                    reader_lookup_hash,
                    preparation_envelope,
                    prepared_at,
                    prepare_expires_at,
                )| PreparationRow {
                    id,
                    operation_lookup_hash,
                    request_lookup_hash,
                    reader_lookup_hash,
                    preparation_envelope,
                    prepared_at,
                    prepare_expires_at,
                },
            )
        })
        .map_err(|_| PersistenceError::Unavailable)
    }

    async fn load_lifecycle_locked(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<LifecycleRow>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        sqlx::query_as::<
            _,
            (
                Uuid,
                Vec<u8>,
                Vec<u8>,
                String,
                OffsetDateTime,
                OffsetDateTime,
                Option<OffsetDateTime>,
                Option<OffsetDateTime>,
                Option<OffsetDateTime>,
                Option<String>,
                Option<OffsetDateTime>,
            ),
        >(
            "SELECT preparation.id, creators.creator_lookup_hash,
                    preparation.preparation_envelope, preparation.state,
                    preparation.prepared_at, preparation.prepare_expires_at,
                    preparation.activated_at, preparation.payment_deadline,
                    preparation.voided_at, preparation.business_outcome,
                    preparation.resolved_at
             FROM marketplace_payment_preparations AS preparation
             JOIN creators ON creators.id = preparation.creator_id
             WHERE preparation.id = $1 AND creators.creator_lookup_hash = $2
             FOR UPDATE OF preparation",
        )
        .bind(invoice_id)
        .bind(creator_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map(|row| {
            row.map(
                |(
                    id,
                    creator_lookup_hash,
                    preparation_envelope,
                    state,
                    prepared_at,
                    prepare_expires_at,
                    activated_at,
                    payment_deadline,
                    voided_at,
                    business_outcome,
                    resolved_at,
                )| LifecycleRow {
                    id,
                    creator_lookup_hash,
                    preparation_envelope,
                    state,
                    prepared_at,
                    prepare_expires_at,
                    activated_at,
                    payment_deadline,
                    voided_at,
                    business_outcome,
                    resolved_at,
                },
            )
        })
        .map_err(|_| PersistenceError::Unavailable)
    }

    fn decode_lifecycle_envelope(
        &self,
        creator_hash: LookupHash,
        row: &LifecycleRow,
    ) -> Result<PreparationEnvelope, PersistenceError> {
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::marketplace_preparation(creator_hash, row.id),
                &EncryptedEnvelope::from_bytes(row.preparation_envelope.clone()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let envelope = PreparationEnvelope::decode(&plaintext)?;
        let ttl = i64::try_from(envelope.prepare_ttl_seconds)
            .map(Duration::seconds)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if envelope.prepared_at != row.prepared_at
            || envelope.prepare_expires_at != row.prepare_expires_at
            || envelope.prepared_at.checked_add(ttl) != Some(envelope.prepare_expires_at)
            || envelope.payment_window_seconds == 0
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        validate_intent(
            &envelope.payment_request_intent,
            &parse_reader(&envelope.reader).map_err(|_| PersistenceError::CorruptOrMissing)?,
            &envelope.reference,
            &envelope.terms,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        Ok(envelope)
    }

    async fn validate_settlement(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        creator_hash: LookupHash,
        row: &LifecycleRow,
        preparation: &PreparationEnvelope,
    ) -> Result<(), PersistenceError> {
        let stored: Option<StoredSettlement> = sqlx::query_as(
            "SELECT payment_record_envelope, bitcoin_address_lookup_hash,
                    derivation_index_lookup_hash
             FROM marketplace_settlements
             WHERE preparation_id = $1 AND creator_id = (
                 SELECT creator_id FROM marketplace_payment_preparations WHERE id = $1
             )",
        )
        .bind(row.id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(StoredSettlement {
            payment_record_envelope: encrypted,
            bitcoin_address_lookup_hash: address_hash,
            derivation_index_lookup_hash: derivation_hash,
        }) = stored
        else {
            return Err(PersistenceError::CorruptOrMissing);
        };
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::marketplace_settlement_payment_record(creator_hash, row.id),
                &EncryptedEnvelope::from_bytes(encrypted),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let actual: InvoicePaymentRecordV1 =
            postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
        let expected = InvoicePaymentRecordV1::from_intent(
            preparation.child_index,
            &preparation.payment_request_intent,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if actual != expected
            || address_hash != self.settlement_address_hash(&expected)?
            || derivation_hash.as_slice()
                != self
                    .crypto
                    .bitcoin_derivation_index_lookup_hash(creator_hash, expected.derivation_index())
                    .as_bytes()
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok(())
    }

    async fn apply_marketplace_observation(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        input: &BitcoinObservationInput,
        observed_at: OffsetDateTime,
    ) -> Result<bool, PersistenceError> {
        let address_hash = self
            .crypto
            .bitcoin_address_lookup_hash(input.address.as_bytes());
        let settlement = sqlx::query_as::<_, MarketplaceSettlementRow>(
            "SELECT settlement.preparation_id, creators.creator_lookup_hash,
                    settlement.payment_record_envelope,
                    settlement.bitcoin_address_lookup_hash,
                    settlement.derivation_index_lookup_hash,
                    preparation.activated_at, preparation.payment_deadline
             FROM marketplace_settlements settlement
             JOIN marketplace_payment_preparations preparation
               ON preparation.id = settlement.preparation_id
              AND preparation.creator_id = settlement.creator_id
             JOIN creators ON creators.id = settlement.creator_id
             WHERE settlement.bitcoin_address_lookup_hash = $1
               AND preparation.state = 'active'
             FOR UPDATE OF settlement",
        )
        .bind(address_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(settlement) = settlement else {
            return Ok(false);
        };
        let creator_hash = stored_hash(&settlement.creator_lookup_hash)?;
        let payment = self.decrypt_settlement_payment_record(
            creator_hash,
            settlement.preparation_id,
            settlement.payment_record_envelope,
        )?;
        let required = payment.bitcoin_required_amount()?;
        if payment.bitcoin_address()? != input.address
            || settlement.bitcoin_address_lookup_hash.as_deref()
                != Some(address_hash.as_bytes().as_slice())
            || settlement.derivation_index_lookup_hash
                != self
                    .crypto
                    .bitcoin_derivation_index_lookup_hash(creator_hash, payment.derivation_index())
                    .as_bytes()
            || observed_at < settlement.activated_at
        {
            return Err(PersistenceError::CorruptOrMissing);
        }

        let outpoint = input.outpoint.canonical_text();
        let outpoint_hash = self
            .crypto
            .bitcoin_outpoint_lookup_hash(outpoint.as_bytes());
        let existing = sqlx::query_as::<_, MarketplaceObservationRow>(
            "SELECT id, invoice_id, marketplace_preparation_id, observation_envelope,
                    outpoint_lookup_hash, confirmations, present, first_observed_at
             FROM bitcoin_observations WHERE outpoint_lookup_hash = $1 FOR UPDATE",
        )
        .bind(outpoint_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if existing.as_ref().is_some_and(|row| {
            row.invoice_id.is_some()
                || row.marketplace_preparation_id != Some(settlement.preparation_id)
        }) {
            return Err(PersistenceError::Conflict);
        }
        if let Some(row) = existing.as_ref() {
            let stored = self.decrypt_marketplace_observation(
                creator_hash,
                settlement.preparation_id,
                row.id,
                row.observation_envelope.clone(),
            )?;
            if stored.outpoint != outpoint
                || stored.observed_sats != input.observed_sats
                || row.outpoint_lookup_hash != outpoint_hash.as_bytes()
            {
                return Err(PersistenceError::Conflict);
            }
        }
        let active = sqlx::query_as::<_, MarketplaceObservationRow>(
            "SELECT id, invoice_id, marketplace_preparation_id, observation_envelope,
                    outpoint_lookup_hash, confirmations, present, first_observed_at
             FROM bitcoin_observations
             WHERE marketplace_preparation_id = $1 AND active FOR UPDATE",
        )
        .bind(settlement.preparation_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let active_record = active
            .as_ref()
            .map(|row| {
                self.decrypt_marketplace_observation(
                    creator_hash,
                    settlement.preparation_id,
                    row.id,
                    row.observation_envelope.clone(),
                )
            })
            .transpose()?;
        if active
            .as_ref()
            .zip(active_record.as_ref())
            .is_some_and(|(row, record)| {
                row.present && row.confirmations >= 6 && record.observed_sats >= required
            })
        {
            return Ok(true);
        }
        if !input.present
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
                    input.observed_sats,
                    input.confirmations,
                    input.present,
                    required,
                )
            });
        if action == Some(ObservationAction::Ignore) {
            return Ok(true);
        }
        if active.is_none() && !input.present {
            return Ok(true);
        }
        if action == Some(ObservationAction::Replace) {
            sqlx::query(
                "UPDATE bitcoin_observations SET active = FALSE, updated_at = clock_timestamp()
                 WHERE marketplace_preparation_id = $1 AND active",
            )
            .bind(settlement.preparation_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }

        let confirmations =
            i32::try_from(input.confirmations).map_err(|_| PersistenceError::CorruptOrMissing)?;
        let observation_id = existing.as_ref().map_or_else(Uuid::new_v4, |row| row.id);
        let first_observed_at = existing
            .as_ref()
            .map_or(observed_at, |row| row.first_observed_at);
        let encrypted = self
            .crypto
            .encrypt(
                &EnvelopeContext::bitcoin_observation_for_marketplace(
                    creator_hash,
                    observation_id,
                    settlement.preparation_id,
                ),
                &postcard::to_allocvec(&MarketplaceBitcoinObservationV1 {
                    version: 1,
                    outpoint,
                    observed_sats: input.observed_sats,
                })
                .map_err(|_| PersistenceError::CorruptOrMissing)?,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let written = sqlx::query(
            "INSERT INTO bitcoin_observations
             (id, marketplace_preparation_id, observation_envelope, outpoint_lookup_hash,
              confirmations, present, active, first_observed_at)
             VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7)
             ON CONFLICT (outpoint_lookup_hash) DO UPDATE SET
                 confirmations = EXCLUDED.confirmations,
                 present = EXCLUDED.present,
                 active = TRUE,
                 updated_at = clock_timestamp()
             WHERE bitcoin_observations.marketplace_preparation_id =
                   EXCLUDED.marketplace_preparation_id",
        )
        .bind(observation_id)
        .bind(settlement.preparation_id)
        .bind(encrypted.as_bytes())
        .bind(outpoint_hash.as_bytes().as_slice())
        .bind(confirmations)
        .bind(input.present)
        .bind(first_observed_at)
        .execute(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Conflict)?;
        if written.rows_affected() != 1 {
            return Err(PersistenceError::Conflict);
        }

        let amount_matched = input.present && input.observed_sats >= required;
        let timely = amount_matched && first_observed_at <= settlement.payment_deadline;
        if timely {
            sqlx::query(
                "INSERT INTO marketplace_timely_amount_matched_outpoints
                 (preparation_id, outpoint_lookup_hash) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(settlement.preparation_id)
            .bind(outpoint_hash.as_bytes().as_slice())
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        if amount_matched {
            sqlx::query(
                "UPDATE marketplace_settlements
                 SET first_amount_matched_observed_at =
                         COALESCE(first_amount_matched_observed_at, $2),
                     first_amount_matched_outpoint_lookup_hash =
                         COALESCE(first_amount_matched_outpoint_lookup_hash, $3)
                 WHERE preparation_id = $1",
            )
            .bind(settlement.preparation_id)
            .bind(first_observed_at)
            .bind(outpoint_hash.as_bytes().as_slice())
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        let projected_confirmations = if !input.present {
            0
        } else if amount_matched {
            confirmations.min(6)
        } else {
            confirmations
        };
        let payment_status = if !input.present {
            "undetected"
        } else if projected_confirmations == 0 {
            "detected"
        } else {
            "confirmed"
        };
        sqlx::query(
            "UPDATE marketplace_settlements
             SET payment_status = $2, confirmation_count = $3, amount_matched = $4,
                 payment_expired_at = CASE
                     WHEN $5 THEN NULL
                     WHEN $6 > $7 THEN COALESCE(payment_expired_at, $6)
                     ELSE payment_expired_at
                 END,
                 updated_at = clock_timestamp()
             WHERE preparation_id = $1",
        )
        .bind(settlement.preparation_id)
        .bind(payment_status)
        .bind(projected_confirmations)
        .bind(amount_matched)
        .bind(timely)
        .bind(observed_at)
        .bind(settlement.payment_deadline)
        .execute(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(true)
    }

    /// The keyed Bitcoin address hash a settlement must hold: present exactly when
    /// the request accepts Bitcoin, because a USDT-only request has no address to watch.
    fn settlement_address_hash(
        &self,
        payment: &InvoicePaymentRecordV1,
    ) -> Result<Option<Vec<u8>>, PersistenceError> {
        payment
            .has_bitcoin()
            .then(|| {
                payment.bitcoin_address().map(|address| {
                    self.crypto
                        .bitcoin_address_lookup_hash(address.as_bytes())
                        .as_bytes()
                        .to_vec()
                })
            })
            .transpose()
    }

    fn decrypt_settlement_payment_record(
        &self,
        creator_hash: LookupHash,
        preparation_id: Uuid,
        envelope: Vec<u8>,
    ) -> Result<InvoicePaymentRecordV1, PersistenceError> {
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::marketplace_settlement_payment_record(
                    creator_hash,
                    preparation_id,
                ),
                &EncryptedEnvelope::from_bytes(envelope),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)
    }

    fn decrypt_marketplace_observation(
        &self,
        creator_hash: LookupHash,
        preparation_id: Uuid,
        observation_id: Uuid,
        envelope: Vec<u8>,
    ) -> Result<MarketplaceBitcoinObservationV1, PersistenceError> {
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::bitcoin_observation_for_marketplace(
                    creator_hash,
                    observation_id,
                    preparation_id,
                ),
                &EncryptedEnvelope::from_bytes(envelope),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let observation: MarketplaceBitcoinObservationV1 =
            postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
        let outpoint = observation
            .outpoint
            .parse::<bitcoin::OutPoint>()
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if observation.version != 1 || outpoint.to_string() != observation.outpoint {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok(observation)
    }

    async fn status_snapshot(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<MarketplaceInvoiceStatus>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        // One snapshot for the settlement row and every receipt, so a status read never
        // shows a proof that a concurrent commit has only half applied.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let row = sqlx::query_as::<_, MarketplaceStatusRow>(
            "SELECT preparation.id, creators.creator_lookup_hash,
                    preparation.preparation_envelope, preparation.state,
                    preparation.prepared_at, preparation.prepare_expires_at,
                    preparation.activated_at, preparation.payment_deadline,
                    preparation.voided_at, preparation.business_outcome,
                    preparation.resolved_at,
                    (SELECT count(*) FROM marketplace_settlements
                     WHERE preparation_id = preparation.id) AS settlement_count,
                    settlement.payment_record_envelope,
                    settlement.bitcoin_address_lookup_hash,
                    settlement.derivation_index_lookup_hash,
                    settlement.payment_status, settlement.confirmation_count,
                    settlement.amount_matched,
                    (SELECT count(*) FROM outbox WHERE marketplace_preparation_id = preparation.id
                        AND intent_kind = 'payment_request_proposal') AS outbox_count,
                    (SELECT status FROM outbox WHERE marketplace_preparation_id = preparation.id
                        AND intent_kind = 'payment_request_proposal' LIMIT 1) AS outbox_status,
                    (SELECT count(*) FROM payment_request_lifecycles
                     WHERE marketplace_preparation_id = preparation.id) AS lifecycle_count,
                    (SELECT request_state FROM payment_request_lifecycles
                     WHERE marketplace_preparation_id = preparation.id
                     ORDER BY CASE request_state
                         WHEN 'invalid_conflict' THEN 9 WHEN 'recovery_required' THEN 8
                         WHEN 'proof_submitted' THEN 7 WHEN 'active_recurring' THEN 6
                         WHEN 'accepted' THEN 5 WHEN 'proposed' THEN 4 ELSE 0 END DESC,
                         last_event_at DESC, request_state DESC LIMIT 1) AS request_state,
                    observation.id AS observation_id,
                    observation.observation_envelope,
                    observation.outpoint_lookup_hash,
                    observation.confirmations, observation.present,
                    observation.first_observed_at,
                    EXISTS (
                        SELECT 1 FROM marketplace_timely_amount_matched_outpoints timely
                        WHERE timely.preparation_id = preparation.id
                          AND timely.outpoint_lookup_hash = observation.outpoint_lookup_hash
                    ) AS active_outpoint_timely,
                    clock_timestamp() AS observed_at
             FROM marketplace_payment_preparations preparation
             JOIN creators ON creators.id = preparation.creator_id
             LEFT JOIN marketplace_settlements settlement
               ON settlement.preparation_id = preparation.id
              AND settlement.creator_id = preparation.creator_id
             LEFT JOIN bitcoin_observations observation
               ON observation.marketplace_preparation_id = preparation.id AND observation.active
             WHERE preparation.id = $1 AND creators.creator_lookup_hash = $2",
        )
        .bind(invoice_id)
        .bind(creator_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if stored_hash(&row.creator_lookup_hash)? != creator_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let lifecycle = LifecycleRow {
            id: row.id,
            creator_lookup_hash: row.creator_lookup_hash.clone(),
            preparation_envelope: row.preparation_envelope.clone(),
            state: row.state.clone(),
            prepared_at: row.prepared_at,
            prepare_expires_at: row.prepare_expires_at,
            activated_at: row.activated_at,
            payment_deadline: row.payment_deadline,
            voided_at: row.voided_at,
            business_outcome: row.business_outcome.clone(),
            resolved_at: row.resolved_at,
        };
        let preparation = self.decode_lifecycle_envelope(creator_hash, &lifecycle)?;
        let accepted_assets = preparation.terms.accepted_assets().to_vec();
        let payment_amounts = preparation.quote()?.payment_amounts().to_vec();
        let outcome = row
            .business_outcome
            .as_deref()
            .map(parse_business_outcome)
            .transpose()?;
        if outcome.is_some() != row.resolved_at.is_some()
            || row.prepared_at >= row.prepare_expires_at
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        match row.state.as_str() {
            "prepared" | "voided" => {
                if row.settlement_count != 0
                    || row.payment_record_envelope.is_some()
                    || row.bitcoin_address_lookup_hash.is_some()
                    || row.derivation_index_lookup_hash.is_some()
                    || row.payment_status.is_some()
                    || row.confirmation_count.is_some()
                    || row.amount_matched.is_some()
                    || row.outbox_count != 0
                    || row.outbox_status.is_some()
                    || row.lifecycle_count != 0
                    || row.request_state.is_some()
                    || row.observation_id.is_some()
                    || row.activated_at.is_some()
                    || row.payment_deadline.is_some()
                    || (row.state == "prepared" && row.voided_at.is_some())
                    || (row.state == "voided" && row.voided_at.is_none())
                    || row
                        .resolved_at
                        .is_some_and(|resolved_at| resolved_at < row.prepared_at)
                {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                Ok(Some(
                    MarketplaceInvoiceStatus::inactive(
                        row.id,
                        if row.state == "prepared" {
                            "prepared"
                        } else {
                            "voided"
                        },
                        outcome,
                        row.resolved_at,
                    )
                    .with_offer(accepted_assets, payment_amounts),
                ))
            }
            "active" => {
                let (
                    Some(activated_at),
                    Some(payment_deadline),
                    Some(payment_record_envelope),
                    Some(derivation_hash),
                    Some(stored_payment_status),
                    Some(stored_confirmations),
                    Some(stored_amount_matched),
                ) = (
                    row.activated_at,
                    row.payment_deadline,
                    row.payment_record_envelope.as_ref(),
                    row.derivation_index_lookup_hash.as_deref(),
                    row.payment_status.as_deref(),
                    row.confirmation_count,
                    row.amount_matched,
                )
                else {
                    return Err(PersistenceError::CorruptOrMissing);
                };
                if row.settlement_count != 1
                    || row.outbox_count != 1
                    || row.lifecycle_count > 1
                    || activated_at >= payment_deadline
                    || row.voided_at.is_some()
                    || activated_at < row.prepared_at
                    || row
                        .resolved_at
                        .is_some_and(|resolved_at| resolved_at < activated_at)
                {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                let payment = self.decrypt_settlement_payment_record(
                    creator_hash,
                    row.id,
                    payment_record_envelope.clone(),
                )?;
                let expected_payment = InvoicePaymentRecordV1::from_intent(
                    preparation.child_index,
                    &preparation.payment_request_intent,
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
                if payment != expected_payment
                    || row.bitcoin_address_lookup_hash != self.settlement_address_hash(&payment)?
                    || derivation_hash
                        != self
                            .crypto
                            .bitcoin_derivation_index_lookup_hash(
                                creator_hash,
                                payment.derivation_index(),
                            )
                            .as_bytes()
                {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                let publication = publication_state(
                    row.outbox_status
                        .as_deref()
                        .ok_or(PersistenceError::CorruptOrMissing)?,
                )?;
                let request_state = row
                    .request_state
                    .as_deref()
                    .map(parse_request_state)
                    .transpose()?;
                let bitcoin = if payment.has_bitcoin() {
                    self.status_bitcoin(
                        creator_hash,
                        &row,
                        payment.bitcoin_required_amount()?,
                        activated_at,
                    )?
                } else if row.observation_id.is_some() {
                    return Err(PersistenceError::CorruptOrMissing);
                } else {
                    None
                };
                let projected_payment_status = match bitcoin.as_ref() {
                    None => "undetected",
                    Some(bitcoin) if !bitcoin.present => "undetected",
                    Some(bitcoin) if bitcoin.confirmations == 0 => "detected",
                    Some(_) => "confirmed",
                };
                let projected_confirmations = bitcoin.as_ref().map_or(0, |bitcoin| {
                    if bitcoin.amount_matched {
                        bitcoin.confirmations.min(6)
                    } else {
                        bitcoin.confirmations
                    }
                });
                let projected_amount_matched = bitcoin
                    .as_ref()
                    .is_some_and(|bitcoin| bitcoin.present && bitcoin.amount_matched);
                if stored_payment_status != projected_payment_status
                    || stored_confirmations
                        != i32::try_from(projected_confirmations)
                            .map_err(|_| PersistenceError::CorruptOrMissing)?
                    || stored_amount_matched != projected_amount_matched
                {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                let (usdt, first_usdt_qualifying_at) = match self
                    .status_usdt(
                        &mut tx,
                        creator_hash,
                        row.id,
                        &payment,
                        activated_at,
                        payment_deadline,
                    )
                    .await?
                {
                    Some((usdt, first)) => (Some(usdt), first),
                    None => (None, None),
                };
                // Each rail is judged alone: partial payments are never combined, and
                // the rail whose receipt qualified first is the paid asset. The two
                // times come from different clocks: Bitcoin's is this server's first
                // sighting of the output (poll-interval granularity, after the
                // broadcast), USDT's is the chain's whole-second block time. They only
                // order two payments that both qualified, so a close race can name
                // either rail; Bitcoin wins an exact tie. USDT's time is the earliest
                // qualifying receipt's, not the displayed receipt's, so a later,
                // higher-ranked receipt cannot move the payment behind Bitcoin.
                let bitcoin_paid = bitcoin
                    .as_ref()
                    .filter(|bitcoin| bitcoin.paid_on_time)
                    .map(|bitcoin| (bitcoin.first_observed_at, AcceptedAsset::Btc));
                let usdt_paid = first_usdt_qualifying_at.map(|first| (first, AcceptedAsset::Usdt));
                let paid_asset = [bitcoin_paid, usdt_paid]
                    .into_iter()
                    .flatten()
                    .min()
                    .map(|(_, asset)| asset);
                let paid_on_time = paid_asset.is_some();
                let deadline_passed = row.observed_at > payment_deadline
                    || bitcoin
                        .as_ref()
                        .is_some_and(|bitcoin| bitcoin.first_observed_at > payment_deadline)
                    || usdt
                        .as_ref()
                        .is_some_and(|usdt| usdt.observed_at > payment_deadline);
                let payment_state = if deadline_passed && !paid_on_time {
                    "expired"
                } else if projected_payment_status == "confirmed"
                    || usdt.as_ref().is_some_and(|usdt| usdt.confirmations > 0)
                {
                    "confirmed"
                } else if projected_payment_status == "detected" || usdt.is_some() {
                    "detected"
                } else {
                    "undetected"
                };
                Ok(Some(
                    MarketplaceInvoiceStatus::active(
                        row.id,
                        publication,
                        request_state,
                        payment_state,
                        activated_at,
                        payment_deadline,
                        bitcoin,
                        outcome,
                        row.resolved_at,
                    )
                    .with_offer(accepted_assets, payment_amounts)
                    .with_usdt(usdt, paid_asset),
                ))
            }
            _ => Err(PersistenceError::CorruptOrMissing),
        }
    }

    fn status_bitcoin(
        &self,
        creator_hash: LookupHash,
        row: &MarketplaceStatusRow,
        required_sats: u64,
        activated_at: OffsetDateTime,
    ) -> Result<Option<MarketplaceBitcoinStatus>, PersistenceError> {
        let values = match (
            row.observation_id,
            row.observation_envelope.as_ref(),
            row.outpoint_lookup_hash.as_ref(),
            row.confirmations,
            row.present,
            row.first_observed_at,
        ) {
            (None, None, None, None, None, None) => return Ok(None),
            (
                Some(id),
                Some(envelope),
                Some(hash),
                Some(confirmations),
                Some(present),
                Some(first_observed_at),
            ) => (
                id,
                envelope.clone(),
                hash,
                confirmations,
                present,
                first_observed_at,
            ),
            _ => return Err(PersistenceError::CorruptOrMissing),
        };
        let observation =
            self.decrypt_marketplace_observation(creator_hash, row.id, values.0, values.1)?;
        if values.2
            != self
                .crypto
                .bitcoin_outpoint_lookup_hash(observation.outpoint.as_bytes())
                .as_bytes()
            || values.3 < 0
            || (!values.4 && values.3 != 0)
            || values.5 < activated_at
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let outpoint = observation
            .outpoint
            .parse::<bitcoin::OutPoint>()
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let confirmations =
            u32::try_from(values.3).map_err(|_| PersistenceError::CorruptOrMissing)?;
        let amount_matched = values.4 && observation.observed_sats >= required_sats;
        let paid_on_time = values.4 && amount_matched && row.active_outpoint_timely;
        Ok(Some(MarketplaceBitcoinStatus::new(
            outpoint.txid.to_string(),
            outpoint.vout,
            observation.observed_sats,
            values.5,
            if values.4 { confirmations } else { 0 },
            values.4,
            amount_matched,
            paid_on_time,
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_replay(
        &self,
        creator_hash: LookupHash,
        operation_hash: LookupHash,
        request_hash: LookupHash,
        reader_hash: LookupHash,
        input: MarketplacePreparationInput<'_>,
        row: PreparationRow,
    ) -> Result<MarketplacePreparationResult, PersistenceError> {
        if stored_hash(&row.operation_lookup_hash)? != operation_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }
        if stored_hash(&row.request_lookup_hash)? != request_hash {
            return Err(PersistenceError::Conflict);
        }
        if stored_hash(&row.reader_lookup_hash)? != reader_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::marketplace_preparation(creator_hash, row.id),
                &EncryptedEnvelope::from_bytes(row.preparation_envelope),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let envelope = PreparationEnvelope::decode(&plaintext)?;
        let stored_ttl = i64::try_from(envelope.prepare_ttl_seconds)
            .map(Duration::seconds)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if envelope.version != 2
            || envelope.operation_id != input.operation_id
            || envelope.request_binding != input.request_binding
            || envelope.reader != input.reader.to_string()
            || envelope.reference != input.reference
            || !envelope.terms_match(input.amount, input.asset)
            || envelope.payment_window_seconds != input.payment_window_seconds
            || envelope.prepared_at != row.prepared_at
            || envelope.prepare_expires_at != row.prepare_expires_at
            || envelope.prepared_at.checked_add(stored_ttl) != Some(envelope.prepare_expires_at)
            || envelope.child_index < 0
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let quote = validate_intent(
            &envelope.payment_request_intent,
            input.reader,
            input.reference,
            &envelope.terms,
        )?;
        Ok(MarketplacePreparationResult {
            invoice_id: row.id,
            terms: envelope.terms,
            quote,
            prepared_at: row.prepared_at,
            prepare_expires_at: row.prepare_expires_at,
            replayed: true,
        })
    }
}

#[async_trait::async_trait]
impl MarketplaceStatusPersistence for MarketplacePreparationStore {
    async fn status(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<MarketplaceInvoiceStatus>, MarketplaceStatusError> {
        self.status_snapshot(creator, invoice_id)
            .await
            .map_err(|error| match error {
                PersistenceError::Conflict => MarketplaceStatusError::Conflict,
                _ => MarketplaceStatusError::Unavailable,
            })
    }
}

fn publication_state(value: &str) -> Result<&'static str, PersistenceError> {
    match value {
        "queued" | "leased" | "retryable" | "handed_off" => Ok("pending"),
        "delivered" => Ok("delivered"),
        "permanently_failed" => Ok("failed"),
        _ => Err(PersistenceError::CorruptOrMissing),
    }
}

fn parse_request_state(value: &str) -> Result<&'static str, PersistenceError> {
    match value {
        "proposed" => Ok("proposed"),
        "proposal_expired" => Ok("proposal_expired"),
        "accepted" => Ok("accepted"),
        "rejected" => Ok("rejected"),
        "canceled" => Ok("canceled"),
        "proof_submitted" => Ok("proof_submitted"),
        "active_recurring" => Ok("active_recurring"),
        "recovery_required" => Ok("recovery_required"),
        "invalid_conflict" => Ok("invalid_conflict"),
        _ => Err(PersistenceError::CorruptOrMissing),
    }
}

fn parse_business_outcome(value: &str) -> Result<&'static str, PersistenceError> {
    match value {
        "paid_manually" => Ok("paid_manually"),
        "refunded" => Ok("refunded"),
        "abandoned" => Ok("abandoned"),
        _ => Err(PersistenceError::CorruptOrMissing),
    }
}

fn validate_intent(
    intent: &DeliveryIntentV1,
    reader: &ReaderPubky,
    reference: &str,
    terms: &MarketplaceTerms,
) -> Result<MarketplaceQuote, PersistenceError> {
    intent
        .validate()
        .map_err(|_| PersistenceError::InvalidInput)?;
    if parse_reader(intent.reader_pubky()).ok().as_ref() != Some(reader) {
        return Err(PersistenceError::InvalidInput);
    }
    if intent
        .terms()
        .map_err(|_| PersistenceError::InvalidInput)?
        .payment_reference
        != reference
    {
        return Err(PersistenceError::InvalidInput);
    }
    MarketplaceQuote::from_intent(intent, terms)
}

fn stored_hash(bytes: &[u8]) -> Result<LookupHash, PersistenceError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    Ok(LookupHash::from_bytes(bytes))
}

fn classify_preparation_insert_error(error: sqlx::Error) -> PersistenceError {
    match error {
        sqlx::Error::Database(error)
            if error.is_unique_violation()
                && error.constraint() == Some(OPERATION_BINDING_UNIQUE_CONSTRAINT) =>
        {
            PersistenceError::Conflict
        }
        sqlx::Error::Database(_) => PersistenceError::CorruptOrMissing,
        _ => PersistenceError::Unavailable,
    }
}

fn classify_settlement_insert_error(error: sqlx::Error) -> PersistenceError {
    match error {
        sqlx::Error::Database(_) => PersistenceError::CorruptOrMissing,
        _ => PersistenceError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_transport_failure_is_unavailable() {
        assert_eq!(
            classify_preparation_insert_error(sqlx::Error::PoolClosed),
            PersistenceError::Unavailable
        );
    }

    fn legacy_intent() -> DeliveryIntentV1 {
        use std::collections::HashMap;

        use paykit_lib::{
            PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload,
            PaymentReference, PaymentRequestTerms,
        };
        let app_id = PaykitAppId::new("paykit-server").unwrap();
        let endpoint = PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap();
        let terms = PaymentRequestTerms::builder(
            PaymentAmount::new("0.00050000", "btc").unwrap(),
            PaymentReference::new("7cceb26d-9042-4ea6-bfcb-01bbd778d76e").unwrap(),
            vec![endpoint.clone()],
        )
        .required_app_id(Some(app_id.clone()))
        .payment_endpoints(Some(HashMap::from([(
            endpoint,
            PaymentEndpointPayload::new(
                serde_json::json!({"value": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"})
                    .to_string(),
            ),
        )])))
        .build()
        .unwrap();
        DeliveryIntentV1::payment_request(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy".into(),
            app_id,
            &terms,
        )
        .unwrap()
    }

    fn legacy_envelope() -> PreparationEnvelopeV1 {
        PreparationEnvelopeV1 {
            version: 1,
            operation_id: "marketplace-payment:order-1:attempt-1".into(),
            request_binding: b"rc16 binding".to_vec(),
            reader: "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy".into(),
            reference: "7cceb26d-9042-4ea6-bfcb-01bbd778d76e".into(),
            total_sats: 50_000,
            payment_window_seconds: 86_400,
            prepare_ttl_seconds: 900,
            prepared_at: OffsetDateTime::UNIX_EPOCH,
            prepare_expires_at: OffsetDateTime::UNIX_EPOCH + Duration::minutes(15),
            child_index: 3,
            payment_request_intent: legacy_intent(),
        }
    }

    #[test]
    fn rc16_envelope_reads_as_bitcoin_denominated_bitcoin_only() {
        let bytes = postcard::to_allocvec(&legacy_envelope()).unwrap();
        let envelope = PreparationEnvelope::decode(&bytes).unwrap();
        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.child_index, 3);
        assert_eq!(envelope.terms.amount(), 50_000);
        assert_eq!(envelope.terms.asset(), CriterionAsset::Btc);
        assert_eq!(envelope.terms.accepted_assets(), [AcceptedAsset::Btc]);
        assert_eq!(
            envelope.quote().unwrap().payment_amounts(),
            [(AcceptedAsset::Btc, 50_000)]
        );
        assert!(envelope.terms_match(50_000, CriterionAsset::Btc));
        assert!(!envelope.terms_match(50_000, CriterionAsset::Usd));
    }

    #[test]
    fn current_envelope_round_trips_and_unknown_versions_are_corrupt() {
        let legacy = legacy_envelope();
        let current = PreparationEnvelope {
            version: 2,
            operation_id: legacy.operation_id,
            request_binding: legacy.request_binding,
            reader: legacy.reader,
            reference: legacy.reference,
            terms: MarketplaceTerms::new(
                50_000,
                CriterionAsset::Btc,
                [AcceptedAsset::Usdt, AcceptedAsset::Btc],
            )
            .unwrap(),
            payment_window_seconds: legacy.payment_window_seconds,
            prepare_ttl_seconds: legacy.prepare_ttl_seconds,
            prepared_at: legacy.prepared_at,
            prepare_expires_at: legacy.prepare_expires_at,
            child_index: legacy.child_index,
            payment_request_intent: legacy.payment_request_intent,
        };
        let bytes = postcard::to_allocvec(&current).unwrap();
        let decoded = PreparationEnvelope::decode(&bytes).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.terms, current.terms);
        for version in [0_u8, 3, 255] {
            let mut tampered = bytes.clone();
            tampered[0] = version;
            assert_eq!(
                PreparationEnvelope::decode(&tampered).err(),
                Some(PersistenceError::CorruptOrMissing)
            );
        }
        assert_eq!(
            PreparationEnvelope::decode(&[]).err(),
            Some(PersistenceError::CorruptOrMissing)
        );
    }
}
