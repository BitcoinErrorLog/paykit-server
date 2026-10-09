//! Durable unpublished Marketplace invoice preparation.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::locks::{CreatorPubky, ReaderPubky, parse_reader},
    persistence::PersistenceError,
};

const OPERATION_BINDING_UNIQUE_CONSTRAINT: &str = "marketplace_preparation_operation_binding_key";

/// Opaque inputs for one atomic Marketplace preparation.
pub struct MarketplacePreparationInput<'a> {
    pub creator: &'a CreatorPubky,
    pub reader: &'a ReaderPubky,
    pub reference: &'a str,
    pub operation_id: &'a str,
    pub request_binding: &'a [u8],
    pub total_sats: u64,
    pub payment_window_seconds: u64,
    pub prepare_ttl_seconds: u64,
    pub payloads: &'a dyn MarketplacePreparationPayloadFactory,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketplacePreparationResult {
    invoice_id: Uuid,
    total_sats: u64,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
    replayed: bool,
}

impl MarketplacePreparationResult {
    /// Builds a result returned by an injected persistence adapter.
    pub fn new(
        invoice_id: Uuid,
        total_sats: u64,
        prepared_at: OffsetDateTime,
        prepare_expires_at: OffsetDateTime,
        replayed: bool,
    ) -> Self {
        Self {
            invoice_id,
            total_sats,
            prepared_at,
            prepare_expires_at,
            replayed,
        }
    }

    pub fn invoice_id(&self) -> Uuid {
        self.invoice_id
    }

    pub fn total_sats(&self) -> u64 {
        self.total_sats
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

/// PostgreSQL-backed Marketplace preparation store.
#[derive(Clone, Debug)]
pub struct MarketplacePreparationStore {
    pool: PgPool,
    crypto: Arc<Crypto>,
}

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

impl MarketplacePreparationStore {
    pub fn new(pool: &PgPool, crypto: Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
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
            || input.total_sats == 0
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

        let prepared_at: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let prepare_expires_at = prepared_at
            .checked_add(ttl)
            .ok_or(PersistenceError::InvalidInput)?;
        let payloads = input.payloads.for_child_index(creator.next_child_index)?;
        validate_intent(
            &payloads.payment_request_intent,
            input.reader,
            input.reference,
            input.total_sats,
        )?;
        let invoice_id = Uuid::new_v4();
        let envelope = PreparationEnvelopeV1 {
            version: 1,
            operation_id: input.operation_id.to_owned(),
            request_binding: input.request_binding.to_vec(),
            reader: input.reader.to_string(),
            reference: input.reference.to_owned(),
            total_sats: input.total_sats,
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
            total_sats: input.total_sats,
            prepared_at,
            prepare_expires_at,
            replayed: false,
        })
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
        let envelope: PreparationEnvelopeV1 =
            postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
        let stored_ttl = i64::try_from(envelope.prepare_ttl_seconds)
            .map(Duration::seconds)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if envelope.version != 1
            || envelope.operation_id != input.operation_id
            || envelope.request_binding != input.request_binding
            || envelope.reader != input.reader.to_string()
            || envelope.reference != input.reference
            || envelope.total_sats != input.total_sats
            || envelope.payment_window_seconds != input.payment_window_seconds
            || envelope.prepared_at != row.prepared_at
            || envelope.prepare_expires_at != row.prepare_expires_at
            || envelope.prepared_at.checked_add(stored_ttl) != Some(envelope.prepare_expires_at)
            || envelope.child_index < 0
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        validate_intent(
            &envelope.payment_request_intent,
            input.reader,
            input.reference,
            input.total_sats,
        )?;
        Ok(MarketplacePreparationResult {
            invoice_id: row.id,
            total_sats: envelope.total_sats,
            prepared_at: row.prepared_at,
            prepare_expires_at: row.prepare_expires_at,
            replayed: true,
        })
    }
}

fn validate_intent(
    intent: &DeliveryIntentV1,
    reader: &ReaderPubky,
    reference: &str,
    total_sats: u64,
) -> Result<(), PersistenceError> {
    intent
        .validate()
        .map_err(|_| PersistenceError::InvalidInput)?;
    if parse_reader(intent.reader_pubky()).ok().as_ref() != Some(reader) {
        return Err(PersistenceError::InvalidInput);
    }
    let terms = intent.terms().map_err(|_| PersistenceError::InvalidInput)?;
    let expected = format!(
        "{}.{:08}",
        total_sats / 100_000_000,
        total_sats % 100_000_000
    );
    if terms.asset != "btc" || terms.amount != expected || terms.payment_reference != reference {
        return Err(PersistenceError::InvalidInput);
    }
    Ok(())
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
}
