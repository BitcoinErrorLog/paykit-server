//! Durable, attributable projection of canonical Paykit SDK Payment Request state.

use std::sync::Arc;

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::{
        locks::{BundleId, CreatorPubky, PubkyLockResource},
        payment_request_lifecycle::{
            PaymentRequestLifecycleProjection, PaymentRequestLifecycleState,
            PersistedPaymentRequestLifecycle, aggregate_lifecycle,
            cursor_stable_transition_allowed,
        },
    },
    persistence::PersistenceError,
};

#[derive(Clone, Debug)]
pub struct PaymentRequestLifecycleStore {
    pool: PgPool,
    crypto: Arc<Crypto>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentRequestLifecycleApply {
    Applied,
    ExactReplay,
    NotAttributable,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RequiredReceiveTarget {
    counterparty: String,
}

impl std::fmt::Debug for RequiredReceiveTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RequiredReceiveTarget(<redacted>)")
    }
}

impl RequiredReceiveTarget {
    pub fn counterparty(&self) -> &str {
        &self.counterparty
    }
}

#[derive(sqlx::FromRow)]
struct LifecycleRow {
    invoice_id: Uuid,
    sdk_payment_request_id: String,
    request_state: String,
    state_event_id: Option<String>,
    last_stream_item_id: Option<i64>,
    last_outbound_message_id: Option<i64>,
    last_event_at: time::OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct IntentRow {
    id: Uuid,
    invoice_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    intent_envelope: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct RequiredReceiveTargetRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    intent_envelope: Vec<u8>,
}

impl PaymentRequestLifecycleStore {
    pub fn new(pool: &PgPool, crypto: Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    pub async fn required_receive_targets_for_lock(
        &self,
        creator_id: Uuid,
        lock_resource: &PubkyLockResource,
    ) -> Result<Vec<RequiredReceiveTarget>, PersistenceError> {
        let lock_hash = self
            .crypto
            .lookup_hash(lock_resource.to_string().as_bytes());
        let rows = sqlx::query_as::<_, RequiredReceiveTargetRow>(
            "SELECT DISTINCT ON (invoice.id)
                    proposal.id, creator.creator_lookup_hash, proposal.intent_envelope
             FROM invoices AS invoice
             JOIN creators AS creator ON creator.id = invoice.creator_id
             JOIN lock_payment_generations AS generation
               ON generation.creator_id = invoice.creator_id
              AND generation.lock_resource_lookup_hash = invoice.lock_resource_lookup_hash
              AND generation.current_generation = invoice.lock_resource_generation
             JOIN outbox AS proposal
               ON proposal.invoice_id = invoice.id
              AND proposal.intent_kind = 'payment_request_proposal'
             WHERE invoice.creator_id = $1
               AND invoice.lock_resource_lookup_hash = $2
               AND (
                   NOT EXISTS (
                       SELECT 1 FROM payment_request_lifecycles AS lifecycle
                       WHERE lifecycle.invoice_id = invoice.id
                   )
                   OR EXISTS (
                       SELECT 1 FROM payment_request_lifecycles AS lifecycle
                       WHERE lifecycle.invoice_id = invoice.id
                         AND lifecycle.request_state NOT IN (
                             'proposal_expired', 'rejected', 'canceled'
                         )
                   )
               )
             ORDER BY invoice.id, proposal.created_at, proposal.id",
        )
        .bind(creator_id)
        .bind(lock_hash.as_bytes().as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        self.decode_required_receive_targets(rows)
    }

    pub async fn required_receive_targets_for_bundle(
        &self,
        creator_id: Uuid,
        bundle_id: &BundleId,
    ) -> Result<Vec<RequiredReceiveTarget>, PersistenceError> {
        let bundle_hash = self.crypto.lookup_hash(bundle_id.to_string().as_bytes());
        let rows = sqlx::query_as::<_, RequiredReceiveTargetRow>(
            "SELECT DISTINCT ON (invoice.id)
                    proposal.id, creator.creator_lookup_hash, proposal.intent_envelope
             FROM invoices AS invoice
             JOIN creators AS creator ON creator.id = invoice.creator_id
             JOIN lock_payment_generations AS generation
               ON generation.creator_id = invoice.creator_id
              AND generation.lock_resource_lookup_hash = invoice.lock_resource_lookup_hash
              AND generation.current_generation = invoice.lock_resource_generation
             JOIN outbox AS proposal
               ON proposal.invoice_id = invoice.id
              AND proposal.intent_kind = 'payment_request_proposal'
             WHERE invoice.creator_id = $1
               AND invoice.bundle_lookup_hash = $2
               AND (
                   NOT EXISTS (
                       SELECT 1 FROM payment_request_lifecycles AS lifecycle
                       WHERE lifecycle.invoice_id = invoice.id
                   )
                   OR EXISTS (
                       SELECT 1 FROM payment_request_lifecycles AS lifecycle
                       WHERE lifecycle.invoice_id = invoice.id
                         AND lifecycle.request_state NOT IN (
                             'proposal_expired', 'rejected', 'canceled'
                         )
                   )
               )
             ORDER BY invoice.id, proposal.created_at, proposal.id",
        )
        .bind(creator_id)
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        self.decode_required_receive_targets(rows)
    }

    pub(crate) async fn required_receive_targets_for_lock_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        creator_id: Uuid,
        lock_hash: &LookupHash,
    ) -> Result<Vec<RequiredReceiveTarget>, PersistenceError> {
        let rows = sqlx::query_as::<_, RequiredReceiveTargetRow>(
            "SELECT DISTINCT ON (invoice.id)
                    proposal.id, creator.creator_lookup_hash, proposal.intent_envelope
             FROM invoices AS invoice
             JOIN creators AS creator ON creator.id = invoice.creator_id
             JOIN lock_payment_generations AS generation
               ON generation.creator_id = invoice.creator_id
              AND generation.lock_resource_lookup_hash = invoice.lock_resource_lookup_hash
              AND generation.current_generation = invoice.lock_resource_generation
             JOIN outbox AS proposal
               ON proposal.invoice_id = invoice.id
              AND proposal.intent_kind = 'payment_request_proposal'
             WHERE invoice.creator_id = $1
               AND invoice.lock_resource_lookup_hash = $2
               AND (
                   NOT EXISTS (
                       SELECT 1 FROM payment_request_lifecycles AS lifecycle
                       WHERE lifecycle.invoice_id = invoice.id
                   )
                   OR EXISTS (
                       SELECT 1 FROM payment_request_lifecycles AS lifecycle
                       WHERE lifecycle.invoice_id = invoice.id
                         AND lifecycle.request_state NOT IN (
                             'proposal_expired', 'rejected', 'canceled'
                         )
                   )
               )
             ORDER BY invoice.id, proposal.created_at, proposal.id",
        )
        .bind(creator_id)
        .bind(lock_hash.as_bytes().as_slice())
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        self.decode_required_receive_targets(rows)
    }

    pub(crate) async fn required_receive_targets_for_bundle_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        creator_id: Uuid,
        bundle_hash: &LookupHash,
    ) -> Result<Vec<RequiredReceiveTarget>, PersistenceError> {
        let rows = sqlx::query_as::<_, RequiredReceiveTargetRow>(
            "SELECT DISTINCT ON (invoice.id)
                    proposal.id, creator.creator_lookup_hash, proposal.intent_envelope
             FROM invoices AS invoice
             JOIN creators AS creator ON creator.id = invoice.creator_id
             JOIN lock_payment_generations AS generation
               ON generation.creator_id = invoice.creator_id
              AND generation.lock_resource_lookup_hash = invoice.lock_resource_lookup_hash
              AND generation.current_generation = invoice.lock_resource_generation
             JOIN outbox AS proposal
               ON proposal.invoice_id = invoice.id
              AND proposal.intent_kind = 'payment_request_proposal'
             WHERE invoice.creator_id = $1
               AND invoice.bundle_lookup_hash = $2
               AND (
                   NOT EXISTS (
                       SELECT 1 FROM payment_request_lifecycles AS lifecycle
                       WHERE lifecycle.invoice_id = invoice.id
                   )
                   OR EXISTS (
                       SELECT 1 FROM payment_request_lifecycles AS lifecycle
                       WHERE lifecycle.invoice_id = invoice.id
                         AND lifecycle.request_state NOT IN (
                             'proposal_expired', 'rejected', 'canceled'
                         )
                   )
               )
             ORDER BY invoice.id, proposal.created_at, proposal.id",
        )
        .bind(creator_id)
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        self.decode_required_receive_targets(rows)
    }

    pub(crate) fn receive_evidence_covers(
        current: &[RequiredReceiveTarget],
        evidence: &[RequiredReceiveTarget],
    ) -> bool {
        current.iter().all(|target| evidence.contains(target))
    }

    fn decode_required_receive_targets(
        &self,
        rows: Vec<RequiredReceiveTargetRow>,
    ) -> Result<Vec<RequiredReceiveTarget>, PersistenceError> {
        let mut targets = Vec::new();
        for row in rows {
            let creator_hash = lookup_hash(&row.creator_lookup_hash)?;
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::outbox_semantic_intent(creator_hash, row.id),
                    &EncryptedEnvelope::from_bytes(row.intent_envelope),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let intent = DeliveryIntentV1::decode(&plaintext)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            if !matches!(
                intent.operation(),
                crate::application::semantic_intent::DeliveryOperationV1::PaymentRequestProposal { .. }
            ) {
                return Err(PersistenceError::CorruptOrMissing);
            }
            let target = RequiredReceiveTarget {
                counterparty: intent.reader_pubky().to_owned(),
            };
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
        Ok(targets)
    }

    /// Applies a canonical SDK snapshot only when its exact request ID or full
    /// stable proposal semantics identify one invoice for the selected Creator.
    pub async fn apply(
        &self,
        creator_id: Uuid,
        projection: &PaymentRequestLifecycleProjection,
    ) -> Result<PaymentRequestLifecycleApply, PersistenceError> {
        validate_projection(projection)?;
        let stream_cursor = optional_cursor(projection.last_stream_item_id)?;
        let outbound_cursor = optional_cursor(projection.last_outbound_message_id)?;
        let last_event_at = postgres_timestamp(projection.last_event_at)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;

        let direct_invoice_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT invoice_id
             FROM outbox
             WHERE creator_id = $1 AND sdk_payment_request_id = $2 AND invoice_id IS NOT NULL",
        )
        .bind(creator_id)
        .bind(&projection.payment_request_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if direct_invoice_ids.len() > 1 {
            return Err(PersistenceError::CorruptOrMissing);
        }

        // The Payment Reference is generated once by the server and reused by
        // every ambiguous SDK proposal retry. Use its dedicated keyed proposal
        // lookup to bound correlation, then validate every immutable proposal
        // field from the authenticated intent before attributing the attempt.
        let payment_reference_hash = self.crypto.payment_request_proposal_lookup_hash(
            projection.proposal.terms.payment_reference.as_bytes(),
        );
        let intent_rows = sqlx::query_as::<_, IntentRow>(
            "SELECT outbox.id, outbox.invoice_id, creators.creator_lookup_hash,
                    outbox.intent_envelope
             FROM outbox
             JOIN creators ON creators.id = outbox.creator_id
             WHERE outbox.creator_id = $1
               AND outbox.proposal_lookup_hash = $2
             ORDER BY outbox.id",
        )
        .bind(creator_id)
        .bind(payment_reference_hash.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let mut semantic_invoice_ids = Vec::new();
        for row in intent_rows {
            let creator_hash = lookup_hash(&row.creator_lookup_hash)?;
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::outbox_semantic_intent(creator_hash, row.id),
                    &EncryptedEnvelope::from_bytes(row.intent_envelope),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let intent = DeliveryIntentV1::decode(&plaintext)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            if intent.matches_proposal(
                &projection.proposal.reader_pubky,
                &projection.proposal.proposal_app_id,
                &projection.proposal.terms,
            ) && !semantic_invoice_ids.contains(&row.invoice_id)
            {
                semantic_invoice_ids.push(row.invoice_id);
            }
        }
        let invoice_id = match semantic_invoice_ids.as_slice() {
            [] if direct_invoice_ids.is_empty() => {
                return Ok(PaymentRequestLifecycleApply::NotAttributable);
            }
            [invoice_id]
                if direct_invoice_ids.is_empty()
                    || direct_invoice_ids.first() == Some(invoice_id) =>
            {
                *invoice_id
            }
            _ => return Err(PersistenceError::CorruptOrMissing),
        };

        let locked_invoice: Option<Uuid> = sqlx::query_scalar(
            "SELECT id
             FROM invoices
             WHERE id = $1 AND creator_id = $2
             FOR UPDATE",
        )
        .bind(invoice_id)
        .bind(creator_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if locked_invoice.is_none() {
            return Err(PersistenceError::CorruptOrMissing);
        }

        let existing = sqlx::query_as::<_, LifecycleRow>(
            "SELECT invoice_id, sdk_payment_request_id, request_state, state_event_id,
                    last_stream_item_id, last_outbound_message_id, last_event_at
             FROM payment_request_lifecycles
             WHERE sdk_payment_request_id = $1
             FOR UPDATE",
        )
        .bind(&projection.payment_request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        if let Some(existing) = existing {
            if exact_replay(
                &existing,
                projection,
                stream_cursor,
                outbound_cursor,
                last_event_at,
            ) {
                transaction
                    .commit()
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                return Ok(PaymentRequestLifecycleApply::ExactReplay);
            }
            let existing_state = PaymentRequestLifecycleState::parse(&existing.request_state)
                .ok_or(PersistenceError::CorruptOrMissing)?;
            let source_cursors_equal = stream_cursor == existing.last_stream_item_id
                && outbound_cursor == existing.last_outbound_message_id;
            let equal_cursor_update_allowed = existing.state_event_id == projection.state_event_id
                && (existing_state == projection.request_state
                    || cursor_stable_transition_allowed(existing_state, projection.request_state));
            if existing.invoice_id != invoice_id
                || existing.sdk_payment_request_id != projection.payment_request_id
                || (existing_state == PaymentRequestLifecycleState::ProposalExpired
                    && projection.request_state == PaymentRequestLifecycleState::Proposed)
                || cursor_regressed(stream_cursor, existing.last_stream_item_id)
                || cursor_regressed(outbound_cursor, existing.last_outbound_message_id)
                || last_event_at < existing.last_event_at
                || (source_cursors_equal && !equal_cursor_update_allowed)
            {
                return Err(PersistenceError::Conflict);
            }
            sqlx::query(
                "UPDATE payment_request_lifecycles
                 SET request_state = $1, state_event_id = $2,
                     last_stream_item_id = $3, last_outbound_message_id = $4,
                     last_event_at = $5, updated_at = NOW()
                 WHERE sdk_payment_request_id = $6",
            )
            .bind(projection.request_state.as_str())
            .bind(&projection.state_event_id)
            .bind(stream_cursor)
            .bind(outbound_cursor)
            .bind(last_event_at)
            .bind(&projection.payment_request_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        } else {
            let inserted = sqlx::query(
                "INSERT INTO payment_request_lifecycles (
                     invoice_id, sdk_payment_request_id, request_state, state_event_id,
                     last_stream_item_id, last_outbound_message_id, last_event_at
                 )
                 SELECT $1, $2, $3, $4, $5, $6, $7
                 WHERE EXISTS (
                     SELECT 1
                     FROM invoices invoice
                     JOIN lock_payment_generations generation
                       ON generation.creator_id = invoice.creator_id
                      AND generation.lock_resource_lookup_hash = invoice.lock_resource_lookup_hash
                      AND generation.current_generation = invoice.lock_resource_generation
                     WHERE invoice.id = $1 AND generation.active_drain_id IS NULL
                 )",
            )
            .bind(invoice_id)
            .bind(&projection.payment_request_id)
            .bind(projection.request_state.as_str())
            .bind(&projection.state_event_id)
            .bind(stream_cursor)
            .bind(outbound_cursor)
            .bind(last_event_at)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            if inserted.rows_affected() != 1 {
                return Err(PersistenceError::Conflict);
            }
        }

        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(PaymentRequestLifecycleApply::Applied)
    }

    pub async fn load(
        &self,
        creator: &CreatorPubky,
        bundle_id: Uuid,
    ) -> Result<Option<PersistedPaymentRequestLifecycle>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_id.as_bytes());
        let rows: Vec<(String, time::OffsetDateTime)> = sqlx::query_as(
            "SELECT lifecycle.request_state, lifecycle.last_event_at
             FROM payment_request_lifecycles AS lifecycle
             JOIN invoices ON invoices.id = lifecycle.invoice_id
             JOIN creators ON creators.id = invoices.creator_id
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let attempts = rows
            .into_iter()
            .map(|(request_state, last_event_at)| {
                PaymentRequestLifecycleState::parse(&request_state)
                    .map(|state| (state, last_event_at))
                    .ok_or(PersistenceError::CorruptOrMissing)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(aggregate_lifecycle(attempts))
    }

    /// Creator rows that currently have attributable SDK Payment Requests.
    pub async fn creator_ids(&self) -> Result<Vec<Uuid>, PersistenceError> {
        sqlx::query_scalar(
            "SELECT DISTINCT creator_id
             FROM outbox
             WHERE invoice_id IS NOT NULL
             ORDER BY creator_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }
}

fn lookup_hash(bytes: &[u8]) -> Result<LookupHash, PersistenceError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    Ok(LookupHash::from_bytes(bytes))
}

fn validate_projection(
    projection: &PaymentRequestLifecycleProjection,
) -> Result<(), PersistenceError> {
    if projection.payment_request_id.is_empty()
        || projection
            .state_event_id
            .as_ref()
            .is_some_and(String::is_empty)
        || (projection.last_stream_item_id.is_none()
            && projection.last_outbound_message_id.is_none())
    {
        return Err(PersistenceError::InvalidInput);
    }
    Ok(())
}

fn optional_cursor(value: Option<u64>) -> Result<Option<i64>, PersistenceError> {
    value
        .map(|value| i64::try_from(value).map_err(|_| PersistenceError::InvalidInput))
        .transpose()
}

fn postgres_timestamp(
    timestamp: time::OffsetDateTime,
) -> Result<time::OffsetDateTime, PersistenceError> {
    let micros = timestamp.unix_timestamp_nanos().div_euclid(1_000);
    let nanos = micros
        .checked_mul(1_000)
        .ok_or(PersistenceError::InvalidInput)?;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| PersistenceError::InvalidInput)
}

fn cursor_regressed(incoming: Option<i64>, existing: Option<i64>) -> bool {
    match (incoming, existing) {
        (None, Some(_)) => true,
        (Some(incoming), Some(existing)) => incoming < existing,
        _ => false,
    }
}

fn exact_replay(
    existing: &LifecycleRow,
    incoming: &PaymentRequestLifecycleProjection,
    stream_cursor: Option<i64>,
    outbound_cursor: Option<i64>,
    last_event_at: time::OffsetDateTime,
) -> bool {
    existing.sdk_payment_request_id == incoming.payment_request_id
        && existing.request_state == incoming.request_state.as_str()
        && existing.state_event_id == incoming.state_event_id
        && existing.last_stream_item_id == stream_cursor
        && existing.last_outbound_message_id == outbound_cursor
        && existing.last_event_at == last_event_at
}
