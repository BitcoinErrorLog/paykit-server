//! Durable, attributable projection of canonical Paykit SDK Payment Request state.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    crypto::Crypto,
    domain::{
        locks::CreatorPubky,
        payment_request_lifecycle::{
            PaymentRequestLifecycleProjection, PaymentRequestLifecycleState,
            PersistedPaymentRequestLifecycle, cursor_stable_transition_allowed,
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

#[derive(sqlx::FromRow)]
struct LifecycleRow {
    sdk_payment_request_id: String,
    request_state: String,
    state_event_id: Option<String>,
    last_stream_item_id: Option<i64>,
    last_outbound_message_id: Option<i64>,
    last_event_at: time::OffsetDateTime,
}

impl PaymentRequestLifecycleStore {
    pub fn new(pool: &PgPool, crypto: Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    /// Applies a canonical SDK snapshot only when its request ID is currently
    /// attributable to exactly one invoice for the selected Creator.
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

        let invoice_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT invoice_id
             FROM outbox
             WHERE creator_id = $1 AND sdk_payment_request_id = $2 AND invoice_id IS NOT NULL",
        )
        .bind(creator_id)
        .bind(&projection.payment_request_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let invoice_id = match invoice_ids.as_slice() {
            [] => return Ok(PaymentRequestLifecycleApply::NotAttributable),
            [invoice_id] => invoice_id,
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
            "SELECT sdk_payment_request_id, request_state, state_event_id,
                    last_stream_item_id, last_outbound_message_id, last_event_at
             FROM payment_request_lifecycles
             WHERE invoice_id = $1
             FOR UPDATE",
        )
        .bind(invoice_id)
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
            if existing.sdk_payment_request_id != projection.payment_request_id
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
                 WHERE invoice_id = $6",
            )
            .bind(projection.request_state.as_str())
            .bind(&projection.state_event_id)
            .bind(stream_cursor)
            .bind(outbound_cursor)
            .bind(last_event_at)
            .bind(invoice_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        } else {
            sqlx::query(
                "INSERT INTO payment_request_lifecycles (
                     invoice_id, sdk_payment_request_id, request_state, state_event_id,
                     last_stream_item_id, last_outbound_message_id, last_event_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
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
        let row: Option<(String, time::OffsetDateTime)> = sqlx::query_as(
            "SELECT lifecycle.request_state, lifecycle.last_event_at
             FROM payment_request_lifecycles AS lifecycle
             JOIN invoices ON invoices.id = lifecycle.invoice_id
             JOIN creators ON creators.id = invoices.creator_id
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        row.map(|(request_state, last_event_at)| {
            let request_state = PaymentRequestLifecycleState::parse(&request_state)
                .ok_or(PersistenceError::CorruptOrMissing)?;
            Ok(PersistedPaymentRequestLifecycle {
                request_state,
                last_event_at,
            })
        })
        .transpose()
    }

    /// Creator rows that currently have attributable SDK Payment Requests.
    pub async fn creator_ids(&self) -> Result<Vec<Uuid>, PersistenceError> {
        sqlx::query_scalar(
            "SELECT DISTINCT creator_id
             FROM outbox
             WHERE sdk_payment_request_id IS NOT NULL AND invoice_id IS NOT NULL
             ORDER BY creator_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }
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
