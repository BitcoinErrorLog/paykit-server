//! Atomic lock-wide Payment Request drain persistence.

use std::sync::Arc;

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::{locks::PubkyLockResource, payment_request_lifecycle::PaymentRequestLifecycleState},
    persistence::PersistenceError,
};

#[derive(Clone, Debug)]
pub struct PaymentDrainStore {
    pool: PgPool,
    crypto: Arc<Crypto>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PaymentDrainSnapshot {
    drain_id: Uuid,
    created_at: OffsetDateTime,
    accepted_count: u64,
    terminal_count: u64,
    cancellation_enqueued_count: u64,
    completed: bool,
    replayed: bool,
}

impl std::fmt::Debug for PaymentDrainSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PaymentDrainSnapshot")
            .field("accepted_count", &self.accepted_count)
            .field("terminal_count", &self.terminal_count)
            .field(
                "cancellation_enqueued_count",
                &self.cancellation_enqueued_count,
            )
            .field("completed", &self.completed)
            .field("replayed", &self.replayed)
            .finish_non_exhaustive()
    }
}

impl PaymentDrainSnapshot {
    pub fn drain_id(&self) -> Uuid {
        self.drain_id
    }

    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    pub fn accepted_count(&self) -> u64 {
        self.accepted_count
    }

    pub fn terminal_count(&self) -> u64 {
        self.terminal_count
    }

    pub fn cancellation_enqueued_count(&self) -> u64 {
        self.cancellation_enqueued_count
    }

    pub fn completed(&self) -> bool {
        self.completed
    }

    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(sqlx::FromRow)]
struct CreatorRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct ExistingDrainRow {
    id: Uuid,
    lock_resource_envelope: Vec<u8>,
    accepted_count: i64,
    terminal_count: i64,
    cancellation_enqueued_count: i64,
    status: String,
    created_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct InvoiceLifecycleRow {
    invoice_id: Uuid,
    request_state: Option<String>,
    sdk_payment_request_id: Option<String>,
}

struct PreparedCancellation {
    invoice_id: Uuid,
    outbox_id: Uuid,
    envelope: EncryptedEnvelope,
}

impl PaymentDrainStore {
    pub fn new(pool: &PgPool, crypto: Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    /// Returns an authenticated immutable replay without performing SDK or
    /// classification work. `None` means this lock has not been drained.
    pub async fn exact_replay(
        &self,
        lock_resource: &PubkyLockResource,
    ) -> Result<Option<PaymentDrainSnapshot>, PersistenceError> {
        let canonical_lock = lock_resource.to_string();
        let creator_hash = self
            .crypto
            .lookup_hash(lock_resource.creator().to_string().as_bytes());
        let lock_hash = self.crypto.lookup_hash(canonical_lock.as_bytes());
        let existing = sqlx::query_as::<_, ExistingDrainRow>(
            "SELECT drains.id, drains.lock_resource_envelope, drains.accepted_count,
                    drains.terminal_count, drains.cancellation_enqueued_count,
                    drains.status, drains.created_at
             FROM payment_drains AS drains
             JOIN creators ON creators.id = drains.creator_id
             WHERE creators.creator_lookup_hash = $1
               AND drains.lock_resource_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(lock_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(existing) = existing else {
            return Ok(None);
        };
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::payment_drain(creator_hash, existing.id),
                &EncryptedEnvelope::from_bytes(existing.lock_resource_envelope.clone()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if plaintext != canonical_lock.as_bytes() {
            return Err(PersistenceError::Conflict);
        }
        snapshot(existing, true).map(Some)
    }

    /// Creates or exactly replays one immutable lock-wide lifecycle snapshot.
    pub async fn create(
        &self,
        lock_resource: &PubkyLockResource,
    ) -> Result<PaymentDrainSnapshot, PersistenceError> {
        let canonical_lock = lock_resource.to_string();
        let creator_hash = self
            .crypto
            .lookup_hash(lock_resource.creator().to_string().as_bytes());
        let lock_hash = self.crypto.lookup_hash(canonical_lock.as_bytes());
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;

        let creator = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash FROM creators
             WHERE creator_lookup_hash = $1 FOR UPDATE",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if lookup_hash(&creator.creator_lookup_hash)? != creator_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }

        if let Some(existing) = sqlx::query_as::<_, ExistingDrainRow>(
            "SELECT id, lock_resource_envelope, accepted_count, terminal_count,
                    cancellation_enqueued_count, status, created_at
             FROM payment_drains
             WHERE creator_id = $1 AND lock_resource_lookup_hash = $2
             FOR UPDATE",
        )
        .bind(creator.id)
        .bind(lock_hash.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        {
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::payment_drain(creator_hash, existing.id),
                    &EncryptedEnvelope::from_bytes(existing.lock_resource_envelope.clone()),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            if plaintext != canonical_lock.as_bytes() {
                return Err(PersistenceError::Conflict);
            }
            transaction
                .commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return snapshot(existing, true);
        }

        sqlx::query(
            "INSERT INTO lock_payment_generations
                 (creator_id, lock_resource_lookup_hash)
             VALUES ($1, $2)
             ON CONFLICT (creator_id, lock_resource_lookup_hash) DO NOTHING",
        )
        .bind(creator.id)
        .bind(lock_hash.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let (lock_resource_generation, active_drain_id): (i64, Option<Uuid>) = sqlx::query_as(
            "SELECT current_generation, active_drain_id
                 FROM lock_payment_generations
                 WHERE creator_id = $1 AND lock_resource_lookup_hash = $2
                 FOR UPDATE",
        )
        .bind(creator.id)
        .bind(lock_hash.as_bytes().as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if lock_resource_generation < 0 || active_drain_id.is_some() {
            return Err(PersistenceError::CorruptOrMissing);
        }

        let rows = sqlx::query_as::<_, InvoiceLifecycleRow>(
            "SELECT invoices.id AS invoice_id, lifecycle.request_state,
                    lifecycle.sdk_payment_request_id
             FROM invoices
             LEFT JOIN payment_request_lifecycles AS lifecycle
               ON lifecycle.invoice_id = invoices.id
             WHERE invoices.creator_id = $1
               AND invoices.lock_resource_lookup_hash = $2
               AND invoices.lock_resource_generation = $3
             ORDER BY invoices.id
             FOR UPDATE OF invoices",
        )
        .bind(creator.id)
        .bind(lock_hash.as_bytes().as_slice())
        .bind(lock_resource_generation)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        let drain_id = Uuid::new_v4();
        let mut accepted_count = 0_i64;
        let mut terminal_count = 0_i64;
        let mut cancellations = Vec::new();
        let mut classifications = Vec::with_capacity(rows.len());
        for row in rows {
            let state = row
                .request_state
                .as_deref()
                .and_then(PaymentRequestLifecycleState::parse)
                .ok_or(PersistenceError::CorruptOrMissing)?;
            let classification = match state {
                PaymentRequestLifecycleState::Accepted => {
                    accepted_count += 1;
                    "accepted"
                }
                PaymentRequestLifecycleState::Rejected => {
                    terminal_count += 1;
                    "rejected"
                }
                PaymentRequestLifecycleState::Canceled => {
                    terminal_count += 1;
                    "canceled"
                }
                PaymentRequestLifecycleState::ProposalExpired => {
                    terminal_count += 1;
                    "proposal_expired"
                }
                PaymentRequestLifecycleState::Proposed => {
                    let payment_request_id = row
                        .sdk_payment_request_id
                        .ok_or(PersistenceError::CorruptOrMissing)?;
                    let proposal_rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
                        "SELECT id, intent_envelope FROM outbox
                         WHERE creator_id = $1 AND invoice_id = $2
                           AND sdk_payment_request_id = $3
                         ORDER BY created_at, id",
                    )
                    .bind(creator.id)
                    .bind(row.invoice_id)
                    .bind(&payment_request_id)
                    .fetch_all(&mut *transaction)
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                    let [(proposal_outbox_id, proposal_envelope)] = proposal_rows.as_slice() else {
                        return Err(PersistenceError::CorruptOrMissing);
                    };
                    let proposal_plaintext = self
                        .crypto
                        .decrypt(
                            &EnvelopeContext::outbox_semantic_intent(
                                creator_hash,
                                *proposal_outbox_id,
                            ),
                            &EncryptedEnvelope::from_bytes(proposal_envelope.clone()),
                        )
                        .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    let proposal = DeliveryIntentV1::decode(&proposal_plaintext)
                        .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    let cancellation = DeliveryIntentV1::payment_request_cancellation(
                        &proposal,
                        payment_request_id,
                    )
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    let outbox_id = Uuid::new_v4();
                    let plaintext = postcard::to_allocvec(&cancellation)
                        .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    let envelope = self
                        .crypto
                        .encrypt(
                            &EnvelopeContext::outbox_semantic_intent(creator_hash, outbox_id),
                            &plaintext,
                        )
                        .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    cancellations.push(PreparedCancellation {
                        invoice_id: row.invoice_id,
                        outbox_id,
                        envelope,
                    });
                    "cancellation_enqueued"
                }
                PaymentRequestLifecycleState::RecoveryRequired => {
                    return Err(PersistenceError::Unavailable);
                }
                PaymentRequestLifecycleState::InvalidConflict
                | PaymentRequestLifecycleState::ProofSubmitted
                | PaymentRequestLifecycleState::ActiveRecurring => {
                    return Err(PersistenceError::Conflict);
                }
            };
            classifications.push((row.invoice_id, classification));
        }

        let lock_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::payment_drain(creator_hash, drain_id),
                canonical_lock.as_bytes(),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let completed = accepted_count == 0;
        let created_at: OffsetDateTime = sqlx::query_scalar(
            "INSERT INTO payment_drains (
                 id, creator_id, lock_resource_lookup_hash, lock_resource_envelope,
                 lock_resource_generation, accepted_count, terminal_count,
                 cancellation_enqueued_count, status, completed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                       CASE WHEN $9 THEN 'completed' ELSE 'active' END,
                       CASE WHEN $9 THEN transaction_timestamp() ELSE NULL END)
             RETURNING created_at",
        )
        .bind(drain_id)
        .bind(creator.id)
        .bind(lock_hash.as_bytes().as_slice())
        .bind(lock_envelope.as_bytes())
        .bind(lock_resource_generation)
        .bind(accepted_count)
        .bind(terminal_count)
        .bind(i64::try_from(cancellations.len()).map_err(|_| PersistenceError::InvalidInput)?)
        .bind(completed)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let fenced = sqlx::query(
            "UPDATE lock_payment_generations
             SET active_drain_id = $1, updated_at = transaction_timestamp()
             WHERE creator_id = $2 AND lock_resource_lookup_hash = $3
               AND current_generation = $4 AND active_drain_id IS NULL",
        )
        .bind(drain_id)
        .bind(creator.id)
        .bind(lock_hash.as_bytes().as_slice())
        .bind(lock_resource_generation)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if fenced.rows_affected() != 1 {
            return Err(PersistenceError::Conflict);
        }

        for cancellation in &cancellations {
            sqlx::query(
                "INSERT INTO outbox (
                     id, creator_id, invoice_id, intent_envelope, status
                 ) VALUES ($1, $2, $3, $4, 'queued')",
            )
            .bind(cancellation.outbox_id)
            .bind(creator.id)
            .bind(cancellation.invoice_id)
            .bind(cancellation.envelope.as_bytes())
            .execute(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        for (invoice_id, classification) in classifications {
            let cancellation_outbox_id = cancellations
                .iter()
                .find(|cancellation| cancellation.invoice_id == invoice_id)
                .map(|cancellation| cancellation.outbox_id);
            sqlx::query(
                "INSERT INTO payment_drain_items (
                     drain_id, invoice_id, classification, cancellation_outbox_id
                 ) VALUES ($1, $2, $3, $4)",
            )
            .bind(drain_id)
            .bind(invoice_id)
            .bind(classification)
            .bind(cancellation_outbox_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }

        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(PaymentDrainSnapshot {
            drain_id,
            created_at,
            accepted_count: count(accepted_count)?,
            terminal_count: count(terminal_count)?,
            cancellation_enqueued_count: u64::try_from(cancellations.len())
                .map_err(|_| PersistenceError::CorruptOrMissing)?,
            completed,
            replayed: false,
        })
    }
}

fn snapshot(
    row: ExistingDrainRow,
    replayed: bool,
) -> Result<PaymentDrainSnapshot, PersistenceError> {
    let completed = match row.status.as_str() {
        "active" => false,
        "completed" => true,
        _ => return Err(PersistenceError::CorruptOrMissing),
    };
    Ok(PaymentDrainSnapshot {
        drain_id: row.id,
        created_at: row.created_at,
        accepted_count: count(row.accepted_count)?,
        terminal_count: count(row.terminal_count)?,
        cancellation_enqueued_count: count(row.cancellation_enqueued_count)?,
        completed,
        replayed,
    })
}

fn count(value: i64) -> Result<u64, PersistenceError> {
    u64::try_from(value).map_err(|_| PersistenceError::CorruptOrMissing)
}

fn lookup_hash(bytes: &[u8]) -> Result<LookupHash, PersistenceError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    Ok(LookupHash::from_bytes(bytes))
}
