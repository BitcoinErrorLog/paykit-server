//! Atomic lock-wide Payment Request drain persistence.

use std::{collections::BTreeMap, sync::Arc};

use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::{locks::PubkyLockResource, payment_request_lifecycle::PaymentRequestLifecycleState},
    persistence::{PaymentRequestLifecycleStore, PersistenceError, RequiredReceiveTarget},
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
    cancellation_set_hash: Vec<u8>,
    item_set_hash: Vec<u8>,
    status: String,
    created_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct InvoiceLifecycleRow {
    invoice_id: Uuid,
    request_state: Option<String>,
    sdk_payment_request_id: Option<String>,
    last_event_at: Option<OffsetDateTime>,
}

struct PreparedCancellation {
    invoice_id: Uuid,
    payment_request_id: String,
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
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let existing = sqlx::query_as::<_, ExistingDrainRow>(
            "SELECT drains.id, drains.lock_resource_envelope, drains.accepted_count,
                    drains.terminal_count, drains.cancellation_enqueued_count,
                    drains.cancellation_set_hash, drains.item_set_hash,
                    drains.status, drains.created_at
             FROM payment_drains AS drains
             JOIN creators ON creators.id = drains.creator_id
             JOIN lock_payment_generations AS generation
               ON generation.creator_id = drains.creator_id
              AND generation.lock_resource_lookup_hash = drains.lock_resource_lookup_hash
              AND generation.current_generation = drains.lock_resource_generation
              AND generation.active_drain_id = drains.id
             WHERE creators.creator_lookup_hash = $1
               AND drains.lock_resource_lookup_hash = $2
             FOR UPDATE OF drains",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(lock_hash.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
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
        self.validate_frozen_sets(&mut transaction, &existing)
            .await?;
        let progressed = sqlx::query_as::<_, ExistingDrainRow>(
            "WITH frozen AS (
                 SELECT
                     COUNT(*) FILTER (
                         WHERE item.classification = 'accepted'
                           AND invoice.payment_expired_at IS NULL
                           AND NOT (
                               invoice.first_amount_matched_observed_at IS NOT NULL
                               AND invoice.first_amount_matched_observed_at <= invoice.payment_deadline
                           )
                     ) AS accepted_count,
                     COUNT(*) FILTER (
                         WHERE item.classification IN ('rejected', 'canceled', 'proposal_expired')
                            OR (
                                item.classification = 'accepted'
                                AND (
                                    invoice.payment_expired_at IS NOT NULL
                                    OR (
                                        invoice.first_amount_matched_observed_at IS NOT NULL
                                        AND invoice.first_amount_matched_observed_at <= invoice.payment_deadline
                                    )
                                )
                            )
                     ) AS terminal_count,
                     (SELECT COUNT(*)
                      FROM payment_drain_cancellations cancellation
                      WHERE cancellation.drain_id = $1) AS cancellation_count
                 FROM payment_drain_items AS item
                 JOIN invoices AS invoice ON invoice.id = item.invoice_id
                 WHERE item.drain_id = $1
             )
             UPDATE payment_drains AS drain
             SET accepted_count = frozen.accepted_count,
                 terminal_count = frozen.terminal_count,
                 status = CASE WHEN frozen.accepted_count = 0 THEN 'completed' ELSE 'active' END,
                 completed_at = CASE
                     WHEN frozen.accepted_count = 0
                         THEN COALESCE(drain.completed_at, transaction_timestamp())
                     ELSE NULL
                 END,
                 updated_at = transaction_timestamp()
             FROM frozen
             WHERE drain.id = $1
               AND frozen.cancellation_count = drain.cancellation_enqueued_count
               AND frozen.accepted_count <= drain.accepted_count
               AND frozen.terminal_count >= drain.terminal_count
               AND frozen.terminal_count - drain.terminal_count
                   = drain.accepted_count - frozen.accepted_count
             RETURNING drain.id, drain.lock_resource_envelope, drain.accepted_count,
                       drain.terminal_count, drain.cancellation_enqueued_count,
                       drain.cancellation_set_hash, drain.item_set_hash,
                       drain.status, drain.created_at",
        )
        .bind(existing.id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        snapshot(progressed, true).map(Some)
    }

    /// Idempotently removes a completed operational drain while retaining its
    /// invoices, lifecycle projection, observations, and outbox history.
    pub async fn cleanup_completed(
        &self,
        lock_resource: &PubkyLockResource,
        cleanup_token: &[u8; 32],
    ) -> Result<(), PersistenceError> {
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

        let creator_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE")
                .bind(creator_hash.as_bytes().as_slice())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
        let Some(creator_id) = creator_id else {
            return Err(PersistenceError::Conflict);
        };

        let generation: Option<(i64, Option<Uuid>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT current_generation, active_drain_id, last_cleanup_token
             FROM lock_payment_generations
             WHERE creator_id = $1 AND lock_resource_lookup_hash = $2
             FOR UPDATE",
        )
        .bind(creator_id)
        .bind(lock_hash.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some((current_generation, active_drain_id, last_cleanup_token)) = generation else {
            let orphaned: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                     SELECT 1 FROM payment_drains
                     WHERE creator_id = $1 AND lock_resource_lookup_hash = $2
                     UNION ALL
                     SELECT 1 FROM invoices
                     WHERE creator_id = $1 AND lock_resource_lookup_hash = $2
                 )",
            )
            .bind(creator_id)
            .bind(lock_hash.as_bytes().as_slice())
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            if orphaned {
                return Err(PersistenceError::CorruptOrMissing);
            }
            return Err(PersistenceError::Conflict);
        };
        let Some(drain_id) = active_drain_id else {
            let orphaned: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                     SELECT 1 FROM payment_drains
                     WHERE creator_id = $1 AND lock_resource_lookup_hash = $2
                 )",
            )
            .bind(creator_id)
            .bind(lock_hash.as_bytes().as_slice())
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            if orphaned {
                return Err(PersistenceError::CorruptOrMissing);
            }
            let receipt = last_cleanup_token.ok_or(PersistenceError::CorruptOrMissing)?;
            if receipt.as_slice() != cleanup_token {
                return Err(PersistenceError::Conflict);
            }
            transaction
                .commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(());
        };

        let drain: ExistingDrainRow = sqlx::query_as(
            "SELECT id, lock_resource_envelope, accepted_count, terminal_count,
                    cancellation_enqueued_count, cancellation_set_hash, item_set_hash, status, created_at
             FROM payment_drains
             WHERE id = $1 AND creator_id = $2 AND lock_resource_lookup_hash = $3
               AND lock_resource_generation = $4
             FOR UPDATE",
        )
        .bind(drain_id)
        .bind(creator_id)
        .bind(lock_hash.as_bytes().as_slice())
        .bind(current_generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        let expected_token = self.crypto.payment_drain_cleanup_token(drain.id);
        if expected_token.as_bytes() != cleanup_token {
            return Err(PersistenceError::Conflict);
        }
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::payment_drain(creator_hash, drain.id),
                &EncryptedEnvelope::from_bytes(drain.lock_resource_envelope.clone()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if plaintext != canonical_lock.as_bytes() {
            return Err(PersistenceError::CorruptOrMissing);
        }
        self.validate_frozen_sets(&mut transaction, &drain).await?;
        let canonical: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 COUNT(*) FILTER (
                     WHERE item.classification = 'accepted'
                       AND invoice.payment_expired_at IS NULL
                       AND NOT (
                           invoice.first_amount_matched_observed_at IS NOT NULL
                           AND invoice.first_amount_matched_observed_at <= invoice.payment_deadline
                       )
                 ),
                 COUNT(*) FILTER (
                     WHERE item.classification IN ('rejected', 'canceled', 'proposal_expired')
                        OR (item.classification = 'accepted' AND (
                            invoice.payment_expired_at IS NOT NULL
                            OR (invoice.first_amount_matched_observed_at IS NOT NULL
                                AND invoice.first_amount_matched_observed_at <= invoice.payment_deadline)
                        ))
                 ),
                 COUNT(*),
                 (SELECT COUNT(*) FROM payment_drain_cancellations WHERE drain_id = $1)
             FROM payment_drain_items item
             JOIN invoices invoice ON invoice.id = item.invoice_id
             WHERE item.drain_id = $1",
        )
        .bind(drain.id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if canonical.0 != drain.accepted_count
            || canonical.1 != drain.terminal_count
            || canonical.3 != drain.cancellation_enqueued_count
            || drain.status
                != if canonical.0 == 0 {
                    "completed"
                } else {
                    "active"
                }
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        if canonical.0 != 0 {
            return Err(PersistenceError::Conflict);
        }
        let drain_id = drain.id;
        let validated = snapshot(drain, false)?;
        if !validated.completed() {
            return Err(PersistenceError::Conflict);
        }

        sqlx::query(
            "UPDATE lock_payment_generations
             SET last_cleanup_token = $1
             WHERE creator_id = $2 AND lock_resource_lookup_hash = $3",
        )
        .bind(cleanup_token.as_slice())
        .bind(creator_id)
        .bind(lock_hash.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("DELETE FROM payment_drains WHERE id = $1")
            .bind(drain_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)
    }

    /// Creates or exactly replays one immutable lock-wide lifecycle snapshot.
    pub async fn create(
        &self,
        lock_resource: &PubkyLockResource,
    ) -> Result<PaymentDrainSnapshot, PersistenceError> {
        self.create_inner(lock_resource, None).await
    }

    pub async fn create_after_receive(
        &self,
        lifecycles: &PaymentRequestLifecycleStore,
        lock_resource: &PubkyLockResource,
        evidence: &[RequiredReceiveTarget],
    ) -> Result<PaymentDrainSnapshot, PersistenceError> {
        self.create_inner(lock_resource, Some((lifecycles, evidence)))
            .await
    }

    async fn create_inner(
        &self,
        lock_resource: &PubkyLockResource,
        receive_evidence: Option<(&PaymentRequestLifecycleStore, &[RequiredReceiveTarget])>,
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
                    cancellation_enqueued_count, cancellation_set_hash, item_set_hash, status, created_at
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
            return self
                .exact_replay(lock_resource)
                .await?
                .ok_or(PersistenceError::CorruptOrMissing);
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

        let _: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id
             FROM invoices
             WHERE creator_id = $1
               AND lock_resource_lookup_hash = $2
               AND lock_resource_generation = $3
             ORDER BY id
             FOR UPDATE",
        )
        .bind(creator.id)
        .bind(lock_hash.as_bytes().as_slice())
        .bind(lock_resource_generation)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        if let Some((lifecycles, evidence)) = receive_evidence {
            let current = lifecycles
                .required_receive_targets_for_lock_in_transaction(
                    &mut transaction,
                    creator.id,
                    &lock_hash,
                )
                .await?;
            if !PaymentRequestLifecycleStore::receive_evidence_covers(&current, evidence) {
                return Err(PersistenceError::Unavailable);
            }
        }

        let rows = sqlx::query_as::<_, InvoiceLifecycleRow>(
            "SELECT invoices.id AS invoice_id, lifecycle.request_state,
                    lifecycle.sdk_payment_request_id, lifecycle.last_event_at
             FROM invoices
             LEFT JOIN payment_request_lifecycles AS lifecycle
               ON lifecycle.invoice_id = invoices.id
             WHERE invoices.creator_id = $1
               AND invoices.lock_resource_lookup_hash = $2
               AND invoices.lock_resource_generation = $3
             ORDER BY invoices.id, lifecycle.sdk_payment_request_id
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
        let mut classifications = Vec::new();
        let mut attempts_by_invoice = BTreeMap::<Uuid, Vec<InvoiceLifecycleRow>>::new();
        for row in rows {
            attempts_by_invoice
                .entry(row.invoice_id)
                .or_default()
                .push(row);
        }
        for (invoice_id, attempts) in attempts_by_invoice {
            let parsed = attempts
                .iter()
                .map(|attempt| {
                    let state = attempt
                        .request_state
                        .as_deref()
                        .and_then(PaymentRequestLifecycleState::parse)
                        .ok_or(PersistenceError::CorruptOrMissing)?;
                    let payment_request_id = attempt
                        .sdk_payment_request_id
                        .as_deref()
                        .ok_or(PersistenceError::CorruptOrMissing)?;
                    let last_event_at = attempt
                        .last_event_at
                        .ok_or(PersistenceError::CorruptOrMissing)?;
                    Ok((state, payment_request_id, last_event_at))
                })
                .collect::<Result<Vec<_>, PersistenceError>>()?;

            if parsed
                .iter()
                .any(|(state, _, _)| *state == PaymentRequestLifecycleState::InvalidConflict)
            {
                return Err(PersistenceError::Conflict);
            }
            if parsed
                .iter()
                .any(|(state, _, _)| *state == PaymentRequestLifecycleState::RecoveryRequired)
            {
                return Err(PersistenceError::Unavailable);
            }

            let proposed_attempts = parsed
                .iter()
                .filter(|(state, _, _)| *state == PaymentRequestLifecycleState::Proposed)
                .collect::<Vec<_>>();
            let has_accepted_attempt = parsed.iter().any(|(state, _, _)| {
                matches!(
                    state,
                    PaymentRequestLifecycleState::Accepted
                        | PaymentRequestLifecycleState::ProofSubmitted
                        | PaymentRequestLifecycleState::ActiveRecurring
                )
            });
            let classification = if has_accepted_attempt {
                accepted_count += 1;
                "accepted"
            } else if proposed_attempts.is_empty() {
                let terminal = parsed
                    .iter()
                    .max_by_key(|(_, _, last_event_at)| *last_event_at)
                    .ok_or(PersistenceError::CorruptOrMissing)?
                    .0;
                terminal_count += 1;
                match terminal {
                    PaymentRequestLifecycleState::Rejected => "rejected",
                    PaymentRequestLifecycleState::Canceled => "canceled",
                    PaymentRequestLifecycleState::ProposalExpired => "proposal_expired",
                    _ => return Err(PersistenceError::CorruptOrMissing),
                }
            } else {
                "cancellation_enqueued"
            };
            if !proposed_attempts.is_empty() {
                let proposal_rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
                    "SELECT id, intent_envelope FROM outbox
                     WHERE creator_id = $1 AND invoice_id = $2
                     ORDER BY created_at, id",
                )
                .bind(creator.id)
                .bind(invoice_id)
                .fetch_all(&mut *transaction)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
                let mut proposals = Vec::new();
                for (proposal_outbox_id, proposal_envelope) in proposal_rows {
                    let proposal_plaintext = self
                        .crypto
                        .decrypt(
                            &EnvelopeContext::outbox_semantic_intent(
                                creator_hash,
                                proposal_outbox_id,
                            ),
                            &EncryptedEnvelope::from_bytes(proposal_envelope),
                        )
                        .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    let intent = DeliveryIntentV1::decode(&proposal_plaintext)
                        .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    if matches!(
                        intent.operation(),
                        crate::application::semantic_intent::DeliveryOperationV1::PaymentRequestProposal { .. }
                    ) {
                        proposals.push(intent);
                    }
                }
                let [proposal] = proposals.as_slice() else {
                    return Err(PersistenceError::CorruptOrMissing);
                };
                for (_, payment_request_id, _) in proposed_attempts {
                    let cancellation = DeliveryIntentV1::payment_request_cancellation(
                        proposal,
                        (*payment_request_id).to_owned(),
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
                        invoice_id,
                        payment_request_id: (*payment_request_id).to_owned(),
                        outbox_id,
                        envelope,
                    });
                }
            }
            classifications.push((invoice_id, classification));
        }

        cancellations.sort_by(|left, right| {
            (
                left.invoice_id,
                left.payment_request_id.as_str(),
                left.outbox_id,
            )
                .cmp(&(
                    right.invoice_id,
                    right.payment_request_id.as_str(),
                    right.outbox_id,
                ))
        });
        let cancellation_set_hash = cancellation_set_hash(&self.crypto, &cancellations);
        let item_set_hash = item_rows_hash(
            &self.crypto,
            &classifications
                .iter()
                .map(|(invoice_id, classification)| {
                    (
                        *invoice_id,
                        creator.id,
                        lock_hash.as_bytes().to_vec(),
                        lock_resource_generation,
                        *classification,
                    )
                })
                .collect::<Vec<_>>(),
        );

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
                 cancellation_enqueued_count, cancellation_set_hash, item_set_hash,
                 status, completed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                       CASE WHEN $11 THEN 'completed' ELSE 'active' END,
                       CASE WHEN $11 THEN transaction_timestamp() ELSE NULL END)
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
        .bind(cancellation_set_hash.as_bytes().as_slice())
        .bind(item_set_hash.as_bytes().as_slice())
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
                     id, creator_id, invoice_id, intent_envelope, intent_kind,
                     cancellation_target_payment_request_id, status
                 ) VALUES ($1, $2, $3, $4, 'payment_request_cancellation', $5, 'queued')",
            )
            .bind(cancellation.outbox_id)
            .bind(creator.id)
            .bind(cancellation.invoice_id)
            .bind(cancellation.envelope.as_bytes())
            .bind(&cancellation.payment_request_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        for (invoice_id, classification) in classifications {
            sqlx::query(
                "INSERT INTO payment_drain_items (
                     drain_id, invoice_id, classification
                 ) VALUES ($1, $2, $3)",
            )
            .bind(drain_id)
            .bind(invoice_id)
            .bind(classification)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        for cancellation in &cancellations {
            sqlx::query(
                "INSERT INTO payment_drain_cancellations (
                     drain_id, invoice_id, sdk_payment_request_id, cancellation_outbox_id
                 ) VALUES ($1, $2, $3, $4)",
            )
            .bind(drain_id)
            .bind(cancellation.invoice_id)
            .bind(&cancellation.payment_request_id)
            .bind(cancellation.outbox_id)
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

    async fn validate_frozen_sets(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        drain: &ExistingDrainRow,
    ) -> Result<(), PersistenceError> {
        let rows: Vec<(Uuid, String, Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT cancellation.invoice_id, cancellation.sdk_payment_request_id,
                    cancellation.cancellation_outbox_id, outbox.intent_envelope
             FROM payment_drain_cancellations AS cancellation
             JOIN outbox ON outbox.id = cancellation.cancellation_outbox_id
             WHERE cancellation.drain_id = $1
             ORDER BY cancellation.invoice_id, cancellation.sdk_payment_request_id,
                      cancellation.cancellation_outbox_id",
        )
        .bind(drain.id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let expected_count = usize::try_from(drain.cancellation_enqueued_count)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if rows.len() != expected_count
            || cancellation_rows_hash(&self.crypto, &rows).as_bytes()
                != drain.cancellation_set_hash.as_slice()
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let item_rows: Vec<(Uuid, Uuid, Vec<u8>, i64, String)> = sqlx::query_as(
            "SELECT item.invoice_id, invoice.creator_id,
                    invoice.lock_resource_lookup_hash, invoice.lock_resource_generation,
                    item.classification
             FROM payment_drain_items AS item
             JOIN invoices AS invoice ON invoice.id = item.invoice_id
             WHERE item.drain_id = $1
             ORDER BY item.invoice_id, item.classification",
        )
        .bind(drain.id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if item_rows_hash(&self.crypto, &item_rows).as_bytes() != drain.item_set_hash.as_slice() {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok(())
    }
}

fn cancellation_set_hash(crypto: &Crypto, cancellations: &[PreparedCancellation]) -> LookupHash {
    cancellation_rows_hash(
        crypto,
        &cancellations
            .iter()
            .map(|item| {
                (
                    item.invoice_id,
                    item.payment_request_id.clone(),
                    item.outbox_id,
                    item.envelope.as_bytes().to_vec(),
                )
            })
            .collect::<Vec<_>>(),
    )
}

fn cancellation_rows_hash(crypto: &Crypto, rows: &[(Uuid, String, Uuid, Vec<u8>)]) -> LookupHash {
    let mut bytes = b"payment-drain-cancellation-set-v1\0".to_vec();
    for (invoice_id, payment_request_id, outbox_id, intent_envelope) in rows {
        bytes.extend_from_slice(invoice_id.as_bytes());
        bytes.extend_from_slice(&(payment_request_id.len() as u64).to_be_bytes());
        bytes.extend_from_slice(payment_request_id.as_bytes());
        bytes.extend_from_slice(outbox_id.as_bytes());
        bytes.extend_from_slice(&(intent_envelope.len() as u64).to_be_bytes());
        bytes.extend_from_slice(intent_envelope);
    }
    crypto.lookup_hash(&bytes)
}

fn item_rows_hash<S: AsRef<str>>(
    crypto: &Crypto,
    rows: &[(Uuid, Uuid, Vec<u8>, i64, S)],
) -> LookupHash {
    let mut bytes = b"payment-drain-item-set-v1\0".to_vec();
    for (invoice_id, creator_id, lock_hash, generation, classification) in rows {
        let classification = classification.as_ref();
        bytes.extend_from_slice(invoice_id.as_bytes());
        bytes.extend_from_slice(creator_id.as_bytes());
        bytes.extend_from_slice(&(lock_hash.len() as u64).to_be_bytes());
        bytes.extend_from_slice(lock_hash);
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&(classification.len() as u64).to_be_bytes());
        bytes.extend_from_slice(classification.as_bytes());
    }
    crypto.lookup_hash(&bytes)
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
    let accepted_count = count(row.accepted_count)?;
    if completed == (accepted_count > 0) {
        return Err(PersistenceError::CorruptOrMissing);
    }
    Ok(PaymentDrainSnapshot {
        drain_id: row.id,
        created_at: row.created_at,
        accepted_count,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: &str, accepted_count: i64) -> ExistingDrainRow {
        ExistingDrainRow {
            id: Uuid::nil(),
            lock_resource_envelope: Vec::new(),
            accepted_count,
            terminal_count: 0,
            cancellation_enqueued_count: 0,
            cancellation_set_hash: vec![0; 32],
            item_set_hash: vec![0; 32],
            status: status.to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn snapshot_rejects_status_that_disagrees_with_accepted_count() {
        assert!(snapshot(row("active", 0), true).is_err());
        assert!(snapshot(row("completed", 1), true).is_err());
        assert!(snapshot(row("active", 1), true).is_ok());
        assert!(snapshot(row("completed", 0), true).is_ok());
    }
}
