//! Fenced PostgreSQL outbox claims and transitions.

use crate::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    persistence::PersistenceError,
};
use sqlx::PgPool;
use std::{collections::BTreeMap, time::Duration};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxRetryClass {
    AdapterUnavailable,
    MarkerFetch,
    MarkerMissing,
    MarkerChanged,
    LinkEstablishment,
    EndpointPublication,
    PaymentRequestProposal,
    ReconciliationPending,
    Reconciliation,
}

impl OutboxRetryClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AdapterUnavailable => "adapter_unavailable",
            Self::MarkerFetch => "marker_fetch",
            Self::MarkerMissing => "marker_missing",
            Self::MarkerChanged => "marker_changed",
            Self::LinkEstablishment => "link_establishment",
            Self::EndpointPublication => "endpoint_publication",
            Self::PaymentRequestProposal => "payment_request_proposal",
            Self::ReconciliationPending => "reconciliation_pending",
            Self::Reconciliation => "reconciliation",
        }
    }
}

/// Exact public-SDK identifiers returned after one durable local enqueue.
#[derive(Clone, PartialEq, Eq)]
pub enum HandoffResult {
    EndpointPublication {
        outbound_message_id: u64,
    },
    PaymentRequestProposal {
        outbound_message_id: u64,
        event_id: String,
        payment_request_id: String,
    },
}

impl std::fmt::Debug for HandoffResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndpointPublication { .. } => {
                formatter.write_str("HandoffResult::EndpointPublication(<redacted>)")
            }
            Self::PaymentRequestProposal { .. } => {
                formatter.write_str("HandoffResult::PaymentRequestProposal(<redacted>)")
            }
        }
    }
}

impl HandoffResult {
    pub fn outbound_message_id(&self) -> u64 {
        match self {
            Self::EndpointPublication {
                outbound_message_id,
            }
            | Self::PaymentRequestProposal {
                outbound_message_id,
                ..
            } => *outbound_message_id,
        }
    }
}

#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ClaimedOutbox {
    id: Uuid,
    creator_id: Uuid,
    invoice_id: Option<Uuid>,
    attempt_count: i32,
    claim_token: Uuid,
    creator_lookup_hash: Vec<u8>,
    intent_envelope: Vec<u8>,
}

impl std::fmt::Debug for ClaimedOutbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClaimedOutbox { <redacted> }")
    }
}

impl ClaimedOutbox {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn creator_id(&self) -> Uuid {
        self.creator_id
    }

    pub fn invoice_id(&self) -> Option<Uuid> {
        self.invoice_id
    }

    pub fn attempt_count(&self) -> i32 {
        self.attempt_count
    }

    pub fn claim_token(&self) -> Uuid {
        self.claim_token
    }
}

/// A separately fenced claim over an attributable `handed_off` row.
#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ClaimedHandoff {
    id: Uuid,
    creator_id: Uuid,
    invoice_id: Option<Uuid>,
    attempt_count: i32,
    claim_token: Uuid,
    sdk_outbound_message_id: String,
}

impl std::fmt::Debug for ClaimedHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClaimedHandoff { <redacted> }")
    }
}

impl ClaimedHandoff {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn creator_id(&self) -> Uuid {
        self.creator_id
    }

    pub fn attempt_count(&self) -> i32 {
        self.attempt_count
    }

    pub fn claim_token(&self) -> Uuid {
        self.claim_token
    }

    pub fn sdk_outbound_message_id(&self) -> Result<u64, PersistenceError> {
        self.sdk_outbound_message_id
            .parse()
            .map_err(|_| PersistenceError::CorruptOrMissing)
    }
}

/// Test seam around the production preflight/fence/SDK sequence. Production
/// never installs hooks, so both points are no-ops there; tests install them
/// to serialize a concurrent cancellation against the fence commit.
#[derive(Clone, Default)]
pub struct HandoffFenceSeam {
    pub after_preflight: Option<SeamHook>,
    pub after_fence: Option<SeamHook>,
}

pub type SeamHook = std::sync::Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync,
>;

impl std::fmt::Debug for HandoffFenceSeam {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HandoffFenceSeam")
            .field("after_preflight", &self.after_preflight.is_some())
            .field("after_fence", &self.after_fence.is_some())
            .finish()
    }
}

impl HandoffFenceSeam {
    pub(crate) async fn run_after_preflight(&self) {
        if let Some(hook) = &self.after_preflight {
            hook().await;
        }
    }

    pub(crate) async fn run_after_fence(&self) {
        if let Some(hook) = &self.after_fence {
            hook().await;
        }
    }
}

#[derive(Clone, Debug)]
pub struct OutboxStore {
    pool: PgPool,
    crypto: std::sync::Arc<Crypto>,
    seam: HandoffFenceSeam,
}

#[derive(Clone, Debug, Default)]
pub struct TerminalFailureHealth {
    pub count: i64,
    pub oldest_age_seconds: Option<i64>,
    pub by_class: BTreeMap<String, i64>,
    pub transitions: Vec<(String, String, i64)>,
}

impl OutboxStore {
    pub fn new(pool: &PgPool, crypto: std::sync::Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
            seam: HandoffFenceSeam::default(),
        }
    }

    /// Installs the test-only fence seam; production never calls this, so
    /// both seam points stay no-ops there.
    pub fn with_handoff_fence_seam(mut self, seam: HandoffFenceSeam) -> Self {
        self.seam = seam;
        self
    }

    pub(crate) fn seam(&self) -> &HandoffFenceSeam {
        &self.seam
    }

    /// Reports aggregate delivery availability without exposing row or Creator identifiers.
    pub async fn delivery_available(&self) -> Result<bool, PersistenceError> {
        sqlx::query_scalar(
            "SELECT NOT EXISTS ( \
                 SELECT 1 FROM outbox \
                 WHERE status IN ('retryable', 'handoff_started', 'handed_off') \
             )",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    pub async fn terminal_failure_health(&self) -> Result<TerminalFailureHealth, PersistenceError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT event_class, COUNT(*)::BIGINT
             FROM outbox_terminal_events
             GROUP BY event_class",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let count = rows.iter().map(|(_, count)| *count).sum();
        let oldest_age_seconds = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))::BIGINT
             FROM outbox_terminal_events",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let transitions = sqlx::query_as(
            "SELECT event_class, reason, COUNT(*)::BIGINT
             FROM outbox_terminal_events
             GROUP BY event_class, reason",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(TerminalFailureHealth {
            count,
            oldest_age_seconds,
            by_class: rows.into_iter().collect(),
            transitions,
        })
    }

    pub async fn claim_metrics(&self, limit: i64) -> Result<(bool, i64), PersistenceError> {
        let (saturated, active_partitions): (bool, i64) = sqlx::query_as(
            "WITH RECURSIVE eligible AS (
                 SELECT id, creator_id, reader_assignment_id AS root_reader_assignment_id, depends_on_id
                 FROM outbox WHERE depends_on_id IS NULL
                 UNION ALL
                 SELECT child.id, child.creator_id, eligible.root_reader_assignment_id, child.depends_on_id
                 FROM outbox child JOIN eligible ON eligible.id = child.depends_on_id
             ), roots AS (
                 SELECT DISTINCT ON (id) id, root_reader_assignment_id FROM eligible ORDER BY id
              ), active AS (
                 SELECT o.creator_id, roots.root_reader_assignment_id
                 FROM outbox o JOIN roots ON roots.id = o.id
                 WHERE o.status IN ('leased', 'handoff_started') AND o.lease_expires_at > NOW()
                 GROUP BY o.creator_id, roots.root_reader_assignment_id
             ), due_partitions AS (
                 SELECT o.creator_id, roots.root_reader_assignment_id
                 FROM outbox o JOIN roots ON roots.id = o.id
                 LEFT JOIN outbox dependency ON dependency.id = o.depends_on_id
                 LEFT JOIN invoices invoice ON invoice.id = o.invoice_id
                 WHERE ((o.status = 'queued' AND o.next_attempt_at <= NOW())
                     OR (o.status IN ('leased', 'handoff_started') AND o.lease_expires_at <= NOW())
                     OR (o.status = 'retryable' AND o.next_attempt_at <= NOW()))
                   AND (o.invoice_id IS NULL OR invoice.baseline_state NOT IN (
                     'expired_final', 'void_baseline_failed', 'void_prepare_expired',
                     'void_cancelled', 'resolved_paid_manually', 'resolved_closed'))
                   AND (o.depends_on_id IS NULL OR dependency.status = 'delivered')
                 GROUP BY o.creator_id, roots.root_reader_assignment_id
             )
             SELECT (SELECT COUNT(*) FROM due_partitions) > $1,
                    (SELECT COUNT(*) FROM active)",
        )
        .bind(limit)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok((saturated, active_partitions))
    }

    /// Claims eligible rows while preserving endpoint-publication dependencies.
    pub async fn claim(
        &self,
        owner: Uuid,
        limit: i64,
        lease: Duration,
    ) -> Result<Vec<ClaimedOutbox>, PersistenceError> {
        let seconds = lease_seconds(lease)?;
        sqlx::query_as(
            "WITH RECURSIVE eligible AS ( \
                 SELECT o.id, o.creator_id, o.reader_assignment_id AS root_reader_assignment_id, \
                        o.depends_on_id, o.status, o.next_attempt_at \
                 FROM outbox o \
                 WHERE o.depends_on_id IS NULL \
                 UNION ALL \
                 SELECT child.id, child.creator_id, eligible.root_reader_assignment_id, \
                        child.depends_on_id, child.status, child.next_attempt_at \
                 FROM outbox child \
                 JOIN eligible ON eligible.id = child.depends_on_id \
             ), \
             roots AS ( \
                 SELECT DISTINCT ON (id) id, root_reader_assignment_id \
                 FROM eligible \
                 ORDER BY id \
             ), \
             active AS ( \
                 SELECT o.creator_id, r.root_reader_assignment_id, COUNT(*) AS active_count \
                 FROM outbox o \
                 JOIN roots r ON r.id = o.id \
                 WHERE o.status IN ('leased', 'handoff_started') AND o.lease_expires_at > NOW() \
                 GROUP BY o.creator_id, r.root_reader_assignment_id \
             ), \
             ranked AS ( \
                 SELECT o.id, \
                        ROW_NUMBER() OVER ( \
                            PARTITION BY o.creator_id, r.root_reader_assignment_id \
                            ORDER BY o.next_attempt_at, o.id \
                        ) AS partition_rank, \
                        COALESCE(active.active_count, 0) AS active_count \
                 FROM outbox o \
                 JOIN roots r ON r.id = o.id \
                 LEFT JOIN active ON active.creator_id = o.creator_id \
                    AND active.root_reader_assignment_id = r.root_reader_assignment_id \
                 LEFT JOIN outbox dependency ON dependency.id = o.depends_on_id \
                 LEFT JOIN invoices invoice ON invoice.id = o.invoice_id \
                 WHERE ( \
                     (o.status = 'queued' AND o.next_attempt_at <= NOW()) \
                     OR (o.status IN ('leased', 'handoff_started') AND o.lease_expires_at <= NOW()) \
                     OR (o.status = 'retryable' AND o.next_attempt_at <= NOW()) \
                 ) \
                 AND (o.invoice_id IS NULL OR invoice.baseline_state NOT IN ( \
                     'expired_final', 'void_baseline_failed', 'void_prepare_expired', \
                     'void_cancelled', 'resolved_paid_manually', 'resolved_closed' \
                 )) \
                 AND (o.depends_on_id IS NULL OR dependency.status = 'delivered') \
             ), \
             candidates AS ( \
                 SELECT ranked.id \
                 FROM outbox o \
                 JOIN ranked ON ranked.id = o.id \
                 WHERE ranked.partition_rank = 1 AND ranked.active_count = 0 \
                 ORDER BY ranked.id \
                 FOR UPDATE OF o SKIP LOCKED \
                 LIMIT $1 \
             ) \
             UPDATE outbox o \
             SET status = 'leased', \
                 lease_owner = $2, \
                 claim_token = gen_random_uuid(), \
                 lease_expires_at = NOW() + ($3 * INTERVAL '1 second'), \
                 attempt_count = o.attempt_count + 1, \
                 updated_at = NOW() \
             FROM candidates \
             WHERE o.id = candidates.id \
             RETURNING o.id, o.creator_id, o.invoice_id, o.attempt_count, o.claim_token, \
                 (SELECT creator_lookup_hash FROM creators WHERE id = o.creator_id) AS creator_lookup_hash, \
                 o.intent_envelope",
        )
        .bind(limit)
        .bind(owner)
        .bind(seconds)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// Atomically closes a leased link-establishment claim at either delivery
    /// ceiling. This runs before decrypting the intent or constructing an
    /// adapter, so a bounded claim cannot reach the public SDK.
    pub async fn exhaust_claim_if_due(
        &self,
        claim: &ClaimedOutbox,
        max_attempts: i32,
        max_age: Duration,
    ) -> Result<bool, PersistenceError> {
        let max_age_seconds =
            i64::try_from(max_age.as_secs()).map_err(|_| PersistenceError::Unavailable)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let parent = sqlx::query_scalar::<_, Uuid>(
            "UPDATE outbox
             SET status = 'permanently_failed',
                 error_class = 'link_establishment_exhausted',
                 failure_reason = CASE
                     WHEN attempt_count >= $1 THEN 'attempt_ceiling'
                     ELSE 'age_ceiling'
                 END,
                 lease_owner = NULL,
                 claim_token = NULL,
                 lease_expires_at = NULL,
                 updated_at = NOW()
             WHERE id = $2
               AND status = 'leased'
               AND claim_token = $3
               AND lease_expires_at > NOW()
               AND error_class = 'link_establishment'
               AND (attempt_count >= $1 OR NOW() >= created_at + ($4 * INTERVAL '1 second'))
             RETURNING id",
        )
        .bind(max_attempts)
        .bind(claim.id)
        .bind(claim.claim_token)
        .bind(max_age_seconds)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(parent_id) = parent else {
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(false);
        };

        Self::cascade_terminal_descendants(
            &mut tx,
            parent_id,
            "parent_link_establishment_exhausted",
        )
        .await?;

        sqlx::query(
            "INSERT INTO outbox_terminal_events
                 (creator_id, invoice_id, outbox_id, event_class, reason)
             SELECT creator_id, invoice_id, id, 'link_establishment_exhausted',
                    failure_reason
             FROM outbox
             WHERE id = $1",
        )
        .bind(parent_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(true)
    }

    pub async fn invoice_is_final(
        &self,
        invoice_id: Option<Uuid>,
    ) -> Result<bool, PersistenceError> {
        let Some(invoice_id) = invoice_id else {
            return Ok(false);
        };
        sqlx::query_scalar(
            "SELECT baseline_state IN (
                 'expired_final', 'void_baseline_failed', 'void_prepare_expired',
                 'void_cancelled', 'resolved_paid_manually', 'resolved_closed'
             )
             FROM invoices
             WHERE id = $1",
        )
        .bind(invoice_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)
    }

    pub async fn mark_final_invoice_failed(
        &self,
        claim: &ClaimedOutbox,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let changed = sqlx::query(
            "UPDATE outbox
             SET status = 'permanently_failed',
                 error_class = 'invoice_finalized',
                 failure_reason = 'invoice_finalized',
                 lease_owner = NULL,
                 claim_token = NULL,
                 lease_expires_at = NULL,
                 updated_at = NOW()
             WHERE id = $1
               AND status = 'leased'
               AND claim_token = $2
               AND lease_expires_at > NOW()",
        )
        .bind(claim.id)
        .bind(claim.claim_token)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if changed.rows_affected() == 1 {
            sqlx::query(
                "INSERT INTO outbox_terminal_events
                     (creator_id, invoice_id, outbox_id, event_class, reason)
                 SELECT creator_id, invoice_id, id, 'invoice_finalized', 'invoice_finalized'
                 FROM outbox
                 WHERE id = $1",
            )
            .bind(claim.id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    /// The pre-SDK finality/handoff linearization fence. Under the invoice
    /// row lock (the same lock void/abandonment hold while terminalizing
    /// outbox rows) this commits the closed `handoff_started` state with the
    /// exact claim token, an unexpired lease, and a non-final invoice —
    /// BEFORE any SDK call. Cancellation committed first makes the CAS match
    /// zero rows (the leased row was terminalized or the invoice is final),
    /// so the worker performs no SDK call; a committed fence is preserved by
    /// cancellation exactly like `handed_off`, and `mark_handed_off` then
    /// attributes the in-flight SDK effect on completion. Returns false when
    /// the fence was not taken (stale token/expired lease/final invoice);
    /// the caller then resolves the row through the final-invoice path,
    /// which is a no-op when a competing claim reclaimed the token.
    pub async fn begin_handoff(&self, claim: &ClaimedOutbox) -> Result<bool, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        if let Some(invoice_id) = claim.invoice_id {
            let baseline_state = sqlx::query_scalar::<_, String>(
                "SELECT baseline_state FROM invoices WHERE id = $1 FOR UPDATE",
            )
            .bind(invoice_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            match baseline_state {
                None => return Err(PersistenceError::CorruptOrMissing),
                Some(state)
                    if matches!(
                        state.as_str(),
                        "expired_final"
                            | "void_baseline_failed"
                            | "void_prepare_expired"
                            | "void_cancelled"
                            | "resolved_paid_manually"
                            | "resolved_closed"
                    ) =>
                {
                    tx.commit()
                        .await
                        .map_err(|_| PersistenceError::Unavailable)?;
                    return Ok(false);
                }
                Some(_) => {}
            }
        }
        let changed = sqlx::query(
            "UPDATE outbox \
             SET status = 'handoff_started', updated_at = NOW() \
             WHERE id = $1 AND status = 'leased' AND claim_token = $2 AND lease_expires_at > NOW()",
        )
        .bind(claim.id)
        .bind(claim.claim_token)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Claims attributable handed-off rows independently from enqueue work.
    pub async fn claim_reconciliation(
        &self,
        owner: Uuid,
        limit: i64,
        lease: Duration,
    ) -> Result<Vec<ClaimedHandoff>, PersistenceError> {
        let seconds = lease_seconds(lease)?;
        sqlx::query_as(
            "WITH candidates AS ( \
                 SELECT id FROM outbox \
                 WHERE status = 'handed_off' \
                   AND sdk_outbound_message_id IS NOT NULL \
                   AND next_attempt_at <= NOW() \
                   AND (claim_token IS NULL OR lease_expires_at <= NOW()) \
                 ORDER BY next_attempt_at, id \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT $1 \
             ) \
             UPDATE outbox o \
             SET lease_owner = $2, claim_token = gen_random_uuid(), \
                 lease_expires_at = NOW() + ($3 * INTERVAL '1 second'), \
                 attempt_count = o.attempt_count + 1, updated_at = NOW() \
             FROM candidates WHERE o.id = candidates.id \
             RETURNING o.id, o.creator_id, o.invoice_id, o.attempt_count, o.claim_token, \
                 o.sdk_outbound_message_id",
        )
        .bind(limit)
        .bind(owner)
        .bind(seconds)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// Decrypts the complete public-SDK inputs for a currently claimed row.
    pub fn delivery_intent(
        &self,
        claim: &ClaimedOutbox,
    ) -> Result<DeliveryIntentV1, PersistenceError> {
        let creator_hash = lookup_hash_from_storage(&claim.creator_lookup_hash)?;
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::outbox_semantic_intent(creator_hash, claim.id),
                &EncryptedEnvelope::from_bytes(claim.intent_envelope.clone()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        DeliveryIntentV1::decode(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)
    }

    /// Atomically associates the exact public-SDK result while the handoff
    /// fence is live. The fence (`handoff_started`) is the linearization
    /// point: cancellation deliberately preserves fenced rows, so this
    /// transition intentionally does not re-check invoice finality — an
    /// SDK effect emitted after a committed fence is attributed here even
    /// when the invoice finalized afterwards, keeping the externally visible
    /// effect auditable instead of orphaned.
    pub async fn mark_handed_off(
        &self,
        claim: &ClaimedOutbox,
        result: &HandoffResult,
    ) -> Result<bool, PersistenceError> {
        let outbound = result.outbound_message_id().to_string();
        let (event_id, payment_request_id) = match result {
            HandoffResult::EndpointPublication { .. } => (None, None),
            HandoffResult::PaymentRequestProposal {
                event_id,
                payment_request_id,
                ..
            } => (Some(event_id.as_str()), Some(payment_request_id.as_str())),
        };
        let changed = sqlx::query(
            "UPDATE outbox SET status = 'handed_off', sdk_outbound_message_id = $1, \
                 sdk_event_id = $2, sdk_payment_request_id = $3, error_class = NULL, \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = NOW() \
             WHERE id = $4 AND status = 'handoff_started' AND claim_token = $5 \
               AND lease_expires_at > NOW()",
        )
        .bind(outbound)
        .bind(event_id)
        .bind(payment_request_id)
        .bind(claim.id)
        .bind(claim.claim_token)
        .execute(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Marks delivery only while the separately acquired reconciliation fence is live.
    pub async fn mark_delivered(&self, claim: &ClaimedHandoff) -> Result<bool, PersistenceError> {
        self.reconciliation_transition(claim, "delivered", None, None)
            .await
    }

    /// Retains an attributable handoff whose SDK state cannot be reconciled safely.
    /// The transition and its durable terminal event commit in one
    /// transaction, so permanent reconciliation failure carries the same
    /// retained evidence as every other terminal transition; a replayed CAS
    /// matches zero rows and inserts no second event.
    pub async fn mark_reconciliation_permanently_failed(
        &self,
        claim: &ClaimedHandoff,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let changed = sqlx::query(
            "UPDATE outbox SET status = 'permanently_failed', \
                 error_class = 'permanent_sdk_reconciliation', \
                 failure_reason = 'permanent_sdk_reconciliation', \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = NOW() \
             WHERE id = $1 AND status = 'handed_off' \
               AND sdk_outbound_message_id = $2 AND claim_token = $3 AND lease_expires_at > NOW()",
        )
        .bind(claim.id)
        .bind(&claim.sdk_outbound_message_id)
        .bind(claim.claim_token)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if changed.rows_affected() == 1 {
            sqlx::query(
                "INSERT INTO outbox_terminal_events
                     (creator_id, invoice_id, outbox_id, event_class, reason)
                 SELECT creator_id, invoice_id, id, 'permanent_sdk_reconciliation',
                        'permanent_sdk_reconciliation'
                 FROM outbox WHERE id = $1",
            )
            .bind(claim.id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Releases a still-pending reconciliation claim with bounded retry delay.
    pub async fn retry_reconciliation(
        &self,
        claim: &ClaimedHandoff,
        delay: Duration,
        error_class: OutboxRetryClass,
    ) -> Result<bool, PersistenceError> {
        self.reconciliation_transition(
            claim,
            "handed_off",
            Some(error_class.as_str()),
            Some(lease_seconds(delay)?),
        )
        .await
    }

    pub async fn mark_permanently_failed(
        &self,
        claim: &ClaimedOutbox,
    ) -> Result<bool, PersistenceError> {
        self.transition(claim, "permanently_failed", Some("permanent"), None)
            .await
    }

    pub async fn mark_retryable(
        &self,
        claim: &ClaimedOutbox,
        delay: Duration,
        error_class: OutboxRetryClass,
    ) -> Result<bool, PersistenceError> {
        self.transition(
            claim,
            "retryable",
            Some(error_class.as_str()),
            Some(lease_seconds(delay)?),
        )
        .await
    }

    async fn transition(
        &self,
        claim: &ClaimedOutbox,
        status: &str,
        error_class: Option<&str>,
        delay: Option<i64>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let changed = sqlx::query(
            "UPDATE outbox \
             SET status = $1, error_class = $2, \
                 next_attempt_at = CASE WHEN $3::BIGINT IS NULL THEN next_attempt_at ELSE NOW() + ($3 * INTERVAL '1 second') END, \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = NOW() \
             WHERE id = $4 AND status IN ('leased', 'handoff_started') \
               AND claim_token = $5 AND lease_expires_at > NOW()",
        )
        .bind(status)
        .bind(error_class)
        .bind(delay)
        .bind(claim.id)
        .bind(claim.claim_token)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if changed.rows_affected() == 1 && status == "permanently_failed" {
            Self::cascade_terminal_descendants(&mut tx, claim.id, "parent_permanently_failed")
                .await?;
            sqlx::query(
                "INSERT INTO outbox_terminal_events
                     (creator_id, invoice_id, outbox_id, event_class, reason)
                 SELECT creator_id, invoice_id, id, COALESCE(error_class, 'permanent'),
                        COALESCE(failure_reason, 'permanent')
                 FROM outbox WHERE id = $1",
            )
            .bind(claim.id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    async fn cascade_terminal_descendants(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        parent_id: Uuid,
        reason: &'static str,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "WITH RECURSIVE descendants AS (
                 SELECT id FROM outbox WHERE depends_on_id = $1
                 UNION ALL
                 SELECT child.id
                 FROM outbox child
                 JOIN descendants parent ON child.depends_on_id = parent.id
             ), changed AS (
                 UPDATE outbox
                 SET status = 'permanently_failed',
                     error_class = 'dependency_failed',
                     failure_reason = $2,
                     lease_owner = NULL,
                     claim_token = NULL,
                     lease_expires_at = NULL,
                     updated_at = NOW()
                 WHERE id IN (SELECT id FROM descendants)
                   AND status IN ('prepared', 'queued', 'leased', 'retryable')
                 RETURNING creator_id, invoice_id, id, error_class, failure_reason
             )
             INSERT INTO outbox_terminal_events
                 (creator_id, invoice_id, outbox_id, event_class, reason)
             SELECT creator_id, invoice_id, id, error_class, failure_reason
             FROM changed",
        )
        .bind(parent_id)
        .bind(reason)
        .execute(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(())
    }

    async fn reconciliation_transition(
        &self,
        claim: &ClaimedHandoff,
        status: &str,
        error_class: Option<&str>,
        delay: Option<i64>,
    ) -> Result<bool, PersistenceError> {
        let changed = sqlx::query(
            "UPDATE outbox SET status = $1, error_class = $2, \
                 next_attempt_at = CASE WHEN $3::BIGINT IS NULL THEN next_attempt_at ELSE NOW() + ($3 * INTERVAL '1 second') END, \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = NOW() \
             WHERE id = $4 AND status = 'handed_off' \
               AND sdk_outbound_message_id = $5 AND claim_token = $6 AND lease_expires_at > NOW()",
        )
        .bind(status)
        .bind(error_class)
        .bind(delay)
        .bind(claim.id)
        .bind(&claim.sdk_outbound_message_id)
        .bind(claim.claim_token)
        .execute(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }
}

fn lease_seconds(duration: Duration) -> Result<i64, PersistenceError> {
    i64::try_from(duration.as_secs()).map_err(|_| PersistenceError::Unavailable)
}

fn lookup_hash_from_storage(bytes: &[u8]) -> Result<LookupHash, PersistenceError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    Ok(LookupHash::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_classes_are_closed_stage_only_diagnostics() {
        assert_eq!(
            [
                OutboxRetryClass::AdapterUnavailable,
                OutboxRetryClass::MarkerFetch,
                OutboxRetryClass::MarkerMissing,
                OutboxRetryClass::MarkerChanged,
                OutboxRetryClass::LinkEstablishment,
                OutboxRetryClass::EndpointPublication,
                OutboxRetryClass::PaymentRequestProposal,
                OutboxRetryClass::ReconciliationPending,
                OutboxRetryClass::Reconciliation,
            ]
            .map(OutboxRetryClass::as_str),
            [
                "adapter_unavailable",
                "marker_fetch",
                "marker_missing",
                "marker_changed",
                "link_establishment",
                "endpoint_publication",
                "payment_request_proposal",
                "reconciliation_pending",
                "reconciliation",
            ]
        );
    }

    #[test]
    fn handoff_and_claim_debug_redact_all_correlation_identifiers() {
        let event_id = "event-correlation-marker";
        let request_id = "request-correlation-marker";
        let outbound_id = "18446744073709551615";
        let result = HandoffResult::PaymentRequestProposal {
            outbound_message_id: u64::MAX,
            event_id: event_id.into(),
            payment_request_id: request_id.into(),
        };
        let claim_id = Uuid::new_v4();
        let creator_id = Uuid::new_v4();
        let claim = ClaimedHandoff {
            id: claim_id,
            creator_id,
            invoice_id: Some(Uuid::new_v4()),
            attempt_count: 8,
            claim_token: Uuid::new_v4(),
            sdk_outbound_message_id: outbound_id.into(),
        };
        let outbox_claim = ClaimedOutbox {
            id: claim_id,
            creator_id,
            invoice_id: Some(Uuid::new_v4()),
            attempt_count: 7,
            claim_token: Uuid::new_v4(),
            creator_lookup_hash: vec![3; 32],
            intent_envelope: vec![4; 64],
        };

        let result_debug = format!("{result:?}");
        let claim_debug = format!("{claim:?}");
        let outbox_claim_debug = format!("{outbox_claim:?}");
        assert!(!result_debug.contains(event_id));
        assert!(!result_debug.contains(request_id));
        assert!(!result_debug.contains(outbound_id));
        assert!(!claim_debug.contains(outbound_id));
        assert!(!claim_debug.contains(&claim_id.to_string()));
        assert!(!claim_debug.contains(&creator_id.to_string()));
        assert_eq!(claim_debug, "ClaimedHandoff { <redacted> }");
        assert!(!outbox_claim_debug.contains(&claim_id.to_string()));
        assert!(!outbox_claim_debug.contains(&creator_id.to_string()));
        assert_eq!(outbox_claim_debug, "ClaimedOutbox { <redacted> }");
    }
}
