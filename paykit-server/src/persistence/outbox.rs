//! Fenced PostgreSQL outbox claims and transitions.

use crate::{
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    persistence::PersistenceError,
};
use paykit_lib::{
    PaymentRequestEvent, PrivateApplicationMessage, PrivateMessageKind,
    parse_payment_request_event_message, parse_private_payment_list_json,
};
use paykit_sdk::storage::{OutboundPrivateMessageRecord, StorageState};
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

/// Static terminal reason for a recovered fence whose durable invocation
/// marker is FALSE (migration 0023 rule 3): the SDK provably never ran, so
/// no effect can exist; the row terminalizes with zero SDK calls.
pub const HANDOFF_UNRESOLVED_SDK_NOT_INVOKED: &str = "sdk_not_invoked";

/// Static terminal reason for a recovered fence whose durable invocation
/// marker is TRUE (migration 0023 rule 3): the SDK may have emitted an
/// effect, but recovery never resolves or attributes it (endpoint
/// identifier sets are not invoice-unique, so attribution could
/// false-match another invoice's publication). The row terminalizes with
/// zero SDK calls and an operator reconciles it by hand.
pub const HANDOFF_UNRESOLVED_SDK_INVOKED_UNATTRIBUTED: &str = "sdk_invoked_unattributed";

/// Outcome of the finality-checked retryable release of a fenced handoff
/// (migration 0023 rule 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffRelease {
    /// The invoice is live; the row became ordinary bounded `retryable` work.
    Retryable,
    /// The invoice is final; the row terminalized as `handoff_unresolved`
    /// with exactly one durable terminal event.
    Unresolved,
    /// The fence was no longer live (stale token/expired lease); no
    /// transition was written and fence recovery owns the row.
    Stale,
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
    handoff_sdk_invocation_started: bool,
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

    /// Whether the durable pre-SDK invocation marker was committed for this
    /// fenced row (migration 0023 rule 1): `false` proves the SDK was never
    /// invoked for the current fence, so no remote effect can exist.
    pub fn sdk_invocation_started(&self) -> bool {
        self.handoff_sdk_invocation_started
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

    /// Reports aggregate delivery availability without exposing row or
    /// Creator identifiers. A final-invoice `handoff_started`/`retryable`
    /// row is never active work (migration 0023 rule 5): it is either
    /// already terminal, awaiting the dedicated fenced-recovery path
    /// (`handoff_started`), or awaiting the bounded final-invoice backfill
    /// sweep (`retryable` residue from before transition-time
    /// terminalization shipped), so it must not degrade readiness while
    /// recovery or the sweep is pending.
    pub async fn delivery_available(&self) -> Result<bool, PersistenceError> {
        sqlx::query_scalar(
            "SELECT NOT EXISTS ( \
                 SELECT 1 FROM outbox o \
                 LEFT JOIN invoices invoice ON invoice.id = o.invoice_id \
                 WHERE o.status = 'handed_off' \
                    OR (o.status IN ('retryable', 'handoff_started') \
                        AND (o.invoice_id IS NULL OR invoice.baseline_state NOT IN ( \
                            'expired_final', 'void_baseline_failed', 'void_prepare_expired', \
                            'void_cancelled', 'resolved_paid_manually', 'resolved_closed' \
                        ))) \
             )",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// Terminal-failure health for the alert contract. `count`,
    /// `oldest_age_seconds`, and `by_class` cover only UNACKNOWLEDGED
    /// events, so operator acknowledgement (docs/outbox-terminal-acknowledgement.md)
    /// clears the critical signal; `transitions` remains the monotonic
    /// per-class/reason transition census feeding the counter.
    pub async fn terminal_failure_health(&self) -> Result<TerminalFailureHealth, PersistenceError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT event_class, COUNT(*)::BIGINT
             FROM outbox_terminal_events
             WHERE acknowledged_at IS NULL
             GROUP BY event_class",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let count = rows.iter().map(|(_, count)| *count).sum();
        let oldest_age_seconds = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))::BIGINT
             FROM outbox_terminal_events
             WHERE acknowledged_at IS NULL",
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

    /// Claim-pass fairness telemetry. A reader partition is FLOODED when its
    /// due eligible rows exceed what one claim pass can admit from it: one
    /// row when the partition holds no unexpired lease, zero when it does.
    /// Returns `(flooded_partitions, active_partitions)`, where active means
    /// holding an unexpired lease.
    pub async fn claim_metrics(&self) -> Result<(i64, i64), PersistenceError> {
        let (flooded_partitions, active_partitions): (i64, i64) = sqlx::query_as(
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
                 SELECT o.creator_id, roots.root_reader_assignment_id, COUNT(*) AS due_count
                 FROM outbox o JOIN roots ON roots.id = o.id
                 LEFT JOIN outbox dependency ON dependency.id = o.depends_on_id
                 LEFT JOIN invoices invoice ON invoice.id = o.invoice_id
                 WHERE ((o.status = 'queued' AND o.next_attempt_at <= NOW())
                     OR (o.status = 'leased' AND o.lease_expires_at <= NOW())
                     OR (o.status = 'retryable' AND o.next_attempt_at <= NOW()))
                   AND (o.invoice_id IS NULL OR invoice.baseline_state NOT IN (
                     'expired_final', 'void_baseline_failed', 'void_prepare_expired',
                     'void_cancelled', 'resolved_paid_manually', 'resolved_closed'))
                   AND (o.depends_on_id IS NULL OR dependency.status = 'delivered')
                 GROUP BY o.creator_id, roots.root_reader_assignment_id
             )
             SELECT (SELECT COUNT(*) FROM due_partitions
                     LEFT JOIN active
                       ON active.creator_id = due_partitions.creator_id
                      AND active.root_reader_assignment_id = due_partitions.root_reader_assignment_id
                     WHERE due_partitions.due_count >
                           CASE WHEN active.creator_id IS NULL THEN 1 ELSE 0 END),
                    (SELECT COUNT(*) FROM active)",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok((flooded_partitions, active_partitions))
    }

    /// Claims eligible rows while preserving endpoint-publication
    /// dependencies. Expired `handoff_started` rows are deliberately NOT
    /// re-admitted here (migration 0023 rule 2): only the dedicated
    /// [`Self::claim_fence_recovery`] path claims fenced rows, so a crashed
    /// handoff is never silently re-executed as ordinary work.
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
                        o.next_attempt_at, \
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
                     OR (o.status = 'leased' AND o.lease_expires_at <= NOW()) \
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
                 AND ( \
                     (o.status = 'queued' AND o.next_attempt_at <= NOW()) \
                     OR (o.status = 'leased' AND o.lease_expires_at <= NOW()) \
                     OR (o.status = 'retryable' AND o.next_attempt_at <= NOW()) \
                 ) \
                 ORDER BY ranked.next_attempt_at, ranked.id \
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
                  o.intent_envelope, o.handoff_sdk_invocation_started",
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

    /// One bounded pass of the one-time legacy backfill: terminalizes up to
    /// `limit` non-handed-off outbox rows whose invoice already sits in a
    /// final baseline state (the same closed set the claim path excludes),
    /// oldest `created_at` first, with the closed `invoice_final_backfill`
    /// reason and exactly one durable terminal event per transitioned row.
    /// These are rows left inert by invoices that reached a final state
    /// before transition-time terminalization shipped: never claimed
    /// (final-invoice exclusion) and never terminal. Rows holding a LIVE
    /// lease are never touched — their claim's final-invoice branch owns
    /// them — and `handed_off`/`handoff_started` rows are preserved. The
    /// batch is taken under the same `FOR UPDATE SKIP LOCKED` row-lock
    /// discipline as the ordinary claim path, and the transition is
    /// idempotent: a replayed pass matches zero rows and writes no second
    /// event.
    pub async fn sweep_final_invoice_backfill(&self, limit: i64) -> Result<u64, PersistenceError> {
        let changed = sqlx::query(
            "WITH candidates AS (
                 SELECT o.id
                 FROM outbox o
                 JOIN invoices invoice ON invoice.id = o.invoice_id
                 WHERE (o.status IN ('prepared', 'queued', 'retryable')
                        OR (o.status = 'leased' AND o.lease_expires_at <= NOW()))
                   AND invoice.baseline_state IN (
                       'expired_final', 'void_baseline_failed', 'void_prepare_expired',
                       'void_cancelled', 'resolved_paid_manually', 'resolved_closed')
                 ORDER BY o.created_at, o.id
                 FOR UPDATE OF o SKIP LOCKED
                 LIMIT $1
             ), changed AS (
                 UPDATE outbox
                 SET status = 'permanently_failed',
                     error_class = 'invoice_final_backfill',
                     failure_reason = 'invoice_final_backfill',
                     lease_owner = NULL,
                     claim_token = NULL,
                     lease_expires_at = NULL,
                     updated_at = NOW()
                 WHERE id IN (SELECT id FROM candidates)
                 RETURNING creator_id, invoice_id, id
             )
             INSERT INTO outbox_terminal_events
                 (creator_id, invoice_id, outbox_id, event_class, reason)
             SELECT creator_id, invoice_id, id, 'invoice_final_backfill',
                    'invoice_final_backfill'
             FROM changed",
        )
        .bind(limit)
        .execute(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected())
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

    /// The durable pre-SDK invocation marker (migration 0023 rule 1). The
    /// worker commits this under the live fence in its own transaction AFTER
    /// `begin_handoff` and BEFORE the SDK call. Because the SDK mints all
    /// outbound identifiers internally and accepts no caller idempotency
    /// key (paykit-sdk/src/runtime/payment_requests.rs:313-314;
    /// paykit-sdk/src/storage/records.rs:336), this marker is the only
    /// durable pre-effect identity available: a fenced row recovered with
    /// the marker FALSE provably never reached the SDK. Returns false when
    /// the fence is no longer live (stale token/expired lease); the caller
    /// must then NOT invoke the SDK and leave the row to fence recovery.
    pub async fn mark_handoff_invocation_started(
        &self,
        claim: &ClaimedOutbox,
    ) -> Result<bool, PersistenceError> {
        let changed = sqlx::query(
            "UPDATE outbox \
             SET handoff_sdk_invocation_started = TRUE, handoff_invocation_token = gen_random_uuid(), \
                 updated_at = NOW() \
             WHERE id = $1 AND status = 'handoff_started' AND claim_token = $2 \
               AND lease_expires_at > NOW()",
        )
        .bind(claim.id)
        .bind(claim.claim_token)
        .execute(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Returns the token minted by the live marker write, but never exposes it
    /// to logs or error text. The worker passes it only to the scoped adapter.
    pub async fn handoff_invocation_token(
        &self,
        claim: &ClaimedOutbox,
    ) -> Result<Option<Uuid>, PersistenceError> {
        sqlx::query_scalar(
            "SELECT handoff_invocation_token FROM outbox \
             WHERE id = $1 AND status = 'handoff_started' AND claim_token = $2 \
               AND lease_expires_at > NOW()",
        )
        .bind(claim.id)
        .bind(claim.claim_token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
        .map(|token| token.flatten())
    }

    /// The dedicated fenced-recovery claim (migration 0023 rule 2). Claims
    /// expired `handoff_started` rows REGARDLESS of invoice finality — the
    /// final-invoice exclusion of the ordinary claim path must not apply to
    /// fenced rows — and keeps the row in `handoff_started` under a fresh
    /// token/lease so `mark_handoff_unresolved` terminalization stays
    /// fenced by the exact token. Recovery never re-runs the SDK effect and
    /// never resolves or attributes durable SDK state (rule 3).
    pub async fn claim_fence_recovery(
        &self,
        owner: Uuid,
        limit: i64,
        lease: Duration,
    ) -> Result<Vec<ClaimedOutbox>, PersistenceError> {
        let seconds = lease_seconds(lease)?;
        self.terminalize_exhausted_fence_recoveries(limit).await?;
        sqlx::query_as(
            "WITH candidates AS ( \
                 SELECT id FROM outbox \
                 WHERE status = 'handoff_started' AND lease_expires_at <= NOW() \
                   AND recovery_attempts < 20 \
                   AND (recovery_first_at IS NULL OR NOW() < recovery_first_at + INTERVAL '1 hour') \
                 ORDER BY next_attempt_at, id \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT $1 \
             ) \
             UPDATE outbox o \
             SET lease_owner = $2, claim_token = gen_random_uuid(), \
                 lease_expires_at = NOW() + ($3 * INTERVAL '1 second'), \
                 recovery_attempts = o.recovery_attempts + 1, \
                 recovery_first_at = COALESCE(o.recovery_first_at, NOW()), \
                 recovery_last_at = NOW(), updated_at = NOW() \
             FROM candidates WHERE o.id = candidates.id \
             RETURNING o.id, o.creator_id, o.invoice_id, o.attempt_count, o.claim_token, \
                 (SELECT creator_lookup_hash FROM creators WHERE id = o.creator_id) AS creator_lookup_hash, \
                 o.intent_envelope, o.handoff_sdk_invocation_started",
        )
        .bind(limit)
        .bind(owner)
        .bind(seconds)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    async fn terminalize_exhausted_fence_recoveries(
        &self,
        limit: i64,
    ) -> Result<(), PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let changed: Vec<Uuid> = sqlx::query_scalar(
            "WITH candidates AS ( \
                 SELECT id FROM outbox \
                 WHERE status = 'handoff_started' AND lease_expires_at <= NOW() \
                   AND (recovery_attempts >= 20 \
                     OR (recovery_first_at IS NOT NULL \
                       AND NOW() >= recovery_first_at + INTERVAL '1 hour')) \
                 ORDER BY next_attempt_at, id FOR UPDATE SKIP LOCKED LIMIT $1 \
             ) UPDATE outbox SET status = 'permanently_failed', \
                 error_class = 'handoff_unresolved', \
                 failure_reason = 'sdk_recovery_infrastructure_unavailable', \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = NOW() \
             WHERE id IN (SELECT id FROM candidates) RETURNING id",
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for id in changed {
            Self::cascade_terminal_descendants(&mut tx, id, "parent_handoff_unresolved").await?;
            sqlx::query(
                "INSERT INTO outbox_terminal_events (creator_id, invoice_id, outbox_id, event_class, reason) \
                 SELECT creator_id, invoice_id, id, 'handoff_unresolved', \
                        'sdk_recovery_infrastructure_unavailable' FROM outbox WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        tx.commit().await.map_err(|_| PersistenceError::Unavailable)
    }

    /// Terminalizes a recovered fenced row (migration 0023 rule 3):
    /// `handoff_unresolved` is the closed terminal class for a
    /// `handoff_started` row that can neither be attributed nor safely
    /// re-executed. Recovery NEVER resolves or attributes an SDK effect, so
    /// both marker states take the same closed transition with zero SDK
    /// calls; only the static reason differs —
    /// [`HANDOFF_UNRESOLVED_SDK_NOT_INVOKED`] when the durable invocation
    /// marker is FALSE (the SDK provably never ran) and
    /// [`HANDOFF_UNRESOLVED_SDK_INVOKED_UNATTRIBUTED`] when it is TRUE (an
    /// effect may exist in durable SDK state and an operator reconciles it
    /// by hand). The transition, descendant cascade, and exactly one
    /// durable terminal event commit together; a replayed CAS matches zero
    /// rows and inserts no second event. The SDK is never re-run for the
    /// row afterwards.
    pub async fn mark_handoff_unresolved(
        &self,
        claim: &ClaimedOutbox,
    ) -> Result<bool, PersistenceError> {
        let reason = if claim.sdk_invocation_started() {
            HANDOFF_UNRESOLVED_SDK_INVOKED_UNATTRIBUTED
        } else {
            HANDOFF_UNRESOLVED_SDK_NOT_INVOKED
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let changed = sqlx::query(
            "UPDATE outbox \
             SET status = 'permanently_failed', \
                 error_class = 'handoff_unresolved', \
                 failure_reason = $3, \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, \
                 updated_at = NOW() \
             WHERE id = $1 AND status = 'handoff_started' AND claim_token = $2 \
               AND lease_expires_at > NOW()",
        )
        .bind(claim.id)
        .bind(claim.claim_token)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if changed.rows_affected() == 1 {
            Self::cascade_terminal_descendants(&mut tx, claim.id, "parent_handoff_unresolved")
                .await?;
            sqlx::query(
                "INSERT INTO outbox_terminal_events
                     (creator_id, invoice_id, outbox_id, event_class, reason)
                 SELECT creator_id, invoice_id, id, 'handoff_unresolved', $2
                 FROM outbox WHERE id = $1",
            )
            .bind(claim.id)
            .bind(reason)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Pure recovery resolver. It decrypts exactly one creator SDK snapshot
    /// under the target fence, never invokes an SDK API, and requires the
    /// current invocation sidecar before semantic equality can attribute.
    pub async fn resolve_fence_recovery(
        &self,
        claim: &ClaimedOutbox,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let marker: Option<(bool, Option<Uuid>)> = sqlx::query_as(
            "SELECT handoff_sdk_invocation_started, handoff_invocation_token FROM outbox \
             WHERE id = $1 AND status = 'handoff_started' AND claim_token = $2 \
               AND lease_expires_at > NOW() FOR UPDATE",
        )
        .bind(claim.id)
        .bind(claim.claim_token)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some((started, token)) = marker else {
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(false);
        };
        if !started {
            return self
                .terminalize_fence_recovery(
                    tx,
                    claim.id,
                    claim.claim_token,
                    HANDOFF_UNRESOLVED_SDK_NOT_INVOKED,
                )
                .await;
        }
        let Some(token) = token else {
            return self
                .terminalize_fence_recovery(
                    tx,
                    claim.id,
                    claim.claim_token,
                    "sdk_evidence_indeterminate",
                )
                .await;
        };
        let intent = match self.delivery_intent(claim) {
            Ok(intent) => intent,
            Err(PersistenceError::Unavailable) => {
                tx.commit()
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                return Err(PersistenceError::Unavailable);
            }
            Err(_) => {
                return self
                    .terminalize_fence_recovery(
                        tx,
                        claim.id,
                        claim.claim_token,
                        "sdk_evidence_indeterminate",
                    )
                    .await;
            }
        };
        let envelope: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT state_envelope FROM sdk_states WHERE creator_id = $1 FOR UPDATE",
        )
        .bind(claim.creator_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(envelope) = envelope else {
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(false);
        };
        let state = decrypt_state_for_recovery(
            &self.crypto,
            &claim.creator_lookup_hash,
            claim.creator_id,
            &envelope,
        )?;
        let mut exact = Vec::new();
        for record in &state.outbound_private_messages {
            match exact_handoff_result(&intent, record) {
                Ok(Some(result)) => exact.push((record.outbound_message_id.to_string(), result)),
                Ok(None) => {}
                Err(()) => {
                    return self
                        .terminalize_fence_recovery(
                            tx,
                            claim.id,
                            claim.claim_token,
                            "sdk_evidence_indeterminate",
                        )
                        .await;
                }
            }
        }
        if exact.is_empty() {
            return self
                .terminalize_fence_recovery(tx, claim.id, claim.claim_token, "sdk_effect_not_found")
                .await;
        }
        let ids = exact.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
        let sidecars: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT sdk_outbound_message_id, invocation_token FROM sdk_outbound_invocations \
             WHERE creator_id = $1 AND sdk_outbound_message_id = ANY($2)",
        )
        .bind(claim.creator_id)
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let sidecars = sidecars
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        if exact.iter().any(|(id, _)| !sidecars.contains_key(id)) {
            return self
                .terminalize_fence_recovery(tx, claim.id, claim.claim_token, "sdk_effect_ambiguous")
                .await;
        }
        let current = exact
            .into_iter()
            .filter(|(id, _)| sidecars.get(id) == Some(&token))
            .collect::<Vec<_>>();
        if current.is_empty() {
            return self
                .terminalize_fence_recovery(tx, claim.id, claim.claim_token, "sdk_effect_not_found")
                .await;
        }
        if current.len() != 1 {
            return self
                .terminalize_fence_recovery(tx, claim.id, claim.claim_token, "sdk_effect_ambiguous")
                .await;
        }
        let (outbound, result) = current.into_iter().next().expect("one current candidate");
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM outbox WHERE creator_id = $1 \
             AND sdk_outbound_message_id = $2 AND id <> $3 FOR UPDATE)",
        )
        .bind(claim.creator_id)
        .bind(&outbound)
        .bind(claim.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if owned {
            return self
                .terminalize_fence_recovery(
                    tx,
                    claim.id,
                    claim.claim_token,
                    "sdk_effect_already_owned",
                )
                .await;
        }
        let (event_id, request_id) = match result {
            HandoffResult::EndpointPublication { .. } => (None, None),
            HandoffResult::PaymentRequestProposal {
                ref event_id,
                ref payment_request_id,
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
        .bind(request_id)
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

    async fn terminalize_fence_recovery(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        id: Uuid,
        claim_token: Uuid,
        reason: &'static str,
    ) -> Result<bool, PersistenceError> {
        let changed = sqlx::query(
            "UPDATE outbox SET status = 'permanently_failed', error_class = 'handoff_unresolved', \
             failure_reason = $3, lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, \
             updated_at = NOW() WHERE id = $1 AND status = 'handoff_started' AND claim_token = $2 \
             AND lease_expires_at > NOW()",
        )
        .bind(id)
        .bind(claim_token)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if changed.rows_affected() == 1 {
            Self::cascade_terminal_descendants(&mut tx, id, "parent_handoff_unresolved").await?;
            sqlx::query(
                "INSERT INTO outbox_terminal_events (creator_id, invoice_id, outbox_id, event_class, reason) \
                 SELECT creator_id, invoice_id, id, 'handoff_unresolved', $2 FROM outbox WHERE id = $1",
            ).bind(id).bind(reason).execute(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?;
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Releases a fenced-recovery claim the worker could not process (the
    /// per-creator adapter was unavailable): the row stays
    /// `handoff_started` (never re-executed as ordinary work) and becomes
    /// claimable by [`Self::claim_fence_recovery`] again after the bounded
    /// delay.
    pub async fn retry_fence_recovery(
        &self,
        claim: &ClaimedOutbox,
        delay: Duration,
    ) -> Result<bool, PersistenceError> {
        let seconds = lease_seconds(delay)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let exhausted: Option<bool> = sqlx::query_scalar(
            "SELECT recovery_attempts >= 20
                 OR (recovery_first_at IS NOT NULL
                     AND NOW() >= recovery_first_at + INTERVAL '1 hour')
             FROM outbox
             WHERE id = $1 AND status = 'handoff_started' AND claim_token = $2
               AND lease_expires_at > NOW()
             FOR UPDATE",
        )
        .bind(claim.id)
        .bind(claim.claim_token)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(exhausted) = exhausted else {
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(false);
        };
        if exhausted {
            return self
                .terminalize_fence_recovery(
                    tx,
                    claim.id,
                    claim.claim_token,
                    "sdk_recovery_infrastructure_unavailable",
                )
                .await;
        }
        let changed = sqlx::query(
            "UPDATE outbox \
             SET lease_owner = NULL, claim_token = NULL, \
                 lease_expires_at = NOW() + ($1 * INTERVAL '1 second'), updated_at = NOW() \
             WHERE id = $2 AND status = 'handoff_started' AND claim_token = $3 \
               AND lease_expires_at > NOW()",
        )
        .bind(seconds)
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

    /// The retryable-error branch of a fenced handoff (migration 0023 rule
    /// 4). `handoff_started -> retryable` is forbidden when the invoice is
    /// final at transition time: finality is checked under the invoice row
    /// lock (the same lock cancellation holds while terminalizing outbox
    /// rows) and, when final, the row terminalizes as `handoff_unresolved`
    /// with one durable terminal event and a descendant cascade instead of
    /// becoming ordinary retryable work that final-invoice exclusion would
    /// strand forever. When the invoice is still live, the row becomes
    /// ordinary bounded `retryable` work as before.
    pub async fn release_handoff_retryable(
        &self,
        claim: &ClaimedOutbox,
        delay: Duration,
        error_class: OutboxRetryClass,
    ) -> Result<HandoffRelease, PersistenceError> {
        let seconds = lease_seconds(delay)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        if let Some(invoice_id) = claim.invoice_id {
            let final_invoice = sqlx::query_scalar::<_, bool>(
                "SELECT baseline_state IN (
                     'expired_final', 'void_baseline_failed', 'void_prepare_expired',
                     'void_cancelled', 'resolved_paid_manually', 'resolved_closed'
                 )
                 FROM invoices WHERE id = $1 FOR UPDATE",
            )
            .bind(invoice_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?
            .ok_or(PersistenceError::CorruptOrMissing)?;
            if final_invoice {
                let changed = sqlx::query(
                    "UPDATE outbox \
                     SET status = 'permanently_failed', \
                         error_class = 'handoff_unresolved', \
                         failure_reason = 'handoff_unresolved', \
                         lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, \
                         updated_at = NOW() \
                     WHERE id = $1 AND status = 'handoff_started' AND claim_token = $2 \
                       AND lease_expires_at > NOW()",
                )
                .bind(claim.id)
                .bind(claim.claim_token)
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
                if changed.rows_affected() == 1 {
                    Self::cascade_terminal_descendants(
                        &mut tx,
                        claim.id,
                        "parent_handoff_unresolved",
                    )
                    .await?;
                    sqlx::query(
                        "INSERT INTO outbox_terminal_events
                             (creator_id, invoice_id, outbox_id, event_class, reason)
                         SELECT creator_id, invoice_id, id, 'handoff_unresolved',
                                'handoff_unresolved'
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
                return Ok(if changed.rows_affected() == 1 {
                    HandoffRelease::Unresolved
                } else {
                    HandoffRelease::Stale
                });
            }
        }
        let changed = sqlx::query(
            "UPDATE outbox \
             SET status = 'retryable', error_class = $1, \
                 next_attempt_at = NOW() + ($2 * INTERVAL '1 second'), \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, \
                 updated_at = NOW() \
             WHERE id = $3 AND status = 'handoff_started' AND claim_token = $4 \
               AND lease_expires_at > NOW()",
        )
        .bind(error_class.as_str())
        .bind(seconds)
        .bind(claim.id)
        .bind(claim.claim_token)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(if changed.rows_affected() == 1 {
            HandoffRelease::Retryable
        } else {
            HandoffRelease::Stale
        })
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

fn decrypt_state_for_recovery(
    crypto: &Crypto,
    lookup_hash: &[u8],
    creator_id: Uuid,
    envelope: &[u8],
) -> Result<StorageState, PersistenceError> {
    let hash = lookup_hash_from_storage(lookup_hash)?;
    crate::persistence::sdk_state::decrypt_state(crypto, hash, creator_id, envelope)
}

/// `Ok(None)` means a different coordinate; `Err(())` means a malformed
/// record at this intent's reader/path/kind coordinate and is indeterminate.
fn exact_handoff_result(
    intent: &DeliveryIntentV1,
    record: &OutboundPrivateMessageRecord,
) -> Result<Option<HandoffResult>, ()> {
    if record.counterparty.to_string() != intent.reader_pubky()
        || record.counterparty_receiver_path.as_str()
            != intent.selected_reader_path().map_err(|_| ())?.as_str()
    {
        return Ok(None);
    }
    match intent.operation() {
        DeliveryOperationV1::EndpointPublication { receiving_details } => {
            if record.kind != PrivateMessageKind::PrivatePaymentList.as_str() {
                return Ok(None);
            }
            let list = parse_private_payment_list_json(&record.raw_json).map_err(|_| ())?;
            let expected_identifiers = receiving_details
                .iter()
                .map(|detail| detail.identifier.as_str())
                .collect::<std::collections::HashSet<_>>();
            if expected_identifiers.len() != receiving_details.len() {
                return Err(());
            }
            let expected = receiving_details
                .iter()
                .map(|detail| (detail.identifier.as_str(), detail.payload.as_str()))
                .collect::<std::collections::BTreeMap<_, _>>();
            let actual = list
                .payment_endpoints
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect::<std::collections::BTreeMap<_, _>>();
            Ok(
                (expected == actual).then_some(HandoffResult::EndpointPublication {
                    outbound_message_id: record.outbound_message_id,
                }),
            )
        }
        DeliveryOperationV1::PaymentRequestProposal { terms } => {
            if record.kind != PrivateMessageKind::PaymentRequest.as_str() {
                return Ok(None);
            }
            let message = PrivateApplicationMessage {
                version: Some(1),
                kind: Some(record.kind.clone()),
                raw_json: record.raw_json.clone(),
            };
            let parsed_message = parse_payment_request_event_message(&message).ok_or(())?;
            let parsed = parsed_message.parsed_event().ok_or(())?;
            let PaymentRequestEvent::Request(request) = parsed else {
                return Err(());
            };
            let mut expected_identifiers = terms.accepted_endpoint_identifiers.clone();
            let mut actual_identifiers = request
                .request
                .accepted_payment_endpoint_identifiers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            expected_identifiers.sort();
            actual_identifiers.sort();
            let exact = request.request.amount.value == terms.amount
                && request.request.amount.asset == terms.asset
                && request.request.payment_reference.to_string() == terms.payment_reference
                && request.request.proposal_expires_at == terms.proposal_expires_at
                && request.request.recurrence.is_none()
                && expected_identifiers == actual_identifiers
                && request.request.metadata == terms.metadata;
            Ok(exact.then_some(HandoffResult::PaymentRequestProposal {
                outbound_message_id: record.outbound_message_id,
                event_id: request.event_id.to_string(),
                payment_request_id: request.payment_request_id.to_string(),
            }))
        }
    }
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
            handoff_sdk_invocation_started: false,
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
