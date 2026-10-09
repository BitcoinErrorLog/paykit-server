//! Fenced PostgreSQL outbox claims and transitions.

use crate::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    persistence::PersistenceError,
};
use sqlx::{PgPool, Postgres, Transaction};
use std::{collections::BTreeSet, sync::Mutex, time::Duration};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxRetryClass {
    AdapterUnavailable,
    RegistryFetch,
    RegistryMissing,
    RegistryIncapable,
    ReaderAuthorizationFetch,
    ReaderAuthorizationMissing,
    ReaderAuthorizationInvalid,
    LinkEstablishment,
    LinkPending,
    PaymentRequestProposal,
    PaymentRequestCancellation,
    ReconciliationPending,
    Reconciliation,
}

impl OutboxRetryClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AdapterUnavailable => "adapter_unavailable",
            Self::RegistryFetch => "registry_fetch",
            Self::RegistryMissing => "registry_missing",
            Self::RegistryIncapable => "registry_incapable",
            Self::ReaderAuthorizationFetch => "reader_authorization_fetch",
            Self::ReaderAuthorizationMissing => "reader_authorization_missing",
            Self::ReaderAuthorizationInvalid => "reader_authorization_invalid",
            Self::LinkEstablishment => "link_establishment",
            Self::LinkPending => "link_pending",
            Self::PaymentRequestProposal => "payment_request_proposal",
            Self::PaymentRequestCancellation => "payment_request_cancellation",
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
    PaymentRequestCancellation {
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
            Self::PaymentRequestCancellation { .. } => {
                formatter.write_str("HandoffResult::PaymentRequestCancellation(<redacted>)")
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
            }
            | Self::PaymentRequestCancellation {
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
    failure_count: i32,
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

    /// Consecutive failures, excluding successful handshake progress or waiting.
    pub fn failure_count(&self) -> i32 {
        self.failure_count
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

#[derive(Clone, Debug)]
pub struct OutboxStore {
    pool: PgPool,
    crypto: std::sync::Arc<Crypto>,
    transport: std::sync::Arc<CreatorWakeup>,
    reconciliation: std::sync::Arc<CreatorWakeup>,
}

#[derive(Default)]
struct CreatorWakeup {
    creators: Mutex<BTreeSet<Uuid>>,
    notified: tokio::sync::Notify,
}

impl std::fmt::Debug for CreatorWakeup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CreatorWakeup { <redacted> }")
    }
}

impl CreatorWakeup {
    fn notify(&self, creator: Uuid) {
        self.creators
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(creator);
        self.notified.notify_one();
    }

    async fn wait(&self) -> Vec<Uuid> {
        self.notified.notified().await;
        let mut creators = self
            .creators
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *creators).into_iter().collect()
    }
}

impl OutboxStore {
    pub fn new(pool: &PgPool, crypto: std::sync::Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
            transport: std::sync::Arc::new(CreatorWakeup::default()),
            reconciliation: std::sync::Arc::new(CreatorWakeup::default()),
        }
    }

    /// Waits for coalesced Creator hints to process durably handed-off SDK work.
    pub async fn wait_for_transport(&self) -> Vec<Uuid> {
        self.transport.wait().await
    }

    /// Waits for coalesced Creator hints to reconcile committed handoffs.
    pub async fn wait_for_reconciliation(&self) -> Vec<Uuid> {
        self.reconciliation.wait().await
    }

    /// Reports aggregate delivery availability without exposing row or Creator identifiers.
    pub async fn delivery_available(&self) -> Result<bool, PersistenceError> {
        sqlx::query_scalar(
            "SELECT NOT EXISTS ( \
                 SELECT 1 FROM outbox \
                 WHERE status IN ('retryable', 'handed_off', 'permanently_failed') \
                    OR (status = 'leased' AND error_class IS NOT NULL) \
             )",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// Claims eligible Payment Request intents under a fresh lease fence.
    pub async fn claim(
        &self,
        owner: Uuid,
        limit: i64,
        lease: Duration,
    ) -> Result<Vec<ClaimedOutbox>, PersistenceError> {
        self.claim_matching(owner, limit, lease, None).await
    }

    /// Discovers due Creators without leasing work. Excluded Creators already
    /// have process-owned work; eligibility is checked again when claiming.
    pub async fn due_creator_ids(
        &self,
        excluded: &[Uuid],
        limit: i64,
    ) -> Result<Vec<Uuid>, PersistenceError> {
        sqlx::query_scalar(
            "SELECT o.creator_id FROM outbox o \
             WHERE NOT (o.creator_id = ANY($1)) AND ( \
                 (o.status IN ('queued', 'retryable') AND o.next_attempt_at <= clock_timestamp()) \
                 OR (o.status = 'leased' AND o.lease_expires_at <= clock_timestamp()) \
             ) AND (o.intent_kind <> 'payment_request_proposal' OR ( \
                 o.proposal_lookup_hash IS NOT NULL AND EXISTS ( \
                     SELECT 1 FROM invoices invoice \
                     JOIN lock_payment_generations generation \
                       ON generation.creator_id = invoice.creator_id \
                      AND generation.lock_resource_lookup_hash = invoice.lock_resource_lookup_hash \
                     WHERE invoice.id = o.invoice_id \
                       AND generation.current_generation = invoice.lock_resource_generation \
                       AND generation.active_drain_id IS NULL \
                 ))) \
             GROUP BY o.creator_id ORDER BY MIN(o.next_attempt_at), o.creator_id LIMIT $2",
        )
        .bind(excluded)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// Claims at most one due row after the caller has acquired Creator ownership.
    /// Discovery is only a hint; the normal due-time and generation fences apply.
    pub async fn claim_for_creator(
        &self,
        owner: Uuid,
        creator_id: Uuid,
        lease: Duration,
    ) -> Result<Option<ClaimedOutbox>, PersistenceError> {
        Ok(self
            .claim_matching(owner, 1, lease, Some(creator_id))
            .await?
            .pop())
    }

    async fn claim_matching(
        &self,
        owner: Uuid,
        limit: i64,
        lease: Duration,
        creator_id: Option<Uuid>,
    ) -> Result<Vec<ClaimedOutbox>, PersistenceError> {
        let seconds = lease_seconds(lease)?;
        sqlx::query_as(
            "WITH candidates AS ( \
                 SELECT o.id \
                 FROM outbox o \
                 WHERE ( \
                     (o.status = 'queued' AND o.next_attempt_at <= clock_timestamp()) \
                     OR (o.status = 'leased' AND o.lease_expires_at <= clock_timestamp()) \
                     OR (o.status = 'retryable' AND o.next_attempt_at <= clock_timestamp()) \
                 ) \
                 AND ($4::UUID IS NULL OR o.creator_id = $4) \
                 AND (o.intent_kind <> 'payment_request_proposal' OR ( \
                     o.proposal_lookup_hash IS NOT NULL AND EXISTS ( \
                     SELECT 1 \
                     FROM invoices invoice \
                     JOIN lock_payment_generations generation \
                       ON generation.creator_id = invoice.creator_id \
                      AND generation.lock_resource_lookup_hash = invoice.lock_resource_lookup_hash \
                     WHERE invoice.id = o.invoice_id \
                       AND generation.current_generation = invoice.lock_resource_generation \
                       AND generation.active_drain_id IS NULL \
                 ))) \
                 ORDER BY o.next_attempt_at, o.id \
                 FOR UPDATE OF o SKIP LOCKED \
                 LIMIT $1 \
             ) \
             UPDATE outbox o \
             SET status = 'leased', \
                 lease_owner = $2, \
                 claim_token = gen_random_uuid(), \
                 lease_expires_at = clock_timestamp() + ($3 * INTERVAL '1 second'), \
                 attempt_count = o.attempt_count + 1, \
                 updated_at = clock_timestamp() \
             FROM candidates \
             WHERE o.id = candidates.id \
             RETURNING o.id, o.creator_id, o.invoice_id, o.attempt_count, o.failure_count, o.claim_token, \
                 (SELECT creator_lookup_hash FROM creators WHERE id = o.creator_id) AS creator_lookup_hash, \
                 o.intent_envelope",
        )
        .bind(limit)
        .bind(owner)
        .bind(seconds)
        .bind(creator_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// Revalidates one live claim against the durable lock-generation drain fence.
    pub async fn claim_handoff_eligible(
        &self,
        claim: &ClaimedOutbox,
    ) -> Result<bool, PersistenceError> {
        sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM outbox o \
                 WHERE o.id = $1 AND o.status = 'leased' \
                   AND o.claim_token = $2 AND o.lease_expires_at > transaction_timestamp() \
                   AND (o.intent_kind <> 'payment_request_proposal' OR ( \
                       o.proposal_lookup_hash IS NOT NULL AND EXISTS ( \
                       SELECT 1 \
                       FROM invoices invoice \
                       JOIN lock_payment_generations generation \
                         ON generation.creator_id = invoice.creator_id \
                        AND generation.lock_resource_lookup_hash = invoice.lock_resource_lookup_hash \
                       WHERE invoice.id = o.invoice_id \
                         AND generation.current_generation = invoice.lock_resource_generation \
                         AND generation.active_drain_id IS NULL \
                   ))) \
             )",
        )
        .bind(claim.id)
        .bind(claim.claim_token)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// Extends only a live claim whose proposal generation still permits handoff.
    pub async fn renew_claim(
        &self,
        claim: &ClaimedOutbox,
        lease: Duration,
    ) -> Result<bool, PersistenceError> {
        let Some((mut transaction, now)) = self.transition_fence(claim.id).await? else {
            return Ok(false);
        };
        let changed = sqlx::query(
            "UPDATE outbox o SET lease_expires_at = $3 + ($4 * INTERVAL '1 second') \
             WHERE o.id = $1 AND o.status = 'leased' AND o.claim_token = $2 \
               AND o.lease_expires_at > $3 \
               AND (o.intent_kind <> 'payment_request_proposal' OR ( \
                   o.proposal_lookup_hash IS NOT NULL AND EXISTS ( \
                       SELECT 1 FROM invoices invoice \
                       JOIN lock_payment_generations generation \
                         ON generation.creator_id = invoice.creator_id \
                        AND generation.lock_resource_lookup_hash = invoice.lock_resource_lookup_hash \
                       WHERE invoice.id = o.invoice_id \
                         AND generation.current_generation = invoice.lock_resource_generation \
                         AND generation.active_drain_id IS NULL \
                   )))",
        )
        .bind(claim.id)
        .bind(claim.claim_token)
        .bind(now)
        .bind(lease_seconds(lease)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        transaction
            .commit()
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
        self.claim_reconciliation_for_creators(owner, limit, lease, None)
            .await
    }

    /// Claims due handoffs for selected Creators, or all Creators on a periodic scan.
    pub async fn claim_reconciliation_for_creators(
        &self,
        owner: Uuid,
        limit: i64,
        lease: Duration,
        creators: Option<&[Uuid]>,
    ) -> Result<Vec<ClaimedHandoff>, PersistenceError> {
        let seconds = lease_seconds(lease)?;
        sqlx::query_as(
            "WITH candidates AS ( \
                 SELECT id FROM outbox \
                 WHERE status = 'handed_off' \
                   AND ($4::UUID[] IS NULL OR creator_id = ANY($4)) \
                   AND sdk_outbound_message_id IS NOT NULL \
                   AND next_attempt_at <= clock_timestamp() \
                   AND (claim_token IS NULL OR lease_expires_at <= clock_timestamp()) \
                 ORDER BY next_attempt_at, id \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT $1 \
             ) \
             UPDATE outbox o \
             SET lease_owner = $2, claim_token = gen_random_uuid(), \
                 lease_expires_at = clock_timestamp() + ($3 * INTERVAL '1 second'), \
                 attempt_count = o.attempt_count + 1, updated_at = clock_timestamp() \
             FROM candidates WHERE o.id = candidates.id \
             RETURNING o.id, o.creator_id, o.attempt_count, o.claim_token, \
                 o.sdk_outbound_message_id",
        )
        .bind(limit)
        .bind(owner)
        .bind(seconds)
        .bind(creators)
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

    /// Records the exact SDK enqueue result while the enqueue fence is live.
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
            }
            | HandoffResult::PaymentRequestCancellation {
                event_id,
                payment_request_id,
                ..
            } => (Some(event_id.as_str()), Some(payment_request_id.as_str())),
        };
        let Some((mut transaction, now)) = self.transition_fence(claim.id).await? else {
            return Ok(false);
        };
        let changed = sqlx::query(
            "UPDATE outbox SET status = 'handed_off', sdk_outbound_message_id = $1, \
                 sdk_event_id = $2, sdk_payment_request_id = $3, error_class = NULL, failure_count = 0, \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = $6 \
             WHERE id = $4 AND status = 'leased' AND claim_token = $5 AND lease_expires_at > $6",
        )
        .bind(outbound)
        .bind(event_id)
        .bind(payment_request_id)
        .bind(claim.id)
        .bind(claim.claim_token)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        if changed.rows_affected() == 1 {
            // Hints never replace the durable row, due time, or claim fence.
            self.transport.notify(claim.creator_id);
            self.reconciliation.notify(claim.creator_id);
        }
        Ok(changed.rows_affected() == 1)
    }

    /// Checks for a committed SDK association after enqueue.
    /// Leased, failed, and already delivered rows are not eligible for an initial send.
    pub async fn handoff_is_committed(
        &self,
        claim: &ClaimedOutbox,
    ) -> Result<bool, PersistenceError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM outbox \
             WHERE id = $1 AND creator_id = $2 AND status = 'handed_off')",
        )
        .bind(claim.id)
        .bind(claim.creator_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// Marks delivery only while the separately acquired reconciliation fence is live.
    pub async fn mark_delivered(&self, claim: &ClaimedHandoff) -> Result<bool, PersistenceError> {
        self.reconciliation_transition(claim, "delivered", None, None)
            .await
    }

    /// Retains an attributable handoff whose SDK state cannot be reconciled safely.
    pub async fn mark_reconciliation_permanently_failed(
        &self,
        claim: &ClaimedHandoff,
    ) -> Result<bool, PersistenceError> {
        self.reconciliation_transition(
            claim,
            "permanently_failed",
            Some("permanent_sdk_reconciliation"),
            None,
        )
        .await
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
            Some(duration_milliseconds(delay)?),
        )
        .await
    }

    async fn transition(
        &self,
        claim: &ClaimedOutbox,
        status: &str,
        error_class: Option<&str>,
        delay_milliseconds: Option<i64>,
    ) -> Result<bool, PersistenceError> {
        let Some((mut transaction, now)) = self.transition_fence(claim.id).await? else {
            return Ok(false);
        };
        let changed = sqlx::query(
            "UPDATE outbox \
             SET status = $1, error_class = $2, \
                 failure_count = CASE WHEN $2 = 'link_pending' THEN 0 \
                     WHEN $1 = 'retryable' THEN LEAST(failure_count::BIGINT + 1, 2147483647)::INTEGER \
                     ELSE failure_count END, \
                 next_attempt_at = CASE WHEN $3::BIGINT IS NULL THEN next_attempt_at ELSE $6 + ($3 * INTERVAL '1 millisecond') END, \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = $6 \
             WHERE id = $4 AND status = 'leased' AND claim_token = $5 AND lease_expires_at > $6",
        )
        .bind(status)
        .bind(error_class)
        .bind(delay_milliseconds)
        .bind(claim.id)
        .bind(claim.claim_token)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    async fn reconciliation_transition(
        &self,
        claim: &ClaimedHandoff,
        status: &str,
        error_class: Option<&str>,
        delay: Option<i64>,
    ) -> Result<bool, PersistenceError> {
        let Some((mut transaction, now)) = self.transition_fence(claim.id).await? else {
            return Ok(false);
        };
        let changed = sqlx::query(
            "UPDATE outbox SET status = $1, error_class = $2, \
                 next_attempt_at = CASE WHEN $3::BIGINT IS NULL THEN next_attempt_at ELSE $7 + ($3 * INTERVAL '1 second') END, \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = $7 \
             WHERE id = $4 AND status = 'handed_off' \
               AND sdk_outbound_message_id = $5 AND claim_token = $6 AND lease_expires_at > $7",
        )
        .bind(status)
        .bind(error_class)
        .bind(delay)
        .bind(claim.id)
        .bind(&claim.sdk_outbound_message_id)
        .bind(claim.claim_token)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(changed.rows_affected() == 1)
    }

    async fn transition_fence(
        &self,
        id: Uuid,
    ) -> Result<Option<(Transaction<'_, Postgres>, OffsetDateTime)>, PersistenceError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM outbox WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
        if exists.is_none() {
            return Ok(None);
        }
        let now = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(Some((transaction, now)))
    }
}

fn lease_seconds(duration: Duration) -> Result<i64, PersistenceError> {
    i64::try_from(duration.as_secs()).map_err(|_| PersistenceError::Unavailable)
}

fn duration_milliseconds(duration: Duration) -> Result<i64, PersistenceError> {
    i64::try_from(duration.as_millis()).map_err(|_| PersistenceError::Unavailable)
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

    #[tokio::test]
    async fn creator_wakeups_coalesce_and_drain_without_losing_later_hints() {
        let wakeup = CreatorWakeup::default();
        let creators = BTreeSet::from([Uuid::new_v4(), Uuid::new_v4()]);
        for creator in &creators {
            wakeup.notify(*creator);
            wakeup.notify(*creator);
        }
        assert_eq!(
            tokio::time::timeout(Duration::ZERO, wakeup.wait())
                .await
                .unwrap(),
            creators.into_iter().collect::<Vec<_>>()
        );
        assert!(
            tokio::time::timeout(Duration::ZERO, wakeup.wait())
                .await
                .is_err()
        );

        let creator = Uuid::new_v4();
        wakeup.notify(creator);
        assert_eq!(
            tokio::time::timeout(Duration::ZERO, wakeup.wait())
                .await
                .unwrap(),
            vec![creator]
        );
    }

    #[test]
    fn retry_classes_are_closed_diagnostics() {
        assert_eq!(
            [
                OutboxRetryClass::AdapterUnavailable,
                OutboxRetryClass::RegistryFetch,
                OutboxRetryClass::RegistryMissing,
                OutboxRetryClass::RegistryIncapable,
                OutboxRetryClass::ReaderAuthorizationFetch,
                OutboxRetryClass::ReaderAuthorizationMissing,
                OutboxRetryClass::ReaderAuthorizationInvalid,
                OutboxRetryClass::LinkEstablishment,
                OutboxRetryClass::LinkPending,
                OutboxRetryClass::PaymentRequestProposal,
                OutboxRetryClass::PaymentRequestCancellation,
                OutboxRetryClass::ReconciliationPending,
                OutboxRetryClass::Reconciliation,
            ]
            .map(OutboxRetryClass::as_str),
            [
                "adapter_unavailable",
                "registry_fetch",
                "registry_missing",
                "registry_incapable",
                "reader_authorization_fetch",
                "reader_authorization_missing",
                "reader_authorization_invalid",
                "link_establishment",
                "link_pending",
                "payment_request_proposal",
                "payment_request_cancellation",
                "reconciliation_pending",
                "reconciliation",
            ]
        );
    }

    #[test]
    fn enqueue_retry_delay_preserves_milliseconds() {
        assert_eq!(
            duration_milliseconds(Duration::from_millis(500)).unwrap(),
            500
        );
        assert_eq!(
            duration_milliseconds(Duration::from_secs(5)).unwrap(),
            5_000
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
            attempt_count: 8,
            claim_token: Uuid::new_v4(),
            sdk_outbound_message_id: outbound_id.into(),
        };
        let outbox_claim = ClaimedOutbox {
            id: claim_id,
            creator_id,
            invoice_id: Some(Uuid::new_v4()),
            attempt_count: 7,
            failure_count: 0,
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
