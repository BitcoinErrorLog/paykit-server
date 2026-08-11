//! Fenced PostgreSQL outbox claims and transitions.

use crate::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    persistence::PersistenceError,
};
use sqlx::PgPool;
use std::time::Duration;
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
    PaymentRequestCancellation,
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
}

impl OutboxStore {
    pub fn new(pool: &PgPool, crypto: std::sync::Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    /// Reports aggregate delivery availability without exposing row or Creator identifiers.
    pub async fn delivery_available(&self) -> Result<bool, PersistenceError> {
        sqlx::query_scalar(
            "SELECT NOT EXISTS ( \
                 SELECT 1 FROM outbox \
                 WHERE status IN ('retryable', 'handed_off', 'permanently_failed') \
             )",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
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
            "WITH candidates AS ( \
                 SELECT o.id \
                 FROM outbox o \
                 LEFT JOIN outbox dependency ON dependency.id = o.depends_on_id \
                 WHERE ( \
                     (o.status = 'queued' AND o.next_attempt_at <= NOW()) \
                     OR (o.status = 'leased' AND o.lease_expires_at <= NOW()) \
                     OR (o.status = 'retryable' AND o.next_attempt_at <= NOW()) \
                 ) \
                 AND (o.depends_on_id IS NULL OR dependency.status = 'delivered') \
                 ORDER BY o.next_attempt_at, o.id \
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
             RETURNING o.id, o.creator_id, o.attempt_count, o.claim_token, \
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

    /// Atomically associates the exact public-SDK result while the enqueue fence is live.
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
        let changed = sqlx::query(
            "UPDATE outbox SET status = 'handed_off', sdk_outbound_message_id = $1, \
                 sdk_event_id = $2, sdk_payment_request_id = $3, error_class = NULL, \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = NOW() \
             WHERE id = $4 AND status = 'leased' AND claim_token = $5 AND lease_expires_at > NOW()",
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
        let changed = sqlx::query(
            "UPDATE outbox \
             SET status = $1, error_class = $2, \
                 next_attempt_at = CASE WHEN $3::BIGINT IS NULL THEN next_attempt_at ELSE NOW() + ($3 * INTERVAL '1 second') END, \
                 lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL, updated_at = NOW() \
             WHERE id = $4 AND status = 'leased' AND claim_token = $5 AND lease_expires_at > NOW()",
        )
        .bind(status)
        .bind(error_class)
        .bind(delay)
        .bind(claim.id)
        .bind(claim.claim_token)
        .execute(&self.pool)
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
                OutboxRetryClass::PaymentRequestCancellation,
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
                "payment_request_cancellation",
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
