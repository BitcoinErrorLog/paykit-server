//! Semantic outbox handoff policy.
//!
//! A call can commit to the SDK queue and the process can crash before the
//! fenced database transition. Retrying therefore has **at-least-once**
//! semantics: Payment Request proposals may be duplicated. The SDK owns its
//! queue and encrypted-link retry state; this worker never claims exactly-once.

use async_trait::async_trait;
use paykit_lib::PaykitReceiverMarker;
use paykit_sdk::OutboundPrivateMessageStatus;

use crate::{
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    metrics::Metrics,
    persistence::{
        ClaimedHandoff, ClaimedOutbox, OutboxStore, PersistenceError, RetryBudget, RetryTransition,
    },
};
use std::time::Duration;

pub use crate::persistence::{HandoffResult, OutboxRetryClass as RetryableHandoffStage};

/// Metric/log label for the enqueue delivery lane (closed set).
pub const DELIVERY_KIND: &str = "delivery";
/// Metric/log label for the reconciliation lane (closed set).
pub const RECONCILIATION_KIND: &str = "reconciliation";

/// Reports a retry-budget exhaustion exactly once: the fenced statement that
/// released the lease already transitioned the row, so concurrent workers see
/// [`RetryTransition::FenceLost`] and never reach this path for the same row.
fn report_budget_exhausted(
    metrics: &Metrics,
    kind: &'static str,
    row_id: uuid::Uuid,
    attempt_count: i32,
) {
    tracing::error!(
        row_id = %row_id,
        kind,
        attempt_count,
        "outbox retry budget exhausted; row transitioned to permanently_failed"
    );
    metrics.outbox_permanent_failure(kind);
}

pub(crate) fn retry_health(
    metrics: &Metrics,
    kind: &'static str,
    row_id: uuid::Uuid,
    attempt_count: i32,
    outcome: RetryTransition,
) -> (bool, ProcessingHealth) {
    match outcome {
        RetryTransition::Scheduled => (true, ProcessingHealth::Retryable),
        RetryTransition::BudgetExhausted => {
            report_budget_exhausted(metrics, kind, row_id, attempt_count);
            (true, ProcessingHealth::PermanentFailure)
        }
        RetryTransition::FenceLost => (false, ProcessingHealth::Retryable),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffError {
    Retryable(RetryableHandoffCause),
    Permanent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryableHandoffCause {
    Storage,
    Identity,
    Transport,
    NotFound,
    PaymentAdapter,
    RecoveryRequired,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffFailure {
    Retryable(RetryableHandoffStage),
    Permanent,
}

fn at_stage(error: HandoffError, stage: RetryableHandoffStage) -> HandoffFailure {
    match error {
        HandoffError::Retryable(_) => HandoffFailure::Retryable(stage),
        HandoffError::Permanent => HandoffFailure::Permanent,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessingHealth {
    Available,
    Retryable,
    PermanentFailure,
}

/// Public-SDK-only adapter. Production implementations must persist SDK state
/// through the creator SDK-state service; an in-memory runtime is test-only.
#[async_trait]
pub trait Adapter: Send + Sync {
    /// Executes one complete semantic handoff. Concrete adapters may override
    /// this to serialize a multi-call SDK operation under one Creator lock.
    async fn execute_handoff(
        &self,
        intent: &DeliveryIntentV1,
    ) -> Result<HandoffResult, HandoffFailure> {
        handoff_steps(self, intent).await
    }

    async fn fetch_marker(
        &self,
        reader: &str,
        path: &str,
    ) -> Result<Option<PaykitReceiverMarker>, HandoffError>;
    async fn ensure_link_with_peer(&self, reader: &str, path: &str) -> Result<(), HandoffError>;
    async fn enqueue_private_payment_list_with_receiving_details(
        &self,
        reader: &str,
        path: &str,
        details: &[crate::application::semantic_intent::ReceivingDetailV1],
    ) -> Result<HandoffResult, HandoffError>;
    async fn propose_payment_request(
        &self,
        reader: &str,
        path: &str,
        terms: &crate::application::semantic_intent::PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError>;
    async fn outbound_status(
        &self,
        outbound_message_id: u64,
    ) -> Result<Option<OutboundPrivateMessageStatus>, HandoffError>;
}

/// Preflight the persisted exact path before any SDK call. Missing, changed, or
/// no-longer-capable markers are retryable and never cause path reselection.
pub async fn handoff(
    adapter: &dyn Adapter,
    intent: &DeliveryIntentV1,
) -> Result<HandoffResult, HandoffFailure> {
    adapter.execute_handoff(intent).await
}

pub(crate) async fn handoff_steps<A: Adapter + ?Sized>(
    adapter: &A,
    intent: &DeliveryIntentV1,
) -> Result<HandoffResult, HandoffFailure> {
    intent.validate().map_err(|_| HandoffFailure::Permanent)?;
    let selected_path = intent
        .selected_reader_path()
        .map_err(|_| HandoffFailure::Permanent)?;
    let marker = adapter
        .fetch_marker(intent.reader_pubky(), selected_path.as_str())
        .await
        .map_err(|error| at_stage(error, RetryableHandoffStage::MarkerFetch))?
        .ok_or(HandoffFailure::Retryable(
            RetryableHandoffStage::MarkerMissing,
        ))?;
    if !marker.capabilities.private_payments
        || !marker.capabilities.payment_requests
        || DeliveryIntentV1::fingerprint(&marker)
            .map_err(|_| HandoffFailure::Retryable(RetryableHandoffStage::MarkerChanged))?
            != intent.marker_fingerprint()
    {
        return Err(HandoffFailure::Retryable(
            RetryableHandoffStage::MarkerChanged,
        ));
    }
    adapter
        .ensure_link_with_peer(intent.reader_pubky(), selected_path.as_str())
        .await
        .map_err(|error| at_stage(error, RetryableHandoffStage::LinkEstablishment))?;
    match intent.operation() {
        DeliveryOperationV1::EndpointPublication { receiving_details } => adapter
            .enqueue_private_payment_list_with_receiving_details(
                intent.reader_pubky(),
                selected_path.as_str(),
                receiving_details,
            )
            .await
            .map_err(|error| at_stage(error, RetryableHandoffStage::EndpointPublication)),
        DeliveryOperationV1::PaymentRequestProposal { terms } => adapter
            .propose_payment_request(intent.reader_pubky(), selected_path.as_str(), terms)
            .await
            .map_err(|error| at_stage(error, RetryableHandoffStage::PaymentRequestProposal)),
    }
}

/// Executes one already-fenced claim. A successful public SDK enqueue is only
/// `handed_off`: the SDK API returns local queue state, not remote delivery.
/// A crash after enqueue but before this fenced transition is intentionally
/// retried, so Payment Request proposals are at-least-once and may duplicate.
pub async fn process_claim(
    store: &OutboxStore,
    adapter: &dyn Adapter,
    claim: &ClaimedOutbox,
    retry_delay: Duration,
    budget: &RetryBudget,
    metrics: &Metrics,
) -> Result<bool, PersistenceError> {
    process_claim_with_health(store, adapter, claim, retry_delay, budget, metrics)
        .await
        .map(|(transitioned, _)| transitioned)
}

pub async fn process_claim_with_health(
    store: &OutboxStore,
    adapter: &dyn Adapter,
    claim: &ClaimedOutbox,
    retry_delay: Duration,
    budget: &RetryBudget,
    metrics: &Metrics,
) -> Result<(bool, ProcessingHealth), PersistenceError> {
    let intent = match store.delivery_intent(claim) {
        Ok(intent) => intent,
        Err(_) => {
            return store
                .mark_permanently_failed(claim)
                .await
                .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure));
        }
    };
    match handoff(adapter, &intent).await {
        Ok(result) => store
            .mark_handed_off(claim, &result)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::Available)),
        Err(HandoffFailure::Retryable(stage)) => store
            .mark_retryable(claim, retry_delay, stage, budget)
            .await
            .map(|outcome| {
                retry_health(
                    metrics,
                    DELIVERY_KIND,
                    claim.id(),
                    claim.attempt_count(),
                    outcome,
                )
            }),
        Err(HandoffFailure::Permanent) => store
            .mark_permanently_failed(claim)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
    }
}

/// Reconciles one exact persisted SDK outbound record. Only durable `Sent`
/// unlocks dependencies. Recoverable states remain `handed_off`; exact
/// `Invalid`, `RecoveryRequired`, or `Superseded` records become retained
/// permanent failures because the SDK will not claim those records again.
pub async fn process_reconciliation(
    store: &OutboxStore,
    adapter: &dyn Adapter,
    claim: &ClaimedHandoff,
    retry_delay: Duration,
    budget: &RetryBudget,
    metrics: &Metrics,
) -> Result<bool, PersistenceError> {
    process_reconciliation_with_health(store, adapter, claim, retry_delay, budget, metrics)
        .await
        .map(|(transitioned, _)| transitioned)
}

pub async fn process_reconciliation_with_health(
    store: &OutboxStore,
    adapter: &dyn Adapter,
    claim: &ClaimedHandoff,
    retry_delay: Duration,
    budget: &RetryBudget,
    metrics: &Metrics,
) -> Result<(bool, ProcessingHealth), PersistenceError> {
    let outbound_message_id = match claim.sdk_outbound_message_id() {
        Ok(value) => value,
        Err(_) => {
            return store
                .mark_reconciliation_permanently_failed(claim)
                .await
                .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure));
        }
    };
    match adapter.outbound_status(outbound_message_id).await {
        Ok(Some(OutboundPrivateMessageStatus::Sent)) => store
            .mark_delivered(claim)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::Available)),
        Ok(Some(
            OutboundPrivateMessageStatus::Invalid
            | OutboundPrivateMessageStatus::RecoveryRequired
            | OutboundPrivateMessageStatus::Superseded,
        )) => store
            .mark_reconciliation_permanently_failed(claim)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
        Ok(_) => store
            .retry_reconciliation(
                claim,
                retry_delay,
                RetryableHandoffStage::ReconciliationPending,
                budget,
            )
            .await
            .map(|outcome| {
                retry_health(
                    metrics,
                    RECONCILIATION_KIND,
                    claim.id(),
                    claim.attempt_count(),
                    outcome,
                )
            }),
        Err(HandoffError::Retryable(_)) => store
            .retry_reconciliation(
                claim,
                retry_delay,
                RetryableHandoffStage::Reconciliation,
                budget,
            )
            .await
            .map(|outcome| {
                retry_health(
                    metrics,
                    RECONCILIATION_KIND,
                    claim.id(),
                    claim.attempt_count(),
                    outcome,
                )
            }),
        Err(HandoffError::Permanent) => store
            .mark_reconciliation_permanently_failed(claim)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
    }
}
