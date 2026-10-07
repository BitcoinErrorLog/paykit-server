//! Semantic outbox handoff policy.
//!
//! A call can commit to the SDK queue and the process can crash before the
//! fenced database transition. Retrying therefore has **at-least-once**
//! semantics: Payment Request proposals may be duplicated. The SDK owns its
//! queue and encrypted-link retry state; this worker never claims exactly-once.

use async_trait::async_trait;
use paykit_lib::PaykitAppRegistry;
use paykit_sdk::OutboundPrivateMessageStatus;

use crate::{
    application::{
        create_invoice::ReaderAuthorization,
        semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    },
    persistence::{ClaimedHandoff, ClaimedOutbox, OutboxStore, PersistenceError},
};
use std::time::Duration;

pub use crate::persistence::{HandoffResult, OutboxRetryClass as RetryableHandoffStage};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffError {
    Retryable(RetryableHandoffCause),
    Permanent,
}

impl HandoffError {
    pub const fn diagnostic_label(self) -> &'static str {
        match self {
            Self::Retryable(cause) => cause.diagnostic_label(),
            Self::Permanent => "permanent",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryableHandoffCause {
    Storage,
    Identity,
    Transport,
    NotFound,
    PaymentAdapter,
    RecoveryRequired,
    Policy,
    LinkPending,
    Other,
}

impl RetryableHandoffCause {
    pub const fn diagnostic_label(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Identity => "identity",
            Self::Transport => "transport",
            Self::NotFound => "not_found",
            Self::PaymentAdapter => "payment_adapter",
            Self::RecoveryRequired => "recovery_required",
            Self::Policy => "policy",
            Self::LinkPending => "link_pending",
            Self::Other => "other",
        }
    }
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
    Retryable(Duration),
    PermanentFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetrySchedule {
    default: Duration,
    link_establishment: Duration,
}

impl RetrySchedule {
    pub fn new(default: Duration, link_establishment: Duration) -> Self {
        Self {
            default,
            link_establishment,
        }
    }

    pub fn default_delay(self) -> Duration {
        self.default
    }

    pub(crate) fn delay_for(self, stage: RetryableHandoffStage) -> Duration {
        if stage == RetryableHandoffStage::LinkEstablishment {
            self.link_establishment
        } else {
            self.default
        }
    }
}

/// Public-SDK-only adapter. Production implementations must persist SDK state
/// through identity-wide Pubky shared storage; an in-memory runtime is test-only.
#[async_trait]
pub trait Adapter: Send + Sync {
    /// Revalidates a claimed row immediately before its external SDK effect.
    /// Production overrides hold the same Creator mutation fence as drain creation.
    async fn execute_claimed_handoff(
        &self,
        store: &OutboxStore,
        claim: &ClaimedOutbox,
        intent: &DeliveryIntentV1,
    ) -> Result<HandoffResult, HandoffFailure> {
        match store.claim_handoff_eligible(claim).await {
            Ok(true) => self.execute_handoff(intent).await,
            Ok(false) => Err(HandoffFailure::Permanent),
            Err(_) => Err(HandoffFailure::Retryable(
                RetryableHandoffStage::AdapterUnavailable,
            )),
        }
    }

    /// Executes one complete semantic handoff. Concrete adapters may override
    /// this to serialize a multi-call SDK operation under one Creator lock.
    async fn execute_handoff(
        &self,
        intent: &DeliveryIntentV1,
    ) -> Result<HandoffResult, HandoffFailure> {
        handoff_steps(self, intent).await
    }

    async fn fetch_registry(&self, reader: &str)
    -> Result<Option<PaykitAppRegistry>, HandoffError>;
    /// The Reader's signed Noise Key Authorization, checked before link setup,
    /// which verifies it again.
    async fn fetch_authorization(&self, reader: &str) -> Result<ReaderAuthorization, HandoffError>;
    async fn observe_recovery_marker(&self, reader: &str) -> Result<(), HandoffError>;
    async fn ensure_link_with_peer(&self, reader: &str) -> Result<(), HandoffError>;
    async fn propose_payment_request(
        &self,
        reader: &str,
        terms: &crate::application::semantic_intent::PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError>;
    async fn cancel_payment_request(
        &self,
        reader: &str,
        payment_request_id: &str,
    ) -> Result<HandoffResult, HandoffError>;
    async fn outbound_status(
        &self,
        outbound_message_id: u64,
    ) -> Result<Option<OutboundPrivateMessageStatus>, HandoffError>;
}

/// Recheck reader capabilities before handing off the persisted intent.
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
    let registry = adapter
        .fetch_registry(intent.reader_pubky())
        .await
        .map_err(|error| at_stage(error, RetryableHandoffStage::RegistryFetch))?
        .ok_or(HandoffFailure::Retryable(
            RetryableHandoffStage::RegistryMissing,
        ))?;
    if !crate::application::reader_registry::reader_is_capable(&registry) {
        return Err(HandoffFailure::Retryable(
            RetryableHandoffStage::RegistryIncapable,
        ));
    }
    // Retryable like an incapable registry: the Reader can still publish or fix it.
    match adapter
        .fetch_authorization(intent.reader_pubky())
        .await
        .map_err(|error| at_stage(error, RetryableHandoffStage::ReaderAuthorizationFetch))?
    {
        ReaderAuthorization::Verified => {}
        ReaderAuthorization::Missing => {
            return Err(HandoffFailure::Retryable(
                RetryableHandoffStage::ReaderAuthorizationMissing,
            ));
        }
        ReaderAuthorization::Invalid => {
            return Err(HandoffFailure::Retryable(
                RetryableHandoffStage::ReaderAuthorizationInvalid,
            ));
        }
    }
    adapter
        .observe_recovery_marker(intent.reader_pubky())
        .await
        .map_err(|error| at_stage(error, RetryableHandoffStage::RecoveryMarkerObservation))?;
    adapter
        .ensure_link_with_peer(intent.reader_pubky())
        .await
        .map_err(|error| at_stage(error, RetryableHandoffStage::LinkEstablishment))?;
    match intent.operation() {
        DeliveryOperationV1::PaymentRequestProposal { terms } => adapter
            .propose_payment_request(intent.reader_pubky(), terms)
            .await
            .map_err(|error| at_stage(error, RetryableHandoffStage::PaymentRequestProposal)),
        DeliveryOperationV1::PaymentRequestCancellation { payment_request_id } => adapter
            .cancel_payment_request(intent.reader_pubky(), payment_request_id)
            .await
            .map_err(|error| at_stage(error, RetryableHandoffStage::PaymentRequestCancellation)),
    }
}

/// Executes one already-fenced claim. Enqueue is only `handed_off`; the SDK
/// outbound record is reconciled separately before publication is acknowledged.
/// A crash after enqueue but before this fenced transition is intentionally
/// retried, so Payment Request proposals are at-least-once and may duplicate.
pub async fn process_claim(
    store: &OutboxStore,
    adapter: &dyn Adapter,
    claim: &ClaimedOutbox,
    retry_delay: Duration,
) -> Result<bool, PersistenceError> {
    process_claim_with_health(
        store,
        adapter,
        claim,
        RetrySchedule::new(retry_delay, retry_delay),
    )
    .await
    .map(|(transitioned, _)| transitioned)
}

pub async fn process_claim_with_health(
    store: &OutboxStore,
    adapter: &dyn Adapter,
    claim: &ClaimedOutbox,
    retry_schedule: RetrySchedule,
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
    match adapter.execute_claimed_handoff(store, claim, &intent).await {
        Ok(result) => store
            .mark_handed_off(claim, &result)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::Available)),
        Err(HandoffFailure::Retryable(stage)) => {
            let delay = retry_schedule.delay_for(stage);
            store
                .mark_retryable(claim, delay, stage)
                .await
                .map(|transitioned| (transitioned, ProcessingHealth::Retryable(delay)))
        }
        Err(HandoffFailure::Permanent) => store
            .mark_permanently_failed(claim)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
    }
}

/// Reconciles one exact persisted SDK outbound event. Only durable `Sent`
/// acknowledges publication. Recoverable states remain `handed_off`; exact
/// `Invalid`, `RecoveryRequired`, or `Superseded` records become retained
/// permanent failures because the SDK will not claim those records again.
pub async fn process_reconciliation(
    store: &OutboxStore,
    adapter: &dyn Adapter,
    claim: &ClaimedHandoff,
    retry_delay: Duration,
) -> Result<bool, PersistenceError> {
    process_reconciliation_with_health(store, adapter, claim, retry_delay)
        .await
        .map(|(transitioned, _)| transitioned)
}

pub async fn process_reconciliation_with_health(
    store: &OutboxStore,
    adapter: &dyn Adapter,
    claim: &ClaimedHandoff,
    retry_delay: Duration,
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
        ))
        | Ok(None) => store
            .mark_reconciliation_permanently_failed(claim)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
        Ok(_) => store
            .retry_reconciliation(
                claim,
                retry_delay,
                RetryableHandoffStage::ReconciliationPending,
            )
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::Retryable(retry_delay))),
        Err(HandoffError::Retryable(_)) => store
            .retry_reconciliation(claim, retry_delay, RetryableHandoffStage::Reconciliation)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::Retryable(retry_delay))),
        Err(HandoffError::Permanent) => store
            .mark_reconciliation_permanently_failed(claim)
            .await
            .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
    }
}
