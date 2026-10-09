//! Semantic outbox handoff policy.
//!
//! A call can commit to the SDK queue and the process can crash before the
//! fenced database transition. The durable outbox UUID binds every retry to one
//! SDK Payment Request proposal with the original terms. Transport remains
//! **at-least-once**; the SDK owns its queue and encrypted-link retry state.

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
    LinkObservation,
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
            Self::LinkObservation => "link_observation",
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
        HandoffError::Retryable(RetryableHandoffCause::LinkPending) => {
            HandoffFailure::Retryable(RetryableHandoffStage::LinkPending)
        }
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
        if stage == RetryableHandoffStage::LinkPending {
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
        check_claim(Some((store, claim))).await?;
        self.execute_handoff(claim.id(), intent).await
    }

    /// Executes one complete semantic handoff. Concrete adapters may override
    /// this to serialize a multi-call SDK operation under one Creator lock.
    /// `outbox_id` must be the persisted UUID-v4 row ID, unchanged on every retry.
    async fn execute_handoff(
        &self,
        outbox_id: uuid::Uuid,
        intent: &DeliveryIntentV1,
    ) -> Result<HandoffResult, HandoffFailure> {
        handoff_steps(self, outbox_id, intent).await
    }

    async fn fetch_registry(&self, reader: &str)
    -> Result<Option<PaykitAppRegistry>, HandoffError>;
    /// The Reader's signed Noise Key Authorization, checked before link setup,
    /// which verifies it again.
    async fn fetch_authorization(&self, reader: &str) -> Result<ReaderAuthorization, HandoffError>;
    async fn ensure_link_with_peer(&self, reader: &str) -> Result<(), HandoffError>;
    /// Creates or recovers the proposal bound to the durable outbox row ID.
    /// Implementations must reject conflicting input and retain the original SDK IDs.
    async fn propose_payment_request(
        &self,
        reader: &str,
        payment_request_id: paykit_lib::PaymentRequestId,
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
/// The caller supplies the same durable UUID-v4 outbox row ID on every retry.
pub async fn handoff(
    adapter: &dyn Adapter,
    outbox_id: uuid::Uuid,
    intent: &DeliveryIntentV1,
) -> Result<HandoffResult, HandoffFailure> {
    adapter.execute_handoff(outbox_id, intent).await
}

pub(crate) async fn handoff_steps<A: Adapter + ?Sized>(
    adapter: &A,
    outbox_id: uuid::Uuid,
    intent: &DeliveryIntentV1,
) -> Result<HandoffResult, HandoffFailure> {
    handoff_steps_with_claim(adapter, outbox_id, intent, None).await
}

pub(crate) async fn claimed_handoff_steps<A: Adapter + ?Sized>(
    adapter: &A,
    intent: &DeliveryIntentV1,
    store: &OutboxStore,
    claim: &ClaimedOutbox,
) -> Result<HandoffResult, HandoffFailure> {
    handoff_steps_with_claim(adapter, claim.id(), intent, Some((store, claim))).await
}

async fn check_claim(claim: Option<(&OutboxStore, &ClaimedOutbox)>) -> Result<(), HandoffFailure> {
    if let Some((store, claim)) = claim {
        match store.claim_handoff_eligible(claim).await {
            Ok(true) => {}
            Ok(false) => return Err(HandoffFailure::Permanent),
            Err(_) => {
                return Err(HandoffFailure::Retryable(
                    RetryableHandoffStage::AdapterUnavailable,
                ));
            }
        }
    }
    Ok(())
}

async fn handoff_steps_with_claim<A: Adapter + ?Sized>(
    adapter: &A,
    outbox_id: uuid::Uuid,
    intent: &DeliveryIntentV1,
    claim: Option<(&OutboxStore, &ClaimedOutbox)>,
) -> Result<HandoffResult, HandoffFailure> {
    intent.validate().map_err(|_| HandoffFailure::Permanent)?;
    let payment_request_id = paykit_lib::PaymentRequestId::new(outbox_id.to_string())
        .map_err(|_| HandoffFailure::Permanent)?;
    check_claim(claim).await?;
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
    check_claim(claim).await?;
    adapter
        .ensure_link_with_peer(intent.reader_pubky())
        .await
        .map_err(|error| at_stage(error, RetryableHandoffStage::LinkEstablishment))?;
    check_claim(claim).await?;
    match intent.operation() {
        DeliveryOperationV1::PaymentRequestProposal { terms } => adapter
            .propose_payment_request(intent.reader_pubky(), payment_request_id, terms)
            .await
            .map_err(|error| at_stage(error, RetryableHandoffStage::PaymentRequestProposal)),
        DeliveryOperationV1::PaymentRequestCancellation { payment_request_id } => adapter
            .cancel_payment_request(intent.reader_pubky(), payment_request_id)
            .await
            .map_err(|error| at_stage(error, RetryableHandoffStage::PaymentRequestCancellation)),
    }
}

/// Renews an admitted handoff without cancelling its in-flight SDK work on lease loss.
/// Subsequent SDK effects and the final database transition must revalidate the claim.
pub async fn with_claim_renewal<F: std::future::Future>(
    store: &OutboxStore,
    claim: &ClaimedOutbox,
    lease: Duration,
    operation: F,
) -> F::Output {
    let renewal = async {
        loop {
            tokio::time::sleep((lease / 3).max(Duration::from_millis(1))).await;
            if !store.renew_claim(claim, lease).await? {
                return Ok::<(), PersistenceError>(());
            }
        }
    };
    tokio::pin!(operation);
    tokio::select! {
        biased;
        result = &mut operation => result,
        result = renewal => {
            tracing::warn!(storage_error = result.is_err(), "outbox claim renewal stopped; draining admitted work");
            operation.await
        }
    }
}

/// Executes one already-fenced claim. Enqueue is only `handed_off`; the SDK
/// outbound record is reconciled separately before publication is acknowledged.
/// A proposal retry after enqueue but before this fenced transition uses the
/// same outbox UUID and terms, recovering the original proposal.
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
    process_claim_with(store, claim, retry_schedule, |intent| async move {
        adapter.execute_claimed_handoff(store, claim, &intent).await
    })
    .await
}

pub(crate) async fn process_claim_with<F>(
    store: &OutboxStore,
    claim: &ClaimedOutbox,
    retry_schedule: RetrySchedule,
    execute: impl FnOnce(DeliveryIntentV1) -> F,
) -> Result<(bool, ProcessingHealth), PersistenceError>
where
    F: std::future::Future<Output = Result<HandoffResult, HandoffFailure>>,
{
    let intent = match store.delivery_intent(claim) {
        Ok(intent) => intent,
        Err(_) => {
            return store
                .mark_permanently_failed(claim)
                .await
                .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure));
        }
    };
    match execute(intent).await {
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
