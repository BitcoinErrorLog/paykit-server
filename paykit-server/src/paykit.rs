//! Concrete per-Creator Paykit SDK boundary used by durable outbox workers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex, OnceLock, Weak},
};

use async_trait::async_trait;
use paykit_lib::{
    PaykitReceiverPath, PaymentAmount, PaymentEndpointIdentifier, PaymentReference,
    PaymentRequestTerms,
};
use paykit_sdk::{
    LinkedPeerState, OutboundPrivateMessageStatus, PaykitSdk, PaykitSdkConfig, PaykitSdkError,
    PaymentAdapter, PrivateReceivingDetail, PubkyPublicKey, PubkySessionAccess,
    PubkySessionProvider, StorageAdapter,
};
use pubky::{Pubky, PubkySession};
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

use crate::{
    application::semantic_intent::{DeliveryIntentV1, PaymentTermsV1, ReceivingDetailV1},
    config::PaykitConfig,
    domain::locks::CreatorPubky,
    persistence::{CreatorStore, PostgresStorageAdapter},
    workers::outbox::{
        Adapter, HandoffError, HandoffFailure, HandoffResult, RetryableHandoffCause, handoff_steps,
    },
};

/// Creator-owned live Pubky access restored from encrypted server credentials.
#[derive(Clone, Debug)]
pub struct CreatorSessionProvider {
    creators: CreatorStore,
    creator: CreatorPubky,
    public_client: Pubky,
}

impl CreatorSessionProvider {
    pub fn new(creators: CreatorStore, creator: CreatorPubky) -> Result<Self, PaykitSdkError> {
        let public_client = Pubky::new().map_err(|error| PaykitSdkError::Identity {
            context: "could not construct Pubky client".into(),
            source: Some(anyhow::anyhow!(error.to_string())),
        })?;
        Ok(Self::with_pubky(creators, creator, public_client))
    }

    /// Uses the process-selected Pubky network for this Creator's restored session.
    pub fn with_pubky(creators: CreatorStore, creator: CreatorPubky, public_client: Pubky) -> Self {
        Self {
            creators,
            creator,
            public_client,
        }
    }
}

#[async_trait]
impl PubkySessionProvider for CreatorSessionProvider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        let credentials =
            self.creators
                .load(&self.creator)
                .await
                .map_err(|_| PaykitSdkError::Storage {
                    context: "creator credentials are unavailable".into(),
                    source: None,
                })?;
        let session = PubkySession::import_secret(
            credentials.session_secret(),
            Some(self.public_client.client().clone()),
        )
        .await
        .map_err(|error| PaykitSdkError::Identity {
            context: "creator Pubky session is unavailable".into(),
            source: Some(anyhow::anyhow!(error.to_string())),
        })?;
        let access = PubkySessionAccess {
            session,
            outbox_client: self.public_client.clone(),
            local_secret_key: None,
            receiver_noise_secret_key: credentials.receiver_noise_secret().clone(),
        };
        bind_session_to_creator(access.public_key()?, &self.creator)?;
        access.validate()?;
        Ok(Some(access))
    }

    async fn load_public_storage(&self) -> paykit_sdk::Result<Option<pubky::PublicStorage>> {
        Ok(Some(self.public_client.public_storage()))
    }

    async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
        Err(PaykitSdkError::Policy {
            context: "server-managed Creator sessions must be replaced through reauthentication"
                .into(),
            source: None,
        })
    }
}

fn bind_session_to_creator(
    actual: PubkyPublicKey,
    expected_creator: &CreatorPubky,
) -> paykit_sdk::Result<()> {
    let expected = PubkyPublicKey::from_raw_or_app_key(expected_creator.to_string())?;
    if actual != expected {
        return Err(PaykitSdkError::Identity {
            context: "restored Pubky session does not match Creator".into(),
            source: None,
        });
    }
    Ok(())
}

/// Minimal adapter required to construct the SDK for explicit server-owned handoff inputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExplicitInputsPaymentAdapter;

impl PaymentAdapter for ExplicitInputsPaymentAdapter {}

type CreatorSdk =
    PaykitSdk<PostgresStorageAdapter, CreatorSessionProvider, ExplicitInputsPaymentAdapter>;

/// Public-SDK-only handoff implementation for one Creator.
pub struct PaykitAdapter {
    sdk: CreatorSdk,
    storage: PostgresStorageAdapter,
    mutation_lock: Arc<TokioMutex<()>>,
}

impl std::fmt::Debug for PaykitAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PaykitAdapter { .. }")
    }
}

impl PaykitAdapter {
    pub fn new(
        storage: PostgresStorageAdapter,
        sessions: CreatorSessionProvider,
        config: &PaykitConfig,
    ) -> Result<Self, PaykitSdkError> {
        let sdk = PaykitSdk::new(
            storage.clone(),
            sessions,
            ExplicitInputsPaymentAdapter,
            PaykitSdkConfig::new(config.receiver_path.clone()),
        )?;
        Ok(Self {
            sdk,
            mutation_lock: creator_mutation_lock(storage.creator_id()),
            storage,
        })
    }
}

type CreatorMutationLock = TokioMutex<()>;

fn creator_mutation_lock(creator_id: Uuid) -> Arc<CreatorMutationLock> {
    static LOCKS: OnceLock<StdMutex<HashMap<Uuid, Weak<CreatorMutationLock>>>> = OnceLock::new();
    let registry = LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut registry = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = registry.get(&creator_id).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(TokioMutex::new(()));
    registry.insert(creator_id, Arc::downgrade(&lock));
    lock
}

fn parse_peer(
    reader: &str,
    path: &str,
) -> Result<(PubkyPublicKey, PaykitReceiverPath), HandoffError> {
    let reader =
        PubkyPublicKey::from_raw_or_app_key(reader).map_err(|_| HandoffError::Permanent)?;
    let path = PaykitReceiverPath::new(path.to_owned()).map_err(|_| HandoffError::Permanent)?;
    Ok((reader, path))
}

fn classify(error: PaykitSdkError) -> HandoffError {
    match error {
        PaykitSdkError::Protocol { .. } => HandoffError::Permanent,
        PaykitSdkError::Policy { .. } => HandoffError::Retryable(RetryableHandoffCause::Other),
        PaykitSdkError::Storage { .. } => HandoffError::Retryable(RetryableHandoffCause::Storage),
        PaykitSdkError::Identity { .. } => HandoffError::Retryable(RetryableHandoffCause::Identity),
        PaykitSdkError::Transport { .. } => {
            HandoffError::Retryable(RetryableHandoffCause::Transport)
        }
        PaykitSdkError::NotFound { .. } => HandoffError::Retryable(RetryableHandoffCause::NotFound),
        PaykitSdkError::PaymentAdapter { .. } => {
            HandoffError::Retryable(RetryableHandoffCause::PaymentAdapter)
        }
        PaykitSdkError::RecoveryRequired { .. } => {
            HandoffError::Retryable(RetryableHandoffCause::RecoveryRequired)
        }
        _ => HandoffError::Retryable(RetryableHandoffCause::Other),
    }
}

fn payment_terms(terms: &PaymentTermsV1) -> Result<PaymentRequestTerms, HandoffError> {
    let amount = PaymentAmount::new(terms.amount.clone(), terms.asset.clone())
        .map_err(|_| HandoffError::Permanent)?;
    let payment_reference = PaymentReference::new(terms.payment_reference.clone())
        .map_err(|_| HandoffError::Permanent)?;
    let accepted_payment_endpoint_identifiers = terms
        .accepted_endpoint_identifiers
        .iter()
        .cloned()
        .map(PaymentEndpointIdentifier::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| HandoffError::Permanent)?;
    Ok(PaymentRequestTerms {
        amount,
        payment_reference,
        proposal_expires_at: terms.proposal_expires_at.clone(),
        recurrence: None,
        accepted_payment_endpoint_identifiers,
        metadata: terms.metadata.clone(),
    })
}

#[async_trait]
impl Adapter for PaykitAdapter {
    async fn execute_handoff(
        &self,
        intent: &DeliveryIntentV1,
    ) -> Result<HandoffResult, HandoffFailure> {
        let _guard = self.mutation_lock.lock().await;
        handoff_steps(self, intent).await
    }

    async fn fetch_marker(
        &self,
        reader: &str,
        path: &str,
    ) -> Result<Option<paykit_lib::PaykitReceiverMarker>, HandoffError> {
        let (reader, path) = parse_peer(reader, path)?;
        self.sdk
            .paykit_receiver_marker(reader, path)
            .await
            .map_err(classify)
    }

    async fn ensure_link_with_peer(&self, reader: &str, path: &str) -> Result<(), HandoffError> {
        let (reader, path) = parse_peer(reader, path)?;
        self.sdk
            .ensure_link_with_peer(reader, path, 1)
            .await
            .map_err(classify)
            .and_then(|report| require_linked(report.state))
    }

    async fn enqueue_private_payment_list_with_receiving_details(
        &self,
        reader: &str,
        path: &str,
        details: &[ReceivingDetailV1],
    ) -> Result<HandoffResult, HandoffError> {
        let (reader, path) = parse_peer(reader, path)?;
        let details = details
            .iter()
            .map(|detail| PrivateReceivingDetail {
                identifier: detail.identifier.clone(),
                payload: detail.payload.clone(),
            })
            .collect();
        let record = self
            .sdk
            .enqueue_private_payment_list_with_receiving_details(reader, path, details)
            .await
            .map_err(classify)?;
        Ok(HandoffResult::EndpointPublication {
            outbound_message_id: record.outbound_message_id,
        })
    }

    async fn propose_payment_request(
        &self,
        reader: &str,
        path: &str,
        terms: &PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        let (reader, path) = parse_peer(reader, path)?;
        let record = self
            .sdk
            .propose_payment_request(reader, path, payment_terms(terms)?)
            .await
            .map_err(classify)?;
        Ok(HandoffResult::PaymentRequestProposal {
            outbound_message_id: record
                .proposal_outbound_message_id
                .ok_or(HandoffError::Permanent)?,
            event_id: record.proposal_event_id.ok_or(HandoffError::Permanent)?,
            payment_request_id: record.payment_request_id,
        })
    }

    async fn outbound_status(
        &self,
        outbound_message_id: u64,
    ) -> Result<Option<OutboundPrivateMessageStatus>, HandoffError> {
        let _guard = self.mutation_lock.lock().await;
        let outbound = self
            .storage
            .transaction(move |transaction| {
                Ok(transaction
                    .export_storage_state()
                    .outbound_private_messages
                    .into_iter()
                    .find(|record| record.outbound_message_id == outbound_message_id)
                    .map(|record| {
                        (
                            record.status,
                            record.counterparty,
                            record.counterparty_receiver_path,
                        )
                    }))
            })
            .await
            .map_err(classify)?;
        let Some((status, counterparty, counterparty_receiver_path)) = outbound else {
            return Ok(None);
        };
        if terminal_outbound_status(&status) {
            return Ok(Some(status));
        }
        let report = self
            .sdk
            .ensure_link_with_peer(counterparty.clone(), counterparty_receiver_path.clone(), 1)
            .await
            .map_err(classify)?;
        require_linked(report.state)?;
        self.sdk
            .process_outbound_private_messages(counterparty, counterparty_receiver_path)
            .await
            .map_err(classify)?;
        self.storage
            .transaction(move |transaction| {
                Ok(transaction
                    .export_storage_state()
                    .outbound_private_messages
                    .into_iter()
                    .find(|record| record.outbound_message_id == outbound_message_id)
                    .map(|record| record.status))
            })
            .await
            .map_err(classify)
    }
}

fn terminal_outbound_status(status: &OutboundPrivateMessageStatus) -> bool {
    matches!(
        status,
        OutboundPrivateMessageStatus::Sent
            | OutboundPrivateMessageStatus::Invalid
            | OutboundPrivateMessageStatus::RecoveryRequired
            | OutboundPrivateMessageStatus::Superseded
    )
}

fn require_linked(state: LinkedPeerState) -> Result<(), HandoffError> {
    match state {
        LinkedPeerState::Linked => Ok(()),
        LinkedPeerState::RecoveryRequired => Err(HandoffError::Retryable(
            RetryableHandoffCause::RecoveryRequired,
        )),
        _ => Err(HandoffError::Retryable(RetryableHandoffCause::Other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

    #[test]
    fn mutation_locks_are_shared_per_creator_and_isolated_between_creators() {
        let creator = Uuid::new_v4();
        let same_creator_first = creator_mutation_lock(creator);
        let same_creator_second = creator_mutation_lock(creator);
        let other_creator = creator_mutation_lock(Uuid::new_v4());

        assert!(Arc::ptr_eq(&same_creator_first, &same_creator_second));
        assert!(!Arc::ptr_eq(&same_creator_first, &other_creator));
    }

    #[test]
    fn incomplete_link_state_is_not_handoff_ready() {
        assert_eq!(require_linked(LinkedPeerState::Linked), Ok(()));
        assert_eq!(
            require_linked(LinkedPeerState::Linking),
            Err(HandoffError::Retryable(RetryableHandoffCause::Other))
        );
        assert_eq!(
            require_linked(LinkedPeerState::RecoveryRequired),
            Err(HandoffError::Retryable(
                RetryableHandoffCause::RecoveryRequired
            ))
        );
    }

    #[test]
    fn sdk_policy_errors_remain_retryable_because_they_include_lease_contention() {
        let error = PaykitSdkError::Policy {
            context: "peer link operation already in progress".into(),
            source: None,
        };

        assert_eq!(
            classify(error),
            HandoffError::Retryable(RetryableHandoffCause::Other)
        );
    }

    #[test]
    fn terminal_outbound_status_does_not_require_peer_processing() {
        for status in [
            OutboundPrivateMessageStatus::Sent,
            OutboundPrivateMessageStatus::Invalid,
            OutboundPrivateMessageStatus::RecoveryRequired,
            OutboundPrivateMessageStatus::Superseded,
        ] {
            assert!(terminal_outbound_status(&status));
        }
        for status in [
            OutboundPrivateMessageStatus::Pending,
            OutboundPrivateMessageStatus::Sending,
            OutboundPrivateMessageStatus::Failed,
        ] {
            assert!(!terminal_outbound_status(&status));
        }
    }

    #[test]
    fn restored_session_identity_must_match_selected_creator() {
        let expected = crate::domain::locks::parse_creator(CREATOR).unwrap();
        let expected_key = PubkyPublicKey::from_raw_or_app_key(CREATOR).unwrap();
        let actual = "ybndrfg8ejkmcpqxot1uwisza345h769"
            .chars()
            .find_map(|replacement| {
                let mut candidate = CREATOR.to_owned();
                candidate.replace_range(5..6, &replacement.to_string());
                PubkyPublicKey::from_raw_or_app_key(&candidate)
                    .ok()
                    .filter(|candidate| candidate != &expected_key)
            })
            .expect("valid second Pubky fixture");

        assert!(matches!(
            bind_session_to_creator(actual, &expected),
            Err(PaykitSdkError::Identity { .. })
        ));
    }
}
