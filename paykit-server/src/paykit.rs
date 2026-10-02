//! Concrete per-Creator Paykit SDK boundary used by durable outbox workers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex, OnceLock, Weak},
};

use async_trait::async_trait;
use paykit_lib::{
    PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload, PaymentReference,
    PaymentRequestTerms,
};
use paykit_sdk::{
    LinkedPeerState, OutboundPrivateMessageStatus, OutboundPrivateSendReport,
    PAYKIT_SESSION_CAPABILITIES, PaykitSdk, PaykitSdkConfig, PaykitSdkError, PaymentAdapter,
    PubkyPublicKey, PubkySessionAccess, PubkySessionBootstrap, PubkySessionProvider,
    PubkySharedStateStorage, StorageAdapter,
};
use pubky::Pubky;
use tokio::sync::Mutex as TokioMutex;
use tracing::warn;
use uuid::Uuid;

use crate::{
    application::semantic_intent::{DeliveryIntentV1, PaymentTermsV1},
    config::PaykitConfig,
    domain::locks::CreatorPubky,
    persistence::CreatorStore,
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
    client_id: String,
    cache: Arc<TokioMutex<Option<CachedSession>>>,
}

impl CreatorSessionProvider {
    pub fn new(
        creators: CreatorStore,
        creator: CreatorPubky,
        config: &PaykitConfig,
    ) -> Result<Self, PaykitSdkError> {
        let public_client = Pubky::new().map_err(|error| PaykitSdkError::Identity {
            context: "could not construct Pubky client".into(),
            source: Some(anyhow::anyhow!(error.to_string())),
        })?;
        Ok(Self::with_pubky(creators, creator, public_client, config))
    }

    /// Uses the process-selected Pubky network for this Creator's restored session.
    pub fn with_pubky(
        creators: CreatorStore,
        creator: CreatorPubky,
        public_client: Pubky,
        config: &PaykitConfig,
    ) -> Self {
        Self {
            creators,
            creator,
            public_client,
            client_id: config.client_id.to_string(),
            cache: Arc::new(TokioMutex::new(None)),
        }
    }
}

#[async_trait]
impl PubkySessionProvider for CreatorSessionProvider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        let mut cache = self.cache.lock().await;
        let credentials = self
            .creators
            .load(&self.creator)
            .await
            .map_err(|error| match error {
                crate::persistence::PersistenceError::CorruptOrMissing => {
                    PaykitSdkError::Identity {
                        context: "creator credentials are missing or invalid".into(),
                        source: None,
                    }
                }
                _ => PaykitSdkError::Storage {
                    context: "creator credentials are unavailable".into(),
                    source: None,
                },
            })?;
        if let Some(cached) = cache.as_ref()
            && cached.session_secret.as_str() == credentials.session_secret()
            && cached.access.paykit_identity_secret_key.as_ref()
                == Some(credentials.paykit_identity_secret())
        {
            return Ok(Some(cached.access.clone()));
        }
        let bootstrap =
            PubkySessionBootstrap::with_pubky(self.public_client.clone(), &self.client_id)?;
        let mut access = bootstrap
            .import_session(
                credentials.session_secret(),
                None,
                PAYKIT_SESSION_CAPABILITIES,
            )
            .await?
            .access;
        access.paykit_identity_secret_key = Some(credentials.paykit_identity_secret().clone());
        bind_session_to_creator(access.public_key()?, &self.creator)?;
        access.validate_for_capabilities(PAYKIT_SESSION_CAPABILITIES)?;
        *cache = Some(CachedSession {
            session_secret: zeroize::Zeroizing::new(credentials.session_secret().to_owned()),
            access: access.clone(),
        });
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

struct CachedSession {
    session_secret: zeroize::Zeroizing<String>,
    access: PubkySessionAccess,
}

impl std::fmt::Debug for CachedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CachedSession(<redacted>)")
    }
}

/// Process-owned live providers, reused by workers and read-only status queries.
#[derive(Clone)]
pub struct CreatorSessions {
    creators: CreatorStore,
    pubky: Pubky,
    config: PaykitConfig,
    providers: Arc<StdMutex<HashMap<String, CreatorSessionProvider>>>,
}

impl CreatorSessions {
    pub fn new(creators: CreatorStore, pubky: Pubky, config: PaykitConfig) -> Self {
        Self {
            creators,
            pubky,
            config,
            providers: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    pub fn provider(&self, creator: &CreatorPubky) -> CreatorSessionProvider {
        let mut providers = self
            .providers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        providers
            .entry(creator.to_string())
            .or_insert_with(|| {
                CreatorSessionProvider::with_pubky(
                    self.creators.clone(),
                    creator.clone(),
                    self.pubky.clone(),
                    &self.config,
                )
            })
            .clone()
    }
}

#[async_trait]
impl crate::application::connection_status::PeerConnectionStateRepository for CreatorSessions {
    async fn connection_state(
        &self,
        creator: &CreatorPubky,
        binding: &crate::application::connection_status::ConnectionBinding,
    ) -> Result<
        crate::application::connection_status::PaykitConnectionState,
        crate::persistence::PersistenceError,
    > {
        use crate::application::connection_status::PaykitConnectionState;
        use crate::persistence::PersistenceError;
        let reader = PubkyPublicKey::from_raw_or_app_key(binding.reader().to_string())
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let storage = PubkySharedStateStorage::new(self.provider(creator));
        storage
            .transaction(move |tx| {
                let state = tx.export_storage_state();
                Ok(
                    match state.linked_peers.get(&reader).map(|peer| &peer.state) {
                        None | Some(LinkedPeerState::NotLinked) => PaykitConnectionState::None,
                        Some(LinkedPeerState::Linking) => PaykitConnectionState::Handshake,
                        Some(LinkedPeerState::Linked) => PaykitConnectionState::Connected,
                        Some(LinkedPeerState::RecoveryRequired) => {
                            PaykitConnectionState::RecoveryRequired
                        }
                        Some(LinkedPeerState::Blocked) => PaykitConnectionState::Blocked,
                        Some(_) => {
                            return Err(PaykitSdkError::Storage {
                                context: "unknown link state".into(),
                                source: None,
                            });
                        }
                    },
                )
            })
            .await
            .map_err(|_| PersistenceError::Unavailable)
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
    PaykitSdk<PubkySharedStateStorage, CreatorSessionProvider, ExplicitInputsPaymentAdapter>;

/// Public-SDK-only handoff implementation for one Creator.
pub struct PaykitAdapter {
    sdk: CreatorSdk,
    storage: PubkySharedStateStorage,
    mutation_lock: Arc<TokioMutex<()>>,
}

impl std::fmt::Debug for PaykitAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PaykitAdapter { .. }")
    }
}

impl PaykitAdapter {
    /// Persists the mixed private stream before the SDK sends confirmations.
    /// No request is claimed, accepted, or executed by the server.
    /// Contention returns `ConcurrentUpdate` for the next poll; other failures take precedence.
    pub async fn maintain_transport(&self) -> paykit_sdk::Result<()> {
        let _guard = self.mutation_lock.lock().await;
        let peers = self.sdk.linked_peers().await?;
        let mut results = Vec::new();
        for peer in peers
            .into_iter()
            .filter(|peer| peer.state == LinkedPeerState::Linked)
        {
            results.push(
                self.sdk
                    .receive_private_messages(peer.counterparty)
                    .await
                    .map(|_| ()),
            );
        }
        // A peer's receive failure must not prevent other peers' queued sends.
        match self.sdk.pending_outbound_private_counterparties().await {
            Ok(peers) => {
                for peer in peers {
                    results.push(
                        self.sdk
                            .process_outbound_private_messages(peer)
                            .await
                            .and_then(check_send_report),
                    );
                }
            }
            Err(error) => results.push(Err(error)),
        }
        check_transport_results(&results)
    }

    pub fn new(
        creator_id: Uuid,
        sessions: CreatorSessionProvider,
        config: &PaykitConfig,
    ) -> Result<Self, PaykitSdkError> {
        let storage = PubkySharedStateStorage::new(sessions.clone());
        let sdk = PaykitSdk::new(
            storage.clone(),
            sessions,
            ExplicitInputsPaymentAdapter,
            PaykitSdkConfig::new(config.app_id.as_str())?,
        );
        Ok(Self {
            sdk,
            mutation_lock: creator_mutation_lock(creator_id),
            storage,
        })
    }
}

fn check_send_report(report: OutboundPrivateSendReport) -> paykit_sdk::Result<()> {
    if !report.failed.is_empty()
        || !report.reservation_cleanup_failures.is_empty()
        || !report.recovery_marker_failures.is_empty()
    {
        return Err(PaykitSdkError::Transport {
            context: "private message maintenance failed".into(),
            source: None,
        });
    }
    Ok(())
}

fn check_transport_results(results: &[paykit_sdk::Result<()>]) -> paykit_sdk::Result<()> {
    let mut deferred = false;
    for result in results {
        if let Err(error) = result {
            if error.is_concurrent_update() {
                deferred = true;
            } else {
                return Err(PaykitSdkError::Transport {
                    context: "private message maintenance failed".into(),
                    source: None,
                });
            }
        }
    }
    if deferred {
        return Err(PaykitSdkError::ConcurrentUpdate {
            context: "private message maintenance deferred to another client".into(),
            source: None,
        });
    }
    Ok(())
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

fn parse_peer(reader: &str) -> Result<PubkyPublicKey, HandoffError> {
    PubkyPublicKey::from_raw_or_app_key(reader).map_err(|_| HandoffError::Permanent)
}

fn classify(error: PaykitSdkError) -> HandoffError {
    match error {
        PaykitSdkError::Protocol { .. } => HandoffError::Permanent,
        PaykitSdkError::Policy { .. } => HandoffError::Retryable(RetryableHandoffCause::Policy),
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
    PaymentRequestTerms::builder(
        amount,
        payment_reference,
        accepted_payment_endpoint_identifiers,
    )
    .proposal_expires_at(terms.proposal_expires_at.clone())
    .required_app_id(Some(
        paykit_lib::PaykitAppId::new(crate::config::PAYKIT_APP_ID)
            .map_err(|_| HandoffError::Permanent)?,
    ))
    .payment_endpoints(Some(
        terms
            .payment_endpoints
            .iter()
            .map(|(identifier, payload)| {
                Ok((
                    PaymentEndpointIdentifier::new(identifier.clone())
                        .map_err(|_| HandoffError::Permanent)?,
                    PaymentEndpointPayload::new(payload.clone()),
                ))
            })
            .collect::<Result<_, HandoffError>>()?,
    ))
    .metadata(terms.metadata.clone())
    .build()
    .map_err(|_| HandoffError::Permanent)
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

    async fn fetch_registry(
        &self,
        reader: &str,
    ) -> Result<Option<paykit_lib::PaykitAppRegistry>, HandoffError> {
        let reader = parse_peer(reader)?;
        self.sdk.paykit_app_registry(reader).await.map_err(classify)
    }

    async fn ensure_link_with_peer(&self, reader: &str) -> Result<(), HandoffError> {
        let reader = parse_peer(reader)?;
        let result = self
            .sdk
            .ensure_link_with_peer(reader, 1)
            .await
            .map_err(classify)
            .and_then(|report| require_linked(report.state));
        if let Err(error) = result {
            warn!(
                stage = "link_establishment",
                cause = error.diagnostic_label(),
                "Paykit handoff failed"
            );
        }
        result
    }

    async fn propose_payment_request(
        &self,
        reader: &str,
        terms: &PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        let reader = parse_peer(reader)?;
        let record = self
            .sdk
            .propose_payment_request(reader, payment_terms(terms)?)
            .await
            .map_err(classify)?;
        Ok(HandoffResult {
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
                    .find(|record| {
                        record.outbound_message_id == outbound_message_id
                            && record.app_id.as_str() == crate::config::PAYKIT_APP_ID
                    })
                    .map(|record| (record.status, record.counterparty)))
            })
            .await
            .map_err(classify)?;
        let Some((status, counterparty)) = outbound else {
            return Ok(None);
        };
        if terminal_outbound_status(&status) {
            return Ok(Some(status));
        }
        let report = self
            .sdk
            .ensure_link_with_peer(counterparty.clone(), 1)
            .await
            .map_err(classify)?;
        require_linked(report.state)?;
        let report = self
            .sdk
            .process_outbound_private_messages(counterparty)
            .await
            .map_err(classify)?;
        if report.sent.contains(&outbound_message_id) {
            return Ok(Some(OutboundPrivateMessageStatus::Sent));
        }
        self.storage
            .transaction(move |transaction| {
                Ok(transaction
                    .export_storage_state()
                    .outbound_private_messages
                    .into_iter()
                    .find(|record| {
                        record.outbound_message_id == outbound_message_id
                            && record.app_id.as_str() == crate::config::PAYKIT_APP_ID
                    })
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
        _ => Err(HandoffError::Retryable(RetryableHandoffCause::LinkPending)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paykit_sdk::{
        OutboundPrivateSendFailure, RecoveryMarkerPublishFailure, ReservationCleanupFailure,
    };

    const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

    #[test]
    fn transport_health_accepts_empty_and_successful_batches() {
        assert!(check_transport_results(&[]).is_ok());
        let sent = check_send_report(OutboundPrivateSendReport {
            attempted: vec![2],
            sent: vec![2],
            ..Default::default()
        });
        assert!(check_transport_results(&[Ok(()), sent]).is_ok());
        let deferred = Err(PaykitSdkError::ConcurrentUpdate {
            context: "peer operation owned by another app".into(),
            source: None,
        });
        assert!(
            check_transport_results(&[Ok(()), deferred])
                .unwrap_err()
                .is_concurrent_update()
        );
    }

    #[test]
    fn transport_health_rejects_peer_and_nested_send_failures_without_private_details() {
        let private_error = "private-peer-error";
        let mut failures = vec![
            Err(PaykitSdkError::Policy {
                context: private_error.into(),
                source: None,
            }),
            Err(PaykitSdkError::SharedStateBusy {
                context: private_error.into(),
                source: None,
            }),
            Err(PaykitSdkError::Transport {
                context: private_error.into(),
                source: None,
            }),
        ];
        for report in [
            OutboundPrivateSendReport {
                failed: vec![OutboundPrivateSendFailure {
                    outbound_message_id: 3,
                    error: private_error.into(),
                }],
                ..Default::default()
            },
            OutboundPrivateSendReport {
                reservation_cleanup_failures: vec![ReservationCleanupFailure {
                    reservation_id: Some("private-reservation".into()),
                    error: private_error.into(),
                }],
                ..Default::default()
            },
            OutboundPrivateSendReport {
                recovery_marker_failures: vec![RecoveryMarkerPublishFailure {
                    outbound_message_id: Some(3),
                    error: private_error.into(),
                }],
                ..Default::default()
            },
        ] {
            failures.push(check_send_report(report));
        }
        for failure in failures {
            let deferred = || {
                Err(PaykitSdkError::ConcurrentUpdate {
                    context: private_error.into(),
                    source: None,
                })
            };
            let error =
                check_transport_results(&[deferred(), failure, Ok(()), deferred()]).unwrap_err();
            assert!(matches!(
                error,
                PaykitSdkError::Transport { source: None, .. }
            ));
            assert!(!format!("{error:?}").contains(private_error));
            assert!(!error.to_string().contains(CREATOR));
        }
    }

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
            Err(HandoffError::Retryable(RetryableHandoffCause::LinkPending))
        );
        assert_eq!(
            require_linked(LinkedPeerState::RecoveryRequired),
            Err(HandoffError::Retryable(
                RetryableHandoffCause::RecoveryRequired
            ))
        );
    }

    #[test]
    fn handoff_diagnostic_causes_use_closed_secret_free_labels() {
        assert_eq!(RetryableHandoffCause::Storage.diagnostic_label(), "storage");
        assert_eq!(
            RetryableHandoffCause::Identity.diagnostic_label(),
            "identity"
        );
        assert_eq!(
            RetryableHandoffCause::Transport.diagnostic_label(),
            "transport"
        );
        assert_eq!(
            RetryableHandoffCause::NotFound.diagnostic_label(),
            "not_found"
        );
        assert_eq!(
            RetryableHandoffCause::PaymentAdapter.diagnostic_label(),
            "payment_adapter"
        );
        assert_eq!(
            RetryableHandoffCause::RecoveryRequired.diagnostic_label(),
            "recovery_required"
        );
        assert_eq!(RetryableHandoffCause::Policy.diagnostic_label(), "policy");
        assert_eq!(
            RetryableHandoffCause::LinkPending.diagnostic_label(),
            "link_pending"
        );
        assert_eq!(RetryableHandoffCause::Other.diagnostic_label(), "other");
    }

    #[test]
    fn invalid_protocol_input_is_permanent() {
        let error = PaykitSdkError::from(paykit_lib::PaykitError::Validation(
            "synthetic invalid input".into(),
        ));
        assert_eq!(classify(error), HandoffError::Permanent);
        assert_eq!(
            classify(PaykitSdkError::Protocol {
                context: "Private Application Message exceeds pubky-noise message size".into(),
                source: None,
            }),
            HandoffError::Permanent
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
            HandoffError::Retryable(RetryableHandoffCause::Policy)
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
