//! Concrete per-Creator Paykit SDK boundary used by durable outbox workers.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex as StdMutex, OnceLock, Weak},
};

use async_trait::async_trait;
use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentDeadline, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestId, PaymentRequestTerms,
};
use paykit_sdk::{
    LinkedPeerState, OutboundPrivateMessageStatus, OutboundPrivateSendReport,
    PAYKIT_SESSION_CAPABILITIES, PaykitSdk, PaykitSdkConfig, PaykitSdkError, PaymentAdapter,
    PaymentRequestLifecycleState as SdkPaymentRequestLifecycleState, PaymentRequestLocalRole,
    PaymentRequestRecord, PrivateStreamCounterpartyIntakeReport, PubkyPublicKey,
    PubkySessionAccess, PubkySessionBootstrap, PubkySessionProvider, PubkySharedStateStorage,
    StorageAdapter,
};
use pubky::Pubky;
use tokio::sync::Mutex as TokioMutex;
use tracing::warn;
use uuid::Uuid;

use crate::{
    application::{
        payment_drain::{PaymentDrainError, PaymentDrainResult},
        payment_request_status::{PaymentRequestStatusError, PaymentRequestStatusSummary},
        semantic_intent::{DeliveryIntentV1, PaymentTermsV1},
    },
    config::PaykitConfig,
    domain::{
        locks::{BundleId, CreatorPubky, PubkyLockResource},
        payment_request_lifecycle::{
            PaymentRequestLifecycleProjection,
            PaymentRequestLifecycleState as PersistedPaymentRequestLifecycleState,
            ProposalCorrelation,
        },
    },
    persistence::{
        ClaimedOutbox, CreatorStore, InvoiceStore, OutboxStore, PaymentDrainStore,
        PaymentRequestLifecycleStore, PersistenceError, RequiredReceiveTarget,
    },
    workers::outbox::{
        Adapter, HandoffError, HandoffFailure, HandoffResult, RetryableHandoffCause,
        RetryableHandoffStage, handoff_steps,
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
    creator_id: Uuid,
    creator: CreatorPubky,
    app_id: PaykitAppId,
    mutation_lock: Arc<TokioMutex<()>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleSyncError {
    Sdk,
    Persistence,
    Conflict,
    InvalidProjection,
    PartialReceive,
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
        let creator = sessions.creator.clone();
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
            creator_id,
            creator,
            app_id: config.app_id.clone(),
        })
    }

    /// Receives linked-peer messages and durably projects the SDK's canonical
    /// lifecycle view while serializing Creator-local SDK mutations.
    pub async fn receive_and_project_payment_requests(
        &self,
        lifecycles: &PaymentRequestLifecycleStore,
    ) -> Result<(), LifecycleSyncError> {
        let _guard = self.mutation_lock.lock().await;
        self.refresh_payment_requests_locked(lifecycles, None).await
    }

    async fn refresh_payment_requests_locked(
        &self,
        lifecycles: &PaymentRequestLifecycleStore,
        required_targets: Option<&[ReceiveTarget]>,
    ) -> Result<(), LifecycleSyncError> {
        let reports = self.sdk.receive_private_messages_from_linked_peers().await;
        let receive_health =
            receive_health_from_reports(reports.as_deref().map_err(|_| ()), required_targets);
        let records = self
            .sdk
            .payment_requests()
            .await
            .map_err(|_| LifecycleSyncError::Sdk)?;
        let projections = lifecycle_projections(&records, &self.app_id);
        let creator_id = self.creator_id;
        project_lifecycles_after_receive(projections, receive_health, |projection| async move {
            lifecycles
                .apply(creator_id, &projection)
                .await
                .map_err(map_projection_persistence_error)?;
            Ok(())
        })
        .await
    }

    /// Receives and projects fresh canonical state before returning status, all
    /// under the same Creator-local mutation fence.
    pub async fn reconcile_and_lookup_payment_request_status(
        &self,
        lifecycles: &PaymentRequestLifecycleStore,
        statuses: &InvoiceStore,
        bundle_id: &BundleId,
    ) -> Result<Option<PaymentRequestStatusSummary>, PaymentRequestStatusError> {
        let _guard = self.mutation_lock.lock().await;
        let required_targets = lifecycles
            .required_receive_targets_for_bundle(self.creator_id, bundle_id)
            .await
            .map_err(|error| {
                crate::diagnostics::failure(
                    "payment_request_status",
                    "receive_targets_load",
                    error.diagnostic_label(),
                );
                PaymentRequestStatusError::Unavailable
            })?;
        let parsed_targets = parse_receive_targets(&required_targets).map_err(|error| {
            let mapped = map_lifecycle_status_error(error);
            crate::diagnostics::failure(
                "payment_request_status",
                "receive_targets_parse",
                mapped.diagnostic_label(),
            );
            mapped
        })?;
        refresh_then(
            || async {
                self.refresh_payment_requests_locked(lifecycles, Some(&parsed_targets))
                    .await
                    .map_err(|error| {
                        let mapped = map_lifecycle_status_error(error);
                        crate::diagnostics::failure(
                            "payment_request_status",
                            "paykit_reconciliation",
                            mapped.diagnostic_label(),
                        );
                        mapped
                    })
            },
            || async {
                statuses
                    .payment_request_status_after_receive(
                        lifecycles,
                        &self.creator,
                        bundle_id,
                        &required_targets,
                    )
                    .await
                    .map_err(|error| {
                        crate::diagnostics::failure(
                            "payment_request_status",
                            "status_projection_load",
                            error.diagnostic_label(),
                        );
                        PaymentRequestStatusError::Unavailable
                    })
            },
        )
        .await
    }

    /// Reconciles receive and the canonical SDK reducer before atomically
    /// snapshotting one lock's drain under the same Creator-local mutation lock.
    pub async fn reconcile_and_create_payment_drain(
        &self,
        lifecycles: &PaymentRequestLifecycleStore,
        drains: &PaymentDrainStore,
        lock_resource: &PubkyLockResource,
    ) -> Result<PaymentDrainResult, PaymentDrainError> {
        if lock_resource.creator() != &self.creator {
            return Err(PaymentDrainError::CreatorMismatch);
        }
        let _guard = self.mutation_lock.lock().await;
        if let Some(replay) = drains
            .exact_replay(lock_resource)
            .await
            .map_err(map_drain_persistence_error)?
        {
            return Ok(replay);
        }
        let required_targets = lifecycles
            .required_receive_targets_for_lock(self.creator_id, lock_resource)
            .await
            .map_err(map_projection_persistence_error)
            .map_err(map_lifecycle_drain_error)?;
        let parsed_targets =
            parse_receive_targets(&required_targets).map_err(map_lifecycle_drain_error)?;
        self.refresh_payment_requests_locked(lifecycles, Some(&parsed_targets))
            .await
            .map_err(map_lifecycle_drain_error)?;
        drains
            .create_after_receive(lifecycles, lock_resource, &required_targets)
            .await
            .map_err(map_drain_persistence_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiveHealth {
    Available,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiveTarget {
    counterparty: PubkyPublicKey,
}

fn parse_receive_targets(
    targets: &[RequiredReceiveTarget],
) -> Result<Vec<ReceiveTarget>, LifecycleSyncError> {
    targets
        .iter()
        .map(|target| {
            Ok(ReceiveTarget {
                counterparty: PubkyPublicKey::from_raw_or_app_key(target.counterparty())
                    .map_err(|_| LifecycleSyncError::InvalidProjection)?,
            })
        })
        .collect()
}

fn receive_health_for_required_targets(
    reports: &[PrivateStreamCounterpartyIntakeReport],
    required_targets: &[ReceiveTarget],
) -> ReceiveHealth {
    if required_targets.iter().all(|required| {
        let matching = || {
            reports
                .iter()
                .filter(|report| report.counterparty == required.counterparty)
        };
        matching().all(|report| report.error.is_none())
            && matching().any(|report| report.report.is_some() && report.error.is_none())
    }) {
        ReceiveHealth::Available
    } else {
        ReceiveHealth::Unavailable
    }
}

fn receive_health_from_reports<E>(
    reports: Result<&[PrivateStreamCounterpartyIntakeReport], E>,
    required_targets: Option<&[ReceiveTarget]>,
) -> ReceiveHealth {
    match required_targets {
        Some([]) => ReceiveHealth::Available,
        Some(required) => reports.map_or(ReceiveHealth::Unavailable, |reports| {
            receive_health_for_required_targets(reports, required)
        }),
        None => reports.map_or(ReceiveHealth::Unavailable, |reports| {
            if reports.iter().all(|report| report.error.is_none()) {
                ReceiveHealth::Available
            } else {
                ReceiveHealth::Unavailable
            }
        }),
    }
}

async fn project_lifecycles_after_receive<F, Fut>(
    projections: Vec<Result<PaymentRequestLifecycleProjection, LifecycleSyncError>>,
    receive_health: ReceiveHealth,
    mut persist: F,
) -> Result<(), LifecycleSyncError>
where
    F: FnMut(PaymentRequestLifecycleProjection) -> Fut,
    Fut: Future<Output = Result<(), LifecycleSyncError>>,
{
    let mut first_error = None;
    for projection in projections {
        match projection {
            Ok(projection) => {
                if let Err(error) = persist(projection).await {
                    first_error.get_or_insert(error);
                }
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    if receive_health == ReceiveHealth::Unavailable {
        return Err(LifecycleSyncError::PartialReceive);
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
async fn replay_or_refresh_then<
    T,
    E,
    Replay,
    ReplayFuture,
    Refresh,
    RefreshFuture,
    Operation,
    OperationFuture,
>(
    replay: Replay,
    refresh: Refresh,
    operation: Operation,
) -> Result<T, E>
where
    Replay: FnOnce() -> ReplayFuture,
    ReplayFuture: Future<Output = Result<Option<T>, E>>,
    Refresh: FnOnce() -> RefreshFuture,
    RefreshFuture: Future<Output = Result<(), E>>,
    Operation: FnOnce() -> OperationFuture,
    OperationFuture: Future<Output = Result<T, E>>,
{
    if let Some(replay) = replay().await? {
        return Ok(replay);
    }
    refresh_then(refresh, operation).await
}

async fn refresh_then<T, E, Refresh, RefreshFuture, Operation, OperationFuture>(
    refresh: Refresh,
    operation: Operation,
) -> Result<T, E>
where
    Refresh: FnOnce() -> RefreshFuture,
    RefreshFuture: Future<Output = Result<(), E>>,
    Operation: FnOnce() -> OperationFuture,
    OperationFuture: Future<Output = Result<T, E>>,
{
    refresh().await?;
    operation().await
}

fn map_projection_persistence_error(error: PersistenceError) -> LifecycleSyncError {
    match error {
        PersistenceError::Conflict => LifecycleSyncError::Conflict,
        _ => LifecycleSyncError::Persistence,
    }
}

fn map_lifecycle_drain_error(error: LifecycleSyncError) -> PaymentDrainError {
    match error {
        LifecycleSyncError::Conflict => PaymentDrainError::Conflict,
        LifecycleSyncError::Sdk
        | LifecycleSyncError::Persistence
        | LifecycleSyncError::InvalidProjection
        | LifecycleSyncError::PartialReceive => PaymentDrainError::Unavailable,
    }
}

fn map_lifecycle_status_error(error: LifecycleSyncError) -> PaymentRequestStatusError {
    match error {
        LifecycleSyncError::Conflict => PaymentRequestStatusError::Conflict,
        LifecycleSyncError::Sdk
        | LifecycleSyncError::Persistence
        | LifecycleSyncError::InvalidProjection
        | LifecycleSyncError::PartialReceive => PaymentRequestStatusError::Unavailable,
    }
}

fn map_drain_persistence_error(error: PersistenceError) -> PaymentDrainError {
    match error {
        PersistenceError::Conflict => PaymentDrainError::Conflict,
        _ => PaymentDrainError::Unavailable,
    }
}

fn recovery_state_event_id<'a>(
    canceled_event_id: Option<&'a str>,
    rejected_event_id: Option<&'a str>,
    latest_payment_proof_event_id: Option<&'a str>,
    accepted_event_id: Option<&'a str>,
    proposal_event_id: Option<&'a str>,
) -> Option<&'a str> {
    canceled_event_id
        .or(rejected_event_id)
        .or(latest_payment_proof_event_id)
        .or(accepted_event_id)
        .or(proposal_event_id)
}

fn lifecycle_projection(
    record: &PaymentRequestRecord,
) -> Result<PaymentRequestLifecycleProjection, LifecycleSyncError> {
    if record.local_role != Some(PaymentRequestLocalRole::Payee) {
        return Err(LifecycleSyncError::InvalidProjection);
    }
    let terms = record
        .terms
        .as_ref()
        .filter(|terms| terms.recurrence.is_none())
        .ok_or(LifecycleSyncError::InvalidProjection)?;
    let request_state = persisted_lifecycle_state(record.state)?;
    let state_event_id = match record.state {
        SdkPaymentRequestLifecycleState::Proposed
        | SdkPaymentRequestLifecycleState::ProposalExpired => record.proposal_event_id.clone(),
        SdkPaymentRequestLifecycleState::Accepted
        | SdkPaymentRequestLifecycleState::ActiveRecurring => record.accepted_event_id.clone(),
        SdkPaymentRequestLifecycleState::Rejected => record.rejected_event_id.clone(),
        SdkPaymentRequestLifecycleState::Canceled => record.canceled_event_id.clone(),
        SdkPaymentRequestLifecycleState::ProofSubmitted => record
            .payment_proofs
            .last()
            .map(|proof| proof.event_id.clone()),
        SdkPaymentRequestLifecycleState::RecoveryRequired => recovery_state_event_id(
            record.canceled_event_id.as_deref(),
            record.rejected_event_id.as_deref(),
            record
                .payment_proofs
                .last()
                .map(|proof| proof.event_id.as_str()),
            record.accepted_event_id.as_deref(),
            record.proposal_event_id.as_deref(),
        )
        .map(str::to_owned),
        SdkPaymentRequestLifecycleState::InvalidConflict => record
            .canceled_event_id
            .clone()
            .or_else(|| record.rejected_event_id.clone())
            .or_else(|| record.accepted_event_id.clone())
            .or_else(|| record.proposal_event_id.clone()),
        _ => return Err(LifecycleSyncError::InvalidProjection),
    };
    let last_event_at = record
        .last_event_at
        .ok_or(LifecycleSyncError::InvalidProjection)?;
    let seconds = i128::from(last_event_at.timestamp());
    let nanos = i128::from(last_event_at.timestamp_subsec_nanos());
    let timestamp_nanos = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(LifecycleSyncError::InvalidProjection)?;
    let last_event_at = time::OffsetDateTime::from_unix_timestamp_nanos(timestamp_nanos)
        .map_err(|_| LifecycleSyncError::InvalidProjection)?;
    Ok(PaymentRequestLifecycleProjection {
        payment_request_id: record.payment_request_id.clone(),
        proposal: ProposalCorrelation {
            reader_pubky: format!("pubky{}", record.counterparty),
            proposal_app_id: record
                .proposal_app_id
                .as_ref()
                .ok_or(LifecycleSyncError::InvalidProjection)?
                .to_string(),
            terms: PaymentTermsV1 {
                amount: terms.amount.value.clone(),
                asset: terms.amount.asset.clone(),
                payment_reference: terms.payment_reference.clone(),
                proposal_expires_at: terms.proposal_expires_at.clone(),
                payment_deadline: terms
                    .payment_deadline
                    .as_ref()
                    .map(|deadline| deadline.at(None))
                    .transpose()
                    .map_err(|_| LifecycleSyncError::InvalidProjection)?,
                accepted_endpoint_identifiers: terms.accepted_payment_endpoint_identifiers.clone(),
                payment_endpoints: terms
                    .payment_endpoints
                    .as_ref()
                    .ok_or(LifecycleSyncError::InvalidProjection)?
                    .iter()
                    .map(|(identifier, payload)| (identifier.clone(), payload.clone()))
                    .collect(),
                metadata: terms.metadata.clone(),
            },
        },
        request_state,
        state_event_id,
        last_stream_item_id: record.last_stream_item_id,
        last_outbound_message_id: record.last_outbound_message_id,
        last_event_at,
    })
}

fn lifecycle_projections(
    records: &[PaymentRequestRecord],
    app_id: &PaykitAppId,
) -> Vec<Result<PaymentRequestLifecycleProjection, LifecycleSyncError>> {
    records
        .iter()
        .filter(|record| record.local_role != Some(PaymentRequestLocalRole::Payer))
        .filter(|record| {
            record
                .proposal_app_id
                .as_ref()
                .is_none_or(|proposal_app_id| proposal_app_id == app_id)
        })
        .map(lifecycle_projection)
        .collect()
}

fn persisted_lifecycle_state(
    state: SdkPaymentRequestLifecycleState,
) -> Result<PersistedPaymentRequestLifecycleState, LifecycleSyncError> {
    match state {
        SdkPaymentRequestLifecycleState::Proposed => {
            Ok(PersistedPaymentRequestLifecycleState::Proposed)
        }
        SdkPaymentRequestLifecycleState::ProposalExpired => {
            Ok(PersistedPaymentRequestLifecycleState::ProposalExpired)
        }
        SdkPaymentRequestLifecycleState::Accepted => {
            Ok(PersistedPaymentRequestLifecycleState::Accepted)
        }
        SdkPaymentRequestLifecycleState::Rejected => {
            Ok(PersistedPaymentRequestLifecycleState::Rejected)
        }
        SdkPaymentRequestLifecycleState::Canceled => {
            Ok(PersistedPaymentRequestLifecycleState::Canceled)
        }
        SdkPaymentRequestLifecycleState::ProofSubmitted => {
            Ok(PersistedPaymentRequestLifecycleState::ProofSubmitted)
        }
        SdkPaymentRequestLifecycleState::ActiveRecurring => {
            Ok(PersistedPaymentRequestLifecycleState::ActiveRecurring)
        }
        SdkPaymentRequestLifecycleState::RecoveryRequired => {
            Ok(PersistedPaymentRequestLifecycleState::RecoveryRequired)
        }
        SdkPaymentRequestLifecycleState::InvalidConflict => {
            Ok(PersistedPaymentRequestLifecycleState::InvalidConflict)
        }
        _ => Err(LifecycleSyncError::InvalidProjection),
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

fn retryable_recovery_observation(error: HandoffError) -> HandoffError {
    match error {
        HandoffError::Retryable(cause) => HandoffError::Retryable(cause),
        HandoffError::Permanent => HandoffError::Retryable(RetryableHandoffCause::Other),
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
    .payment_deadline(
        terms
            .payment_deadline
            .clone()
            .map(|timestamp| PaymentDeadline::At { timestamp }),
    )
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
    async fn execute_claimed_handoff(
        &self,
        store: &OutboxStore,
        claim: &ClaimedOutbox,
        intent: &DeliveryIntentV1,
    ) -> Result<HandoffResult, HandoffFailure> {
        let _guard = self.mutation_lock.lock().await;
        match store.claim_handoff_eligible(claim).await {
            Ok(true) => handoff_steps(self, intent).await,
            Ok(false) => Err(HandoffFailure::Permanent),
            Err(_) => Err(HandoffFailure::Retryable(
                RetryableHandoffStage::AdapterUnavailable,
            )),
        }
    }

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

    async fn observe_recovery_marker(&self, reader: &str) -> Result<(), HandoffError> {
        let reader = parse_peer(reader)?;
        self.sdk
            .observe_encrypted_link_recovery_marker(reader)
            .await
            .map(|_| ())
            .map_err(classify)
            .map_err(retryable_recovery_observation)
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
        Ok(HandoffResult::PaymentRequestProposal {
            outbound_message_id: record
                .proposal_outbound_message_id
                .ok_or(HandoffError::Permanent)?,
            event_id: record.proposal_event_id.ok_or(HandoffError::Permanent)?,
            payment_request_id: record.payment_request_id,
        })
    }

    async fn cancel_payment_request(
        &self,
        reader: &str,
        payment_request_id: &str,
    ) -> Result<HandoffResult, HandoffError> {
        let reader = parse_peer(reader)?;
        let payment_request_id = PaymentRequestId::new(payment_request_id.to_owned())
            .map_err(|_| HandoffError::Permanent)?;
        let record = self
            .sdk
            .cancel_payment_request(reader, &payment_request_id, None)
            .await
            .map_err(classify)?;
        Ok(HandoffResult::PaymentRequestCancellation {
            outbound_message_id: record
                .last_outbound_message_id
                .ok_or(HandoffError::Permanent)?,
            event_id: record.canceled_event_id.ok_or(HandoffError::Permanent)?,
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
        AmountRecord, OutboundPrivateSendFailure, PaymentRequestTermsRecord,
        RecoveryMarkerPublishFailure, ReservationCleanupFailure,
    };
    use serde_json::Map;

    const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

    fn server_app_id() -> PaykitAppId {
        PaykitAppId::new("paykit-server").unwrap()
    }

    fn canonical_record(local_role: Option<PaymentRequestLocalRole>) -> PaymentRequestRecord {
        PaymentRequestRecord {
            counterparty: PubkyPublicKey::from_raw_or_app_key(CREATOR).unwrap(),
            proposal_app_id: Some(server_app_id()),
            payer_app_id: None,
            execution_claim_app_id: None,
            conversion_quotes: Vec::new(),
            payment_request_id: Uuid::new_v4().to_string(),
            local_role,
            state: SdkPaymentRequestLifecycleState::Proposed,
            proposal_stream_item_id: Some(1),
            proposal_outbound_message_id: None,
            proposal_outbound_status: None,
            proposal_event_id: Some(Uuid::new_v4().to_string()),
            terms: Some(PaymentRequestTermsRecord {
                amount: AmountRecord {
                    asset: "BTC".into(),
                    value: "0.00001000".into(),
                },
                payment_reference: Uuid::new_v4().to_string(),
                proposal_expires_at: Some("2027-01-15T08:00:00Z".into()),
                recurrence: None,
                required_app_id: Some(server_app_id()),
                conversion: None,
                payment_deadline: None,
                accepted_payment_endpoint_identifiers: vec!["btc-bitcoin-p2wpkh".into()],
                payment_endpoints: Some(HashMap::from([(
                    "btc-bitcoin-p2wpkh".into(),
                    "payload".into(),
                )])),
                metadata: Map::new(),
            }),
            accepted_event_id: None,
            accepted_outbound_status: None,
            rejected_event_id: None,
            rejected_outbound_status: None,
            canceled_event_id: None,
            canceled_outbound_status: None,
            payment_proofs: Vec::new(),
            last_stream_item_id: Some(1),
            last_outbound_message_id: None,
            last_outbound_status: None,
            last_event_at: Some(
                (std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000))
                    .into(),
            ),
            invalid_reason: None,
        }
    }

    #[test]
    fn payer_records_do_not_poison_shared_status_and_drain_refresh_projection() {
        let mut payer = canonical_record(Some(PaymentRequestLocalRole::Payer));
        payer.terms = None;
        payer.last_event_at = None;
        let payee = canonical_record(Some(PaymentRequestLocalRole::Payee));
        let payee_id = payee.payment_request_id.clone();

        let projections = lifecycle_projections(&[payer, payee], &server_app_id());

        assert_eq!(projections.len(), 1);
        assert_eq!(
            projections[0].as_ref().unwrap().payment_request_id,
            payee_id
        );
    }

    #[test]
    fn foreign_payee_records_do_not_poison_server_lifecycle_projection() {
        let mut foreign_payee = canonical_record(Some(PaymentRequestLocalRole::Payee));
        foreign_payee.proposal_app_id = Some(PaykitAppId::new("bitkit").unwrap());
        foreign_payee.terms.as_mut().unwrap().payment_endpoints = None;
        let server_payee = canonical_record(Some(PaymentRequestLocalRole::Payee));
        let server_payment_request_id = server_payee.payment_request_id.clone();

        let projections = lifecycle_projections(&[foreign_payee, server_payee], &server_app_id());

        assert_eq!(projections.len(), 1);
        assert_eq!(
            projections[0].as_ref().unwrap().payment_request_id,
            server_payment_request_id
        );
    }

    #[test]
    fn server_owned_malformed_and_unknown_records_still_fail_projection() {
        let mut malformed_payee = canonical_record(Some(PaymentRequestLocalRole::Payee));
        malformed_payee.terms = None;
        let mut missing_app_id = canonical_record(Some(PaymentRequestLocalRole::Payee));
        missing_app_id.proposal_app_id = None;
        let unknown_role = canonical_record(None);

        for record in [malformed_payee, missing_app_id, unknown_role] {
            assert_eq!(
                lifecycle_projections(&[record], &server_app_id()),
                vec![Err(LifecycleSyncError::InvalidProjection)]
            );
        }
    }

    fn receive_target(counterparty: &str) -> ReceiveTarget {
        ReceiveTarget {
            counterparty: PubkyPublicKey::from_raw_or_app_key(counterparty).unwrap(),
        }
    }

    fn intake_report(
        counterparty: &str,
        error: Option<&str>,
    ) -> paykit_sdk::PrivateStreamCounterpartyIntakeReport {
        paykit_sdk::PrivateStreamCounterpartyIntakeReport {
            counterparty: PubkyPublicKey::from_raw_or_app_key(counterparty).unwrap(),
            report: error
                .is_none()
                .then_some(paykit_sdk::PrivateStreamIntakeReport {
                    receive_batch_id: Some(1),
                    stream_item_ids: Vec::new(),
                    event_conflicts: Vec::new(),
                }),
            error: error.map(str::to_owned),
        }
    }

    #[test]
    fn required_receive_target_rejects_empty_reports() {
        let required = vec![receive_target(CREATOR)];

        assert_eq!(
            receive_health_for_required_targets(&[], &required),
            ReceiveHealth::Unavailable
        );
    }

    #[test]
    fn required_receive_target_rejects_matching_report_errors() {
        let required = vec![receive_target(CREATOR)];

        assert_eq!(
            receive_health_for_required_targets(
                &[intake_report(CREATOR, Some("offline"))],
                &required
            ),
            ReceiveHealth::Unavailable
        );
    }

    #[test]
    fn required_receive_target_rejects_any_matching_report_error() {
        let required = vec![receive_target(CREATOR)];

        assert_eq!(
            receive_health_for_required_targets(
                &[
                    intake_report(CREATOR, None),
                    intake_report(CREATOR, Some("offline")),
                ],
                &required,
            ),
            ReceiveHealth::Unavailable
        );
    }

    #[test]
    fn successful_required_report_ignores_unrelated_peer_failure() {
        let required = vec![receive_target(CREATOR)];
        let unrelated = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";

        assert_eq!(
            receive_health_for_required_targets(
                &[
                    intake_report(CREATOR, None),
                    intake_report(unrelated, Some("offline")),
                ],
                &required,
            ),
            ReceiveHealth::Available
        );
    }

    #[test]
    fn no_required_receive_targets_ignore_unrelated_failures() {
        assert_eq!(
            receive_health_for_required_targets(&[intake_report(CREATOR, Some("offline"))], &[],),
            ReceiveHealth::Available
        );
    }

    #[test]
    fn no_required_receive_targets_ignore_top_level_receive_failure() {
        assert_eq!(
            receive_health_from_reports(Err(()), Some(&[])),
            ReceiveHealth::Available
        );
    }

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
    fn recovery_marker_observation_normalizes_permanent_sdk_errors_to_retryable() {
        assert_eq!(
            retryable_recovery_observation(HandoffError::Permanent),
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

    #[test]
    fn every_known_sdk_lifecycle_state_maps_one_to_one() {
        let cases = [
            (
                SdkPaymentRequestLifecycleState::Proposed,
                PersistedPaymentRequestLifecycleState::Proposed,
            ),
            (
                SdkPaymentRequestLifecycleState::ProposalExpired,
                PersistedPaymentRequestLifecycleState::ProposalExpired,
            ),
            (
                SdkPaymentRequestLifecycleState::Accepted,
                PersistedPaymentRequestLifecycleState::Accepted,
            ),
            (
                SdkPaymentRequestLifecycleState::Rejected,
                PersistedPaymentRequestLifecycleState::Rejected,
            ),
            (
                SdkPaymentRequestLifecycleState::Canceled,
                PersistedPaymentRequestLifecycleState::Canceled,
            ),
            (
                SdkPaymentRequestLifecycleState::ProofSubmitted,
                PersistedPaymentRequestLifecycleState::ProofSubmitted,
            ),
            (
                SdkPaymentRequestLifecycleState::ActiveRecurring,
                PersistedPaymentRequestLifecycleState::ActiveRecurring,
            ),
            (
                SdkPaymentRequestLifecycleState::RecoveryRequired,
                PersistedPaymentRequestLifecycleState::RecoveryRequired,
            ),
            (
                SdkPaymentRequestLifecycleState::InvalidConflict,
                PersistedPaymentRequestLifecycleState::InvalidConflict,
            ),
        ];
        for (sdk, persisted) in cases {
            assert_eq!(persisted_lifecycle_state(sdk), Ok(persisted));
        }
    }

    #[test]
    fn recovery_projection_uses_the_latest_underlying_event_identity() {
        assert_eq!(
            recovery_state_event_id(
                Some("cancel"),
                Some("reject"),
                Some("proof"),
                Some("accept"),
                Some("proposal"),
            ),
            Some("cancel")
        );
        assert_eq!(
            recovery_state_event_id(
                None,
                Some("reject"),
                Some("proof"),
                Some("accept"),
                Some("proposal"),
            ),
            Some("reject")
        );
        assert_eq!(
            recovery_state_event_id(None, None, Some("proof"), Some("accept"), Some("proposal")),
            Some("proof")
        );
        assert_eq!(
            recovery_state_event_id(None, None, None, Some("accept"), Some("proposal")),
            Some("accept")
        );
        assert_eq!(
            recovery_state_event_id(None, None, None, None, Some("proposal")),
            Some("proposal")
        );
    }

    #[test]
    fn drain_refresh_error_mapping_preserves_conflicts_and_degrades_malformed_records() {
        assert_eq!(
            map_projection_persistence_error(PersistenceError::Conflict),
            LifecycleSyncError::Conflict
        );
        assert_eq!(
            map_lifecycle_drain_error(LifecycleSyncError::Conflict),
            PaymentDrainError::Conflict
        );
        assert_eq!(
            map_lifecycle_drain_error(LifecycleSyncError::InvalidProjection),
            PaymentDrainError::Unavailable
        );
        assert_eq!(
            map_lifecycle_status_error(LifecycleSyncError::Conflict),
            PaymentRequestStatusError::Conflict
        );
        assert_eq!(
            map_lifecycle_status_error(LifecycleSyncError::InvalidProjection),
            PaymentRequestStatusError::Unavailable
        );
    }

    fn projection(
        index: u64,
        request_state: PersistedPaymentRequestLifecycleState,
    ) -> PaymentRequestLifecycleProjection {
        PaymentRequestLifecycleProjection {
            payment_request_id: Uuid::new_v4().to_string(),
            proposal: ProposalCorrelation {
                reader_pubky: CREATOR.into(),
                proposal_app_id: crate::config::PAYKIT_APP_ID.into(),
                terms: PaymentTermsV1 {
                    amount: "1".into(),
                    asset: "btc".into(),
                    payment_reference: Uuid::new_v4().to_string(),
                    proposal_expires_at: None,
                    payment_deadline: None,
                    accepted_endpoint_identifiers: vec!["btc-bitcoin-p2wpkh".into()],
                    payment_endpoints: [("btc-bitcoin-p2wpkh".into(), "bc1qexample".into())]
                        .into_iter()
                        .collect(),
                    metadata: serde_json::Map::new(),
                },
            },
            request_state,
            state_event_id: Some(Uuid::new_v4().to_string()),
            last_stream_item_id: Some(index),
            last_outbound_message_id: None,
            last_event_at: time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        }
    }

    #[tokio::test]
    async fn top_level_receive_failure_projects_every_canonical_record_before_returning_degraded() {
        let projections = vec![
            Ok(projection(
                1,
                PersistedPaymentRequestLifecycleState::Proposed,
            )),
            Ok(projection(
                2,
                PersistedPaymentRequestLifecycleState::Accepted,
            )),
        ];
        let persisted = Arc::new(StdMutex::new(Vec::new()));
        let captured = persisted.clone();

        let result = project_lifecycles_after_receive(
            projections,
            ReceiveHealth::Unavailable,
            move |projection| {
                captured.lock().unwrap().push(projection.request_state);
                std::future::ready(Ok(()))
            },
        )
        .await;

        assert_eq!(result, Err(LifecycleSyncError::PartialReceive));
        assert_eq!(
            *persisted.lock().unwrap(),
            vec![
                PersistedPaymentRequestLifecycleState::Proposed,
                PersistedPaymentRequestLifecycleState::Accepted,
            ]
        );
    }

    #[tokio::test]
    async fn malformed_canonical_record_does_not_prevent_later_valid_projection() {
        let projections = vec![
            Ok(projection(
                1,
                PersistedPaymentRequestLifecycleState::Proposed,
            )),
            Err(LifecycleSyncError::InvalidProjection),
            Ok(projection(
                3,
                PersistedPaymentRequestLifecycleState::Accepted,
            )),
        ];
        let persisted = Arc::new(StdMutex::new(Vec::new()));
        let captured = persisted.clone();

        let result = project_lifecycles_after_receive(
            projections,
            ReceiveHealth::Available,
            move |projection| {
                captured.lock().unwrap().push(projection.request_state);
                std::future::ready(Ok(()))
            },
        )
        .await;

        assert_eq!(result, Err(LifecycleSyncError::InvalidProjection));
        assert_eq!(
            *persisted.lock().unwrap(),
            vec![
                PersistedPaymentRequestLifecycleState::Proposed,
                PersistedPaymentRequestLifecycleState::Accepted,
            ]
        );
    }

    #[tokio::test]
    async fn exact_replay_precedes_and_bypasses_fresh_mutable_work() {
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let replay_calls = calls.clone();
        let refresh_calls = calls.clone();
        let operation_calls = calls.clone();

        let result = replay_or_refresh_then(
            move || {
                replay_calls.lock().unwrap().push("replay");
                std::future::ready(Ok::<_, PaymentDrainError>(Some(7_u8)))
            },
            move || {
                refresh_calls.lock().unwrap().push("refresh");
                std::future::ready(Ok::<_, PaymentDrainError>(()))
            },
            move || {
                operation_calls.lock().unwrap().push("operation");
                std::future::ready(Ok::<_, PaymentDrainError>(9_u8))
            },
        )
        .await;

        assert_eq!(result, Ok(7));
        assert_eq!(*calls.lock().unwrap(), vec!["replay"]);
    }

    #[tokio::test]
    async fn unavailable_refresh_prevents_stale_operation_result() {
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let replay_calls = calls.clone();
        let refresh_calls = calls.clone();
        let operation_calls = calls.clone();

        let result = replay_or_refresh_then(
            move || {
                replay_calls.lock().unwrap().push("replay");
                std::future::ready(Ok::<_, PaymentDrainError>(None))
            },
            move || {
                refresh_calls.lock().unwrap().push("refresh");
                std::future::ready(Err(PaymentDrainError::Unavailable))
            },
            move || {
                operation_calls.lock().unwrap().push("operation");
                std::future::ready(Ok::<_, PaymentDrainError>(9_u8))
            },
        )
        .await;

        assert_eq!(result, Err(PaymentDrainError::Unavailable));
        assert_eq!(*calls.lock().unwrap(), vec!["replay", "refresh"]);
    }

    #[tokio::test]
    async fn unavailable_required_intake_prevents_payment_request_status_lookup() {
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let refresh_calls = calls.clone();
        let lookup_calls = calls.clone();

        let result = refresh_then(
            move || {
                refresh_calls.lock().unwrap().push("refresh");
                std::future::ready(Err(PaymentRequestStatusError::Unavailable))
            },
            move || {
                lookup_calls.lock().unwrap().push("lookup");
                std::future::ready(Ok::<_, PaymentRequestStatusError>(Some(7_u8)))
            },
        )
        .await;

        assert_eq!(result, Err(PaymentRequestStatusError::Unavailable));
        assert_eq!(*calls.lock().unwrap(), vec!["refresh"]);
    }
}
