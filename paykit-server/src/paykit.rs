//! Concrete per-Creator Paykit SDK boundary used by durable outbox workers.

use std::{
    collections::HashMap,
    future::Future,
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
    PubkySessionBootstrap, PubkySessionProvider, ReceiverNoiseSecretKey, StorageAdapter,
};
use pubky::{Pubky, errors::RequestError};
use thiserror::Error;
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
    client_id: String,
    required_capabilities: String,
}

impl CreatorSessionProvider {
    pub fn new(
        creators: CreatorStore,
        creator: CreatorPubky,
        paykit: &PaykitConfig,
    ) -> Result<Self, PaykitSdkError> {
        let public_client = Pubky::new().map_err(|error| PaykitSdkError::Identity {
            context: "could not construct Pubky client".into(),
            source: Some(anyhow::anyhow!(error.to_string())),
        })?;
        Ok(Self::with_pubky(creators, creator, public_client, paykit))
    }

    /// Uses the process-selected Pubky network for this Creator's restored session.
    pub fn with_pubky(
        creators: CreatorStore,
        creator: CreatorPubky,
        public_client: Pubky,
        paykit: &PaykitConfig,
    ) -> Self {
        Self {
            creators,
            creator,
            public_client,
            client_id: paykit.client_id.clone(),
            required_capabilities: PaykitSdkConfig::new(paykit.receiver_path.clone())
                .required_session_capabilities(),
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
        let access = restore_server_session(
            &self.public_client,
            credentials.session_secret(),
            credentials.receiver_noise_secret().clone(),
            &self.client_id,
            &self.required_capabilities,
        )
        .await
        .map_err(|error| match error {
            ServerSessionRestoreError::Invalid => PaykitSdkError::Identity {
                context: "creator Pubky session is invalid".into(),
                source: None,
            },
            ServerSessionRestoreError::Unavailable => PaykitSdkError::Transport {
                context: "creator Pubky session dependency is unavailable".into(),
                source: None,
            },
        })?;
        bind_session_to_creator(access.public_key()?, &self.creator)?;
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

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum ServerSessionRestoreError {
    #[error("creator Pubky session is invalid")]
    Invalid,
    #[error("creator Pubky session dependency is unavailable")]
    Unavailable,
}

pub(crate) async fn restore_server_session(
    public_client: &Pubky,
    session_secret: &str,
    receiver_noise_secret_key: ReceiverNoiseSecretKey,
    client_id: &str,
    required_capabilities: &str,
) -> Result<PubkySessionAccess, ServerSessionRestoreError> {
    if !session_secret.starts_with("pubky-grant-credential-") {
        return Err(ServerSessionRestoreError::Invalid);
    }

    let bootstrap = PubkySessionBootstrap::with_pubky(public_client.clone(), client_id)
        .map_err(|error| classify_sdk_restore_error(&error))?;
    bootstrap
        .import_session(
            session_secret,
            None,
            receiver_noise_secret_key,
            required_capabilities,
        )
        .await
        .map(|result| result.access)
        .map_err(|error| classify_sdk_restore_error(&error))
}

fn classify_sdk_restore_error(error: &PaykitSdkError) -> ServerSessionRestoreError {
    match error {
        PaykitSdkError::Identity {
            source: Some(source),
            ..
        } => source.downcast_ref::<pubky::Error>().map_or(
            ServerSessionRestoreError::Invalid,
            classify_pubky_restore_error,
        ),
        PaykitSdkError::Identity { .. }
        | PaykitSdkError::Policy { .. }
        | PaykitSdkError::Protocol { .. } => ServerSessionRestoreError::Invalid,
        _ => ServerSessionRestoreError::Unavailable,
    }
}

fn classify_pubky_restore_error(error: &pubky::Error) -> ServerSessionRestoreError {
    match error {
        pubky::Error::Authentication(_) | pubky::Error::Parse(_) => {
            ServerSessionRestoreError::Invalid
        }
        pubky::Error::Request(RequestError::Validation { .. }) => {
            ServerSessionRestoreError::Invalid
        }
        pubky::Error::Request(RequestError::Server { status, .. })
            if status.is_client_error() && status.as_u16() != 408 && status.as_u16() != 429 =>
        {
            ServerSessionRestoreError::Invalid
        }
        _ => ServerSessionRestoreError::Unavailable,
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
    handoff_invocation_token: StdMutex<Option<Uuid>>,
}

struct StorageInvocationScope(PostgresStorageAdapter);

impl Drop for StorageInvocationScope {
    fn drop(&mut self) {
        self.0.clear_invocation_token();
    }
}

struct HandoffInvocationScope<'a>(&'a StdMutex<Option<Uuid>>);

impl Drop for HandoffInvocationScope<'_> {
    fn drop(&mut self) {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = None;
    }
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
            handoff_invocation_token: StdMutex::new(None),
        })
    }

    async fn with_handoff_invocation_token<T>(
        &self,
        callback: impl Future<Output = paykit_sdk::Result<T>>,
    ) -> paykit_sdk::Result<T> {
        let token = *self
            .handoff_invocation_token
            .lock()
            .map_err(|_| PaykitSdkError::Storage {
                context: "handoff invocation token is unavailable".into(),
                source: None,
            })?;
        let token = token.ok_or_else(|| PaykitSdkError::Storage {
            context: "handoff invocation token is absent".into(),
            source: None,
        })?;
        self.storage.set_invocation_token(token)?;
        let _scope = StorageInvocationScope(self.storage.clone());
        callback.await
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
        // Identity/session failures require reauthentication. Retrying the
        // same persisted credential can never make a private handoff succeed.
        PaykitSdkError::Identity { .. } => HandoffError::Permanent,
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

    async fn execute_handoff_with_invocation_token(
        &self,
        intent: &DeliveryIntentV1,
        invocation_token: Uuid,
    ) -> Result<HandoffResult, HandoffFailure> {
        let _guard = self.mutation_lock.lock().await;
        {
            let mut slot = self.handoff_invocation_token.lock().map_err(|_| {
                HandoffFailure::Retryable(crate::persistence::OutboxRetryClass::AdapterUnavailable)
            })?;
            if slot.is_some() {
                return Err(HandoffFailure::Retryable(
                    crate::persistence::OutboxRetryClass::AdapterUnavailable,
                ));
            }
            *slot = Some(invocation_token);
        }
        let _scope = HandoffInvocationScope(&self.handoff_invocation_token);
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
            .with_handoff_invocation_token(async {
                self.sdk
                    .enqueue_private_payment_list_with_receiving_details(reader, path, details)
                    .await
            })
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
        let terms = payment_terms(terms)?;
        let record = self
            .with_handoff_invocation_token(async {
                self.sdk.propose_payment_request(reader, path, terms).await
            })
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
    use paykit_sdk::InMemoryStorage;
    #[allow(
        deprecated,
        reason = "regression covers persisted manual-claim cookie sessions"
    )]
    use pubky::{
        AuthFlowKind, AuthToken, Capabilities, EncryptedHttpRelayInboxChannel, Keypair,
        PubkyCookieAuthFlow, PubkySession,
    };
    use pubky_testnet::EphemeralTestnet;

    static PUBKY_TESTNET_LOCK: TokioMutex<()> = TokioMutex::const_new(());

    const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

    #[derive(Clone)]
    struct FixedSessionProvider(PubkySessionAccess);

    #[async_trait]
    impl PubkySessionProvider for FixedSessionProvider {
        async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
            Ok(Some(self.0.clone()))
        }

        async fn load_public_storage(&self) -> paykit_sdk::Result<Option<pubky::PublicStorage>> {
            Ok(None)
        }

        async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(
        deprecated,
        reason = "regression covers persisted manual-claim cookie sessions"
    )]
    async fn cookie_session_private_operation_is_terminal_not_retryable() {
        let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
        let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(
            &std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL"),
        )
        .unwrap();
        let testnet = EphemeralTestnet::builder()
            .postgres(postgres)
            .with_http_relay()
            .build()
            .await
            .unwrap();
        let pubky = testnet.sdk().unwrap();
        let keypair = Keypair::random();
        pubky
            .signer(keypair.clone())
            .signup(&testnet.homeserver_app().public_key(), None)
            .await
            .unwrap();

        let required_capabilities =
            PaykitSdkConfig::new(PaykitReceiverPath::new("paykit/server").unwrap())
                .required_session_capabilities();
        let capabilities = Capabilities::try_from(required_capabilities.as_str()).unwrap();
        let client_secret = [42; 32];
        let relay = testnet.http_relay().local_url().join("inbox").unwrap();
        let flow = PubkyCookieAuthFlow::builder(&capabilities, AuthFlowKind::signin())
            .client(pubky.client().clone())
            .client_secret(client_secret)
            .relay(relay.clone())
            .start()
            .unwrap();
        let token = AuthToken::sign(&keypair, capabilities.clone()).serialize();
        EncryptedHttpRelayInboxChannel::new(relay, client_secret)
            .unwrap()
            .produce(pubky.client(), &token)
            .await
            .unwrap();
        let minted = flow.await_approval().await.unwrap();
        let session_secret = minted
            .as_cookie()
            .and_then(|cookie| cookie.export_secret())
            .expect("manual-claim cookie session must export");

        let restore_error = restore_server_session(
            &pubky,
            &session_secret,
            ReceiverNoiseSecretKey::random(),
            "paykit-server",
            &required_capabilities,
        )
        .await
        .expect_err("rc55 server sessions must reject legacy cookie credentials");
        assert_eq!(restore_error, ServerSessionRestoreError::Invalid);

        let restored_cookie =
            PubkySession::import_secret(&session_secret, Some(pubky.client().clone()))
                .await
                .expect("fixture must remain a real restorable legacy cookie");
        assert!(restored_cookie.as_cookie().is_some());

        let sdk = PaykitSdk::new(
            InMemoryStorage::default(),
            FixedSessionProvider(PubkySessionAccess {
                session: restored_cookie,
                outbox_client: pubky,
                local_secret_key: None,
                receiver_noise_secret_key: ReceiverNoiseSecretKey::random(),
            }),
            ExplicitInputsPaymentAdapter,
            PaykitSdkConfig::new(PaykitReceiverPath::new("paykit/server").unwrap()),
        )
        .unwrap();
        let private_operation_error = sdk
            .ensure_link_with_peer(
                PubkyPublicKey::from_public_key(&Keypair::random().public_key()),
                PaykitReceiverPath::new("bitkit/server").unwrap(),
                1,
            )
            .await
            .expect_err("rc55 must reject cookie access before private link work");

        assert_eq!(
            classify(private_operation_error),
            HandoffError::Permanent,
            "a persisted legacy cookie must terminalize instead of retrying forever"
        );
    }

    #[tokio::test]
    async fn malformed_session_secret_is_invalid_without_cookie_fallback() {
        let error = restore_server_session(
            &Pubky::new().unwrap(),
            "not-a-session-secret",
            ReceiverNoiseSecretKey::random(),
            "paykit-server",
            "/pub/paykit/server/:rw",
        )
        .await
        .expect_err("malformed credentials are terminal");

        assert_eq!(error, ServerSessionRestoreError::Invalid);
    }

    #[tokio::test]
    async fn corrupt_grant_prefix_is_invalid_without_cookie_fallback() {
        let error = restore_server_session(
            &Pubky::new().unwrap(),
            "pubky-grant-credential-corrupt",
            ReceiverNoiseSecretKey::random(),
            "paykit-server",
            "/pub/paykit/server/:rw",
        )
        .await
        .expect_err("corrupt grant credentials are terminal");

        assert_eq!(error, ServerSessionRestoreError::Invalid);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transient_grant_restore_failure_is_unavailable_without_cookie_fallback() {
        let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
        let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(
            &std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL"),
        )
        .unwrap();
        let testnet = EphemeralTestnet::builder()
            .postgres(postgres)
            .build()
            .await
            .unwrap();
        let pubky = testnet.sdk().unwrap();
        let required_capabilities =
            PaykitSdkConfig::new(PaykitReceiverPath::new("paykit/server").unwrap())
                .required_session_capabilities();
        let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "paykit-server").unwrap();
        let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
        let account = bootstrap
            .sign_up(
                &paykit_sdk::PubkyLocalSecretKey::new(Keypair::random().secret()),
                ReceiverNoiseSecretKey::random(),
                &homeserver,
                None,
                &required_capabilities,
            )
            .await
            .unwrap();
        let session_secret = account.export_session_secret().await.unwrap().into_inner();
        assert!(session_secret.starts_with("pubky-grant-credential-"));
        let restored = restore_server_session(
            &pubky,
            &session_secret,
            ReceiverNoiseSecretKey::random(),
            "paykit-server",
            &required_capabilities,
        )
        .await
        .expect("persisted grant credential must restore while its homeserver is available");
        assert!(restored.session.as_grant().is_some());
        PaykitSdk::new(
            InMemoryStorage::default(),
            FixedSessionProvider(restored),
            ExplicitInputsPaymentAdapter,
            PaykitSdkConfig::new(PaykitReceiverPath::new("paykit/server").unwrap()),
        )
        .unwrap()
        .initialize()
        .await
        .expect("rc55 runtime must accept restored grant-backed access");
        drop(testnet);

        let error = restore_server_session(
            &pubky,
            &session_secret,
            ReceiverNoiseSecretKey::random(),
            "paykit-server",
            &required_capabilities,
        )
        .await
        .expect_err("stopped homeserver must be retryable");

        assert_eq!(error, ServerSessionRestoreError::Unavailable);
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
    fn handoff_invocation_scope_clears_token_on_every_drop_path() {
        let token = StdMutex::new(Some(Uuid::new_v4()));
        {
            let _scope = HandoffInvocationScope(&token);
        }
        assert!(token.lock().unwrap().is_none());
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
