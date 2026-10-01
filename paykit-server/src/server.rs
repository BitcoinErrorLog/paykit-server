//! Explicit production composition root for one multi-Creator Paykit Server process.

use std::{future::Future, sync::Arc, time::Duration};

use crate::{
    application::{
        connection_status::ConnectionStatusService,
        create_invoice::{
            AppRegistryDiscovery, CreateInvoiceError, CreateInvoiceService, LockFetchError,
            LockFetcher, PaykitIntentBuilder, SessionValidationError, SessionValidator,
        },
        payment_status::PaymentStatusService,
        setup_status::SetupStatusService,
    },
    bitkit_setup::BitkitAuthStarter,
    config::{Config, OutboxConfig, PaykitConfig, PaykitNetwork},
    crypto::Crypto,
    domain::locks::{CreatorPubky, PubkyLockResource, ReaderPubky},
    http::{self, auth::SignedLocksAuth},
    paykit::{CreatorSessions, PaykitAdapter},
    persistence::{CreatorStore, InvoiceStore, OutboxRetryClass, OutboxStore, PersistenceError},
    real_setup::RealSetupCompleter,
    runtime::{PostgresDependency, Runtime, operational_router},
    setup::{SetupLimits, SetupService, SystemClock},
    setup_orchestration::PubkyCompanionRelay,
    workers::{
        observer::{ElectrumAdapter, ElectrumPort, ObserverError, observe_once},
        outbox::{
            ProcessingHealth, RetrySchedule, process_claim_with_health,
            process_reconciliation_with_health,
        },
    },
};
use async_trait::async_trait;
use axum::{Extension, Router};
use locks_core::lock_policy::ContentLock;
use paykit_lib::{PaykitAppRegistry, get_paykit_app_registry};
use paykit_sdk::{PaykitSdkError, PubkyPublicKey, PubkySessionBootstrap, PubkySessionProvider};
use pubky::{Pubky, errors::RequestError};
use sqlx::PgPool;
use thiserror::Error;
use tokio::{task::JoinSet, time::MissedTickBehavior};
use uuid::Uuid;

fn setup_bootstrap(
    pubky: Pubky,
    client_id: &str,
    network: PaykitNetwork,
) -> Result<PubkySessionBootstrap, ServerBuildError> {
    let bootstrap =
        PubkySessionBootstrap::with_pubky(pubky, client_id).map_err(|_| ServerBuildError::Pubky)?;
    match network {
        PaykitNetwork::Mainnet => Ok(bootstrap),
        PaykitNetwork::Testnet => bootstrap
            .with_auth_relay("http://127.0.0.1:15412/inbox")
            .map_err(|_| ServerBuildError::Pubky),
    }
}

/// Fail-fast, secret-free construction errors.
#[derive(Debug, Error)]
pub enum ServerBuildError {
    #[error("could not construct the configured Pubky client")]
    Pubky,
    #[error("could not construct the Electrum adapter")]
    Electrum,
    #[error("could not construct server cryptography")]
    Crypto,
}

/// Concrete process-owned server components.
pub struct Server {
    config: Config,
    router: Router,
    runtime: Arc<Runtime>,
    workers: WorkerComponents,
}

struct WorkerComponents {
    creators: CreatorStore,
    sessions: CreatorSessions,
    outbox: OutboxStore,
    invoices: InvoiceStore,
    electrum: Arc<dyn ElectrumPort>,
    paykit: PaykitConfig,
    bitcoin_network: crate::config::BitcoinNetwork,
    outbox_poll_interval: Duration,
    outbox_batch_size: i64,
    outbox_lease_duration: Duration,
    outbox_retry_initial: Duration,
    outbox_retry_max: Duration,
    electrum_poll_interval: Duration,
}

impl Server {
    /// Builds every required production adapter and all public routes.
    pub async fn build(config: Config, pool: PgPool) -> Result<Self, ServerBuildError> {
        let pubky = configured_pubky(config.paykit.network)?;
        Self::build_with_client(config, pool, pubky).await
    }

    /// Builds the production composition with a controlled Pubky client for E2E tests.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn build_with_pubky(
        config: Config,
        pool: PgPool,
        pubky: Pubky,
    ) -> Result<Self, ServerBuildError> {
        Self::build_with_client(config, pool, pubky).await
    }

    /// Builds the production composition with controlled transport ports for E2E tests.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn build_with_transports(
        config: Config,
        pool: PgPool,
        pubky: Pubky,
        electrum: Arc<dyn ElectrumPort>,
    ) -> Result<Self, ServerBuildError> {
        Self::build_with_clients(config, pool, pubky, electrum).await
    }

    async fn build_with_client(
        config: Config,
        pool: PgPool,
        pubky: Pubky,
    ) -> Result<Self, ServerBuildError> {
        let electrum = ElectrumAdapter::configured(
            config.electrum.endpoint(),
            config.deployment_invariants().bitcoin_network.clone(),
            config.electrum.request_timeout,
            config.electrum.connect_retries,
        )
        .map_err(map_electrum_error)?;
        Self::build_with_clients(config, pool, pubky, Arc::new(electrum)).await
    }

    async fn build_with_clients(
        config: Config,
        pool: PgPool,
        pubky: Pubky,
        electrum: Arc<dyn ElectrumPort>,
    ) -> Result<Self, ServerBuildError> {
        let crypto = Arc::new(
            Crypto::from_master_key(config.master_key().as_bytes())
                .map_err(|_| ServerBuildError::Crypto)?,
        );
        let creators = CreatorStore::new(&pool, crypto.clone());
        let invoices = InvoiceStore::new(&pool, crypto.clone());
        let outbox = OutboxStore::new(&pool, crypto.clone());

        let bootstrap = setup_bootstrap(
            pubky.clone(),
            config.paykit.client_id.as_str(),
            config.paykit.network,
        )?;
        let relay = Arc::new(PubkyCompanionRelay::new(pubky.client().clone()));
        let sessions = CreatorSessions::new(creators.clone(), pubky.clone(), config.paykit.clone());
        let setup_completer = Arc::new(RealSetupCompleter::new(
            BitkitAuthStarter::new(bootstrap),
            relay,
            creators.clone(),
            sessions.clone(),
            config.deployment_invariants().bitcoin_network.clone(),
        ));
        let setup = SetupService::new_with_authorization_url_logging(
            config.setup.allowed_origins.clone(),
            setup_completer,
            Arc::new(SystemClock::default()),
            SetupLimits {
                max_polls_per_flow: usize::try_from(
                    config.rate_limits.max_completion_polls_per_flow,
                )
                .expect("validated completion poll limit fits usize"),
                max_polls: usize::try_from(config.rate_limits.max_completion_polls)
                    .expect("validated completion poll limit fits usize"),
                setup_per_ip_per_minute: usize::try_from(
                    config.rate_limits.setup_per_ip_per_minute,
                )
                .expect("validated setup rate limit fits usize"),
                max_pending_setup_flows: config.rate_limits.max_pending_setup_flows(),
            },
            config.setup.log_authorization_url,
        );

        let session_validator = Arc::new(CreatorSessionValidator {
            creators: creators.clone(),
            sessions: sessions.clone(),
        });
        let invoice_service = Arc::new(CreateInvoiceService::new(
            session_validator.clone(),
            Arc::new(PubkyLockFetcher {
                storage: pubky.public_storage(),
                max_bytes: config.limits.lock_resource_bytes,
                timeout: config.limits.lock_fetch_timeout,
            }),
            Arc::new(PubkyAppRegistryDiscovery {
                storage: pubky.public_storage(),
            }),
            config.paykit.app_id.clone(),
            Arc::new(creators.clone()),
            config.deployment_invariants().bitcoin_network.clone(),
            Arc::new(invoices.clone()),
            Arc::new(PaykitIntentBuilder::new(
                config.deployment_invariants().bitcoin_network.clone(),
            )),
        ));
        let connection_status_service = Arc::new(ConnectionStatusService::new(
            Arc::new(invoices.clone()),
            Arc::new(sessions.clone()),
        ));
        let status_service = Arc::new(PaymentStatusService::new(Arc::new(invoices.clone())));
        let setup_status_service = Arc::new(SetupStatusService::new(session_validator));
        let signed_auth = Arc::new(SignedLocksAuth::from_config(&config));
        let business_routes = http::setup::setup_router(setup).merge(
            http::invoices::invoices_router(invoice_service)
                .merge(http::connection_status::connection_status_router(
                    connection_status_service,
                ))
                .merge(http::status::status_router(status_service))
                .merge(http::setup_status::setup_status_router(
                    setup_status_service,
                ))
                .layer(Extension(signed_auth)),
        );

        let runtime = Arc::new(Runtime::new(
            Arc::new(PostgresDependency::new(pool.clone())),
            64,
        ));
        let router = operational_router(business_routes, runtime.clone());
        let workers = WorkerComponents {
            creators,
            sessions,
            outbox,
            invoices,
            electrum,
            paykit: config.paykit.clone(),
            bitcoin_network: config.deployment_invariants().bitcoin_network.clone(),
            outbox_poll_interval: config.outbox.poll_interval,
            outbox_batch_size: outbox_batch_size(&config.outbox),
            outbox_lease_duration: config.outbox.lease_duration,
            outbox_retry_initial: config.outbox.retry_initial,
            outbox_retry_max: config.outbox.retry_max,
            electrum_poll_interval: config.electrum.poll_interval,
        };

        Ok(Self {
            config,
            router,
            runtime,
            workers,
        })
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub fn runtime(&self) -> Arc<Runtime> {
        self.runtime.clone()
    }

    pub async fn run(self, listener: tokio::net::TcpListener) -> std::io::Result<()> {
        self.run_with_shutdown(listener, crate::runtime::shutdown_signal())
            .await
    }

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn run_until<F>(
        self,
        listener: tokio::net::TcpListener,
        shutdown: F,
    ) -> std::io::Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        self.run_with_shutdown(listener, shutdown).await
    }

    async fn run_with_shutdown<F>(
        self,
        listener: tokio::net::TcpListener,
        shutdown: F,
    ) -> std::io::Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let drain_timeout = self.config.shutdown.drain_timeout;
        let mut tasks = spawn_owned_workers(self.workers, self.runtime.clone());
        let serving = crate::runtime::serve(listener, self.router, self.runtime.clone());
        tokio::pin!(serving);
        tokio::pin!(shutdown);
        tokio::select! {
            biased;
            _ = &mut shutdown => {}
            _ = self.runtime.cancelled() => {}
            result = &mut serving => {
                self.runtime.begin_shutdown();
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                return result;
            }
            _ = tasks.join_next() => {
                self.runtime.begin_shutdown();
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                return Err(std::io::Error::other("owned worker exited unexpectedly"));
            }
        }
        self.runtime.begin_shutdown();
        let joined = async {
            let (serving_result, worker_result, ()) = tokio::join!(
                &mut serving,
                join_owned_workers(&mut tasks),
                self.runtime.wait_for_idle(),
            );
            serving_result?;
            worker_result
        };
        match tokio::time::timeout(drain_timeout, joined).await {
            Ok(result) => result,
            Err(_) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                Ok(())
            }
        }
    }
}

async fn join_owned_workers(tasks: &mut JoinSet<()>) -> std::io::Result<()> {
    while let Some(result) = tasks.join_next().await {
        result.map_err(|_| std::io::Error::other("owned worker exited unexpectedly"))?;
    }
    Ok(())
}

fn spawn_owned_workers(workers: WorkerComponents, runtime: Arc<Runtime>) -> JoinSet<()> {
    let mut tasks = JoinSet::new();
    let workers = Arc::new(workers);
    tasks.spawn(outbox_enqueue_loop(workers.clone(), runtime.clone()));
    tasks.spawn(outbox_reconciliation_loop(workers.clone(), runtime.clone()));
    tasks.spawn(shared_transport_loop(workers.clone(), runtime.clone()));
    tasks.spawn(observer_loop(workers, runtime));
    tasks
}

async fn shared_transport_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let mut interval = tokio::time::interval(workers.outbox_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = runtime.cancelled() => break,
            _ = interval.tick() => {}
        }
        let Ok(creators) = workers.creators.ready_ids().await else {
            runtime.set_paykit_transport_available(false);
            continue;
        };
        let mut available = true;
        let mut deferred = false;
        for creator in creators {
            if !runtime.may_start_worker_claim() {
                return;
            }
            let maintained = match creator_adapter(&workers, creator).await {
                Ok(adapter) => match adapter.maintain_transport().await {
                    Ok(()) => true,
                    Err(error) if error.is_concurrent_update() => {
                        deferred = true;
                        true
                    }
                    Err(_) => false,
                },
                Err(_) => false,
            };
            if !maintained {
                available = false;
                tracing::warn!(
                    stage = "shared_transport",
                    "Paykit transport maintenance failed"
                );
            }
        }
        // Contention is retried by the next poll, not evidence of recovery or failure.
        if !available || !deferred {
            runtime.set_paykit_transport_available(available);
        }
    }
}

fn outbox_batch_size(config: &OutboxConfig) -> i64 {
    i64::from(config.batch_size)
}

#[derive(Clone, Copy)]
enum AdapterBuildError {
    Permanent,
    Unavailable,
}

async fn creator_adapter(
    workers: &WorkerComponents,
    creator_id: Uuid,
) -> Result<PaykitAdapter, AdapterBuildError> {
    let credentials =
        workers
            .creators
            .load_by_id(creator_id)
            .await
            .map_err(|error| match error {
                PersistenceError::CorruptOrMissing => AdapterBuildError::Permanent,
                _ => AdapterBuildError::Unavailable,
            })?;
    let creator = credentials.creator().clone();
    let sessions = workers.sessions.provider(&creator);
    PaykitAdapter::new(creator_id, sessions, &workers.paykit)
        .map_err(|_| AdapterBuildError::Permanent)
}

fn retry_delay(initial: Duration, maximum: Duration, attempt_count: i32) -> Duration {
    let exponent = u32::try_from(attempt_count.saturating_sub(1))
        .unwrap_or_default()
        .min(31);
    initial.saturating_mul(1_u32 << exponent).min(maximum)
}

const RAPID_LINK_ESTABLISHMENT_RETRY_ATTEMPTS: i32 = 20;
const RAPID_LINK_ESTABLISHMENT_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_LINK_ESTABLISHMENT_RETRY_DELAY: Duration = Duration::from_secs(5);

fn outbox_retry_schedule(
    initial: Duration,
    maximum: Duration,
    attempt_count: i32,
) -> RetrySchedule {
    let default = retry_delay(initial, maximum, attempt_count);
    let link_establishment = if attempt_count <= RAPID_LINK_ESTABLISHMENT_RETRY_ATTEMPTS {
        RAPID_LINK_ESTABLISHMENT_RETRY_DELAY
    } else {
        retry_delay(
            initial,
            maximum,
            attempt_count - RAPID_LINK_ESTABLISHMENT_RETRY_ATTEMPTS,
        )
        .min(MAX_LINK_ESTABLISHMENT_RETRY_DELAY)
    };
    RetrySchedule::new(default, link_establishment)
}

async fn outbox_enqueue_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let owner = Uuid::new_v4();
    let mut next_poll_delay = Duration::ZERO;
    loop {
        tokio::select! {
            _ = runtime.cancelled() => break,
            _ = tokio::time::sleep(next_poll_delay) => {}
        }
        if !runtime.may_start_worker_claim() {
            break;
        }
        let claims = match workers
            .outbox
            .claim(
                owner,
                workers.outbox_batch_size,
                workers.outbox_lease_duration,
            )
            .await
        {
            Ok(claims) => {
                runtime.set_outbox_enqueue_available(true);
                claims
            }
            Err(_) => {
                runtime.set_outbox_enqueue_available(false);
                next_poll_delay = workers.outbox_poll_interval;
                continue;
            }
        };
        let mut batch = JoinSet::new();
        for claim in claims {
            let workers = workers.clone();
            batch.spawn(async move {
                let retry_schedule = outbox_retry_schedule(
                    workers.outbox_retry_initial,
                    workers.outbox_retry_max,
                    claim.attempt_count(),
                );
                match creator_adapter(&workers, claim.creator_id()).await {
                    Ok(adapter) => {
                        process_claim_with_health(&workers.outbox, &adapter, &claim, retry_schedule)
                            .await
                    }
                    Err(AdapterBuildError::Permanent) => workers
                        .outbox
                        .mark_permanently_failed(&claim)
                        .await
                        .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
                    Err(AdapterBuildError::Unavailable) => workers
                        .outbox
                        .mark_retryable(
                            &claim,
                            retry_schedule.default_delay(),
                            OutboxRetryClass::AdapterUnavailable,
                        )
                        .await
                        .map(|transitioned| {
                            (
                                transitioned,
                                ProcessingHealth::Retryable(retry_schedule.default_delay()),
                            )
                        }),
                }
            });
        }
        let mut delivery_available = true;
        let mut outbox_available = true;
        next_poll_delay = workers.outbox_poll_interval;
        while let Some(result) = batch.join_next().await {
            match result {
                Ok(Ok((_, ProcessingHealth::Available))) => {}
                Ok(Ok((_, ProcessingHealth::Retryable(delay)))) => {
                    delivery_available = false;
                    next_poll_delay = next_poll_delay.min(delay);
                }
                Ok(Ok((_, ProcessingHealth::PermanentFailure))) => {
                    delivery_available = false;
                }
                Ok(Err(_)) => outbox_available = false,
                Err(_) => panic!("owned outbox claim task exited unexpectedly"),
            }
        }
        match workers.outbox.delivery_available().await {
            Ok(persisted_available) => {
                delivery_available &= persisted_available;
            }
            Err(_) => {
                delivery_available = false;
                outbox_available = false;
            }
        }
        runtime.set_paykit_enqueue_available(delivery_available);
        runtime.set_outbox_enqueue_available(outbox_available);
    }
}

async fn outbox_reconciliation_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let owner = Uuid::new_v4();
    let mut interval = tokio::time::interval(workers.outbox_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = runtime.cancelled() => break,
            _ = interval.tick() => {}
        }
        if !runtime.may_start_worker_claim() {
            break;
        }
        let claims = match workers
            .outbox
            .claim_reconciliation(
                owner,
                workers.outbox_batch_size,
                workers.outbox_lease_duration,
            )
            .await
        {
            Ok(claims) => {
                runtime.set_outbox_reconciliation_available(true);
                claims
            }
            Err(_) => {
                runtime.set_outbox_reconciliation_available(false);
                continue;
            }
        };
        let mut batch = JoinSet::new();
        for claim in claims {
            let workers = workers.clone();
            batch.spawn(async move {
                let delay = retry_delay(
                    workers.outbox_retry_initial,
                    workers.outbox_retry_max,
                    claim.attempt_count(),
                );
                match creator_adapter(&workers, claim.creator_id()).await {
                    Ok(adapter) => {
                        process_reconciliation_with_health(&workers.outbox, &adapter, &claim, delay)
                            .await
                    }
                    Err(AdapterBuildError::Permanent) => workers
                        .outbox
                        .mark_reconciliation_permanently_failed(&claim)
                        .await
                        .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
                    Err(AdapterBuildError::Unavailable) => workers
                        .outbox
                        .retry_reconciliation(&claim, delay, OutboxRetryClass::AdapterUnavailable)
                        .await
                        .map(|transitioned| (transitioned, ProcessingHealth::Retryable(delay))),
                }
            });
        }
        let mut delivery_available = true;
        let mut outbox_available = true;
        while let Some(result) = batch.join_next().await {
            match result {
                Ok(Ok((_, ProcessingHealth::Available))) => {}
                Ok(Ok((
                    _,
                    ProcessingHealth::Retryable(_) | ProcessingHealth::PermanentFailure,
                ))) => {
                    delivery_available = false;
                }
                Ok(Err(_)) => outbox_available = false,
                Err(_) => panic!("owned outbox reconciliation task exited unexpectedly"),
            }
        }
        match workers.outbox.delivery_available().await {
            Ok(persisted_available) => {
                delivery_available &= persisted_available;
            }
            Err(_) => {
                delivery_available = false;
                outbox_available = false;
            }
        }
        runtime.set_paykit_reconciliation_available(delivery_available);
        runtime.set_outbox_reconciliation_available(outbox_available);
    }
}

async fn observer_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let mut interval = tokio::time::interval(workers.electrum_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = runtime.cancelled() => break,
            _ = interval.tick() => {}
        }
        if !runtime.may_start_worker_claim() {
            break;
        }
        let targets = match workers.invoices.observation_targets().await {
            Ok(targets) => targets,
            Err(_) => {
                runtime.set_electrum_available(false);
                continue;
            }
        };
        if targets.is_empty() {
            runtime.set_electrum_available(true);
            continue;
        }
        runtime.set_electrum_available(
            observe_once(
                workers.electrum.as_ref(),
                &workers.invoices,
                &workers.bitcoin_network,
                &targets,
            )
            .await
            .is_ok(),
        );
    }
}

fn configured_pubky(network: PaykitNetwork) -> Result<Pubky, ServerBuildError> {
    match network {
        PaykitNetwork::Mainnet => Pubky::new(),
        PaykitNetwork::Testnet => Pubky::testnet(),
    }
    .map_err(|_| ServerBuildError::Pubky)
}

fn map_electrum_error(_: ObserverError) -> ServerBuildError {
    ServerBuildError::Electrum
}

#[derive(Clone)]
struct CreatorSessionValidator {
    creators: CreatorStore,
    sessions: CreatorSessions,
}

#[async_trait]
impl SessionValidator for CreatorSessionValidator {
    async fn validate(&self, creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        if !self
            .creators
            .setup_complete(creator)
            .await
            .map_err(|_| SessionValidationError::Unavailable)?
        {
            return Err(SessionValidationError::Invalid);
        }
        let provider = self.sessions.provider(creator);
        let access = provider
            .load_session_access()
            .await
            .map_err(map_session_validation_error)?
            .ok_or(SessionValidationError::Invalid)?;
        access
            .session
            .revalidate()
            .await
            .map_err(|error| classify_pubky_session_error(&error))?
            .ok_or(SessionValidationError::Invalid)?;
        let owner = access
            .public_key()
            .and_then(|key| key.to_public_key())
            .map_err(map_session_validation_error)?;
        let registry =
            paykit_lib::get_paykit_app_registry(&access.outbox_client.public_storage(), &owner)
                .await
                .map_err(|_| SessionValidationError::Unavailable)?
                .ok_or(SessionValidationError::Invalid)?;
        let key = access
            .paykit_identity_secret_key
            .as_ref()
            .ok_or(SessionValidationError::Invalid)?;
        crate::real_setup::verify_registry_key(&registry, key)
            .map_err(|_| SessionValidationError::Invalid)?;
        let app_id =
            paykit_lib::PaykitAppId::new(crate::config::PAYKIT_APP_ID).expect("static app id");
        if registry.apps().get(&app_id) != Some(&crate::real_setup::server_app()) {
            return Err(SessionValidationError::Invalid);
        }
        use paykit_sdk::StorageAdapter;
        paykit_sdk::PubkySharedStateStorage::new(provider)
            .transaction(|tx| Ok(tx.load_identity_state()))
            .await
            .map_err(map_session_validation_error)?
            .ok_or(SessionValidationError::Invalid)?;
        Ok(())
    }
}

fn map_session_validation_error(error: PaykitSdkError) -> SessionValidationError {
    match error {
        PaykitSdkError::Identity { source, .. } => match source {
            None => SessionValidationError::Invalid,
            Some(source) => match source.downcast_ref::<pubky::Error>() {
                Some(error) => classify_pubky_session_error(error),
                None => SessionValidationError::Unavailable,
            },
        },
        PaykitSdkError::Protocol { .. } | PaykitSdkError::Policy { .. } => {
            SessionValidationError::Invalid
        }
        _ => SessionValidationError::Unavailable,
    }
}

fn classify_pubky_session_error(error: &pubky::Error) -> SessionValidationError {
    match error {
        pubky::Error::Authentication(_) | pubky::Error::Parse(_) => SessionValidationError::Invalid,
        pubky::Error::Request(RequestError::Validation { .. }) => SessionValidationError::Invalid,
        // Untyped HTTP errors cannot distinguish revoked grants from recoverable PoP failures.
        pubky::Error::Request(_) | pubky::Error::Pkarr(_) | pubky::Error::Build(_) => {
            SessionValidationError::Unavailable
        }
    }
}

#[derive(Clone)]
struct PubkyLockFetcher {
    storage: pubky::PublicStorage,
    max_bytes: u64,
    timeout: Duration,
}

#[async_trait]
impl LockFetcher for PubkyLockFetcher {
    async fn fetch(&self, resource: &PubkyLockResource) -> Result<ContentLock, LockFetchError> {
        tokio::time::timeout(self.timeout, self.fetch_inner(resource))
            .await
            .map_err(|_| LockFetchError::Unavailable)?
    }
}

impl PubkyLockFetcher {
    async fn fetch_inner(
        &self,
        resource: &PubkyLockResource,
    ) -> Result<ContentLock, LockFetchError> {
        let mut response =
            self.storage
                .get(resource.to_string())
                .await
                .map_err(|error| match error {
                    pubky::Error::Request(RequestError::Server { status, .. })
                        if status.as_u16() == 404 =>
                    {
                        LockFetchError::NotFound
                    }
                    _ => LockFetchError::Unavailable,
                })?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| LockFetchError::Unavailable)?
        {
            let next_len = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or(LockFetchError::Invalid)?;
            if u64::try_from(next_len).map_err(|_| LockFetchError::Invalid)? > self.max_bytes {
                return Err(LockFetchError::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        let lock: ContentLock =
            serde_json::from_slice(&bytes).map_err(|_| LockFetchError::Invalid)?;
        let path = lock
            .content_lock_path()
            .map_err(|_| LockFetchError::Invalid)?;
        if format!("{}{}", resource.creator(), path) != resource.to_string() {
            return Err(LockFetchError::Invalid);
        }
        Ok(lock)
    }
}

#[derive(Clone)]
struct PubkyAppRegistryDiscovery {
    storage: pubky::PublicStorage,
}

#[async_trait]
impl AppRegistryDiscovery for PubkyAppRegistryDiscovery {
    async fn discover(
        &self,
        reader: &ReaderPubky,
    ) -> Result<Option<PaykitAppRegistry>, CreateInvoiceError> {
        let reader = PubkyPublicKey::from_raw_or_app_key(reader.to_string())
            .and_then(|key| key.to_public_key())
            .map_err(|_| CreateInvoiceError::InvalidRequest)?;
        get_paykit_app_registry(&self.storage, &reader)
            .await
            .map_err(|_| CreateInvoiceError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn setup_auth_relay_matches_the_configured_pubky_network() {
        for (network, expected_relay) in [
            (PaykitNetwork::Testnet, "http://127.0.0.1:15412/inbox"),
            (PaykitNetwork::Mainnet, "https://httprelay.pubky.app/inbox"),
        ] {
            let bootstrap =
                setup_bootstrap(Pubky::testnet().unwrap(), "app.paykit.server", network).unwrap();
            let request = bootstrap
                .start_sign_in_auth(crate::bitkit_claim::LOCAL_DEMO_CAPABILITIES)
                .await
                .unwrap();
            let details = paykit_sdk::parse_pubky_auth_url(request.authorization_url()).unwrap();
            assert_eq!(details.relay_url, expected_relay);
        }
    }
    use crate::config::ConfigEnvironment;

    const CONFIG_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
    const CONFIG_MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    #[test]
    fn invalid_grant_session_is_invalid_not_dependency_unavailable() {
        let error = PaykitSdkError::Identity {
            context: "expired grant".into(),
            source: None,
        };
        assert_eq!(
            map_session_validation_error(error),
            SessionValidationError::Invalid
        );
    }

    #[tokio::test]
    async fn untyped_pubky_unauthorized_restore_does_not_require_setup() {
        struct UnauthorizedSession(&'static str);

        #[async_trait]
        impl SessionValidator for UnauthorizedSession {
            async fn validate(&self, _: &CreatorPubky) -> Result<(), SessionValidationError> {
                Err(map_session_validation_error(PaykitSdkError::Identity {
                    context: "restore Pubky grant session".into(),
                    source: Some(
                        pubky::Error::Request(RequestError::Server {
                            status: pubky::StatusCode::UNAUTHORIZED,
                            message: self.0.into(),
                        })
                        .into(),
                    ),
                }))
            }
        }

        let creator = crate::domain::locks::parse_creator(CONFIG_KEY).unwrap();
        for message in [
            "invalid PoP proof: PoP audience mismatch",
            "invalid PoP proof: PoP timestamp out of range",
            "PoP nonce already used",
            "Grant has been revoked",
            "Unauthorized",
        ] {
            let sessions = Arc::new(UnauthorizedSession(message));
            assert_eq!(
                sessions.validate(&creator).await,
                Err(SessionValidationError::Unavailable)
            );
            assert_eq!(
                SetupStatusService::new(sessions).status(&creator).await,
                crate::application::setup_status::SetupStatus::Unavailable
            );
        }
    }

    #[test]
    fn transient_pubky_server_errors_remain_unavailable() {
        for status in [
            pubky::StatusCode::MISDIRECTED_REQUEST,
            pubky::StatusCode::SERVICE_UNAVAILABLE,
            pubky::StatusCode::TOO_MANY_REQUESTS,
        ] {
            let error = PaykitSdkError::Identity {
                context: "restore Pubky grant session".into(),
                source: Some(
                    pubky::Error::Request(pubky::errors::RequestError::Server {
                        status,
                        message: "temporary outage".into(),
                    })
                    .into(),
                ),
            };

            assert_eq!(
                map_session_validation_error(error),
                SessionValidationError::Unavailable
            );
        }
    }

    #[test]
    fn definitive_pubky_auth_parse_and_validation_errors_are_invalid() {
        for error in [
            pubky::Error::Authentication(pubky::errors::AuthError::RequestExpired),
            pubky::Error::Parse(url::ParseError::EmptyHost),
            pubky::Error::Request(pubky::errors::RequestError::Validation {
                message: "malformed stored grant".into(),
            }),
        ] {
            assert_eq!(
                map_session_validation_error(PaykitSdkError::Identity {
                    context: "restore Pubky grant session".into(),
                    source: Some(error.into()),
                }),
                SessionValidationError::Invalid
            );
        }
    }

    #[test]
    fn link_establishment_retry_delay_is_capped_below_general_backoff() {
        let initial = Duration::from_secs(1);
        let maximum = Duration::from_secs(300);

        for attempt in 1..=RAPID_LINK_ESTABLISHMENT_RETRY_ATTEMPTS {
            let schedule = outbox_retry_schedule(initial, maximum, attempt);
            assert_eq!(
                schedule.delay_for(OutboxRetryClass::LinkEstablishment),
                Duration::from_secs(1)
            );
        }

        assert_eq!(
            outbox_retry_schedule(initial, maximum, 21)
                .delay_for(OutboxRetryClass::LinkEstablishment),
            Duration::from_secs(1)
        );
        assert_eq!(
            outbox_retry_schedule(initial, maximum, 22)
                .delay_for(OutboxRetryClass::LinkEstablishment),
            Duration::from_secs(2)
        );
        assert_eq!(
            outbox_retry_schedule(initial, maximum, 30)
                .delay_for(OutboxRetryClass::LinkEstablishment),
            Duration::from_secs(5)
        );
        assert_eq!(
            outbox_retry_schedule(initial, maximum, 30).default_delay(),
            Duration::from_secs(300)
        );
    }

    #[tokio::test]
    async fn production_spawn_path_owns_all_four_workers() {
        let config = Config::from_toml_and_environment(
            &format!(
                r#"
[http]
listen_addr = "127.0.0.1:0"
[locks]
trusted_public_key = "{CONFIG_KEY}"
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "testnet"
[electrum]
endpoint = "tcp://127.0.0.1:1"
request_timeout = "1s"
connect_retries = 0
[outbox]
poll_interval = "1s"
"#
            ),
            ConfigEnvironment {
                database_url: Some("postgres://127.0.0.1:1/paykit".into()),
                master_key: Some(CONFIG_MASTER_KEY.into()),
            },
        )
        .unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1:1/paykit")
            .unwrap();
        let server = Server::build(config, pool).await.unwrap();
        let mut tasks = spawn_owned_workers(server.workers, server.runtime);
        assert_eq!(tasks.len(), 4);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}
