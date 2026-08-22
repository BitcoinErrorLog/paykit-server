//! Explicit production composition root for one multi-Creator Paykit Server process.

use std::{future::Future, sync::Arc, time::Duration};

use crate::{
    application::{
        create_invoice::{
            CreateInvoiceError, CreateInvoiceService, LockFetchError, LockFetcher, MarkerDiscovery,
            PaykitIntentBuilder, SessionValidationError, SessionValidator,
        },
        create_payment_request::MarketplacePaymentRequestService,
        payment_status::PaymentStatusService,
    },
    bitkit_setup::BitkitAuthStarter,
    config::{Config, OutboxConfig, PaykitConfig, PaykitNetwork},
    crypto::Crypto,
    domain::locks::{CreatorPubky, PubkyLockResource, ReaderPubky},
    http::{self, accounts::AccountsState, auth::SignedLocksAuth},
    manual_claim::{ManualClaimService, RelayLoopbackSessionMinter},
    paykit::{CreatorSessionProvider, PaykitAdapter},
    persistence::{
        CreatorStore, InvoiceStore, OutboxRetryClass, OutboxStore, PersistenceError,
        PostgresStorageAdapter, SdkStateStore,
    },
    real_setup::RealSetupCompleter,
    runtime::{PostgresDependency, Runtime, operational_router},
    setup::{SetupLimits, SetupService, SystemClock},
    setup_orchestration::PubkyCompanionRelay,
    workers::{
        observer::{ElectrumAdapter, ElectrumPort, ObserverError, observe_once},
        outbox::{ProcessingHealth, process_claim_with_health, process_reconciliation_with_health},
    },
};
use async_trait::async_trait;
use axum::{Extension, Router};
use locks_core::lock_policy::ContentLock;
use paykit_lib::{PaykitReceiverMarker, get_paykit_receiver_marker, list_paykit_receiver_paths};
use paykit_sdk::{PubkyPublicKey, PubkySessionBootstrap};
use pubky::{Pubky, PubkySession, errors::RequestError};
use sqlx::PgPool;
use thiserror::Error;
use tokio::{task::JoinSet, time::MissedTickBehavior};
use uuid::Uuid;

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
    pool: PgPool,
    crypto: Arc<Crypto>,
    creators: CreatorStore,
    outbox: OutboxStore,
    invoices: InvoiceStore,
    electrum: Arc<dyn ElectrumPort>,
    pubky: Pubky,
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
            config.electrum.endpoint.clone(),
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

        let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone());
        let relay = Arc::new(PubkyCompanionRelay::new(pubky.client().clone()));
        let setup_completer = Arc::new(RealSetupCompleter::new(
            BitkitAuthStarter::new(bootstrap, &config.paykit.receiver_path),
            relay,
            creators.clone(),
            config.deployment_invariants().bitcoin_network.clone(),
            config.paykit.receiver_path.clone(),
        ));
        let setup = SetupService::new(
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
                max_pending_setup_flows: usize::try_from(
                    config.rate_limits.max_pending_setup_flows,
                )
                .expect("validated pending setup limit fits usize"),
            },
        );

        let invoice_service = Arc::new(CreateInvoiceService::new(
            Arc::new(CreatorSessionValidator {
                creators: creators.clone(),
                pubky: pubky.clone(),
            }),
            Arc::new(PubkyLockFetcher {
                storage: pubky.public_storage(),
                max_bytes: config.limits.lock_resource_bytes,
                timeout: config.limits.lock_fetch_timeout,
            }),
            Arc::new(PubkyMarkerDiscovery {
                storage: pubky.public_storage(),
            }),
            config.paykit.receiver_path_priority.clone(),
            config.paykit.receiver_path.clone(),
            Arc::new(creators.clone()),
            config.deployment_invariants().bitcoin_network.clone(),
            Arc::new(invoices.clone()),
            Arc::new(PaykitIntentBuilder::for_network(
                &config.deployment_invariants().bitcoin_network,
            )),
        ));
        let status_service = Arc::new(PaymentStatusService::new(Arc::new(invoices.clone())));
        let payment_request_service = Arc::new(MarketplacePaymentRequestService::new(
            Arc::new(CreatorSessionValidator {
                creators: creators.clone(),
                pubky: pubky.clone(),
            }),
            Arc::new(PubkyMarkerDiscovery {
                storage: pubky.public_storage(),
            }),
            config.paykit.receiver_path_priority.clone(),
            config.paykit.receiver_path.clone(),
            Arc::new(creators.clone()),
            config.deployment_invariants().bitcoin_network.clone(),
            Arc::new(invoices.clone()),
            Arc::new(PaykitIntentBuilder::for_network(
                &config.deployment_invariants().bitcoin_network,
            )),
        ));
        let manual_claims = Arc::new(ManualClaimService::new(
            pubky.clone(),
            Arc::new(RelayLoopbackSessionMinter::new(
                pubky.clone(),
                config.paykit.auth_relay.clone(),
            )),
            creators.clone(),
            Arc::new(crate::real_setup::DirectMarkerPublisher),
            config.deployment_invariants().bitcoin_network.clone(),
            config.paykit.receiver_path.clone(),
        ));
        let accounts_state = AccountsState::new(
            manual_claims,
            config.rate_limits.claims_per_minute,
            config.setup.allowed_origins.clone(),
        );
        let signed_auth = Arc::new(SignedLocksAuth::from_config(&config));
        let business_routes = http::setup::setup_router(setup)
            .merge(http::accounts::accounts_router(accounts_state))
            .merge(
                http::invoices::invoices_router(invoice_service)
                    .merge(http::status::status_router(status_service))
                    .merge(http::payment_requests::payment_requests_router(
                        payment_request_service,
                    ))
                    .layer(Extension(signed_auth)),
            );

        let runtime = Arc::new(Runtime::new(
            Arc::new(PostgresDependency::new(pool.clone())),
            64,
        ));
        let router = operational_router(business_routes, runtime.clone());
        let workers = WorkerComponents {
            pool,
            crypto,
            creators,
            outbox,
            invoices,
            electrum,
            pubky,
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
    tasks.spawn(observer_loop(workers, runtime));
    tasks
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
    SdkStateStore::new(&workers.pool, workers.crypto.clone())
        .load(&creator)
        .await
        .map_err(|error| match error {
            PersistenceError::CorruptOrMissing => AdapterBuildError::Permanent,
            _ => AdapterBuildError::Unavailable,
        })?;
    let storage = PostgresStorageAdapter::new(&workers.pool, workers.crypto.clone(), creator_id);
    let sessions = CreatorSessionProvider::with_pubky(
        workers.creators.clone(),
        creator,
        workers.pubky.clone(),
    );
    PaykitAdapter::new(storage, sessions, &workers.paykit).map_err(|_| AdapterBuildError::Permanent)
}

fn retry_delay(initial: Duration, maximum: Duration, attempt_count: i32) -> Duration {
    let exponent = u32::try_from(attempt_count.saturating_sub(1))
        .unwrap_or_default()
        .min(31);
    initial.saturating_mul(1_u32 << exponent).min(maximum)
}

async fn outbox_enqueue_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
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
                        process_claim_with_health(&workers.outbox, &adapter, &claim, delay).await
                    }
                    Err(AdapterBuildError::Permanent) => workers
                        .outbox
                        .mark_permanently_failed(&claim)
                        .await
                        .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
                    Err(AdapterBuildError::Unavailable) => workers
                        .outbox
                        .mark_retryable(&claim, delay, OutboxRetryClass::AdapterUnavailable)
                        .await
                        .map(|transitioned| (transitioned, ProcessingHealth::Retryable)),
                }
            });
        }
        let mut delivery_available = true;
        let mut outbox_available = true;
        while let Some(result) = batch.join_next().await {
            match result {
                Ok(Ok((_, ProcessingHealth::Available))) => {}
                Ok(Ok((_, ProcessingHealth::Retryable | ProcessingHealth::PermanentFailure))) => {
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
                        .map(|transitioned| (transitioned, ProcessingHealth::Retryable)),
                }
            });
        }
        let mut delivery_available = true;
        let mut outbox_available = true;
        while let Some(result) = batch.join_next().await {
            match result {
                Ok(Ok((_, ProcessingHealth::Available))) => {}
                Ok(Ok((_, ProcessingHealth::Retryable | ProcessingHealth::PermanentFailure))) => {
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
    pubky: Pubky,
}

#[async_trait]
impl SessionValidator for CreatorSessionValidator {
    async fn validate(&self, creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        let credentials = self
            .creators
            .load(creator)
            .await
            .map_err(|error| match error {
                crate::persistence::PersistenceError::CorruptOrMissing => {
                    SessionValidationError::Invalid
                }
                _ => SessionValidationError::Unavailable,
            })?;
        let session = PubkySession::import_secret(
            credentials.session_secret(),
            Some(self.pubky.client().clone()),
        )
        .await
        .map_err(map_session_import_error)?;
        let expected = PubkyPublicKey::from_raw_or_app_key(creator.to_string())
            .map_err(|_| SessionValidationError::Invalid)?;
        let actual = PubkyPublicKey::from_public_key(session.info().public_key());
        if actual != expected {
            return Err(SessionValidationError::Invalid);
        }
        Ok(())
    }
}

fn map_session_import_error(error: pubky::Error) -> SessionValidationError {
    match error {
        pubky::Error::Authentication(_) | pubky::Error::Parse(_) => SessionValidationError::Invalid,
        _ => SessionValidationError::Unavailable,
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
struct PubkyMarkerDiscovery {
    storage: pubky::PublicStorage,
}

#[async_trait]
impl MarkerDiscovery for PubkyMarkerDiscovery {
    async fn discover(
        &self,
        reader: &ReaderPubky,
    ) -> Result<Vec<PaykitReceiverMarker>, CreateInvoiceError> {
        let reader = PubkyPublicKey::from_raw_or_app_key(reader.to_string())
            .and_then(|key| key.to_public_key())
            .map_err(|_| CreateInvoiceError::InvalidRequest)?;
        let paths = list_paykit_receiver_paths(&self.storage, &reader)
            .await
            .map_err(|_| CreateInvoiceError::Unavailable)?;
        let mut markers = Vec::with_capacity(paths.len());
        for path in paths {
            if let Some(marker) = get_paykit_receiver_marker(&self.storage, &reader, &path)
                .await
                .map_err(|_| CreateInvoiceError::Unavailable)?
            {
                markers.push(marker);
            }
        }
        Ok(markers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigEnvironment;

    const CONFIG_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
    const CONFIG_MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    #[test]
    fn expired_persisted_session_is_invalid_not_dependency_unavailable() {
        let error = pubky::Error::Authentication(pubky::errors::AuthError::RequestExpired);
        assert_eq!(
            map_session_import_error(error),
            SessionValidationError::Invalid
        );
    }

    #[tokio::test]
    async fn production_spawn_path_owns_all_three_workers() {
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
receiver_path = "paykit/server"
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
        assert_eq!(tasks.len(), 3);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}
