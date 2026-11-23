//! Explicit production composition root for one multi-Creator Paykit Server process.

use std::{
    collections::BTreeSet,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    application::{
        connection_status::ConnectionStatusService,
        create_invoice::{
            AppRegistryDiscovery, CreateInvoiceService, LockFetchError, LockFetcher,
            PaykitIntentBuilder, ReaderAuthorization, RegistryDiscoveryError,
            SessionValidationError, SessionValidator,
        },
        marketplace_lifecycle::MarketplaceLifecycleService,
        marketplace_preparation::PrepareMarketplaceService,
        marketplace_receipt::MarketplaceReceiptService,
        marketplace_status::MarketplaceStatusService,
        payment_drain::{
            PaymentDrainCleanupToken, PaymentDrainError, PaymentDrainOperations,
            PaymentDrainSummary,
        },
        payment_request_status::{
            PaymentRequestStatusError, PaymentRequestStatusOperations, PaymentRequestStatusSummary,
        },
        payment_status::PaymentStatusService,
        provider_v2::ProviderV2Service,
        setup_status::SetupStatusService,
    },
    bitkit_setup::BitkitAuthStarter,
    config::{Config, OutboxConfig, PaykitConfig, PaykitNetwork},
    crypto::Crypto,
    domain::locks::{BundleId, CreatorPubky, PubkyLockResource, ReaderPubky},
    http::{self, auth::SignedServiceAuth},
    paykit::{
        ALLOWANCE_INTAKE_COOLDOWN, ALLOWANCE_INTAKE_PASS_DEADLINE, AllowanceIntake,
        CreatorSessions, IntakeTurns, PaykitAdapter, SELLER_RECEIPT_READ_INTERVAL,
        SellerReceiptReads, TransportMaintenanceError, creator_mutation_lock, sdk_error_label,
    },
    persistence::{
        CreatorStore, InvoiceStore, MarketplacePreparationStore, OutboxRetryClass, OutboxStore,
        PaymentDrainStore, PaymentRequestLifecycleStore, PersistenceError,
    },
    real_setup::RealSetupCompleter,
    runtime::{PostgresDependency, Runtime, operational_router},
    setup::{SetupLimits, SetupService, SystemClock},
    setup_orchestration::PubkyCompanionRelay,
    workers::{
        creator_tasks::CreatorTasks,
        observer::{
            ElectrumAdapter, ElectrumPort, ObserverError, observe_marketplace_once, observe_once,
        },
        outbox::{
            ProcessingHealth, RetrySchedule, process_claim_with,
            process_reconciliation_with_health, with_claim_renewal,
        },
    },
};
use async_trait::async_trait;
use axum::{Extension, Router};
use locks_core::lock_policy::ContentLock;
use paykit_lib::{
    PaykitAppRegistry, PaykitError, get_paykit_app_registry, get_paykit_noise_key_authorization,
};
use paykit_sdk::{PaykitSdkError, PubkyPublicKey, PubkySessionBootstrap, PubkySessionProvider};
use pubky::{Pubky, errors::RequestError};
use sqlx::PgPool;
use thiserror::Error;
use tokio::{task::JoinSet, time::MissedTickBehavior};
use url::Url;
use uuid::Uuid;

fn setup_bootstrap(
    pubky: Pubky,
    client_id: &str,
    network: PaykitNetwork,
    auth_relay: Option<&Url>,
) -> Result<PubkySessionBootstrap, ServerBuildError> {
    let bootstrap =
        PubkySessionBootstrap::with_pubky(pubky, client_id).map_err(|_| ServerBuildError::Pubky)?;
    let relay = match (auth_relay, network) {
        (Some(relay), _) => relay.as_str(),
        (None, PaykitNetwork::Mainnet) => return Ok(bootstrap),
        (None, PaykitNetwork::Testnet) => "http://127.0.0.1:15412/inbox",
    };
    bootstrap
        .with_auth_relay(relay)
        .map_err(|_| ServerBuildError::Pubky)
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
    #[error("could not construct Arbitrum verification")]
    Arbitrum,
    #[error("could not construct exchange-rate client")]
    ExchangeRates,
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
    marketplace_preparations: Arc<MarketplacePreparationStore>,
    payment_request_lifecycles: PaymentRequestLifecycleStore,
    electrum: Arc<dyn ElectrumPort>,
    usdt: Option<crate::usdt::ArbitrumVerifier>,
    paykit: PaykitConfig,
    bitcoin_network: crate::config::BitcoinNetwork,
    outbox_poll_interval: Duration,
    outbox_batch_size: i64,
    outbox_lease_duration: Duration,
    outbox_retry_initial: Duration,
    outbox_retry_max: Duration,
    rapid_link_retry_attempts: u32,
    rapid_link_retry_interval: Duration,
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
        let payment_request_lifecycles = PaymentRequestLifecycleStore::new(&pool, crypto.clone());
        let payment_drains = PaymentDrainStore::new(&pool, crypto.clone());
        let marketplace_preparations =
            Arc::new(MarketplacePreparationStore::new(&pool, crypto.clone()));

        let bootstrap = setup_bootstrap(
            pubky.clone(),
            config.paykit.client_id.as_str(),
            config.paykit.network,
            config.setup.auth_relay.as_ref(),
        )?;
        let relay = Arc::new(PubkyCompanionRelay::new(pubky.client().clone()));
        let sessions = CreatorSessions::new(creators.clone(), pubky.clone(), config.paykit.clone());
        let mut auth_starter = BitkitAuthStarter::new(bootstrap);
        let usdt = config
            .usdt
            .as_ref()
            .map(|config| crate::usdt::ArbitrumVerifier::new(config.rpc_url.clone()))
            .transpose()
            .map_err(|_| ServerBuildError::Arbitrum)?;
        if config.usdt.is_some() {
            auth_starter = auth_starter.with_usdt();
        }
        let setup_completer = Arc::new(
            RealSetupCompleter::new(
                auth_starter,
                relay,
                creators.clone(),
                sessions.clone(),
                config.deployment_invariants().bitcoin_network.clone(),
            )
            .with_bitcoin_rotation(payment_request_lifecycles.clone(), config.paykit.clone()),
        );
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
                creator_held_per_ip_per_minute: usize::try_from(
                    config.rate_limits.creator_held_per_ip_per_minute,
                )
                .expect("validated creator-held rate limit fits usize"),
                max_pending_setup_flows: config.rate_limits.max_pending_setup_flows(),
            },
            config.setup.log_authorization_url,
        )
        .with_bitcoin_network(config.deployment_invariants().bitcoin_network.clone());

        let session_validator = Arc::new(CreatorSessionValidator {
            creators: creators.clone(),
            sessions: sessions.clone(),
            identity_states: IdentityStateReads::default(),
        });
        let exchange_rates: Arc<dyn crate::application::invoice_pricing::ExchangeRates> = Arc::new(
            crate::application::invoice_pricing::FeedRates::new(&config.exchange_rate)
                .map_err(|_| ServerBuildError::ExchangeRates)?,
        );
        let invoice_service = Arc::new(
            CreateInvoiceService::with_invoice_windows(
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
                config.paykit.proposal_acceptance_window,
                config.paykit.payment_window,
            )
            .with_usdt(usdt.is_some())
            .with_conversion_payment_window(config.paykit.conversion_payment_window)
            .with_exchange_rates(exchange_rates.clone()),
        );
        let provider_v2_service = Arc::new(
            ProviderV2Service::new(
                session_validator.clone(),
                Arc::new(PubkyAppRegistryDiscovery {
                    storage: pubky.public_storage(),
                }),
                Arc::new(creators.clone()),
                invoices.clone(),
                config.paykit.app_id.clone(),
                config.deployment_invariants().bitcoin_network.clone(),
                config.paykit.proposal_acceptance_window,
            )
            .with_usdt(usdt.is_some())
            .with_conversion_payment_window(config.paykit.conversion_payment_window)
            .with_exchange_rates(exchange_rates.clone()),
        );
        let marketplace_preparation_service = Arc::new(
            PrepareMarketplaceService::new(
                session_validator.clone(),
                Arc::new(PubkyAppRegistryDiscovery {
                    storage: pubky.public_storage(),
                }),
                Arc::new(creators.clone()),
                marketplace_preparations.clone(),
                config.paykit.app_id.clone(),
                config.deployment_invariants().bitcoin_network.clone(),
                config.paykit.payment_window,
                config.paykit.marketplace_prepare_ttl,
            )
            .with_usdt(usdt.is_some())
            .with_conversion_payment_window(config.paykit.conversion_payment_window)
            .with_exchange_rates(exchange_rates.clone()),
        );
        let marketplace_lifecycle_service = Arc::new(MarketplaceLifecycleService::new(
            marketplace_preparations.clone(),
            config.paykit.proposal_acceptance_window,
        ));
        let marketplace_status_service = Arc::new(MarketplaceStatusService::new(
            marketplace_preparations.clone(),
        ));
        let marketplace_receipt_service = Arc::new(MarketplaceReceiptService::new(
            marketplace_preparations.clone(),
        ));
        let connection_status_service = Arc::new(ConnectionStatusService::new(
            Arc::new(invoices.clone()),
            Arc::new(sessions.clone()),
        ));
        let status_service = Arc::new(PaymentStatusService::new(Arc::new(invoices.clone())));
        let payment_drain_operations: Arc<dyn PaymentDrainOperations> =
            Arc::new(ProductionPaymentDrainOperations {
                crypto: crypto.clone(),
                creators: creators.clone(),
                sessions: sessions.clone(),
                lifecycles: payment_request_lifecycles.clone(),
                drains: payment_drains,
                invoices: invoices.clone(),
                usdt: usdt.clone(),
                paykit: config.paykit.clone(),
            });
        let payment_request_status_operations: Arc<dyn PaymentRequestStatusOperations> =
            Arc::new(ProductionPaymentRequestStatusOperations {
                creators: creators.clone(),
                sessions: sessions.clone(),
                lifecycles: payment_request_lifecycles.clone(),
                statuses: invoices.clone(),
                usdt: usdt.clone(),
                paykit: config.paykit.clone(),
            });
        let setup_status_service = Arc::new(
            SetupStatusService::new(session_validator)
                .with_receiving(Arc::new(creators.clone()), usdt.is_some()),
        );
        let signed_auth = Arc::new(SignedServiceAuth::from_config(&config));
        let business_routes = http::setup::setup_router_with_trusted_proxy_hops(
            setup,
            config.http.trusted_proxy_hops(),
        )
        .merge(
            http::invoices::invoices_router(invoice_service)
                .merge(http::connection_status::connection_status_router(
                    connection_status_service,
                ))
                .merge(
                    http::marketplace_preparation::marketplace_preparation_router(
                        marketplace_preparation_service,
                    ),
                )
                .merge(http::marketplace_lifecycle::marketplace_lifecycle_router(
                    marketplace_lifecycle_service,
                ))
                .merge(http::marketplace_status::marketplace_status_router(
                    marketplace_status_service,
                ))
                .merge(http::marketplace_receipt::marketplace_receipt_router(
                    marketplace_receipt_service,
                ))
                .merge(http::status::status_router(status_service))
                .merge(http::payment_drains::payment_drains_router(
                    payment_drain_operations,
                ))
                .merge(http::payment_requests::payment_requests_router(
                    payment_request_status_operations,
                ))
                .merge(http::provider_v2::provider_v2_router(provider_v2_service))
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
            marketplace_preparations,
            payment_request_lifecycles,
            electrum,
            usdt,
            paykit: config.paykit.clone(),
            bitcoin_network: config.deployment_invariants().bitcoin_network.clone(),
            outbox_poll_interval: config.outbox.poll_interval,
            outbox_batch_size: outbox_batch_size(&config.outbox),
            outbox_lease_duration: config.outbox.lease_duration,
            outbox_retry_initial: config.outbox.retry_initial,
            outbox_retry_max: config.outbox.retry_max,
            rapid_link_retry_attempts: config.outbox.rapid_link_retry_attempts,
            rapid_link_retry_interval: config.outbox.rapid_link_retry_interval,
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
        let (mut tasks, mut settling) = spawn_owned_workers(self.workers, self.runtime.clone());
        let serving = crate::runtime::serve(listener, self.router, self.runtime.clone());
        tokio::pin!(serving);
        tokio::pin!(shutdown);
        enum Stop {
            Shutdown,
            Served(std::io::Result<()>),
            WorkerExited,
            SettlingExited,
        }
        let stop = tokio::select! {
            biased;
            _ = &mut shutdown => Stop::Shutdown,
            _ = self.runtime.cancelled() => Stop::Shutdown,
            result = &mut serving => Stop::Served(result),
            _ = tasks.join_next() => Stop::WorkerExited,
            () = settling_exited(&mut settling) => Stop::SettlingExited,
        };
        match stop {
            Stop::Shutdown => {}
            Stop::Served(result) => {
                self.runtime.begin_shutdown();
                abort_owned_workers(&mut tasks, &mut settling).await;
                return result;
            }
            Stop::WorkerExited => {
                self.runtime.begin_shutdown();
                abort_owned_workers(&mut tasks, &mut settling).await;
                return Err(std::io::Error::other("owned worker exited unexpectedly"));
            }
            // These run until shutdown; returning or panicking before is fatal.
            Stop::SettlingExited => {
                self.runtime.begin_shutdown();
                abort_owned_workers(&mut tasks, &mut settling).await;
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
        let result = match tokio::time::timeout(drain_timeout, joined).await {
            Ok(result) => result,
            Err(_) => Ok(()),
        };
        abort_owned_workers(&mut tasks, &mut settling).await;
        result
    }
}

async fn join_owned_workers(tasks: &mut JoinSet<()>) -> std::io::Result<()> {
    while let Some(result) = tasks.join_next().await {
        result.map_err(|_| std::io::Error::other("owned worker exited unexpectedly"))?;
    }
    Ok(())
}

/// Completes when the root task of Allowance intake or the seller Receipt
/// reader ends, by returning or panicking; never, when neither runs. The
/// ended task leaves the set.
async fn settling_exited(settling: &mut JoinSet<()>) {
    if settling.is_empty() {
        std::future::pending::<()>().await;
    }
    let _ = settling.join_next().await;
}

/// Aborts the abortable owned workers, then waits for Allowance intake and the
/// seller Receipt reader, which are never aborted: their running passes are
/// SDK calls under the shared-state lock that must settle, and they start no
/// new one once shutdown has begun.
async fn abort_owned_workers(tasks: &mut JoinSet<()>, settling: &mut JoinSet<()>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    while settling.join_next().await.is_some() {}
}

/// Spawns the owned workers. Allowance intake and the seller Receipt reader
/// run outside the abortable set, so a drain deadline never drops a running
/// SDK call.
fn spawn_owned_workers(
    workers: WorkerComponents,
    runtime: Arc<Runtime>,
) -> (JoinSet<()>, JoinSet<()>) {
    let mut tasks = JoinSet::new();
    let workers = Arc::new(workers);
    tasks.spawn(outbox_enqueue_loop(workers.clone(), runtime.clone()));
    tasks.spawn(outbox_reconciliation_loop(workers.clone(), runtime.clone()));
    tasks.spawn(lifecycle_reconciliation_loop(
        workers.clone(),
        runtime.clone(),
    ));
    tasks.spawn(shared_transport_loop(workers.clone(), runtime.clone()));
    let mut settling = JoinSet::new();
    if workers.paykit.allowance_intake {
        settling.spawn(allowance_intake_loop(workers.clone(), runtime.clone()));
    }
    if workers.paykit.marketplace_seller_receipts {
        settling.spawn(seller_receipts_loop(workers.clone(), runtime.clone()));
    }
    tasks.spawn(buyer_contacts_loop(workers.clone(), runtime.clone()));
    tasks.spawn(observer_loop(workers, runtime));
    (tasks, settling)
}

async fn buyer_contacts_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let mut interval = tokio::time::interval(workers.outbox_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = runtime.cancelled() => break,
            _ = interval.tick() => {}
        }
        for _ in 0..workers.outbox_batch_size {
            if !runtime.may_start_worker_claim() {
                return;
            }
            let pending = match workers.invoices.claim_buyer_contact().await {
                Ok(Some(pending)) => pending,
                Ok(None) => break,
                Err(_) => {
                    tracing::warn!(
                        stage = "buyer_contact_claim",
                        "Buyer contact work unavailable"
                    );
                    break;
                }
            };
            let saved = match creator_adapter(&workers, pending.creator_id).await {
                Ok(adapter) => adapter
                    .save_buyer_contact(&workers.invoices, &pending)
                    .await
                    .is_ok(),
                Err(_) => false,
            };
            if !saved {
                tracing::warn!(stage = "buyer_contact_save", "Buyer contact save deferred");
            }
        }
    }
}

async fn shared_transport_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let mut interval = tokio::time::interval(workers.outbox_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let hinted_creators = tokio::select! {
            biased;
            _ = runtime.cancelled() => break,
            _ = interval.tick() => None,
            creators = workers.outbox.wait_for_transport() => Some(creators),
        };
        let full_scan = hinted_creators.is_none();
        let creators = match hinted_creators {
            Some(creators) => creators,
            None => match workers.creators.ready_ids().await {
                Ok(creators) => creators,
                Err(error) => {
                    tracing::warn!(
                        stage = "shared_transport",
                        step = "creator_ids_load",
                        category = error.diagnostic_label(),
                        "Paykit transport maintenance unavailable"
                    );
                    runtime.set_paykit_transport_available(false);
                    continue;
                }
            },
        };
        let limit =
            usize::try_from(workers.outbox_batch_size).expect("validated outbox batch size");
        let deferred = maintain_transport_pass(creators, limit, runtime.clone(), |creator| {
            let workers = workers.clone();
            async move { maintain_creator_transport(&workers, creator, full_scan).await }
        })
        .await;
        if !runtime.may_start_worker_claim() {
            return;
        }
        // A targeted pass cannot clear a failed Creator enumeration or deferred work.
        if full_scan && !deferred {
            runtime.set_paykit_transport_available(true);
        }
    }
}

/// Accepts the Allowance proposals invoiced readers leave on the server link.
/// It runs apart from the shared transport loop, one task per Creator, so a
/// slow read delays only that Creator's intake, never transport or another
/// Creator. At most `outbox_batch_size` passes run at once across Creators,
/// and free slots go to the Creator whose last pass started longest ago.
async fn allowance_intake_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let intake = Arc::new(AllowanceIntake::new(ALLOWANCE_INTAKE_COOLDOWN));
    let limit = usize::try_from(workers.outbox_batch_size).expect("validated outbox batch size");
    let mut tasks = CreatorTasks::new(limit, runtime.clone());
    let mut turns = IntakeTurns::default();
    let mut interval = tokio::time::interval(workers.outbox_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = runtime.cancelled() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
            _ = interval.tick() => {}
        }
        if tasks.available_slots() == 0 {
            continue;
        }
        let creators = match workers.creators.ready_ids().await {
            Ok(creators) => creators,
            Err(error) => {
                tracing::warn!(
                    stage = "allowance_intake",
                    step = "creator_ids_load",
                    category = error.diagnostic_label(),
                    "Paykit Allowance intake unavailable"
                );
                continue;
            }
        };
        start_intake_passes(&mut tasks, &mut turns, creators, |creator| {
            allowance_intake_pass(workers.clone(), intake.clone(), runtime.clone(), creator)
        });
    }
    finish_intake_passes(&mut tasks).await;
}

/// Waits for every running pass to end. A pass starts no new read once
/// shutdown begins, and the one it is in is an SDK mutation that must settle:
/// dropping it mid-flight would skip the shared-state unlock and leave state
/// unconfirmed. Pubky requests are bounded by [`PUBKY_REQUEST_TIMEOUT`], so a
/// running read ends in bounded time.
async fn finish_intake_passes(tasks: &mut CreatorTasks<()>) {
    while tasks.join_next().await.is_some() {}
}

/// Starts intake passes in the free slots, least recently started Creator
/// first, skipping Creators whose pass is still running. A pass reads
/// reader-supplied history, so a panic in it is caught in the pass's own
/// future: it is logged and frees the slot instead of stopping the server,
/// and the pass stays owned by the slot, so shutdown waits for it.
fn start_intake_passes<Pass, PassFuture>(
    tasks: &mut CreatorTasks<()>,
    turns: &mut IntakeTurns,
    creators: Vec<Uuid>,
    pass: Pass,
) where
    Pass: FnMut(Uuid) -> PassFuture,
    PassFuture: Future<Output = ()> + Send + 'static,
{
    start_creator_passes("allowance_intake", tasks, turns, creators, pass);
}

/// [`start_intake_passes`] for any per-Creator worker; `stage` names it in
/// the panic log.
fn start_creator_passes<Pass, PassFuture>(
    stage: &'static str,
    tasks: &mut CreatorTasks<()>,
    turns: &mut IntakeTurns,
    creators: Vec<Uuid>,
    mut pass: Pass,
) where
    Pass: FnMut(Uuid) -> PassFuture,
    PassFuture: Future<Output = ()> + Send + 'static,
{
    let running = tasks.active_creators();
    for creator in turns.order(creators) {
        if tasks.available_slots() == 0 {
            break;
        }
        if running.contains(&creator) {
            continue;
        }
        if tasks.try_spawn(creator, contain_panic(stage, pass(creator))) {
            turns.started(creator);
        }
    }
}

/// Runs `pass`, logging a panic in it instead of passing it on.
async fn contain_panic(stage: &'static str, pass: impl Future<Output = ()> + Send) {
    if pass_panicked(pass).await {
        tracing::error!(stage, "Paykit worker pass panicked");
    }
}

async fn pass_panicked(pass: impl Future<Output = ()> + Send) -> bool {
    let mut pass = std::pin::pin!(pass);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pass.as_mut().poll(cx))) {
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Ok(std::task::Poll::Ready(())) => std::task::Poll::Ready(false),
            Err(_) => std::task::Poll::Ready(true),
        }
    })
    .await
}

/// One Creator's intake pass. It is never cut short: each read is an SDK
/// mutation, so the pass deadline only stops new reads from starting.
async fn allowance_intake_pass(
    workers: Arc<WorkerComponents>,
    intake: Arc<AllowanceIntake>,
    runtime: Arc<Runtime>,
    creator: Uuid,
) {
    run_allowance_intake_pass(&workers, &intake, &runtime, creator).await;
}

async fn run_allowance_intake_pass(
    workers: &WorkerComponents,
    intake: &AllowanceIntake,
    runtime: &Runtime,
    creator: Uuid,
) {
    let deadline = Instant::now() + ALLOWANCE_INTAKE_PASS_DEADLINE;
    let keep_reading = || runtime.may_start_worker_claim() && Instant::now() < deadline;
    let failure = match creator_adapter(workers, creator).await {
        Ok(adapter) => match adapter
            .take_in_allowances(intake, &workers.invoices, &keep_reading)
            .await
        {
            Ok(queued) => {
                // The transport worker delivers them, each Creator on its own task.
                if queued > 0 {
                    workers.outbox.wake_transport(creator);
                }
                None
            }
            Err(
                PaykitSdkError::ConcurrentUpdate { .. } | PaykitSdkError::SharedStateBusy { .. },
            ) => None,
            Err(error) => Some(("take_in_allowances", sdk_error_label(&error))),
        },
        Err(error) => Some(("adapter_build", error.diagnostic_label())),
    };
    if let Some((step, category)) = failure {
        tracing::warn!(
            stage = "allowance_intake",
            step,
            category,
            "Paykit Allowance intake failed"
        );
    }
}

/// Reads the Receipts sellers' wallets issue for Marketplace requests. Like
/// Allowance intake it runs one task per Creator, at most `outbox_batch_size`
/// at once, least recently started Creator first. It considers only Creators
/// with an open Marketplace request whose seller Receipt is not stored, and
/// reads each no more often than its spacing allows.
async fn seller_receipts_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let reads = Arc::new(SellerReceiptReads::new(SELLER_RECEIPT_READ_INTERVAL));
    let limit = usize::try_from(workers.outbox_batch_size).expect("validated outbox batch size");
    let mut tasks = CreatorTasks::new(limit, runtime.clone());
    let mut turns = IntakeTurns::default();
    let mut interval = tokio::time::interval(workers.outbox_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = runtime.cancelled() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
            _ = interval.tick() => {}
        }
        if tasks.available_slots() == 0 {
            continue;
        }
        let creators = match workers
            .marketplace_preparations
            .creators_awaiting_seller_receipts()
            .await
        {
            Ok(creators) => creators,
            Err(error) => {
                tracing::warn!(
                    stage = "seller_receipts",
                    step = "creator_ids_load",
                    category = error.diagnostic_label(),
                    "Paykit seller Receipt reads unavailable"
                );
                continue;
            }
        };
        let now = Instant::now();
        let due = creators
            .into_iter()
            .filter(|creator| reads.is_due(*creator, now))
            .collect();
        start_creator_passes("seller_receipts", &mut tasks, &mut turns, due, |creator| {
            seller_receipts_pass(workers.clone(), reads.clone(), runtime.clone(), creator)
        });
    }
    finish_intake_passes(&mut tasks).await;
}

/// One Creator's seller Receipt read. A busy shared state is retried on a
/// later pass without a warning.
async fn seller_receipts_pass(
    workers: Arc<WorkerComponents>,
    reads: Arc<SellerReceiptReads>,
    runtime: Arc<Runtime>,
    creator: Uuid,
) {
    let failure = match creator_adapter(&workers, creator).await {
        Ok(_) if !runtime.may_start_worker_claim() => None,
        Ok(adapter) => match adapter
            .read_seller_receipts(&reads, &workers.marketplace_preparations)
            .await
        {
            Ok(_)
            | Err(
                PaykitSdkError::ConcurrentUpdate { .. } | PaykitSdkError::SharedStateBusy { .. },
            ) => None,
            Err(error) => Some(("issued_receipts", sdk_error_label(&error))),
        },
        Err(error) => Some(("adapter_build", error.diagnostic_label())),
    };
    if let Some((step, category)) = failure {
        tracing::warn!(
            stage = "seller_receipts",
            step,
            category,
            "Paykit seller Receipt read failed"
        );
    }
}

enum TransportMaintenance {
    Complete,
    Deferred,
    Failed {
        step: &'static str,
        category: &'static str,
    },
}

fn transport_maintenance_outcome(
    result: Result<(), TransportMaintenanceError>,
) -> TransportMaintenance {
    match result {
        Ok(()) => TransportMaintenance::Complete,
        Err(TransportMaintenanceError::Deferred) => TransportMaintenance::Deferred,
        Err(TransportMaintenanceError::Failed(category)) => TransportMaintenance::Failed {
            step: "maintain_transport",
            category: category.label(),
        },
    }
}

fn log_transport_maintenance_failure(step: &'static str, category: &'static str) {
    if step == "maintain_transport" && matches!(category, "transport" | "storage") {
        tracing::debug!(
            stage = "shared_transport",
            step,
            category,
            "Paykit transport maintenance failed"
        );
    } else {
        tracing::warn!(
            stage = "shared_transport",
            step,
            category,
            "Paykit transport maintenance failed"
        );
    }
}

fn record_shared_transport_timing(
    full_scan: bool,
    outcome: &TransportMaintenance,
    started: Instant,
) {
    if full_scan && matches!(outcome, TransportMaintenance::Complete) {
        return;
    }
    crate::diagnostics::timing(
        "worker",
        "shared_transport",
        match outcome {
            TransportMaintenance::Complete => crate::diagnostics::TimingOutcome::Completed,
            TransportMaintenance::Deferred => crate::diagnostics::TimingOutcome::Deferred,
            TransportMaintenance::Failed { category, .. }
                if matches!(*category, "transport" | "storage") =>
            {
                crate::diagnostics::TimingOutcome::RoutineFailure
            }
            TransportMaintenance::Failed { .. } => crate::diagnostics::TimingOutcome::Failed,
        },
        started,
    );
}

async fn maintain_transport_pass<Work, WorkFuture>(
    creators: Vec<Uuid>,
    limit: usize,
    runtime: Arc<Runtime>,
    mut maintain: Work,
) -> bool
where
    Work: FnMut(Uuid) -> WorkFuture,
    WorkFuture: Future<Output = TransportMaintenance> + Send + 'static,
{
    let mut tasks = CreatorTasks::new(limit, runtime.clone());
    let mut creators = creators.into_iter();
    let mut deferred = false;
    loop {
        while tasks.available_slots() > 0 && runtime.may_start_worker_claim() {
            let Some(creator) = creators.next() else {
                break;
            };
            tasks.try_spawn(creator, maintain(creator));
        }
        // Drain admitted SDK work even after shutdown stops admission.
        let Some((_, outcome)) = tasks.join_next().await else {
            break;
        };
        match outcome {
            TransportMaintenance::Complete => {}
            TransportMaintenance::Deferred => deferred = true,
            // One Creator's failure must not withdraw every Creator's rail.
            TransportMaintenance::Failed { step, category } => {
                log_transport_maintenance_failure(step, category);
            }
        }
    }
    deferred
}

async fn maintain_creator_transport(
    workers: &WorkerComponents,
    creator: Uuid,
    full_scan: bool,
) -> TransportMaintenance {
    let started = Instant::now();
    let adapter = match creator_adapter(workers, creator).await {
        Ok(adapter) => adapter,
        Err(error) => {
            let outcome = TransportMaintenance::Failed {
                step: "adapter_build",
                category: error.diagnostic_label(),
            };
            record_shared_transport_timing(full_scan, &outcome, started);
            return outcome;
        }
    };
    let result = if full_scan {
        adapter.maintain_transport_classified().await
    } else {
        // Handoff hints concern work already queued in the SDK.
        adapter.maintain_outbound_transport_classified().await
    };
    let outcome = transport_maintenance_outcome(result);
    record_shared_transport_timing(full_scan, &outcome, started);
    outcome
}

fn outbox_batch_size(config: &OutboxConfig) -> i64 {
    i64::from(config.batch_size)
}

#[derive(Clone, Copy)]
enum AdapterBuildError {
    Permanent,
    Unavailable,
}

impl AdapterBuildError {
    const fn diagnostic_label(self) -> &'static str {
        match self {
            Self::Permanent => "adapter_permanent",
            Self::Unavailable => "adapter_unavailable",
        }
    }
}

#[derive(Clone)]
struct ProductionPaymentDrainOperations {
    crypto: Arc<Crypto>,
    creators: CreatorStore,
    sessions: CreatorSessions,
    lifecycles: PaymentRequestLifecycleStore,
    drains: PaymentDrainStore,
    invoices: InvoiceStore,
    usdt: Option<crate::usdt::ArbitrumVerifier>,
    paykit: PaykitConfig,
}

#[async_trait]
impl PaymentDrainOperations for ProductionPaymentDrainOperations {
    async fn create(
        &self,
        lock_resource: &PubkyLockResource,
    ) -> Result<PaymentDrainSummary, PaymentDrainError> {
        if let Some(replay) = self
            .drains
            .exact_replay(lock_resource)
            .await
            .map_err(|_| PaymentDrainError::Unavailable)?
        {
            return Ok(self.summary(replay));
        }
        let (creator_id, credentials) = self
            .creators
            .load_with_id(lock_resource.creator())
            .await
            .map_err(|_| PaymentDrainError::Unavailable)?;
        if credentials.creator() != lock_resource.creator() {
            return Err(PaymentDrainError::Unavailable);
        }
        let sessions = self.sessions.provider(lock_resource.creator());
        let adapter = PaykitAdapter::new(creator_id, sessions, &self.paykit)
            .map_err(|_| PaymentDrainError::Unavailable)?
            .with_usdt(self.invoices.clone(), self.usdt.clone());
        adapter
            .reconcile_and_create_payment_drain(&self.lifecycles, &self.drains, lock_resource)
            .await
            .map(|snapshot| self.summary(snapshot))
    }

    async fn lookup(
        &self,
        lock_resource: &PubkyLockResource,
    ) -> Result<Option<PaymentDrainSummary>, PaymentDrainError> {
        self.drains
            .exact_replay(lock_resource)
            .await
            .map(|snapshot| snapshot.map(|snapshot| self.summary(snapshot)))
            .map_err(|_| PaymentDrainError::Unavailable)
    }

    async fn cleanup(
        &self,
        lock_resource: &PubkyLockResource,
        cleanup_token: PaymentDrainCleanupToken,
    ) -> Result<(), PaymentDrainError> {
        self.drains
            .cleanup_completed(lock_resource, cleanup_token.as_bytes())
            .await
            .map_err(|error| match error {
                PersistenceError::Conflict => PaymentDrainError::Conflict,
                _ => PaymentDrainError::Unavailable,
            })
    }
}

impl ProductionPaymentDrainOperations {
    fn summary(&self, snapshot: crate::persistence::PaymentDrainSnapshot) -> PaymentDrainSummary {
        let token = self.crypto.payment_drain_cleanup_token(snapshot.drain_id());
        PaymentDrainSummary::from_snapshot(
            snapshot,
            PaymentDrainCleanupToken::from_bytes(*token.as_bytes()),
        )
    }
}

#[derive(Clone)]
struct ProductionPaymentRequestStatusOperations {
    creators: CreatorStore,
    sessions: CreatorSessions,
    lifecycles: PaymentRequestLifecycleStore,
    statuses: InvoiceStore,
    usdt: Option<crate::usdt::ArbitrumVerifier>,
    paykit: PaykitConfig,
}

#[async_trait]
impl PaymentRequestStatusOperations for ProductionPaymentRequestStatusOperations {
    async fn lookup(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<PaymentRequestStatusSummary>, PaymentRequestStatusError> {
        if !self
            .statuses
            .invoice_exists(creator, bundle_id)
            .await
            .map_err(|error| {
                crate::diagnostics::failure(
                    "payment_request_status",
                    "invoice_existence_check",
                    error.diagnostic_label(),
                );
                PaymentRequestStatusError::Unavailable
            })?
        {
            return Ok(None);
        }
        let (creator_id, credentials) =
            self.creators.load_with_id(creator).await.map_err(|error| {
                crate::diagnostics::failure(
                    "payment_request_status",
                    "creator_credentials_load",
                    error.diagnostic_label(),
                );
                PaymentRequestStatusError::Unavailable
            })?;
        if credentials.creator() != creator {
            crate::diagnostics::failure(
                "payment_request_status",
                "creator_credentials_check",
                "creator_mismatch",
            );
            return Err(PaymentRequestStatusError::Unavailable);
        }
        let sessions = self.sessions.provider(creator);
        let adapter = PaykitAdapter::new(creator_id, sessions, &self.paykit)
            .map_err(|_| {
                crate::diagnostics::failure(
                    "payment_request_status",
                    "paykit_adapter_construction",
                    "invalid_configuration",
                );
                PaymentRequestStatusError::Unavailable
            })?
            .with_usdt(self.statuses.clone(), self.usdt.clone());
        adapter
            .reconcile_and_lookup_payment_request_status(
                &self.lifecycles,
                &self.statuses,
                bundle_id,
            )
            .await
    }
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
        .map(|adapter| {
            adapter
                .with_lifecycles(workers.payment_request_lifecycles.clone())
                .with_usdt(workers.invoices.clone(), workers.usdt.clone())
                .with_marketplace_usdt(workers.marketplace_preparations.clone())
        })
        .map_err(|_| AdapterBuildError::Permanent)
}

fn retry_delay(initial: Duration, maximum: Duration, attempt_count: i32) -> Duration {
    let exponent = u32::try_from(attempt_count.saturating_sub(1))
        .unwrap_or_default()
        .min(31);
    initial.saturating_mul(1_u32 << exponent).min(maximum)
}

const MAX_LINK_ESTABLISHMENT_RETRY_DELAY: Duration = Duration::from_secs(5);

fn outbox_retry_schedule(
    initial: Duration,
    maximum: Duration,
    rapid_link_retry_attempts: u32,
    rapid_link_retry_interval: Duration,
    attempt_count: i32,
    failure_count: i32,
) -> RetrySchedule {
    let default = retry_delay(initial, maximum, failure_count.saturating_add(1));
    let rapid_link_retry_attempts = i32::try_from(rapid_link_retry_attempts)
        .expect("validated rapid link retry attempts fit i32");
    let link_establishment = if attempt_count <= rapid_link_retry_attempts {
        rapid_link_retry_interval
    } else {
        retry_delay(initial, maximum, attempt_count - rapid_link_retry_attempts)
            .min(MAX_LINK_ESTABLISHMENT_RETRY_DELAY)
    };
    RetrySchedule::new(default, link_establishment)
}

fn processing_timing_outcome(
    result: &Result<(bool, ProcessingHealth), PersistenceError>,
) -> crate::diagnostics::TimingOutcome {
    match result {
        Ok((_, ProcessingHealth::Available)) => crate::diagnostics::TimingOutcome::Completed,
        Ok((_, ProcessingHealth::Retryable(_))) => crate::diagnostics::TimingOutcome::Deferred,
        Ok((_, ProcessingHealth::PermanentFailure)) | Err(_) => {
            crate::diagnostics::TimingOutcome::Failed
        }
    }
}

async fn outbox_enqueue_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let owner = Uuid::new_v4();
    let limit = usize::try_from(workers.outbox_batch_size).expect("validated outbox batch size");
    let mut tasks = CreatorTasks::new(limit, runtime.clone());
    let mut next_poll = tokio::time::Instant::now();
    loop {
        let completed = tokio::select! {
            _ = runtime.cancelled() => break,
            result = tasks.join_next(), if !tasks.is_empty() => result,
            _ = workers.invoices.wait_for_admission() => None,
            _ = tokio::time::sleep_until(next_poll) => None,
        };
        if !runtime.may_start_worker_claim() {
            break;
        }
        let now = tokio::time::Instant::now();
        if next_poll <= now {
            next_poll = now + workers.outbox_poll_interval;
        }
        let mut outbox_available = true;
        if let Some((_, result)) = completed {
            match result {
                Ok(Some((true, ProcessingHealth::Retryable(delay)))) => {
                    next_poll = next_poll.min(now + delay);
                }
                Ok(_) => {}
                Err(_) => {
                    outbox_available = false;
                }
            }
        }
        if outbox_available && tasks.available_slots() > 0 {
            match workers
                .outbox
                .due_creator_ids(
                    &tasks.active_creators(),
                    i64::try_from(tasks.available_slots()).expect("bounded Creator task capacity"),
                )
                .await
            {
                Ok(creators) => {
                    for creator in creators {
                        tasks.try_spawn(
                            creator,
                            process_creator_outbox(
                                workers.clone(),
                                runtime.clone(),
                                owner,
                                creator,
                            ),
                        );
                    }
                }
                Err(_) => outbox_available = false,
            }
        }
        match workers.outbox.delivery_available().await {
            Ok(persisted_available) => {
                runtime.set_paykit_enqueue_available(persisted_available);
                runtime.set_outbox_enqueue_available(outbox_available);
            }
            Err(_) => {
                runtime.set_paykit_enqueue_available(false);
                runtime.set_outbox_enqueue_available(false);
            }
        }
    }
    // Finish admitted effects. The server's drain deadline still bounds shutdown.
    while tasks.join_next().await.is_some() {}
}

async fn process_creator_outbox(
    workers: Arc<WorkerComponents>,
    runtime: Arc<Runtime>,
    owner: Uuid,
    creator: Uuid,
) -> Result<Option<(bool, ProcessingHealth)>, PersistenceError> {
    let task_started = Instant::now();
    // Setup/rotation takes this PostgreSQL fence before the process-local SDK
    // mutex. Keep the same ordering here to serialize external SDK effects with
    // durable cutover across processes without lock inversion.
    let mutation_fence = tokio::select! {
        _ = runtime.cancelled() => return Ok(None),
        fence = workers.creators.acquire_setup_lock_for_creator_id(creator) => fence,
    };
    let mutation_fence = match mutation_fence {
        Ok(fence) => fence,
        Err(error) => {
            crate::diagnostics::timing(
                "worker",
                "outbox_enqueue",
                crate::diagnostics::TimingOutcome::Failed,
                task_started,
            );
            return Err(error);
        }
    };
    let guard = tokio::select! {
        _ = runtime.cancelled() => return Ok(None),
        guard = creator_mutation_lock(creator).lock_owned() => guard,
    };
    if !runtime.may_start_worker_claim() {
        return Ok(None);
    }
    // No row is leased while waiting for a scheduler slot or Creator ownership.
    let claim = workers
        .outbox
        .claim_for_creator(owner, creator, workers.outbox_lease_duration)
        .await;
    let claim = match claim {
        Ok(Some(claim)) => claim,
        Ok(None) => return Ok(None),
        Err(error) => {
            crate::diagnostics::timing(
                "worker",
                "outbox_enqueue",
                crate::diagnostics::TimingOutcome::Failed,
                task_started,
            );
            return Err(error);
        }
    };
    let retry_schedule = outbox_retry_schedule(
        workers.outbox_retry_initial,
        workers.outbox_retry_max,
        workers.rapid_link_retry_attempts,
        workers.rapid_link_retry_interval,
        claim.attempt_count(),
        claim.failure_count(),
    );
    let mut ready_adapter = None;
    let result = with_claim_renewal(
        &workers.outbox,
        &claim,
        workers.outbox_lease_duration,
        async {
            let intent =
                match workers.outbox.delivery_intent(&claim) {
                    Ok(intent) => intent,
                    Err(_) => {
                        return workers.outbox.mark_permanently_failed(&claim).await.map(
                            |transitioned| (transitioned, ProcessingHealth::PermanentFailure),
                        );
                    }
                };
            if let Some(deadline) = intent
                .proposal_expires_at()
                .map_err(|_| PersistenceError::CorruptOrMissing)?
                && workers.outbox.proposal_expired(deadline).await?
            {
                return workers
                    .outbox
                    .mark_proposal_expired(&claim)
                    .await
                    .map(|transitioned| (transitioned, ProcessingHealth::Available));
            }
            match creator_adapter(&workers, creator).await {
                Ok(adapter) => {
                    let adapter = ready_adapter.insert(adapter);
                    process_claim_with(&workers.outbox, &claim, retry_schedule, |intent| {
                        let adapter = &*adapter;
                        let guard = &guard;
                        let store = &workers.outbox;
                        let claim = &claim;
                        async move {
                            adapter
                                .execute_claimed_handoff_with_guard(guard, store, claim, &intent)
                                .await
                        }
                    })
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
        },
    )
    .await;
    if matches!(result, Ok((false, _))) {
        tracing::warn!("outbox handoff finished without a live claim transition");
    }
    if matches!(result, Ok((true, ProcessingHealth::Available)))
        && runtime.may_start_worker_claim()
        && let Some(adapter) = ready_adapter
        && let Err(error) = adapter
            .send_handed_off_with_guard(&guard, &workers.outbox, &claim)
            .await
    {
        tracing::warn!(
            ?error,
            "handed-off delivery deferred to transport maintenance"
        );
    }
    let outcome = processing_timing_outcome(&result);
    let result = result.map(Some);
    let unlocked = mutation_fence.release().await;
    let result = match (result, unlocked) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(result), Ok(())) => Ok(result),
    };
    crate::diagnostics::timing(
        "worker",
        "outbox_enqueue",
        if result.is_err() {
            crate::diagnostics::TimingOutcome::Failed
        } else {
            outcome
        },
        task_started,
    );
    result
}

async fn outbox_reconciliation_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let owner = Uuid::new_v4();
    let mut interval = tokio::time::interval(workers.outbox_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let hinted_creators = tokio::select! {
            biased;
            _ = runtime.cancelled() => break,
            _ = interval.tick() => None,
            creators = workers.outbox.wait_for_reconciliation() => Some(creators),
        };
        if !runtime.may_start_worker_claim() {
            break;
        }
        let claims = match workers
            .outbox
            .claim_reconciliation_for_creators(
                owner,
                workers.outbox_batch_size,
                workers.outbox_lease_duration,
                hinted_creators.as_deref(),
            )
            .await
        {
            Ok(claims) => {
                if hinted_creators.is_none() {
                    runtime.set_outbox_reconciliation_available(true);
                }
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
                let started = Instant::now();
                let delay = retry_delay(
                    workers.outbox_retry_initial,
                    workers.outbox_retry_max,
                    claim.attempt_count(),
                );
                let result = match creator_adapter(&workers, claim.creator_id()).await {
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
                };
                crate::diagnostics::timing(
                    "worker",
                    "outbox_reconciliation",
                    processing_timing_outcome(&result),
                    started,
                );
                result
            });
        }
        let mut delivery_available = true;
        let mut outbox_available = true;
        while let Some(result) = batch.join_next().await {
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => {
                    delivery_available = false;
                    outbox_available = false;
                }
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
        if !delivery_available || hinted_creators.is_none() {
            runtime.set_paykit_reconciliation_available(delivery_available);
        }
        if !outbox_available || hinted_creators.is_none() {
            runtime.set_outbox_reconciliation_available(outbox_available);
        }
    }
}

/// Lifecycle receive does not wait behind an unrelated Creator's claimed outbox work.
/// Each Creator has at most one pass; queued hints survive an occupied slot.
async fn lifecycle_reconciliation_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let limit = usize::try_from(workers.outbox_batch_size).expect("validated outbox batch size");
    let mut tasks = CreatorTasks::new(limit, runtime.clone());
    let mut turns = IntakeTurns::default();
    let mut pending = BTreeSet::new();
    let mut known_creators = Vec::new();
    let mut readiness = LifecycleReadiness::default();
    let mut interval = tokio::time::interval(workers.outbox_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = runtime.cancelled() => break,
            Some((creator, available)) = tasks.join_next(), if !tasks.is_empty() => {
                readiness.completed(creator, available, &runtime);
            }
            _ = interval.tick() => {
                match workers.payment_request_lifecycles.creator_ids().await {
                    Ok(creators) => {
                        readiness.full_pass(&creators, &runtime);
                        pending.extend(creators.iter().copied());
                        known_creators = creators;
                    }
                    Err(error) => {
                        tracing::warn!(
                            stage = "lifecycle_reconciliation",
                            step = "creator_ids_load",
                            category = error.diagnostic_label(),
                            "Payment request lifecycle reconciliation unavailable"
                        );
                        readiness.failed(&runtime);
                    }
                }
            }
            creators = workers.outbox.wait_for_lifecycle_reconciliation() => {
                pending.extend(creators);
            }
        }
        start_lifecycle_passes(
            &mut tasks,
            &mut turns,
            &mut pending,
            &known_creators,
            |creator| reconcile_creator_lifecycle(workers.clone(), creator),
        );
    }
    // Admitted SDK work drains under the server's existing shutdown deadline.
    finish_lifecycle_passes(&mut tasks, &mut readiness, &runtime).await;
}

async fn finish_lifecycle_passes(
    tasks: &mut CreatorTasks<bool>,
    readiness: &mut LifecycleReadiness,
    runtime: &Runtime,
) {
    while let Some((creator, available)) = tasks.join_next().await {
        readiness.completed(creator, available, runtime);
    }
}

/// A full enumeration and completion of its Creators recover readiness. Targeted
/// hints cannot clear a failed enumeration or an earlier panicked pass.
#[derive(Default)]
struct LifecycleReadiness {
    checking: Option<BTreeSet<Uuid>>,
}

impl LifecycleReadiness {
    fn full_pass(&mut self, creators: &[Uuid], runtime: &Runtime) {
        self.checking
            .get_or_insert_with(|| creators.iter().copied().collect());
        self.publish_if_complete(runtime);
    }

    fn failed(&mut self, runtime: &Runtime) {
        self.checking = None;
        runtime.set_paykit_lifecycle_available(false);
    }

    fn completed(&mut self, creator: Uuid, available: bool, runtime: &Runtime) {
        if !available {
            self.failed(runtime);
        } else if let Some(checking) = &mut self.checking {
            checking.remove(&creator);
            self.publish_if_complete(runtime);
        }
    }

    fn publish_if_complete(&mut self, runtime: &Runtime) {
        if self.checking.as_ref().is_some_and(BTreeSet::is_empty) {
            self.checking = None;
            runtime.set_paykit_lifecycle_available(true);
        }
    }
}

fn start_lifecycle_passes<Pass, PassFuture>(
    tasks: &mut CreatorTasks<bool>,
    turns: &mut IntakeTurns,
    pending: &mut BTreeSet<Uuid>,
    known_creators: &[Uuid],
    mut pass: Pass,
) where
    Pass: FnMut(Uuid) -> PassFuture,
    PassFuture: Future<Output = ()> + Send + 'static,
{
    let running = tasks.active_creators().into_iter().collect::<BTreeSet<_>>();
    // Keep completed Creators in the ordering until discovery removes them, so
    // a later hint cannot reset their turn ahead of older queued work.
    let mut creators = pending.union(&running).copied().collect::<BTreeSet<_>>();
    creators.extend(known_creators);
    for creator in turns.order(creators.into_iter().collect()) {
        if tasks.available_slots() == 0 {
            break;
        }
        if running.contains(&creator) || !pending.contains(&creator) {
            continue;
        }
        let work = pass(creator);
        if tasks.try_spawn(creator, async move {
            let available = !pass_panicked(work).await;
            if !available {
                tracing::warn!(
                    stage = "lifecycle_reconciliation",
                    step = "task_join",
                    "Payment request lifecycle reconciliation task failed"
                );
            }
            available
        }) {
            turns.started(creator);
            pending.remove(&creator);
        }
    }
}

/// One Creator's receive/projection error is retried without withdrawing every
/// Creator's rail; durable delivery failures retain their separate readiness owner.
fn log_lifecycle_reconciliation_deferred(step: &'static str, category: &'static str) {
    if step == "receive_and_project" && matches!(category, "sdk" | "partial_receive") {
        tracing::debug!(
            stage = "lifecycle_reconciliation",
            step,
            category,
            "Creator payment request reconciliation deferred"
        );
    } else {
        tracing::warn!(
            stage = "lifecycle_reconciliation",
            step,
            category,
            "Creator payment request reconciliation deferred"
        );
    }
}

async fn reconcile_creator_lifecycle(workers: Arc<WorkerComponents>, creator: Uuid) {
    let result = async {
        let adapter = creator_adapter(&workers, creator)
            .await
            .map_err(|error| ("adapter_build", error.diagnostic_label()))?;
        adapter
            .receive_and_project_payment_requests(&workers.payment_request_lifecycles)
            .await
            .map_err(|error| ("receive_and_project", error.diagnostic_label()))
    }
    .await;
    if let Err((step, category)) = result {
        log_lifecycle_reconciliation_deferred(step, category);
    }
}

/// A single failed tick is routine for a remote Electrum server. Readiness turns
/// degraded only once failures persist for both a tick count and a wall-clock
/// span, so a short `poll_interval` cannot turn a blip into a withdrawn rail.
const ELECTRUM_DEGRADED_AFTER_FAILURES: u32 = 3;
const ELECTRUM_DEGRADED_AFTER: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ElectrumTick {
    /// No observation target, so Electrum was not called.
    Idle,
    Succeeded,
    Failed,
}

#[derive(Debug, Default)]
struct ElectrumReadiness {
    last_success: Option<tokio::time::Instant>,
    consecutive_failures: u32,
}

fn log_electrum_observation_failure(
    step: &'static str,
    category: &'static str,
    consecutive_failures: u32,
    degraded: bool,
) {
    if is_routine_electrum_observation_failure(step, category) {
        tracing::debug!(
            stage = "electrum_observation",
            step,
            category,
            consecutive_failures,
            degraded,
            "Electrum observation tick failed"
        );
    } else {
        tracing::warn!(
            stage = "electrum_observation",
            step,
            category,
            consecutive_failures,
            degraded,
            "Electrum observation tick failed"
        );
    }
}

fn is_routine_electrum_observation_failure(step: &str, category: &str) -> bool {
    matches!(step, "invoice_observation" | "marketplace_observation") && category == "unavailable"
}

fn record_electrum_observation_failure(
    failure: &mut Option<(&'static str, &'static str)>,
    step: &'static str,
    category: &'static str,
) {
    // Retain the first failure unless a later one must remain visible at INFO.
    if failure.is_none_or(|(existing_step, existing_category)| {
        is_routine_electrum_observation_failure(existing_step, existing_category)
            && !is_routine_electrum_observation_failure(step, category)
    }) {
        *failure = Some((step, category));
    }
}

impl ElectrumReadiness {
    /// Records one observer tick and returns whether Electrum counts as available.
    /// Only a completed observation is evidence of Electrum success; an idle tick
    /// keeps the no-work readiness without establishing any. Before any success a
    /// failure is reported immediately.
    fn record(&mut self, tick: ElectrumTick, now: tokio::time::Instant) -> bool {
        match tick {
            ElectrumTick::Idle => true,
            ElectrumTick::Succeeded => {
                self.last_success = Some(now);
                self.consecutive_failures = 0;
                true
            }
            ElectrumTick::Failed => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                match self.last_success {
                    None => false,
                    Some(last_success) => {
                        self.consecutive_failures < ELECTRUM_DEGRADED_AFTER_FAILURES
                            || now.saturating_duration_since(last_success) < ELECTRUM_DEGRADED_AFTER
                    }
                }
            }
        }
    }
}

async fn observer_loop(workers: Arc<WorkerComponents>, runtime: Arc<Runtime>) {
    let mut interval = tokio::time::interval(workers.electrum_poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut readiness = ElectrumReadiness::default();
    loop {
        tokio::select! {
            _ = runtime.cancelled() => break,
            _ = interval.tick() => {}
        }
        if !runtime.may_start_worker_claim() {
            break;
        }
        let started = Instant::now();
        let mut failure: Option<(&'static str, &'static str)> = None;
        let mut observed = false;
        match workers.invoices.observation_targets().await {
            Ok(targets) if !targets.is_empty() => {
                observed = true;
                if let Err(error) = observe_once(
                    workers.electrum.as_ref(),
                    &workers.invoices,
                    &workers.bitcoin_network,
                    &targets,
                )
                .await
                {
                    record_electrum_observation_failure(
                        &mut failure,
                        "invoice_observation",
                        error.diagnostic_label(),
                    );
                }
            }
            Ok(_) => {}
            Err(error) => {
                record_electrum_observation_failure(
                    &mut failure,
                    "invoice_targets_load",
                    error.diagnostic_label(),
                );
            }
        }
        match workers.marketplace_preparations.observation_targets().await {
            Ok(targets) if !targets.is_empty() => {
                observed = true;
                if let Err(error) = observe_marketplace_once(
                    workers.electrum.as_ref(),
                    workers.marketplace_preparations.as_ref(),
                    &workers.bitcoin_network,
                    &targets,
                )
                .await
                {
                    record_electrum_observation_failure(
                        &mut failure,
                        "marketplace_observation",
                        error.diagnostic_label(),
                    );
                }
            }
            Ok(_) => {}
            Err(error) => {
                record_electrum_observation_failure(
                    &mut failure,
                    "marketplace_targets_load",
                    error.diagnostic_label(),
                );
            }
        }
        let tick = match (failure, observed) {
            (Some(_), _) => ElectrumTick::Failed,
            (None, true) => ElectrumTick::Succeeded,
            (None, false) => ElectrumTick::Idle,
        };
        let now = tokio::time::Instant::now();
        let available = readiness.record(tick, now);
        if let Some((step, category)) = failure {
            log_electrum_observation_failure(
                step,
                category,
                readiness.consecutive_failures,
                !available,
            );
        }
        if tick == ElectrumTick::Succeeded {
            runtime.metrics().record_electrum_success(now.into_std());
        }
        if tick != ElectrumTick::Idle {
            crate::diagnostics::timing(
                "worker",
                "observer",
                if tick == ElectrumTick::Succeeded {
                    crate::diagnostics::TimingOutcome::Completed
                } else {
                    crate::diagnostics::TimingOutcome::RoutineFailure
                },
                started,
            );
        }
        runtime.set_electrum_available(available);
    }
}

/// Longest any one Pubky HTTP request may take. An SDK call that writes
/// shared state is never dropped mid-flight, so this is what bounds a call on
/// a stalled homeserver: the request fails and the SDK settles its write
/// lock. The companion relay sets its own timeout on each poll.
const PUBKY_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn configured_pubky(network: PaykitNetwork) -> Result<Pubky, ServerBuildError> {
    let mut builder = pubky::PubkyHttpClient::builder();
    if network == PaykitNetwork::Testnet {
        builder.testnet();
    }
    let client = builder
        .request_timeout(PUBKY_REQUEST_TIMEOUT)
        .build()
        .map_err(|_| ServerBuildError::Pubky)?;
    Ok(Pubky::with_client(client))
}

fn map_electrum_error(_: ObserverError) -> ServerBuildError {
    ServerBuildError::Electrum
}

#[derive(Clone)]
struct CreatorSessionValidator {
    creators: CreatorStore,
    sessions: CreatorSessions,
    identity_states: IdentityStateReads,
}

/// How long a Creator's last identity state read stands in for one that lost
/// the shared-state lock. It outlasts the SDK's 5-minute uncertain-write
/// cooldown, during which another holder keeps the lock.
const IDENTITY_STATE_BUSY_GRACE: Duration = Duration::from_secs(10 * 60);

/// When each Creator's identity state was last read. Reading it takes the
/// Creator's shared-state write lock, which Bitkit, the outbox workers and
/// concurrent readiness checks also take, so a busy lock says nothing about
/// whether the state is there.
#[derive(Clone, Default)]
struct IdentityStateReads {
    read_at: Arc<std::sync::Mutex<std::collections::HashMap<String, tokio::time::Instant>>>,
}

impl IdentityStateReads {
    /// The outcome of the identity state step: a read state is recorded, and a
    /// read that lost the lock passes when the state was read within
    /// [`IDENTITY_STATE_BUSY_GRACE`]. Every other failure is unchanged.
    fn outcome(
        &self,
        creator: &CreatorPubky,
        loaded: Result<bool, PaykitSdkError>,
        now: tokio::time::Instant,
    ) -> Result<(), SessionValidationError> {
        let mut read_at = self
            .read_at
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match loaded {
            Ok(true) => {
                read_at.retain(|_, at| now.duration_since(*at) < IDENTITY_STATE_BUSY_GRACE);
                read_at.insert(creator.to_string(), now);
                Ok(())
            }
            Ok(false) => {
                read_at.remove(&creator.to_string());
                Err(SessionValidationError::Invalid)
            }
            Err(PaykitSdkError::SharedStateBusy { .. })
                if read_at
                    .get(&creator.to_string())
                    .is_some_and(|at| now.duration_since(*at) < IDENTITY_STATE_BUSY_GRACE) =>
            {
                Ok(())
            }
            Err(error) => {
                let mapped = map_session_validation_error(error);
                Err(session_failure("identity_state_load", mapped))
            }
        }
    }
}

#[async_trait]
impl SessionValidator for CreatorSessionValidator {
    async fn validate(&self, creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        if !self
            .creators
            .setup_complete(creator)
            .await
            .map_err(|error| {
                crate::diagnostics::failure(
                    "creator_session_validation",
                    "setup_state_load",
                    error.diagnostic_label(),
                );
                SessionValidationError::Unavailable
            })?
        {
            return Err(SessionValidationError::Invalid);
        }
        let provider = self.sessions.provider(creator);
        let access = provider
            .load_session_access()
            .await
            .map_err(|error| {
                let mapped = map_session_validation_error(error);
                session_failure("session_access_load", mapped)
            })?
            .ok_or(SessionValidationError::Invalid)?;
        access
            .session
            .revalidate()
            .await
            .map_err(|error| {
                let mapped = classify_pubky_session_error(&error);
                session_failure("session_revalidation", mapped)
            })?
            .ok_or(SessionValidationError::Invalid)?;
        let owner = access
            .public_key()
            .and_then(|key| key.to_public_key())
            .map_err(|error| {
                let mapped = map_session_validation_error(error);
                session_failure("session_public_key", mapped)
            })?;
        let authorization = paykit_lib::get_paykit_noise_key_authorization(
            &access.outbox_client.public_storage(),
            &owner,
        )
        .await
        .map_err(|error| match error {
            paykit_lib::PaykitError::Transport { .. } => session_failure(
                "creator_noise_key_authorization_fetch",
                SessionValidationError::Unavailable,
            ),
            _ => SessionValidationError::Invalid,
        })?
        .ok_or(SessionValidationError::Invalid)?;
        let registry =
            paykit_lib::get_paykit_app_registry(&access.outbox_client.public_storage(), &owner)
                .await
                .map_err(|_| {
                    session_failure(
                        "creator_app_registry_fetch",
                        SessionValidationError::Unavailable,
                    )
                })?
                .ok_or(SessionValidationError::Invalid)?;
        let key = access
            .paykit_identity_secret_key
            .as_ref()
            .ok_or(SessionValidationError::Invalid)?;
        crate::real_setup::verify_authorized_key(&authorization, key)
            .map_err(|_| SessionValidationError::Invalid)?;
        let app_id =
            paykit_lib::PaykitAppId::new(crate::config::PAYKIT_APP_ID).expect("static app id");
        if registry.apps().get(&app_id) != Some(&crate::real_setup::server_app()) {
            return Err(SessionValidationError::Invalid);
        }
        use paykit_sdk::StorageAdapter;
        let loaded = paykit_sdk::PubkySharedStateStorage::new(provider)
            .transaction(|tx| Ok(tx.load_identity_state()))
            .await
            .map(|state| state.is_some());
        self.identity_states
            .outcome(creator, loaded, tokio::time::Instant::now())
    }
}

fn session_failure(stage: &'static str, error: SessionValidationError) -> SessionValidationError {
    if error == SessionValidationError::Unavailable {
        crate::diagnostics::failure("creator_session_validation", stage, "unavailable");
    }
    error
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
            .map_err(|_| {
                crate::diagnostics::failure("invoice_create", "lock_fetch", "timeout");
                LockFetchError::Unavailable
            })?
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
                        crate::diagnostics::failure("invoice_create", "lock_fetch", "not_found");
                        LockFetchError::NotFound
                    }
                    _ => {
                        crate::diagnostics::failure("invoice_create", "lock_fetch", "unavailable");
                        LockFetchError::Unavailable
                    }
                })?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            crate::diagnostics::failure("invoice_create", "lock_body_read", "unavailable");
            LockFetchError::Unavailable
        })? {
            let next_len = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or(LockFetchError::Invalid)?;
            if u64::try_from(next_len).map_err(|_| LockFetchError::Invalid)? > self.max_bytes {
                crate::diagnostics::failure(
                    "invoice_create",
                    "lock_body_read",
                    "payload_too_large",
                );
                return Err(LockFetchError::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        let lock: ContentLock = serde_json::from_slice(&bytes).map_err(|_| {
            crate::diagnostics::failure("invoice_create", "lock_parse", "invalid_json");
            LockFetchError::Invalid
        })?;
        let path = lock.content_lock_path().map_err(|_| {
            crate::diagnostics::failure("invoice_create", "lock_parse", "invalid_path");
            LockFetchError::Invalid
        })?;
        if format!("{}{}", resource.creator(), path) != resource.to_string() {
            crate::diagnostics::failure("invoice_create", "lock_validation", "resource_mismatch");
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
    ) -> Result<Option<PaykitAppRegistry>, RegistryDiscoveryError> {
        let reader = PubkyPublicKey::from_raw_or_app_key(reader.to_string())
            .and_then(|key| key.to_public_key())
            .map_err(|_| RegistryDiscoveryError::InvalidRequest)?;
        get_paykit_app_registry(&self.storage, &reader)
            .await
            .or_else(|error| match error {
                PaykitError::NotFound(_) => Ok(None),
                PaykitError::Transport { .. } => Err(RegistryDiscoveryError::Unavailable),
                PaykitError::InvalidData { .. } | PaykitError::Validation(_) => {
                    Err(RegistryDiscoveryError::Malformed)
                }
            })
    }

    async fn authorization(
        &self,
        reader: &ReaderPubky,
    ) -> Result<ReaderAuthorization, RegistryDiscoveryError> {
        let reader = PubkyPublicKey::from_raw_or_app_key(reader.to_string())
            .and_then(|key| key.to_public_key())
            .map_err(|_| RegistryDiscoveryError::InvalidRequest)?;
        reader_authorization(get_paykit_noise_key_authorization(&self.storage, &reader).await)
    }
}

/// Deserializing the record verifies the identity signature and pins the owner,
/// so only `Ok(Some(_))` is verified.
fn reader_authorization<T>(
    fetched: Result<Option<T>, PaykitError>,
) -> Result<ReaderAuthorization, RegistryDiscoveryError> {
    match fetched {
        Ok(Some(_)) => Ok(ReaderAuthorization::Verified),
        Ok(None) | Err(PaykitError::NotFound(_)) => Ok(ReaderAuthorization::Missing),
        Err(PaykitError::InvalidData { .. } | PaykitError::Validation(_)) => {
            Ok(ReaderAuthorization::Invalid)
        }
        Err(PaykitError::Transport { .. }) => Err(RegistryDiscoveryError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tracing::{Event, Level, Subscriber};
    use tracing_subscriber::{EnvFilter, Layer, layer::Context, prelude::*};

    #[derive(Clone, Default)]
    struct TimingCapture(Arc<Mutex<Vec<Level>>>);

    impl<S: Subscriber> Layer<S> for TimingCapture {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            self.0.lock().unwrap().push(*event.metadata().level());
        }
    }

    fn captured_shared_transport_timing(
        full_scan: bool,
        outcome: TransportMaintenance,
    ) -> Vec<Level> {
        let capture = TimingCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("off,paykit_server=info"))
            .with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            record_shared_transport_timing(full_scan, &outcome, Instant::now());
        });
        capture.0.lock().unwrap().clone()
    }

    #[test]
    fn idle_shared_transport_full_scan_is_quiet_under_production_filter() {
        assert!(captured_shared_transport_timing(true, TransportMaintenance::Complete).is_empty());
    }

    #[test]
    fn hinted_shared_transport_success_is_info_under_production_filter() {
        assert_eq!(
            captured_shared_transport_timing(false, TransportMaintenance::Complete),
            vec![Level::INFO]
        );
    }

    #[test]
    fn routine_shared_transport_failure_is_quiet_under_production_filter() {
        assert_eq!(
            captured_shared_transport_timing(
                true,
                TransportMaintenance::Failed {
                    step: "maintain_transport",
                    category: "transport",
                },
            ),
            Vec::<Level>::new()
        );
    }

    #[test]
    fn lifecycle_categories_keep_only_nonroutine_warn_under_production_filter() {
        let capture = TimingCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("off,paykit_server=info"))
            .with(capture.clone());

        tracing::subscriber::with_default(subscriber, || {
            log_lifecycle_reconciliation_deferred("receive_and_project", "partial_receive");
            log_lifecycle_reconciliation_deferred("receive_and_project", "persistence");
        });

        assert_eq!(*capture.0.lock().unwrap(), vec![Level::WARN]);
    }

    #[test]
    fn mixed_observer_failure_keeps_non_allowlisted_warn_under_production_filter() {
        let capture = TimingCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("off,paykit_server=info"))
            .with(capture.clone());

        tracing::subscriber::with_default(subscriber, || {
            let mut failure = None;
            record_electrum_observation_failure(&mut failure, "invoice_observation", "unavailable");
            record_electrum_observation_failure(
                &mut failure,
                "marketplace_targets_load",
                "storage",
            );
            let (step, category) = failure.expect("mixed tick must retain a failure");
            log_electrum_observation_failure(step, category, 1, false);
        });

        assert_eq!(*capture.0.lock().unwrap(), vec![Level::WARN]);
    }

    #[tokio::test]
    async fn adapter_transport_categories_reach_production_filter() {
        use paykit_sdk::{
            OutboundPrivateSendReport, RecoveryMarkerPublishFailure, ReservationCleanupFailure,
        };

        type Fixture = crate::paykit::TransportOperationFixture;

        async fn observe(fixture: Fixture) -> (Option<&'static str>, bool, Vec<Level>) {
            let adapter = PaykitAdapter::for_transport_fixture(fixture);
            let outcome =
                transport_maintenance_outcome(adapter.maintain_transport_classified().await);
            let category = match &outcome {
                TransportMaintenance::Failed { category, .. } => Some(*category),
                _ => None,
            };
            let deferred = matches!(outcome, TransportMaintenance::Deferred);
            let capture = TimingCapture::default();
            let subscriber = tracing_subscriber::registry()
                .with(EnvFilter::new("off,paykit_server=info"))
                .with(capture.clone());
            tracing::subscriber::with_default(subscriber, || {
                if let TransportMaintenance::Failed { step, category } = outcome {
                    log_transport_maintenance_failure(step, category);
                }
            });
            let levels = capture.0.lock().unwrap().clone();
            (category, deferred, levels)
        }

        let private = "private-transport-details";
        let scenarios = vec![
            (
                "routine then policy",
                Fixture::new(
                    vec![
                        Err(PaykitSdkError::Transport {
                            context: private.into(),
                            source: None,
                        }),
                        Err(PaykitSdkError::Policy {
                            context: private.into(),
                            source: None,
                        }),
                    ],
                    Vec::new(),
                ),
                Some("policy"),
                false,
                vec![Level::WARN],
            ),
            (
                "policy then routine",
                Fixture::new(
                    vec![
                        Err(PaykitSdkError::Policy {
                            context: private.into(),
                            source: None,
                        }),
                        Err(PaykitSdkError::Storage {
                            context: private.into(),
                            source: None,
                        }),
                    ],
                    Vec::new(),
                ),
                Some("policy"),
                false,
                vec![Level::WARN],
            ),
            (
                "reservation cleanup",
                Fixture::new(
                    Vec::new(),
                    vec![Ok(OutboundPrivateSendReport {
                        reservation_cleanup_failures: vec![ReservationCleanupFailure {
                            reservation_id: Some("private-reservation".into()),
                            error: private.into(),
                        }],
                        ..Default::default()
                    })],
                ),
                Some("reservation_cleanup"),
                false,
                vec![Level::WARN],
            ),
            (
                "recovery marker",
                Fixture::new(
                    Vec::new(),
                    vec![Ok(OutboundPrivateSendReport {
                        recovery_marker_failures: vec![RecoveryMarkerPublishFailure {
                            outbound_message_id: Some(7),
                            error: private.into(),
                        }],
                        ..Default::default()
                    })],
                ),
                Some("recovery_marker"),
                false,
                vec![Level::WARN],
            ),
            (
                "protocol",
                Fixture::new(
                    vec![Err(PaykitSdkError::Protocol {
                        context: private.into(),
                        source: None,
                    })],
                    Vec::new(),
                ),
                Some("protocol"),
                false,
                vec![Level::WARN],
            ),
            (
                "routine transport",
                Fixture::new(
                    vec![Err(PaykitSdkError::Transport {
                        context: private.into(),
                        source: None,
                    })],
                    Vec::new(),
                ),
                Some("transport"),
                false,
                Vec::new(),
            ),
            (
                "routine storage",
                Fixture::new(
                    vec![Err(PaykitSdkError::Storage {
                        context: private.into(),
                        source: None,
                    })],
                    Vec::new(),
                ),
                Some("storage"),
                false,
                Vec::new(),
            ),
            (
                "deferred contention",
                Fixture::new(
                    vec![Err(PaykitSdkError::SharedStateBusy {
                        context: private.into(),
                        source: None,
                    })],
                    Vec::new(),
                ),
                None,
                true,
                Vec::new(),
            ),
        ];

        for (name, fixture, expected_category, expected_deferred, expected_levels) in scenarios {
            let (category, deferred, levels) = observe(fixture).await;
            assert_eq!(category, expected_category, "{name}");
            assert_eq!(deferred, expected_deferred, "{name}");
            assert_eq!(levels, expected_levels, "{name}");
        }
    }

    #[tokio::test]
    async fn nested_send_failure_remains_warn_visible_through_adapter() {
        use paykit_sdk::{OutboundPrivateSendFailure, OutboundPrivateSendReport};

        let adapter =
            PaykitAdapter::for_transport_fixture(crate::paykit::TransportOperationFixture::new(
                Vec::new(),
                vec![Ok(OutboundPrivateSendReport {
                    failed: vec![OutboundPrivateSendFailure {
                        outbound_message_id: 7,
                        error: "private-transport-details".into(),
                    }],
                    ..Default::default()
                })],
            ));
        let outcome = transport_maintenance_outcome(adapter.maintain_transport_classified().await);
        let capture = TimingCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("off,paykit_server=info"))
            .with(capture.clone());

        tracing::subscriber::with_default(subscriber, || {
            let TransportMaintenance::Failed { step, category } = &outcome else {
                panic!("nested send failure must fail transport maintenance");
            };
            assert_eq!(*category, "other");
            log_transport_maintenance_failure(step, category);
            record_shared_transport_timing(true, &outcome, Instant::now());
        });

        assert_eq!(*capture.0.lock().unwrap(), vec![Level::WARN, Level::WARN]);
    }

    #[test]
    fn expected_worker_retry_events_are_debug_but_other_failures_remain_warn() {
        let capture = TimingCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            log_transport_maintenance_failure("maintain_transport", "transport");
            log_transport_maintenance_failure("maintain_transport", "storage");
            log_transport_maintenance_failure("adapter_build", "adapter_unavailable");
            log_transport_maintenance_failure("adapter_build", "transport");
            log_transport_maintenance_failure("maintain_transport", "protocol");

            log_lifecycle_reconciliation_deferred("receive_and_project", "sdk");
            log_lifecycle_reconciliation_deferred("receive_and_project", "partial_receive");
            log_lifecycle_reconciliation_deferred("adapter_build", "adapter_unavailable");
            log_lifecycle_reconciliation_deferred("adapter_build", "sdk");
            log_lifecycle_reconciliation_deferred("receive_and_project", "persistence");

            log_electrum_observation_failure("invoice_observation", "unavailable", 1, false);
            log_electrum_observation_failure("marketplace_observation", "unavailable", 1, false);
            log_electrum_observation_failure("invoice_targets_load", "storage", 1, false);
            log_electrum_observation_failure("invoice_targets_load", "unavailable", 1, false);
            log_electrum_observation_failure(
                "invoice_observation",
                "invalid_observation",
                1,
                false,
            );
        });

        assert_eq!(
            *capture.0.lock().unwrap(),
            vec![
                Level::DEBUG,
                Level::DEBUG,
                Level::WARN,
                Level::WARN,
                Level::WARN,
                Level::DEBUG,
                Level::DEBUG,
                Level::WARN,
                Level::WARN,
                Level::WARN,
                Level::DEBUG,
                Level::DEBUG,
                Level::WARN,
                Level::WARN,
                Level::WARN,
            ]
        );
    }

    #[test]
    fn worker_processing_health_maps_to_coarse_timing_outcomes() {
        assert_eq!(
            processing_timing_outcome(&Ok((true, ProcessingHealth::Available))),
            crate::diagnostics::TimingOutcome::Completed
        );
        assert_eq!(
            processing_timing_outcome(&Ok((
                true,
                ProcessingHealth::Retryable(Duration::from_secs(1)),
            ))),
            crate::diagnostics::TimingOutcome::Deferred
        );
        assert_eq!(
            processing_timing_outcome(&Ok((true, ProcessingHealth::PermanentFailure))),
            crate::diagnostics::TimingOutcome::Failed
        );
        assert_eq!(
            processing_timing_outcome(&Err(PersistenceError::Unavailable)),
            crate::diagnostics::TimingOutcome::Failed
        );
    }

    fn busy() -> Result<bool, PaykitSdkError> {
        Err(PaykitSdkError::SharedStateBusy {
            context: "Pubky shared state remains locked; retry later".into(),
            source: None,
        })
    }

    #[test]
    fn a_busy_shared_state_lock_keeps_a_recently_read_identity_state() {
        let reads = IdentityStateReads::default();
        let creator = crate::domain::locks::parse_creator(
            "pubky3f4khszd4gzg38bsazw88dmcfws36js9ct19s9dikb3a9ht3r84y",
        )
        .expect("creator");
        let start = tokio::time::Instant::now();

        assert_eq!(
            reads.outcome(&creator, busy(), start),
            Err(SessionValidationError::Unavailable),
            "a busy lock with no earlier read cannot say"
        );
        assert_eq!(reads.outcome(&creator, Ok(true), start), Ok(()));
        assert_eq!(
            reads.outcome(&creator, busy(), start + Duration::from_secs(5 * 60)),
            Ok(()),
            "a busy lock within the grace keeps the earlier read"
        );
        assert_eq!(
            reads.outcome(&creator, busy(), start + IDENTITY_STATE_BUSY_GRACE),
            Err(SessionValidationError::Unavailable),
            "the grace runs from the last read, not the last busy answer"
        );
        assert_eq!(
            reads.outcome(
                &creator,
                Err(PaykitSdkError::Transport {
                    context: "read encrypted Pubky shared state".into(),
                    source: None,
                }),
                start + Duration::from_secs(1),
            ),
            Err(SessionValidationError::Unavailable),
            "only a busy lock is covered"
        );
        assert_eq!(
            reads.outcome(&creator, Ok(false), start + Duration::from_secs(2)),
            Err(SessionValidationError::Invalid)
        );
        assert_eq!(
            reads.outcome(&creator, busy(), start + Duration::from_secs(3)),
            Err(SessionValidationError::Unavailable),
            "missing identity state forgets the earlier read"
        );
    }

    #[test]
    fn reader_authorization_is_verified_only_for_a_fetched_record() {
        let cases = [
            (Ok(Some(())), Ok(ReaderAuthorization::Verified)),
            (Ok(None), Ok(ReaderAuthorization::Missing)),
            (
                Err(PaykitError::NotFound("gone".into())),
                Ok(ReaderAuthorization::Missing),
            ),
            (
                Err(PaykitError::InvalidData {
                    context: "bad signature".into(),
                    source: None,
                }),
                Ok(ReaderAuthorization::Invalid),
            ),
            (
                Err(PaykitError::Validation("other owner".into())),
                Ok(ReaderAuthorization::Invalid),
            ),
            (
                Err(PaykitError::Transport {
                    context: "read failed".into(),
                    source: anyhow::anyhow!("connection reset"),
                }),
                Err(RegistryDiscoveryError::Unavailable),
            ),
        ];
        for (fetched, expected) in cases {
            assert_eq!(reader_authorization(fetched), expected);
        }
    }

    #[tokio::test]
    async fn setup_auth_relay_matches_the_configured_pubky_network() {
        for (network, expected_relay) in [
            (PaykitNetwork::Testnet, "http://127.0.0.1:15412/inbox"),
            (PaykitNetwork::Mainnet, "https://httprelay.pubky.app/inbox"),
        ] {
            let bootstrap = setup_bootstrap(
                Pubky::testnet().unwrap(),
                "app.paykit.server",
                network,
                None,
            )
            .unwrap();
            let request = bootstrap
                .start_sign_in_auth(crate::bitkit_claim::LOCAL_DEMO_CAPABILITIES)
                .await
                .unwrap();
            let details = paykit_sdk::parse_pubky_auth_url(request.authorization_url()).unwrap();
            assert_eq!(details.relay_url, expected_relay);
        }
    }

    #[tokio::test]
    async fn configured_setup_auth_relay_replaces_the_network_default() {
        let configured = Url::parse("https://relay.shop.example/inbox").unwrap();
        for network in [PaykitNetwork::Testnet, PaykitNetwork::Mainnet] {
            let bootstrap = setup_bootstrap(
                Pubky::testnet().unwrap(),
                "app.paykit.server",
                network,
                Some(&configured),
            )
            .unwrap();
            let request = bootstrap
                .start_sign_in_auth(crate::bitkit_claim::LOCAL_DEMO_CAPABILITIES)
                .await
                .unwrap();
            let details = paykit_sdk::parse_pubky_auth_url(request.authorization_url()).unwrap();
            assert_eq!(details.relay_url, "https://relay.shop.example/inbox");
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
    fn pending_links_do_not_inflate_failure_backoff() {
        let initial = Duration::from_secs(1);
        let maximum = Duration::from_secs(300);
        let rapid_attempts = 3;
        let rapid_interval = Duration::from_millis(500);

        for attempt in 1_i32..=3 {
            let schedule =
                outbox_retry_schedule(initial, maximum, rapid_attempts, rapid_interval, attempt, 0);
            assert_eq!(
                schedule.delay_for(OutboxRetryClass::LinkPending),
                rapid_interval
            );
        }

        assert_eq!(
            outbox_retry_schedule(initial, maximum, rapid_attempts, rapid_interval, 4, 0)
                .delay_for(OutboxRetryClass::LinkPending),
            Duration::from_secs(1)
        );
        assert_eq!(
            outbox_retry_schedule(initial, maximum, rapid_attempts, rapid_interval, 5, 0)
                .delay_for(OutboxRetryClass::LinkPending),
            Duration::from_secs(2)
        );
        assert_eq!(
            outbox_retry_schedule(initial, maximum, rapid_attempts, rapid_interval, 30, 0)
                .delay_for(OutboxRetryClass::LinkPending),
            Duration::from_secs(5)
        );
        assert_eq!(
            outbox_retry_schedule(initial, maximum, rapid_attempts, rapid_interval, 30, 0)
                .default_delay(),
            Duration::from_secs(1)
        );
        assert_eq!(
            outbox_retry_schedule(initial, maximum, rapid_attempts, rapid_interval, 30, 1)
                .delay_for(OutboxRetryClass::LinkEstablishment),
            Duration::from_secs(2)
        );
        assert_eq!(
            outbox_retry_schedule(initial, maximum, rapid_attempts, rapid_interval, 30, 30)
                .default_delay(),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn electrum_blips_do_not_degrade_until_failures_persist() {
        use ElectrumTick::{Failed, Succeeded};
        let start = tokio::time::Instant::now();
        let mut readiness = ElectrumReadiness::default();
        assert!(readiness.record(Succeeded, start));

        // Second-scale bursts as seen on a 1 s poll interval stay available.
        for second in 1..=5 {
            assert!(readiness.record(Failed, start + Duration::from_secs(second)));
        }
        assert!(readiness.record(Succeeded, start + Duration::from_secs(6)));
        assert_eq!(readiness.consecutive_failures, 0);

        // Long-interval polling needs the tick count as well as the span.
        let last_success = start + Duration::from_secs(6);
        assert!(readiness.record(Failed, last_success + Duration::from_secs(40)));
        assert!(readiness.record(Failed, last_success + Duration::from_secs(80)));
        assert!(!readiness.record(Failed, last_success + Duration::from_secs(120)));

        // A sustained outage on a short interval degrades once the span elapses.
        let mut readiness = ElectrumReadiness::default();
        assert!(readiness.record(Succeeded, start));
        for second in 1..30 {
            assert!(readiness.record(Failed, start + Duration::from_secs(second)));
        }
        assert!(!readiness.record(Failed, start + Duration::from_secs(30)));
        assert!(readiness.record(Succeeded, start + Duration::from_secs(31)));
    }

    #[test]
    fn electrum_failure_before_any_success_is_reported_immediately() {
        let start = tokio::time::Instant::now();
        let mut readiness = ElectrumReadiness::default();
        assert!(!readiness.record(ElectrumTick::Failed, start));
        assert!(readiness.record(ElectrumTick::Succeeded, start + Duration::from_secs(1)));
    }

    #[test]
    fn idle_electrum_ticks_never_establish_success() {
        let start = tokio::time::Instant::now();
        let mut readiness = ElectrumReadiness::default();
        for second in 0..60 {
            assert!(readiness.record(ElectrumTick::Idle, start + Duration::from_secs(second)));
        }
        assert_eq!(readiness.last_success, None);
        assert!(!readiness.record(ElectrumTick::Failed, start + Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn production_spawn_path_owns_all_workers() {
        let server = test_server().await;
        let (mut tasks, mut settling) = spawn_owned_workers(server.workers, server.runtime);
        assert_eq!(tasks.len(), 6);
        assert!(settling.is_empty());
        abort_owned_workers(&mut tasks, &mut settling).await;
    }

    #[tokio::test]
    async fn allowance_intake_runs_only_when_enabled() {
        let mut server = test_server().await;
        assert!(
            !server.workers.paykit.allowance_intake,
            "intake is off by default"
        );
        server.workers.paykit.allowance_intake = true;
        let runtime = server.runtime.clone();
        let (mut tasks, mut settling) = spawn_owned_workers(server.workers, server.runtime);
        // Intake runs outside the abortable set.
        assert_eq!(tasks.len(), 6);
        assert_eq!(settling.len(), 1);
        runtime.begin_shutdown();
        abort_owned_workers(&mut tasks, &mut settling).await;
    }

    #[tokio::test]
    async fn seller_receipt_reads_run_only_when_enabled() {
        let mut server = test_server().await;
        assert!(
            !server.workers.paykit.marketplace_seller_receipts,
            "seller Receipt reads are off by default"
        );
        server.workers.paykit.marketplace_seller_receipts = true;
        let runtime = server.runtime.clone();
        let (mut tasks, mut settling) = spawn_owned_workers(server.workers, server.runtime);
        // The reader runs outside the abortable set, like intake.
        assert_eq!(tasks.len(), 6);
        assert_eq!(settling.len(), 1);
        runtime.begin_shutdown();
        abort_owned_workers(&mut tasks, &mut settling).await;
    }

    #[tokio::test]
    async fn a_settling_root_that_returns_or_panics_is_noticed_while_serving() {
        let mut off = JoinSet::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), settling_exited(&mut off))
                .await
                .is_err(),
            "no settling worker never counts as exited"
        );
        let mut running = JoinSet::new();
        running.spawn(std::future::pending::<()>());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), settling_exited(&mut running))
                .await
                .is_err()
        );
        running.abort_all();
        for panics in [false, true] {
            let mut settling = JoinSet::new();
            settling.spawn(async move {
                if panics {
                    panic!("settling root panicked");
                }
            });
            tokio::time::timeout(Duration::from_secs(5), settling_exited(&mut settling))
                .await
                .expect("the exit was noticed");
            // The spent task is never awaited again at shutdown.
            assert!(settling.is_empty());
        }
    }

    #[tokio::test]
    async fn a_drain_deadline_never_aborts_a_running_intake_mutation() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut tasks = JoinSet::new();
        // An ordinary worker that would run forever: aborted at the deadline.
        tasks.spawn(std::future::pending::<()>());
        // Intake whose SDK mutation is still running when the drain deadline
        // passes; it must settle rather than be dropped.
        let settled = Arc::new(AtomicBool::new(false));
        let mut settling = JoinSet::new();
        settling.spawn({
            let settled = settled.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                settled.store(true, Ordering::SeqCst);
            }
        });
        let drained = tokio::time::timeout(Duration::from_millis(10), std::future::pending::<()>());
        assert!(drained.await.is_err(), "the drain deadline passed");

        abort_owned_workers(&mut tasks, &mut settling).await;

        assert!(
            settled.load(Ordering::SeqCst),
            "the intake mutation was dropped"
        );
        assert!(tasks.is_empty());
    }

    fn lifecycle_runtime() -> Arc<Runtime> {
        struct Available;
        #[async_trait]
        impl crate::runtime::DependencyCheck for Available {
            async fn postgres_ready(&self) -> bool {
                true
            }
        }
        let runtime = Arc::new(Runtime::new(Arc::new(Available), 1));
        runtime.set_electrum_available(true);
        runtime.set_outbox_available(true);
        runtime.set_paykit_enqueue_available(true);
        runtime.set_paykit_reconciliation_available(true);
        runtime.set_paykit_transport_available(true);
        runtime
    }

    #[tokio::test]
    async fn lifecycle_passes_bound_work_retain_hints_and_advance_past_a_slow_creator() {
        use crate::runtime::ComponentState;
        let runtime = lifecycle_runtime();
        let mut tasks = CreatorTasks::new(2, runtime.clone());
        let mut turns = IntakeTurns::default();
        let mut readiness = LifecycleReadiness::default();
        let [slow, fast, queued] = [1, 2, 3].map(Uuid::from_u128);
        let creators = [slow, fast, queued];
        let gates = Arc::new(
            creators
                .map(|creator| (creator, tokio::sync::Semaphore::new(0)))
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        );
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let pass = |creator| {
            let gates = gates.clone();
            let started = started.clone();
            async move {
                started.send(creator).unwrap();
                gates[&creator].acquire().await.unwrap().forget();
            }
        };
        let mut pending = creators.into_iter().collect::<BTreeSet<_>>();
        readiness.full_pass(&creators, &runtime);
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        let first = tokio::time::timeout(Duration::from_secs(1), async {
            BTreeSet::from([starts.recv().await.unwrap(), starts.recv().await.unwrap()])
        })
        .await
        .unwrap();
        assert_eq!(first, BTreeSet::from([slow, fast]));
        assert_eq!(pending, BTreeSet::from([queued]));

        // Hints arriving while both slots are occupied must survive, including
        // another hint for the currently running slow Creator.
        pending.extend([slow, fast]);
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        assert_eq!(tasks.active_creators().len(), 2);
        assert!(starts.try_recv().is_err());
        for (completed, next) in [(fast, queued), (queued, fast)] {
            gates[&completed].add_permits(1);
            let (creator, available) =
                tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!((creator, available), (completed, true));
            readiness.completed(creator, available, &runtime);
            start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), starts.recv())
                    .await
                    .unwrap(),
                Some(next)
            );
            assert_eq!(tasks.active_creators().len(), 2);
            assert_eq!(
                runtime.readiness().await.paykit_delivery,
                ComponentState::NotReady
            );
        }
        gates[&fast].add_permits(1);
        assert_eq!(tasks.join_next().await, Some((fast, true)));
        assert_eq!(pending, BTreeSet::from([slow]));
        assert_eq!(tasks.active_creators(), vec![slow]);
        gates[&slow].add_permits(1);
        let (creator, available) = tasks.join_next().await.unwrap();
        assert_eq!((creator, available), (slow, true));
        readiness.completed(creator, available, &runtime);
        assert_eq!(runtime.readiness().await.status, ComponentState::Ready);
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), starts.recv())
                .await
                .unwrap(),
            Some(slow)
        );
        gates[&slow].add_permits(1);
        assert_eq!(tasks.join_next().await, Some((slow, true)));
        assert!(tasks.is_empty());
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn lifecycle_requeued_creator_waits_for_older_pending_work() {
        use crate::runtime::ComponentState;
        let runtime = lifecycle_runtime();
        let mut tasks = CreatorTasks::new(1, runtime.clone());
        let mut turns = IntakeTurns::default();
        let mut readiness = LifecycleReadiness::default();
        let [first, second, waiting] = [1, 2, 3].map(Uuid::from_u128);
        let creators = [first, second, waiting];
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let pass = |creator| {
            let gate = gate.clone();
            let started = started.clone();
            async move {
                started.send(creator).unwrap();
                gate.acquire().await.unwrap().forget();
            }
        };
        let mut pending = creators.into_iter().collect::<BTreeSet<_>>();
        readiness.full_pass(&creators, &runtime);
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        assert_eq!(starts.recv().await, Some(first));
        gate.add_permits(1);
        let (finished, available) = tasks.join_next().await.unwrap();
        assert_eq!((finished, available), (first, true));
        readiness.completed(finished, available, &runtime);

        // The completed Creator is neither pending nor running when the next
        // slot is filled. A later hint must not make it look never started.
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        assert_eq!(starts.recv().await, Some(second));
        pending.insert(first);
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        assert_eq!(tasks.active_creators(), vec![second]);
        assert_eq!(pending, BTreeSet::from([first, waiting]));
        assert_eq!(
            runtime.readiness().await.paykit_delivery,
            ComponentState::NotReady
        );
        gate.add_permits(1);
        let (finished, available) = tasks.join_next().await.unwrap();
        assert_eq!((finished, available), (second, true));
        readiness.completed(finished, available, &runtime);
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        assert_eq!(starts.recv().await, Some(waiting));
        gate.add_permits(1);
        let (finished, available) = tasks.join_next().await.unwrap();
        assert_eq!((finished, available), (waiting, true));
        readiness.completed(finished, available, &runtime);
        assert_eq!(runtime.readiness().await.status, ComponentState::Ready);
        assert_eq!(pending, BTreeSet::from([first]));
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        assert_eq!(starts.recv().await, Some(first));
        gate.add_permits(1);
        assert_eq!(tasks.join_next().await, Some((first, true)));
        assert!(pending.is_empty());
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn lifecycle_panic_frees_the_creator_but_only_a_full_pass_recovers_readiness() {
        use crate::runtime::ComponentState;
        let runtime = lifecycle_runtime();
        let mut tasks = CreatorTasks::new(1, runtime.clone());
        let mut turns = IntakeTurns::default();
        let mut readiness = LifecycleReadiness::default();
        let creator = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut pending = BTreeSet::from([creator]);
        readiness.full_pass(&[creator], &runtime);
        start_lifecycle_passes(
            &mut tasks,
            &mut turns,
            &mut pending,
            &[creator],
            |_| async { panic!("fixture panic") },
        );
        let (finished, available) = tasks.join_next().await.unwrap();
        assert_eq!((finished, available), (creator, false));
        readiness.completed(finished, available, &runtime);
        assert!(tasks.active_creators().is_empty());
        assert_eq!(
            runtime.readiness().await.paykit_delivery,
            ComponentState::Degraded
        );

        pending.insert(creator);
        start_lifecycle_passes(
            &mut tasks,
            &mut turns,
            &mut pending,
            &[creator],
            |_| async {},
        );
        let (finished, available) = tasks.join_next().await.unwrap();
        assert_eq!((finished, available), (creator, true));
        readiness.completed(finished, available, &runtime);
        assert_eq!(
            runtime.readiness().await.paykit_delivery,
            ComponentState::Degraded
        );

        readiness.full_pass(&[creator, other], &runtime);
        readiness.completed(creator, true, &runtime);
        // A later tick must not reset the outstanding full pass; an unrelated
        // completed Creator cannot clear the pending one either.
        readiness.full_pass(&[creator, other], &runtime);
        readiness.completed(Uuid::new_v4(), true, &runtime);
        assert_eq!(
            runtime.readiness().await.paykit_delivery,
            ComponentState::Degraded
        );
        readiness.completed(other, true, &runtime);
        assert_eq!(runtime.readiness().await.status, ComponentState::Ready);

        readiness.full_pass(&[creator], &runtime);
        readiness.failed(&runtime); // Enumeration failure invalidates that pass.
        readiness.completed(creator, true, &runtime);
        assert_eq!(
            runtime.readiness().await.paykit_delivery,
            ComponentState::Degraded
        );
        readiness.full_pass(&[], &runtime);
        assert_eq!(runtime.readiness().await.status, ComponentState::Ready);
    }

    #[tokio::test]
    async fn lifecycle_shutdown_drains_admitted_work_without_starting_queued_creators() {
        let runtime = lifecycle_runtime();
        let mut tasks = CreatorTasks::new(1, runtime.clone());
        let mut turns = IntakeTurns::default();
        let mut readiness = LifecycleReadiness::default();
        let creators = [1, 2].map(Uuid::from_u128);
        let mut pending = creators.into_iter().collect::<BTreeSet<_>>();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let (finished, mut finishes) = tokio::sync::mpsc::unbounded_channel();
        let pass = |creator| {
            let gate = gate.clone();
            let started = started.clone();
            let finished = finished.clone();
            async move {
                started.send(creator).unwrap();
                gate.acquire().await.unwrap().forget();
                finished.send(creator).unwrap();
            }
        };
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        assert_eq!(starts.recv().await, Some(creators[0]));
        runtime.begin_shutdown();
        {
            let drain = finish_lifecycle_passes(&mut tasks, &mut readiness, &runtime);
            tokio::pin!(drain);
            assert!(
                tokio::time::timeout(Duration::ZERO, &mut drain)
                    .await
                    .is_err()
            );
            assert!(finishes.try_recv().is_err());
            gate.add_permits(1);
            tokio::time::timeout(Duration::from_secs(1), &mut drain)
                .await
                .unwrap();
        }
        assert_eq!(finishes.recv().await, Some(creators[0]));
        start_lifecycle_passes(&mut tasks, &mut turns, &mut pending, &creators, &pass);
        assert!(tasks.is_empty());
        assert_eq!(pending, BTreeSet::from([creators[1]]));
        assert!(starts.try_recv().is_err());
    }

    #[tokio::test]
    async fn allowance_intake_bounds_its_passes_and_gives_every_creator_a_turn() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let runtime = test_server().await.runtime;
        let mut tasks = CreatorTasks::new(2, runtime);
        let mut turns = IntakeTurns::default();
        let creators = (0..5).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        // Every pass stalls, as in a very large history, until released.
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let mut started = std::collections::HashSet::new();
        for _ in 0..creators.len() {
            start_intake_passes(&mut tasks, &mut turns, creators.clone(), |_| {
                let (active, peak, release) = (active.clone(), peak.clone(), release.clone());
                async move {
                    peak.fetch_max(active.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                    release.acquire().await.unwrap().forget();
                    active.fetch_sub(1, Ordering::SeqCst);
                }
            });
            assert_eq!(tasks.active_creators().len(), 2);
            started.extend(tasks.active_creators());
            tokio::time::timeout(Duration::from_secs(1), async {
                while active.load(Ordering::SeqCst) < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            // The longest-running pass finishes; its slot goes to a Creator
            // that has waited longer, not back to the first in the list.
            release.add_permits(1);
            tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(started.len(), creators.len(), "a Creator never got a turn");
        release.add_permits(creators.len());
        while tasks.join_next().await.is_some() {}
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn shutdown_waits_for_a_running_intake_pass_instead_of_dropping_it() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let runtime = test_server().await.runtime;
        let mut tasks = CreatorTasks::new(1, runtime);
        let mut turns = IntakeTurns::default();
        let release = Arc::new(tokio::sync::Notify::new());
        let (entered, has_entered) = tokio::sync::oneshot::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let mut entered = Some(entered);
        start_intake_passes(&mut tasks, &mut turns, vec![Uuid::new_v4()], |_| {
            let (release, finished, entered) =
                (release.clone(), finished.clone(), entered.take().unwrap());
            async move {
                // Stands in for an SDK mutation still in flight at shutdown.
                entered.send(()).unwrap();
                release.notified().await;
                finished.store(true, Ordering::SeqCst);
            }
        });
        has_entered.await.unwrap();

        {
            let shutdown = finish_intake_passes(&mut tasks);
            tokio::pin!(shutdown);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut shutdown)
                    .await
                    .is_err(),
                "shutdown returned while the pass was still running"
            );
            release.notify_one();
            shutdown.await;
        }

        assert!(finished.load(Ordering::SeqCst), "the pass was dropped");
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn shutdown_lets_a_pass_finish() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let runtime = test_server().await.runtime;
        let mut tasks = CreatorTasks::new(1, runtime);
        let mut turns = IntakeTurns::default();
        let finished = Arc::new(AtomicBool::new(false));
        start_intake_passes(&mut tasks, &mut turns, vec![Uuid::new_v4()], |_| {
            let finished = finished.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                finished.store(true, Ordering::SeqCst);
            }
        });

        finish_intake_passes(&mut tasks).await;

        assert!(finished.load(Ordering::SeqCst), "the pass was cut short");
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn a_panicking_intake_pass_frees_its_slot() {
        let runtime = test_server().await.runtime;
        let mut tasks = CreatorTasks::new(1, runtime);
        let mut turns = IntakeTurns::default();
        let creator = Uuid::new_v4();

        start_intake_passes(&mut tasks, &mut turns, vec![creator], |_| async {
            panic!("malformed history");
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
                .await
                .unwrap(),
            Some((creator, ()))
        );

        // The slot is free and the Creator gets its next pass.
        let (ran, done) = tokio::sync::oneshot::channel();
        let mut ran = Some(ran);
        start_intake_passes(&mut tasks, &mut turns, vec![creator], |_| {
            let ran = ran.take().unwrap();
            async move { ran.send(()).unwrap() }
        });
        tokio::time::timeout(Duration::from_secs(1), done)
            .await
            .unwrap()
            .unwrap();
        while tasks.join_next().await.is_some() {}
    }

    #[tokio::test]
    async fn transport_pass_refills_bounded_slots_while_a_creator_is_slow() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let runtime = test_server().await.runtime;
        let creators = vec![
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        ];
        let slow = creators[0];
        let (release_slow, slow_wait) = tokio::sync::oneshot::channel();
        let (release_fast, fast_wait) = tokio::sync::oneshot::channel();
        let mut waits =
            std::collections::HashMap::from([(slow, slow_wait), (creators[1], fast_wait)]);
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let (completed, mut completions) = tokio::sync::mpsc::unbounded_channel();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let observed_peak = peak.clone();
        let pass = tokio::spawn(maintain_transport_pass(
            creators.clone(),
            2,
            runtime,
            move |creator| {
                let wait = waits.remove(&creator);
                let started = started.clone();
                let completed = completed.clone();
                let active = active.clone();
                let peak = peak.clone();
                async move {
                    peak.fetch_max(active.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                    started.send(creator).unwrap();
                    if let Some(wait) = wait {
                        wait.await.unwrap();
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                    completed.send(creator).unwrap();
                    TransportMaintenance::Complete
                }
            },
        ));
        let mut seen = tokio::time::timeout(Duration::from_secs(1), async {
            vec![starts.recv().await.unwrap(), starts.recv().await.unwrap()]
        })
        .await
        .unwrap();
        assert!(
            starts.try_recv().is_err(),
            "the pass must respect its task limit"
        );
        release_fast.send(()).unwrap();
        let fast = tokio::time::timeout(Duration::from_secs(1), async {
            let mut fast = Vec::new();
            for _ in 0..3 {
                fast.push(completions.recv().await.unwrap());
            }
            fast
        })
        .await
        .unwrap();
        assert!(!fast.contains(&slow));
        assert!(!pass.is_finished());
        release_slow.send(()).unwrap();
        assert!(
            !tokio::time::timeout(Duration::from_secs(1), pass)
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(completions.recv().await, Some(slow));
        assert_eq!(completions.recv().await, None);
        while let Some(creator) = starts.recv().await {
            seen.push(creator);
        }
        seen.sort();
        let mut expected = creators;
        expected.sort();
        assert_eq!(seen, expected, "each Creator runs once per pass");
        assert_eq!(observed_peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn transport_pass_shutdown_drains_admitted_creators_without_refilling() {
        let runtime = test_server().await.runtime;
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let gate = release.clone();
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let (completed, mut completions) = tokio::sync::mpsc::unbounded_channel();
        let creators = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        let pass = tokio::spawn(maintain_transport_pass(
            creators.clone(),
            2,
            runtime.clone(),
            move |creator| {
                let gate = gate.clone();
                let started = started.clone();
                let completed = completed.clone();
                async move {
                    started.send(creator).unwrap();
                    let _permit = gate.acquire().await.unwrap();
                    completed.send(creator).unwrap();
                    TransportMaintenance::Complete
                }
            },
        ));
        let mut admitted = tokio::time::timeout(Duration::from_secs(1), async {
            vec![starts.recv().await.unwrap(), starts.recv().await.unwrap()]
        })
        .await
        .unwrap();
        runtime.begin_shutdown();
        assert!(!pass.is_finished());
        release.add_permits(2);
        assert!(
            !tokio::time::timeout(Duration::from_secs(1), pass)
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(starts.recv().await, None);
        let mut finished = Vec::new();
        while let Some(creator) = completions.recv().await {
            finished.push(creator);
        }
        admitted.sort();
        finished.sort();
        assert_eq!(finished, admitted);
        assert!(!finished.contains(&creators[2]));
    }

    #[tokio::test]
    async fn transport_pass_preserves_contention_across_mixed_outcomes() {
        for deferred in [false, true] {
            let runtime = test_server().await.runtime;
            let creators = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
            let mut outcomes = vec![
                TransportMaintenance::Failed {
                    step: "adapter_build",
                    category: "adapter_unavailable",
                },
                if deferred {
                    TransportMaintenance::Deferred
                } else {
                    TransportMaintenance::Complete
                },
                TransportMaintenance::Complete,
            ]
            .into_iter();
            let mut seen = Vec::new();
            assert_eq!(
                maintain_transport_pass(creators.clone(), 2, runtime, |creator| {
                    seen.push(creator);
                    let outcome = outcomes.next().unwrap();
                    async move { outcome }
                })
                .await,
                deferred,
            );
            assert_eq!(seen, creators, "a Creator failure must not stop the pass");
            assert!(outcomes.next().is_none());
        }
    }

    #[tokio::test]
    async fn shutdown_cancels_creator_lock_wait_before_claiming() {
        let server = test_server().await;
        let creator = Uuid::new_v4();
        let guard = creator_mutation_lock(creator).lock_owned().await;
        let work = process_creator_outbox(
            Arc::new(server.workers),
            server.runtime.clone(),
            Uuid::new_v4(),
            creator,
        );
        tokio::pin!(work);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut work)
                .await
                .is_err()
        );
        server.runtime.begin_shutdown();
        // The fixture's database is unreachable; a claim attempt would return an error.
        assert_eq!(work.await.unwrap(), None);
        drop(guard);
    }

    async fn test_server() -> Server {
        let config = Config::from_toml_and_environment(
            &format!(
                r#"
[http]
listen_addr = "127.0.0.1:0"
[signed_services]
trusted_public_keys = ["{CONFIG_KEY}"]
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
        Server::build(config, pool).await.unwrap()
    }
}
