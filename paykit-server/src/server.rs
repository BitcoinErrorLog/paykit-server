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
    paykit::{
        CreatorSessionProvider, PaykitAdapter, ServerSessionRestoreError, restore_server_session,
    },
    persistence::{
        CreatorStore, InvoiceStore, OutboxRetryClass, OutboxStore, PersistenceError,
        PostgresStorageAdapter, SdkStateStore, StackIdentity,
    },
    real_setup::RealSetupCompleter,
    runtime::{
        OutboxTerminalHealth, PostgresDependency, Runtime, operational_router_with_deadline,
    },
    setup::{PostgresCancellationStore, SetupLimits, SetupService, SystemClock},
    setup_orchestration::PubkyCompanionRelay,
    workers::{
        observer::{
            ElectrumAdapter, ElectrumPort, ObserverError, ObserverLeadership, ObserverPolicy,
            RequestLimiter, observation_loop,
        },
        outbox::{
            ProcessingHealth, process_claim_with_health, process_fence_recovery_with_health,
            process_reconciliation_with_health,
        },
    },
};
use async_trait::async_trait;
use axum::{Extension, Router};
use locks_core::lock_policy::ContentLock;
use paykit_lib::{PaykitReceiverMarker, get_paykit_receiver_marker, list_paykit_receiver_paths};
use paykit_sdk::{PaykitSdkConfig, PubkyPublicKey, PubkySessionBootstrap};
use pubky::{Pubky, errors::RequestError};
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
    drain_timeout: Duration,
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
    link_establishment_max_attempts: i32,
    link_establishment_max_age: Duration,
    electrum_policy: ObserverPolicy,
    sentinel_policy: crate::sentinel::SentinelPolicy,
    observer_lease_ttl: Duration,
}

impl Server {
    /// Builds every required production adapter and all public routes.
    pub async fn build(
        config: Config,
        pool: PgPool,
        stack_identity: StackIdentity,
    ) -> Result<Self, ServerBuildError> {
        let pubky = configured_pubky(config.paykit.network)?;
        Self::build_with_client(config, pool, stack_identity, pubky).await
    }

    /// Builds the production composition with a controlled Pubky client for E2E tests.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn build_with_pubky(
        config: Config,
        pool: PgPool,
        stack_identity: StackIdentity,
        pubky: Pubky,
    ) -> Result<Self, ServerBuildError> {
        Self::build_with_client(config, pool, stack_identity, pubky).await
    }

    /// Builds the production composition with controlled transport ports for E2E tests.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn build_with_transports(
        config: Config,
        pool: PgPool,
        stack_identity: StackIdentity,
        pubky: Pubky,
        electrum: Arc<dyn ElectrumPort>,
    ) -> Result<Self, ServerBuildError> {
        Self::build_with_clients(config, pool, stack_identity, pubky, electrum).await
    }

    async fn build_with_client(
        config: Config,
        pool: PgPool,
        stack_identity: StackIdentity,
        pubky: Pubky,
    ) -> Result<Self, ServerBuildError> {
        let electrum = ElectrumAdapter::configured(
            config.electrum.endpoint.clone(),
            config.deployment_invariants().bitcoin_network.clone(),
            config.electrum.request_timeout,
            usize::try_from(config.electrum.max_utxos_per_address).unwrap_or(usize::MAX),
            config.electrum.address_deadline,
            config.electrum.max_response_bytes,
        )
        .map_err(map_electrum_error)?;
        Self::build_with_clients(config, pool, stack_identity, pubky, Arc::new(electrum)).await
    }

    async fn build_with_clients(
        config: Config,
        pool: PgPool,
        stack_identity: StackIdentity,
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

        let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), &config.paykit.client_id)
            .and_then(|bootstrap| bootstrap.with_auth_relay(config.paykit.auth_relay.as_str()))
            .map_err(|_| ServerBuildError::Pubky)?;
        let relay = Arc::new(PubkyCompanionRelay::new(pubky.client().clone()));
        let setup_completer = Arc::new(RealSetupCompleter::new(
            BitkitAuthStarter::new(bootstrap, &config.paykit.receiver_path),
            relay,
            creators.clone(),
            config.deployment_invariants().bitcoin_network.clone(),
            config.deployment_invariants().stack_role,
            config.paykit.receiver_path.clone(),
        ));
        let setup = SetupService::with_cancellation_store(
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
                claim_identity_per_second: config.rate_limits.claim_identity_per_second,
                claim_identity_burst: config.rate_limits.claim_identity_burst,
                claim_ip_per_second: config.rate_limits.claim_ip_per_second,
                claim_ip_burst: config.rate_limits.claim_ip_burst,
                claim_limiter_max_entries: usize::try_from(
                    config.rate_limits.claim_limiter_max_entries,
                )
                .expect("validated claim limiter max entries fits usize"),
                claim_limiter_idle_ttl: config.rate_limits.claim_limiter_idle_ttl,
                claim_ip_ipv4_prefix: config.rate_limits.claim_ip_ipv4_prefix,
                claim_ip_ipv6_prefix: config.rate_limits.claim_ip_ipv6_prefix,
                trusted_proxy_hops: config.rate_limits.trusted_proxy_hops,
            },
            Arc::new(PostgresCancellationStore::new(pool.clone())),
        );

        let electrum_request_limiter = RequestLimiter::new(
            u64::from(config.electrum.max_requests_per_tick),
            u64::from(config.electrum.max_requests_per_second),
        );
        let creation_snapshot_slots = Arc::new(tokio::sync::Semaphore::new(
            usize::try_from(config.electrum.max_concurrent_creation_snapshots)
                .expect("validated creation snapshot concurrency fits usize"),
        ));
        // The runtime is built before the creation services so both can
        // gate first-time binds on its live `bitcoin_offer_available`
        // verdict (read per request, never cached).
        let runtime = Arc::new(Runtime::new(
            Arc::new(PostgresDependency::new(pool.clone())),
            64,
        ));
        // The creation-facing store alarms (non-secret, telemetry only) when
        // a new invoice's remaining request lifetime is shorter than the
        // configured link-establishment max age; the exact ceiling values are
        // exposed on /health/ready for the parent's deployment preflight.
        let invoices = invoices
            .with_outbox_ceiling_alarm(config.outbox.link_establishment_max_age, runtime.metrics());
        runtime.set_outbox_link_establishment_ceiling(
            config.outbox.link_establishment_max_attempts,
            config.outbox.link_establishment_max_age,
        );
        let invoice_service = Arc::new(
            CreateInvoiceService::new(
                Arc::new(CreatorSessionValidator {
                    creators: creators.clone(),
                    pubky: pubky.clone(),
                    client_id: config.paykit.client_id.clone(),
                    required_capabilities: PaykitSdkConfig::new(
                        config.paykit.receiver_path.clone(),
                    )
                    .required_session_capabilities(),
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
                config.bitcoin.creation_enabled,
                Arc::new(invoices.clone()),
                electrum.clone(),
                usize::try_from(config.electrum.max_creation_history_entries)
                    .expect("validated history cap fits usize"),
                usize::try_from(config.electrum.max_transaction_bytes)
                    .expect("validated transaction cap fits usize"),
                Arc::new(PaykitIntentBuilder::for_network(
                    &config.deployment_invariants().bitcoin_network,
                )),
            )
            .with_electrum_controls(
                electrum_request_limiter.clone(),
                creation_snapshot_slots.clone(),
            )
            .with_offer_availability(runtime.clone())
            .with_stack_identity(stack_identity.stack_id())
            .with_prepare_ttl(config.bitcoin.prepare_ttl)
            .with_max_request_expiry(config.bitcoin.max_request_expiry),
        );
        let status_service = Arc::new(PaymentStatusService::new(Arc::new(invoices.clone())));
        let payment_request_service = Arc::new(
            MarketplacePaymentRequestService::new(
                Arc::new(CreatorSessionValidator {
                    creators: creators.clone(),
                    pubky: pubky.clone(),
                    client_id: config.paykit.client_id.clone(),
                    required_capabilities: PaykitSdkConfig::new(
                        config.paykit.receiver_path.clone(),
                    )
                    .required_session_capabilities(),
                }),
                Arc::new(PubkyMarkerDiscovery {
                    storage: pubky.public_storage(),
                }),
                config.paykit.receiver_path_priority.clone(),
                config.paykit.receiver_path.clone(),
                Arc::new(creators.clone()),
                config.deployment_invariants().bitcoin_network.clone(),
                config.bitcoin.creation_enabled,
                Arc::new(invoices.clone()),
                electrum.clone(),
                usize::try_from(config.electrum.max_creation_history_entries)
                    .expect("validated history cap fits usize"),
                usize::try_from(config.electrum.max_transaction_bytes)
                    .expect("validated transaction cap fits usize"),
                Arc::new(PaykitIntentBuilder::for_network(
                    &config.deployment_invariants().bitcoin_network,
                )),
            )
            .with_electrum_controls(
                electrum_request_limiter.clone(),
                creation_snapshot_slots.clone(),
            )
            .with_offer_availability(runtime.clone())
            .with_stack_identity(stack_identity.stack_id())
            .with_prepare_ttl(config.bitcoin.prepare_ttl)
            .with_max_request_expiry(config.bitcoin.max_request_expiry),
        );
        // §B.11 phase 2: the signed activate/void service. It reuses the
        // same Electrum adapter, request limiter and snapshot slots as
        // creation (the tick-1 snapshot is one bounded round inside the
        // §B.7 budget), and the same signed-body authentication as the
        // create routes — no new auth path.
        let two_phase_service = Arc::new(crate::application::two_phase::TwoPhaseService::new(
            Arc::new(invoices.clone()),
            electrum.clone(),
            electrum_request_limiter.clone(),
            creation_snapshot_slots,
            usize::try_from(config.electrum.max_creation_history_entries)
                .expect("validated history cap fits usize"),
            usize::try_from(config.electrum.max_transaction_bytes)
                .expect("validated transaction cap fits usize"),
            stack_identity.stack_id(),
        ));
        // The claim-time history scan (design §B.5) reuses the observer's
        // Electrum adapter type and timeout configuration; each scan batch
        // opens its own bounded connection, so no second client type is
        // introduced. The response-item cap, per-window deadline, and
        // process-wide concurrency bound come from the validated electrum
        // config.
        let claim_history = Arc::new(
            ElectrumAdapter::configured(
                config.electrum.endpoint.clone(),
                config.deployment_invariants().bitcoin_network.clone(),
                config.electrum.request_timeout,
                usize::try_from(config.electrum.max_utxos_per_address).unwrap_or(usize::MAX),
                config.electrum.address_deadline,
                config.electrum.max_response_bytes,
            )
            .map_err(map_electrum_error)?
            .with_claim_scan_bounds(
                usize::try_from(config.electrum.max_history_items_per_window)
                    .expect("validated history item cap fits usize"),
                config.electrum.claim_scan_window_deadline,
                usize::try_from(config.electrum.max_concurrent_claim_scans)
                    .expect("validated claim scan concurrency bound fits usize"),
            )
            .with_request_limiter(electrum_request_limiter.clone()),
        );
        let manual_claims = Arc::new(ManualClaimService::new(
            pubky.clone(),
            Arc::new(RelayLoopbackSessionMinter::new(
                pubky.clone(),
                config.paykit.auth_relay.clone(),
            )),
            creators.clone(),
            Arc::new(creators.clone()),
            Arc::new(crate::real_setup::DirectMarkerPublisher),
            claim_history,
            config.deployment_invariants().bitcoin_network.clone(),
            config.deployment_invariants().stack_role,
            stack_identity.stack_id(),
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
                    .merge(http::two_phase::two_phase_router(two_phase_service))
                    .layer(Extension(signed_auth)),
            );

        runtime.set_stack_id(stack_identity.stack_id());
        runtime.set_electrum_probe_interval(config.electrum.poll_interval);
        // One app-owned Electrum request limiter, built from the validated
        // budget config: the observer tick and every non-tick Electrum
        // caller (creation snapshot fetches, first-bind candidate fetch,
        // claim-time history scan) charge this single bucket.
        runtime.set_electrum_request_limiter(electrum_request_limiter);
        // Regtest tips are mined on demand and can be arbitrarily old
        // without indicating endpoint trouble, so the tip-age check only
        // applies to networks with a live block cadence.
        runtime.set_electrum_max_tip_age(match config.deployment_invariants().bitcoin_network {
            crate::config::BitcoinNetwork::Regtest => None,
            _ => Some(config.electrum.max_tip_age),
        });
        runtime.set_bitcoin_creation_enabled(config.bitcoin.creation_enabled);
        let router = operational_router_with_deadline(
            business_routes,
            runtime.clone(),
            config.limits.http_request_deadline,
        );
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
            link_establishment_max_attempts: i32::try_from(
                config.outbox.link_establishment_max_attempts,
            )
            .expect("validated link-establishment attempt ceiling fits i32"),
            link_establishment_max_age: config.outbox.link_establishment_max_age,
            electrum_policy: ObserverPolicy {
                poll_interval: config.electrum.poll_interval,
                max_requests_per_tick: config.electrum.max_requests_per_tick,
                max_requests_per_second: config.electrum.max_requests_per_second,
                max_transaction_bytes: usize::try_from(config.electrum.max_transaction_bytes)
                    .expect("validated transaction cap fits usize"),
                baseline_completion_timeout: config.electrum.baseline_completion_timeout,
                expiry_tail: config.bitcoin.expiry_tail,
            },
            sentinel_policy: config.sentinel.policy(),
            observer_lease_ttl: config.electrum.observer_lease_ttl,
        };
        let drain_timeout = config.shutdown.drain_timeout;

        Ok(Self {
            drain_timeout,
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
        let drain_timeout = self.drain_timeout;
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
        &workers.paykit,
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
        if crate::workers::outbox::publish_claim_fairness_metrics(
            &workers.outbox,
            &runtime.metrics(),
        )
        .await
        .is_err()
        {
            runtime.set_outbox_enqueue_available(false);
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
                if workers
                    .outbox
                    .exhaust_claim_if_due(
                        &claim,
                        workers.link_establishment_max_attempts,
                        workers.link_establishment_max_age,
                    )
                    .await?
                {
                    return Ok((true, ProcessingHealth::PermanentFailure));
                }
                if workers.outbox.invoice_is_final(claim.invoice_id()).await? {
                    return workers
                        .outbox
                        .mark_final_invoice_failed(&claim)
                        .await
                        .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure));
                }
                match creator_adapter(&workers, claim.creator_id()).await {
                    Ok(adapter) => {
                        process_claim_with_health(
                            &workers.outbox,
                            &adapter,
                            &claim,
                            delay,
                            workers.link_establishment_max_attempts,
                            workers.link_establishment_max_age,
                        )
                        .await
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
        // Dedicated fenced-recovery pass (migration 0023 rule 2): expired
        // `handoff_started` rows are claimed regardless of invoice finality
        // and terminalize as `handoff_unresolved` without ever re-running
        // the SDK effect or resolving/attributing durable SDK state.
        let recovery_claims = match workers
            .outbox
            .claim_fence_recovery(
                owner,
                workers.outbox_batch_size,
                workers.outbox_lease_duration,
            )
            .await
        {
            Ok(claims) => claims,
            Err(_) => {
                outbox_available = false;
                Vec::new()
            }
        };
        let mut recovery_batch = JoinSet::new();
        for claim in recovery_claims {
            let workers = workers.clone();
            recovery_batch.spawn(async move {
                let delay = retry_delay(
                    workers.outbox_retry_initial,
                    workers.outbox_retry_max,
                    claim.attempt_count(),
                );
                match creator_adapter(&workers, claim.creator_id()).await {
                    Ok(adapter) => {
                        process_fence_recovery_with_health(&workers.outbox, &adapter, &claim).await
                    }
                    Err(AdapterBuildError::Permanent) => workers
                        .outbox
                        .mark_handoff_unresolved(&claim)
                        .await
                        .map(|transitioned| (transitioned, ProcessingHealth::PermanentFailure)),
                    Err(AdapterBuildError::Unavailable) => workers
                        .outbox
                        .retry_fence_recovery(&claim, delay)
                        .await
                        .map(|transitioned| (transitioned, ProcessingHealth::Retryable)),
                }
            });
        }
        while let Some(result) = recovery_batch.join_next().await {
            match result {
                Ok(Ok((_, ProcessingHealth::Available))) => {}
                Ok(Ok((_, ProcessingHealth::Retryable | ProcessingHealth::PermanentFailure))) => {
                    delivery_available = false;
                }
                Ok(Err(_)) => outbox_available = false,
                Err(_) => panic!("owned outbox fence-recovery task exited unexpectedly"),
            }
        }
        // One bounded pass of the one-time legacy final-invoice backfill
        // per loop tick, under the same worker cadence as ordinary claims:
        // rows left inert by invoices that reached a final baseline state
        // before transition-time terminalization shipped terminalize,
        // oldest first, with zero SDK calls.
        if workers
            .outbox
            .sweep_final_invoice_backfill(crate::workers::outbox::FINAL_INVOICE_SWEEP_LIMIT)
            .await
            .is_err()
        {
            outbox_available = false;
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
        if let Ok(health) = workers.outbox.terminal_failure_health().await {
            runtime
                .metrics()
                .set_outbox_terminal_health(health.count, health.oldest_age_seconds);
            runtime
                .metrics()
                .observe_outbox_terminal_transitions(health.transitions);
            runtime.set_outbox_terminal_health(OutboxTerminalHealth {
                count: health.count,
                oldest_age_seconds: health.oldest_age_seconds,
                by_class: health.by_class,
            });
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
    observation_loop(
        workers.electrum.clone(),
        workers.invoices.clone(),
        Arc::new(crate::persistence::PgObserverLeadership::new(
            &workers.pool,
            workers.observer_lease_ttl,
        )) as Arc<dyn ObserverLeadership>,
        workers.bitcoin_network.clone(),
        workers.electrum_policy,
        workers.sentinel_policy,
        runtime,
    )
    .await;
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
    client_id: String,
    required_capabilities: String,
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
        let access = restore_server_session(
            &self.pubky,
            credentials.session_secret(),
            credentials.receiver_noise_secret().clone(),
            &self.client_id,
            &self.required_capabilities,
        )
        .await
        .map_err(map_server_session_restore_error)?;
        let expected = PubkyPublicKey::from_raw_or_app_key(creator.to_string())
            .map_err(|_| SessionValidationError::Invalid)?;
        let actual = access
            .public_key()
            .map_err(|_| SessionValidationError::Invalid)?;
        if actual != expected {
            return Err(SessionValidationError::Invalid);
        }
        Ok(())
    }
}

fn map_server_session_restore_error(error: ServerSessionRestoreError) -> SessionValidationError {
    match error {
        ServerSessionRestoreError::Invalid => SessionValidationError::Invalid,
        ServerSessionRestoreError::Unavailable => SessionValidationError::Unavailable,
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
        // Whole-request deadline: TCP connect, TLS handshake, and body
        // all run inside this timeout. Cancelling the future aborts an
        // in-progress async connect rather than waiting for the OS SYN
        // timeout.
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
    fn session_restore_classification_preserves_invalid_and_unavailable() {
        assert_eq!(
            map_server_session_restore_error(ServerSessionRestoreError::Invalid),
            SessionValidationError::Invalid
        );
        assert_eq!(
            map_server_session_restore_error(ServerSessionRestoreError::Unavailable),
            SessionValidationError::Unavailable
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
client_id = "paykit-server"
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
network = "testnet"
[deployment]
stack_role = "proof"
[electrum]
endpoint = "tcp://127.0.0.1:1"
request_timeout = "1s"
[outbox]
poll_interval = "1s"
"#
            ),
            ConfigEnvironment {
                database_url: Some("postgres://127.0.0.1:1/paykit".into()),
                migrator_database_url: Some("postgres://127.0.0.1:1/paykit".into()),
                master_key: Some(CONFIG_MASTER_KEY.into()),
                ..Default::default()
            },
        )
        .unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1:1/paykit")
            .unwrap();
        let stack_identity = StackIdentity::new(crate::config::StackRole::Proof, Uuid::new_v4());
        let server = Server::build(config, pool, stack_identity).await.unwrap();
        let mut tasks = spawn_owned_workers(server.workers, server.runtime);
        assert_eq!(tasks.len(), 3);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    #[tokio::test]
    async fn startup_installs_the_configured_limiter_over_the_fail_closed_default() {
        use crate::{runtime::DependencyCheck, workers::observer::BudgetExhausted};

        struct ReadyPostgres;
        #[async_trait]
        impl DependencyCheck for ReadyPostgres {
            async fn postgres_ready(&self) -> bool {
                true
            }
        }

        // The pre-install state Server::build starts from: Runtime::new's
        // limiter is fail-closed (an empty, non-refilling bucket), so no
        // caller can issue unbudgeted Electrum requests before startup
        // installs the configured one.
        let before = Runtime::new(Arc::new(ReadyPostgres), 64);
        assert_eq!(
            before.electrum_request_limiter().try_reserve(1),
            Err(BudgetExhausted {
                requested: 1,
                available: 0
            }),
            "the fail-closed default admits nothing before install"
        );

        // The same build path as production: Server::build installs one
        // app-owned limiter from the validated electrum budget config.
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
client_id = "paykit-server"
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
network = "testnet"
[deployment]
stack_role = "proof"
[electrum]
endpoint = "tcp://127.0.0.1:1"
request_timeout = "1s"
max_requests_per_tick = 7
max_requests_per_second = 3
[outbox]
poll_interval = "1s"
"#
            ),
            ConfigEnvironment {
                database_url: Some("postgres://127.0.0.1:1/paykit".into()),
                migrator_database_url: Some("postgres://127.0.0.1:1/paykit".into()),
                master_key: Some(CONFIG_MASTER_KEY.into()),
                ..Default::default()
            },
        )
        .unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1:1/paykit")
            .unwrap();
        let stack_identity = StackIdentity::new(crate::config::StackRole::Proof, Uuid::new_v4());
        let server = Server::build(config, pool, stack_identity).await.unwrap();
        let installed = server.runtime.electrum_request_limiter();
        assert_eq!(
            installed.available(),
            7,
            "the installed limiter is the configured one: a fresh bucket holds the full \
             max_requests_per_tick capacity"
        );
        assert!(
            installed.try_reserve(1).is_ok(),
            "admission succeeds after startup installs the configured limiter"
        );
        // The installed limiter is the runtime's one shared bucket: the
        // reservation above is visible to every other holder.
        assert_eq!(server.runtime.electrum_request_limiter().available(), 6);
    }
}
