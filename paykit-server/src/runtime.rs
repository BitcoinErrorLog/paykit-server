//! Process lifecycle, dependency readiness, capacity admission, and server shutdown.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use tokio::{sync::Notify, time::timeout};

use crate::{http::health, metrics::Metrics};

const READY: u8 = 0;
const DEGRADED: u8 = 1;
const NOT_READY: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentState {
    Ready,
    Degraded,
    NotReady,
}
impl ComponentState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::NotReady => "not_ready",
        }
    }
    fn from_atomic(value: u8) -> Self {
        match value {
            DEGRADED => Self::Degraded,
            NOT_READY => Self::NotReady,
            _ => Self::Ready,
        }
    }

    fn combine(first: Self, second: Self) -> Self {
        if first == Self::NotReady || second == Self::NotReady {
            Self::NotReady
        } else if first == Self::Degraded || second == Self::Degraded {
            Self::Degraded
        } else {
            Self::Ready
        }
    }
}

struct AdmissionGuard {
    runtime: Arc<Runtime>,
    admitted: bool,
    started: std::time::Instant,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if self.admitted {
            self.runtime.request_finished();
        }
        self.runtime
            .metrics()
            .observe_http(self.started.elapsed().as_secs_f64());
    }
}

/// One recorded Electrum tip probe. A probe that reached the endpoint but
/// proved the wrong chain records `genesis_ok: false` with no tip facts.
#[derive(Clone, Copy, Debug)]
pub struct ElectrumProbe {
    probed_at: Instant,
    probed_at_unix: u64,
    tip_height: Option<u32>,
    tip_time_unix: Option<u32>,
    genesis_ok: bool,
}

impl ElectrumProbe {
    /// Records a successful tip probe against the configured chain.
    pub fn success(tip_height: u32, tip_time_unix: u32) -> Self {
        Self {
            probed_at: Instant::now(),
            probed_at_unix: unix_now(),
            tip_height: Some(tip_height),
            tip_time_unix: Some(tip_time_unix),
            genesis_ok: true,
        }
    }

    /// Records a reached endpoint whose genesis block is not the configured
    /// network's genesis block.
    pub fn genesis_mismatch() -> Self {
        Self {
            probed_at: Instant::now(),
            probed_at_unix: unix_now(),
            tip_height: None,
            tip_time_unix: None,
            genesis_ok: false,
        }
    }

    fn is_available(&self, freshness: Duration, max_tip_age: Option<Duration>) -> bool {
        if !self.genesis_ok || self.probed_at.elapsed() > freshness {
            return false;
        }
        match (max_tip_age, self.tip_time_unix) {
            (Some(max_tip_age), Some(tip_time_unix)) => {
                unix_now().saturating_sub(u64::from(tip_time_unix)) <= max_tip_age.as_secs()
            }
            _ => true,
        }
    }

    /// Secret-free probe report for the health surface. `max_tip_age` bounds
    /// the accepted chain-tip age; `None` skips the tip-age check (regtest
    /// deployments, whose tips are arbitrarily old by design).
    pub fn report(
        &self,
        freshness: Duration,
        max_tip_age: Option<Duration>,
    ) -> ElectrumProbeReport {
        let now = unix_now();
        ElectrumProbeReport {
            available: self.is_available(freshness, max_tip_age),
            tip_height: self.tip_height,
            tip_age_secs: self
                .tip_time_unix
                .map(|tip_time| now.saturating_sub(u64::from(tip_time))),
            last_probe_at: Some(self.probed_at_unix),
            genesis_ok: self.genesis_ok,
        }
    }
}

/// Health-surface view of the most recent Electrum probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElectrumProbeReport {
    pub available: bool,
    pub tip_height: Option<u32>,
    pub tip_age_secs: Option<u64>,
    pub last_probe_at: Option<u64>,
    pub genesis_ok: bool,
}

impl ElectrumProbeReport {
    fn never_probed() -> Self {
        Self {
            available: false,
            tip_height: None,
            tip_age_secs: None,
            last_probe_at: None,
            genesis_ok: false,
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

const DEFAULT_ELECTRUM_PROBE_FRESHNESS: Duration = Duration::from_secs(20);
const DEFAULT_ELECTRUM_MAX_TIP_AGE: Duration = Duration::from_secs(4 * 60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Readiness {
    pub status: ComponentState,
    pub postgres: ComponentState,
    pub electrum: ComponentState,
    pub electrum_probe: ElectrumProbeReport,
    /// Observation targets currently flagged `observation_overrun` and
    /// excluded from the head-of-line budget bypass.
    pub electrum_overrun_targets: u64,
    pub bitcoin_creation_enabled: bool,
    pub paykit_delivery: ComponentState,
    pub outbox: ComponentState,
}

#[async_trait]
pub trait DependencyCheck: Send + Sync + 'static {
    async fn postgres_ready(&self) -> bool;
}

pub struct PostgresDependency {
    pool: PgPool,
}
impl PostgresDependency {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
#[async_trait]
impl DependencyCheck for PostgresDependency {
    async fn postgres_ready(&self) -> bool {
        sqlx::query("SELECT 1").execute(&self.pool).await.is_ok()
    }
}

/// Shared, injectable lifecycle state. Worker adapters report availability here;
/// they never publish endpoint, identity, or provider-error data.
pub struct Runtime {
    dependency: Arc<dyn DependencyCheck>,
    stopping: AtomicBool,
    cancelled: Notify,
    in_flight: AtomicUsize,
    idle: Notify,
    capacity: Arc<tokio::sync::Semaphore>,
    electrum: AtomicU8,
    electrum_overrun_targets: AtomicU64,
    bitcoin_creation_enabled: AtomicBool,
    electrum_probe: Mutex<Option<ElectrumProbe>>,
    electrum_probe_freshness: Mutex<Duration>,
    electrum_max_tip_age: Mutex<Option<Duration>>,
    paykit_enqueue: AtomicU8,
    paykit_reconciliation: AtomicU8,
    outbox_enqueue: AtomicU8,
    outbox_reconciliation: AtomicU8,
    metrics: Arc<Metrics>,
}

impl Runtime {
    pub fn new(dependency: Arc<dyn DependencyCheck>, max_concurrent_requests: usize) -> Self {
        assert!(
            max_concurrent_requests > 0,
            "request concurrency must be nonzero"
        );
        let metrics = Arc::new(Metrics::new());
        metrics.set_runtime_active(true);
        Self {
            dependency,
            stopping: AtomicBool::new(false),
            cancelled: Notify::new(),
            in_flight: AtomicUsize::new(0),
            idle: Notify::new(),
            capacity: Arc::new(tokio::sync::Semaphore::new(max_concurrent_requests)),
            electrum: AtomicU8::new(NOT_READY),
            electrum_overrun_targets: AtomicU64::new(0),
            bitcoin_creation_enabled: AtomicBool::new(true),
            electrum_probe: Mutex::new(None),
            electrum_probe_freshness: Mutex::new(DEFAULT_ELECTRUM_PROBE_FRESHNESS),
            electrum_max_tip_age: Mutex::new(Some(DEFAULT_ELECTRUM_MAX_TIP_AGE)),
            paykit_enqueue: AtomicU8::new(NOT_READY),
            paykit_reconciliation: AtomicU8::new(NOT_READY),
            outbox_enqueue: AtomicU8::new(NOT_READY),
            outbox_reconciliation: AtomicU8::new(NOT_READY),
            metrics,
        }
    }
    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }
    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }
    pub fn may_start_worker_claim(&self) -> bool {
        !self.stopping()
    }
    pub fn set_electrum_available(&self, available: bool) {
        self.electrum
            .store(if available { READY } else { DEGRADED }, Ordering::Release);
        self.metrics.set_electrum_available(available);
    }
    /// Publishes the number of observation targets currently flagged
    /// `observation_overrun` for the health surface and metrics.
    pub fn set_electrum_overrun_targets(&self, count: u64) {
        self.electrum_overrun_targets
            .store(count, Ordering::Release);
        self.metrics
            .set_electrum_observation_overrun_targets(i64::try_from(count).unwrap_or(i64::MAX));
    }
    /// Publishes whether this stack accepts new Bitcoin payment-request binds.
    pub fn set_bitcoin_creation_enabled(&self, enabled: bool) {
        self.bitcoin_creation_enabled
            .store(enabled, Ordering::Release);
    }
    /// Records the most recent Electrum tip probe result.
    pub fn record_electrum_probe(&self, probe: ElectrumProbe) {
        // A poisoned lock must not take down the readiness path: the
        // critical section holds no user code, so the inner value is sound.
        *self
            .electrum_probe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(probe);
    }
    /// Sets the observer poll interval; a probe older than three intervals
    /// (covering ±20% jitter plus tick duration) is stale and Electrum is
    /// reported unavailable.
    pub fn set_electrum_probe_interval(&self, poll_interval: Duration) {
        *self
            .electrum_probe_freshness
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = 3 * poll_interval;
    }
    /// Sets the maximum accepted chain-tip age for readiness. `None` skips
    /// the tip-age check: regtest tips are mined on demand and can be
    /// arbitrarily old without indicating endpoint trouble.
    pub fn set_electrum_max_tip_age(&self, max_tip_age: Option<Duration>) {
        *self
            .electrum_max_tip_age
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = max_tip_age;
    }
    fn electrum_probe_report(&self) -> ElectrumProbeReport {
        let freshness = *self
            .electrum_probe_freshness
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let max_tip_age = *self
            .electrum_max_tip_age
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.electrum_probe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .map(|probe| probe.report(freshness, max_tip_age))
            .unwrap_or_else(ElectrumProbeReport::never_probed)
    }
    pub fn set_paykit_delivery_available(&self, available: bool) {
        self.set_paykit_enqueue_available(available);
        self.set_paykit_reconciliation_available(available);
    }
    pub fn set_outbox_available(&self, available: bool) {
        self.set_outbox_enqueue_available(available);
        self.set_outbox_reconciliation_available(available);
    }
    pub(crate) fn set_paykit_enqueue_available(&self, available: bool) {
        self.paykit_enqueue
            .store(if available { READY } else { DEGRADED }, Ordering::Release);
    }
    pub(crate) fn set_paykit_reconciliation_available(&self, available: bool) {
        self.paykit_reconciliation
            .store(if available { READY } else { DEGRADED }, Ordering::Release);
    }
    pub(crate) fn set_outbox_enqueue_available(&self, available: bool) {
        self.outbox_enqueue
            .store(if available { READY } else { DEGRADED }, Ordering::Release);
    }
    pub(crate) fn set_outbox_reconciliation_available(&self, available: bool) {
        self.outbox_reconciliation
            .store(if available { READY } else { DEGRADED }, Ordering::Release);
    }
    pub fn begin_shutdown(&self) {
        if !self.stopping.swap(true, Ordering::AcqRel) {
            self.cancelled.notify_waiters();
        }
        self.metrics.set_runtime_active(false);
        if self.in_flight.load(Ordering::Acquire) == 0 {
            self.idle.notify_waiters();
        }
    }
    pub async fn cancelled(&self) {
        if self.stopping() {
            return;
        }
        let notified = self.cancelled.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.stopping() {
            return;
        }
        notified.await;
    }
    pub async fn readiness(&self) -> Readiness {
        let postgres = if self.stopping() || !self.dependency.postgres_ready().await {
            ComponentState::NotReady
        } else {
            ComponentState::Ready
        };
        let electrum_probe = self.electrum_probe_report();
        let electrum = match ComponentState::from_atomic(self.electrum.load(Ordering::Acquire)) {
            ComponentState::NotReady => ComponentState::NotReady,
            ComponentState::Ready if electrum_probe.available => ComponentState::Ready,
            _ => ComponentState::Degraded,
        };
        let paykit_delivery = ComponentState::combine(
            ComponentState::from_atomic(self.paykit_enqueue.load(Ordering::Acquire)),
            ComponentState::from_atomic(self.paykit_reconciliation.load(Ordering::Acquire)),
        );
        let outbox = ComponentState::combine(
            ComponentState::from_atomic(self.outbox_enqueue.load(Ordering::Acquire)),
            ComponentState::from_atomic(self.outbox_reconciliation.load(Ordering::Acquire)),
        );
        let status = if postgres == ComponentState::NotReady
            || [electrum, paykit_delivery, outbox]
                .into_iter()
                .any(|state| state == ComponentState::NotReady)
        {
            ComponentState::NotReady
        } else if [electrum, paykit_delivery, outbox]
            .into_iter()
            .any(|state| state != ComponentState::Ready)
        {
            ComponentState::Degraded
        } else {
            ComponentState::Ready
        };
        Readiness {
            status,
            postgres,
            electrum,
            electrum_probe,
            electrum_overrun_targets: self.electrum_overrun_targets.load(Ordering::Acquire),
            bitcoin_creation_enabled: self.bitcoin_creation_enabled.load(Ordering::Acquire),
            paykit_delivery,
            outbox,
        }
    }
    pub(crate) async fn wait_for_idle(&self) {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.in_flight.load(Ordering::Acquire) == 0 {
                break;
            }
            notified.await;
        }
    }
    async fn drain(&self, duration: Duration) -> bool {
        timeout(duration, self.wait_for_idle()).await.is_ok()
    }
    fn request_started(&self) {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
    }
    fn request_finished(&self) {
        if self.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.notify_waiters();
        }
    }
}

/// Signals shutdown in testable ordering and waits only for already-admitted work.
pub async fn shutdown_and_drain(runtime: &Runtime, drain_timeout: Duration) -> bool {
    runtime.begin_shutdown();
    runtime.drain(drain_timeout).await
}

pub fn operational_router(public_routes: Router, runtime: Arc<Runtime>) -> Router {
    let metrics_runtime = runtime.clone();
    public_routes
        .merge(health::router(runtime.clone()))
        .route("/metrics", get(move || metrics(metrics_runtime.clone())))
        .layer(middleware::from_fn_with_state(runtime, capacity_middleware))
}

async fn metrics(runtime: Arc<Runtime>) -> Response {
    match runtime.metrics().encode() {
        Ok(body) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn capacity_middleware(
    axum::extract::State(runtime): axum::extract::State<Arc<Runtime>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let exempt = matches!(request.uri().path(), "/health/live" | "/health/ready");
    if !exempt && runtime.stopping() {
        return unavailable();
    }
    let permit = if exempt {
        None
    } else {
        match runtime.capacity.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return unavailable(),
        }
    };
    if !exempt {
        runtime.request_started();
    }
    let _guard = AdmissionGuard {
        runtime,
        admitted: !exempt,
        started: std::time::Instant::now(),
        _permit: permit,
    };
    next.run(request).await
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "1")],
    )
        .into_response()
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    runtime: Arc<Runtime>,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move { runtime.cancelled().await })
    .await
}

pub(crate) async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler can be installed");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("shutdown signal can be installed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadyPostgres;

    #[async_trait]
    impl DependencyCheck for ReadyPostgres {
        async fn postgres_ready(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn task9_composite_worker_health_requires_both_owned_loops() {
        let runtime = Runtime::new(Arc::new(ReadyPostgres), 1);
        runtime.set_electrum_available(true);
        runtime.record_electrum_probe(ElectrumProbe::success(
            1,
            u32::try_from(unix_now()).unwrap_or(u32::MAX),
        ));

        runtime.set_outbox_enqueue_available(true);
        runtime.set_paykit_enqueue_available(true);
        let one_loop = runtime.readiness().await;
        assert_eq!(one_loop.outbox, ComponentState::NotReady);
        assert_eq!(one_loop.paykit_delivery, ComponentState::NotReady);

        runtime.set_outbox_reconciliation_available(true);
        runtime.set_paykit_reconciliation_available(true);
        assert_eq!(runtime.readiness().await.status, ComponentState::Ready);

        runtime.set_paykit_enqueue_available(false);
        let retrying = runtime.readiness().await;
        assert_eq!(retrying.status, ComponentState::Degraded);
        assert_eq!(retrying.paykit_delivery, ComponentState::Degraded);
        assert_eq!(retrying.outbox, ComponentState::Ready);
    }

    #[tokio::test]
    async fn task9_shutdown_broadcasts_one_runtime_cancellation_signal() {
        let runtime = Arc::new(Runtime::new(Arc::new(ReadyPostgres), 1));
        let waiter_runtime = runtime.clone();
        let waiter = tokio::spawn(async move { waiter_runtime.cancelled().await });

        runtime.begin_shutdown();

        tokio::time::timeout(Duration::from_millis(50), waiter)
            .await
            .expect("cancellation waiter must be notified")
            .unwrap();
        runtime.cancelled().await;
    }
}
