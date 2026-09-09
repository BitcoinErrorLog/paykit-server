//! Identifier-free Prometheus metrics for the process runtime.

use std::sync::Mutex;

use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{
        counter::Counter,
        family::Family,
        gauge::Gauge,
        histogram::{Histogram, exponential_buckets},
    },
    registry::Registry,
};

/// Label set for per-address observation lookup failures. The value set is
/// a closed code-owned enum (`error`, `response_too_large`, `deadline`) —
/// never caller input — so cardinality is bounded at three series.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AddressFailureLabels {
    reason: &'static str,
}

/// Metrics intentionally carry no route, identifier, or caller-input
/// labels: the only label anywhere is the closed failure-reason enum above,
/// so caller input can never become metric cardinality or a data-exposure
/// boundary.
pub struct Metrics {
    registry: Mutex<Registry>,
    http_requests: Counter,
    http_latency_seconds: Histogram,
    outbox_depth: Gauge,
    outbox_retries: Counter,
    outbox_permanent_failures: Counter,
    electrum_available: Gauge,
    electrum_last_success_age_seconds: Gauge,
    electrum_backlog_oldest_age_seconds: Gauge,
    electrum_observation_stamp_misses: Counter,
    electrum_observation_address_failures: Family<AddressFailureLabels, Counter>,
    payment_states: Gauge,
    runtime_active: Gauge,
    session_validation_results: Counter,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let http_requests = Counter::default();
        let http_latency_seconds = Histogram::new(exponential_buckets(0.001, 2.0, 16));
        let outbox_depth = Gauge::default();
        let outbox_retries = Counter::default();
        let outbox_permanent_failures = Counter::default();
        let electrum_available = Gauge::default();
        let electrum_last_success_age_seconds = Gauge::default();
        let electrum_backlog_oldest_age_seconds = Gauge::default();
        let electrum_observation_stamp_misses = Counter::default();
        let electrum_observation_address_failures = Family::default();
        let payment_states = Gauge::default();
        let runtime_active = Gauge::default();
        let session_validation_results = Counter::default();
        registry.register(
            "paykit_http_requests",
            "Completed HTTP requests.",
            http_requests.clone(),
        );
        registry.register(
            "paykit_http_latency_seconds",
            "HTTP request latency.",
            http_latency_seconds.clone(),
        );
        registry.register(
            "paykit_outbox_depth",
            "Current outbox depth.",
            outbox_depth.clone(),
        );
        registry.register(
            "paykit_outbox_retries",
            "Outbox retry transitions.",
            outbox_retries.clone(),
        );
        registry.register(
            "paykit_outbox_permanent_failures",
            "Permanent outbox failures.",
            outbox_permanent_failures.clone(),
        );
        registry.register(
            "paykit_electrum_available",
            "Whether Electrum was recently available.",
            electrum_available.clone(),
        );
        registry.register(
            "paykit_electrum_last_success_age_seconds",
            "Age of last Electrum success.",
            electrum_last_success_age_seconds.clone(),
        );
        registry.register(
            "paykit_electrum_backlog_oldest_age_seconds",
            "Age of the oldest pending Electrum observation.",
            electrum_backlog_oldest_age_seconds.clone(),
        );
        registry.register(
            "paykit_electrum_observation_stamp_misses",
            "Observation tick stamps that matched no invoice row.",
            electrum_observation_stamp_misses.clone(),
        );
        registry.register(
            "paykit_electrum_observation_address_failures",
            "Isolated per-address Electrum lookup failures by closed reason label \
             (error, response_too_large, or deadline).",
            electrum_observation_address_failures.clone(),
        );
        registry.register(
            "paykit_payment_states",
            "Aggregate persisted payment-state count.",
            payment_states.clone(),
        );
        registry.register(
            "paykit_runtime_active",
            "Active runtime count.",
            runtime_active.clone(),
        );
        registry.register(
            "paykit_session_validation_results",
            "Session validation result count.",
            session_validation_results.clone(),
        );
        Self {
            registry: Mutex::new(registry),
            http_requests,
            http_latency_seconds,
            outbox_depth,
            outbox_retries,
            outbox_permanent_failures,
            electrum_available,
            electrum_last_success_age_seconds,
            electrum_backlog_oldest_age_seconds,
            electrum_observation_stamp_misses,
            electrum_observation_address_failures,
            payment_states,
            runtime_active,
            session_validation_results,
        }
    }

    pub fn observe_http(&self, seconds: f64) {
        self.http_requests.inc();
        self.http_latency_seconds.observe(seconds);
    }
    pub fn set_outbox_depth(&self, value: i64) {
        self.outbox_depth.set(value);
    }
    pub fn outbox_retry(&self) {
        self.outbox_retries.inc();
    }
    pub fn outbox_permanent_failure(&self) {
        self.outbox_permanent_failures.inc();
    }
    pub fn set_electrum_available(&self, available: bool) {
        self.electrum_available.set(i64::from(available));
    }
    pub fn set_electrum_last_success_age_seconds(&self, seconds: i64) {
        self.electrum_last_success_age_seconds.set(seconds.max(0));
    }
    pub fn set_electrum_backlog_oldest_age_seconds(&self, seconds: i64) {
        self.electrum_backlog_oldest_age_seconds.set(seconds.max(0));
    }
    pub fn electrum_observation_stamp_misses(&self, misses: u64) {
        self.electrum_observation_stamp_misses.inc_by(misses);
    }
    pub fn electrum_observation_address_failures(&self, reason: &'static str, failures: u64) {
        self.electrum_observation_address_failures
            .get_or_create(&AddressFailureLabels { reason })
            .inc_by(failures);
    }
    pub fn set_payment_states(&self, value: i64) {
        self.payment_states.set(value);
    }
    pub fn set_runtime_active(&self, value: bool) {
        self.runtime_active.set(i64::from(value));
    }
    pub fn session_validation_result(&self) {
        self.session_validation_results.inc();
    }
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut text = String::new();
        encode(
            &mut text,
            &self
                .registry
                .lock()
                .expect("metrics registry mutex is not poisoned"),
        )?;
        Ok(text)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
