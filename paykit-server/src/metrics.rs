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

/// Closed-set label for the outbox lane whose retry budget ran out. Only
/// server-owned constants may become label values: routes, identifiers, and
/// caller input must never become metric cardinality or data-exposure
/// boundaries.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct OutboxFailureKind {
    kind: &'static str,
}

/// Metrics intentionally have no caller-controlled labels: routes, identifiers,
/// and caller input must never become metric cardinality or data-exposure
/// boundaries. The only label in use is the closed outbox-lane `kind` set.
pub struct Metrics {
    registry: Mutex<Registry>,
    http_requests: Counter,
    http_latency_seconds: Histogram,
    outbox_depth: Gauge,
    outbox_retries: Counter,
    outbox_permanent_failures: Family<OutboxFailureKind, Counter>,
    outbox_permanently_failed_rows: Gauge,
    electrum_available: Gauge,
    electrum_last_success_age_seconds: Gauge,
    electrum_backlog_oldest_age_seconds: Gauge,
    electrum_bypassed_head_requests: Gauge,
    electrum_bypassed_head_budget_violations: Counter,
    electrum_observation_overrun_targets: Gauge,
    electrum_observation_stamp_misses: Counter,
    electrum_overrun_lane_admissions: Counter,
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
        let outbox_permanent_failures = Family::<OutboxFailureKind, Counter>::default();
        let outbox_permanently_failed_rows = Gauge::default();
        let electrum_available = Gauge::default();
        let electrum_last_success_age_seconds = Gauge::default();
        let electrum_backlog_oldest_age_seconds = Gauge::default();
        let electrum_bypassed_head_requests = Gauge::default();
        let electrum_bypassed_head_budget_violations = Counter::default();
        let electrum_observation_overrun_targets = Gauge::default();
        let electrum_observation_stamp_misses = Counter::default();
        let electrum_overrun_lane_admissions = Counter::default();
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
            "Outbox rows transitioned to permanently_failed when their retry budget was exhausted, by lane kind.",
            outbox_permanent_failures.clone(),
        );
        registry.register(
            "paykit_outbox_permanently_failed_rows",
            "Outbox rows currently retained as permanently_failed.",
            outbox_permanently_failed_rows.clone(),
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
            "paykit_electrum_bypassed_head_requests",
            "Estimated request cost of the last budget-bypassed head observation target.",
            electrum_bypassed_head_requests.clone(),
        );
        registry.register(
            "paykit_electrum_bypassed_head_budget_violations",
            "Ticks whose bypassed head cost exceeded twice the per-tick budget.",
            electrum_bypassed_head_budget_violations.clone(),
        );
        registry.register(
            "paykit_electrum_observation_overrun_targets",
            "Observation targets excluded from the head-of-line bypass for exceeding the per-target request bound.",
            electrum_observation_overrun_targets.clone(),
        );
        registry.register(
            "paykit_electrum_observation_stamp_misses",
            "Observation tick stamps that matched no invoice row.",
            electrum_observation_stamp_misses.clone(),
        );
        registry.register(
            "paykit_electrum_overrun_lane_admissions",
            "Overrun-flagged observation targets admitted through the slow lane.",
            electrum_overrun_lane_admissions.clone(),
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
            outbox_permanently_failed_rows,
            electrum_available,
            electrum_last_success_age_seconds,
            electrum_backlog_oldest_age_seconds,
            electrum_bypassed_head_requests,
            electrum_bypassed_head_budget_violations,
            electrum_observation_overrun_targets,
            electrum_observation_stamp_misses,
            electrum_overrun_lane_admissions,
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
    pub fn outbox_permanent_failure(&self, kind: &'static str) {
        self.outbox_permanent_failures
            .get_or_create(&OutboxFailureKind { kind })
            .inc();
    }
    pub fn set_outbox_permanently_failed_rows(&self, count: i64) {
        self.outbox_permanently_failed_rows.set(count.max(0));
    }
    pub fn outbox_permanently_failed_rows(&self) -> u64 {
        u64::try_from(self.outbox_permanently_failed_rows.get()).unwrap_or(0)
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
    pub fn set_electrum_bypassed_head_requests(&self, requests: i64) {
        self.electrum_bypassed_head_requests.set(requests.max(0));
    }
    pub fn electrum_bypassed_head_budget_violation(&self) {
        self.electrum_bypassed_head_budget_violations.inc();
    }
    pub fn set_electrum_observation_overrun_targets(&self, count: i64) {
        self.electrum_observation_overrun_targets.set(count.max(0));
    }
    pub fn electrum_observation_stamp_misses(&self, misses: u64) {
        self.electrum_observation_stamp_misses.inc_by(misses);
    }
    pub fn electrum_overrun_lane_admission(&self) {
        self.electrum_overrun_lane_admissions.inc();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_permanent_failures_are_counted_per_closed_kind_label() {
        let metrics = Metrics::new();
        metrics.outbox_permanent_failure("delivery");
        metrics.outbox_permanent_failure("delivery");
        metrics.outbox_permanent_failure("reconciliation");
        metrics.set_outbox_permanently_failed_rows(3);

        let encoded = metrics.encode().unwrap();
        assert!(
            encoded.contains("paykit_outbox_permanent_failures_total{kind=\"delivery\"} 2"),
            "{encoded}"
        );
        assert!(
            encoded.contains("paykit_outbox_permanent_failures_total{kind=\"reconciliation\"} 1"),
            "{encoded}"
        );
        assert!(
            encoded.contains("paykit_outbox_permanently_failed_rows 3"),
            "{encoded}"
        );
        assert_eq!(metrics.outbox_permanently_failed_rows(), 3);
    }
}
