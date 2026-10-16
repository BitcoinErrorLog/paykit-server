//! Identifier-free Prometheus metrics for the process runtime.

use std::{sync::Mutex, time::Instant};

use prometheus_client::{
    encoding::text::encode,
    metrics::{
        counter::Counter,
        gauge::Gauge,
        histogram::{Histogram, exponential_buckets},
    },
    registry::Registry,
};

/// Metrics intentionally have no labels: routes, identifiers, and caller input
/// must never become metric cardinality or data-exposure boundaries.
pub struct Metrics {
    registry: Mutex<Registry>,
    http_requests: Counter,
    http_latency_seconds: Histogram,
    outbox_depth: Gauge,
    outbox_retries: Counter,
    outbox_permanent_failures: Counter,
    electrum_available: Gauge,
    electrum_last_success_age_seconds: Gauge,
    electrum_success_observed: Gauge,
    electrum_last_success: Mutex<Option<Instant>>,
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
        let electrum_success_observed = Gauge::default();
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
            "paykit_electrum_success_observed",
            "Whether any Electrum observation has succeeded since startup.",
            electrum_success_observed.clone(),
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
            electrum_success_observed,
            electrum_last_success: Mutex::new(None),
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
    /// Records a completed Electrum observation. The age gauge is only exposed
    /// once a success exists, so a scrape never reports `0` for "never".
    pub fn record_electrum_success(&self, at: Instant) {
        let mut last_success = self
            .electrum_last_success
            .lock()
            .expect("Electrum success mutex is not poisoned");
        if last_success.is_none() {
            self.registry
                .lock()
                .expect("metrics registry mutex is not poisoned")
                .register(
                    "paykit_electrum_last_success_age_seconds",
                    "Seconds since the last successful Electrum observation.",
                    self.electrum_last_success_age_seconds.clone(),
                );
            self.electrum_success_observed.set(1);
        }
        if last_success.is_none_or(|previous| at > previous) {
            *last_success = Some(at);
        }
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
        self.encode_at(Instant::now())
    }

    fn encode_at(&self, now: Instant) -> Result<String, std::fmt::Error> {
        let last_success = *self
            .electrum_last_success
            .lock()
            .expect("Electrum success mutex is not poisoned");
        if let Some(last_success) = last_success {
            let age = now.saturating_duration_since(last_success).as_secs();
            self.electrum_last_success_age_seconds
                .set(i64::try_from(age).unwrap_or(i64::MAX));
        }
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
    use std::time::Duration;

    use super::*;

    fn line<'a>(text: &'a str, name: &str) -> Option<&'a str> {
        text.lines()
            .find(|line| line.starts_with(&format!("{name} ")))
    }

    #[test]
    fn electrum_success_age_is_absent_before_any_success() {
        let metrics = Metrics::new();
        let text = metrics.encode_at(Instant::now()).unwrap();
        assert_eq!(
            line(&text, "paykit_electrum_success_observed"),
            Some("paykit_electrum_success_observed 0")
        );
        assert!(!text.contains("paykit_electrum_last_success_age_seconds"));
    }

    #[test]
    fn electrum_success_age_advances_between_scrapes_without_new_ticks() {
        let metrics = Metrics::new();
        let success = Instant::now();
        metrics.record_electrum_success(success);
        let first = metrics.encode_at(success + Duration::from_secs(5)).unwrap();
        assert_eq!(
            line(&first, "paykit_electrum_last_success_age_seconds"),
            Some("paykit_electrum_last_success_age_seconds 5")
        );
        assert_eq!(
            line(&first, "paykit_electrum_success_observed"),
            Some("paykit_electrum_success_observed 1")
        );
        let later = metrics
            .encode_at(success + Duration::from_secs(47))
            .unwrap();
        assert_eq!(
            line(&later, "paykit_electrum_last_success_age_seconds"),
            Some("paykit_electrum_last_success_age_seconds 47")
        );

        metrics.record_electrum_success(success + Duration::from_secs(50));
        let refreshed = metrics
            .encode_at(success + Duration::from_secs(52))
            .unwrap();
        assert_eq!(
            line(&refreshed, "paykit_electrum_last_success_age_seconds"),
            Some("paykit_electrum_last_success_age_seconds 2")
        );
        assert_eq!(
            refreshed
                .matches("# TYPE paykit_electrum_last_success_age_seconds")
                .count(),
            1
        );
    }
}
