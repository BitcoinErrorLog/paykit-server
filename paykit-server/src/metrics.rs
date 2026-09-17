//! Identifier-free Prometheus metrics for the process runtime.

use std::{collections::BTreeMap, sync::Mutex};

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

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct OutboxTransitionLabels {
    class: &'static str,
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
    electrum_zero_success_ticks: Counter,
    electrum_budget_exhausted_ticks: Counter,
    sentinel_downgrades: Counter,
    sentinel_oldest_unscanned_age_seconds: Gauge,
    payment_states: Gauge,
    runtime_active: Gauge,
    session_validation_results: Counter,
    outbox_terminal_transitions: Family<OutboxTransitionLabels, Counter>,
    outbox_terminal_transition_counts: Mutex<BTreeMap<(String, String), i64>>,
    outbox_terminal_failure_count: Gauge,
    outbox_terminal_oldest_age_seconds: Gauge,
    outbox_reader_saturated: Counter,
    outbox_active_partitions: Gauge,
    outbox_ceiling_exceeds_invoice: Counter,
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
        let electrum_zero_success_ticks = Counter::default();
        let electrum_budget_exhausted_ticks = Counter::default();
        let sentinel_downgrades = Counter::default();
        let sentinel_oldest_unscanned_age_seconds = Gauge::default();
        let payment_states = Gauge::default();
        let runtime_active = Gauge::default();
        let session_validation_results = Counter::default();
        let outbox_terminal_transitions = Family::default();
        let outbox_terminal_failure_count = Gauge::default();
        let outbox_terminal_oldest_age_seconds = Gauge::default();
        let outbox_reader_saturated = Counter::default();
        let outbox_active_partitions = Gauge::default();
        let outbox_ceiling_exceeds_invoice = Counter::default();
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
            "paykit_electrum_zero_success_ticks",
            "Observer ticks that attempted lookups and succeeded at none.",
            electrum_zero_success_ticks.clone(),
        );
        registry.register(
            "paykit_electrum_budget_exhausted_ticks",
            "Observer ticks deferred because the shared request budget could not \
             cover the probe reservation; the tick sent no Electrum requests.",
            electrum_budget_exhausted_ticks.clone(),
        );
        registry.register(
            "paykit_sentinel_downgrades",
            "Exclusive accounts downgraded to shared_manual by unassigned-sentinel \
             evidence (W1.14); one per account, on the transition only.",
            sentinel_downgrades.clone(),
        );
        registry.register(
            "paykit_sentinel_oldest_unscanned_age_seconds",
            "Age of the oldest admitted exclusive account's last completed sentinel scan.",
            sentinel_oldest_unscanned_age_seconds.clone(),
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
        registry.register(
            "paykit_outbox_terminal_transitions",
            "Terminal outbox transitions by closed class and reason.",
            outbox_terminal_transitions.clone(),
        );
        registry.register(
            "paykit_outbox_terminal_failure_count",
            "Current retained terminal outbox failure count.",
            outbox_terminal_failure_count.clone(),
        );
        registry.register(
            "paykit_outbox_terminal_oldest_age_seconds",
            "Age of the oldest retained terminal outbox failure.",
            outbox_terminal_oldest_age_seconds.clone(),
        );
        registry.register(
            "paykit_outbox_reader_saturated",
            "Reader-partition flooding observations: partitions whose due \
             eligible rows exceeded what one claim pass could admit (one row \
             per partition without an unexpired lease, zero with one).",
            outbox_reader_saturated.clone(),
        );
        registry.register(
            "paykit_outbox_active_partitions",
            "Current number of reader partitions with an unexpired lease.",
            outbox_active_partitions.clone(),
        );
        registry.register(
            "paykit_outbox_ceiling_exceeds_invoice",
            "Invoices whose remaining request lifetime at creation was shorter \
             than the configured link-establishment max age.",
            outbox_ceiling_exceeds_invoice.clone(),
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
            electrum_zero_success_ticks,
            electrum_budget_exhausted_ticks,
            sentinel_downgrades,
            sentinel_oldest_unscanned_age_seconds,
            payment_states,
            runtime_active,
            session_validation_results,
            outbox_terminal_transitions,
            outbox_terminal_transition_counts: Mutex::new(BTreeMap::new()),
            outbox_terminal_failure_count,
            outbox_terminal_oldest_age_seconds,
            outbox_reader_saturated,
            outbox_active_partitions,
            outbox_ceiling_exceeds_invoice,
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
    pub fn electrum_zero_success_tick(&self) {
        self.electrum_zero_success_ticks.inc();
    }
    pub fn electrum_budget_exhausted_tick(&self) {
        self.electrum_budget_exhausted_ticks.inc();
    }
    pub fn sentinel_downgrade(&self) {
        self.sentinel_downgrades.inc();
    }
    pub fn set_sentinel_oldest_unscanned_age_seconds(&self, seconds: i64) {
        self.sentinel_oldest_unscanned_age_seconds
            .set(seconds.max(0));
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
    pub fn observe_outbox_terminal_transitions(&self, counts: Vec<(String, String, i64)>) {
        let mut observed = self
            .outbox_terminal_transition_counts
            .lock()
            .expect("terminal transition counts mutex is not poisoned");
        for (class, reason, count) in counts {
            let previous = observed.entry((class.clone(), reason.clone())).or_default();
            let delta = count.saturating_sub(*previous);
            if delta > 0 {
                self.outbox_terminal_transitions
                    .get_or_create(&OutboxTransitionLabels {
                        class: terminal_class_label(&class),
                        reason: terminal_reason_label(&reason),
                    })
                    .inc_by(u64::try_from(delta).expect("positive terminal count fits u64"));
                *previous = count;
            }
        }
    }
    pub fn set_outbox_terminal_health(&self, count: i64, oldest_age_seconds: Option<i64>) {
        self.outbox_terminal_failure_count.set(count);
        self.outbox_terminal_oldest_age_seconds
            .set(oldest_age_seconds.unwrap_or_default().max(0));
    }
    pub fn outbox_reader_saturated(&self, flooded_partitions: u64) {
        self.outbox_reader_saturated.inc_by(flooded_partitions);
    }
    pub fn set_outbox_active_partitions(&self, value: i64) {
        self.outbox_active_partitions.set(value.max(0));
    }
    pub fn outbox_ceiling_exceeds_invoice(&self) {
        self.outbox_ceiling_exceeds_invoice.inc();
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

/// The terminal-failure alert contract (design §4), pinned here so the
/// exported values and the alerting expressions cannot drift apart:
/// warning on `increase(paykit_outbox_terminal_transitions_total[5m]) > 0`;
/// critical when the oldest UNACKNOWLEDGED terminal failure is older than
/// fifteen minutes or five transitions occur within five minutes.
pub const TERMINAL_ALERT_WINDOW: &str = "5m";
pub const TERMINAL_ALERT_CRITICAL_AGE_SECONDS: i64 = 15 * 60;
pub const TERMINAL_ALERT_CRITICAL_TRANSITIONS_PER_WINDOW: u64 = 5;

/// Warning: any terminal transition inside the alert window.
pub fn terminal_alert_warning(transitions_in_window: u64) -> bool {
    transitions_in_window > 0
}

/// Critical: an unacknowledged terminal failure is older than the critical
/// age, or the window saw at least the critical number of transitions.
/// `oldest_unacknowledged_age_seconds` is `None` when every terminal event
/// is acknowledged, which clears the age leg.
pub fn terminal_alert_critical(
    oldest_unacknowledged_age_seconds: Option<i64>,
    transitions_in_window: u64,
) -> bool {
    oldest_unacknowledged_age_seconds.is_some_and(|age| age > TERMINAL_ALERT_CRITICAL_AGE_SECONDS)
        || transitions_in_window >= TERMINAL_ALERT_CRITICAL_TRANSITIONS_PER_WINDOW
}

fn terminal_class_label(class: &str) -> &'static str {
    match class {
        "link_establishment_exhausted" => "link_establishment_exhausted",
        "dependency_failed" => "dependency_failed",
        "permanent" => "permanent",
        "invoice_finalized" => "invoice_finalized",
        "invoice_voided" => "invoice_voided",
        "invoice_abandoned" => "invoice_abandoned",
        "permanent_sdk_reconciliation" => "permanent_sdk_reconciliation",
        _ => "unknown",
    }
}

fn terminal_reason_label(reason: &str) -> &'static str {
    match reason {
        "attempt_ceiling" => "attempt_ceiling",
        "age_ceiling" => "age_ceiling",
        "parent_link_establishment_exhausted" => "parent_link_establishment_exhausted",
        "parent_permanently_failed" => "parent_permanently_failed",
        "permanent" => "permanent",
        "invoice_finalized" => "invoice_finalized",
        "invoice_voided" => "invoice_voided",
        "invoice_abandoned" => "invoice_abandoned",
        "permanent_sdk_reconciliation" => "permanent_sdk_reconciliation",
        _ => "unknown",
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
    fn terminal_alert_warning_is_any_transition_in_window() {
        assert!(!terminal_alert_warning(0));
        assert!(terminal_alert_warning(1));
        assert!(terminal_alert_warning(4));
        assert!(terminal_alert_warning(5));
    }

    #[test]
    fn terminal_alert_critical_uses_unacknowledged_age_and_window_count() {
        // Nothing unacknowledged and a quiet window: no critical signal.
        assert!(!terminal_alert_critical(None, 0));
        assert!(!terminal_alert_critical(None, 4));
        // Age leg: only an unacknowledged oldest age beyond fifteen minutes.
        assert!(!terminal_alert_critical(
            Some(TERMINAL_ALERT_CRITICAL_AGE_SECONDS),
            0
        ));
        assert!(terminal_alert_critical(
            Some(TERMINAL_ALERT_CRITICAL_AGE_SECONDS + 1),
            0
        ));
        // Count leg: five transitions in five minutes.
        assert!(terminal_alert_critical(None, 5));
        assert!(terminal_alert_critical(Some(0), 5));
    }
}
