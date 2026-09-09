//! Polling-independent direct Bitcoin observation worker boundary.
//!
//! Observation uses one raw Electrum `script_list_unspent` lookup per
//! tracked address. Each `ListUnspentRes` item carries the outpoint
//! (`tx_hash`, `tx_pos`), the value, and the confirmation height, so the
//! outpoint/value/presence model is preserved without ever calling
//! history RPCs or fetching a historical transaction: the request
//! count is exactly one per observed address and cannot be expanded by an
//! attacker dusting a disclosed invoice address.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bdk_electrum::electrum_client::{Client, ConfigBuilder, ElectrumApi, Error as ElectrumError};
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Txid, consensus::deserialize};
use rand::Rng;

use crate::{
    bitcoin::{ObservationTarget, ObservedOutput, PlannedObservation},
    chain_history::{ChainHistoryPort, ClaimScanError},
    config::BitcoinNetwork,
    domain::payment::BitcoinOutpoint,
    persistence::{BitcoinObservationInput, InvoiceStore, PendingCandidate, PersistenceError},
    runtime::{ElectrumProbe, Runtime},
};

/// Oldest-observation age that triggers the backlog metric and WARN log.
pub const BACKLOG_ALERT_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// Requests reserved from each tick's budget for the active health probe
/// (`headers.subscribe` + `block_header(0)`), so the configured rate bounds
/// the probe and the observation batch together.
pub const PROBE_REQUESTS_PER_TICK: u64 = 2;

/// Consecutive per-address lookup failures across distinct addresses that
/// degrade endpoint availability. This is the explicit endpoint-failure
/// rule: a single oversized, timed-out, or errored response for one address
/// never marks Electrum unavailable and never discards the tick's other
/// observations; only a streak of failures for three pairwise-distinct
/// addresses with no intervening success is treated as an endpoint-level
/// condition (alongside connect failure and tip-probe failure, which
/// degrade immediately). A single address that fails every time it is
/// retried cannot trip the gate on its own.
pub const MAX_CONSECUTIVE_ADDRESS_FAILURES: u32 = 3;

const BACKOFF_INITIAL: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);

const MAINNET_GENESIS_HASH: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const TESTNET_GENESIS_HASH: &str =
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
const SIGNET_GENESIS_HASH: &str =
    "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
const REGTEST_GENESIS_HASH: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

/// Hardcoded canonical genesis block hash for each supported network. The
/// active health probe rejects any endpoint whose chain does not anchor here.
pub fn expected_genesis_hash(network: &BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Mainnet => MAINNET_GENESIS_HASH,
        BitcoinNetwork::Testnet => TESTNET_GENESIS_HASH,
        BitcoinNetwork::Signet => SIGNET_GENESIS_HASH,
        BitcoinNetwork::Regtest => REGTEST_GENESIS_HASH,
    }
}

/// Chain tip facts returned by the active health probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipProbe {
    pub height: u32,
    /// Tip block timestamp (seconds since the UNIX epoch).
    pub time_unix: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreationSnapshot {
    pub tip_height: u32,
    pub baseline_outputs: Vec<OutPoint>,
    pub unconfirmed_inputs: Vec<OutPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateTransaction {
    pub txid: Txid,
    pub inputs: Vec<OutPoint>,
}

/// One tick's observation response with per-address outcomes. `outputs`
/// holds the matched outputs of every successfully looked-up address;
/// `observed` and `failed` partition the requested target addresses so the
/// tick stamps only successful lookups and leaves failed targets stale for
/// the next tick. One failed address never discards the others' results.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservationReport {
    pub outputs: Vec<ObservedOutput>,
    /// Target addresses whose `list_unspent` lookup succeeded.
    pub observed: Vec<String>,
    /// Target addresses whose lookup timed out or errored; they keep their
    /// staleness and lead the next tick's plan.
    pub failed: Vec<String>,
}

/// Production Electrum adapters are injected here. This boundary deliberately
/// does not prescribe an Electrum wire protocol or invent payer messages.
#[async_trait]
pub trait ElectrumPort: Send + Sync {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
    ) -> Result<CreationSnapshot, ObserverError> {
        Err(ObserverError::Unavailable)
    }

    async fn candidate_transaction(
        &self,
        _txid: Txid,
        _max_transaction_bytes: usize,
    ) -> Result<CandidateTransaction, ObserverError> {
        Err(ObserverError::Unavailable)
    }

    /// Observes each target independently with one `list_unspent` lookup per
    /// address, deriving confirmations from `tip_height` (the tip returned
    /// by this tick's probe). A per-address failure is reported in the
    /// report, never by failing the whole batch; `Err` is reserved for
    /// endpoint-level conditions (the initial connect failing).
    async fn observations(
        &self,
        tip_height: u32,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError>;

    /// Active liveness probe: returns the chain tip and proves the endpoint's
    /// genesis block matches the configured network.
    async fn probe(&self) -> Result<TipProbe, ObserverError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverError {
    Unavailable,
    WrongNetwork,
    InvalidObservation,
    Persistence,
    /// A tick stamp matched no invoice row: the lookup hash derived from
    /// the observed address failed to match the stored hash. Other records
    /// were still stamped; the tick reports this named error so the miss
    /// cannot silently pin the same head target forever.
    ObservationStampMiss,
}

/// Durable side of the observer: plans, applies, and records one tick. The
/// production implementation is [`InvoiceStore`]; tests inject fakes.
#[async_trait]
pub trait ObservationBackend: Send + Sync {
    /// Loads the non-final observation plan, oldest successful observation first.
    async fn observation_plan(&self) -> Result<Vec<PlannedObservation>, ObserverError>;
    /// Validates and persists one fetched batch for the requested targets.
    async fn apply_observations(
        &self,
        network: &BitcoinNetwork,
        targets: &[ObservationTarget],
        outputs: Vec<ObservedOutput>,
    ) -> Result<usize, ObserverError>;
    /// Stamps the successfully observed target addresses. Returns the
    /// number of records whose stamp matched no invoice row; misses are
    /// logged and counted but never abort the other records.
    async fn record_observation_tick(&self, addresses: &[String]) -> Result<u64, ObserverError>;
    async fn pending_candidates(&self) -> Result<Vec<PendingCandidate>, ObserverError> {
        Ok(Vec::new())
    }
    async fn resolve_candidate(
        &self,
        _candidate: &PendingCandidate,
        _inputs: &[OutPoint],
    ) -> Result<(), ObserverError> {
        Err(ObserverError::Persistence)
    }
}

#[async_trait]
impl ObservationBackend for InvoiceStore {
    async fn observation_plan(&self) -> Result<Vec<PlannedObservation>, ObserverError> {
        InvoiceStore::observation_plan(self)
            .await
            .map_err(map_persistence)
    }

    async fn apply_observations(
        &self,
        network: &BitcoinNetwork,
        targets: &[ObservationTarget],
        outputs: Vec<ObservedOutput>,
    ) -> Result<usize, ObserverError> {
        let validated = validate_batch(outputs, network, targets)?;
        self.apply_bitcoin_observation_batch(&validated)
            .await
            .map_err(map_persistence)
    }

    async fn record_observation_tick(&self, addresses: &[String]) -> Result<u64, ObserverError> {
        InvoiceStore::record_observation_tick(self, addresses)
            .await
            .map_err(map_persistence)
    }

    async fn pending_candidates(&self) -> Result<Vec<PendingCandidate>, ObserverError> {
        InvoiceStore::pending_candidates(self)
            .await
            .map_err(map_persistence)
    }

    async fn resolve_candidate(
        &self,
        candidate: &PendingCandidate,
        inputs: &[OutPoint],
    ) -> Result<(), ObserverError> {
        InvoiceStore::resolve_candidate(self, candidate, inputs)
            .await
            .map_err(map_persistence)
    }
}

/// Cluster-wide observer leadership boundary. Exactly one replica may run
/// observation ticks at a time; implementations re-assert the underlying
/// lock or lease on every call, so takeover is fail-closed: while another
/// replica leads, `is_leader` returns `false` and this replica idles, and
/// when the leader's lease expires (its session dies) a later call returns
/// `true` here. A check that errors is treated as "not leader".
#[async_trait]
pub trait ObserverLeadership: Send + Sync {
    async fn is_leader(&self) -> Result<bool, ObserverError>;
}

#[async_trait]
impl ObserverLeadership for crate::persistence::PgObserverLeadership {
    async fn is_leader(&self) -> Result<bool, ObserverError> {
        crate::persistence::PgObserverLeadership::is_leader(self)
            .await
            .map_err(map_persistence)
    }
}

/// Bounded Electrum request policy for one observer deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObserverPolicy {
    pub poll_interval: Duration,
    /// Hard cap on Electrum lookups admitted to one tick, including the
    /// tick's two probe requests ([`PROBE_REQUESTS_PER_TICK`]), which are
    /// reserved before observation targets are admitted. Each admitted
    /// target costs exactly one `list_unspent` lookup; there is no bypass,
    /// no slow lane, and no unmetered admission of any kind.
    pub max_requests_per_tick: u32,
    /// Sustained rate budget; the per-tick allowance is this rate times the
    /// poll interval, so lookups per second stay at or below it.
    pub max_requests_per_second: u32,
    pub max_transaction_bytes: usize,
}

impl ObserverPolicy {
    /// Effective per-tick lookup budget: the hard cap bounded further by the
    /// sustained rate allowance for one poll interval.
    pub fn per_tick_budget(&self) -> u64 {
        let rate_allowance = u64::from(self.max_requests_per_second) * self.poll_interval.as_secs();
        u64::from(self.max_requests_per_tick).min(rate_allowance)
    }
}

/// Result of splitting one plan into this tick's batch and the deferred tail.
#[derive(Debug)]
pub struct BudgetSelection {
    pub batch: Vec<PlannedObservation>,
    pub deferred: Vec<PlannedObservation>,
}

/// Walks the oldest-first plan and admits exactly as many targets as the
/// lookup budget allows; the remainder is deferred to the next tick and,
/// keeping its staleness, is admitted first then. Every target costs
/// exactly one lookup, so admission is a strict prefix of the plan: no
/// bypass, no skipping, no slow lane. Observing a target stamps it, so an
/// admitted target rotates behind the deferred tail and every target is
/// observed within a bounded number of ticks.
pub fn select_within_budget(plan: Vec<PlannedObservation>, budget: u64) -> BudgetSelection {
    let admit = usize::try_from(budget).unwrap_or(usize::MAX);
    let mut plan = plan;
    let deferred = plan.split_off(plan.len().min(admit));
    BudgetSelection {
        batch: plan,
        deferred,
    }
}

/// Tracks consecutive per-address lookup failures to decide when they stop
/// being isolated address conditions and become an endpoint condition.
/// Rule (see [`MAX_CONSECUTIVE_ADDRESS_FAILURES`]): any successful lookup
/// resets the streak; a failure for the same address as the previous
/// failure does not extend it, so one repeatedly failing address (for
/// example an address dusted until its response times out) degrades only
/// its own observation cadence.
#[derive(Clone, Debug, Default)]
pub struct AddressFailureGate {
    consecutive: u32,
    last_failed: Option<String>,
}

impl AddressFailureGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one tick's per-address outcomes into the streak and returns
    /// whether the endpoint must now be treated as unavailable.
    pub fn record_tick(&mut self, failed: &[String], any_success: bool) -> bool {
        if any_success {
            self.consecutive = 0;
            self.last_failed = None;
            return false;
        }
        for address in failed {
            if self.last_failed.as_deref() != Some(address.as_str()) {
                self.consecutive = self.consecutive.saturating_add(1);
                self.last_failed = Some(address.clone());
            }
        }
        self.consecutive >= MAX_CONSECUTIVE_ADDRESS_FAILURES
    }
}

/// Poll interval with ±20% jitter so co-located observers do not synchronize
/// their request bursts against a shared Electrum endpoint.
pub fn jittered_interval(base: Duration) -> Duration {
    let percent = rand::rng().random_range(80..=120_u32);
    base.saturating_mul(percent) / 100
}

/// Exponential backoff after `ObserverError::Unavailable`: 30 s, doubling to
/// a 15-minute cap, reset by any successful tick.
#[derive(Clone, Debug, Default)]
pub struct ObserverBackoff {
    consecutive_failures: u32,
}

impl ObserverBackoff {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1).min(32);
    }

    pub fn reset(&mut self) {
        self.consecutive_failures = 0;
    }

    pub fn is_backing_off(&self) -> bool {
        self.consecutive_failures > 0
    }

    /// Delay before the next attempt given the recorded failures so far.
    pub fn delay(&self) -> Duration {
        if self.consecutive_failures == 0 {
            return Duration::ZERO;
        }
        let shift = (self.consecutive_failures - 1).min(31);
        BACKOFF_INITIAL
            .saturating_mul(1_u32 << shift)
            .min(BACKOFF_MAX)
    }

    /// Folds one observer tick outcome into the backoff schedule: an
    /// `Unavailable` probe or endpoint failure records a failure; a
    /// successful tick resets the schedule. A stamp miss also resets it: the
    /// tick reached Electrum and committed the other records, so a
    /// persistent miss must not hold the observer at the backoff cap after
    /// an outage recovered. Ticks with isolated per-address failures are
    /// successful ticks: they reached the endpoint and committed the
    /// successful addresses' observations.
    pub fn record_outcome(&mut self, outcome: &ObserverTickOutcome) {
        match outcome {
            ObserverTickOutcome::ProbeFailed(ObserverError::Unavailable)
            | ObserverTickOutcome::ObservationFailed(ObserverError::Unavailable) => {
                self.record_failure();
            }
            ObserverTickOutcome::Observed { .. }
            | ObserverTickOutcome::ObservationFailed(ObserverError::ObservationStampMiss) => {
                self.reset();
            }
            ObserverTickOutcome::ProbeFailed(_)
            | ObserverTickOutcome::ObservationFailed(_)
            | ObserverTickOutcome::PlanUnavailable => {}
        }
    }
}

/// What one observer tick established, in secret-free terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverTickOutcome {
    /// The active health probe failed with the named error.
    ProbeFailed(ObserverError),
    /// The durable observation plan could not be loaded.
    PlanUnavailable,
    /// Fetching, validating, applying, or recording observations failed.
    ObservationFailed(ObserverError),
    /// The tick probed and observed successfully; `failed` counts isolated
    /// per-address lookup failures whose targets keep their staleness.
    Observed {
        processed: usize,
        deferred: usize,
        failed: usize,
    },
}

/// Runs one bounded observer tick: active probe, plan, budgeted batch,
/// persistence, and health publication. The empty-target case still probes
/// and reports availability from the probe alone. `failure_gate` carries
/// the cross-tick per-address failure streak; the tick records its failed
/// lookups into it, and only a tripped gate (or a probe/connect failure)
/// degrades endpoint availability.
pub async fn observe_tick(
    port: &dyn ElectrumPort,
    backend: &dyn ObservationBackend,
    network: &BitcoinNetwork,
    policy: &ObserverPolicy,
    runtime: &Runtime,
    failure_gate: &mut AddressFailureGate,
) -> ObserverTickOutcome {
    let tip = match port.probe().await {
        Ok(tip) => {
            runtime.record_electrum_probe(ElectrumProbe::success(tip.height, tip.time_unix));
            tip
        }
        Err(ObserverError::WrongNetwork) => {
            runtime.record_electrum_probe(ElectrumProbe::genesis_mismatch());
            runtime.set_electrum_available(false);
            tracing::warn!(
                error = "wrong_network",
                "electrum endpoint genesis block does not match the configured bitcoin network"
            );
            return ObserverTickOutcome::ProbeFailed(ObserverError::WrongNetwork);
        }
        Err(error) => {
            runtime.record_electrum_probe_failure();
            runtime.set_electrum_available(false);
            return ObserverTickOutcome::ProbeFailed(error);
        }
    };
    let plan = match backend.observation_plan().await {
        Ok(plan) => plan,
        Err(_) => {
            runtime.set_electrum_available(false);
            return ObserverTickOutcome::PlanUnavailable;
        }
    };
    let oldest_staleness = plan
        .first()
        .map(|entry| entry.staleness())
        .unwrap_or_default();
    runtime.metrics().set_electrum_backlog_oldest_age_seconds(
        i64::try_from(oldest_staleness.as_secs()).unwrap_or(i64::MAX),
    );
    if oldest_staleness > BACKLOG_ALERT_THRESHOLD {
        tracing::warn!(
            staleness_secs = oldest_staleness.as_secs(),
            "oldest pending electrum observation exceeds the backlog alert threshold"
        );
    }

    // The active probe issues requests of its own; reserve them so the
    // configured rate bounds the probe and the observation batch together.
    let lookup_budget = policy
        .per_tick_budget()
        .saturating_sub(PROBE_REQUESTS_PER_TICK);
    let selection = select_within_budget(plan, lookup_budget);
    let processed = selection.batch.len();
    let deferred = selection.deferred.len();
    if selection.batch.is_empty() {
        runtime.set_electrum_available(true);
        return ObserverTickOutcome::Observed {
            processed,
            deferred,
            failed: 0,
        };
    }
    let targets: Vec<ObservationTarget> = selection
        .batch
        .iter()
        .map(|entry| entry.target().clone())
        .collect();
    let report = match port.observations(tip.height, &targets).await {
        Ok(report) => report,
        Err(error) => {
            runtime.set_electrum_available(false);
            return ObserverTickOutcome::ObservationFailed(error);
        }
    };
    let failed_count = report.failed.len();
    if failed_count > 0 {
        runtime
            .metrics()
            .electrum_observation_address_failures(u64::try_from(failed_count).unwrap_or(u64::MAX));
        tracing::warn!(
            failed = failed_count,
            succeeded = report.observed.len(),
            "isolated per-address electrum lookup failures this tick; failed targets stay stale"
        );
    }
    tracing::info!(
        lookups = processed,
        deferred,
        failed = failed_count,
        "electrum observation batch completed"
    );
    let observed_targets: Vec<ObservationTarget> = selection
        .batch
        .iter()
        .filter(|entry| {
            report
                .observed
                .iter()
                .any(|address| address == entry.target().address())
        })
        .map(|entry| entry.target().clone())
        .collect();
    if let Err(error) = backend
        .apply_observations(network, &observed_targets, report.outputs)
        .await
    {
        runtime.set_electrum_available(false);
        return ObserverTickOutcome::ObservationFailed(error);
    }
    if u64::try_from(processed).unwrap_or(u64::MAX) < lookup_budget
        && let Ok(candidates) = backend.pending_candidates().await
        && let Some(candidate) = candidates.first()
        && let Ok(transaction) = port
            .candidate_transaction(candidate.outpoint.txid, policy.max_transaction_bytes)
            .await
        && transaction.txid == candidate.outpoint.txid
        && let Err(error) = backend
            .resolve_candidate(candidate, &transaction.inputs)
            .await
    {
        runtime.set_electrum_available(false);
        return ObserverTickOutcome::ObservationFailed(error);
    }
    let misses = match backend.record_observation_tick(&report.observed).await {
        Ok(misses) => misses,
        Err(error) => {
            runtime.set_electrum_available(false);
            return ObserverTickOutcome::ObservationFailed(error);
        }
    };
    if misses > 0 {
        // A stamp miss means a target's lookup hash matched no invoice row:
        // left silent, the head would never rotate and the same target
        // would be re-observed every tick. The other records were stamped;
        // surface the miss as a named tick failure. The tick itself reached
        // Electrum and committed the other records, so availability
        // recovers and the loop's backoff resets: a persistent miss must
        // not hold the observer at the backoff cap after an outage has
        // already recovered.
        runtime.metrics().electrum_observation_stamp_misses(misses);
        runtime.set_electrum_available(true);
        return ObserverTickOutcome::ObservationFailed(ObserverError::ObservationStampMiss);
    }
    // Isolated per-address failures degrade only the failed targets (they
    // keep their staleness and lead the next plan). The endpoint degrades
    // solely on the documented rule: a streak of failures across distinct
    // addresses with no intervening success.
    if failure_gate.record_tick(&report.failed, !report.observed.is_empty()) {
        tracing::error!(
            consecutive_failures = MAX_CONSECUTIVE_ADDRESS_FAILURES,
            "consecutive per-address electrum lookup failures across distinct addresses; \
             treating the endpoint as unavailable"
        );
        runtime.set_electrum_available(false);
        return ObserverTickOutcome::ObservationFailed(ObserverError::Unavailable);
    }
    runtime.set_electrum_available(true);
    ObserverTickOutcome::Observed {
        processed,
        deferred,
        failed: failed_count,
    }
}

/// Long-running observer worker: one bounded tick per jittered poll interval,
/// with exponential backoff while the endpoint reports `Unavailable`. Only
/// the leadership holder ticks; other replicas idle (logged once per
/// transition) and re-check every interval, so a dead leader is succeeded
/// fail-closed without two replicas ever stamping the same tick.
pub async fn observation_loop(
    port: Arc<dyn ElectrumPort>,
    backend: Arc<dyn ObservationBackend>,
    leadership: Arc<dyn ObserverLeadership>,
    network: BitcoinNetwork,
    policy: ObserverPolicy,
    runtime: Arc<Runtime>,
) {
    let mut backoff = ObserverBackoff::new();
    let mut failure_gate = AddressFailureGate::new();
    let mut first_tick = true;
    let mut was_leader = true;
    loop {
        let delay = if first_tick {
            Duration::ZERO
        } else if backoff.is_backing_off() {
            backoff.delay()
        } else {
            jittered_interval(policy.poll_interval)
        };
        first_tick = false;
        tokio::select! {
            _ = runtime.cancelled() => break,
            _ = tokio::time::sleep(delay) => {}
        }
        if !runtime.may_start_worker_claim() {
            break;
        }
        match leadership.is_leader().await {
            Ok(true) => {
                if !was_leader {
                    tracing::info!(
                        "observer leadership acquired; this replica is the active observer"
                    );
                    was_leader = true;
                }
            }
            Ok(false) => {
                if was_leader {
                    tracing::info!("another replica holds observer leadership; this replica idles");
                    was_leader = false;
                }
                continue;
            }
            Err(_) => {
                // Fail closed: without a leadership verdict this replica must
                // not observe, so a second replica can never double-stamp.
                if was_leader {
                    tracing::warn!("observer leadership check failed; idling fail-closed");
                    was_leader = false;
                }
                continue;
            }
        }
        let outcome = observe_tick(
            port.as_ref(),
            backend.as_ref(),
            &network,
            &policy,
            &runtime,
            &mut failure_gate,
        )
        .await;
        backoff.record_outcome(&outcome);
    }
}

/// Concrete synchronous Electrum client isolated behind the async observation port.
pub struct ElectrumAdapter {
    endpoint: Arc<str>,
    network: BitcoinNetwork,
    timeout: Duration,
    retries: u8,
}

impl ElectrumAdapter {
    fn clone_for_fetch(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            network: self.network.clone(),
            timeout: self.timeout,
            retries: self.retries,
        }
    }

    /// Constructs a production adapter without requiring the remote endpoint to be online.
    pub fn configured(
        endpoint: impl Into<String>,
        network: BitcoinNetwork,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ObserverError> {
        let endpoint = endpoint.into();
        let parsed = url::Url::parse(&endpoint).map_err(|_| ObserverError::Unavailable)?;
        if !matches!(parsed.scheme(), "tcp" | "ssl")
            || parsed.host_str().is_none()
            || parsed.port().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ObserverError::Unavailable);
        }
        Ok(Self {
            endpoint: endpoint.into(),
            network,
            timeout,
            retries,
        })
    }

    pub async fn connect(
        endpoint: impl Into<String>,
        network: BitcoinNetwork,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ObserverError> {
        let adapter = Self::configured(endpoint, network, timeout, retries)?;
        adapter.raw_client().await?;
        Ok(adapter)
    }

    async fn raw_client(&self) -> Result<Client, ObserverError> {
        let config = ConfigBuilder::new()
            .timeout(Some(self.timeout))
            .retry(self.retries)
            .build();
        let endpoint = self.endpoint.clone();
        tokio::task::spawn_blocking(move || Client::from_config(&endpoint, config))
            .await
            .map_err(|_| ObserverError::Unavailable)?
            .map_err(|_| ObserverError::Unavailable)
    }

    fn raw_client_blocking(&self) -> Result<Client, ElectrumError> {
        let config = ConfigBuilder::new()
            .timeout(Some(self.timeout))
            .retry(self.retries)
            .build();
        Client::from_config(&self.endpoint, config)
    }
}

#[async_trait]
impl ElectrumPort for ElectrumAdapter {
    async fn creation_snapshot(
        &self,
        address: &str,
        max_history_entries: usize,
        max_transaction_bytes: usize,
    ) -> Result<CreationSnapshot, ObserverError> {
        let adapter = self.clone_for_fetch();
        let address = address.to_owned();
        tokio::task::spawn_blocking(move || {
            let client = adapter.raw_client_blocking().map_err(map_electrum)?;
            let address = parse_address(&address, adapter.network.as_bitcoin_network())?;
            let notification = client.block_headers_subscribe().map_err(map_electrum)?;
            let history = client
                .script_get_history(address.script_pubkey().as_script())
                .map_err(map_electrum)?;
            if history.len() > max_history_entries {
                return Err(ObserverError::Unavailable);
            }
            let unspent = client
                .script_list_unspent(address.script_pubkey().as_script())
                .map_err(map_electrum)?;
            let mut baseline_outputs = unspent
                .into_iter()
                .map(|item| {
                    Ok(OutPoint::new(
                        item.tx_hash,
                        u32::try_from(item.tx_pos)
                            .map_err(|_| ObserverError::InvalidObservation)?,
                    ))
                })
                .collect::<Result<Vec<_>, ObserverError>>()?;
            let mut unconfirmed_inputs = Vec::new();
            for entry in history.into_iter().filter(|entry| entry.height <= 0) {
                let transaction =
                    fetch_transaction_blocking(&client, entry.tx_hash, max_transaction_bytes)?;
                unconfirmed_inputs.extend(
                    transaction
                        .input
                        .into_iter()
                        .map(|input| input.previous_output),
                );
            }
            baseline_outputs.sort_unstable();
            baseline_outputs.dedup();
            unconfirmed_inputs.sort_unstable();
            unconfirmed_inputs.dedup();
            Ok(CreationSnapshot {
                tip_height: u32::try_from(notification.height)
                    .map_err(|_| ObserverError::InvalidObservation)?,
                baseline_outputs,
                unconfirmed_inputs,
            })
        })
        .await
        .map_err(|_| ObserverError::Unavailable)?
    }

    async fn candidate_transaction(
        &self,
        txid: Txid,
        max_transaction_bytes: usize,
    ) -> Result<CandidateTransaction, ObserverError> {
        let adapter = self.clone_for_fetch();
        tokio::task::spawn_blocking(move || {
            let client = adapter.raw_client_blocking().map_err(map_electrum)?;
            let transaction = fetch_transaction_blocking(&client, txid, max_transaction_bytes)?;
            Ok(CandidateTransaction {
                txid,
                inputs: transaction
                    .input
                    .into_iter()
                    .map(|input| input.previous_output)
                    .collect(),
            })
        })
        .await
        .map_err(|_| ObserverError::Unavailable)?
    }

    async fn observations(
        &self,
        tip_height: u32,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        let adapter = Self {
            endpoint: self.endpoint.clone(),
            network: self.network.clone(),
            timeout: self.timeout,
            retries: self.retries,
        };
        let targets = targets.to_vec();
        tokio::task::spawn_blocking(move || {
            // A connect failure before any lookup is an endpoint-level
            // condition; per-address failures after it are isolated.
            let mut client = adapter
                .raw_client_blocking()
                .map_err(|_| ObserverError::Unavailable)?;
            let mut report = ObservationReport::default();
            for (index, target) in targets.iter().enumerate() {
                match observe_address_blocking(&client, &adapter.network, tip_height, target) {
                    Ok(outputs) => {
                        report.observed.push(target.address().to_owned());
                        report.outputs.extend(outputs);
                    }
                    Err(_) => {
                        report.failed.push(target.address().to_owned());
                        // A failed (for example timed-out) response can leave
                        // the connection's response stream desynchronized, so
                        // the remaining addresses are fetched over a fresh
                        // connection. A reconnect failure fails the remaining
                        // addresses without discarding the observations
                        // already collected.
                        match adapter.raw_client_blocking() {
                            Ok(fresh) => client = fresh,
                            Err(_) => {
                                report.failed.extend(
                                    targets[index + 1..]
                                        .iter()
                                        .map(|target| target.address().to_owned()),
                                );
                                break;
                            }
                        }
                    }
                }
            }
            Ok(report)
        })
        .await
        .map_err(|_| ObserverError::Unavailable)?
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        let client = self.raw_client().await?;
        let network = self.network.clone();
        tokio::task::spawn_blocking(move || {
            let notification = client.block_headers_subscribe().map_err(map_electrum)?;
            let genesis = client.block_header(0).map_err(map_electrum)?;
            if genesis.block_hash().to_string() != expected_genesis_hash(&network) {
                return Err(ObserverError::WrongNetwork);
            }
            Ok(TipProbe {
                height: u32::try_from(notification.height)
                    .map_err(|_| ObserverError::InvalidObservation)?,
                time_unix: notification.header.time,
            })
        })
        .await
        .map_err(|_| ObserverError::Unavailable)?
    }
}

/// Claim-time history scan on the same adapter the observer uses (design
/// §B.5). The observer tick never calls this port — the scan runs only in the
/// claim handler — so this adds no Electrum calls to observation. Each batch
/// runs bounded and blocking on its own dedicated connection with the
/// configured timeout and retries, exactly like
/// [`ElectrumPort::creation_snapshot`], and every failure maps to
/// [`ClaimScanError::Unavailable`] so the claim is refused rather than
/// defaulted to index 0.
#[async_trait]
impl ChainHistoryPort for ElectrumAdapter {
    async fn history_presence_batch(
        &self,
        scripts: &[ScriptBuf],
    ) -> Result<Vec<bool>, ClaimScanError> {
        let adapter = self.clone_for_fetch();
        let scripts = scripts.to_vec();
        tokio::task::spawn_blocking(move || {
            let client = adapter
                .raw_client_blocking()
                .map_err(|_| ClaimScanError::Unavailable)?;
            let refs: Vec<&bitcoin::Script> = scripts.iter().map(ScriptBuf::as_script).collect();
            // ONE batched get_history round-trip for the window; presence
            // only, so transactions are never fetched.
            let histories = client
                .batch_script_get_history(refs)
                .map_err(|_| ClaimScanError::Unavailable)?;
            if histories.len() != scripts.len() {
                // A malformed response is an Electrum failure, not an empty
                // window.
                return Err(ClaimScanError::Unavailable);
            }
            Ok(histories
                .iter()
                .map(|history| !history.is_empty())
                .collect())
        })
        .await
        .map_err(|_| ClaimScanError::Unavailable)?
    }
}

/// Observes one address with a single `script_list_unspent` call. Every
/// returned item becomes a present output; a previously tracked outpoint
/// missing from the unspent set becomes the same absence record the
/// settlement layer already consumes. Any error fails this address only;
/// the caller isolates it from the rest of the tick.
fn observe_address_blocking(
    client: &Client,
    network: &BitcoinNetwork,
    tip_height: u32,
    target: &ObservationTarget,
) -> Result<Vec<ObservedOutput>, ObserverError> {
    let expected_network = network.as_bitcoin_network();
    let address = parse_address(target.address(), expected_network)?;
    let unspent = client
        .script_list_unspent(address.script_pubkey().as_script())
        .map_err(map_electrum)?;
    let mut outputs = Vec::with_capacity(unspent.len() + 1);
    let mut seen_outpoints = HashSet::with_capacity(unspent.len());
    for item in unspent {
        // electrum-client 0.25 types `ListUnspentRes.height` as `usize`, so
        // the Electrum `get_history` convention of -1 for unconfirmed-with-
        // unconfirmed-parents cannot be represented here: height 0 is the
        // only unconfirmed marker this response can carry.
        let confirmations = if item.height == 0 {
            0
        } else {
            let height =
                u32::try_from(item.height).map_err(|_| ObserverError::InvalidObservation)?;
            tip_height
                .checked_sub(height)
                .and_then(|distance| distance.checked_add(1))
                .ok_or(ObserverError::InvalidObservation)?
        };
        let outpoint = bitcoin::OutPoint::new(
            item.tx_hash,
            u32::try_from(item.tx_pos).map_err(|_| ObserverError::InvalidObservation)?,
        );
        seen_outpoints.insert(outpoint);
        outputs.push(ObservedOutput {
            network: network.clone(),
            address: address.to_string(),
            outpoint,
            sats: item.value,
            confirmations,
            confirmed_height: (item.height != 0)
                .then(|| u32::try_from(item.height))
                .transpose()
                .map_err(|_| ObserverError::InvalidObservation)?,
            present: true,
        });
    }
    if let Some(current) = target.current()
        && !seen_outpoints.contains(&current.outpoint())
    {
        outputs.push(ObservedOutput {
            network: network.clone(),
            address: address.to_string(),
            outpoint: current.outpoint(),
            sats: current.sats(),
            confirmations: 0,
            confirmed_height: None,
            present: false,
        });
    }
    Ok(outputs)
}

fn map_electrum(_: ElectrumError) -> ObserverError {
    ObserverError::Unavailable
}

fn fetch_transaction_blocking(
    client: &Client,
    txid: Txid,
    max_transaction_bytes: usize,
) -> Result<bitcoin::Transaction, ObserverError> {
    let raw = client.transaction_get_raw(&txid).map_err(map_electrum)?;
    if raw.len() > max_transaction_bytes {
        return Err(ObserverError::Unavailable);
    }
    deserialize(&raw).map_err(|_| ObserverError::InvalidObservation)
}

fn parse_address(address: &str, network: Network) -> Result<Address, ObserverError> {
    Address::from_str(address)
        .map_err(|_| ObserverError::InvalidObservation)?
        .require_network(network)
        .map_err(|_| ObserverError::WrongNetwork)
}

fn validate_batch(
    observations: Vec<ObservedOutput>,
    network: &BitcoinNetwork,
    targets: &[ObservationTarget],
) -> Result<Vec<BitcoinObservationInput>, ObserverError> {
    let expected_network = network.as_bitcoin_network();
    let mut targets_by_address = HashMap::with_capacity(targets.len());
    for target in targets {
        let address = parse_address(target.address(), expected_network)?;
        if address.to_string() != target.address()
            || targets_by_address
                .insert(target.address(), target)
                .is_some()
        {
            return Err(ObserverError::InvalidObservation);
        }
    }
    let mut outpoints = HashSet::with_capacity(observations.len());
    let mut validated = observations
        .into_iter()
        .map(|output| {
            if &output.network != network {
                return Err(ObserverError::WrongNetwork);
            }
            if i32::try_from(output.confirmations).is_err()
                || (!output.present && output.confirmations != 0)
                || (output.confirmations == 0) != output.confirmed_height.is_none()
            {
                return Err(ObserverError::InvalidObservation);
            }
            let address = parse_address(&output.address, expected_network)?;
            if address.to_string() != output.address {
                return Err(ObserverError::InvalidObservation);
            }
            let target = targets_by_address
                .get(output.address.as_str())
                .ok_or(ObserverError::InvalidObservation)?;
            if !output.present
                && !target.current().is_some_and(|current| {
                    current.outpoint() == output.outpoint && current.sats() == output.sats
                })
            {
                return Err(ObserverError::InvalidObservation);
            }
            if !outpoints.insert(output.outpoint) {
                return Err(ObserverError::InvalidObservation);
            }
            let outpoint = BitcoinOutpoint::from_bitcoin(output.outpoint);
            Ok(BitcoinObservationInput {
                address: output.address,
                outpoint,
                observed_sats: output.sats,
                confirmations: output.confirmations,
                confirmed_height: output.confirmed_height,
                present: output.present,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validated.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| left.outpoint.txid().cmp(right.outpoint.txid()))
            .then_with(|| left.outpoint.vout().cmp(&right.outpoint.vout()))
    });
    Ok(validated)
}

fn map_persistence(_: PersistenceError) -> ObserverError {
    ObserverError::Persistence
}

#[cfg(test)]
mod tests {
    use bitcoin::constants::genesis_block;

    use super::*;

    fn target(label: &str) -> ObservationTarget {
        ObservationTarget::new(format!("addr-{label}"), None)
    }

    fn planned(label: &str) -> PlannedObservation {
        PlannedObservation::new(target(label), Duration::ZERO)
    }

    fn labels(entries: &[PlannedObservation]) -> Vec<String> {
        entries
            .iter()
            .map(|entry| entry.target().address().to_owned())
            .collect()
    }

    #[test]
    fn budget_admits_an_oldest_first_prefix_and_defers_the_remainder() {
        let plan = vec![planned("stale"), planned("middle"), planned("fresh")];
        let selection = select_within_budget(plan, 2);
        assert_eq!(labels(&selection.batch), vec!["addr-stale", "addr-middle"]);
        assert_eq!(labels(&selection.deferred), vec!["addr-fresh"]);

        // Zero budget admits nothing; a budget beyond the plan admits all.
        let selection = select_within_budget(vec![planned("a"), planned("b")], 0);
        assert!(selection.batch.is_empty());
        assert_eq!(labels(&selection.deferred), vec!["addr-a", "addr-b"]);
        let selection = select_within_budget(vec![planned("a"), planned("b")], 99);
        assert_eq!(labels(&selection.batch), vec!["addr-a", "addr-b"]);
        assert!(selection.deferred.is_empty());
    }

    #[test]
    fn the_gate_rejects_exactly_one_extra_lookup() {
        // Every target costs exactly one lookup: a plan one target larger
        // than the budget admits the budget exactly and defers exactly one.
        let plan: Vec<PlannedObservation> =
            (0..6).map(|index| planned(&format!("t{index}"))).collect();
        let selection = select_within_budget(plan, 5);
        assert_eq!(selection.batch.len(), 5);
        assert_eq!(labels(&selection.deferred), vec!["addr-t5"]);
    }

    #[test]
    fn every_target_is_observed_within_n_ticks_of_a_sustained_over_budget_set() {
        use std::collections::{HashSet, VecDeque};

        const TARGETS: usize = 5;
        let mut oldest_first: VecDeque<String> = (0..TARGETS)
            .map(|index| format!("target-{index}"))
            .collect();
        let mut observed: HashSet<String> = HashSet::new();
        for _ in 0..TARGETS {
            let plan = oldest_first
                .iter()
                .map(|address| {
                    PlannedObservation::new(
                        ObservationTarget::new(address.clone(), None),
                        Duration::ZERO,
                    )
                })
                .collect();
            let selection = select_within_budget(plan, 1);
            assert_eq!(selection.batch.len(), 1, "budget 1 admits the oldest");
            for entry in selection.batch {
                let address = entry.target().address().to_owned();
                observed.insert(address.clone());
                // A successful observation stamps the head, rotating it
                // behind the deferred tail.
                oldest_first.retain(|pending| *pending != address);
                oldest_first.push_back(address);
            }
        }
        assert_eq!(
            observed.len(),
            TARGETS,
            "every target must be observed within {TARGETS} ticks"
        );
    }

    #[test]
    fn the_failure_gate_trips_only_on_distinct_consecutive_failures() {
        let mut gate = AddressFailureGate::new();
        // One address failing on every retry never trips the gate.
        for _ in 0..10 {
            assert!(!gate.record_tick(&["a".to_owned()], false));
        }
        // Failures for distinct addresses with no intervening success do.
        assert!(!gate.record_tick(&["a".to_owned()], false));
        assert!(!gate.record_tick(&["b".to_owned()], false));
        assert!(gate.record_tick(&["c".to_owned()], false));
    }

    #[test]
    fn the_failure_gate_resets_on_any_success() {
        let mut gate = AddressFailureGate::new();
        assert!(!gate.record_tick(&["a".to_owned()], false));
        assert!(!gate.record_tick(&["b".to_owned()], false));
        assert!(!gate.record_tick(&["c".to_owned()], true));
        assert!(!gate.record_tick(&["a".to_owned()], false));
        assert!(!gate.record_tick(&["b".to_owned()], false));
        assert!(gate.record_tick(&["d".to_owned()], false));
    }

    #[test]
    fn per_tick_budget_is_the_rate_allowance_capped_by_the_hard_limit() {
        let policy = ObserverPolicy {
            poll_interval: Duration::from_secs(10),
            max_requests_per_tick: 1000,
            max_requests_per_second: 5,
            max_transaction_bytes: 400_000,
        };
        assert_eq!(policy.per_tick_budget(), 50);
        let capped = ObserverPolicy {
            max_requests_per_tick: 10,
            ..policy
        };
        assert_eq!(capped.per_tick_budget(), 10);
    }

    #[test]
    fn jitter_stays_within_twenty_percent_of_the_poll_interval() {
        let base = Duration::from_secs(10);
        for _ in 0..1_000 {
            let jittered = jittered_interval(base);
            assert!(jittered >= Duration::from_secs(8), "{jittered:?}");
            assert!(jittered <= Duration::from_secs(12), "{jittered:?}");
        }
    }

    #[test]
    fn backoff_doubles_from_thirty_seconds_to_a_fifteen_minute_cap() {
        let mut backoff = ObserverBackoff::new();
        assert!(!backoff.is_backing_off());
        assert_eq!(backoff.delay(), Duration::ZERO);
        for expected in [30, 60, 120, 240, 480, 900, 900, 900] {
            backoff.record_failure();
            assert!(backoff.is_backing_off());
            assert_eq!(backoff.delay(), Duration::from_secs(expected));
        }
        backoff.reset();
        assert!(!backoff.is_backing_off());
        assert_eq!(backoff.delay(), Duration::ZERO);
    }

    #[test]
    fn hardcoded_genesis_hashes_match_every_supported_network() {
        for network in [
            BitcoinNetwork::Mainnet,
            BitcoinNetwork::Testnet,
            BitcoinNetwork::Signet,
            BitcoinNetwork::Regtest,
        ] {
            let expected = genesis_block(network.as_bitcoin_network())
                .block_hash()
                .to_string();
            assert_eq!(expected_genesis_hash(&network), expected, "{network:?}");
        }
    }
}
