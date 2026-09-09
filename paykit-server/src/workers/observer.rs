//! Polling-independent direct Bitcoin observation worker boundary.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bdk_electrum::{
    BdkElectrumClient,
    bdk_core::{BlockId, CheckPoint, spk_client::SyncRequest},
    electrum_client::{Client, ConfigBuilder, ElectrumApi, Error as ElectrumError},
};
use bitcoin::{Address, Network, constants::genesis_block};
use rand::Rng;

use crate::{
    bitcoin::{ObservationTarget, ObservedOutput, PlannedObservation, TargetTickRecord},
    config::BitcoinNetwork,
    domain::payment::BitcoinOutpoint,
    persistence::{BitcoinObservationInput, InvoiceStore, PersistenceError},
    runtime::{ElectrumProbe, Runtime},
};

/// Oldest-observation age that triggers the backlog metric and WARN log.
pub const BACKLOG_ALERT_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// Requests reserved from each tick's budget for the active health probe
/// (`headers.subscribe` + `block_header(0)`), so the configured rate bounds
/// the probe and the observation batch together.
pub const PROBE_REQUESTS_PER_TICK: u64 = 2;

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

/// One target's history size as returned by the previous tick's fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetHistory {
    pub address: String,
    pub tx_count: u32,
}

/// One tick's observation response: matched outputs, the per-target
/// history sizes, and the actual number of Electrum requests the adapter
/// issued for the batch. The request count is measured at the client and
/// feeds the next tick's per-target cost estimate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservationReport {
    pub outputs: Vec<ObservedOutput>,
    pub history: Vec<TargetHistory>,
    /// Electrum requests actually issued for this batch.
    pub request_count: u64,
}

/// Production Electrum adapters are injected here. This boundary deliberately
/// does not prescribe an Electrum wire protocol or invent payer messages.
#[async_trait]
pub trait ElectrumPort: Send + Sync {
    async fn observations(
        &self,
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
    /// Persists per-target history sizes and stamps the targets observed.
    async fn record_observation_tick(
        &self,
        records: &[TargetTickRecord],
    ) -> Result<(), ObserverError>;
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

    async fn record_observation_tick(
        &self,
        records: &[TargetTickRecord],
    ) -> Result<(), ObserverError> {
        InvoiceStore::record_observation_tick(self, records)
            .await
            .map_err(map_persistence)
    }
}

/// Bounded Electrum request policy for one observer deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObserverPolicy {
    pub poll_interval: Duration,
    /// Hard cap on Electrum requests issued per tick. The tick's probe
    /// requests ([`PROBE_REQUESTS_PER_TICK`]) are reserved from this cap
    /// before observation targets are admitted.
    pub max_requests_per_tick: u32,
    /// Sustained rate budget; the per-tick allowance is this rate times the
    /// poll interval, so estimated requests per second stay at or below it.
    pub max_requests_per_second: u32,
}

impl ObserverPolicy {
    /// Effective per-tick request budget: the hard cap bounded further by the
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
    /// Estimated requests for the whole plan before trimming.
    pub estimated_requests: u64,
    /// Estimated cost of the oldest target when it alone exceeded the budget
    /// and was admitted by the head-of-line bypass; `None` when the head fit
    /// within the budget or the plan was empty.
    pub bypassed_head_cost: Option<u64>,
}

/// Walks the oldest-first plan and admits targets until the budget is
/// exhausted; the remainder is deferred to the next tick. Two liveness rules
/// keep one expensive target from starving observation:
///
/// * The single oldest target is always admitted, even when its estimated
///   cost alone exceeds `budget` (head-of-line bypass). A bypassed head does
///   not consume the budget, so cheaper targets are still admitted this
///   tick; its cost is reported via `bypassed_head_cost` so the caller can
///   log the overrun against the hard per-tick cap.
/// * A later over-budget entry is skipped without blocking: entries behind
///   it that still fit are admitted.
///
/// Observing the head stamps it, so a permanently over-budget target rotates
/// behind the deferred tail and every target is observed within a bounded
/// number of ticks.
pub fn select_within_budget(plan: Vec<PlannedObservation>, budget: u64) -> BudgetSelection {
    let estimated_requests = plan
        .iter()
        .map(PlannedObservation::estimated_requests)
        .sum();
    let mut used = 0_u64;
    let mut batch = Vec::new();
    let mut deferred = Vec::new();
    let mut bypassed_head_cost = None;
    for (position, entry) in plan.into_iter().enumerate() {
        let cost = entry.estimated_requests();
        if used.saturating_add(cost) <= budget {
            used += cost;
            batch.push(entry);
        } else if position == 0 {
            bypassed_head_cost = Some(cost);
            batch.push(entry);
        } else {
            deferred.push(entry);
        }
    }
    BudgetSelection {
        batch,
        deferred,
        estimated_requests,
        bypassed_head_cost,
    }
}

/// Splits one measured batch request count across the batch's targets
/// proportionally to each target's structural estimate, so an expensive
/// target absorbs its own cost instead of smearing it across the batch.
///
/// Each share is `max(1, ceil(total × est_i / Σ est_j))`; the remainder
/// after summing the shares (negative when the ceiling overshoots) is
/// assigned to the largest-estimate target, so the shares sum to `total`
/// exactly whenever `total` is at least the target count. That always
/// holds for a real Electrum sync, which costs at least one history
/// request per script.
pub fn attribute_request_count(total: u64, estimates: &[u64]) -> Vec<u64> {
    if estimates.is_empty() {
        return Vec::new();
    }
    let estimate_sum = estimates
        .iter()
        .map(|estimate| u128::from(*estimate))
        .sum::<u128>()
        .max(1);
    let mut shares: Vec<u64> = estimates
        .iter()
        .map(|estimate| {
            let scaled = u128::from(total).saturating_mul(u128::from(*estimate));
            u64::try_from(scaled.div_ceil(estimate_sum))
                .unwrap_or(u64::MAX)
                .max(1)
        })
        .collect();
    let assigned = shares.iter().map(|share| u128::from(*share)).sum::<u128>();
    let remainder = i128::from(total) - i128::try_from(assigned).unwrap_or(i128::MAX);
    if remainder != 0
        && let Some((largest, _)) = estimates
            .iter()
            .enumerate()
            .max_by_key(|(position, estimate)| (**estimate, *position))
    {
        let adjusted = i128::from(shares[largest]).saturating_add(remainder);
        shares[largest] = u64::try_from(adjusted.max(1)).unwrap_or(u64::MAX);
    }
    shares
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
    /// The tick probed and observed successfully.
    Observed { processed: usize, deferred: usize },
}

/// Runs one bounded observer tick: active probe, plan, budgeted batch,
/// persistence, and health publication. The empty-target case still probes
/// and reports availability from the probe alone.
pub async fn observe_tick(
    port: &dyn ElectrumPort,
    backend: &dyn ObservationBackend,
    network: &BitcoinNetwork,
    policy: &ObserverPolicy,
    runtime: &Runtime,
) -> ObserverTickOutcome {
    match port.probe().await {
        Ok(tip) => runtime.record_electrum_probe(ElectrumProbe::success(tip.height, tip.time_unix)),
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
            runtime.set_electrum_available(false);
            return ObserverTickOutcome::ProbeFailed(error);
        }
    }
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
    let target_budget = policy
        .per_tick_budget()
        .saturating_sub(PROBE_REQUESTS_PER_TICK);
    let selection = select_within_budget(plan, target_budget);
    if let Some(cost) = selection.bypassed_head_cost {
        tracing::warn!(
            estimated_requests = cost,
            budget = target_budget,
            hard_cap = policy.max_requests_per_tick,
            "oldest observation target exceeds the per-tick request budget; \
             observing it alone to preserve liveness"
        );
    }
    let processed = selection.batch.len();
    let deferred = selection.deferred.len();
    if selection.batch.is_empty() {
        runtime.set_electrum_available(true);
        return ObserverTickOutcome::Observed {
            processed,
            deferred,
        };
    }
    let estimated_batch_requests: u64 = selection
        .batch
        .iter()
        .map(PlannedObservation::estimated_requests)
        .sum();
    let targets: Vec<ObservationTarget> = selection
        .batch
        .iter()
        .map(|entry| entry.target().clone())
        .collect();
    let report = match port.observations(&targets).await {
        Ok(report) => report,
        Err(error) => {
            runtime.set_electrum_available(false);
            return ObserverTickOutcome::ObservationFailed(error);
        }
    };
    tracing::info!(
        estimated_requests = estimated_batch_requests,
        actual_requests = report.request_count,
        targets = targets.len(),
        deferred,
        "electrum observation batch completed"
    );
    if let Err(error) = backend
        .apply_observations(network, &targets, report.outputs)
        .await
    {
        runtime.set_electrum_available(false);
        return ObserverTickOutcome::ObservationFailed(error);
    }
    // Attribute the measured batch request count proportionally to each
    // target's own structural estimate so an expensive target absorbs its
    // own cost: an evenly split share would stamp every cheap target with
    // the dusted target's cost and collapse the next tick's throughput.
    // The adapter fetches the whole batch in one BDK sync call, so the
    // client request counter cannot attribute requests per script.
    let estimates: Vec<u64> = selection
        .batch
        .iter()
        .map(|entry| 1 + u64::from(entry.history_tx_count().unwrap_or(1)))
        .collect();
    let shares = attribute_request_count(report.request_count, &estimates);
    let shares_by_address: HashMap<&str, u64> = selection
        .batch
        .iter()
        .map(|entry| entry.target().address())
        .zip(shares)
        .collect();
    let records: Vec<TargetTickRecord> = report
        .history
        .iter()
        .map(|history| {
            let share = shares_by_address
                .get(history.address.as_str())
                .copied()
                .unwrap_or(1);
            TargetTickRecord::new(
                history.address.clone(),
                history.tx_count,
                u32::try_from(share).unwrap_or(u32::MAX),
            )
        })
        .collect();
    if let Err(error) = backend.record_observation_tick(&records).await {
        runtime.set_electrum_available(false);
        return ObserverTickOutcome::ObservationFailed(error);
    }
    runtime.set_electrum_available(true);
    ObserverTickOutcome::Observed {
        processed,
        deferred,
    }
}

/// Long-running observer worker: one bounded tick per jittered poll interval,
/// with exponential backoff while the endpoint reports `Unavailable`.
pub async fn observation_loop(
    port: Arc<dyn ElectrumPort>,
    backend: Arc<dyn ObservationBackend>,
    network: BitcoinNetwork,
    policy: ObserverPolicy,
    runtime: Arc<Runtime>,
) {
    let mut backoff = ObserverBackoff::new();
    let mut first_tick = true;
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
        match observe_tick(port.as_ref(), backend.as_ref(), &network, &policy, &runtime).await {
            ObserverTickOutcome::ProbeFailed(ObserverError::Unavailable)
            | ObserverTickOutcome::ObservationFailed(ObserverError::Unavailable) => {
                backoff.record_failure();
            }
            ObserverTickOutcome::Observed { .. } => backoff.reset(),
            ObserverTickOutcome::ProbeFailed(_)
            | ObserverTickOutcome::ObservationFailed(_)
            | ObserverTickOutcome::PlanUnavailable => {}
        }
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
        adapter.client().await?;
        Ok(adapter)
    }

    /// Connects a fresh client pair: the raw client (whose request counter
    /// is readable) and the BDK sync client layered over it.
    async fn client(&self) -> Result<(Arc<Client>, BdkElectrumClient<Arc<Client>>), ObserverError> {
        let raw = Arc::new(self.raw_client().await?);
        Ok((raw.clone(), BdkElectrumClient::new(raw)))
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
}

#[async_trait]
impl ElectrumPort for ElectrumAdapter {
    async fn observations(
        &self,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        let (raw, client) = self.client().await?;
        let network = self.network.clone();
        let targets = targets.to_vec();
        tokio::task::spawn_blocking(move || {
            let before = raw.calls_made().map_err(map_electrum)?;
            let mut report = observe_blocking(&client, &network, &targets)?;
            let after = raw.calls_made().map_err(map_electrum)?;
            report.request_count = u64::try_from(after.saturating_sub(before))
                .map_err(|_| ObserverError::InvalidObservation)?;
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

fn observe_blocking(
    client: &BdkElectrumClient<Arc<Client>>,
    network: &BitcoinNetwork,
    targets: &[ObservationTarget],
) -> Result<ObservationReport, ObserverError> {
    let expected_network = network.as_bitcoin_network();
    let mut parsed_targets = Vec::with_capacity(targets.len());
    for target in targets {
        let address = parse_address(target.address(), expected_network)?;
        parsed_targets.push((
            address.to_string(),
            address.script_pubkey(),
            target.current(),
        ));
    }

    let genesis = CheckPoint::new(BlockId {
        height: 0,
        hash: genesis_block(expected_network).block_hash(),
    });
    let scripts = parsed_targets
        .iter()
        .map(|(_, script, _)| script.clone())
        .collect::<Vec<_>>();
    let expected_txids = parsed_targets
        .iter()
        .filter_map(|(_, script, current)| {
            current.map(|current| (script.clone(), current.outpoint().txid))
        })
        .collect::<Vec<_>>();
    let request = SyncRequest::builder()
        .chain_tip(genesis)
        .spks(scripts)
        .expected_spk_txids(expected_txids)
        .build();
    let response = client.sync(request, 100, false).map_err(map_electrum)?;
    let tip_height = response
        .chain_update
        .as_ref()
        .ok_or(ObserverError::Unavailable)?
        .height();
    // Per-target history sizes from this response feed the next tick's
    // request budget. Only transactions paying a target's script are
    // visible here, so the count is a lower-bound estimate of the full
    // Electrum history length.
    let mut history = Vec::with_capacity(parsed_targets.len());
    for (address, script, _) in &parsed_targets {
        let tx_count = response
            .tx_update
            .txs
            .iter()
            .filter(|transaction| {
                transaction
                    .output
                    .iter()
                    .any(|output| &output.script_pubkey == script)
            })
            .count();
        history.push(TargetHistory {
            address: address.clone(),
            tx_count: u32::try_from(tx_count).map_err(|_| ObserverError::InvalidObservation)?,
        });
    }
    let mut confirmations_by_txid = response
        .tx_update
        .seen_ats
        .iter()
        .map(|(txid, _)| (*txid, 0))
        .collect::<HashMap<_, _>>();
    for (anchor, txid) in &response.tx_update.anchors {
        let confirmations = tip_height
            .checked_sub(anchor.block_id.height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(ObserverError::Unavailable)?;
        confirmations_by_txid.insert(*txid, confirmations);
    }
    let targets_by_script = parsed_targets
        .iter()
        .map(|(address, script, _)| (script.clone(), address.as_str()))
        .collect::<HashMap<_, _>>();
    let mut seen_outpoints = HashSet::new();
    let mut processed_txids = HashSet::new();
    let mut observations = Vec::new();
    for transaction in response.tx_update.txs {
        let txid = transaction.compute_txid();
        if !processed_txids.insert(txid) {
            continue;
        }
        let confirmations = confirmations_by_txid
            .get(&txid)
            .copied()
            .ok_or(ObserverError::InvalidObservation)?;
        for (vout, output) in transaction.output.iter().enumerate() {
            if let Some(address) = targets_by_script.get(&output.script_pubkey) {
                let outpoint = bitcoin::OutPoint::new(
                    txid,
                    u32::try_from(vout).map_err(|_| ObserverError::InvalidObservation)?,
                );
                seen_outpoints.insert(outpoint);
                observations.push(ObservedOutput {
                    network: network.clone(),
                    address: (*address).to_owned(),
                    outpoint,
                    sats: output.value.to_sat(),
                    confirmations,
                    present: true,
                });
            }
        }
    }
    for (address, _, current) in parsed_targets {
        if let Some(current) = current
            && !seen_outpoints.contains(&current.outpoint())
        {
            observations.push(ObservedOutput {
                network: network.clone(),
                address,
                outpoint: current.outpoint(),
                sats: current.sats(),
                confirmations: 0,
                present: false,
            });
        }
    }
    Ok(ObservationReport {
        outputs: observations,
        history,
        // Filled in by the caller, which measures the client request counter
        // around this sync.
        request_count: 0,
    })
}

fn map_electrum(error: ElectrumError) -> ObserverError {
    match error {
        ElectrumError::Message(message)
            if message.contains("cannot find agreement block with server") =>
        {
            ObserverError::WrongNetwork
        }
        _ => ObserverError::Unavailable,
    }
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
    use super::*;

    fn target(label: &str) -> ObservationTarget {
        ObservationTarget::new(format!("addr-{label}"), None)
    }

    fn planned(label: &str, history_tx_count: Option<u32>) -> PlannedObservation {
        PlannedObservation::new(target(label), history_tx_count, None, Duration::ZERO)
    }

    fn labels(entries: &[PlannedObservation]) -> Vec<String> {
        entries
            .iter()
            .map(|entry| entry.target().address().to_owned())
            .collect()
    }

    #[test]
    fn budget_estimates_one_history_fetch_plus_known_transactions_per_target() {
        let plan = vec![
            planned("a", None),
            planned("b", Some(0)),
            planned("c", Some(4)),
        ];
        let selection = select_within_budget(plan, u64::MAX);
        // 1+1 (unknown counts as 1), 1+0, 1+4.
        assert_eq!(selection.estimated_requests, 8);
    }

    #[test]
    fn budget_uses_the_measured_request_count_when_it_exceeds_the_structural_estimate() {
        let measured = PlannedObservation::new(target("d"), Some(4), Some(12), Duration::ZERO);
        assert_eq!(measured.estimated_requests(), 12);
        let structural = PlannedObservation::new(target("e"), Some(4), Some(2), Duration::ZERO);
        assert_eq!(structural.estimated_requests(), 5);
    }

    #[test]
    fn budget_admits_oldest_first_and_defers_the_remainder() {
        let plan = vec![
            planned("stale", Some(2)),
            planned("middle", None),
            planned("fresh", Some(1)),
        ];
        // Costs 3, 2, 2: budget 5 admits the first two only.
        let selection = select_within_budget(plan, 5);
        assert_eq!(labels(&selection.batch), vec!["addr-stale", "addr-middle"]);
        assert_eq!(labels(&selection.deferred), vec!["addr-fresh"]);
        assert_eq!(selection.estimated_requests, 7);
        assert_eq!(selection.bypassed_head_cost, None);

        // An over-budget oldest target is admitted by the liveness bypass
        // rather than starving the whole tick.
        let bypass = select_within_budget(vec![planned("big", Some(10))], 2);
        assert_eq!(labels(&bypass.batch), vec!["addr-big"]);
        assert!(bypass.deferred.is_empty());
        assert_eq!(bypass.bypassed_head_cost, Some(11));
    }

    #[test]
    fn over_budget_entries_are_skipped_without_blocking_cheaper_targets() {
        let plan = vec![
            planned("oldest", Some(0)),
            planned("expensive", Some(10)),
            planned("cheap", Some(1)),
        ];
        // Costs 1, 11, 2 with budget 3: the expensive middle entry is
        // deferred while the cheap tail is still admitted.
        let selection = select_within_budget(plan, 3);
        assert_eq!(labels(&selection.batch), vec!["addr-oldest", "addr-cheap"]);
        assert_eq!(labels(&selection.deferred), vec!["addr-expensive"]);
        assert_eq!(selection.bypassed_head_cost, None);
    }

    #[test]
    fn every_target_is_observed_within_n_ticks_of_a_sustained_over_budget_set() {
        use std::collections::{HashSet, VecDeque};

        const TARGETS: usize = 5;
        // Every target alone costs more than the whole per-tick budget, so
        // only the head-of-line bypass can ever admit one.
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
                        Some(9),
                        None,
                        Duration::ZERO,
                    )
                })
                .collect();
            let selection = select_within_budget(plan, 3);
            assert_eq!(
                selection.batch.len(),
                1,
                "the bypass admits exactly the oldest target"
            );
            assert_eq!(selection.bypassed_head_cost, Some(10));
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
    fn attribution_gives_the_expensive_target_its_own_cost() {
        // One dusted target (structural estimate 201) in a batch of twenty
        // cheap targets (estimate 1 each).
        let mut estimates = vec![201_u64];
        estimates.extend([1_u64; 20]);
        let shares = attribute_request_count(242, &estimates);
        assert_eq!(shares.len(), 21);
        assert_eq!(shares.iter().sum::<u64>(), 242);
        assert!(
            shares[0] >= 200,
            "the dusted target must absorb its own cost, got {}",
            shares[0]
        );
        for share in &shares[1..] {
            assert!(
                *share <= 2,
                "cheap targets must keep a small share, got {share}"
            );
        }
    }

    #[test]
    fn attribution_remainder_lands_on_the_largest_estimate_target() {
        // Ceil overshoot: 84 + 9 + 9 = 102 > 100, so the largest-estimate
        // target absorbs the -2 remainder and the shares stay exact.
        let shares = attribute_request_count(100, &[10, 1, 1]);
        assert_eq!(shares, vec![82, 9, 9]);
        // Undershoot-free equal split.
        let shares = attribute_request_count(10, &[3, 3]);
        assert_eq!(shares, vec![5, 5]);
        // Every share is at least one, then the remainder rebalances.
        let shares = attribute_request_count(7, &[1, 1, 1]);
        assert_eq!(shares.iter().sum::<u64>(), 7);
        assert!(shares.iter().all(|share| *share >= 1));
        let shares = attribute_request_count(5, &[2, 1]);
        assert_eq!(shares, vec![3, 2]);
    }

    #[test]
    fn attribution_handles_empty_and_zero_totals() {
        assert!(attribute_request_count(10, &[]).is_empty());
        let shares = attribute_request_count(0, &[5, 1]);
        assert_eq!(shares.len(), 2);
        assert!(shares.iter().all(|share| *share >= 1));
    }

    #[test]
    fn per_tick_budget_is_the_rate_allowance_capped_by_the_hard_limit() {
        let policy = ObserverPolicy {
            poll_interval: Duration::from_secs(10),
            max_requests_per_tick: 1000,
            max_requests_per_second: 5,
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
