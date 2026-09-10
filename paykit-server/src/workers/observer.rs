//! Polling-independent direct Bitcoin observation worker boundary.
//!
//! Observation uses one raw Electrum `script_list_unspent` lookup per
//! tracked address. Each `ListUnspentRes` item carries the outpoint
//! (`tx_hash`, `tx_pos`), the value, and the confirmation height, so the
//! outpoint/value/presence model is preserved without ever calling
//! history RPCs or fetching a historical transaction: the request
//! count is exactly one per observed address and cannot be expanded by an
//! attacker dusting a disclosed invoice address. The response work is
//! bounded too: every connection's stream is byte-capped per response
//! line (see [`crate::workers::electrum`]) before the client buffers or
//! decodes anything, the decoded item count is capped before any
//! per-UTXO record is materialised, and every address runs under a
//! wall-clock deadline, and every per-address failure is isolated — it
//! never degrades endpoint availability or the tick's other
//! observations.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bitcoin::{
    Address, Network, OutPoint, ScriptBuf, Txid, consensus::deserialize, hex::DisplayHex,
};
use electrum_client::{
    Batch, ElectrumApi, Error as ElectrumError, ListUnspentRes, Param, ToElectrumScriptHash,
};
use rand::Rng;
use tokio::sync::Semaphore;

use crate::{
    bitcoin::{ObservationTarget, ObservedOutput, PlannedObservation},
    chain_history::{ChainHistoryPort, ClaimScanError},
    config::BitcoinNetwork,
    domain::payment::BitcoinOutpoint,
    persistence::{BitcoinObservationInput, InvoiceStore, PendingCandidate, PersistenceError},
    runtime::{ElectrumProbe, Runtime},
    workers::electrum::{self, CappedClient},
};

/// Oldest-observation age that triggers the backlog metric and WARN log.
pub const BACKLOG_ALERT_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// Requests reserved from each tick's budget for the active health probe
/// (`headers.subscribe` + `block_header(0)`), so the configured rate bounds
/// the probe and the observation batch together.
pub const PROBE_REQUESTS_PER_TICK: u64 = 2;

/// Minimum interval between WARN logs for the same failing address: a
/// permanently failing target is visible without flooding the log, while
/// the per-tick summary WARN still records every tick's failure count.
const ADDRESS_FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_CANDIDATE_ATTEMPTS: u32 = 12;

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

/// Why one address's `list_unspent` lookup failed. Every reason is an
/// isolated per-address condition — never an endpoint condition — and is
/// counted under a distinct metric label
/// (`paykit_electrum_observation_address_failures{reason=...}`).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum AddressFailureReason {
    /// The lookup errored: transport timeout, malformed response, a
    /// response line over `electrum.max_response_bytes` (the transport
    /// cap fails the read before decode), or an inconsistent height
    /// relative to the probed tip.
    Error,
    /// The response listed more UTXOs than `electrum.max_utxos_per_address`;
    /// it was rejected before any per-UTXO record was materialised.
    ResponseTooLarge,
    /// Connect + call + decode exceeded `electrum.address_deadline`.
    Deadline,
}

impl AddressFailureReason {
    /// Stable metric label value.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::ResponseTooLarge => "response_too_large",
            Self::Deadline => "deadline",
        }
    }
}

/// One failed per-address lookup with its classified reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedObservation {
    pub address: String,
    pub reason: AddressFailureReason,
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
/// `observed` and `failed` partition the requested target addresses. The
/// tick stamps every attempted address — observed with the success
/// stamp, failed with the failure stamp — so both rotate behind the
/// plan, while failed targets keep their `last_observed_at` staleness.
/// One failed address never discards the others' results.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservationReport {
    pub outputs: Vec<ObservedOutput>,
    /// Target addresses whose `list_unspent` lookup succeeded.
    pub observed: Vec<String>,
    /// Target addresses whose lookup timed out, exceeded the UTXO cap or
    /// the per-address deadline, or errored; they keep their staleness
    /// but rotate behind the rest of the plan like successes.
    pub failed: Vec<FailedObservation>,
}

/// Production Electrum adapters are injected here. This boundary deliberately
/// does not prescribe an Electrum wire protocol or invent payer messages.
#[async_trait]
pub trait ElectrumPort: Send + Sync {
    /// The caller hands over the owned creation-snapshot slot it acquired
    /// (bounded by the request deadline) so the implementation can keep it
    /// for exactly as long as the Electrum I/O it admits: the slot is
    /// released only when the underlying blocking read returns, never when
    /// the awaiting side gives up.
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
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
    /// A transaction response exceeded `electrum.max_transaction_bytes`.
    /// Unlike a transport failure this is deterministic: refetching the
    /// same transaction can never succeed under the configured cap.
    TransactionTooLarge,
    /// A tick stamp matched no invoice row: the lookup hash derived from
    /// the observed address failed to match the stored hash. Other records
    /// were still stamped; the tick reports this named error so the miss
    /// cannot silently pin the same head target forever.
    ObservationStampMiss,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateFailureKind {
    /// The bounded transaction fetch failed; consumes one of the
    /// candidate's bounded retry-budget attempts.
    Fetch,
    /// Persisting the resolution failed; never consumes the fetch retry
    /// budget and never moves the invoice — diagnostic state only.
    Persistence,
    /// The candidate transaction exceeds `electrum.max_transaction_bytes`
    /// and is deterministically unresolvable: one attempt routes the
    /// invoice to `manual_review`.
    TransactionTooLarge,
}

impl CandidateFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Persistence => "persistence",
            Self::TransactionTooLarge => "transaction_too_large",
        }
    }
}

/// Durable side of the observer: plans, applies, and records one tick. The
/// production implementation is [`InvoiceStore`]; tests inject fakes.
#[async_trait]
pub trait ObservationBackend: Send + Sync {
    /// Loads the non-final observation plan, oldest attempt first.
    async fn observation_plan(&self) -> Result<Vec<PlannedObservation>, ObserverError>;
    /// Validates and persists one fetched batch for the requested targets.
    async fn apply_observations(
        &self,
        network: &BitcoinNetwork,
        targets: &[ObservationTarget],
        outputs: Vec<ObservedOutput>,
    ) -> Result<usize, ObserverError>;
    /// Stamps the tick's attempted target addresses: observed targets
    /// with a success stamp (`last_observed_at` + `last_attempted_at`),
    /// failed targets with a failure stamp (`last_attempted_at` only) so
    /// they rotate behind the plan exactly like successes and cannot
    /// starve it. Returns the number of records whose stamp matched no
    /// invoice row; misses are logged and counted but never abort the
    /// other records.
    async fn record_observation_tick(
        &self,
        observed: &[String],
        failed: &[String],
    ) -> Result<u64, ObserverError>;
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
    async fn record_candidate_failure(
        &self,
        _candidate: &PendingCandidate,
        _kind: CandidateFailureKind,
    ) -> Result<(), ObserverError> {
        Err(ObserverError::Persistence)
    }
    async fn sweep_stale_creation_baselines(
        &self,
        _timeout: Duration,
    ) -> Result<u64, ObserverError> {
        Ok(0)
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

    async fn record_observation_tick(
        &self,
        observed: &[String],
        failed: &[String],
    ) -> Result<u64, ObserverError> {
        InvoiceStore::record_observation_tick(self, observed, failed)
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

    async fn record_candidate_failure(
        &self,
        candidate: &PendingCandidate,
        kind: CandidateFailureKind,
    ) -> Result<(), ObserverError> {
        InvoiceStore::record_candidate_failure(
            self,
            candidate,
            kind.as_str(),
            MAX_CANDIDATE_ATTEMPTS,
        )
        .await
        .map_err(map_persistence)
    }

    async fn sweep_stale_creation_baselines(
        &self,
        timeout: Duration,
    ) -> Result<u64, ObserverError> {
        InvoiceStore::sweep_stale_creation_baselines(self, timeout)
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
    /// Token-bucket capacity: the maximum Electrum requests one tick may
    /// hold, including the tick's two probe requests
    /// ([`PROBE_REQUESTS_PER_TICK`]), which are charged before observation
    /// targets are admitted. Each admitted target costs exactly one
    /// `list_unspent` lookup; there is no bypass, no slow lane, and no
    /// unmetered admission of any kind.
    pub max_requests_per_tick: u32,
    /// Token-bucket refill rate. Tokens refill from elapsed wall time at
    /// this rate, so no loop cadence — including the shortest jitter
    /// interval — can sustain more requests per second.
    pub max_requests_per_second: u32,
    pub max_transaction_bytes: usize,
    pub baseline_completion_timeout: Duration,
}

impl ObserverPolicy {
    /// Effective per-tick lookup budget in steady state: the bucket
    /// capacity bounded further by one poll interval's refill. Startup
    /// validation requires this to exceed [`PROBE_REQUESTS_PER_TICK`] so no
    /// accepted configuration probes successfully while admitting zero
    /// address lookups forever.
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

/// Walks the oldest-attempt-first plan and admits exactly as many targets
/// as the lookup budget allows; the remainder is deferred to the next
/// tick and, being the least recently attempted, is admitted first then.
/// Every target costs exactly one lookup, so admission is a strict prefix
/// of the plan: no bypass, no skipping, no slow lane. Attempting a target
/// stamps it — success or failure — so an admitted target rotates behind
/// the deferred tail and every target is attempted within a bounded
/// number of ticks.
pub fn select_within_budget(plan: Vec<PlannedObservation>, budget: u64) -> BudgetSelection {
    let admit = usize::try_from(budget).unwrap_or(usize::MAX);
    let mut plan = plan;
    let deferred = plan.split_off(plan.len().min(admit));
    BudgetSelection {
        batch: plan,
        deferred,
    }
}

/// Sustained Electrum request token bucket. Tokens refill from elapsed
/// wall time at `max_requests_per_second` up to `max_requests_per_tick`, so
/// the jittered loop can never sustain a rate above the configured one: a
/// window's admissions are bounded by one bucket capacity plus rate ×
/// window, and once the bucket is drained (sustained over-budget load)
/// every window admits at most rate × window. Refill accounting is
/// integer-exact: sub-token remainders stay in `last_refill` and cannot
/// drift over long runs.
#[derive(Clone, Debug)]
pub struct RequestBudget {
    capacity: u64,
    refill_per_second: u64,
    tokens: u64,
    last_refill: Instant,
}

impl RequestBudget {
    /// Starts with a full bucket: the first tick may burst up to the
    /// configured per-tick capacity; sustained admission is then bounded by
    /// the refill rate.
    pub fn new(capacity: u64, refill_per_second: u64, now: Instant) -> Self {
        Self {
            capacity,
            refill_per_second,
            tokens: capacity,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        if self.refill_per_second == 0 {
            self.last_refill = now;
            return;
        }
        let elapsed_millis = now.saturating_duration_since(self.last_refill).as_millis();
        let whole = u64::try_from(elapsed_millis * u128::from(self.refill_per_second) / 1000)
            .unwrap_or(u64::MAX);
        if whole == 0 {
            return;
        }
        self.tokens = self.tokens.saturating_add(whole).min(self.capacity);
        // Advance only by the time the granted whole tokens represent, so
        // the sub-token remainder keeps accruing instead of being dropped.
        let consumed_millis = u128::from(whole) * 1000 / u128::from(self.refill_per_second);
        self.last_refill +=
            Duration::from_millis(u64::try_from(consumed_millis).unwrap_or(u64::MAX));
    }

    /// Tokens available after refilling from elapsed wall time.
    pub fn available(&mut self, now: Instant) -> u64 {
        self.refill(now);
        self.tokens
    }

    /// Spends up to `count` tokens (saturating at what is available).
    pub fn spend(&mut self, count: u64) {
        self.tokens = self.tokens.saturating_sub(count);
    }
}

/// The shared bucket holds fewer tokens than the caller asked to reserve;
/// nothing was charged. `available` is the post-refill balance the caller
/// was shown, so it can back off by `(requested - available) / refill
/// rate` seconds instead of retrying immediately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExhausted {
    pub requested: u64,
    pub available: u64,
}

impl std::fmt::Display for BudgetExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "electrum request budget exhausted: requested {}, available {}",
            self.requested, self.available
        )
    }
}

impl std::error::Error for BudgetExhausted {}

/// Proof that `granted` Electrum requests were charged against the shared
/// bucket at reservation time. This is a rate limiter, not a concurrency
/// limiter: dropping a permit neither refunds nor charges again — the
/// tokens stay spent and refill only from elapsed wall time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permit {
    granted: u64,
}

impl Permit {
    /// Requests this permit charged at reservation.
    pub fn granted(&self) -> u64 {
        self.granted
    }
}

impl Drop for Permit {
    /// Explicitly a no-op: the tokens were charged at reservation, so
    /// dropping the permit neither refunds them nor charges again.
    fn drop(&mut self) {}
}

/// App-owned, process-wide Electrum request limiter: one token bucket
/// behind an `Arc`-shared mutex, cheap to clone into any task. Every
/// Electrum caller charges this single bucket before dispatch, so the
/// configured sustained rate bounds all callers jointly — there are no
/// per-caller pools.
///
/// Expected callers:
///
/// - **The observer tick** ([`observe_tick`]): reserves
///   [`PROBE_REQUESTS_PER_TICK`] with [`Self::try_reserve`] BEFORE
///   sending the probe, deferring the whole tick on exhaustion, then
///   admits lookups with one atomic [`Self::reserve_up_to`] against the
///   post-probe balance.
/// - **Invoice-creation snapshot fetches, the first-bind candidate fetch,
///   and the claim-time history scan** (sibling slices): charge
///   [`Self::try_reserve`] before dispatch, or [`Self::reserve_or_wait`]
///   when they may wait briefly for refill.
///
/// The mutex is held only for synchronous refill/spend arithmetic — never
/// across an `.await` — so clones are tokio-friendly.
#[derive(Clone, Debug)]
pub struct RequestLimiter {
    inner: Arc<Mutex<RequestBudget>>,
}

impl RequestLimiter {
    /// Starts with a full bucket: the first callers may burst up to
    /// capacity; sustained admission is then bounded by the refill rate.
    pub fn new(capacity: u64, refill_per_second: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RequestBudget::new(
                capacity,
                refill_per_second,
                Instant::now(),
            ))),
        }
    }

    /// Builds the limiter from the observer policy's budget config
    /// (`electrum.max_requests_per_tick` capacity,
    /// `electrum.max_requests_per_second` refill).
    pub fn from_policy(policy: &ObserverPolicy) -> Self {
        Self::new(
            u64::from(policy.max_requests_per_tick),
            u64::from(policy.max_requests_per_second),
        )
    }

    fn lock(&self) -> MutexGuard<'_, RequestBudget> {
        // The critical section holds no user code, so a poisoned lock still
        // holds a sound bucket; refusing to panic keeps the readiness path
        // alive, matching the metrics registry's policy.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Tokens available right now, after refilling from elapsed wall time.
    pub fn available(&self) -> u64 {
        self.lock().available(Instant::now())
    }

    /// Charges `requests` against the bucket and returns the permit to
    /// dispatch them, or fails without charging when the bucket holds
    /// fewer. Callers must reserve before dispatching.
    pub fn try_reserve(&self, requests: u64) -> Result<Permit, BudgetExhausted> {
        let mut budget = self.lock();
        let available = budget.available(Instant::now());
        if available < requests {
            return Err(BudgetExhausted {
                requested: requests,
                available,
            });
        }
        budget.spend(requests);
        Ok(Permit { granted: requests })
    }

    /// `try_reserve` for non-tick callers that may wait briefly: waits for
    /// wall-clock refill, giving up at `deadline`. Fails without charging
    /// when the reservation cannot be satisfied by then (including
    /// requests above capacity, which can never be satisfied). The bucket
    /// lock is never held across a sleep, and each retry re-reads the
    /// balance because another caller may have taken the refilled tokens.
    pub async fn reserve_or_wait(
        &self,
        requests: u64,
        deadline: Instant,
    ) -> Result<Permit, BudgetExhausted> {
        loop {
            let wait = {
                let mut budget = self.lock();
                let now = Instant::now();
                let available = budget.available(now);
                if available >= requests {
                    budget.spend(requests);
                    return Ok(Permit { granted: requests });
                }
                if now >= deadline || requests > budget.capacity || budget.refill_per_second == 0 {
                    return Err(BudgetExhausted {
                        requested: requests,
                        available,
                    });
                }
                // Earliest wait that guarantees the deficit has refilled:
                // the bucket's sub-token remainder keeps accruing, so
                // ceil(deficit x 1000 / rate) milliseconds always grant the
                // missing whole tokens.
                let deficit = requests - available;
                let millis =
                    (u128::from(deficit) * 1000).div_ceil(u128::from(budget.refill_per_second));
                let wake = now + Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX));
                wake.min(deadline).saturating_duration_since(now)
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// Atomically reserves as many of the currently available tokens as
    /// `max` allows (possibly zero) and returns the permit for the
    /// granted count. One lock covers the refill, the balance read, and
    /// the charge, so the observer tick's lookup admission derives from
    /// one consistent balance and a concurrent caller can never push the
    /// joint total over budget. The surplus stays for other callers.
    pub fn reserve_up_to(&self, max: u64) -> Permit {
        let mut budget = self.lock();
        let granted = budget.available(Instant::now()).min(max);
        budget.spend(granted);
        Permit { granted }
    }

    /// Rewinds the refill clock by `elapsed`, so deterministic tests can
    /// simulate wall time passing exactly as the production loop's real
    /// sleep between ticks would. Test-only; no production caller.
    pub fn rewind_refill_clock(&self, elapsed: Duration) {
        let mut budget = self.lock();
        if let Some(rewound) = budget.last_refill.checked_sub(elapsed) {
            budget.last_refill = rewound;
        }
    }
}

/// Per-address WARN-log rate limiter: one failing address logs at most once
/// per [`ADDRESS_FAILURE_LOG_INTERVAL`] no matter how many ticks it fails,
/// so a permanently dusted address cannot flood the log.
#[derive(Clone, Debug, Default)]
pub struct AddressFailureLog {
    last_logged: HashMap<String, Instant>,
}

impl AddressFailureLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a failure for `address` and returns whether it should be
    /// logged now.
    pub fn should_log(&mut self, address: &str, now: Instant) -> bool {
        if let Some(last) = self.last_logged.get(address)
            && now.duration_since(*last) < ADDRESS_FAILURE_LOG_INTERVAL
        {
            return false;
        }
        self.last_logged.insert(address.to_owned(), now);
        true
    }
}

/// Cross-tick observer state owned by the loop: the shared sustained
/// request limiter, the per-address failure-log rate limiter, and the
/// zero-success-tick log streak.
#[derive(Clone, Debug)]
pub struct ObserverTickState {
    budget: RequestLimiter,
    failure_log: AddressFailureLog,
    /// Whether the current zero-success streak has already emitted its one
    /// ERROR log; reset by any tick with at least one successful lookup, so
    /// the next zero-success streak logs again.
    zero_success_logged: bool,
    max_transaction_bytes: usize,
    baseline_completion_timeout: Duration,
}

impl ObserverTickState {
    /// Tick state over a private limiter built from the policy's budget —
    /// for tests that drive ticks in isolation. Production uses
    /// [`Self::with_limiter`] with the app-owned shared limiter.
    /// Test-only; no production caller.
    pub fn new(policy: &ObserverPolicy) -> Self {
        let mut state = Self::with_limiter_and_transaction_cap(
            RequestLimiter::from_policy(policy),
            policy.max_transaction_bytes,
        );
        state.baseline_completion_timeout = policy.baseline_completion_timeout;
        state
    }

    /// Tick state over the app-owned shared limiter: the tick and every
    /// other Electrum caller draw from one bucket, so a busy non-tick
    /// caller shrinks the next tick's admission and vice versa.
    pub fn with_limiter(limiter: RequestLimiter) -> Self {
        Self::with_limiter_and_transaction_cap(limiter, 400_000)
    }

    pub fn with_limiter_and_transaction_cap(
        limiter: RequestLimiter,
        max_transaction_bytes: usize,
    ) -> Self {
        Self {
            budget: limiter,
            failure_log: AddressFailureLog::new(),
            zero_success_logged: false,
            max_transaction_bytes,
            baseline_completion_timeout: Duration::from_secs(60),
        }
    }

    /// The shared limiter this tick charges, for other callers to clone.
    pub fn limiter(&self) -> RequestLimiter {
        self.budget.clone()
    }

    /// Whether the current zero-success streak has already emitted its one
    /// ERROR log (the log gate; exposed for tests and diagnostics).
    /// Test-only; no production caller.
    pub fn zero_success_logged(&self) -> bool {
        self.zero_success_logged
    }

    /// Rewinds the budget's refill clock by `elapsed`, so the next tick
    /// refills as if that much wall time had passed since the previous
    /// tick. The production loop gets the same refill from its real sleep
    /// between ticks; deterministic tests use this to space ticks.
    /// Test-only; no production caller.
    pub fn rewind_budget_clock(&mut self, elapsed: Duration) {
        self.budget.rewind_refill_clock(elapsed);
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
            | ObserverTickOutcome::PlanUnavailable
            | ObserverTickOutcome::Deferred => {}
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
    /// The shared request budget could not cover the probe reservation,
    /// so the tick sent no Electrum requests and deferred the whole tick
    /// to the next poll interval. Not an availability change and not a
    /// zero-success tick: nothing was attempted.
    Deferred,
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

/// Runs one bounded observer tick: budget-reserved active probe, plan,
/// budgeted batch, persistence, and health publication. The empty-target
/// case still probes and reports availability from the probe alone. If the
/// shared budget cannot cover the probe reservation the tick sends no
/// Electrum requests at all and returns [`ObserverTickOutcome::Deferred`].
/// `state` carries the cross-tick request budget and failure-log rate
/// limiter. Per-address lookup failures are always isolated: they are
/// counted and logged but never degrade endpoint availability; only a
/// probe or connect failure does.
pub async fn observe_tick(
    port: &dyn ElectrumPort,
    backend: &dyn ObservationBackend,
    network: &BitcoinNetwork,
    runtime: &Runtime,
    state: &mut ObserverTickState,
) -> ObserverTickOutcome {
    // Reserve the probe's two requests BEFORE any Electrum I/O: every
    // request the process sends is charged against the shared bucket
    // first. `try_reserve`, not `reserve_or_wait`: the tick runs once per
    // jittered poll interval, so when the bucket cannot cover the probe
    // the correct action is to defer the whole tick to the next interval
    // (pending targets keep their staleness) rather than hold the tick
    // open waiting for refill. On exhaustion the tick sends nothing and
    // touches neither availability nor the zero-success signal — no
    // lookup was attempted — so it is counted under its own
    // budget_exhausted reason instead.
    let _probe_permit = match state.budget.try_reserve(PROBE_REQUESTS_PER_TICK) {
        Ok(permit) => permit,
        Err(exhausted) => {
            runtime.metrics().electrum_budget_exhausted_tick();
            tracing::info!(
                reason = "budget_exhausted",
                requested = exhausted.requested,
                available = exhausted.available,
                "shared electrum request budget cannot cover the probe; deferring the whole tick"
            );
            return ObserverTickOutcome::Deferred;
        }
    };
    if let Err(error) = backend
        .sweep_stale_creation_baselines(state.baseline_completion_timeout)
        .await
    {
        return ObserverTickOutcome::ObservationFailed(error);
    }
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

    // The probe's requests were reserved before it ran; admit lookups
    // from whatever the shared bucket holds now. One atomic
    // reserve-up-to grants at most min(balance, plan length): the tick
    // charges exactly what it will dispatch, the surplus stays for
    // non-tick callers, and a concurrent caller can never push the joint
    // total over budget. The bucket refills from elapsed wall time, so
    // the jittered loop cannot sustain a higher rate.
    let lookup_permit = state
        .budget
        .reserve_up_to(u64::try_from(plan.len()).unwrap_or(u64::MAX));
    let selection = select_within_budget(plan, lookup_permit.granted());
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
        let mut by_reason: HashMap<AddressFailureReason, u64> = HashMap::new();
        let now = Instant::now();
        for failure in &report.failed {
            *by_reason.entry(failure.reason).or_default() += 1;
            if state.failure_log.should_log(&failure.address, now) {
                tracing::warn!(
                    address = %failure.address,
                    reason = failure.reason.as_label(),
                    "isolated per-address electrum lookup failure; the target stays stale"
                );
            }
        }
        for (reason, count) in by_reason {
            runtime
                .metrics()
                .electrum_observation_address_failures(reason.as_label(), count);
        }
        tracing::warn!(
            failed = failed_count,
            succeeded = report.observed.len(),
            "isolated per-address electrum lookup failures this tick; failed targets stay stale"
        );
    }
    // Zero-success visibility: with per-address failures isolated from
    // endpoint availability, a tick that attempted lookups and succeeded
    // at none would otherwise be indistinguishable from health. Count
    // every such tick and log ERROR once per streak (the streak resets on
    // the first tick with a successful lookup). Availability is untouched
    // and no backoff triggers: the endpoint was reached and answered.
    let succeeded = processed.saturating_sub(failed_count);
    if processed > 0 && succeeded == 0 {
        runtime.metrics().electrum_zero_success_tick();
        if !state.zero_success_logged {
            tracing::error!(
                attempted = processed,
                deferred,
                "every electrum lookup in this tick failed in isolation; targets stay stale"
            );
            state.zero_success_logged = true;
        }
    } else if succeeded > 0 {
        state.zero_success_logged = false;
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
    // The candidate fetch is admissible only when the observation batch
    // did not exhaust the tick's budget: a non-empty `deferred` means the
    // budget truncated the plan, so no headroom remains. `try_reserve(1)`
    // is the authoritative charge — the fetch is never uncharged.
    if deferred == 0
        && let Ok(candidates) = backend.pending_candidates().await
        && let Some(candidate) = candidates.first()
        && state.budget.try_reserve(1).is_ok()
    {
        let failure = match port
            .candidate_transaction(candidate.outpoint.txid, state.max_transaction_bytes)
            .await
        {
            // The fetch verified the returned bytes against the requested
            // txid, so an `Ok` transaction is the candidate's own.
            Ok(transaction) => backend
                .resolve_candidate(candidate, &transaction.inputs)
                .await
                .err()
                .map(|_| CandidateFailureKind::Persistence),
            Err(ObserverError::TransactionTooLarge) => {
                Some(CandidateFailureKind::TransactionTooLarge)
            }
            Err(_) => Some(CandidateFailureKind::Fetch),
        };
        if let Some(kind) = failure
            && let Err(error) = backend.record_candidate_failure(candidate, kind).await
        {
            return ObserverTickOutcome::ObservationFailed(error);
        }
    }
    // Stamp every ATTEMPTED target: observed targets with the success
    // stamp, failed targets with the failure stamp, so both rotate
    // behind the rest of the oldest-first plan. Stamping only successes
    // would let a run of permanently failing targets hold the plan's
    // head forever and starve every honest seller of attempts; the
    // failed targets keep their `last_observed_at` staleness either way.
    let failed_addresses: Vec<String> = report
        .failed
        .iter()
        .map(|failure| failure.address.clone())
        .collect();
    let misses = match backend
        .record_observation_tick(&report.observed, &failed_addresses)
        .await
    {
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
    // keep their staleness, though they rotate behind the plan like
    // successes); they never degrade endpoint availability. The endpoint
    // degrades solely on a probe or connect failure, handled above.
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
    // The tick charges the app-owned shared limiter installed on the
    // runtime at startup, so non-tick Electrum callers (creation snapshot
    // fetches, first-bind candidate fetch, claim-time history scan) draw
    // from the same bucket the tick does.
    let mut state = ObserverTickState::with_limiter_and_transaction_cap(
        runtime.electrum_request_limiter(),
        policy.max_transaction_bytes,
    );
    state.baseline_completion_timeout = policy.baseline_completion_timeout;
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
            &runtime,
            &mut state,
        )
        .await;
        backoff.record_outcome(&outcome);
    }
}

/// Default claim-scan response bound: raw history items accepted across one
/// window's batched `get_history` before the window is treated as used
/// (`electrum.max_history_items_per_window`).
const DEFAULT_MAX_HISTORY_ITEMS_PER_WINDOW: usize = 2_000;

/// Default claim-scan per-window wall-clock deadline over connect + call +
/// decode (`electrum.claim_scan_window_deadline`).
const DEFAULT_CLAIM_SCAN_WINDOW_DEADLINE: Duration = Duration::from_secs(5);

/// Default process-wide bound on concurrent claim-scan window fetches
/// (`electrum.max_concurrent_claim_scans`).
const DEFAULT_MAX_CONCURRENT_CLAIM_SCANS: usize = 2;

/// Concrete synchronous Electrum client isolated behind the async observation port.
#[derive(Clone)]
pub struct ElectrumAdapter {
    endpoint: Arc<str>,
    network: BitcoinNetwork,
    timeout: Duration,
    /// Hard cap on decoded `list_unspent` items per address
    /// (`electrum.max_utxos_per_address`); over-limit responses are
    /// rejected before any per-UTXO record is materialised.
    max_utxos_per_address: usize,
    /// Per-address wall-clock deadline over connect + call + decode
    /// (`electrum.address_deadline`). The tick's probe shares it: the
    /// per-read socket timeout does not bound a drip-feeding endpoint,
    /// so without a wall-clock bound on the probe a slow-drip
    /// `headers.subscribe` reply would stall the tick forever — no
    /// backoff, no availability change, no failover.
    address_deadline: Duration,
    /// Transport-level cap on one Electrum response line
    /// (`electrum.max_response_bytes`): every connection this adapter
    /// opens is a [`CappedClient`], so no single response line larger
    /// than this is ever held in memory — the read fails before the
    /// client's `BufReader` grows or any JSON decode runs, and the
    /// poisoned connection is torn down.
    max_response_bytes: u64,
    /// Claim-scan response bound: raw history items accepted across one
    /// window's batched `get_history`, enforced on the raw response values
    /// before any domain value is materialised.
    max_history_items_per_window: usize,
    /// Claim-scan per-window wall-clock deadline over connect + call +
    /// decode.
    claim_scan_window_deadline: Duration,
    /// Process-wide bound on concurrent claim-scan window fetches, shared
    /// across clones, so concurrent claims cannot grow the blocking pool
    /// unboundedly. Only the claim scan (`ChainHistoryPort`) draws permits.
    /// Each permit is owned by the blocking call it admits and released
    /// only when that call's socket read returns, so the bound covers
    /// reads orphaned past their window deadline too.
    claim_scan_permits: Arc<Semaphore>,
}

impl ElectrumAdapter {
    fn clone_for_fetch(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            network: self.network.clone(),
            timeout: self.timeout,
            max_utxos_per_address: self.max_utxos_per_address,
            address_deadline: self.address_deadline,
            max_response_bytes: self.max_response_bytes,
            max_history_items_per_window: self.max_history_items_per_window,
            claim_scan_window_deadline: self.claim_scan_window_deadline,
            claim_scan_permits: self.claim_scan_permits.clone(),
        }
    }

    /// Overrides the claim-scan bounds (production wiring passes the
    /// validated `electrum.*` config values; the constructors' defaults
    /// match the config defaults).
    pub fn with_claim_scan_bounds(
        mut self,
        max_history_items_per_window: usize,
        claim_scan_window_deadline: Duration,
        max_concurrent_claim_scans: usize,
    ) -> Self {
        self.max_history_items_per_window = max_history_items_per_window;
        self.claim_scan_window_deadline = claim_scan_window_deadline;
        self.claim_scan_permits = Arc::new(Semaphore::new(max_concurrent_claim_scans));
        self
    }

    /// Constructs a production adapter without requiring the remote endpoint to be online.
    pub fn configured(
        endpoint: impl Into<String>,
        network: BitcoinNetwork,
        timeout: Duration,
        max_utxos_per_address: usize,
        address_deadline: Duration,
        max_response_bytes: u64,
    ) -> Result<Self, ObserverError> {
        let endpoint = endpoint.into();
        // Refuse everything but tcp://host:port and ssl://host:port
        // (including socks5://) at startup: the proxy transport is not
        // routed through the capped wrapper.
        electrum::ElectrumEndpoint::parse(&endpoint).map_err(|_| ObserverError::Unavailable)?;
        Ok(Self {
            endpoint: endpoint.into(),
            network,
            timeout,
            max_utxos_per_address,
            address_deadline,
            max_response_bytes,
            max_history_items_per_window: DEFAULT_MAX_HISTORY_ITEMS_PER_WINDOW,
            claim_scan_window_deadline: DEFAULT_CLAIM_SCAN_WINDOW_DEADLINE,
            claim_scan_permits: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_CLAIM_SCANS)),
        })
    }

    pub async fn connect(
        endpoint: impl Into<String>,
        network: BitcoinNetwork,
        timeout: Duration,
        max_utxos_per_address: usize,
        address_deadline: Duration,
        max_response_bytes: u64,
    ) -> Result<Self, ObserverError> {
        let adapter = Self::configured(
            endpoint,
            network,
            timeout,
            max_utxos_per_address,
            address_deadline,
            max_response_bytes,
        )?;
        adapter.raw_client().await?;
        Ok(adapter)
    }

    /// Opens one fresh capped connection. There are no client-side call
    /// retries: each admitted target is exactly one request, charged once
    /// against the sustained budget, and the observer's own next tick is
    /// the retry. Connecting performs no Electrum RPC (the TLS handshake
    /// is transport I/O, not an Electrum request, and the client does not
    /// negotiate `server.version`), so a (re)connect is never a budgeted
    /// send.
    async fn raw_client(&self) -> Result<CappedClient, ObserverError> {
        let endpoint = self.endpoint.clone();
        let timeout = self.timeout;
        let max_response_bytes = self.max_response_bytes;
        tokio::task::spawn_blocking(move || {
            electrum::connect(&endpoint, timeout, max_response_bytes)
        })
        .await
        .map_err(|_| ObserverError::Unavailable)?
        .map_err(|_| ObserverError::Unavailable)
    }

    fn raw_client_blocking(&self) -> Result<CappedClient, std::io::Error> {
        electrum::connect(&self.endpoint, self.timeout, self.max_response_bytes)
    }
}

/// Outcome of one address's connect + call + decode inside the blocking
/// pool. A successful lookup hands the connection back for reuse; a failed
/// one drops it (its response stream may be desynchronized — a poisoned
/// capped stream can never be resumed) so the next address reconnects.
enum AddressAttempt {
    Observed(Box<CappedClient>, Vec<ObservedOutput>),
    Failed(AddressFailureReason),
    ConnectFailed,
}

#[async_trait]
impl ElectrumPort for ElectrumAdapter {
    async fn creation_snapshot(
        &self,
        address: &str,
        max_history_entries: usize,
        max_transaction_bytes: usize,
        request_limiter: &RequestLimiter,
        snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        let adapter = self.clone_for_fetch();
        let address = address.to_owned();
        let request_limiter = request_limiter.clone();
        tokio::task::spawn_blocking(move || {
            // The slot permit lives exactly as long as the Electrum I/O it
            // admits: it is owned by this blocking call and released only
            // when the call returns — never when the awaiting side gives up
            // on the request deadline. A snapshot whose socket read
            // outlives its handler therefore keeps its slot occupied until
            // the read ends (bounded at latest by the client
            // `electrum.request_timeout` on the wire), so the semaphore
            // bounds live blocking reads, not just awaited snapshots.
            let _snapshot_slot = snapshot_slot;
            let client = adapter
                .raw_client_blocking()
                .map_err(|_| ObserverError::Unavailable)?;
            let address = parse_address(&address, adapter.network.as_bitcoin_network())?;
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
                request_limiter
                    .try_reserve(1)
                    .map_err(|_| ObserverError::Unavailable)?;
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
            let notification = client.block_headers_subscribe().map_err(map_electrum)?;
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
            let client = adapter
                .raw_client_blocking()
                .map_err(|_| ObserverError::Unavailable)?;
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
        let mut report = ObservationReport::default();
        let mut client: Option<CappedClient> = None;
        for (index, target) in targets.iter().enumerate() {
            let adapter = self.clone();
            let target = target.clone();
            let address = target.address().to_owned();
            let attempt = tokio::task::spawn_blocking(move || {
                // A connect failure before any lookup is an endpoint-level
                // condition; per-address failures after it are isolated.
                let client = match client {
                    Some(client) => client,
                    None => match adapter.raw_client_blocking() {
                        Ok(client) => client,
                        Err(_) => return AddressAttempt::ConnectFailed,
                    },
                };
                match observe_address_blocking(
                    &client,
                    &adapter.network,
                    tip_height,
                    &target,
                    adapter.max_utxos_per_address,
                ) {
                    Ok(outputs) => AddressAttempt::Observed(Box::new(client), outputs),
                    Err(reason) => AddressAttempt::Failed(reason),
                }
            });
            // Per-address wall-clock deadline over connect + call + decode.
            // The blocking socket read cannot be cancelled, so on expiry
            // the join handle is abandoned: the tick moves on, the
            // connection is never reused, and the detached task exits when
            // the socket read returns (bounded by
            // `electrum.request_timeout`).
            let attempt = match tokio::time::timeout(self.address_deadline, attempt).await {
                Ok(Ok(attempt)) => attempt,
                Ok(Err(_)) => AddressAttempt::Failed(AddressFailureReason::Error),
                Err(_) => AddressAttempt::Failed(AddressFailureReason::Deadline),
            };
            match attempt {
                AddressAttempt::Observed(returned, outputs) => {
                    report.observed.push(address);
                    report.outputs.extend(outputs);
                    client = Some(*returned);
                }
                AddressAttempt::Failed(reason) => {
                    report.failed.push(FailedObservation { address, reason });
                    client = None;
                }
                AddressAttempt::ConnectFailed => {
                    if index == 0 {
                        return Err(ObserverError::Unavailable);
                    }
                    // A reconnect failure fails the remaining addresses
                    // without discarding the observations already
                    // collected.
                    report
                        .failed
                        .extend(targets[index..].iter().map(|target| FailedObservation {
                            address: target.address().to_owned(),
                            reason: AddressFailureReason::Error,
                        }));
                    break;
                }
            }
        }
        Ok(report)
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        let client = self.raw_client().await?;
        let network = self.network.clone();
        let probe = tokio::task::spawn_blocking(move || {
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
        });
        // Wall-clock deadline over the whole probe, reusing the
        // per-address `electrum.address_deadline` knob: the per-read
        // socket timeout (`electrum.request_timeout`) does not bound a
        // drip-feeding endpoint that answers one byte per interval, so
        // without this a slow-drip `headers.subscribe` reply would stall
        // the tick forever — no backoff, no `set_electrum_available`,
        // no metrics, leadership never released. Expiry fails the probe
        // as `Unavailable`, the same endpoint-level condition as a
        // connect outage, so the existing backoff/metrics/availability
        // path applies unchanged. As with the per-address path, the
        // blocking socket read cannot be cancelled: the abandoned
        // blocking task and its socket exit only when the read returns.
        match tokio::time::timeout(self.address_deadline, probe).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => Err(ObserverError::Unavailable),
        }
    }
}

/// Claim-time history scan on the same adapter the observer uses (design
/// §B.5). The observer tick never calls this port — the scan runs only in the
/// claim handler — so this adds no Electrum calls to observation. Each batch
/// runs bounded and blocking on its own dedicated connection with the
/// configured timeout, exactly like
/// [`ElectrumPort::creation_snapshot`], and every failure maps to
/// [`ClaimScanError::Unavailable`] so the claim is refused rather than
/// defaulted to index 0.
///
/// The response work is bounded three ways:
///
/// - **Item cap before materialising domain values.** The window's ONE
///   batched round-trip goes through [`ElectrumApi::batch_call`], which
///   returns the raw `serde_json::Value` results; the total item count is
///   capped at `max_history_items_per_window` across the batch BEFORE any
///   `GetHistoryRes` is deserialised — none ever is, presence is read off
///   the raw values. An over-cap window is treated as USED (presence =
///   `true` for the whole window, never attributed to individual
///   addresses): that only advances the start index, and the 50-window
///   scan bound still yields `account_history_too_deep`, so a seller with
///   a deep-history address is never derivable onto and never permanently
///   refused by the cap. (A raw-BYTE cap before JSON decode IS feasible
///   on the pinned electrum-client 0.25 through the public
///   `RawClient<S>` — it accepts any `S: Read + Write` via `impl
///   From<S>` (raw_client.rs:191-214), so a capped `Read` wrapper around
///   the TCP/TLS stream can reject an over-limit response before
///   `BufReader` growth or JSON decode — but it changes how the shared
///   Electrum client is constructed, so it lands as a separate
///   transport slice on the observer branch. Until that slice lands the
///   residual stands: the client buffers the whole response line
///   internally before the item cap applies. See
///   docs/observer-threat-model.md under "claim-time scan".)
/// - **Per-window wall-clock deadline.** Connect + call + decode must
///   finish within `claim_scan_window_deadline`. The blocking socket read
///   cannot be cancelled, so on expiry the join handle is abandoned: the
///   window fails `Unavailable`, the connection is never reused, and the
///   detached task exits when the socket read returns. That return is not
///   bounded by one `electrum.request_timeout`: the timeout is PER READ,
///   so the true wire bound is retries × request_timeout + reconnect
///   backoff (client-side retries are pinned at zero in this composition,
///   collapsing the formula) plus, for a drip-feeding endpoint, up to one
///   request_timeout per delivered byte until the
///   `electrum.max_response_bytes` + 1 line cap trips. Occupancy is
///   therefore bounded in count by the concurrency permit, not in time by
///   request_timeout.
/// - **Concurrency bound.** At most `max_concurrent_claim_scans` window
///   fetches run at once across the process; over the bound the window
///   fails `Unavailable` immediately (no queueing, no Electrum call).
///   The permit is owned by the blocking call itself, not by the awaiting
///   side: it is released only when the blocking socket read actually
///   returns, so a read orphaned past its window deadline still occupies
///   its slot (with the true wire bound named above: retries ×
///   request_timeout + reconnect backoff, retries pinned at zero here,
///   plus the per-read drip-feed extension to the
///   `electrum.max_response_bytes` + 1 line cap) and the bound holds in
///   live blocking threads and sockets.
#[async_trait]
impl ChainHistoryPort for ElectrumAdapter {
    async fn history_presence_batch(
        &self,
        scripts: &[ScriptBuf],
    ) -> Result<Vec<bool>, ClaimScanError> {
        // Concurrency bound first: over it the claim scan is unavailable
        // immediately, before any blocking task or Electrum call exists.
        let permit = self
            .claim_scan_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ClaimScanError::Unavailable)?;
        let adapter = self.clone_for_fetch();
        let scripts = scripts.to_vec();
        let max_items = self.max_history_items_per_window;
        let fetch = tokio::task::spawn_blocking(move || {
            // The permit lives exactly as long as the Electrum I/O it
            // admits: it is owned by this blocking call and released only
            // when the call returns — never when the awaiting side gives
            // up on the per-window deadline. A window whose socket read
            // outlives its deadline therefore keeps its slot occupied
            // until the read ends — not bounded by one
            // `electrum.request_timeout`: the timeout is per read, so the
            // true wire bound is retries × request_timeout + reconnect
            // backoff (client-side retries are pinned at zero in this
            // composition) plus, for a drip-feeding endpoint, up to one
            // request_timeout per delivered byte until the
            // `electrum.max_response_bytes` + 1 line cap trips — so the
            // semaphore bounds live blocking threads and sockets, not
            // just awaited windows.
            let _permit = permit;
            let client = adapter
                .raw_client_blocking()
                .map_err(|_| ClaimScanError::Unavailable)?;
            // ONE batched get_history round-trip for the window; presence
            // only, so transactions are never fetched.
            let mut batch = Batch::default();
            for script in &scripts {
                batch.script_get_history(script.as_script());
            }
            let responses = client
                .batch_call(&batch)
                .map_err(|_| ClaimScanError::Unavailable)?;
            if responses.len() != scripts.len() {
                // A malformed response is an Electrum failure, not an empty
                // window.
                return Err(ClaimScanError::Unavailable);
            }
            // Cap the decoded item count BEFORE any domain value is
            // materialised; presence is computed on the raw values.
            let mut items = 0_usize;
            let mut presence = Vec::with_capacity(responses.len());
            for response in &responses {
                let entries = response.as_array().ok_or(ClaimScanError::Unavailable)?;
                items = items.saturating_add(entries.len());
                presence.push(!entries.is_empty());
            }
            if items > max_items {
                // Over-cap: the whole window is treated as used (design
                // §B.5 — conservative: it only advances the start index;
                // the 50-window bound still yields account_history_too_deep).
                tracing::debug!(
                    items,
                    max_items,
                    "claim scan window over the history item cap; treating the window as used"
                );
                return Ok(vec![true; scripts.len()]);
            }
            Ok(presence)
        });
        // Per-window wall-clock deadline over connect + call + decode. The
        // blocking socket read cannot be cancelled, so on expiry the join
        // handle is abandoned: the scan fails the window Unavailable, the
        // connection is never reused, and the detached task exits when the
        // socket read returns — not bounded by one
        // `electrum.request_timeout`: the timeout is per read, so the true
        // wire bound is retries × request_timeout + reconnect backoff
        // (client-side retries are pinned at zero in this composition)
        // plus, for a drip-feeding endpoint, up to one request_timeout per
        // delivered byte until the `electrum.max_response_bytes` + 1 line
        // cap trips. The semaphore permit
        // moved into the blocking closure above stays held for exactly that
        // long too: the slot frees only when the read actually ends, not
        // when the deadline fires.
        match tokio::time::timeout(self.claim_scan_window_deadline, fetch).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => Err(ClaimScanError::Unavailable),
        }
    }
}

/// Observes one address with a single `blockchain.scripthash.listunspent`
/// raw call. The decoded item count is capped at `max_utxos` BEFORE any
/// per-UTXO record is materialised: an over-limit response fails this
/// address with [`AddressFailureReason::ResponseTooLarge`] and no record
/// vector is built for it. Below the item cap sits the transport cap: the
/// client's stream is a [`crate::workers::electrum::CappedStream`], so a
/// response line larger than `electrum.max_response_bytes` fails the read
/// (with the literal `electrum response exceeds max_response_bytes`
/// error) before the client's `BufReader` buffers it or any JSON decode
/// runs; the poisoned connection is torn down by the caller and the next
/// address reconnects. Every returned item becomes a present output; a
/// previously tracked outpoint missing from the unspent set becomes the
/// same absence record the settlement layer already consumes. Any error
/// fails this address only; the caller isolates it from the rest of the
/// tick.
fn observe_address_blocking(
    client: &CappedClient,
    network: &BitcoinNetwork,
    tip_height: u32,
    target: &ObservationTarget,
    max_utxos: usize,
) -> Result<Vec<ObservedOutput>, AddressFailureReason> {
    let expected_network = network.as_bitcoin_network();
    let address = parse_address(target.address(), expected_network)
        .map_err(|_| AddressFailureReason::Error)?;
    let response = client
        .raw_call(
            "blockchain.scripthash.listunspent",
            [Param::String(
                address
                    .script_pubkey()
                    .as_script()
                    .to_electrum_scripthash()
                    .to_lower_hex_string(),
            )],
        )
        .map_err(|_| AddressFailureReason::Error)?;
    if response
        .as_array()
        .ok_or(AddressFailureReason::Error)?
        .len()
        > max_utxos
    {
        return Err(AddressFailureReason::ResponseTooLarge);
    }
    let mut unspent: Vec<ListUnspentRes> =
        serde_json::from_value(response).map_err(|_| AddressFailureReason::Error)?;
    // Mirror ElectrumApi::script_list_unspent's canonical ordering.
    unspent.sort_unstable_by_key(|item| (item.height, item.tx_pos));
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
            let height = u32::try_from(item.height).map_err(|_| AddressFailureReason::Error)?;
            tip_height
                .checked_sub(height)
                .and_then(|distance| distance.checked_add(1))
                .ok_or(AddressFailureReason::Error)?
        };
        let outpoint = bitcoin::OutPoint::new(
            item.tx_hash,
            u32::try_from(item.tx_pos).map_err(|_| AddressFailureReason::Error)?,
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
                .map_err(|_| AddressFailureReason::Error)?,
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

/// Fetches one transaction and proves the returned bytes belong to the
/// requested txid before any caller consumes its inputs: an endpoint that
/// answers with a different (valid) transaction is a fetch failure, never
/// a resolution input. Over-cap responses are reported separately because
/// they are deterministically unresolvable under the configured byte cap.
fn fetch_transaction_blocking(
    client: &CappedClient,
    txid: Txid,
    max_transaction_bytes: usize,
) -> Result<bitcoin::Transaction, ObserverError> {
    let raw = client.transaction_get_raw(&txid).map_err(map_electrum)?;
    if raw.len() > max_transaction_bytes {
        return Err(ObserverError::TransactionTooLarge);
    }
    let transaction: bitcoin::Transaction =
        deserialize(&raw).map_err(|_| ObserverError::InvalidObservation)?;
    if transaction.compute_txid() != txid {
        return Err(ObserverError::Unavailable);
    }
    Ok(transaction)
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
    fn the_budget_refills_from_elapsed_wall_time_and_caps_at_capacity() {
        let start = Instant::now();
        let mut budget = RequestBudget::new(50, 5, start);
        // A fresh bucket is full: the first tick may burst to capacity.
        assert_eq!(budget.available(start), 50);
        budget.spend(50);
        assert_eq!(budget.available(start), 0);
        // Refill is wall-clock driven: 5/s over 8s (the shortest jitter of
        // a 10s poll interval) restores exactly 40 tokens, not the nominal
        // 50 a per-tick allowance would grant.
        assert_eq!(budget.available(start + Duration::from_secs(8)), 40);
        budget.spend(40);
        // Sub-token remainders keep accruing instead of being dropped: two
        // 100ms waits at 5/s grant exactly one token.
        assert_eq!(budget.available(start + Duration::from_millis(8100)), 0);
        assert_eq!(budget.available(start + Duration::from_millis(8200)), 1);
        // Accumulation never exceeds capacity, even across a long backoff.
        assert_eq!(budget.available(start + Duration::from_secs(3600)), 50);
    }

    #[test]
    fn sustained_ticks_at_the_shortest_jitter_interval_never_exceed_the_configured_rate() {
        const TICKS: usize = 100;
        let start = Instant::now();
        let interval = Duration::from_secs(8); // 80% of a 10s poll interval
        let mut budget = RequestBudget::new(50, 5, start);
        let mut instants = Vec::with_capacity(TICKS + 1);
        let mut consumed = Vec::with_capacity(TICKS);
        instants.push(start);
        for tick in 0..TICKS {
            let now = start + interval * u32::try_from(tick).unwrap();
            // Sustained over-budget load: demand always exceeds supply, so
            // every tick drains the bucket.
            let available = budget.available(now);
            budget.spend(available);
            consumed.push(available);
            instants.push(now);
        }
        // After the initial burst, every window admits at most
        // rate x window: the shortest possible loop cadence cannot beat
        // the configured sustained rate.
        let burst = consumed[0];
        assert_eq!(burst, 50, "the first tick spends the full bucket");
        for i in 1..TICKS {
            for j in i + 1..=TICKS {
                let window = instants[j] - instants[i - 1];
                let admitted: u64 = consumed[i..j].iter().sum();
                assert!(
                    admitted <= 5 * window.as_secs(),
                    "window {i}..{j} admitted {admitted} in {window:?}"
                );
            }
        }
    }

    #[test]
    fn concurrent_callers_cannot_jointly_exceed_the_shared_capacity() {
        // Real contention: 16 threads race try_reserve(1) against one
        // non-refilling bucket of capacity 5. Exactly 5 permits are
        // granted and 11 callers see BudgetExhausted, no matter the
        // interleaving; the bucket ends empty. Deterministic: every
        // thread is joined and the assertions are over counts, never
        // over timing.
        use std::sync::atomic::{AtomicUsize, Ordering};

        const CALLERS: usize = 16;
        const CAPACITY: u64 = 5;
        let limiter = RequestLimiter::new(CAPACITY, 0);
        let granted = Arc::new(AtomicUsize::new(0));
        let exhausted = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let limiter = limiter.clone();
            let granted = granted.clone();
            let exhausted = exhausted.clone();
            handles.push(std::thread::spawn(move || match limiter.try_reserve(1) {
                Ok(_permit) => {
                    granted.fetch_add(1, Ordering::Relaxed);
                }
                Err(BudgetExhausted { .. }) => {
                    exhausted.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("caller thread panicked");
        }
        assert_eq!(
            granted.load(Ordering::Relaxed),
            usize::try_from(CAPACITY).unwrap(),
            "exactly the bucket capacity is granted under contention"
        );
        assert_eq!(
            exhausted.load(Ordering::Relaxed),
            CALLERS - usize::try_from(CAPACITY).unwrap(),
            "every other caller fails without charging"
        );
        assert_eq!(limiter.available(), 0);
    }

    #[test]
    fn dropping_a_permit_neither_refunds_nor_double_charges() {
        let limiter = RequestLimiter::new(10, 0);
        let permit = limiter.try_reserve(4).expect("bucket starts full");
        assert_eq!(limiter.available(), 6);
        // Tokens were charged at reservation: dropping the permit leaves
        // the balance untouched (no refund, no second charge).
        drop(permit);
        assert_eq!(limiter.available(), 6);
    }

    #[tokio::test]
    async fn reserve_or_wait_waits_for_refill_until_the_deadline() {
        // A drained bucket refills at 100/s: the next token arrives within
        // ~10ms, well inside the deadline.
        let limiter = RequestLimiter::new(1, 100);
        let _taken = limiter.try_reserve(1).expect("bucket starts full");
        let permit = limiter
            .reserve_or_wait(1, Instant::now() + Duration::from_secs(2))
            .await
            .expect("refill arrives before the deadline");
        assert_eq!(permit.granted(), 1);
        // A deadline before the refill fails without charging.
        let err = limiter
            .reserve_or_wait(1, Instant::now() + Duration::from_millis(1))
            .await
            .unwrap_err();
        assert_eq!(err.requested, 1);
        // A non-refilling bucket can never satisfy a reservation: fail
        // fast instead of waiting out the deadline.
        let dry = RequestLimiter::new(1, 0);
        let _taken = dry.try_reserve(1).expect("bucket starts full");
        let start = Instant::now();
        assert!(
            dry.reserve_or_wait(1, start + Duration::from_secs(60))
                .await
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        // A reservation above capacity can never be satisfied.
        assert!(
            limiter
                .reserve_or_wait(2, Instant::now() + Duration::from_secs(60))
                .await
                .is_err()
        );
    }

    #[test]
    fn the_failure_log_rate_limits_per_address() {
        let start = Instant::now();
        let mut log = AddressFailureLog::new();
        assert!(log.should_log("a", start));
        assert!(!log.should_log("a", start + Duration::from_secs(60)));
        // Other addresses are unaffected by a's suppression.
        assert!(log.should_log("b", start + Duration::from_secs(60)));
        // After the interval the failure is visible again.
        assert!(log.should_log("a", start + ADDRESS_FAILURE_LOG_INTERVAL));
    }

    #[test]
    fn per_tick_budget_is_the_rate_allowance_capped_by_the_hard_limit() {
        let policy = ObserverPolicy {
            poll_interval: Duration::from_secs(10),
            max_requests_per_tick: 1000,
            max_requests_per_second: 5,
            max_transaction_bytes: 400_000,
            baseline_completion_timeout: Duration::from_secs(60),
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
