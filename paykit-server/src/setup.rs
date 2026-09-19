use std::{
    any::Any,
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use paykit_sdk::PubkyPublicKey;
use rand::{TryRngCore, rngs::OsRng};
use sqlx::PgPool;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use url::Url;

const FLOW_LIFETIME: Duration = Duration::from_secs(5 * 60);
const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const SETUP_RATE_WINDOW: Duration = Duration::from_secs(60);
const Z_BASE_32_ALPHABET: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Opaque, secret-bearing state owned by exactly one setup flow.
pub trait SetupAttempt: Send + 'static {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send>;
}

/// A started setup request. Its authorization URL is deliberately available only
/// to the server-owned iframe renderer; the secret-bearing attempt is never
/// exposed outside this module.
pub struct StartedSetup {
    pub authorization_url: String,
    attempt: Box<dyn SetupAttempt>,
}

impl StartedSetup {
    pub fn new(authorization_url: String, attempt: Box<dyn SetupAttempt>) -> Self {
        Self {
            authorization_url,
            attempt,
        }
    }
}

impl core::fmt::Debug for StartedSetup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartedSetup")
            .field("authorization_url", &"<redacted>")
            .finish()
    }
}

#[async_trait]
pub trait SetupCompleter: Send + Sync {
    /// Starts one normal Pubky AUTH request. The returned attempt is retained
    /// within one in-memory flow, not in a process-global completer.
    async fn start(&self) -> Result<StartedSetup, Completion>;
    /// Consumes the exact per-flow attempt after the iframe asks to complete.
    async fn complete(
        &self,
        attempt: Box<dyn SetupAttempt>,
        expected_creator: &PubkyPublicKey,
    ) -> Completion;
}

#[async_trait]
pub trait CancellationStore: Send + Sync {
    async fn record(&self, flow_id: &str) -> Result<(), ()>;
    async fn contains(&self, flow_id: &str) -> Result<bool, ()>;
}

pub struct PostgresCancellationStore {
    pool: PgPool,
}

impl PostgresCancellationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CancellationStore for PostgresCancellationStore {
    async fn record(&self, flow_id: &str) -> Result<(), ()> {
        sqlx::query(
            "INSERT INTO setup_flow_cancellations (flow_id, reason) \
             VALUES ($1, 'user_requested') ON CONFLICT (flow_id) DO NOTHING",
        )
        .bind(flow_id)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|_| ())
    }

    async fn contains(&self, flow_id: &str) -> Result<bool, ()> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM setup_flow_cancellations WHERE flow_id = $1)",
        )
        .bind(flow_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| ())
    }
}

struct MemoryCancellationStore(Mutex<HashMap<String, ()>>);

#[async_trait]
impl CancellationStore for MemoryCancellationStore {
    async fn record(&self, flow_id: &str) -> Result<(), ()> {
        self.0.lock().await.insert(flow_id.to_owned(), ());
        Ok(())
    }

    async fn contains(&self, flow_id: &str) -> Result<bool, ()> {
        Ok(self.0.lock().await.contains_key(flow_id))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    DurableSuccess,
    IdentityMismatch,
    DefinitiveFailure,
    TransientOverload,
    TransientUnavailable,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Duration;
}

/// Monotonic production clock scoped to this process lifetime.
#[derive(Debug)]
pub struct SystemClock(Instant);

impl Default for SystemClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

#[derive(Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn advance(&self, duration: Duration) {
        self.0
            .fetch_add(duration.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Clone)]
pub struct SetupService {
    inner: Arc<Inner>,
}

struct Inner {
    allowed_origins: Vec<String>,
    completer: Arc<dyn SetupCompleter>,
    clock: Arc<dyn Clock>,
    poll_timeout: Duration,
    max_polls_per_flow: usize,
    max_polls: usize,
    setup_capacity: Arc<Semaphore>,
    setup_rate: Mutex<SetupRateLimiter>,
    cancellations: Arc<dyn CancellationStore>,
    state: Mutex<State>,
    active_polls: AtomicUsize,
    changed: Notify,
}

struct State {
    flows: HashMap<String, Flow>,
    /// Retains only the fact that a recently expired flow existed. The flow and
    /// its secret-bearing AUTH attempt are removed immediately, while callers
    /// still receive the protocol's terminal `Expired` result.
    expired: HashMap<String, Duration>,
    cancelled: HashMap<String, Duration>,
}

struct Flow {
    state: String,
    origin: String,
    authorization_url: String,
    expected_creator: PubkyPublicKey,
    attempt: Option<Box<dyn SetupAttempt>>,
    reservation: Option<OwnedSemaphorePermit>,
    expires_at: Duration,
    status: FlowStatus,
    failure_result: Option<PollResult>,
    active_polls: Arc<AtomicUsize>,
}

struct CompletionLease {
    inner: Arc<Inner>,
    flow_id: String,
    _reservation: OwnedSemaphorePermit,
    armed: bool,
}

impl CompletionLease {
    fn new(inner: Arc<Inner>, flow_id: String, reservation: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            flow_id,
            _reservation: reservation,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for CompletionLease {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut state) = self.inner.state.try_lock() {
            fail_cancelled_completion(&mut state, &self.flow_id);
            self.inner.changed.notify_waiters();
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let inner = self.inner.clone();
        let flow_id = self.flow_id.clone();
        drop(runtime.spawn(async move {
            let mut state = inner.state.lock().await;
            fail_cancelled_completion(&mut state, &flow_id);
            inner.changed.notify_waiters();
        }));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowStatus {
    Pending,
    Cancelling,
    Completing,
    Completed,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BeginError {
    InvalidRequest,
    RateLimited,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupLimits {
    pub max_polls_per_flow: usize,
    pub max_polls: usize,
    pub setup_per_ip_per_minute: usize,
    pub max_pending_setup_flows: usize,
}

struct SetupRateLimiter {
    limit: usize,
    windows: HashMap<IpAddr, SetupRateWindow>,
}

struct SetupRateWindow {
    started_at: Duration,
    count: usize,
}

impl SetupRateLimiter {
    fn permit(&mut self, peer_ip: IpAddr, now: Duration) -> bool {
        self.windows
            .retain(|_, window| now.saturating_sub(window.started_at) < SETUP_RATE_WINDOW);
        let window = self.windows.entry(peer_ip).or_insert(SetupRateWindow {
            started_at: now,
            count: 0,
        });
        if window.count >= self.limit {
            return false;
        }
        window.count += 1;
        true
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StartedFlow {
    pub flow_id: String,
    pub state: String,
    pub origin: String,
    pub authorization_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollResult {
    Complete,
    IdentityMismatch,
    PendingTimeout,
    Unknown,
    Expired,
    Failed,
    Overloaded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelResult {
    Cancelled,
    Complete,
    Unknown,
    Expired,
    Failed,
    Completing,
    Unavailable,
}

impl SetupService {
    pub fn new(
        allowed_origins: Vec<String>,
        completer: Arc<dyn SetupCompleter>,
        clock: Arc<dyn Clock>,
        limits: SetupLimits,
    ) -> Self {
        Self::with_poll_timeout(
            allowed_origins,
            completer,
            clock,
            limits,
            DEFAULT_POLL_TIMEOUT,
        )
    }

    pub fn with_poll_timeout(
        allowed_origins: Vec<String>,
        completer: Arc<dyn SetupCompleter>,
        clock: Arc<dyn Clock>,
        limits: SetupLimits,
        poll_timeout: Duration,
    ) -> Self {
        Self::with_poll_timeout_and_cancellation_store(
            allowed_origins,
            completer,
            clock,
            limits,
            poll_timeout,
            Arc::new(MemoryCancellationStore(Mutex::new(HashMap::new()))),
        )
    }

    pub fn with_cancellation_store(
        allowed_origins: Vec<String>,
        completer: Arc<dyn SetupCompleter>,
        clock: Arc<dyn Clock>,
        limits: SetupLimits,
        cancellations: Arc<dyn CancellationStore>,
    ) -> Self {
        Self::with_poll_timeout_and_cancellation_store(
            allowed_origins,
            completer,
            clock,
            limits,
            DEFAULT_POLL_TIMEOUT,
            cancellations,
        )
    }

    fn with_poll_timeout_and_cancellation_store(
        allowed_origins: Vec<String>,
        completer: Arc<dyn SetupCompleter>,
        clock: Arc<dyn Clock>,
        limits: SetupLimits,
        poll_timeout: Duration,
        cancellations: Arc<dyn CancellationStore>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                allowed_origins,
                completer,
                clock,
                poll_timeout,
                max_polls_per_flow: limits.max_polls_per_flow,
                max_polls: limits.max_polls,
                setup_capacity: Arc::new(Semaphore::new(limits.max_pending_setup_flows)),
                setup_rate: Mutex::new(SetupRateLimiter {
                    limit: limits.setup_per_ip_per_minute,
                    windows: HashMap::new(),
                }),
                cancellations,
                state: Mutex::new(State {
                    flows: HashMap::new(),
                    expired: HashMap::new(),
                    cancelled: HashMap::new(),
                }),
                active_polls: AtomicUsize::new(0),
                changed: Notify::new(),
            }),
        }
    }

    pub async fn begin(
        &self,
        peer_ip: IpAddr,
        return_to: &str,
        state: &str,
        creator: &str,
    ) -> Result<StartedFlow, BeginError> {
        let origin = validated_origin(return_to, &self.inner.allowed_origins)
            .ok_or(BeginError::InvalidRequest)?;
        if !valid_state(state) {
            return Err(BeginError::InvalidRequest);
        }
        let expected_creator = parse_expected_creator(creator).ok_or(BeginError::InvalidRequest)?;
        let now = self.inner.clock.now();
        if !self.inner.setup_rate.lock().await.permit(peer_ip, now) {
            return Err(BeginError::RateLimited);
        }
        {
            let mut guard = self.inner.state.lock().await;
            cleanup_expired(&mut guard, now);
        }
        let reservation = self
            .inner
            .setup_capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| BeginError::Unavailable)?;
        let started_setup = self
            .inner
            .completer
            .start()
            .await
            .map_err(|_| BeginError::Unavailable)?;
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| BeginError::Unavailable)?;
        let flow_id = URL_SAFE_NO_PAD.encode(bytes);
        let started = StartedFlow {
            flow_id: flow_id.clone(),
            state: state.to_owned(),
            origin,
            authorization_url: started_setup.authorization_url.clone(),
        };
        let mut guard = self.inner.state.lock().await;
        cleanup_expired(&mut guard, self.inner.clock.now());
        guard.flows.insert(
            flow_id,
            Flow {
                state: state.to_owned(),
                origin: started.origin.clone(),
                authorization_url: started_setup.authorization_url,
                expected_creator,
                attempt: Some(started_setup.attempt),
                reservation: Some(reservation),
                expires_at: self.inner.clock.now() + FLOW_LIFETIME,
                status: FlowStatus::Pending,
                failure_result: None,
                active_polls: Arc::new(AtomicUsize::new(0)),
            },
        );
        Ok(started)
    }

    /// Runs real completion for precisely this flow. A completion attempt is
    /// consumed once because Pubky AUTH approval is one-shot.
    pub async fn trigger_completion(&self, flow_id: &str) -> PollResult {
        let (attempt, reservation, expected_creator) = {
            let mut guard = self.inner.state.lock().await;
            let now = self.inner.clock.now();
            cleanup_expired(&mut guard, now);
            let Some(flow) = guard.flows.get_mut(flow_id) else {
                return expired_or_unknown(&guard, flow_id);
            };
            match flow.status {
                FlowStatus::Completed => return PollResult::Complete,
                FlowStatus::Failed => {
                    return flow.failure_result.unwrap_or(PollResult::Failed);
                }
                FlowStatus::Cancelling => return PollResult::PendingTimeout,
                FlowStatus::Completing => return PollResult::PendingTimeout,
                FlowStatus::Pending => {}
            }
            flow.status = FlowStatus::Completing;
            (
                flow.attempt
                    .take()
                    .expect("pending flow has an auth attempt"),
                flow.reservation
                    .take()
                    .expect("pending flow has a setup reservation"),
                flow.expected_creator.clone(),
            )
        };
        let completion_lease =
            CompletionLease::new(self.inner.clone(), flow_id.to_owned(), reservation);
        let completion = self
            .inner
            .completer
            .complete(attempt, &expected_creator)
            .await;
        let mut guard = self.inner.state.lock().await;
        let now = self.inner.clock.now();
        cleanup_expired(&mut guard, now);
        let result = match guard.flows.get_mut(flow_id) {
            None => expired_or_unknown(&guard, flow_id),
            Some(flow) => match completion {
                Completion::DurableSuccess => {
                    flow.status = FlowStatus::Completed;
                    PollResult::Complete
                }
                Completion::IdentityMismatch => {
                    flow.status = FlowStatus::Failed;
                    flow.failure_result = Some(PollResult::IdentityMismatch);
                    PollResult::IdentityMismatch
                }
                // One-shot auth requests cannot safely be replayed after any
                // completion failure. Fail closed rather than falsely retaining
                // a consumed request as pending.
                Completion::DefinitiveFailure
                | Completion::TransientOverload
                | Completion::TransientUnavailable => {
                    flow.status = FlowStatus::Failed;
                    flow.failure_result = Some(PollResult::Failed);
                    PollResult::Failed
                }
            },
        };
        drop(guard);
        self.inner.changed.notify_waiters();
        completion_lease.disarm();
        result
    }

    pub async fn poll(&self, flow_id: &str) -> PollResult {
        let lease = match self.acquire_poll(flow_id).await {
            Ok(lease) => lease,
            Err(result) => return result,
        };
        let notified = self.inner.changed.notified();
        let initial = self.status(flow_id).await;
        if initial != PollResult::PendingTimeout {
            drop(lease);
            return initial;
        }
        let _ = tokio::time::timeout(self.inner.poll_timeout, notified).await;
        drop(lease);
        self.status(flow_id).await
    }

    /// Handles the completion endpoint through the same bounded poll path used
    /// by an iframe retry. If another request already initiated one-shot AUTH,
    /// this waits at most one poll interval and applies the normal poll limits.
    pub async fn complete_and_poll(&self, flow_id: &str) -> PollResult {
        match self.trigger_completion(flow_id).await {
            PollResult::PendingTimeout => self.poll(flow_id).await,
            result => result,
        }
    }

    /// Cancels only a still-pending flow. The opaque flow id is the existing
    /// capability; it is never returned or logged. Persist before dropping
    /// the one-shot attempt so a storage failure leaves the flow usable.
    pub async fn cancel(&self, flow_id: &str) -> CancelResult {
        {
            let mut guard = self.inner.state.lock().await;
            let now = self.inner.clock.now();
            cleanup_expired(&mut guard, now);
            let Some(flow) = guard.flows.get_mut(flow_id) else {
                if guard.cancelled.contains_key(flow_id) {
                    return CancelResult::Cancelled;
                }
                if guard.expired.contains_key(flow_id) {
                    return CancelResult::Expired;
                }
                drop(guard);
                return match self.inner.cancellations.contains(flow_id).await {
                    Ok(true) => CancelResult::Cancelled,
                    Ok(false) => CancelResult::Unknown,
                    Err(()) => CancelResult::Unavailable,
                };
            };
            match flow.status {
                FlowStatus::Pending => flow.status = FlowStatus::Cancelling,
                FlowStatus::Cancelling => return CancelResult::Completing,
                FlowStatus::Completing => return CancelResult::Completing,
                FlowStatus::Completed => return CancelResult::Complete,
                FlowStatus::Failed => return CancelResult::Failed,
            }
        }
        if self.inner.cancellations.record(flow_id).await.is_err() {
            let mut guard = self.inner.state.lock().await;
            if let Some(flow) = guard.flows.get_mut(flow_id)
                && flow.status == FlowStatus::Cancelling
            {
                flow.status = FlowStatus::Pending;
            }
            return CancelResult::Unavailable;
        }
        let mut guard = self.inner.state.lock().await;
        let now = self.inner.clock.now();
        cleanup_expired(&mut guard, now);
        let Some(flow) = guard.flows.get(flow_id) else {
            return expired_or_unknown(&guard, flow_id).into_cancel_result();
        };
        if flow.status != FlowStatus::Cancelling {
            return CancelResult::Completing;
        }
        guard.flows.remove(flow_id);
        guard
            .cancelled
            .insert(flow_id.to_owned(), now + FLOW_LIFETIME);
        drop(guard);
        self.inner.changed.notify_waiters();
        CancelResult::Cancelled
    }

    pub async fn flow(&self, flow_id: &str) -> Option<StartedFlow> {
        let mut guard = self.inner.state.lock().await;
        cleanup_expired(&mut guard, self.inner.clock.now());
        guard.flows.get(flow_id).map(|flow| StartedFlow {
            flow_id: flow_id.to_owned(),
            state: flow.state.clone(),
            origin: flow.origin.clone(),
            authorization_url: flow.authorization_url.clone(),
        })
    }

    async fn status(&self, flow_id: &str) -> PollResult {
        let mut guard = self.inner.state.lock().await;
        cleanup_expired(&mut guard, self.inner.clock.now());
        match guard.flows.get(flow_id) {
            None => expired_or_unknown(&guard, flow_id),
            Some(Flow {
                status: FlowStatus::Pending | FlowStatus::Cancelling | FlowStatus::Completing,
                ..
            }) => PollResult::PendingTimeout,
            Some(Flow {
                status: FlowStatus::Completed,
                ..
            }) => PollResult::Complete,
            Some(Flow {
                status: FlowStatus::Failed,
                failure_result,
                ..
            }) => failure_result.unwrap_or(PollResult::Failed),
        }
    }

    async fn acquire_poll(&self, flow_id: &str) -> Result<PollLease<'_>, PollResult> {
        let mut guard = self.inner.state.lock().await;
        let now = self.inner.clock.now();
        cleanup_expired(&mut guard, now);
        let Some(flow) = guard.flows.get(flow_id) else {
            return Err(expired_or_unknown(&guard, flow_id));
        };
        match flow.status {
            FlowStatus::Failed => {
                return Err(flow.failure_result.unwrap_or(PollResult::Failed));
            }
            FlowStatus::Completed => return Err(PollResult::Complete),
            FlowStatus::Pending | FlowStatus::Cancelling | FlowStatus::Completing => {}
        }
        let flow_polls = flow.active_polls.clone();
        drop(guard);
        if !reserve_poll(&flow_polls, self.inner.max_polls_per_flow) {
            return Err(PollResult::Overloaded);
        }
        if !reserve_poll(&self.inner.active_polls, self.inner.max_polls) {
            flow_polls.fetch_sub(1, Ordering::SeqCst);
            return Err(PollResult::Unavailable);
        }
        Ok(PollLease {
            flow_polls,
            total_polls: &self.inner.active_polls,
        })
    }
}

struct PollLease<'a> {
    flow_polls: Arc<AtomicUsize>,
    total_polls: &'a AtomicUsize,
}

impl Drop for PollLease<'_> {
    fn drop(&mut self) {
        self.flow_polls.fetch_sub(1, Ordering::SeqCst);
        self.total_polls.fetch_sub(1, Ordering::SeqCst);
    }
}

fn reserve_poll(counter: &AtomicUsize, maximum: usize) -> bool {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            (current < maximum).then_some(current + 1)
        })
        .is_ok()
}

fn cleanup_expired(state: &mut State, now: Duration) {
    state.expired.retain(|_, until| now < *until);
    state.cancelled.retain(|_, until| now < *until);
    let expired_ids = state
        .flows
        .iter()
        .filter(|(_, flow)| now >= flow.expires_at)
        .map(|(flow_id, _)| flow_id.clone())
        .collect::<Vec<_>>();
    for flow_id in expired_ids {
        // Removing the flow drops its attempt and authorization URL before the
        // tombstone is recorded. Tombstones contain no flow secrets.
        state.flows.remove(&flow_id);
        state.expired.insert(flow_id, now + FLOW_LIFETIME);
    }
}

impl PollResult {
    fn into_cancel_result(self) -> CancelResult {
        match self {
            Self::Unknown => CancelResult::Unknown,
            Self::Expired => CancelResult::Expired,
            Self::Complete => CancelResult::Complete,
            Self::Failed | Self::IdentityMismatch => CancelResult::Failed,
            Self::PendingTimeout | Self::Overloaded | Self::Unavailable => {
                CancelResult::Unavailable
            }
        }
    }
}

fn fail_cancelled_completion(state: &mut State, flow_id: &str) {
    if let Some(flow) = state.flows.get_mut(flow_id)
        && flow.status == FlowStatus::Completing
    {
        flow.status = FlowStatus::Failed;
        flow.failure_result = Some(PollResult::Failed);
    }
}

fn expired_or_unknown(state: &State, flow_id: &str) -> PollResult {
    if state.expired.contains_key(flow_id) {
        PollResult::Expired
    } else {
        PollResult::Unknown
    }
}

fn valid_state(state: &str) -> bool {
    (1..=512).contains(&state.len()) && !state.chars().any(char::is_control)
}

fn parse_expected_creator(creator: &str) -> Option<PubkyPublicKey> {
    if creator.len() != 52
        || !creator
            .bytes()
            .all(|byte| Z_BASE_32_ALPHABET.contains(&byte))
    {
        return None;
    }
    PubkyPublicKey::new(creator).ok()
}

fn validated_origin(return_to: &str, allowed_origins: &[String]) -> Option<String> {
    if return_to.len() > 2048 {
        return None;
    }
    let url = Url::parse(return_to).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.cannot_be_a_base()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    allowed_origins
        .iter()
        .any(|allowed| allowed == "*" || allowed == &origin)
        .then_some(origin)
}
