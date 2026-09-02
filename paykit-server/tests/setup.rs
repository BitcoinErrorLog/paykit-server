use std::{
    any::Any,
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode},
    response::Response,
};
use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use paykit_server::{
    config::BitcoinNetwork,
    http::setup::setup_router,
    real_setup::validate_xpub,
    setup::{
        BeginError, Completion, ManualClock, PollResult, SetupAttempt, SetupCompleter, SetupLimits,
        SetupService, StartedSetup,
    },
};
use tokio::sync::{Mutex, Notify, Semaphore};
use tower::ServiceExt;

fn account_xpub(network: Network, coin_type: u32, account_index: u32) -> Xpub {
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(network, &[42; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(coin_type).unwrap(),
                ChildNumber::from_hardened_idx(account_index).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account)
}

#[test]
fn setup_claim_accepts_only_a_usable_canonical_bip84_account_xpub() {
    let xpub = account_xpub(Network::Bitcoin, 0, 7);

    let canonical =
        validate_xpub(&xpub.encode(), 7, &BitcoinNetwork::Mainnet).expect("valid account claim");

    assert_eq!(canonical, xpub.to_string());
    assert!(
        paykit_server::application::create_invoice::derive_bip84_p2wpkh_address(
            &canonical,
            7,
            &BitcoinNetwork::Mainnet,
            0,
        )
        .is_ok(),
        "claim validation must cover external-chain child-zero address derivation"
    );
}

#[test]
fn setup_claim_rejects_xpub_for_the_wrong_configured_network() {
    let testnet = account_xpub(Network::Testnet, 1, 0);
    assert!(validate_xpub(&testnet.encode(), 0, &BitcoinNetwork::Mainnet).is_err());

    let mainnet = account_xpub(Network::Bitcoin, 0, 0);
    assert!(validate_xpub(&mainnet.encode(), 0, &BitcoinNetwork::Testnet).is_err());
}

#[test]
fn setup_claim_rejects_non_account_depth_xpub() {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Bitcoin, &[42; 32]).unwrap();
    let master_xpub = Xpub::from_priv(&secp, &master);

    assert!(validate_xpub(&master_xpub.encode(), 0, &BitcoinNetwork::Mainnet).is_err());
}

#[test]
fn setup_claim_rejects_account_xpub_for_a_different_hardened_account_index() {
    let account_one = account_xpub(Network::Bitcoin, 0, 1);

    assert!(validate_xpub(&account_one.encode(), 0, &BitcoinNetwork::Mainnet).is_err());
}

#[test]
fn setup_claim_rejects_malformed_public_key_bytes() {
    let mut malformed = account_xpub(Network::Bitcoin, 0, 0).encode();
    malformed[45..78].fill(0);

    assert!(validate_xpub(&malformed, 0, &BitcoinNetwork::Mainnet).is_err());
}

struct MockCompleter {
    calls: AtomicUsize,
    results: Mutex<VecDeque<Completion>>,
}

impl MockCompleter {
    fn new(results: impl IntoIterator<Item = Completion>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            results: Mutex::new(results.into_iter().collect()),
        }
    }
}

struct MockAttempt;
impl SetupAttempt for MockAttempt {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

struct InstructionCompleter;

#[async_trait]
impl SetupCompleter for InstructionCompleter {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        Ok(StartedSetup::new(
            "pubkyauth://signin?secret=mock&label=<approve>".to_owned(),
            Box::new(MockAttempt),
        ))
    }

    async fn complete(&self, _: Box<dyn SetupAttempt>) -> Completion {
        Completion::DurableSuccess
    }
}

struct TrackingAttempt(Arc<AtomicUsize>);

impl Drop for TrackingAttempt {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl SetupAttempt for TrackingAttempt {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

struct TrackingCompleter {
    dropped: Arc<AtomicUsize>,
}

#[async_trait]
impl SetupCompleter for TrackingCompleter {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        Ok(StartedSetup::new(
            "pubkyauth://signin?secret=tracking".to_owned(),
            Box::new(TrackingAttempt(self.dropped.clone())),
        ))
    }

    async fn complete(&self, _: Box<dyn SetupAttempt>) -> Completion {
        Completion::DurableSuccess
    }
}

struct BlockingCompleter {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

struct BlockingStartCompleter {
    entered: Arc<AtomicUsize>,
    changed: Arc<Notify>,
    release: Arc<Semaphore>,
}

#[async_trait]
impl SetupCompleter for BlockingStartCompleter {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
        self.release
            .acquire()
            .await
            .expect("test release semaphore remains open")
            .forget();
        Ok(StartedSetup::new(
            "pubkyauth://signin?secret=blocked-start".to_owned(),
            Box::new(MockAttempt),
        ))
    }

    async fn complete(&self, _: Box<dyn SetupAttempt>) -> Completion {
        Completion::DurableSuccess
    }
}

struct FailFirstStartCompleter(AtomicUsize);

#[async_trait]
impl SetupCompleter for FailFirstStartCompleter {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(Completion::TransientUnavailable);
        }
        Ok(StartedSetup::new(
            "pubkyauth://signin?secret=recovered".to_owned(),
            Box::new(MockAttempt),
        ))
    }

    async fn complete(&self, _: Box<dyn SetupAttempt>) -> Completion {
        Completion::DurableSuccess
    }
}

#[async_trait]
impl SetupCompleter for BlockingCompleter {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        Ok(StartedSetup::new(
            "pubkyauth://signin?secret=blocked".to_owned(),
            Box::new(MockAttempt),
        ))
    }

    async fn complete(&self, _: Box<dyn SetupAttempt>) -> Completion {
        self.entered.notify_one();
        self.release.notified().await;
        Completion::DurableSuccess
    }
}

#[async_trait]
impl SetupCompleter for MockCompleter {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        Ok(StartedSetup::new(
            "pubkyauth://signin?secret=mock".to_owned(),
            Box::new(MockAttempt),
        ))
    }

    async fn complete(&self, _: Box<dyn SetupAttempt>) -> Completion {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.results
            .lock()
            .await
            .pop_front()
            .unwrap_or(Completion::DurableSuccess)
    }
}

fn service(completer: Arc<dyn SetupCompleter>, clock: Arc<ManualClock>) -> SetupService {
    let limits = runtime_limits(2, 4, 100, 100);
    SetupService::with_poll_timeout(
        vec!["https://app.example".to_owned()],
        completer,
        clock,
        limits,
        Duration::ZERO,
    )
}

fn runtime_limits(
    max_polls_per_flow: usize,
    max_polls: usize,
    setup_per_ip_per_minute: usize,
    max_pending_setup_flows: usize,
) -> SetupLimits {
    SetupLimits {
        max_pending_setup_flows,
        setup_per_ip_per_minute,
        max_polls_per_flow,
        max_polls,
    }
}

fn limited_service(
    completer: Arc<dyn SetupCompleter>,
    clock: Arc<ManualClock>,
    setup_per_ip_per_minute: usize,
    max_pending_setup_flows: usize,
) -> SetupService {
    let limits = runtime_limits(2, 4, setup_per_ip_per_minute, max_pending_setup_flows);
    SetupService::with_poll_timeout(
        vec!["https://app.example".to_owned()],
        completer,
        clock,
        limits,
        Duration::ZERO,
    )
}

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

async fn request(router: axum::Router, method: Method, uri: &str) -> Response {
    request_with_body(router, method, uri, Body::empty()).await
}

async fn request_with_body(
    router: axum::Router,
    method: Method,
    uri: &str,
    request_body: Body,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(request_body)
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(peer(), 12345)));
    router.oneshot(request).await.unwrap()
}

async fn body(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 32 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn invalid_and_unknown_setup_queries_are_rejected_without_a_flow_or_completion() {
    let completer = Arc::new(MockCompleter::new([]));
    let router = setup_router(service(completer.clone(), Arc::new(ManualClock::default())));
    for uri in [
        "/setup?return_to=https://evil.example&state=ok",
        "/setup?return_to=https://app.example&state=ok&delivery=redirect",
        "/setup?return_to=https://app.example&state=ok&extra=x",
        "/setup?return_to=https://app.example&state=ok&state=twice",
        "/setup?return_to=https://user:pass@app.example&state=ok",
        "/setup?return_to=https://app.example&state=%00",
    ] {
        let response = request(router.clone(), Method::GET, uri).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body(response).await, r#"{"error":"invalid_request"}"#);
    }
    assert_eq!(completer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn flow_ids_are_random_base64url_32_byte_values() {
    let completer = Arc::new(MockCompleter::new([]));
    let setup = service(completer, Arc::new(ManualClock::default()));
    let first = setup
        .begin(peer(), "https://app.example/path", "one")
        .await
        .unwrap();
    let second = setup
        .begin(peer(), "https://app.example/path", "two")
        .await
        .unwrap();
    assert_eq!(first.flow_id.len(), 43);
    assert!(
        first
            .flow_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    );
    assert_ne!(first.flow_id, second.flow_id);
}

#[tokio::test]
async fn flow_lifecycle_is_memory_only_single_initiation_and_expiry_is_terminal() {
    let completer = Arc::new(MockCompleter::new([Completion::DurableSuccess]));
    let clock = Arc::new(ManualClock::default());
    let setup = service(completer, clock.clone());
    let flow = setup
        .begin(peer(), "https://app.example", "state")
        .await
        .unwrap();
    assert_eq!(
        setup.trigger_completion(&flow.flow_id).await,
        PollResult::Complete
    );
    assert_eq!(setup.poll(&flow.flow_id).await, PollResult::Complete);
    clock.advance(Duration::from_secs(300));
    assert_eq!(setup.poll(&flow.flow_id).await, PollResult::Expired);
    let replacement = service(Arc::new(MockCompleter::new([])), clock);
    assert_eq!(replacement.poll(&flow.flow_id).await, PollResult::Unknown);
}

#[tokio::test]
async fn expired_flows_drop_secret_attempts_but_retain_a_bounded_expired_tombstone() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let clock = Arc::new(ManualClock::default());
    let setup = service(
        Arc::new(TrackingCompleter {
            dropped: dropped.clone(),
        }),
        clock.clone(),
    );
    let flow = setup
        .begin(peer(), "https://app.example", "state")
        .await
        .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 0);

    clock.advance(Duration::from_secs(300));
    assert_eq!(setup.poll(&flow.flow_id).await, PollResult::Expired);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(setup.flow(&flow.flow_id).await.is_none());
    assert_eq!(
        setup.trigger_completion(&flow.flow_id).await,
        PollResult::Expired
    );
    clock.advance(Duration::from_secs(300));
    assert_eq!(setup.poll(&flow.flow_id).await, PollResult::Unknown);
}

#[tokio::test]
async fn completion_port_results_map_to_terminal_and_transient_states_without_secret_details() {
    let clock = Arc::new(ManualClock::default());
    let completer = Arc::new(MockCompleter::new([
        Completion::DurableSuccess,
        Completion::DefinitiveFailure,
        Completion::TransientOverload,
        Completion::TransientUnavailable,
    ]));
    let setup = service(completer, clock);
    let complete = setup
        .begin(peer(), "https://app.example", "a")
        .await
        .unwrap();
    let failed = setup
        .begin(peer(), "https://app.example", "b")
        .await
        .unwrap();
    let overloaded = setup
        .begin(peer(), "https://app.example", "c")
        .await
        .unwrap();
    let unavailable = setup
        .begin(peer(), "https://app.example", "d")
        .await
        .unwrap();
    assert_eq!(
        setup.trigger_completion(&complete.flow_id).await,
        PollResult::Complete
    );
    assert_eq!(
        setup.trigger_completion(&failed.flow_id).await,
        PollResult::Failed
    );
    assert_eq!(
        setup.trigger_completion(&overloaded.flow_id).await,
        PollResult::Failed
    );
    assert_eq!(setup.poll(&overloaded.flow_id).await, PollResult::Failed);
    assert_eq!(
        setup.trigger_completion(&unavailable.flow_id).await,
        PollResult::Failed
    );
    assert_eq!(setup.poll(&unavailable.flow_id).await, PollResult::Failed);
    let router = setup_router(setup);
    for (id, expected) in [
        (complete.flow_id, StatusCode::OK),
        (failed.flow_id, StatusCode::UNPROCESSABLE_ENTITY),
        (overloaded.flow_id, StatusCode::UNPROCESSABLE_ENTITY),
        (unavailable.flow_id, StatusCode::UNPROCESSABLE_ENTITY),
        ("missing".to_owned(), StatusCode::NOT_FOUND),
    ] {
        let response = request(
            router.clone(),
            Method::POST,
            &format!("/setup/{id}/complete"),
        )
        .await;
        assert_eq!(response.status(), expected);
        let response_body = body(response).await;
        assert!(!response_body.contains("xpub"));
        assert!(!response_body.contains("authorization_url"));
    }
}

#[tokio::test]
async fn complete_route_returns_safe_json_and_preserves_expired_status() {
    let completer = Arc::new(MockCompleter::new([
        Completion::DefinitiveFailure,
        Completion::DurableSuccess,
    ]));
    let clock = Arc::new(ManualClock::default());
    let setup = service(completer, clock.clone());
    let complete = setup
        .begin(peer(), "https://app.example", "complete")
        .await
        .unwrap();
    let failed = setup
        .begin(peer(), "https://app.example", "failed")
        .await
        .unwrap();
    assert_eq!(
        setup.trigger_completion(&failed.flow_id).await,
        PollResult::Failed
    );
    let router = setup_router(setup.clone());

    let completed = request(
        router.clone(),
        Method::POST,
        &format!("/setup/{}/complete", complete.flow_id),
    )
    .await;
    assert_eq!(completed.status(), StatusCode::OK);
    assert_eq!(body(completed).await, r#"{"status":"complete"}"#);
    let failed = request(
        router.clone(),
        Method::POST,
        &format!("/setup/{}/complete", failed.flow_id),
    )
    .await;
    assert_eq!(failed.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body(failed).await, r#"{"error":"setup_failed"}"#);

    let expired = setup
        .begin(peer(), "https://app.example", "expired")
        .await
        .unwrap();
    clock.advance(Duration::from_secs(300));
    let expired = request(
        router.clone(),
        Method::POST,
        &format!("/setup/{}/complete", expired.flow_id),
    )
    .await;
    assert_eq!(expired.status(), StatusCode::GONE);
    assert_eq!(body(expired).await, r#"{"error":"expired"}"#);
    let missing = request(router, Method::POST, "/setup/missing/complete").await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(body(missing).await, r#"{"error":"not_found"}"#);
}

#[tokio::test]
async fn manual_claim_route_is_not_mounted() {
    let completer = Arc::new(MockCompleter::new([]));
    let setup = service(completer.clone(), Arc::new(ManualClock::default()));
    let flow = setup
        .begin(peer(), "https://app.example", "state")
        .await
        .unwrap();

    let response = request_with_body(
        setup_router(setup),
        Method::POST,
        &format!("/setup/{}/claim", flow.flow_id),
        Body::from(r#"{"xpub":"xpub-FAKE-NON-SECRET-REGRESSION-MARKER"}"#),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(completer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn xpub_bearing_completion_request_cannot_override_normal_completion_failure() {
    let completer = Arc::new(MockCompleter::new([Completion::DefinitiveFailure]));
    let setup = service(completer.clone(), Arc::new(ManualClock::default()));
    let flow = setup
        .begin(peer(), "https://app.example", "state")
        .await
        .unwrap();

    let response = request_with_body(
        setup_router(setup),
        Method::POST,
        &format!("/setup/{}/complete", flow.flow_id),
        Body::from(r#"{"xpub":"xpub-FAKE-NON-SECRET-REGRESSION-MARKER"}"#),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body(response).await, r#"{"error":"setup_failed"}"#);
    assert_eq!(completer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn complete_route_uses_the_bounded_poll_path_and_maps_poll_limits() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let limits = runtime_limits(1, 1, 10, 10);
    let setup = SetupService::with_poll_timeout(
        vec!["https://app.example".to_owned()],
        Arc::new(BlockingCompleter {
            entered: entered.clone(),
            release: release.clone(),
        }),
        Arc::new(ManualClock::default()),
        limits,
        Duration::from_secs(5),
    );
    let flow = setup
        .begin(peer(), "https://app.example", "state")
        .await
        .unwrap();
    let router = setup_router(setup);

    let entered_wait = entered.notified();
    let first_uri = format!("/setup/{}/complete", flow.flow_id);
    let first_router = router.clone();
    let first = tokio::spawn(async move { request(first_router, Method::POST, &first_uri).await });
    entered_wait.await;
    let second_uri = format!("/setup/{}/complete", flow.flow_id);
    let second_router = router.clone();
    let second =
        tokio::spawn(async move { request(second_router, Method::POST, &second_uri).await });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let limited = request(
        router,
        Method::POST,
        &format!("/setup/{}/complete", flow.flow_id),
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body(limited).await, r#"{"error":"overloaded"}"#);

    release.notify_one();
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    assert_eq!(second.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn concurrent_polls_are_limited_per_flow_and_globally() {
    let completer = Arc::new(MockCompleter::new([]));
    let limits = runtime_limits(2, 2, 10, 10);
    let setup = SetupService::new(
        vec!["https://app.example".to_owned()],
        completer,
        Arc::new(ManualClock::default()),
        limits,
    );
    let first = setup
        .begin(peer(), "https://app.example", "one")
        .await
        .unwrap();
    let second = setup
        .begin(peer(), "https://app.example", "two")
        .await
        .unwrap();
    let first_poll = tokio::spawn({
        let setup = setup.clone();
        let id = first.flow_id.clone();
        async move { setup.poll(&id).await }
    });
    let second_poll = tokio::spawn({
        let setup = setup.clone();
        let id = second.flow_id.clone();
        async move { setup.poll(&id).await }
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(setup.poll(&first.flow_id).await, PollResult::Unavailable);
    assert_eq!(
        setup.trigger_completion(&first.flow_id).await,
        PollResult::Complete
    );
    assert_eq!(
        setup.trigger_completion(&second.flow_id).await,
        PollResult::Complete
    );
    assert_eq!(first_poll.await.unwrap(), PollResult::Complete);
    assert_eq!(second_poll.await.unwrap(), PollResult::Complete);

    let limits = runtime_limits(2, 3, 10, 10);
    let per_flow_setup = SetupService::new(
        vec!["https://app.example".to_owned()],
        Arc::new(MockCompleter::new([])),
        Arc::new(ManualClock::default()),
        limits,
    );
    let per_flow = per_flow_setup
        .begin(peer(), "https://app.example", "three")
        .await
        .unwrap();
    let poll_one = tokio::spawn({
        let setup = per_flow_setup.clone();
        let id = per_flow.flow_id.clone();
        async move { setup.poll(&id).await }
    });
    let poll_two = tokio::spawn({
        let setup = per_flow_setup.clone();
        let id = per_flow.flow_id.clone();
        async move { setup.poll(&id).await }
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        per_flow_setup.poll(&per_flow.flow_id).await,
        PollResult::Overloaded
    );
    assert_eq!(
        per_flow_setup.trigger_completion(&per_flow.flow_id).await,
        PollResult::Complete
    );
    assert_eq!(poll_one.await.unwrap(), PollResult::Complete);
    assert_eq!(poll_two.await.unwrap(), PollResult::Complete);
}

#[tokio::test]
async fn concurrent_starts_never_exceed_pending_setup_capacity() {
    let entered = Arc::new(AtomicUsize::new(0));
    let changed = Arc::new(Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let setup = limited_service(
        Arc::new(BlockingStartCompleter {
            entered: entered.clone(),
            changed: changed.clone(),
            release: release.clone(),
        }),
        Arc::new(ManualClock::default()),
        100,
        2,
    );
    let mut starts = Vec::new();
    for state in ["one", "two"] {
        let setup = setup.clone();
        starts.push(tokio::spawn(async move {
            setup.begin(peer(), "https://app.example", state).await
        }));
    }
    while entered.load(Ordering::SeqCst) < 2 {
        let notified = changed.notified();
        if entered.load(Ordering::SeqCst) < 2 {
            notified.await;
        }
    }
    assert_eq!(
        setup.begin(peer(), "https://app.example", "three").await,
        Err(BeginError::Unavailable)
    );
    assert_eq!(entered.load(Ordering::SeqCst), 2);
    release.add_permits(2);
    for start in starts {
        assert!(start.await.unwrap().is_ok());
    }
}

#[tokio::test]
async fn setup_policy_uses_transport_ip_and_ignores_forwarded_for() {
    let setup = limited_service(
        Arc::new(MockCompleter::new([])),
        Arc::new(ManualClock::default()),
        1,
        10,
    );
    let router = setup_router(setup);
    let make_request = |peer_ip: IpAddr, forwarded_for: &str, state: &str| {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "/setup?return_to=https://app.example&state={state}"
            ))
            .header("X-Forwarded-For", forwarded_for)
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer_ip, 12345)));
        request
    };
    assert_eq!(
        router
            .clone()
            .oneshot(make_request(peer(), "198.51.100.1", "one"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let limited = router
        .clone()
        .oneshot(make_request(peer(), "203.0.113.2", "two"))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers()["retry-after"], "60");
    assert_eq!(
        router
            .oneshot(make_request(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                "203.0.113.2",
                "three",
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn reservation_releases_after_start_failure_terminal_completion_and_expiry() {
    let failed_start = limited_service(
        Arc::new(FailFirstStartCompleter(AtomicUsize::new(0))),
        Arc::new(ManualClock::default()),
        100,
        1,
    );
    assert_eq!(
        failed_start
            .begin(peer(), "https://app.example", "first")
            .await,
        Err(BeginError::Unavailable)
    );
    assert!(
        failed_start
            .begin(peer(), "https://app.example", "second")
            .await
            .is_ok()
    );

    let clock = Arc::new(ManualClock::default());
    let setup = limited_service(
        Arc::new(MockCompleter::new([Completion::DurableSuccess])),
        clock.clone(),
        100,
        1,
    );
    let completed = setup
        .begin(peer(), "https://app.example", "completed")
        .await
        .unwrap();
    assert_eq!(
        setup.begin(peer(), "https://app.example", "blocked").await,
        Err(BeginError::Unavailable)
    );
    assert_eq!(
        setup.trigger_completion(&completed.flow_id).await,
        PollResult::Complete
    );

    let failed = limited_service(
        Arc::new(MockCompleter::new([Completion::DefinitiveFailure])),
        Arc::new(ManualClock::default()),
        100,
        1,
    );
    let failed_flow = failed
        .begin(peer(), "https://app.example", "failed")
        .await
        .unwrap();
    assert_eq!(
        failed.trigger_completion(&failed_flow.flow_id).await,
        PollResult::Failed
    );
    assert!(
        failed
            .begin(peer(), "https://app.example", "after-failure")
            .await
            .is_ok()
    );

    let expiring = setup
        .begin(peer(), "https://app.example", "expiring")
        .await
        .unwrap();
    clock.advance(Duration::from_secs(300));
    assert!(
        setup
            .begin(peer(), "https://app.example", "after-expiry")
            .await
            .is_ok()
    );
    assert_eq!(setup.poll(&expiring.flow_id).await, PollResult::Expired);
}

#[tokio::test]
async fn cancelling_start_and_completion_releases_reservation() {
    let entered = Arc::new(AtomicUsize::new(0));
    let changed = Arc::new(Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let setup = limited_service(
        Arc::new(BlockingStartCompleter {
            entered: entered.clone(),
            changed: changed.clone(),
            release: release.clone(),
        }),
        Arc::new(ManualClock::default()),
        100,
        1,
    );
    let first = tokio::spawn({
        let setup = setup.clone();
        async move {
            setup
                .begin(peer(), "https://app.example", "cancelled")
                .await
        }
    });
    while entered.load(Ordering::SeqCst) < 1 {
        let notified = changed.notified();
        if entered.load(Ordering::SeqCst) < 1 {
            notified.await;
        }
    }
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let second = tokio::spawn({
        let setup = setup.clone();
        async move {
            setup
                .begin(peer(), "https://app.example", "replacement")
                .await
        }
    });
    while entered.load(Ordering::SeqCst) < 2 {
        let notified = changed.notified();
        if entered.load(Ordering::SeqCst) < 2 {
            notified.await;
        }
    }
    release.add_permits(1);
    assert!(second.await.unwrap().is_ok());

    let completion_entered = Arc::new(Notify::new());
    let setup = limited_service(
        Arc::new(BlockingCompleter {
            entered: completion_entered.clone(),
            release: Arc::new(Notify::new()),
        }),
        Arc::new(ManualClock::default()),
        100,
        1,
    );
    let flow = setup
        .begin(peer(), "https://app.example", "complete")
        .await
        .unwrap();
    let flow_id = flow.flow_id.clone();
    let entered_wait = completion_entered.notified();
    let completion = tokio::spawn({
        let setup = setup.clone();
        let flow_id = flow_id.clone();
        async move { setup.trigger_completion(&flow_id).await }
    });
    entered_wait.await;
    completion.abort();
    assert!(completion.await.unwrap_err().is_cancelled());
    tokio::task::yield_now().await;
    assert_eq!(setup.poll(&flow_id).await, PollResult::Failed);
    assert!(
        setup
            .begin(peer(), "https://app.example", "after-cancel")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn valid_setup_preserves_polling_and_secret_free_callback_shell() {
    let response = request(
        setup_router(service(
            Arc::new(MockCompleter::new([])),
            Arc::new(ManualClock::default()),
        )),
        Method::GET,
        "/setup?return_to=https://app.example/path?x=1&state=%3C%2Fscript%3E%3Cimg%3E",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-security-policy"],
        "frame-ancestors https://app.example"
    );
    let shell = body(response).await;
    assert!(shell.contains("new Set([408,425,429,502,503,504])"));
    assert!(shell.contains("delay=500"));
    assert!(shell.contains("Math.min(delay*2,5000)"));
    assert!(shell.contains("postMessage({type:'paykit-setup-callback',state},targetOrigin)"));
    assert!(shell.contains(
        "postMessage({type:'paykit-setup-callback',state,error:'setup-failed'},targetOrigin)"
    ));
    assert_eq!(shell.matches("postMessage(").count(), 2);
    assert!(!shell.contains("</script><img"));
    assert!(shell.contains("\\u003c/script\\u003e\\u003cimg\\u003e"));

    let script = shell
        .split_once("<script>")
        .expect("setup shell contains polling script")
        .1;
    for forbidden in ["pubkyauth://", "response.json", "response.text", "console."] {
        assert!(
            !script.contains(forbidden),
            "setup script contained forbidden value {forbidden}"
        );
    }
    for forbidden in [
        "xpub",
        "/claim",
        "window.location.assign",
        "location.href",
        "<input",
    ] {
        assert!(
            !shell.contains(forbidden),
            "setup shell contained forbidden value {forbidden}"
        );
    }
}

#[tokio::test]
async fn setup_iframe_displays_escaped_auth_url_and_approved_cli_command() {
    let response = request(
        setup_router(service(
            Arc::new(InstructionCompleter),
            Arc::new(ManualClock::default()),
        )),
        Method::GET,
        "/setup?return_to=https://app.example/callback&state=opaque",
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let shell = body(response).await;
    let (instructions, script) = shell
        .split_once("<script>")
        .expect("setup shell contains polling script");
    assert!(instructions.contains("pubkyauth://signin?secret=mock&amp;label=&lt;approve&gt;"));
    assert!(instructions.contains(
        "href=\"bitkit://pubky-auth/setup?secret=mock&amp;label=&lt;approve&gt;\">Open in Bitkit</a>"
    ));
    assert!(!script.contains("pubkyauth://signin?secret=mock"));
    assert!(!script.contains("bitkit://pubky-auth/setup"));
    assert!(instructions.contains(
        "docker compose exec creator-demo npm --prefix examples/js-sdk run authenticate-paykit -- --role content-creator"
    ));
    assert!(instructions.contains("npm --prefix examples/js-sdk run generate-paykit-account-tpub"));
}

#[tokio::test]
async fn wildcard_setup_policy_uses_the_callers_concrete_origin() {
    let setup = SetupService::with_poll_timeout(
        vec!["*".to_owned()],
        Arc::new(MockCompleter::new([])),
        Arc::new(ManualClock::default()),
        runtime_limits(2, 4, 100, 100),
        Duration::ZERO,
    );
    let response = request(
        setup_router(setup),
        Method::GET,
        "/setup?return_to=https://creator.example/callback&state=opaque",
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-security-policy"],
        "frame-ancestors https://creator.example"
    );
    let shell = body(response).await;
    assert!(shell.contains("targetOrigin=\"https://creator.example\""));
    assert!(!shell.contains("targetOrigin=\"*\""));

    let wildcard = SetupService::with_poll_timeout(
        vec!["*".to_owned()],
        Arc::new(MockCompleter::new([])),
        Arc::new(ManualClock::default()),
        runtime_limits(2, 4, 100, 100),
        Duration::ZERO,
    );
    for return_to in [
        "not a URL",
        "/relative/callback",
        "//creator.example/callback",
        "pubky://creator.example/callback",
        "https://",
        "https://user:password@creator.example/callback",
    ] {
        assert_eq!(
            wildcard.begin(peer(), return_to, "opaque").await,
            Err(BeginError::InvalidRequest),
            "wildcard accepted invalid return_to {return_to:?}"
        );
    }
    let oversized = format!("https://creator.example/{}", "x".repeat(2049));
    assert_eq!(
        wildcard.begin(peer(), &oversized, "opaque").await,
        Err(BeginError::InvalidRequest)
    );
}
