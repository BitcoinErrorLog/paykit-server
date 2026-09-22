use std::{
    any::Any,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode},
};
use paykit_server::http::setup::setup_router;
use paykit_server::setup::{
    CancellationStore, Completion, ManualClock, PostgresCancellationStore, SetupAttempt,
    SetupCompleter, SetupLimits, SetupService, StartedSetup,
};
use paykit_server_e2e::postgres::TestDatabase;
use tower::ServiceExt;

const CREATOR: &str = "tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

struct Attempt;

impl SetupAttempt for Attempt {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

struct Completer;

#[async_trait]
impl SetupCompleter for Completer {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        Ok(StartedSetup::new(
            "https://bitkit.example/auth".into(),
            Box::new(Attempt),
        ))
    }

    async fn complete(
        &self,
        _attempt: Box<dyn SetupAttempt>,
        _expected_creator: &paykit_sdk::PubkyPublicKey,
    ) -> Completion {
        Completion::DurableSuccess
    }
}

struct TrackedAttempt {
    drops: Arc<AtomicUsize>,
}

impl Drop for TrackedAttempt {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl SetupAttempt for TrackedAttempt {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

struct TrackingCompleter {
    drops: Arc<AtomicUsize>,
}

#[async_trait]
impl SetupCompleter for TrackingCompleter {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        Ok(StartedSetup::new(
            "https://bitkit.example/auth".into(),
            Box::new(TrackedAttempt {
                drops: self.drops.clone(),
            }),
        ))
    }

    async fn complete(
        &self,
        _attempt: Box<dyn SetupAttempt>,
        _expected_creator: &paykit_sdk::PubkyPublicKey,
    ) -> Completion {
        Completion::DurableSuccess
    }
}

fn service(store: Arc<dyn CancellationStore>) -> SetupService {
    SetupService::with_cancellation_store(
        vec!["https://app.example".into()],
        Arc::new(Completer),
        Arc::new(ManualClock::default()),
        SetupLimits {
            max_polls_per_flow: 2,
            max_polls: 2,
            setup_per_ip_per_minute: 10,
            max_pending_setup_flows: 2,
            claim_identity_per_second: SetupLimits::generous_claim_for_tests().0,
            claim_identity_burst: SetupLimits::generous_claim_for_tests().1,
            claim_ip_per_second: SetupLimits::generous_claim_for_tests().2,
            claim_ip_burst: SetupLimits::generous_claim_for_tests().3,
            claim_limiter_max_entries: SetupLimits::TEST_MAX_ENTRIES,
            claim_limiter_idle_ttl: SetupLimits::test_idle_ttl(),
            claim_ip_ipv4_prefix: SetupLimits::TEST_IPV4_PREFIX,
            claim_ip_ipv6_prefix: SetupLimits::TEST_IPV6_PREFIX,
            trusted_proxy_hops: 0,
        },
        store,
    )
}

fn tracked_service(store: Arc<dyn CancellationStore>, drops: Arc<AtomicUsize>) -> SetupService {
    SetupService::with_cancellation_store(
        vec!["https://app.example".into()],
        Arc::new(TrackingCompleter { drops }),
        Arc::new(ManualClock::default()),
        SetupLimits {
            max_polls_per_flow: 2,
            max_polls: 2,
            setup_per_ip_per_minute: 10,
            max_pending_setup_flows: 1,
            claim_identity_per_second: SetupLimits::generous_claim_for_tests().0,
            claim_identity_burst: SetupLimits::generous_claim_for_tests().1,
            claim_ip_per_second: SetupLimits::generous_claim_for_tests().2,
            claim_ip_burst: SetupLimits::generous_claim_for_tests().3,
            claim_limiter_max_entries: SetupLimits::TEST_MAX_ENTRIES,
            claim_limiter_idle_ttl: SetupLimits::test_idle_ttl(),
            claim_ip_ipv4_prefix: SetupLimits::TEST_IPV4_PREFIX,
            claim_ip_ipv6_prefix: SetupLimits::TEST_IPV6_PREFIX,
            trusted_proxy_hops: 0,
        },
        store,
    )
}

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

async fn cancel_http(
    router: axum::Router,
    flow_id: &str,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/setup/{flow_id}/cancel"))
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(peer(), 12345)));
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body =
        String::from_utf8(to_bytes(response.into_body(), 4096).await.unwrap().to_vec()).unwrap();
    (status, body, headers)
}

#[tokio::test]
async fn postgres_cancellation_is_durable_idempotent_and_preserves_completed_flow() {
    let database = TestDatabase::create().await;
    paykit_server::persistence::run_migrations(database.pool())
        .await
        .unwrap();
    let store: Arc<dyn CancellationStore> =
        Arc::new(PostgresCancellationStore::new(database.pool().clone()));
    let setup = service(store);
    let pending = setup
        .begin(peer(), "https://app.example", "pending", CREATOR)
        .await
        .unwrap();

    assert_eq!(
        setup.cancel(peer(), &pending.flow_id).await,
        paykit_server::setup::CancelResult::Cancelled
    );
    let tombstones: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM setup_flow_cancellations WHERE flow_id = $1")
            .bind(&pending.flow_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(tombstones, 1);
    assert_eq!(
        setup.cancel(peer(), &pending.flow_id).await,
        paykit_server::setup::CancelResult::Cancelled
    );

    let completed = setup
        .begin(peer(), "https://app.example", "completed", CREATOR)
        .await
        .unwrap();
    assert_eq!(
        setup.trigger_completion(&completed.flow_id).await,
        paykit_server::setup::PollResult::Complete
    );
    assert_eq!(
        setup.cancel(peer(), &completed.flow_id).await,
        paykit_server::setup::CancelResult::Complete
    );
    database.cleanup().await;
}

#[tokio::test]
async fn cancel_http_route_persists_tombstone_and_maps_closed_outcomes() {
    let database = TestDatabase::create().await;
    paykit_server::persistence::run_migrations(database.pool())
        .await
        .unwrap();
    let store: Arc<dyn CancellationStore> =
        Arc::new(PostgresCancellationStore::new(database.pool().clone()));
    let setup = service(store);
    let pending = setup
        .begin(peer(), "https://app.example", "pending-http", CREATOR)
        .await
        .unwrap();
    let (status, body, headers) = cancel_http(setup_router(setup.clone()), &pending.flow_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"status":"cancelled"}"#);
    assert_eq!(headers["cache-control"], "no-store");
    let stored: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM setup_flow_cancellations WHERE flow_id = $1")
            .bind(&pending.flow_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(stored, 1);
    assert_eq!(
        cancel_http(setup_router(setup.clone()), &pending.flow_id)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        cancel_http(setup_router(setup.clone()), "wrong-capability")
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    let completed = setup
        .begin(peer(), "https://app.example", "completed-http", CREATOR)
        .await
        .unwrap();
    assert_eq!(
        setup.trigger_completion(&completed.flow_id).await,
        paykit_server::setup::PollResult::Complete
    );
    assert_eq!(
        cancel_http(setup_router(setup), &completed.flow_id).await.0,
        StatusCode::CONFLICT
    );
    database.cleanup().await;
}

#[tokio::test]
async fn non_owning_replica_retries_until_owner_releases_secret_and_capacity() {
    let database = TestDatabase::create().await;
    paykit_server::persistence::run_migrations(database.pool())
        .await
        .unwrap();
    let owner_store: Arc<dyn CancellationStore> =
        Arc::new(PostgresCancellationStore::new(database.pool().clone()));
    let replica_store: Arc<dyn CancellationStore> =
        Arc::new(PostgresCancellationStore::new(database.pool().clone()));
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = tracked_service(owner_store.clone(), drops.clone());
    let non_owner = service(replica_store);
    let pending = owner
        .begin(peer(), "https://app.example", "pending-replica", CREATOR)
        .await
        .unwrap();

    // Reproduce the owner's persist-before-release window using the real
    // shared Postgres store while its secret-bearing flow remains local.
    owner_store.record(&pending.flow_id).await.unwrap();
    let (status, body, headers) = cancel_http(setup_router(non_owner), &pending.flow_id).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, r#"{"error":"unavailable"}"#);
    assert_eq!(headers["retry-after"], "1");
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(owner.flow(&pending.flow_id).await.is_some());
    assert!(matches!(
        owner
            .begin(peer(), "https://app.example", "capacity-held", CREATOR)
            .await,
        Err(paykit_server::setup::BeginError::Unavailable)
    ));

    let (status, body, _) = cancel_http(setup_router(owner.clone()), &pending.flow_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"status":"cancelled"}"#);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(owner.flow(&pending.flow_id).await.is_none());
    owner
        .begin(peer(), "https://app.example", "capacity-released", CREATOR)
        .await
        .expect("owner cancellation releases the pending-flow permit");

    database.cleanup().await;
}
