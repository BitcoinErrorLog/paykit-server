use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    routing::get,
};
use paykit_server::runtime::{
    ComponentState, DependencyCheck, ElectrumProbe, PostgresDependency, Runtime,
    operational_router, shutdown_and_drain,
};
use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment, StackRole},
    persistence::StackIdentity,
};
use tower::ServiceExt;

const CONFIG_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const CONFIG_MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn production_config(electrum_endpoint: &str) -> Config {
    let source = format!(
        r#"
[http]
listen_addr = "127.0.0.1:0"
[locks]
trusted_public_key = "{CONFIG_KEY}"
[setup]
allowed_origins = ["https://app.example"]
[paykit]
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
network = "testnet"
[deployment]
stack_role = "proof"
[electrum]
endpoint = "{electrum_endpoint}"
request_timeout = "1s"
connect_retries = 0
[outbox]
poll_interval = "1s"
"#,
    );
    Config::from_toml_and_environment(
        &source,
        ConfigEnvironment {
            database_url: Some("postgres://127.0.0.1:1/paykit".into()),
            master_key: Some(CONFIG_MASTER_KEY.into()),
        },
    )
    .unwrap()
}

fn lazy_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(5))
        .connect_lazy("postgres://127.0.0.1:1/paykit")
        .unwrap()
}

struct Check(AtomicBool);
#[async_trait]
impl DependencyCheck for Check {
    async fn postgres_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
fn runtime(pg: bool, capacity: usize) -> Arc<Runtime> {
    Arc::new(Runtime::new(Arc::new(Check(AtomicBool::new(pg))), capacity))
}

fn test_stack_identity() -> StackIdentity {
    StackIdentity::new(
        StackRole::Proof,
        "6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19".parse().unwrap(),
    )
}

fn fresh_tip_time() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

async fn intentional_panic_handler() -> &'static str {
    panic!("intentional handler panic")
}

#[tokio::test]
async fn task9_components_start_not_ready_until_runtime_evidence_arrives() {
    let runtime = runtime(true, 1);

    let starting = runtime.readiness().await;
    assert_eq!(starting.status, ComponentState::NotReady);
    assert_eq!(starting.electrum, ComponentState::NotReady);
    assert_eq!(starting.paykit_delivery, ComponentState::NotReady);
    assert_eq!(starting.outbox, ComponentState::NotReady);

    runtime.set_electrum_available(true);
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    // Without a fresh probe, worker evidence alone leaves Electrum degraded.
    assert_eq!(runtime.readiness().await.status, ComponentState::Degraded);
    runtime.record_electrum_probe(ElectrumProbe::success(1, fresh_tip_time()));
    assert_eq!(runtime.readiness().await.status, ComponentState::Ready);
}

#[tokio::test]
async fn bitcoin_offer_availability_uses_three_probe_hysteresis() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);

    // Fail-closed from boot: the offer is false before the first probe and
    // turns true only after three consecutive successful probes.
    assert!(!runtime.readiness().await.bitcoin_offer_available);
    runtime.record_electrum_probe_failure();
    runtime.record_electrum_probe_failure();
    assert!(!runtime.readiness().await.bitcoin_offer_available);
    runtime.record_electrum_probe_failure();
    assert!(!runtime.readiness().await.bitcoin_offer_available);

    runtime.record_electrum_probe(ElectrumProbe::success(1, fresh_tip_time()));
    runtime.record_electrum_probe(ElectrumProbe::success(2, fresh_tip_time()));
    assert!(!runtime.readiness().await.bitcoin_offer_available);
    runtime.record_electrum_probe(ElectrumProbe::success(3, fresh_tip_time()));
    assert!(runtime.readiness().await.bitcoin_offer_available);
}

#[tokio::test]
async fn postgres_not_ready_forces_the_offer_off_while_status_is_not_ready() {
    let check = Arc::new(Check(AtomicBool::new(true)));
    let runtime = Arc::new(Runtime::new(check.clone(), 1));
    runtime.set_electrum_available(true);
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    for height in 1..=3 {
        runtime.record_electrum_probe(ElectrumProbe::success(height, fresh_tip_time()));
    }
    assert!(runtime.readiness().await.bitcoin_offer_available);

    // The contract consumer reads only this field, and paykit cannot bind
    // or observe without postgres: the offer folds postgres in.
    check.0.store(false, Ordering::Release);
    let report = runtime.readiness().await;
    assert_eq!(report.status, ComponentState::NotReady);
    assert_eq!(report.postgres, ComponentState::NotReady);
    assert!(!report.bitcoin_offer_available);
}

#[tokio::test]
async fn electrum_readiness_requires_a_fresh_chain_tip_unless_the_check_is_skipped() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    // A tip from 2020 is far older than the default four-hour maximum: the
    // endpoint's chain view cannot be trusted, so readiness fails closed.
    runtime.record_electrum_probe(ElectrumProbe::success(1, 1_600_000_000));
    let report = runtime.readiness().await;
    assert!(!report.electrum_probe.available);
    assert_eq!(report.electrum, ComponentState::NotReady);

    // Regtest deployments skip the tip checks: blocks are mined on
    // demand, so an arbitrarily old tip says nothing about endpoint health.
    runtime.set_electrum_max_tip_age(None);
    let report = runtime.readiness().await;
    assert!(report.electrum_probe.available);
    assert_eq!(report.electrum, ComponentState::Ready);
}

#[tokio::test]
async fn a_stale_tip_fails_readiness_closed_with_http_503() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    runtime.record_electrum_probe(ElectrumProbe::success(800_000, 1_600_000_000));
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    let app = operational_router(Router::new(), runtime);

    let ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(ready.into_body(), 1024).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["status"], "not_ready");
    assert_eq!(parsed["electrum"]["state"], "not_ready");
    assert_eq!(parsed["electrum"]["available"], false);
    assert_eq!(parsed["bitcoin_offer_available"], false);
}

#[tokio::test]
async fn a_tip_height_regression_within_the_reorg_tolerance_is_degraded_not_503() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    for _ in 0..3 {
        runtime.record_electrum_probe(ElectrumProbe::success(800_000, fresh_tip_time()));
    }
    let report = runtime.readiness().await;
    assert_eq!(report.status, ComponentState::Ready);
    assert!(report.bitcoin_offer_available);

    // A one-block-lagging backend of a pool-balanced endpoint is a
    // degraded (HTTP 200) condition, not a fleet-wide 503.
    for lagging_height in [799_999, 799_994] {
        runtime.record_electrum_probe(ElectrumProbe::success(lagging_height, fresh_tip_time()));
        let report = runtime.readiness().await;
        assert!(!report.electrum_probe.available);
        assert_eq!(report.electrum, ComponentState::Degraded);
        assert_eq!(report.status, ComponentState::Degraded);
        assert!(!report.bitcoin_offer_available);
    }
    let app = operational_router(Router::new(), runtime.clone());
    let ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);

    // The tip catches back up to the previous maximum: readiness recovers.
    for _ in 0..3 {
        runtime.record_electrum_probe(ElectrumProbe::success(800_000, fresh_tip_time()));
    }
    let report = runtime.readiness().await;
    assert_eq!(report.status, ComponentState::Ready);
    assert!(report.bitcoin_offer_available);
}

#[tokio::test]
async fn a_tip_height_regression_beyond_the_reorg_tolerance_fails_closed_until_recovery() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    for _ in 0..3 {
        runtime.record_electrum_probe(ElectrumProbe::success(800_000, fresh_tip_time()));
    }
    assert_eq!(runtime.readiness().await.status, ComponentState::Ready);

    // Seven blocks below the observed maximum exceeds the reorg tolerance:
    // the endpoint's chain view cannot be trusted, so readiness fails
    // closed (503) until the chain exceeds the previous maximum.
    runtime.record_electrum_probe(ElectrumProbe::success(799_993, fresh_tip_time()));
    let report = runtime.readiness().await;
    assert!(!report.electrum_probe.available);
    assert_eq!(report.electrum, ComponentState::NotReady);
    assert_eq!(report.status, ComponentState::NotReady);
    assert!(!report.bitcoin_offer_available);
    let app = operational_router(Router::new(), runtime.clone());
    let ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);

    // The regression stays visible while the tip remains beyond the
    // tolerance below the previously observed maximum.
    runtime.record_electrum_probe(ElectrumProbe::success(799_993, fresh_tip_time()));
    assert_eq!(runtime.readiness().await.electrum, ComponentState::NotReady);
    for _ in 0..3 {
        runtime.record_electrum_probe(ElectrumProbe::success(800_001, fresh_tip_time()));
    }
    assert_eq!(runtime.readiness().await.status, ComponentState::Ready);
}

#[tokio::test]
async fn a_stalled_tip_height_fails_readiness_closed() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    runtime.set_electrum_max_tip_age(Some(Duration::from_millis(1_100)));
    runtime.record_electrum_probe(ElectrumProbe::success(800_000, fresh_tip_time()));
    assert_eq!(runtime.readiness().await.status, ComponentState::Ready);

    // No new block within the accepted tip-age window: the chain view is
    // not advancing, so the endpoint cannot be trusted.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    runtime.record_electrum_probe(ElectrumProbe::success(800_000, fresh_tip_time()));
    let report = runtime.readiness().await;
    assert!(!report.electrum_probe.available);
    assert_eq!(report.electrum, ComponentState::NotReady);

    // The next advance restores readiness.
    runtime.record_electrum_probe(ElectrumProbe::success(800_001, fresh_tip_time()));
    assert_eq!(runtime.readiness().await.status, ComponentState::Ready);
}

#[tokio::test]
async fn a_far_future_tip_time_is_degraded_without_failing_closed() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    // Three hours ahead exceeds Bitcoin's MAX_FUTURE_BLOCK_TIME: the
    // peer's clock cannot be trusted, a 200-degraded condition.
    runtime.record_electrum_probe(ElectrumProbe::success(
        800_000,
        fresh_tip_time() + 3 * 60 * 60,
    ));
    let report = runtime.readiness().await;
    assert!(!report.electrum_probe.available);
    assert_eq!(report.electrum, ComponentState::Degraded);
    assert_eq!(report.status, ComponentState::Degraded);
}

#[tokio::test]
async fn task9_cancelled_request_releases_admission_for_shutdown_drain() {
    let runtime = runtime(true, 1);
    let entered = Arc::new(tokio::sync::Notify::new());
    let handler_entered = entered.clone();
    let app = operational_router(
        Router::new().route(
            "/work",
            get(move || {
                let entered = handler_entered.clone();
                async move {
                    entered.notify_one();
                    std::future::pending::<()>().await;
                }
            }),
        ),
        runtime.clone(),
    );
    let request = tokio::spawn(app.oneshot(Request::get("/work").body(Body::empty()).unwrap()));
    entered.notified().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());

    assert!(shutdown_and_drain(&runtime, Duration::from_millis(10)).await);
}

#[tokio::test]
async fn task9_panicking_request_releases_admission_for_shutdown_drain() {
    let runtime = runtime(true, 1);
    let app = operational_router(
        Router::new().route("/panic", get(intentional_panic_handler)),
        runtime.clone(),
    );

    let request = tokio::spawn(app.oneshot(Request::get("/panic").body(Body::empty()).unwrap()));
    assert!(request.await.unwrap_err().is_panic());
    assert!(shutdown_and_drain(&runtime, Duration::from_millis(10)).await);
}

#[tokio::test]
async fn health_schemas_and_status_codes_are_secret_free() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    for _ in 0..3 {
        runtime.record_electrum_probe(ElectrumProbe::success(800_000, fresh_tip_time()));
    }
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    let app = operational_router(Router::new(), runtime);
    let live = app
        .clone()
        .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(live.into_body(), 1024).await.unwrap(),
        "{\"status\":\"live\"}"
    );
    let ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);
    let body = to_bytes(ready.into_body(), 1024).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["status"], "ready");
    assert_eq!(parsed["postgres"], "ready");
    assert_eq!(parsed["bitcoin_offer_available"], true);
    assert_eq!(parsed["electrum_tip_height"], 800_000);
    assert!(parsed["electrum_tip_age_seconds"].as_u64().is_some());
    assert_eq!(parsed["paykit_delivery"], "ready");
    assert_eq!(parsed["outbox"], "ready");
    let electrum = &parsed["electrum"];
    assert_eq!(electrum["state"], "ready");
    assert_eq!(electrum["available"], true);
    assert_eq!(electrum["tip_height"], 800_000);
    assert_eq!(electrum["genesis_ok"], true);
    assert!(electrum["tip_age_secs"].as_u64().is_some());
    assert!(electrum["last_probe_at"].as_u64().is_some());
}

#[tokio::test]
async fn health_ready_reports_the_stack_id_regardless_of_status() {
    // Ready and not-ready stacks must both say who they are: the stack_id is
    // the reference value the marketplace's resolution arm compares its
    // pinned outbox row against.
    let ready_runtime = runtime(true, 1);
    ready_runtime.set_stack_id(test_stack_identity().stack_id());
    ready_runtime.set_electrum_available(true);
    for _ in 0..3 {
        ready_runtime.record_electrum_probe(ElectrumProbe::success(800_000, fresh_tip_time()));
    }
    ready_runtime.set_paykit_delivery_available(true);
    ready_runtime.set_outbox_available(true);
    let app = operational_router(Router::new(), ready_runtime);
    let ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);
    let body = to_bytes(ready.into_body(), 1024).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["stack_id"],
        "proof:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19"
    );

    let not_ready_runtime = runtime(false, 1);
    not_ready_runtime.set_stack_id(test_stack_identity().stack_id());
    let app = operational_router(Router::new(), not_ready_runtime);
    let not_ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(not_ready.into_body(), 1024).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["stack_id"], "proof:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19",
        "a degraded stack must still say who it is"
    );
}

#[tokio::test]
async fn health_reports_electrum_unavailable_without_a_fresh_probe() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    runtime.record_electrum_probe(ElectrumProbe::genesis_mismatch());
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);

    let report = runtime.readiness().await;
    assert_eq!(report.electrum, ComponentState::Degraded);
    assert!(!report.electrum_probe.available);
    assert!(!report.electrum_probe.genesis_ok);
    assert!(report.electrum_probe.last_probe_at.is_some());
}

#[tokio::test]
async fn creation_kill_switch_only_changes_offer_field() {
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(true);
    for _ in 0..3 {
        runtime.record_electrum_probe(ElectrumProbe::success(800_000, fresh_tip_time()));
    }
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    let before = runtime.readiness().await;
    assert!(before.bitcoin_offer_available);
    runtime.set_bitcoin_creation_enabled(false);
    let after = runtime.readiness().await;
    assert_eq!(after.status, before.status);
    assert_eq!(after.electrum, before.electrum);
    assert!(!after.bitcoin_offer_available);

    let app = operational_router(Router::new(), runtime);
    let ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);
    let body = to_bytes(ready.into_body(), 1024).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["status"], "ready");
    assert_eq!(parsed["electrum"]["state"], "ready");
    assert_eq!(parsed["bitcoin_offer_available"], false);
}

#[tokio::test]
async fn health_tip_fields_are_null_before_the_first_probe() {
    let runtime = runtime(true, 1);
    let app = operational_router(Router::new(), runtime);
    let ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = to_bytes(ready.into_body(), 1024).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed["electrum_tip_height"].is_null());
    assert!(parsed["electrum_tip_age_seconds"].is_null());
}

#[tokio::test]
async fn postgres_failure_is_not_ready_and_workers_are_only_degraded() {
    let unavailable = runtime(false, 1);
    assert_eq!(
        unavailable.readiness().await.status,
        ComponentState::NotReady
    );
    let unreachable_pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(5))
        .connect_lazy("postgres://127.0.0.1:1/paykit")
        .unwrap();
    let actual_postgres_check = Arc::new(Runtime::new(
        Arc::new(PostgresDependency::new(unreachable_pool)),
        1,
    ));
    assert_eq!(
        actual_postgres_check.readiness().await.status,
        ComponentState::NotReady
    );
    let runtime = runtime(true, 1);
    runtime.set_electrum_available(false);
    runtime.set_paykit_delivery_available(false);
    runtime.set_outbox_available(false);
    let report = runtime.readiness().await;
    assert_eq!(report.status, ComponentState::Degraded);
    assert_eq!(report.postgres, ComponentState::Ready);
    assert!(runtime.may_start_worker_claim());
}

#[tokio::test]
async fn capacity_is_503_but_existing_auth_policy_429_is_unchanged() {
    let runtime = runtime(true, 1);
    let release = Arc::new(tokio::sync::Notify::new());
    let handler_release = release.clone();
    let app = operational_router(
        Router::new().route(
            "/work",
            get(move || {
                let release = handler_release.clone();
                async move {
                    release.notified().await;
                    "ok"
                }
            }),
        ),
        runtime,
    );
    let first = tokio::spawn(
        app.clone()
            .oneshot(Request::get("/work").body(Body::empty()).unwrap()),
    );
    tokio::task::yield_now().await;
    let overloaded = app
        .clone()
        .oneshot(Request::get("/work").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(overloaded.headers()["retry-after"], "1");
    release.notify_waiters();
    assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
    let live = app
        .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::OK);
}

#[tokio::test]
async fn shutdown_changes_readiness_before_worker_claims_and_drains() {
    let runtime = runtime(true, 1);
    let app = operational_router(
        Router::new().route("/work", get(|| async { "ok" })),
        runtime.clone(),
    );
    assert!(runtime.may_start_worker_claim());
    assert!(shutdown_and_drain(&runtime, Duration::from_millis(10)).await);
    assert_eq!(runtime.readiness().await.status, ComponentState::NotReady);
    assert!(!runtime.may_start_worker_claim());
    assert_eq!(
        app.oneshot(Request::get("/work").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn metrics_have_no_user_controlled_labels_or_identifiers() {
    let runtime = runtime(true, 1);
    let app = operational_router(Router::new(), runtime);
    let response = app
        .oneshot(
            Request::get("/metrics?creator=secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let text = String::from_utf8(
        to_bytes(response.into_body(), 32 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(text.contains("paykit_http_requests"));
    assert!(!text.contains("creator"));
    assert!(!text.contains("secret"));
    assert!(!text.contains("creator="));
}

#[tokio::test]
async fn production_constructor_mounts_all_routes() {
    let server = Server::build(
        production_config("tcp://127.0.0.1:1"),
        lazy_pool(),
        test_stack_identity(),
    )
    .await
    .unwrap();
    let app = server.router();
    for (request, expected) in [
        (
            Request::delete("/setup").body(Body::empty()).unwrap(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Request::post("/invoices").body(Body::empty()).unwrap(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Request::post("/transactions/status")
                .body(Body::empty())
                .unwrap(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Request::delete("/health/ready")
                .body(Body::empty())
                .unwrap(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Request::get("/health/live").body(Body::empty()).unwrap(),
            StatusCode::OK,
        ),
        (
            Request::get("/metrics").body(Body::empty()).unwrap(),
            StatusCode::OK,
        ),
    ] {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }
}

#[tokio::test]
async fn production_constructor_allows_electrum_to_be_temporarily_unavailable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
    drop(listener);
    assert!(
        Server::build(
            production_config(&endpoint),
            lazy_pool(),
            test_stack_identity()
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn production_constructor_rejects_malformed_electrum_adapter_configuration() {
    assert!(
        Server::build(
            production_config("https://electrum.example:50002/path?token=secret"),
            lazy_pool(),
            test_stack_identity(),
        )
        .await
        .is_err()
    );
}
