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
    ComponentState, DependencyCheck, PostgresDependency, Runtime, operational_router,
    shutdown_and_drain,
};
use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment, ConfigError},
};
use tower::ServiceExt;
use tracing::{Event, Subscriber, instrument::WithSubscriber};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

const CONFIG_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const CONFIG_MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn production_config(electrum_endpoint: &str) -> Config {
    production_config_with_setup_logging(electrum_endpoint, false)
}

fn production_config_with_setup_logging(
    electrum_endpoint: &str,
    log_authorization_url: bool,
) -> Config {
    try_production_config_with_setup_logging(electrum_endpoint, log_authorization_url).unwrap()
}

fn try_production_config_with_setup_logging(
    electrum_endpoint: &str,
    log_authorization_url: bool,
) -> Result<Config, ConfigError> {
    let source = format!(
        r#"
[http]
listen_addr = "127.0.0.1:0"
[locks]
trusted_public_key = "{CONFIG_KEY}"
[setup]
allowed_origins = ["https://app.example"]
log_authorization_url = {log_authorization_url}
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "testnet"
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
}

fn lazy_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(5))
        .connect_lazy("postgres://127.0.0.1:1/paykit")
        .unwrap()
}

type CapturedSetupEventFields = Vec<Vec<(String, String)>>;

#[derive(Clone, Default)]
struct SetupEventCapture(Arc<std::sync::Mutex<CapturedSetupEventFields>>);

impl<S> Layer<S> for SetupEventCapture
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = Vec::new();
        event.record(&mut RuntimeFieldVisitor(&mut fields));
        self.0.lock().unwrap().push(fields);
    }
}

impl SetupEventCapture {
    fn authorization_url_event_count(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|fields| {
                fields.iter().any(|(name, value)| {
                    name == "event" && value.contains("paykit_setup_authorization_url")
                })
            })
            .count()
    }
}

struct RuntimeFieldVisitor<'a>(&'a mut Vec<(String, String)>);

impl tracing::field::Visit for RuntimeFieldVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }
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
    assert_eq!(runtime.readiness().await.status, ComponentState::Ready);
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
    assert_eq!(
        to_bytes(ready.into_body(), 1024).await.unwrap(),
        "{\"status\":\"ready\",\"postgres\":\"ready\",\"electrum\":\"ready\",\"paykit_delivery\":\"ready\",\"outbox\":\"ready\"}"
    );
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
async fn production_constructor_propagates_setup_authorization_url_logging_config() {
    for (enabled, expected_count) in [(false, 0), (true, 1)] {
        let server = Server::build(
            production_config_with_setup_logging("tcp://127.0.0.1:1", enabled),
            lazy_pool(),
        )
        .await
        .unwrap();
        let capture = SetupEventCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let mut request = Request::get(
            "/setup?return_to=https://app.example/callback&state=production-propagation",
        )
        .body(Body::empty())
        .unwrap();
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
        ));

        let response = server
            .router()
            .oneshot(request)
            .with_subscriber(subscriber)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(capture.authorization_url_event_count(), expected_count);
    }
}

#[tokio::test]
async fn production_constructor_mounts_all_routes() {
    let server = Server::build(production_config("tcp://127.0.0.1:1"), lazy_pool())
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
            Request::post("/connections/status")
                .body(Body::empty())
                .unwrap(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Request::post("/transactions/status")
                .body(Body::empty())
                .unwrap(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Request::post("/setup/status").body(Body::empty()).unwrap(),
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
        Server::build(production_config(&endpoint), lazy_pool())
            .await
            .is_ok()
    );
}

#[test]
fn config_rejects_malformed_electrum_adapter_configuration_before_server_construction() {
    assert!(matches!(
        try_production_config_with_setup_logging(
            "https://electrum.example:50002/path?token=secret",
            false,
        ),
        Err(ConfigError::InvalidElectrumEndpoint)
    ));
}
