use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::post,
};
use paykit_server::{
    http::error::ApiError,
    runtime::{DependencyCheck, Runtime, operational_router},
};
use tower::ServiceExt;
use tracing::{Event, Subscriber, instrument::WithSubscriber};
use tracing_subscriber::{Layer, layer::Context, prelude::*};
use uuid::{Uuid, Version};

const REQUEST_ID_HEADER: &str = "x-request-id";

type CapturedEvents = Vec<Vec<(String, String)>>;

#[derive(Clone, Default)]
struct EventCapture(Arc<Mutex<CapturedEvents>>);

impl<S> Layer<S> for EventCapture
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = Vec::new();
        event.record(&mut FieldVisitor(&mut fields));
        self.0.lock().unwrap().push(fields);
    }
}

struct FieldVisitor<'a>(&'a mut Vec<(String, String)>);

impl tracing::field::Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }
}

impl EventCapture {
    fn invoice_events(&self) -> Vec<Vec<(String, String)>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|fields| field(fields, "event") == Some("paykit_invoice_outcome"))
            .cloned()
            .collect()
    }
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value.trim_matches('"'))
}

struct ReadyDependency;

#[async_trait]
impl DependencyCheck for ReadyDependency {
    async fn postgres_ready(&self) -> bool {
        true
    }
}

fn runtime() -> Arc<Runtime> {
    Arc::new(Runtime::new(Arc::new(ReadyDependency), 1))
}

fn request(request_id: &str) -> Request<Body> {
    request_for("/invoices", request_id)
}

fn request_for(path: &str, request_id: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(REQUEST_ID_HEADER, request_id)
        .body(Body::empty())
        .unwrap()
}

async fn intentional_panic_handler() -> StatusCode {
    panic!("intentional handler panic")
}

#[tokio::test]
async fn cancelled_status_request_emits_one_safe_event_without_fabricated_response() {
    let request_id = "d9428888-122b-4b85-bc8f-2c2e0bf7c874";
    let entered = Arc::new(tokio::sync::Notify::new());
    let handler_entered = entered.clone();
    let capture = EventCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let router = operational_router(
        Router::new().route(
            "/payment-requests/status",
            post(move || {
                let entered = handler_entered.clone();
                async move {
                    entered.notify_one();
                    std::future::pending::<StatusCode>().await
                }
            }),
        ),
        runtime(),
    );

    let _subscriber_guard = tracing::subscriber::set_default(subscriber);
    let request = tokio::spawn(router.oneshot(request_for("/payment-requests/status", request_id)));
    entered.notified().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());

    let events = capture.0.lock().unwrap();
    let events = events
        .iter()
        .filter(|fields| field(fields, "event") == Some("paykit_locks_status_outcome"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    let event = events[0];
    assert_eq!(field(event, "operation"), Some("payment_request_status"));
    assert_eq!(field(event, "failure_class"), Some("cancelled"));
    assert_eq!(field(event, "request_id"), Some(request_id));
    assert!(field(event, "elapsed_ms").unwrap().parse::<u64>().is_ok());
    assert_eq!(field(event, "http_status"), None);
    assert!(event.iter().all(|(name, _)| {
        matches!(
            name.as_str(),
            "message" | "event" | "operation" | "failure_class" | "elapsed_ms" | "request_id"
        )
    }));
}

#[tokio::test]
async fn panicking_invoice_request_emits_one_safe_event_without_fabricated_response() {
    let request_id = "d9428888-122b-4b85-bc8f-2c2e0bf7c874";
    let capture = EventCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let router = operational_router(
        Router::new().route("/invoices", post(intentional_panic_handler)),
        runtime(),
    );

    let request = tokio::spawn(
        router
            .oneshot(request(request_id))
            .with_subscriber(subscriber),
    );
    assert!(request.await.unwrap_err().is_panic());

    let events = capture.invoice_events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(field(event, "failure_class"), Some("cancelled"));
    assert_eq!(field(event, "request_id"), Some(request_id));
    assert!(field(event, "elapsed_ms").unwrap().parse::<u64>().is_ok());
    assert_eq!(field(event, "http_status"), None);
    assert_eq!(field(event, "operation"), None);
    assert!(event.iter().all(|(name, _)| {
        matches!(
            name.as_str(),
            "message" | "event" | "failure_class" | "elapsed_ms" | "request_id"
        )
    }));
}

#[tokio::test]
async fn typed_invoice_failure_emits_one_safe_event_without_changing_response() {
    let request_id = "d9428888-122b-4b85-bc8f-2c2e0bf7c874";
    let error = ApiError::CreatorSessionUnavailable;
    let capture = EventCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let router = operational_router(
        Router::new().route("/invoices", post(move || async move { error })),
        runtime(),
    );
    let expected = error.into_response();
    let expected_headers = expected.headers().clone();
    let expected_body = to_bytes(expected.into_body(), 4096).await.unwrap();

    let response = router
        .oneshot(request(request_id))
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers().get("retry-after"),
        expected_headers.get("retry-after")
    );
    assert_eq!(response.headers()[REQUEST_ID_HEADER], request_id);
    assert_eq!(
        to_bytes(response.into_body(), 4096).await.unwrap(),
        expected_body
    );

    let events = capture.invoice_events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(field(event, "http_status"), Some("503"));
    assert_eq!(
        field(event, "failure_class"),
        Some("creator_session_unavailable")
    );
    assert_eq!(field(event, "request_id"), Some(request_id));
    assert!(field(event, "elapsed_ms").unwrap().parse::<u64>().is_ok());
    assert!(event.iter().all(|(name, _)| {
        matches!(
            name.as_str(),
            "message" | "event" | "http_status" | "failure_class" | "elapsed_ms" | "request_id"
        )
    }));
}

#[tokio::test]
async fn shutdown_503_rejects_unsafe_request_id_without_echo_or_log() {
    let unsafe_value = "secret-identity-and-query-data";
    let runtime = runtime();
    runtime.begin_shutdown();
    let capture = EventCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let router = operational_router(
        Router::new().route("/invoices", post(|| async { StatusCode::OK })),
        runtime,
    );

    let response = router
        .oneshot(request(unsafe_value))
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
    let response_id = response.headers()[REQUEST_ID_HEADER]
        .to_str()
        .unwrap()
        .to_owned();
    let parsed = Uuid::parse_str(&response_id).unwrap();
    assert_eq!(parsed.get_version(), Some(Version::Random));
    assert_ne!(response_id, unsafe_value);
    assert!(to_bytes(response.into_body(), 1).await.unwrap().is_empty());

    let events = capture.invoice_events();
    assert_eq!(events.len(), 1);
    assert_eq!(field(&events[0], "failure_class"), Some("shutdown"));
    assert_eq!(field(&events[0], "request_id"), Some(response_id.as_str()));
    assert!(!format!("{events:?}").contains(unsafe_value));
}
