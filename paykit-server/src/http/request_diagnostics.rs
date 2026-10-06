use std::time::Instant;

use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use uuid::{Uuid, Version};

use super::error::ApiError;

pub(crate) const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone, Copy, Debug)]
pub(crate) struct OutcomeFailureClass(&'static str);

impl OutcomeFailureClass {
    pub(crate) const OVERLOAD: Self = Self("overload");
    pub(crate) const SHUTDOWN: Self = Self("shutdown");

    pub(crate) const fn api(error: ApiError) -> Self {
        Self(error.code())
    }

    const fn as_str(self) -> &'static str {
        self.0
    }
}

pub(crate) fn annotate(response: &mut Response, class: OutcomeFailureClass) {
    response.extensions_mut().insert(class);
}

#[derive(Clone, Copy)]
struct DiagnosedRoute {
    event: &'static str,
    operation: Option<&'static str>,
    source_operation: &'static str,
    frequent_poll: bool,
}

struct RequestOutcomeGuard {
    route: DiagnosedRoute,
    started: Instant,
    request_id: Uuid,
    armed: bool,
}

impl RequestOutcomeGuard {
    fn new(route: DiagnosedRoute, started: Instant, request_id: Uuid) -> Self {
        Self {
            route,
            started,
            request_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RequestOutcomeGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let route = self.route;
        let elapsed_ms = elapsed_ms(self.started);
        let request_id = self.request_id;
        let panicking = std::thread::panicking();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            emit_incomplete(route, elapsed_ms, request_id, panicking);
        }));
    }
}

fn diagnosed_route(request: &Request<Body>) -> Option<DiagnosedRoute> {
    if request.method() != Method::POST {
        return None;
    }
    match request.uri().path() {
        "/invoices" => Some(DiagnosedRoute {
            event: "paykit_invoice_outcome",
            operation: None,
            source_operation: "invoice_create",
            frequent_poll: false,
        }),
        "/payment-requests/status" => Some(DiagnosedRoute {
            event: "paykit_locks_status_outcome",
            operation: Some("payment_request_status"),
            source_operation: "payment_request_status",
            frequent_poll: true,
        }),
        "/connections/status" => Some(DiagnosedRoute {
            event: "paykit_locks_status_outcome",
            operation: Some("connection_status"),
            source_operation: "connection_status",
            frequent_poll: true,
        }),
        "/setup/status" => Some(DiagnosedRoute {
            event: "paykit_locks_status_outcome",
            operation: Some("setup_status"),
            source_operation: "setup_status",
            frequent_poll: true,
        }),
        _ => None,
    }
}

pub(crate) async fn middleware(request: Request<Body>, next: Next) -> Response {
    let Some(route) = diagnosed_route(&request) else {
        return next.run(request).await;
    };

    let started = Instant::now();
    let request_id = accepted_request_id(request.headers()).unwrap_or_else(Uuid::new_v4);
    let mut outcome_guard = RequestOutcomeGuard::new(route, started, request_id);
    let (mut response, source_failure) =
        crate::diagnostics::scope(request_id, route.source_operation, next.run(request)).await;
    outcome_guard.disarm();
    response.headers_mut().insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_str(&request_id.hyphenated().to_string())
            .expect("UUID is a valid header value"),
    );

    let status = response.status();
    let failure_class = response
        .extensions()
        .get::<OutcomeFailureClass>()
        .copied()
        .map(OutcomeFailureClass::as_str)
        .unwrap_or(if status.is_success() {
            "none"
        } else {
            "unclassified"
        });
    let elapsed_ms = elapsed_ms(started);
    emit(
        route,
        status,
        failure_class,
        elapsed_ms,
        request_id,
        source_failure,
    );
    response
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn accepted_request_id(headers: &axum::http::HeaderMap) -> Option<Uuid> {
    let values = headers.get_all(&REQUEST_ID_HEADER);
    if values.iter().count() != 1 {
        return None;
    }
    let value = values.iter().next()?.to_str().ok()?;
    let parsed = Uuid::parse_str(value).ok()?;
    (parsed.get_version() == Some(Version::Random) && parsed.hyphenated().to_string() == value)
        .then_some(parsed)
}

fn emit(
    route: DiagnosedRoute,
    status: StatusCode,
    failure_class: &'static str,
    elapsed_ms: u64,
    request_id: Uuid,
    source_failure: bool,
) {
    let http_status = status.as_u16();
    let request_id = request_id.hyphenated();
    if route.frequent_poll && (status.is_success() || failure_class != "unclassified") {
        tracing::debug!(
            event = route.event,
            operation = route.operation.expect("poll routes have an operation"),
            http_status,
            failure_class,
            elapsed_ms,
            request_id = %request_id,
            "Paykit Locks status request completed"
        );
    } else if route.frequent_poll {
        tracing::warn!(
            event = route.event,
            operation = route.operation.expect("poll routes have an operation"),
            http_status,
            failure_class,
            elapsed_ms,
            request_id = %request_id,
            "Paykit Locks status request completed"
        );
    } else if status.is_server_error() && !source_failure {
        tracing::warn!(
            event = route.event,
            http_status,
            failure_class,
            elapsed_ms,
            request_id = %request_id,
            "Paykit invoice request completed"
        );
    } else if status.is_success() || source_failure {
        tracing::debug!(
            event = route.event,
            http_status,
            failure_class,
            elapsed_ms,
            request_id = %request_id,
            "Paykit invoice request completed"
        );
    } else {
        tracing::info!(
            event = route.event,
            http_status,
            failure_class,
            elapsed_ms,
            request_id = %request_id,
            "Paykit invoice request completed"
        );
    }
}

fn emit_incomplete(route: DiagnosedRoute, elapsed_ms: u64, request_id: Uuid, panicking: bool) {
    let failure_class = "cancelled";
    let request_id = request_id.hyphenated();
    if panicking {
        if let Some(operation) = route.operation {
            tracing::warn!(
                event = route.event,
                operation,
                failure_class,
                elapsed_ms,
                request_id = %request_id,
                "Paykit request ended without a response"
            );
        } else {
            tracing::warn!(
                event = route.event,
                failure_class,
                elapsed_ms,
                request_id = %request_id,
                "Paykit request ended without a response"
            );
        }
    } else if route.frequent_poll {
        tracing::debug!(
            event = route.event,
            operation = route.operation.expect("poll routes have an operation"),
            failure_class,
            elapsed_ms,
            request_id = %request_id,
            "Paykit request ended without a response"
        );
    } else {
        tracing::info!(
            event = route.event,
            failure_class,
            elapsed_ms,
            request_id = %request_id,
            "Paykit request ended without a response"
        );
    }
}
