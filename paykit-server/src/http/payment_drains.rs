use std::sync::Arc;

use axum::{
    Router,
    extract::{OriginalUri, State},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};

use crate::{
    application::payment_drain::{
        PaymentDrainCleanupToken, PaymentDrainError, PaymentDrainOperations, PaymentDrainSummary,
    },
    domain::locks::parse_addressed_lock_resource,
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct DrainBody {
    lock_resource: String,
}

#[derive(Deserialize)]
struct CleanupBody {
    lock_resource: String,
    cleanup_token: String,
}

#[derive(Serialize)]
struct DrainResponse {
    status: &'static str,
    accepted_count: u64,
    terminal_count: u64,
    cancellation_enqueued_count: u64,
    cleanup_token: String,
}

#[derive(Serialize)]
struct CleanupResponse {
    status: &'static str,
}

pub fn payment_drains_router(operations: Arc<dyn PaymentDrainOperations>) -> Router {
    Router::new()
        .route("/payment-request-drains", post(create))
        .route("/payment-request-drain-lookups", post(lookup))
        .route("/payment-request-drain-cleanups", post(cleanup))
        .with_state(operations)
}

async fn create(
    State(operations): State<Arc<dyn PaymentDrainOperations>>,
    OriginalUri(uri): OriginalUri,
    AuthenticatedJson(body): AuthenticatedJson<DrainBody>,
) -> Response {
    if uri.query().is_some() {
        return ApiError::InvalidRequest.into_response();
    }
    let lock_resource = match parse_addressed_lock_resource(&body.lock_resource) {
        Ok(resource) => resource,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    result(operations.create(&lock_resource).await)
}

async fn lookup(
    State(operations): State<Arc<dyn PaymentDrainOperations>>,
    OriginalUri(uri): OriginalUri,
    AuthenticatedJson(body): AuthenticatedJson<DrainBody>,
) -> Response {
    if uri.query().is_some() {
        return ApiError::InvalidRequest.into_response();
    }
    let lock_resource = match parse_addressed_lock_resource(&body.lock_resource) {
        Ok(resource) => resource,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    match operations.lookup(&lock_resource).await {
        Ok(Some(summary)) => axum::Json(DrainResponse::from(summary)).into_response(),
        Ok(None) => ApiError::InvoiceNotFound.into_response(),
        Err(error) => drain_error(error).into_response(),
    }
}

async fn cleanup(
    State(operations): State<Arc<dyn PaymentDrainOperations>>,
    OriginalUri(uri): OriginalUri,
    AuthenticatedJson(body): AuthenticatedJson<CleanupBody>,
) -> Response {
    if uri.query().is_some() {
        return ApiError::InvalidRequest.into_response();
    }
    let lock_resource = match parse_addressed_lock_resource(&body.lock_resource) {
        Ok(resource) => resource,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let cleanup_token = match PaymentDrainCleanupToken::parse(&body.cleanup_token) {
        Some(token) => token,
        None => return ApiError::InvalidRequest.into_response(),
    };
    match operations.cleanup(&lock_resource, cleanup_token).await {
        Ok(()) => axum::Json(CleanupResponse { status: "removed" }).into_response(),
        Err(error) => drain_error(error).into_response(),
    }
}

fn result(result: Result<PaymentDrainSummary, PaymentDrainError>) -> Response {
    match result {
        Ok(summary) => axum::Json(DrainResponse::from(summary)).into_response(),
        Err(error) => drain_error(error).into_response(),
    }
}

fn drain_error(error: PaymentDrainError) -> ApiError {
    match error {
        PaymentDrainError::CreatorMismatch | PaymentDrainError::Conflict => ApiError::Conflict,
        PaymentDrainError::Unavailable => ApiError::Unavailable,
    }
}

impl From<PaymentDrainSummary> for DrainResponse {
    fn from(value: PaymentDrainSummary) -> Self {
        Self {
            status: value.status(),
            accepted_count: value.accepted_count(),
            terminal_count: value.terminal_count(),
            cancellation_enqueued_count: value.cancellation_enqueued_count(),
            cleanup_token: value.cleanup_token().to_canonical_string(),
        }
    }
}
