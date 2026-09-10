//! Signed two-phase routes (design §B.11.3): `activate` and `void` for both
//! creation entrypoint families.
//!
//! Authenticated exactly like the create routes (canonical JSON body, single
//! `x-paykit-signature` header verified against the configured trusted
//! keys — the same middleware, no new auth path). `POST …/void` is a POST
//! rather than a DELETE for the mechanical reason §B.11.3 states: this
//! router's authentication is a signature over the canonical JSON body, so
//! a bodyless DELETE would have nothing to sign.
//!
//! The `invoice_id` is repeated in every body because the signature covers
//! the body, not the path; the handler refuses a path/body mismatch so a
//! valid signature can never be replayed against a different invoice id.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    application::two_phase::{ActivateRequest, TwoPhaseError, TwoPhaseService, VoidRequest},
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct ActivateBody {
    invoice_id: Uuid,
    stack_id: String,
    total_sats: u64,
    activation_attempt: u64,
}

#[derive(Deserialize)]
struct VoidBody {
    invoice_id: Uuid,
    stack_id: String,
    reason: String,
}

pub fn two_phase_router(service: Arc<TwoPhaseService>) -> Router {
    Router::new()
        .route("/invoices/{invoice_id}/activate", post(activate))
        .route("/invoices/{invoice_id}/void", post(void_invoice))
        .route("/v0/payment-requests/{invoice_id}/activate", post(activate))
        .route("/v0/payment-requests/{invoice_id}/void", post(void_invoice))
        .with_state(service)
}

async fn activate(
    State(service): State<Arc<TwoPhaseService>>,
    Path(invoice_id): Path<Uuid>,
    AuthenticatedJson(body): AuthenticatedJson<ActivateBody>,
) -> Response {
    if body.invoice_id != invoice_id {
        return ApiError::InvalidRequest.into_response();
    }
    match service
        .activate(ActivateRequest {
            invoice_id,
            stack_id: body.stack_id,
            total_sats: body.total_sats,
            activation_attempt: body.activation_attempt,
        })
        .await
    {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(error) => two_phase_error(error),
    }
}

async fn void_invoice(
    State(service): State<Arc<TwoPhaseService>>,
    Path(invoice_id): Path<Uuid>,
    AuthenticatedJson(body): AuthenticatedJson<VoidBody>,
) -> Response {
    if body.invoice_id != invoice_id {
        return ApiError::InvalidRequest.into_response();
    }
    match service
        .void(VoidRequest {
            invoice_id,
            stack_id: body.stack_id,
            reason: body.reason,
        })
        .await
    {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(error) => two_phase_error(error),
    }
}

fn two_phase_error(error: TwoPhaseError) -> Response {
    match error {
        TwoPhaseError::UnknownInvoice => ApiError::UnknownInvoice.into_response(),
        TwoPhaseError::StackIdentityMismatch => ApiError::StackIdentityMismatch.into_response(),
        TwoPhaseError::ActivationTotalMismatch => ApiError::ActivationTotalMismatch.into_response(),
        TwoPhaseError::PrepareExpired => ApiError::PrepareExpired.into_response(),
        TwoPhaseError::InvoiceFinalized => ApiError::InvoiceFinalized.into_response(),
        TwoPhaseError::BaselineInProgress => ApiError::InvoiceBaselineInProgress.into_response(),
        TwoPhaseError::DeadlineExceeded => ApiError::DependencyTimeout.into_response(),
        TwoPhaseError::Unavailable => ApiError::CreatorSessionUnavailable.into_response(),
    }
}
