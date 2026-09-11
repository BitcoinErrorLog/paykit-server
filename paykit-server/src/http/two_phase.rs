//! Signed two-phase routes (design §B.11.3): `activate` and `void` for both
//! creation entrypoint families, plus the §B.9 `resolve` route on the same
//! two families (and nowhere else — no `/v0/invoices` alias).
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
    application::two_phase::{
        ActivateRequest, Resolution, ResolveError, ResolveRequest, TwoPhaseError, TwoPhaseService,
        VoidRequest,
    },
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

#[derive(Deserialize)]
struct ResolveHttpBody {
    invoice_id: Uuid,
    stack_id: String,
    resolution: String,
    resolved_at: String,
}

pub fn two_phase_router(service: Arc<TwoPhaseService>) -> Router {
    Router::new()
        .route("/invoices/{invoice_id}/activate", post(activate))
        .route("/invoices/{invoice_id}/void", post(void_invoice))
        .route("/invoices/{invoice_id}/resolve", post(resolve))
        .route("/v0/payment-requests/{invoice_id}/activate", post(activate))
        .route("/v0/payment-requests/{invoice_id}/void", post(void_invoice))
        .route("/v0/payment-requests/{invoice_id}/resolve", post(resolve))
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

/// §B.9: the marketplace's one-way money-outcome record. `resolved_at` is
/// recorded as supplied; every state decision uses the server clock.
async fn resolve(
    State(service): State<Arc<TwoPhaseService>>,
    Path(invoice_id): Path<Uuid>,
    AuthenticatedJson(body): AuthenticatedJson<ResolveHttpBody>,
) -> Response {
    if body.invoice_id != invoice_id {
        return ApiError::InvalidRequest.into_response();
    }
    let resolution = match body.resolution.as_str() {
        "paid_manually" => Resolution::PaidManually,
        "refunded" => Resolution::Refunded,
        "abandoned" => Resolution::Abandoned,
        _ => return ApiError::InvalidRequest.into_response(),
    };
    let resolved_at = match time::OffsetDateTime::parse(
        &body.resolved_at,
        &time::format_description::well_known::Rfc3339,
    ) {
        Ok(resolved_at) => resolved_at,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    match service
        .resolve(ResolveRequest {
            invoice_id,
            stack_id: body.stack_id,
            resolution,
            resolved_at,
        })
        .await
    {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(error) => resolve_error(error),
    }
}

fn resolve_error(error: ResolveError) -> Response {
    match error {
        ResolveError::UnknownInvoice => ApiError::UnknownInvoice.into_response(),
        ResolveError::StackIdentityMismatch => ApiError::StackIdentityMismatch.into_response(),
        ResolveError::InvoiceNotActivated => ApiError::InvoiceNotActivated.into_response(),
        ResolveError::InvoiceAlreadyResolved(existing) => {
            crate::http::error::invoice_already_resolved(&existing)
        }
        ResolveError::PrepareExpired => ApiError::PrepareExpired.into_response(),
        ResolveError::InvoiceFinalized => ApiError::InvoiceFinalized.into_response(),
        ResolveError::BaselineInProgress => ApiError::InvoiceBaselineInProgress.into_response(),
        ResolveError::Unavailable => ApiError::CreatorSessionUnavailable.into_response(),
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
