use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::{
    application::marketplace_lifecycle::{
        ActivateMarketplaceRequest, MarketplaceLifecycleError, MarketplaceLifecycleService,
        ResolveMarketplaceRequest, VoidMarketplaceRequest,
    },
    domain::locks::parse_creator,
    http::{auth::AuthenticatedJson, error::ApiError},
    persistence::MarketplaceResolutionOutcome,
};

#[derive(Deserialize)]
struct ActivateBody {
    creator: String,
    invoice_id: String,
    total_sats: u64,
}

#[derive(Deserialize)]
struct VoidBody {
    creator: String,
    invoice_id: String,
}

#[derive(Deserialize)]
struct ResolveBody {
    creator: String,
    invoice_id: String,
    outcome: String,
}

#[derive(Serialize)]
struct ActivateResponse {
    invoice_id: String,
    state: &'static str,
    activated_at: String,
    payment_deadline: String,
    total_sats: u64,
}

#[derive(Serialize)]
struct VoidResponse {
    invoice_id: String,
    state: &'static str,
    voided_at: String,
}

#[derive(Serialize)]
struct ResolveResponse {
    invoice_id: String,
    outcome: &'static str,
    resolved_at: String,
}

pub fn marketplace_lifecycle_router(service: Arc<MarketplaceLifecycleService>) -> Router {
    Router::new()
        .route("/marketplace/payment-requests/activate", post(activate))
        .route("/marketplace/payment-requests/void", post(void))
        .route("/marketplace/payment-requests/resolve", post(resolve))
        .with_state(service)
}

async fn activate(
    State(service): State<Arc<MarketplaceLifecycleService>>,
    AuthenticatedJson(body): AuthenticatedJson<ActivateBody>,
) -> Response {
    let request = match parse_activate(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match service.activate(request).await {
        Ok(result) => {
            let activated_at = match result.activated_at().format(&Rfc3339) {
                Ok(value) => value,
                Err(_) => return ApiError::InternalError.into_response(),
            };
            let payment_deadline = match result.payment_deadline().format(&Rfc3339) {
                Ok(value) => value,
                Err(_) => return ApiError::InternalError.into_response(),
            };
            (
                StatusCode::OK,
                axum::Json(ActivateResponse {
                    invoice_id: result.invoice_id().hyphenated().to_string(),
                    state: "active",
                    activated_at,
                    payment_deadline,
                    total_sats: result.total_sats(),
                }),
            )
                .into_response()
        }
        Err(error) => map_error(error).into_response(),
    }
}

async fn void(
    State(service): State<Arc<MarketplaceLifecycleService>>,
    AuthenticatedJson(body): AuthenticatedJson<VoidBody>,
) -> Response {
    let request = match parse_void(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match service.void(request).await {
        Ok(result) => {
            let voided_at = match result.voided_at().format(&Rfc3339) {
                Ok(value) => value,
                Err(_) => return ApiError::InternalError.into_response(),
            };
            (
                StatusCode::OK,
                axum::Json(VoidResponse {
                    invoice_id: result.invoice_id().hyphenated().to_string(),
                    state: "voided",
                    voided_at,
                }),
            )
                .into_response()
        }
        Err(error) => map_error(error).into_response(),
    }
}

async fn resolve(
    State(service): State<Arc<MarketplaceLifecycleService>>,
    AuthenticatedJson(body): AuthenticatedJson<ResolveBody>,
) -> Response {
    let request = match parse_resolve(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match service.resolve(request).await {
        Ok(result) => {
            let resolved_at = match result.resolved_at().format(&Rfc3339) {
                Ok(value) => value,
                Err(_) => return ApiError::InternalError.into_response(),
            };
            (
                StatusCode::OK,
                axum::Json(ResolveResponse {
                    invoice_id: result.invoice_id().hyphenated().to_string(),
                    outcome: result.outcome().as_str(),
                    resolved_at,
                }),
            )
                .into_response()
        }
        Err(error) => map_error(error).into_response(),
    }
}

fn parse_activate(body: ActivateBody) -> Result<ActivateMarketplaceRequest, ApiError> {
    Ok(ActivateMarketplaceRequest {
        creator: parse_creator(&body.creator).map_err(|_| ApiError::InvalidRequest)?,
        invoice_id: parse_uuid(&body.invoice_id)?,
        total_sats: body.total_sats,
    })
}

fn parse_void(body: VoidBody) -> Result<VoidMarketplaceRequest, ApiError> {
    Ok(VoidMarketplaceRequest {
        creator: parse_creator(&body.creator).map_err(|_| ApiError::InvalidRequest)?,
        invoice_id: parse_uuid(&body.invoice_id)?,
    })
}

fn parse_resolve(body: ResolveBody) -> Result<ResolveMarketplaceRequest, ApiError> {
    Ok(ResolveMarketplaceRequest {
        creator: parse_creator(&body.creator).map_err(|_| ApiError::InvalidRequest)?,
        invoice_id: parse_uuid(&body.invoice_id)?,
        outcome: MarketplaceResolutionOutcome::parse(&body.outcome)
            .ok_or(ApiError::InvalidRequest)?,
    })
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    let parsed = Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest)?;
    if parsed.get_version_num() != 4
        || parsed.get_variant() != uuid::Variant::RFC4122
        || parsed.hyphenated().to_string() != value
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(parsed)
}

fn map_error(error: MarketplaceLifecycleError) -> ApiError {
    match error {
        MarketplaceLifecycleError::InvalidRequest => ApiError::InvalidRequest,
        MarketplaceLifecycleError::PrepareExpired => ApiError::PrepareExpired,
        MarketplaceLifecycleError::LifecycleTerminal => ApiError::LifecycleTerminal,
        MarketplaceLifecycleError::InvoiceActive => ApiError::InvoiceActive,
        MarketplaceLifecycleError::TotalMismatch => ApiError::TotalMismatch,
        MarketplaceLifecycleError::ResolutionConflict => ApiError::ResolutionConflict,
        MarketplaceLifecycleError::NotFound => ApiError::InvoiceNotFound,
        MarketplaceLifecycleError::Unavailable => ApiError::DependencyUnavailable,
        MarketplaceLifecycleError::Internal => ApiError::InternalError,
    }
}
