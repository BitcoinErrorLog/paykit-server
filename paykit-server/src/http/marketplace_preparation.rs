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

use crate::{
    application::marketplace_preparation::{
        PrepareMarketplaceError, PrepareMarketplaceRequest, PrepareMarketplaceService,
    },
    domain::locks::{parse_creator, parse_reader},
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct PrepareBody {
    creator: String,
    reader: String,
    reference: String,
    amount_sats: u64,
    operation_id: String,
    payment_window_seconds: u64,
}

#[derive(Serialize)]
struct PrepareResponse {
    invoice_id: String,
    state: &'static str,
    total_sats: u64,
    prepare_expires_at: String,
}

pub fn marketplace_preparation_router(service: Arc<PrepareMarketplaceService>) -> Router {
    Router::new()
        .route("/marketplace/payment-requests/prepare", post(prepare))
        .with_state(service)
}

async fn prepare(
    State(service): State<Arc<PrepareMarketplaceService>>,
    AuthenticatedJson(body): AuthenticatedJson<PrepareBody>,
) -> Response {
    let request = match parse(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match service.prepare(request).await {
        Ok(result) => {
            let prepare_expires_at = match result.prepare_expires_at().format(&Rfc3339) {
                Ok(value) => value,
                Err(_) => {
                    crate::diagnostics::failure(
                        "marketplace_prepare",
                        "response_serialization",
                        "invalid_prepare_expires_at",
                    );
                    return ApiError::InternalError.into_response();
                }
            };
            (
                StatusCode::OK,
                axum::Json(PrepareResponse {
                    invoice_id: result.invoice_id().hyphenated().to_string(),
                    state: "prepared",
                    total_sats: result.total_sats(),
                    prepare_expires_at,
                }),
            )
                .into_response()
        }
        Err(error) => {
            crate::diagnostics::failure(
                "marketplace_prepare",
                "application_service",
                error.diagnostic_label(),
            );
            map_error(error).into_response()
        }
    }
}

fn parse(body: PrepareBody) -> Result<PrepareMarketplaceRequest, ApiError> {
    Ok(PrepareMarketplaceRequest {
        creator: parse_creator(&body.creator).map_err(|_| ApiError::InvalidRequest)?,
        reader: parse_reader(&body.reader).map_err(|_| ApiError::InvalidRequest)?,
        reference: body.reference,
        amount_sats: body.amount_sats,
        operation_id: body.operation_id,
        payment_window_seconds: body.payment_window_seconds,
    })
}

fn map_error(error: PrepareMarketplaceError) -> ApiError {
    match error {
        PrepareMarketplaceError::InvalidRequest => ApiError::InvalidRequest,
        PrepareMarketplaceError::Conflict => ApiError::OperationConflict,
        PrepareMarketplaceError::CreatorSessionInvalid => ApiError::CreatorSessionInvalid,
        PrepareMarketplaceError::CreatorSessionUnavailable => ApiError::CreatorSessionUnavailable,
        PrepareMarketplaceError::ReaderSetupPending => ApiError::ReaderSetupPending,
        PrepareMarketplaceError::ReaderNotPayable => ApiError::ReaderNotPayable,
        PrepareMarketplaceError::ReaderRegistryUnavailable => ApiError::ReaderRegistryUnavailable,
        PrepareMarketplaceError::ReaderRegistryMalformed => ApiError::ReaderRegistryMalformed,
        PrepareMarketplaceError::SellerSetupPending => ApiError::SellerSetupPending,
        PrepareMarketplaceError::DeadlineExceeded => ApiError::DependencyTimeout,
        PrepareMarketplaceError::Unavailable => ApiError::DependencyUnavailable,
    }
}
