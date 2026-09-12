use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;

use crate::{
    application::create_invoice::{CreateInvoiceError, CreateInvoiceRequest, CreateInvoiceService},
    domain::locks::{parse_addressed_lock_resource, parse_bundle_id, parse_reader},
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct InvoiceBody {
    bundle_id: String,
    lock_resource: String,
    reader: String,
    /// §B.9: required exactly as on `/v0/payment-requests`; a missing field
    /// is the schema's plain `invalid_request`, past/over-maximum are named
    /// by the service.
    expires_at: String,
}

pub fn invoices_router(service: Arc<CreateInvoiceService>) -> Router {
    Router::new()
        .route("/invoices", post(create))
        .with_state(service)
}

async fn create(
    State(service): State<Arc<CreateInvoiceService>>,
    AuthenticatedJson(body): AuthenticatedJson<InvoiceBody>,
) -> Response {
    let request = match parse(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match service.create(request).await {
        // §B.11 phase 1 returns 200 with the prepare body (the r3 204 was
        // the B.11.0 defect: the caller learned nothing it could bind to).
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(error) => invoice_error(error),
    }
}

fn parse(body: InvoiceBody) -> Result<CreateInvoiceRequest, ApiError> {
    Ok(CreateInvoiceRequest {
        bundle_id: parse_bundle_id(&body.bundle_id).map_err(|_| ApiError::InvalidRequest)?,
        lock_resource: parse_addressed_lock_resource(&body.lock_resource)
            .map_err(|_| ApiError::InvalidRequest)?,
        reader: parse_reader(&body.reader).map_err(|_| ApiError::InvalidRequest)?,
        expires_at: time::OffsetDateTime::parse(
            &body.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| ApiError::InvalidRequest)?,
    })
}

fn invoice_error(error: CreateInvoiceError) -> Response {
    match error {
        CreateInvoiceError::InvalidRequest => ApiError::InvalidRequest.into_response(),
        CreateInvoiceError::CreatorSessionInvalid => {
            ApiError::CreatorSessionInvalid.into_response()
        }
        CreateInvoiceError::CreatorSessionUnavailable
        | CreateInvoiceError::LockUnavailable
        | CreateInvoiceError::Unavailable => ApiError::CreatorSessionUnavailable.into_response(),
        CreateInvoiceError::LockNotFound => ApiError::LockNotFound.into_response(),
        CreateInvoiceError::Conflict => ApiError::InvoiceConflict.into_response(),
        CreateInvoiceError::BaselineInProgress => {
            ApiError::InvoiceBaselineInProgress.into_response()
        }
        CreateInvoiceError::DeadlineExceeded => ApiError::DependencyTimeout.into_response(),
        CreateInvoiceError::BitcoinCreationDisabled => {
            ApiError::BitcoinCreationDisabled.into_response()
        }
        CreateInvoiceError::BitcoinOfferUnavailable => {
            ApiError::BitcoinOfferUnavailable.into_response()
        }
        CreateInvoiceError::InvoiceFinalized => ApiError::InvoiceFinalized.into_response(),
        CreateInvoiceError::PrepareExpired => ApiError::PrepareExpired.into_response(),
        CreateInvoiceError::InvalidExpiry(reason) => crate::http::error::invalid_expiry(reason),
    }
}
