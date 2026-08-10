use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    application::create_invoice::{CreateInvoiceError, CreateInvoiceRequest, CreateInvoiceService},
    domain::{
        invoice::CriterionPaymentWindowHours,
        locks::{parse_addressed_lock_resource, parse_bundle_id, parse_reader},
    },
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct InvoiceBody {
    bundle_id: String,
    lock_resource: String,
    reader: String,
    payment_in: Value,
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
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => invoice_error(error),
    }
}

fn parse(body: InvoiceBody) -> Result<CreateInvoiceRequest, ApiError> {
    Ok(CreateInvoiceRequest {
        bundle_id: parse_bundle_id(&body.bundle_id).map_err(|_| ApiError::InvalidRequest)?,
        lock_resource: parse_addressed_lock_resource(&body.lock_resource)
            .map_err(|_| ApiError::InvalidRequest)?,
        reader: parse_reader(&body.reader).map_err(|_| ApiError::InvalidRequest)?,
        payment_in: CriterionPaymentWindowHours::parse(&body.payment_in)
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
        CreateInvoiceError::DeadlineExceeded => ApiError::DependencyTimeout.into_response(),
    }
}
