use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;

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

#[derive(Serialize)]
struct InvoiceResponse {
    invoice_created_at: String,
    payment_deadline: String,
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
        Ok(result) => match response(result) {
            Ok(body) => (StatusCode::OK, axum::Json(body)).into_response(),
            Err(error) => error.into_response(),
        },
        Err(error) => invoice_error(error),
    }
}

fn response(result: crate::persistence::AtomicInvoiceResult) -> Result<InvoiceResponse, ApiError> {
    Ok(InvoiceResponse {
        invoice_created_at: result
            .invoice_created_at()
            .format(&Rfc3339)
            .map_err(|_| ApiError::InternalError)?,
        payment_deadline: result
            .payment_deadline()
            .format(&Rfc3339)
            .map_err(|_| ApiError::InternalError)?,
    })
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
