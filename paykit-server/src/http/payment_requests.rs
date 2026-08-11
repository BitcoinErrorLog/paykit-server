use std::sync::Arc;

use axum::{
    Router,
    extract::{OriginalUri, State},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;

use crate::{
    application::payment_request_status::{
        PaymentRequestStatusError, PaymentRequestStatusOperations, PaymentRequestStatusSummary,
    },
    domain::locks::{parse_bundle_id, parse_creator},
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct PaymentRequestStatusBody {
    creator: String,
    bundle_id: String,
}

#[derive(Serialize)]
struct PaymentRequestStatusResponse {
    request_state: &'static str,
    payment_state: &'static str,
    invoice_created_at: String,
    payment_deadline: String,
    confirmations: u32,
    amount_matched: bool,
}

pub fn payment_requests_router(operations: Arc<dyn PaymentRequestStatusOperations>) -> Router {
    Router::new()
        .route("/payment-requests/status", post(status))
        .with_state(operations)
}

async fn status(
    State(operations): State<Arc<dyn PaymentRequestStatusOperations>>,
    OriginalUri(uri): OriginalUri,
    AuthenticatedJson(body): AuthenticatedJson<PaymentRequestStatusBody>,
) -> Response {
    if uri.query().is_some() {
        return ApiError::InvalidRequest.into_response();
    }
    let creator = match parse_creator(&body.creator) {
        Ok(creator) => creator,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let bundle_id = match parse_bundle_id(&body.bundle_id) {
        Ok(bundle_id) => bundle_id,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    match operations.lookup(&creator, &bundle_id).await {
        Ok(Some(summary)) => match PaymentRequestStatusResponse::try_from(summary) {
            Ok(response) => axum::Json(response).into_response(),
            Err(()) => ApiError::Unavailable.into_response(),
        },
        Ok(None) => ApiError::InvoiceNotFound.into_response(),
        Err(PaymentRequestStatusError::Unavailable) => ApiError::Unavailable.into_response(),
    }
}

impl TryFrom<PaymentRequestStatusSummary> for PaymentRequestStatusResponse {
    type Error = ();

    fn try_from(value: PaymentRequestStatusSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            request_state: value.request_state().as_str(),
            payment_state: value.payment_state().as_str(),
            invoice_created_at: value
                .invoice_created_at()
                .format(&Rfc3339)
                .map_err(|_| ())?,
            payment_deadline: value.payment_deadline().format(&Rfc3339).map_err(|_| ())?,
            confirmations: value.confirmations(),
            amount_matched: value.amount_matched(),
        })
    }
}
