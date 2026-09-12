use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};

use crate::{
    application::payment_status::{
        PaymentStatusError, PaymentStatusResponse, PaymentStatusService,
    },
    domain::locks::{parse_bundle_id, parse_creator},
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct StatusBody {
    creator: String,
    bundle_id: String,
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    confirmations: u32,
    amount_matched: bool,
    late_settlement: bool,
    /// The creator's CURRENT database allocation mode (W1.14): the
    /// automatic paid transition gates on it at transition time — never a
    /// claim-time cached copy. Always present, always exactly `exclusive`
    /// or `shared_manual` (an unknown persisted mode fails the read
    /// closed rather than emitting an ignorable value).
    allocation_mode: &'static str,
    /// The versioned status contract identifier (W1.14): consumers that
    /// auto-confirm MUST fail closed on any other (or missing) version —
    /// see [`crate::application::payment_status::BITCOIN_STATUS_CONTRACT_V2`].
    contract_version: &'static str,
}

pub fn status_router(service: Arc<PaymentStatusService>) -> Router {
    Router::new()
        .route("/transactions/status", post(status))
        .with_state(service)
}

async fn status(
    State(service): State<Arc<PaymentStatusService>>,
    AuthenticatedJson(body): AuthenticatedJson<StatusBody>,
) -> Response {
    let creator = match parse_creator(&body.creator) {
        Ok(creator) => creator,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let bundle_id = match parse_bundle_id(&body.bundle_id) {
        Ok(bundle_id) => bundle_id,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    match service.status(&creator, &bundle_id).await {
        Ok(response) => axum::Json(StatusResponse::from(response)).into_response(),
        Err(PaymentStatusError::NotFound) => ApiError::InvoiceNotFound.into_response(),
        Err(PaymentStatusError::Unavailable) => ApiError::InternalError.into_response(),
    }
}

impl From<PaymentStatusResponse> for StatusResponse {
    fn from(value: PaymentStatusResponse) -> Self {
        Self {
            status: value.status(),
            confirmations: value.confirmations(),
            amount_matched: value.amount_matched(),
            late_settlement: value.late_settlement(),
            allocation_mode: value.allocation_mode().as_str(),
            contract_version: crate::application::payment_status::BITCOIN_STATUS_CONTRACT_V2,
        }
    }
}
