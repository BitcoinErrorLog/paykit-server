//! Signed marketplace payment-request route.
//!
//! Authenticated exactly like `/invoices` (canonical JSON body, single
//! `x-paykit-signature` header verified against the configured trusted
//! keys); the expected signer is the marketplace transaction service.

use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;

use crate::{
    application::create_invoice::CreateInvoiceError,
    application::create_payment_request::{
        MarketplacePaymentRequest, MarketplacePaymentRequestService,
    },
    domain::locks::{parse_bundle_id, parse_creator, parse_reader},
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct PaymentRequestBody {
    creator: String,
    reader: String,
    reference: String,
    amount_sats: u64,
}

pub fn payment_requests_router(service: Arc<MarketplacePaymentRequestService>) -> Router {
    Router::new()
        .route("/v0/payment-requests", post(create))
        .with_state(service)
}

async fn create(
    State(service): State<Arc<MarketplacePaymentRequestService>>,
    AuthenticatedJson(body): AuthenticatedJson<PaymentRequestBody>,
) -> Response {
    let request = match parse(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match service.create(request).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => payment_request_error(error),
    }
}

fn parse(body: PaymentRequestBody) -> Result<MarketplacePaymentRequest, ApiError> {
    Ok(MarketplacePaymentRequest {
        creator: parse_creator(&body.creator).map_err(|_| ApiError::InvalidRequest)?,
        reader: parse_reader(&body.reader).map_err(|_| ApiError::InvalidRequest)?,
        reference: parse_bundle_id(&body.reference).map_err(|_| ApiError::InvalidRequest)?,
        amount_sats: body.amount_sats,
    })
}

fn payment_request_error(error: CreateInvoiceError) -> Response {
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
    }
}
