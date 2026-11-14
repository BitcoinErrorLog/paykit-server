use std::sync::Arc;

use axum::{
    Router,
    extract::{OriginalUri, State},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    application::marketplace_receipt::{
        MarketplaceReceiptError, MarketplaceReceiptService, StoredSellerReceipt,
    },
    domain::locks::parse_creator,
    http::{
        auth::AuthenticatedJson,
        error::ApiError,
        marketplace_status::{format, parse_uuid},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptBody {
    creator: String,
    invoice_id: String,
}

#[derive(Serialize)]
struct AmountResponse {
    value: String,
    currency: String,
}

#[derive(Serialize)]
struct SellerReceiptResponse {
    receipt_id: String,
    app_id: String,
    payment_request_id: String,
    payment_reference: String,
    payment_endpoint_identifier: Option<String>,
    amount: Option<AmountResponse>,
    metadata: Map<String, Value>,
    issued_at: String,
    stored_at: String,
}

#[derive(Serialize)]
struct ReceiptResponse {
    invoice_id: String,
    receipt: Option<SellerReceiptResponse>,
}

pub fn marketplace_receipt_router(service: Arc<MarketplaceReceiptService>) -> Router {
    Router::new()
        .route("/marketplace/payment-requests/receipt", post(receipt))
        .with_state(service)
}

async fn receipt(
    State(service): State<Arc<MarketplaceReceiptService>>,
    OriginalUri(uri): OriginalUri,
    AuthenticatedJson(body): AuthenticatedJson<ReceiptBody>,
) -> Response {
    if uri.query().is_some() {
        return ApiError::InvalidRequest.into_response();
    }
    let creator = match parse_creator(&body.creator) {
        Ok(creator) => creator,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let invoice_id = match parse_uuid(&body.invoice_id) {
        Ok(invoice_id) => invoice_id,
        Err(error) => return error.into_response(),
    };
    match service.seller_receipt(&creator, invoice_id).await {
        Ok(Some(stored)) => match stored.map(seller_receipt_response).transpose() {
            Ok(receipt) => axum::Json(ReceiptResponse {
                invoice_id: invoice_id.hyphenated().to_string(),
                receipt,
            })
            .into_response(),
            Err(error) => error.into_response(),
        },
        Ok(None) => ApiError::InvoiceNotFound.into_response(),
        Err(MarketplaceReceiptError::Unavailable) => ApiError::Unavailable.into_response(),
    }
}

fn seller_receipt_response(stored: StoredSellerReceipt) -> Result<SellerReceiptResponse, ApiError> {
    let receipt = stored.receipt;
    Ok(SellerReceiptResponse {
        receipt_id: receipt.receipt_id,
        app_id: receipt.app_id,
        payment_request_id: receipt.payment_request_id,
        payment_reference: receipt.payment_reference,
        payment_endpoint_identifier: receipt.payment_endpoint_identifier,
        amount: receipt.amount.map(|amount| AmountResponse {
            value: amount.value,
            currency: amount.currency,
        }),
        metadata: receipt.metadata,
        issued_at: format(receipt.issued_at)?,
        stored_at: format(stored.stored_at)?,
    })
}
