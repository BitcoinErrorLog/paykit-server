use std::sync::Arc;

use axum::{
    Router,
    extract::{OriginalUri, State},
    response::{IntoResponse, Response},
    routing::post,
};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    application::{
        marketplace_status::{
            MarketplaceBitcoinStatus, MarketplaceInvoiceStatus, MarketplaceStatusError,
            MarketplaceStatusService, MarketplaceUsdtStatus,
        },
        setup_status::AcceptedAsset,
    },
    domain::locks::parse_creator,
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusBody {
    creator: String,
    invoice_id: String,
}

#[derive(Serialize)]
struct BitcoinResponse {
    txid: String,
    observed_sats: u64,
    confirmations: u32,
    amount_matched: bool,
    paid_on_time: bool,
}

#[derive(Serialize)]
struct UsdtResponse {
    tx_hash: String,
    observed_amount: String,
    confirmations: u32,
    amount_matched: bool,
    paid_on_time: bool,
    finalized: bool,
}

#[derive(Serialize)]
struct StatusResponse {
    invoice_id: String,
    state: &'static str,
    proposal_delivery_state: &'static str,
    request_state: Option<&'static str>,
    payment_state: Option<&'static str>,
    activated_at: Option<String>,
    payment_deadline: Option<String>,
    accepted_assets: Vec<&'static str>,
    payment_amounts: BTreeMap<&'static str, String>,
    bitcoin: Option<BitcoinResponse>,
    usdt_arbitrum: Option<UsdtResponse>,
    paid_asset: Option<&'static str>,
    outcome: Option<&'static str>,
    resolved_at: Option<String>,
}

pub fn marketplace_status_router(service: Arc<MarketplaceStatusService>) -> Router {
    Router::new()
        .route("/marketplace/payment-requests/status", post(status))
        .with_state(service)
}

async fn status(
    State(service): State<Arc<MarketplaceStatusService>>,
    OriginalUri(uri): OriginalUri,
    AuthenticatedJson(body): AuthenticatedJson<StatusBody>,
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
    match service.status(&creator, invoice_id).await {
        Ok(Some(status)) => match response(status) {
            Ok(response) => axum::Json(response).into_response(),
            Err(error) => error.into_response(),
        },
        Ok(None) => ApiError::InvoiceNotFound.into_response(),
        Err(MarketplaceStatusError::Conflict) => ApiError::Conflict.into_response(),
        Err(MarketplaceStatusError::Unavailable) => ApiError::Unavailable.into_response(),
        Err(MarketplaceStatusError::RecoveryRequired) => ApiError::RecoveryRequired.into_response(),
        Err(MarketplaceStatusError::InvalidConflict) => ApiError::InvalidConflict.into_response(),
    }
}

fn response(status: MarketplaceInvoiceStatus) -> Result<StatusResponse, ApiError> {
    Ok(StatusResponse {
        invoice_id: status.invoice_id.hyphenated().to_string(),
        state: status.state,
        proposal_delivery_state: status.proposal_delivery_state,
        request_state: status.request_state,
        payment_state: status.payment_state,
        activated_at: format_optional(status.activated_at)?,
        payment_deadline: format_optional(status.payment_deadline)?,
        accepted_assets: status
            .accepted_assets
            .iter()
            .copied()
            .map(AcceptedAsset::as_str)
            .collect(),
        payment_amounts: status
            .payment_amounts
            .iter()
            .map(|(asset, amount)| (asset.as_str(), amount.to_string()))
            .collect(),
        bitcoin: status.bitcoin.map(bitcoin_response),
        usdt_arbitrum: status.usdt_arbitrum.map(usdt_response),
        paid_asset: status.paid_asset.map(AcceptedAsset::as_str),
        outcome: status.outcome,
        resolved_at: format_optional(status.resolved_at)?,
    })
}

fn bitcoin_response(status: MarketplaceBitcoinStatus) -> BitcoinResponse {
    BitcoinResponse {
        txid: status.txid,
        observed_sats: status.observed_sats,
        confirmations: status.confirmations,
        amount_matched: status.amount_matched,
        paid_on_time: status.paid_on_time,
    }
}

fn usdt_response(status: MarketplaceUsdtStatus) -> UsdtResponse {
    UsdtResponse {
        tx_hash: status.tx_hash,
        observed_amount: status.observed_amount.to_string(),
        confirmations: status.confirmations,
        amount_matched: status.amount_matched,
        paid_on_time: status.paid_on_time,
        finalized: status.finalized,
    }
}

fn format_optional(value: Option<OffsetDateTime>) -> Result<Option<String>, ApiError> {
    value.map(format).transpose()
}

fn format(value: OffsetDateTime) -> Result<String, ApiError> {
    value.format(&Rfc3339).map_err(|_| ApiError::Unavailable)
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
