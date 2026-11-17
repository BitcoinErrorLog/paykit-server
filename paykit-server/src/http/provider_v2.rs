use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    application::{
        payment_request_status::{BitcoinPaymentStatus, UsdtPaymentStatus},
        provider_v2::{ProviderV2CreateRequest, ProviderV2Error, ProviderV2Service},
    },
    domain::{
        locks::{parse_addressed_lock_resource, parse_bundle_id, parse_creator, parse_reader},
        provider_v2::{ProviderV2Payment, ProviderV2Sample},
    },
    http::{auth::AuthenticatedJson, error::ApiError},
    persistence::{ProviderV2CreateResult, ProviderV2Status},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    bundle_id: String,
    lock_resource: String,
    reader: String,
    payment: PaymentBody,
    deadline: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentBody {
    recipient_pubky: String,
    amount: String,
    asset: String,
    minimum_confirmations: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusBody {
    creator: String,
    bundle_id: String,
}

#[derive(Serialize)]
struct CreateResponse {
    invoice_created_at: String,
    proposal_expires_at: String,
    deadline: String,
}

#[derive(Serialize)]
struct StatusResponse {
    creator: String,
    bundle_id: String,
    request_state: &'static str,
    payment_state: &'static str,
    invoice_created_at: String,
    proposal_expires_at: String,
    deadline: String,
    asset: &'static str,
    minimum_confirmations: u8,
    current_sample: Option<SampleResponse>,
    first_threshold_satisfied: Option<SampleResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bitcoin: Option<Option<BitcoinPaymentStatus>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usdt_arbitrum: Option<Option<UsdtPaymentStatus>>,
}

#[derive(Serialize)]
struct SampleResponse {
    observed_at: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    outpoint: Option<OutpointResponse>,
    confirmations: u8,
    amount_matched: bool,
}

#[derive(Serialize)]
struct OutpointResponse {
    txid: String,
    vout: u32,
}

pub fn provider_v2_router(service: Arc<ProviderV2Service>) -> Router {
    Router::new()
        .route("/v2/invoices", post(create))
        .route("/v2/invoices/status", post(status))
        .with_state(service)
}

async fn create(
    State(service): State<Arc<ProviderV2Service>>,
    AuthenticatedJson(body): AuthenticatedJson<CreateBody>,
) -> Response {
    let request = match parse_create(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match service.create(request).await {
        Ok(result) => match create_response(result) {
            Ok(body) => (StatusCode::OK, axum::Json(body)).into_response(),
            Err(error) => error.into_response(),
        },
        Err(error) => map_error(error).into_response(),
    }
}

async fn status(
    State(service): State<Arc<ProviderV2Service>>,
    AuthenticatedJson(body): AuthenticatedJson<StatusBody>,
) -> Response {
    let creator = match parse_creator(&body.creator) {
        Ok(value) => value,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let bundle = match parse_bundle_id(&body.bundle_id) {
        Ok(value) => value,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    match service.status(&creator, &bundle).await {
        Ok(Some(summary)) => match status_response(summary) {
            Ok(body) => (StatusCode::OK, axum::Json(body)).into_response(),
            Err(error) => error.into_response(),
        },
        Ok(None) => ApiError::InvoiceNotFound.into_response(),
        Err(error) => map_error(error).into_response(),
    }
}

fn parse_create(body: CreateBody) -> Result<ProviderV2CreateRequest, ApiError> {
    let lock_resource =
        parse_addressed_lock_resource(&body.lock_resource).map_err(|_| ApiError::InvalidRequest)?;
    let deadline =
        OffsetDateTime::parse(&body.deadline, &Rfc3339).map_err(|_| ApiError::InvalidRequest)?;
    if deadline.offset() != time::UtcOffset::UTC
        || !deadline.nanosecond().is_multiple_of(1_000)
        || deadline
            .format(&Rfc3339)
            .map_err(|_| ApiError::InvalidRequest)?
            != body.deadline
    {
        return Err(ApiError::InvalidRequest);
    }
    let payment = ProviderV2Payment::parse(
        &body.payment.recipient_pubky,
        &body.payment.amount,
        &body.payment.asset,
        body.payment.minimum_confirmations,
        lock_resource.creator(),
    )
    .map_err(|_| ApiError::InvalidRequest)?;
    Ok(ProviderV2CreateRequest {
        bundle_id: parse_bundle_id(&body.bundle_id).map_err(|_| ApiError::InvalidRequest)?,
        lock_resource,
        reader: parse_reader(&body.reader).map_err(|_| ApiError::InvalidRequest)?,
        payment,
        deadline,
    })
}

fn create_response(result: ProviderV2CreateResult) -> Result<CreateResponse, ApiError> {
    Ok(CreateResponse {
        invoice_created_at: result
            .invoice_created_at()
            .format(&Rfc3339)
            .map_err(|_| ApiError::InternalError)?,
        proposal_expires_at: result
            .proposal_expires_at()
            .format(&Rfc3339)
            .map_err(|_| ApiError::InternalError)?,
        deadline: result
            .deadline()
            .format(&Rfc3339)
            .map_err(|_| ApiError::InternalError)?,
    })
}

fn status_response(summary: ProviderV2Status) -> Result<StatusResponse, ApiError> {
    let include_rail_status = summary.asset.as_str() == "USDT";
    Ok(StatusResponse {
        creator: summary.creator,
        bundle_id: summary.bundle_id,
        request_state: summary.request_state.as_str(),
        payment_state: summary.payment_state,
        invoice_created_at: summary
            .invoice_created_at
            .format(&Rfc3339)
            .map_err(|_| ApiError::InternalError)?,
        proposal_expires_at: summary
            .proposal_expires_at
            .format(&Rfc3339)
            .map_err(|_| ApiError::InternalError)?,
        deadline: summary
            .deadline
            .format(&Rfc3339)
            .map_err(|_| ApiError::InternalError)?,
        asset: summary.asset.as_str(),
        minimum_confirmations: summary.minimum_confirmations,
        current_sample: summary.current_sample.map(sample_response).transpose()?,
        first_threshold_satisfied: summary
            .first_threshold_satisfied
            .map(sample_response)
            .transpose()?,
        bitcoin: include_rail_status.then_some(summary.bitcoin),
        usdt_arbitrum: include_rail_status.then_some(summary.usdt_arbitrum),
    })
}

fn sample_response(sample: ProviderV2Sample) -> Result<SampleResponse, ApiError> {
    Ok(SampleResponse {
        observed_at: sample
            .observed_at()
            .format(&Rfc3339)
            .map_err(|_| ApiError::InternalError)?,
        status: sample.status().as_str(),
        outpoint: sample.outpoint().map(|outpoint| OutpointResponse {
            txid: outpoint.txid().to_owned(),
            vout: outpoint.vout(),
        }),
        confirmations: sample.confirmations(),
        amount_matched: sample.amount_matched(),
    })
}

fn map_error(error: ProviderV2Error) -> ApiError {
    match error {
        ProviderV2Error::InvalidRequest => ApiError::InvalidRequest,
        ProviderV2Error::Conflict => ApiError::InvoiceConflict,
        ProviderV2Error::DeadlineElapsed => ApiError::DeadlineElapsed,
        ProviderV2Error::CreatorSessionInvalid => ApiError::CreatorSessionInvalid,
        ProviderV2Error::CreatorSessionUnavailable => ApiError::CreatorSessionUnavailable,
        ProviderV2Error::ReaderSetupPending => ApiError::ReaderSetupPending,
        ProviderV2Error::ReaderNotPayable => ApiError::ReaderNotPayable,
        ProviderV2Error::ReaderRegistryUnavailable => ApiError::ReaderRegistryUnavailable,
        ProviderV2Error::ReaderRegistryMalformed => ApiError::ReaderRegistryMalformed,
        ProviderV2Error::Unavailable => ApiError::DependencyUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
    const BUNDLE: &str = "000G40R40M30E209185GR38E1W";
    const LOCK_ID: &str = "000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG";

    fn body() -> CreateBody {
        CreateBody {
            bundle_id: BUNDLE.into(),
            lock_resource: format!("{CREATOR}/pub/app.locks/{LOCK_ID}.json"),
            reader: CREATOR.into(),
            payment: PaymentBody {
                recipient_pubky: CREATOR.into(),
                amount: "0001".into(),
                asset: "BTC".into(),
                minimum_confirmations: 6,
            },
            deadline: "2030-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn closed_create_parser_preserves_amount_lexeme_and_exact_utc_deadline() {
        let parsed = parse_create(body()).unwrap();
        assert_eq!(parsed.payment.amount_lexeme(), "0001");
        assert_eq!(parsed.payment.minimum_confirmations(), 6);
        assert_eq!(
            parsed.deadline.format(&Rfc3339).unwrap(),
            "2030-01-01T00:00:00Z"
        );
    }

    #[test]
    fn closed_create_parser_rejects_invalid_payment_and_noncanonical_time() {
        let mut invalid = body();
        invalid.payment.asset = "btc".into();
        assert_eq!(parse_create(invalid).unwrap_err(), ApiError::InvalidRequest);

        let mut invalid = body();
        invalid.payment.amount = "0".into();
        assert_eq!(parse_create(invalid).unwrap_err(), ApiError::InvalidRequest);

        let mut invalid = body();
        invalid.payment.minimum_confirmations = 7;
        assert_eq!(parse_create(invalid).unwrap_err(), ApiError::InvalidRequest);

        let mut invalid = body();
        invalid.deadline = "2030-01-01T01:00:00+01:00".into();
        assert_eq!(parse_create(invalid).unwrap_err(), ApiError::InvalidRequest);

        let mut invalid = body();
        invalid.deadline = "2030-01-01T00:00:00.000000001Z".into();
        assert_eq!(parse_create(invalid).unwrap_err(), ApiError::InvalidRequest);
    }

    #[test]
    fn exact_btc_and_usdt_wire_fixtures_parse_as_base_units() {
        let btc: CreateBody = serde_json::from_str(include_str!(
            "../../../docs/fixtures/provider-v2/create-btc.json"
        ))
        .unwrap();
        let btc = parse_create(btc).unwrap();
        assert_eq!(btc.payment.asset().as_str(), "BTC");
        assert_eq!(btc.payment.amount_units(), 1);

        let usdt: CreateBody = serde_json::from_str(include_str!(
            "../../../docs/fixtures/provider-v2/create-usdt.json"
        ))
        .unwrap();
        let usdt = parse_create(usdt).unwrap();
        assert_eq!(usdt.payment.asset().as_str(), "USDT");
        assert_eq!(usdt.payment.amount_units(), 5_000_001);
    }

    #[test]
    fn wire_bodies_reject_unknown_fields() {
        let unknown_create = format!(
            r#"{{"bundle_id":"{BUNDLE}","lock_resource":"{CREATOR}/pub/app.locks/{LOCK_ID}.json","reader":"{CREATOR}","payment":{{"recipient_pubky":"{CREATOR}","amount":"1","asset":"BTC","minimum_confirmations":0}},"deadline":"2030-01-01T00:00:00Z","unknown":true}}"#
        );
        assert!(serde_json::from_str::<CreateBody>(&unknown_create).is_err());
        assert!(
            serde_json::from_str::<StatusBody>(&format!(
                r#"{{"creator":"{CREATOR}","bundle_id":"{BUNDLE}","unknown":true}}"#
            ))
            .is_err()
        );
    }
}
