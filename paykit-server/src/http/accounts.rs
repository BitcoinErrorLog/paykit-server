//! Account existence, status, and legacy-claim refusal routes.
//!
//! `POST /v0/accounts/claim` is retained only as an explicit fail-closed
//! tombstone. The legacy flow minted cookie sessions that rc55 cannot use for
//! private Paykit operations, so every request is refused before parsing,
//! rate limiting, session minting, marker publication, or persistence.
//! `GET /v0/accounts/{creator}` remains the public, secret-free existence
//! lookup used by the marketplace transaction service.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    domain::locks::parse_creator, http::error::ApiError, manual_claim::ManualClaimService,
};

#[derive(Clone)]
pub struct AccountsState {
    service: Arc<ManualClaimService>,
    allowed_origins: Arc<Vec<String>>,
}

impl AccountsState {
    pub fn new(
        service: Arc<ManualClaimService>,
        _claims_per_minute: u64,
        allowed_origins: Vec<String>,
    ) -> Self {
        Self {
            service,
            allowed_origins: Arc::new(allowed_origins),
        }
    }
}

pub fn accounts_router(state: AccountsState) -> Router {
    let cors_state = state.clone();
    Router::new()
        .route("/v0/accounts/claim", post(manual_claim_removed))
        .route("/v0/accounts/{creator}", get(exists))
        .route("/v0/accounts/{creator}/status", get(allocation_status))
        .route(
            "/v0/accounts/{creator}/alerts/acknowledge",
            post(acknowledge_alert),
        )
        .layer(middleware::from_fn(
            move |request: axum::extract::Request, next: Next| {
                let state = cors_state.clone();
                async move { apply_cors(state, request, next).await }
            },
        ))
        .with_state(state)
}

/// Minimal CORS for the browser-called claim and status routes: exact-origin
/// (or `*`) allow-listing shared with the setup flow's configured origins.
/// The allowed headers cover the JSON claim body (`content-type`) and the
/// status endpoint's bearer token (`authorization`); the allowed-origin
/// policy itself is unchanged by the header list.
async fn apply_cors(state: AccountsState, request: axum::extract::Request, next: Next) -> Response {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let allowed = origin.as_deref().and_then(|origin| {
        state
            .allowed_origins
            .iter()
            .find(|entry| entry.as_str() == "*" || entry.as_str() == origin)
            .map(|entry| {
                if entry.as_str() == "*" {
                    "*".to_owned()
                } else {
                    origin.to_owned()
                }
            })
    });
    let mut response = if request.method() == Method::OPTIONS {
        match &allowed {
            Some(_) => StatusCode::NO_CONTENT.into_response(),
            None => StatusCode::FORBIDDEN.into_response(),
        }
    } else {
        next.run(request).await
    };
    if let Some(allowed) = allowed
        && let Ok(value) = HeaderValue::from_str(&allowed)
    {
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("content-type, authorization"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    response
}

async fn manual_claim_removed() -> Response {
    status_error(
        StatusCode::GONE,
        "manual_claim_removed",
        "legacy manual account claims were removed; connect with Bitkit setup",
    )
}

async fn exists(State(state): State<AccountsState>, Path(creator): Path<String>) -> Response {
    let creator = match parse_creator(&creator) {
        Ok(creator) => creator,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    match state.service.account_exists(&creator).await {
        Ok(claimed) => (StatusCode::OK, Json(json!({ "claimed": claimed }))).into_response(),
        Err(_) => ApiError::InternalError.into_response(),
    }
}

/// Authenticates the owner-only surfaces (status, alert acknowledgement):
/// the same capability-scoped Pubky AuthToken the claim carries in the
/// `Authorization: Bearer` header, whose signer must BE the addressed
/// creator. 401 unauthenticated, 403 for any other authenticated identity.
/// Returns the error response boxed (the `Err` variant would otherwise
/// dominate the `Result` size).
fn authenticate_owner(
    state: &AccountsState,
    creator: &crate::domain::locks::CreatorPubky,
    headers: &axum::http::HeaderMap,
) -> Result<(), Box<Response>> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        return Err(Box::new(status_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "a capability-scoped auth token is required",
        )));
    };
    match state.service.authenticate_claim_token(token) {
        Ok(signer) if &signer == creator => Ok(()),
        Ok(_) => Err(Box::new(status_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this surface is visible to the addressed seller only",
        ))),
        Err(_) => Err(Box::new(status_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "auth token verification failed",
        ))),
    }
}

/// The authenticated seller's own allocation status (design §B.8.6): the
/// mode, the claim channel recorded at claim time, the downgrade reason if
/// any, the §B.8.7 sentinel detection evidence metadata (W1.14), the
/// durable sentinel alerts (W1.14), and the two evidence fields the
/// Ring-verification client fails closed without — `key_fingerprint` and
/// `first_derived_address`, the same values the claim response emits. It is
/// the seller's own data about their own creator record: authentication is
/// the same capability-scoped Pubky AuthToken the claim carries (in the
/// `Authorization: Bearer` header), the token's signer must BE the
/// addressed creator, and the response carries no key material — the
/// fingerprint is a hash and the evidence rows are the seller's own account
/// data.
/// 401 unauthenticated, 403 for any other authenticated identity.
async fn allocation_status(
    State(state): State<AccountsState>,
    Path(creator): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let creator = match parse_creator(&creator) {
        Ok(creator) => creator,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    if let Err(error) = authenticate_owner(&state, &creator, &headers) {
        return *error;
    }
    match state.service.allocation_status(&creator).await {
        Ok(Some(status)) => (
            StatusCode::OK,
            Json(json!({
                "creator": creator.to_string(),
                "allocation_mode": status.allocation_mode,
                "claim_channel": status.claim_channel,
                "downgrade_reason": status.downgrade_reason,
                // The Ring-verification client's required evidence: the same
                // canonical-78-byte-hash fingerprint and claim-time address
                // the claim response emits. Not key material — the
                // fingerprint is a hash and the first address is what
                // invoices reveal.
                "key_fingerprint": status.key_fingerprint,
                "first_derived_address": status.first_derived_address,
                // The derivation coordinates (W1.13 r3): with its own xpub
                // the client re-derives `first_derived_address` at
                // (`account_index`, `first_child_index`) — the immutable
                // claim-time index, equal to the claim response's value
                // forever. `next_child_index` is informational: invoice
                // allocation moves it.
                "account_index": status.account_index,
                "first_child_index": status.first_child_index,
                "next_child_index": status.next_child_index,
                // §B.8.7 detection evidence metadata (W1.14): the seller's
                // own durable sentinel rows — classification, derivation
                // index, address, txid:vout, value, confirmation status and
                // observation timestamps. Fixed field names; no
                // attacker- or server-supplied text is interpolated.
                "evidence": status.evidence.iter().map(|row| json!({
                    "classification": row.classification,
                    "derivation_index": row.derivation_index,
                    "address": row.address,
                    "outpoint": row.outpoint,
                    "value_sats": row.value_sats,
                    "confirmations": row.confirmations,
                    "first_observed_at": row.first_observed_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                    "last_observed_at": row.last_observed_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                })).collect::<Vec<_>>(),
                // The durable, unread/acknowledgeable §B.8.7 seller alert
                // (W1.14): at most one row, on the mode transition only.
                // Stable identifiers and timestamps only — no address,
                // xpub, outpoint or value is ever interpolated. `acknowledged_at`
                // is null while UNREAD; POST
                // /v0/accounts/{creator}/alerts/acknowledge sets it once.
                // Status polling is the delivery mechanism (no push
                // channel exists); W1.16 renders it.
                "alerts": status.alerts.iter().map(|alert| json!({
                    "event_kind": alert.event_kind,
                    "reason": alert.reason,
                    "created_at": alert.created_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                    "acknowledged_at": alert.acknowledged_at
                        .map(|at| at.format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default()),
                })).collect::<Vec<_>>(),
            })),
        )
            .into_response(),
        Ok(None) => status_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "no watch-only account is claimed for this seller",
        ),
        Err(_) => ApiError::InternalError.into_response(),
    }
}

/// The seller's durable acknowledgement of a sentinel alert (W1.14). The
/// alert is delivered by the status surface above (status polling is the
/// only delivery mechanism — no push channel exists); this endpoint is the
/// owner's read receipt. It accepts exactly the fixed event-kind
/// vocabulary (`sentinel_downgrade`), is idempotent (the first receipt
/// stands; acknowledging twice changes nothing), and is owner-only with
/// the same bearer authentication as the status surface: 401
/// unauthenticated, 403 for any other authenticated identity. No
/// address/xpub/outpoint/value is accepted or returned — the body carries
/// the fixed kind only.
async fn acknowledge_alert(
    State(state): State<AccountsState>,
    Path(creator): Path<String>,
    headers: axum::http::HeaderMap,
    body: Json<AcknowledgeBody>,
) -> Response {
    let creator = match parse_creator(&creator) {
        Ok(creator) => creator,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    if body.event_kind != crate::sentinel::SENTINEL_EVENT_KIND_DOWNGRADE {
        return ApiError::InvalidRequest.into_response();
    }
    if let Err(error) = authenticate_owner(&state, &creator, &headers) {
        return *error;
    }
    match state
        .service
        .acknowledge_sentinel_alert(&creator, &body.event_kind)
        .await
    {
        Ok(acknowledged) => (
            StatusCode::OK,
            Json(json!({ "acknowledged": acknowledged })),
        )
            .into_response(),
        Err(_) => ApiError::InternalError.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgeBody {
    event_kind: String,
}

fn status_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}
