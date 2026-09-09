//! Manual watch-only account claim and existence routes.
//!
//! `POST /v0/accounts/claim` is called directly from browser marketplace
//! clients (the request body carries its own proof: a capability-scoped
//! Pubky AuthToken), so this router answers CORS preflights for the same
//! origins the setup flow allows. `GET /v0/accounts/{creator}` is a public,
//! secret-free existence lookup used by the marketplace transaction service
//! to report per-seller Bitcoin availability.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    domain::locks::parse_creator,
    http::error::ApiError,
    manual_claim::{ManualClaimError, ManualClaimRequest, ManualClaimService},
};

/// Rolling one-minute claim budget. Each claim performs a relay round-trip
/// and a homeserver session exchange, so the window is deliberately small.
struct ClaimWindow {
    budget: u64,
    admitted: VecDeque<Instant>,
}

impl ClaimWindow {
    fn new(budget: u64) -> Self {
        Self {
            budget,
            admitted: VecDeque::new(),
        }
    }

    fn try_admit(&mut self, now: Instant) -> bool {
        while self
            .admitted
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= Duration::from_secs(60))
        {
            self.admitted.pop_front();
        }
        if self.admitted.len() as u64 >= self.budget {
            return false;
        }
        self.admitted.push_back(now);
        true
    }
}

#[derive(Clone)]
pub struct AccountsState {
    service: Arc<ManualClaimService>,
    claim_limiter: Arc<Mutex<ClaimWindow>>,
    allowed_origins: Arc<Vec<String>>,
}

impl AccountsState {
    pub fn new(
        service: Arc<ManualClaimService>,
        claims_per_minute: u64,
        allowed_origins: Vec<String>,
    ) -> Self {
        Self {
            service,
            claim_limiter: Arc::new(Mutex::new(ClaimWindow::new(claims_per_minute))),
            allowed_origins: Arc::new(allowed_origins),
        }
    }
}

pub fn accounts_router(state: AccountsState) -> Router {
    let cors_state = state.clone();
    Router::new()
        .route("/v0/accounts/claim", post(claim))
        .route("/v0/accounts/{creator}", get(exists))
        .route("/v0/accounts/{creator}/status", get(allocation_status))
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimBody {
    auth_token: String,
    account_xpub: String,
    account_index: u32,
    /// The channel the Shop client asserts (design §B.8.6): `manual` or
    /// `bitkit_watch_only_v1`. Missing is treated as `manual`; any other
    /// value is refused with `unknown_claim_channel` (fail closed).
    claim_channel: Option<String>,
    /// Optional requested mode. Honored only as a refusal: `pasted_auto` is
    /// rejected unconditionally with `allocation_mode_not_enabled`
    /// (§B.8.6 r6); the server decides every accepted mode itself.
    allocation_mode: Option<String>,
}

async fn claim(State(state): State<AccountsState>, body: Json<ClaimBody>) -> Response {
    let permitted = state
        .claim_limiter
        .lock()
        .expect("claim rate limiter mutex is not poisoned")
        .try_admit(Instant::now());
    if !permitted {
        return ApiError::RateLimited.into_response();
    }
    let request = ManualClaimRequest {
        auth_token: body.0.auth_token,
        account_xpub: body.0.account_xpub,
        account_index: body.0.account_index,
        claim_channel: body.0.claim_channel,
        allocation_mode: body.0.allocation_mode,
    };
    match state.service.claim(request).await {
        Ok(outcome) => (
            StatusCode::OK,
            Json(json!({
                "status": "claimed",
                "creator": outcome.creator,
                "account_index": outcome.account_index,
                "next_child_index": outcome.next_child_index,
                "key_fingerprint": outcome.key_fingerprint,
                "first_derived_address": outcome.first_derived_address,
                "stack_id": outcome.stack_id,
                "allocation_mode": outcome.allocation_mode,
                "downgrade_reason": outcome.downgrade_reason,
            })),
        )
            .into_response(),
        Err(error) => claim_error(error),
    }
}

fn claim_error(error: ManualClaimError) -> Response {
    let (status, code, message) = match error {
        ManualClaimError::InvalidToken => (
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "auth token verification or session exchange failed",
        ),
        ManualClaimError::InvalidCapabilities => (
            StatusCode::UNAUTHORIZED,
            "invalid_capabilities",
            "auth token capabilities must exactly match the receiver-path session capabilities",
        ),
        ManualClaimError::InvalidXpub => (
            StatusCode::BAD_REQUEST,
            "invalid_xpub",
            "account xpub is not a valid BIP84 account key for this network and index",
        ),
        ManualClaimError::AccountIndexOutOfRange => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "account_index_out_of_range",
            "account index is outside the claimable range 0..=99",
        ),
        ManualClaimError::KeyDenyListed => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "key_deny_listed",
            "account key material is a known-public test-vector key and cannot be claimed",
        ),
        ManualClaimError::KeyClaimedByOtherSeller => (
            StatusCode::CONFLICT,
            "key_claimed_by_other_seller",
            "this watch-only key material is claimed by a different seller on this stack",
        ),
        ManualClaimError::AccountMismatch => (
            StatusCode::CONFLICT,
            "account_mismatch",
            "a different watch-only account is already claimed for this creator",
        ),
        ManualClaimError::ClaimScanUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "claim_scan_unavailable",
            "the claim-time address history scan could not reach Electrum; the claim was refused",
        ),
        ManualClaimError::AccountHistoryTooDeep => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "account_history_too_deep",
            "account history exceeds the claim scan bound; claim a fresh, dedicated account",
        ),
        ManualClaimError::SessionUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "session_unavailable",
            "relay or homeserver session exchange is unavailable",
        ),
        ManualClaimError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "marker publication or persistence is unavailable",
        ),
        ManualClaimError::AllocationModeNotEnabled => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "allocation_mode_not_enabled",
            "the requested allocation mode is not enabled on this stack",
        ),
        ManualClaimError::UnknownClaimChannel => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown_claim_channel",
            "claim_channel must be one of manual or bitkit_watch_only_v1 when present",
        ),
    };
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
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

/// The authenticated seller's own allocation status (design §B.8.6): the
/// mode, the claim channel recorded at claim time, the downgrade reason if
/// any, the detection evidence metadata (§B.8.7 is W1.14's, so the evidence
/// list is always empty here), and the two evidence fields the
/// Ring-verification client fails closed without — `key_fingerprint` and
/// `first_derived_address`, the same values the claim response emits. It is
/// the seller's own data about their own creator record: authentication is
/// the same capability-scoped Pubky AuthToken the claim carries (in the
/// `Authorization: Bearer` header), the token's signer must BE the addressed
/// creator, and the response carries no key material — the fingerprint is a
/// hash and the first address is what invoices reveal anyway.
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
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        return status_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "a capability-scoped auth token is required",
        );
    };
    match state.service.authenticate_claim_token(token) {
        Ok(signer) if signer == creator => {}
        Ok(_) => {
            return status_error(
                StatusCode::FORBIDDEN,
                "forbidden",
                "allocation status is visible to the addressed seller only",
            );
        }
        Err(_) => {
            return status_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "auth token verification failed",
            );
        }
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
                // canonical-78-byte-hash fingerprint and cursor address the
                // claim response emits. Not key material — the fingerprint
                // is a hash and the first address is what invoices reveal.
                "key_fingerprint": status.key_fingerprint,
                "first_derived_address": status.first_derived_address,
                // §B.8.7 detection evidence metadata: no evidence rows exist
                // until W1.14's sentinel detection records them.
                "evidence": [],
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

fn status_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}
