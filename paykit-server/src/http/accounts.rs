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
        .layer(middleware::from_fn(
            move |request: axum::extract::Request, next: Next| {
                let state = cors_state.clone();
                async move { apply_cors(state, request, next).await }
            },
        ))
        .with_state(state)
}

/// Minimal CORS for the browser-called claim route: exact-origin (or `*`)
/// allow-listing shared with the setup flow's configured origins.
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
            HeaderValue::from_static("content-type"),
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
    };
    match state.service.claim(request).await {
        Ok(outcome) => (
            StatusCode::OK,
            Json(json!({
                "status": "claimed",
                "creator": outcome.creator,
                "account_index": outcome.account_index,
                "next_child_index": outcome.next_child_index,
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
