use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    InvalidRequest,
    InvalidSignature,
    PayloadTooLarge,
    RateLimited,
    CreatorSessionInvalid,
    CreatorSessionUnavailable,
    DependencyTimeout,
    InvoiceConflict,
    InvoiceBaselineInProgress,
    InvoiceNotFound,
    InternalError,
    LockNotFound,
    BitcoinCreationDisabled,
    BitcoinOfferUnavailable,
    PrepareExpired,
    InvoiceFinalized,
    ActivationTotalMismatch,
    UnknownInvoice,
    StackIdentityMismatch,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    const fn details(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
            ),
            Self::InvalidSignature => (
                StatusCode::UNAUTHORIZED,
                "invalid_signature",
                "request authentication failed",
            ),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "request body is too large",
            ),
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "request rate limit exceeded",
            ),
            Self::CreatorSessionInvalid => (
                StatusCode::CONFLICT,
                "creator_session_invalid",
                "creator session is invalid",
            ),
            Self::CreatorSessionUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "creator_session_unavailable",
                "creator session is unavailable",
            ),
            Self::DependencyTimeout => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_timeout",
                "request deadline exceeded",
            ),
            Self::InvoiceConflict => (
                StatusCode::CONFLICT,
                "invoice_conflict",
                "invoice binding conflicts with an existing invoice",
            ),
            Self::InvoiceBaselineInProgress => (
                StatusCode::CONFLICT,
                "invoice_baseline_in_progress",
                "invoice creation baseline is still resolving; retry the identical request",
            ),
            Self::InvoiceNotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "requested resource was not found",
            ),
            Self::InternalError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error",
            ),
            Self::LockNotFound => (
                StatusCode::NOT_FOUND,
                "lock_not_found",
                "lock resource was not found",
            ),
            Self::BitcoinCreationDisabled => (
                StatusCode::FORBIDDEN,
                "bitcoin_creation_disabled",
                "bitcoin payment request creation is disabled",
            ),
            Self::BitcoinOfferUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "bitcoin_offer_unavailable",
                "bitcoin offer is temporarily unavailable; retry later",
            ),
            // §B.11.3's named two-phase errors, with distinct codes so the
            // marketplace can branch without string-matching prose.
            Self::PrepareExpired => (
                StatusCode::CONFLICT,
                "prepare_expired",
                "invoice prepare window expired without activation",
            ),
            Self::InvoiceFinalized => (
                StatusCode::CONFLICT,
                "invoice_finalized",
                "invoice is finalized",
            ),
            Self::ActivationTotalMismatch => (
                StatusCode::CONFLICT,
                "activation_total_mismatch",
                "echoed total does not match the stored invoice total",
            ),
            Self::UnknownInvoice => (
                StatusCode::NOT_FOUND,
                "unknown_invoice",
                "no such invoice on this stack",
            ),
            Self::StackIdentityMismatch => (
                StatusCode::CONFLICT,
                "stack_identity_mismatch",
                "echoed stack_id is not this stack's identity",
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.details();
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody { code, message },
            }),
        )
            .into_response();
        if self == Self::RateLimited {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                "1".parse().expect("static header value"),
            );
        }
        response
    }
}

/// §B.9's fail-closed `expires_at` refusal: one `invalid_request` code with
/// a machine-readable `reason` so the marketplace can branch without
/// string-matching prose. "Missing" is the route schema's plain
/// `invalid_request`; past and over-maximum are named here.
pub fn invalid_expiry(
    reason: crate::application::create_invoice::ExpiryRefusal,
) -> Response {
    let message = match reason {
        crate::application::create_invoice::ExpiryRefusal::Past => {
            "expires_at is already in the past"
        }
        crate::application::create_invoice::ExpiryRefusal::OverMaximum => {
            "expires_at exceeds the configured maximum request expiry"
        }
    };
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": {
                "code": "invalid_request",
                "message": message,
                "reason": reason.as_str(),
            }
        })),
    )
        .into_response()
}
