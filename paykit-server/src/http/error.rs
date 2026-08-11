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
    Conflict,
    Unavailable,
    InvoiceConflict,
    InvoiceNotFound,
    InternalError,
    LockNotFound,
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
            Self::Conflict => (
                StatusCode::CONFLICT,
                "conflict",
                "request conflicts with persisted payment state",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "payment request state is unavailable",
            ),
            Self::InvoiceConflict => (
                StatusCode::CONFLICT,
                "invoice_conflict",
                "invoice binding conflicts with an existing invoice",
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
