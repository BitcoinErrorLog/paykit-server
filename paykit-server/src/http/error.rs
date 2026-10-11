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
    DependencyUnavailable,
    DependencyTimeout,
    Conflict,
    OperationConflict,
    PrepareExpired,
    LifecycleTerminal,
    InvoiceActive,
    TotalMismatch,
    ResolutionConflict,
    RecoveryRequired,
    InvalidConflict,
    Unavailable,
    InvoiceConflict,
    InvoiceNotFound,
    InternalError,
    LockNotFound,
    LockResourceUnavailable,
    ReaderSetupPending,
    ReaderNotPayable,
    ReaderRegistryUnavailable,
    ReaderRegistryMalformed,
    SellerSetupPending,
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
    pub(crate) const fn code(self) -> &'static str {
        self.details().1
    }

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
            Self::DependencyUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_unavailable",
                "dependency is unavailable",
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
            Self::OperationConflict => (
                StatusCode::CONFLICT,
                "operation_conflict",
                "operation binding conflicts with persisted payment state",
            ),
            Self::PrepareExpired => (
                StatusCode::CONFLICT,
                "prepare_expired",
                "payment preparation expired",
            ),
            Self::LifecycleTerminal => (
                StatusCode::CONFLICT,
                "lifecycle_terminal",
                "payment lifecycle is already terminal",
            ),
            Self::InvoiceActive => (
                StatusCode::CONFLICT,
                "invoice_active",
                "invoice is already active",
            ),
            Self::TotalMismatch => (
                StatusCode::CONFLICT,
                "total_mismatch",
                "total does not match prepared payment",
            ),
            Self::ResolutionConflict => (
                StatusCode::CONFLICT,
                "resolution_conflict",
                "business resolution conflicts with persisted outcome",
            ),
            Self::RecoveryRequired => (
                StatusCode::SERVICE_UNAVAILABLE,
                "recovery_required",
                "payment request requires recovery",
            ),
            Self::InvalidConflict => (
                StatusCode::CONFLICT,
                "invalid_conflict",
                "payment request lifecycle is inconsistent",
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
            Self::LockResourceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "lock_resource_unavailable",
                "lock resource is unavailable",
            ),
            Self::ReaderSetupPending => (
                StatusCode::SERVICE_UNAVAILABLE,
                "reader_setup_pending",
                "reader wallet setup needed",
            ),
            Self::ReaderNotPayable => (
                StatusCode::CONFLICT,
                "reader_not_payable",
                "reader has no Paykit app able to pay requests",
            ),
            Self::ReaderRegistryUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "reader_registry_unavailable",
                "reader registry is unavailable",
            ),
            Self::ReaderRegistryMalformed => (
                StatusCode::BAD_GATEWAY,
                "reader_registry_malformed",
                "reader registry is malformed",
            ),
            Self::SellerSetupPending => (
                StatusCode::SERVICE_UNAVAILABLE,
                "seller_setup_pending",
                "seller Bitcoin receiving setup is needed",
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
        super::request_diagnostics::annotate(
            &mut response,
            super::request_diagnostics::OutcomeFailureClass::api(self),
        );
        response
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    #[tokio::test]
    async fn reader_registry_errors_have_closed_status_body_and_retry_contract() {
        let cases = [
            (
                ApiError::ReaderSetupPending,
                StatusCode::SERVICE_UNAVAILABLE,
                "reader_setup_pending",
                "reader wallet setup needed",
                None,
            ),
            (
                ApiError::ReaderNotPayable,
                StatusCode::CONFLICT,
                "reader_not_payable",
                "reader has no Paykit app able to pay requests",
                None,
            ),
            (
                ApiError::ReaderRegistryUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "reader_registry_unavailable",
                "reader registry is unavailable",
                None,
            ),
            (
                ApiError::ReaderRegistryMalformed,
                StatusCode::BAD_GATEWAY,
                "reader_registry_malformed",
                "reader registry is malformed",
                None,
            ),
        ];

        for (error, status, code, message, retry_after) in cases {
            let response = error.into_response();
            assert_eq!(response.status(), status);
            assert_eq!(
                response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .map(|value| value.to_str().unwrap()),
                retry_after
            );
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"error":{"code":code,"message":message}})
            );
        }
    }
}
