use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};

use crate::{
    application::connection_status::{
        ConnectionStatusError, ConnectionStatusService, PaykitConnectionState,
    },
    domain::locks::{parse_bundle_id, parse_creator},
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct ConnectionStatusBody {
    creator: String,
    bundle_id: String,
}

#[derive(Serialize)]
struct ConnectionStatusResponse {
    state: PaykitConnectionState,
}

pub fn connection_status_router(service: Arc<ConnectionStatusService>) -> Router {
    Router::new()
        .route("/connections/status", post(status))
        .with_state(service)
}

async fn status(
    State(service): State<Arc<ConnectionStatusService>>,
    AuthenticatedJson(body): AuthenticatedJson<ConnectionStatusBody>,
) -> Response {
    let creator = match parse_creator(&body.creator) {
        Ok(creator) => creator,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let bundle_id = match parse_bundle_id(&body.bundle_id) {
        Ok(bundle_id) => bundle_id,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    match service.status(&creator, &bundle_id).await {
        Ok(state) => axum::Json(ConnectionStatusResponse { state }).into_response(),
        Err(ConnectionStatusError::NotFound) => ApiError::InvoiceNotFound.into_response(),
        Err(ConnectionStatusError::Unavailable) => ApiError::InternalError.into_response(),
    }
}
