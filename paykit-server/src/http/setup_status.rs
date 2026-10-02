use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};

use crate::{
    application::setup_status::SetupStatusService,
    domain::locks::parse_creator,
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct SetupStatusBody {
    creator: String,
}

#[derive(Serialize)]
struct SetupStatusResponse {
    status: &'static str,
}

pub fn setup_status_router(service: Arc<SetupStatusService>) -> Router {
    Router::new()
        .route("/setup/status", post(status))
        .with_state(service)
}

async fn status(
    State(service): State<Arc<SetupStatusService>>,
    AuthenticatedJson(body): AuthenticatedJson<SetupStatusBody>,
) -> Response {
    let creator = match parse_creator(&body.creator) {
        Ok(creator) => creator,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let status = service.status(&creator).await;
    axum::Json(SetupStatusResponse {
        status: status.as_str(),
    })
    .into_response()
}
