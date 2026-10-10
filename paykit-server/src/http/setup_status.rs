use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    application::setup_status::{AcceptedAsset, SetupStatusService},
    domain::locks::parse_creator,
    http::{auth::AuthenticatedJson, error::ApiError},
};

#[derive(Deserialize)]
struct SetupStatusBody {
    creator: String,
    asset: Option<String>,
    #[serde(default, deserialize_with = "present_string")]
    accepted_asset: Option<String>,
}

/// Decodes a field that may be absent but, when present, must be a string.
///
/// `Option<String>` alone maps an explicit JSON `null` to `None`, which is
/// indistinguishable from an omitted field. For `accepted_asset` that would turn
/// a malformed request into an authority-only readiness answer, so a present
/// `null` is rejected like any other non-string value.
fn present_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
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
    let asset = match body.asset {
        Some(asset) => match crate::domain::invoice::CriterionAsset::parse(&asset) {
            Ok(asset) => Some(asset),
            Err(_) => return ApiError::InvalidRequest.into_response(),
        },
        None => None,
    };
    let accepted = match body.accepted_asset {
        Some(accepted) => match AcceptedAsset::parse(&accepted) {
            Ok(accepted) => Some(accepted),
            Err(_) => return ApiError::InvalidRequest.into_response(),
        },
        None => None,
    };
    let status = match (asset, accepted) {
        (Some(asset), Some(accepted)) => {
            service
                .status_for_asset_and_accepted_asset(&creator, asset, accepted)
                .await
        }
        (Some(asset), None) => service.status_for_asset(&creator, asset).await,
        (None, Some(accepted)) => service.status_for_accepted_asset(&creator, accepted).await,
        (None, None) => service.status(&creator).await,
    };
    axum::Json(SetupStatusResponse {
        status: status.as_str(),
    })
    .into_response()
}
