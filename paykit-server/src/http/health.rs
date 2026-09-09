use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use serde::Serialize;

use crate::runtime::{ComponentState, Runtime};

#[derive(Serialize)]
struct LiveResponse {
    status: &'static str,
}
#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    postgres: &'static str,
    electrum: ElectrumResponse,
    bitcoin_creation_enabled: bool,
    bitcoin_offer_available: bool,
    electrum_tip_height: Option<u32>,
    electrum_tip_age_seconds: Option<u64>,
    paykit_delivery: &'static str,
    outbox: &'static str,
    /// Informational count of retained terminal outbox rows. Terminal rows
    /// never degrade readiness; this only surfaces the operator requeue queue.
    outbox_permanently_failed: u64,
}

#[derive(Serialize)]
struct ElectrumResponse {
    state: &'static str,
    available: bool,
    tip_height: Option<u32>,
    tip_age_secs: Option<u64>,
    last_probe_at: Option<u64>,
    genesis_ok: bool,
    overrun_targets: u64,
}

pub fn router(runtime: Arc<Runtime>) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(runtime)
}

async fn live() -> Json<LiveResponse> {
    Json(LiveResponse { status: "live" })
}

async fn ready(State(runtime): State<Arc<Runtime>>) -> impl IntoResponse {
    let report = runtime.readiness().await;
    let status = match report.status {
        ComponentState::Ready => "ready",
        ComponentState::Degraded => "degraded",
        ComponentState::NotReady => "not_ready",
    };
    let body = Json(ReadyResponse {
        status,
        postgres: report.postgres.as_str(),
        electrum: ElectrumResponse {
            state: report.electrum.as_str(),
            available: report.electrum_probe.available,
            tip_height: report.electrum_probe.tip_height,
            tip_age_secs: report.electrum_probe.tip_age_secs,
            last_probe_at: report.electrum_probe.last_probe_at,
            genesis_ok: report.electrum_probe.genesis_ok,
            overrun_targets: report.electrum_overrun_targets,
        },
        bitcoin_creation_enabled: report.bitcoin_creation_enabled,
        bitcoin_offer_available: report.bitcoin_offer_available,
        electrum_tip_height: report.electrum_probe.tip_height,
        electrum_tip_age_seconds: report.electrum_probe.tip_age_secs,
        paykit_delivery: report.paykit_delivery.as_str(),
        outbox: report.outbox.as_str(),
        outbox_permanently_failed: runtime.metrics().outbox_permanently_failed_rows(),
    });
    let code = if report.status == ComponentState::NotReady {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (code, [(header::CONTENT_TYPE, "application/json")], body)
}
