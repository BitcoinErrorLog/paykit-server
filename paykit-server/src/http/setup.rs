use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, RawQuery, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use qrcode::{EcLevel, QrCode, render::svg};
use serde_json::json;
use std::net::SocketAddr;

use crate::setup::{BeginError, PollResult, SetupService, StartedFlow};

pub fn setup_router(service: SetupService) -> Router {
    Router::new()
        .route("/setup", get(begin))
        .route("/setup/{flow_id}/complete", post(complete))
        .with_state(service)
}

async fn begin(
    State(service): State<SetupService>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    RawQuery(query): RawQuery,
) -> Response<Body> {
    let Some((return_to, state)) = parse_setup_query(query.as_deref()) else {
        return invalid_request();
    };
    match service.begin(peer.ip(), &return_to, &state).await {
        Ok(flow) => match iframe_response(flow) {
            Ok(response) => response,
            Err(()) => safe_response_with_retry(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"unavailable"}),
                "1",
            ),
        },
        Err(BeginError::InvalidRequest) => invalid_request(),
        Err(BeginError::RateLimited) => safe_response_with_retry(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error":"rate_limited"}),
            "60",
        ),
        Err(BeginError::Unavailable) => safe_response_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"unavailable"}),
            "1",
        ),
    }
}

async fn complete(
    State(service): State<SetupService>,
    Path(flow_id): Path<String>,
) -> Response<Body> {
    response_for_poll(service.complete_and_poll(&flow_id).await)
}

fn parse_setup_query(query: Option<&str>) -> Option<(String, String)> {
    let mut return_to = None;
    let mut state = None;
    for (key, value) in url::form_urlencoded::parse(query?.as_bytes()) {
        match key.as_ref() {
            "return_to" if return_to.is_none() => return_to = Some(value.into_owned()),
            "state" if state.is_none() => state = Some(value.into_owned()),
            _ => return None,
        }
    }
    Some((return_to?, state?))
}

fn iframe_response(flow: StartedFlow) -> Result<Response<Body>, ()> {
    let flow_id = json_for_script(&flow.flow_id);
    let state = json_for_script(&flow.state);
    let origin = json_for_script(&flow.origin);
    let authorization_url = html_for_attribute(&flow.authorization_url);
    let qr_svg = qr_code_svg(&flow.authorization_url)?;
    let mut shell = String::from(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Connect Bitkit</title></head><body><main><h1>Connect Bitkit</h1><p>Scan this code with Bitkit, or open this page on your phone and tap <em>Open in Bitkit</em>.</p><p><a href=\"",
    );
    shell.push_str(&authorization_url);
    shell.push_str("\">Open in Bitkit</a></p><div aria-label=\"Bitkit connection QR code\">");
    shell.push_str(&qr_svg);
    shell.push_str(
        "</div><p>Bitkit 2.5 or newer is required.</p><p id=\"status\" role=\"status\" aria-live=\"polite\">Waiting for Bitkit…</p><p><a id=\"restart\" hidden>Start again</a></p></main><script>\nconst flowId=",
    );
    shell.push_str(&flow_id);
    shell.push_str(";const state=");
    shell.push_str(&state);
    shell.push_str(";const targetOrigin=");
    shell.push_str(&origin);
    shell.push_str(
        ";\nconst status=document.getElementById('status');const restart=document.getElementById('restart');const retryable=new Set([408,425,429,502,503,504]);const waitLimit=6*60*1000;let delay=500;let finished=false;\nfunction finish(){finished=true;}\nfunction stopWaiting(){if(finished)return;finished=true;status.textContent='No approval received. Update Bitkit to 2.5 or newer and start again.';restart.href=window.location.pathname+window.location.search;restart.hidden=false;}\nsetTimeout(stopWaiting,waitLimit);\nasync function poll(){if(finished)return;try{const response=await fetch('/setup/'+flowId+'/complete',{method:'POST'});if(response.status===200){finish();status.textContent='Connected';window.parent.postMessage({type:'paykit-setup-callback',state},targetOrigin);return;}if(!retryable.has(response.status)){finish();status.textContent='Setup failed… try again';window.parent.postMessage({type:'paykit-setup-callback',state,error:'setup-failed'},targetOrigin);return;}}catch(_error){}if(!finished){setTimeout(poll,delay);delay=Math.min(delay*2,5000);}}setTimeout(poll,delay);\n</script></body></html>",
    );
    let mut response = Response::new(Body::from(shell));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!("frame-ancestors {}", flow.origin))
            .expect("validated origin is a header value"),
    );
    Ok(response)
}

fn html_for_attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn qr_code_svg(value: &str) -> Result<String, ()> {
    let code = QrCode::with_error_correction_level(value.as_bytes(), EcLevel::M).map_err(|_| ())?;
    Ok(code.render::<svg::Color>().min_dimensions(256, 256).build())
}

fn json_for_script(value: &str) -> String {
    serde_json::to_string(value)
        .expect("strings serialize")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn response_for_poll(result: PollResult) -> Response<Body> {
    let mut response = match result {
        PollResult::Complete => safe_response(StatusCode::OK, json!({"status":"complete"})),
        PollResult::PendingTimeout => {
            safe_response(StatusCode::REQUEST_TIMEOUT, json!({"status":"pending"}))
        }
        PollResult::Unknown => safe_response(StatusCode::NOT_FOUND, json!({"error":"not_found"})),
        PollResult::Expired => safe_response(StatusCode::GONE, json!({"error":"expired"})),
        PollResult::Failed => safe_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"error":"setup_failed"}),
        ),
        PollResult::Overloaded => safe_response_with_retry(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error":"overloaded"}),
            "60",
        ),
        PollResult::Unavailable => safe_response_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"unavailable"}),
            "1",
        ),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn invalid_request() -> Response<Body> {
    safe_response(StatusCode::BAD_REQUEST, json!({"error":"invalid_request"}))
}

fn safe_response(status: StatusCode, payload: serde_json::Value) -> Response<Body> {
    let mut response = Response::new(Body::from(payload.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn safe_response_with_retry(
    status: StatusCode,
    payload: serde_json::Value,
    retry_after: &'static str,
) -> Response<Body> {
    let mut response = safe_response(status, payload);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static(retry_after));
    response
}
