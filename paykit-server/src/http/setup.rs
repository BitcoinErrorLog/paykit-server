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

use crate::setup::{BeginError, CancelResult, PollResult, SetupService, StartedFlow};

pub fn setup_router(service: SetupService) -> Router {
    Router::new()
        .route("/setup", get(begin))
        .route("/setup/{flow_id}/cancel", post(cancel))
        .route("/setup/{flow_id}/complete", post(complete))
        .with_state(service)
}

async fn begin(
    State(service): State<SetupService>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    RawQuery(query): RawQuery,
) -> Response<Body> {
    let Some((return_to, state, creator)) = parse_setup_query(query.as_deref()) else {
        return invalid_request();
    };
    match service.begin(peer.ip(), &return_to, &state, &creator).await {
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

async fn cancel(
    State(service): State<SetupService>,
    Path(flow_id): Path<String>,
) -> Response<Body> {
    let result = match service.cancel(&flow_id).await {
        CancelResult::Cancelled => safe_response(StatusCode::OK, json!({"status":"cancelled"})),
        CancelResult::Complete => safe_response(StatusCode::CONFLICT, json!({"error":"completed"})),
        CancelResult::Unknown => safe_response(StatusCode::NOT_FOUND, json!({"error":"not_found"})),
        CancelResult::Expired => safe_response(StatusCode::GONE, json!({"error":"expired"})),
        CancelResult::Failed => safe_response(StatusCode::CONFLICT, json!({"error":"failed"})),
        CancelResult::Completing => {
            safe_response(StatusCode::CONFLICT, json!({"error":"completing"}))
        }
        CancelResult::Unavailable => safe_response_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"unavailable"}),
            "1",
        ),
    };
    with_no_store(result)
}

fn parse_setup_query(query: Option<&str>) -> Option<(String, String, String)> {
    let mut return_to = None;
    let mut state = None;
    let mut creator = None;
    for (key, value) in url::form_urlencoded::parse(query?.as_bytes()) {
        match key.as_ref() {
            "return_to" if return_to.is_none() => return_to = Some(value.into_owned()),
            "state" if state.is_none() => state = Some(value.into_owned()),
            "creator" if creator.is_none() => creator = Some(value.into_owned()),
            _ => return None,
        }
    }
    Some((return_to?, state?, creator?))
}

fn iframe_response(flow: StartedFlow) -> Result<Response<Body>, ()> {
    let flow_id = json_for_script(&flow.flow_id);
    let state = json_for_script(&flow.state);
    let origin = json_for_script(&flow.origin);
    let authorization_url = html_for_attribute(&flow.authorization_url);
    let qr_svg = qr_code_svg(&flow.authorization_url)?;
    let mut shell = String::from(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Connect Bitkit</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b0b0b;color:#f5f5f5;font-family:system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif}main{display:grid;justify-items:center;gap:1rem;max-width:32rem;margin:0 auto;padding:2rem;text-align:center}h1,p{margin:0}a{color:#f59e0b;font-weight:600}div[aria-label]{padding:1rem;background:#fff;border-radius:.75rem;line-height:0}svg{display:block;width:min(16rem,100%);height:auto}#status{color:#d4d4d4}.is-embedded{display:none}</style></head><body><main><h1 id=\"setup-title\">Connect Bitkit</h1><p id=\"setup-instructions\">Scan this code with Bitkit, or open this page on your phone and tap <em>Open in Bitkit</em>.</p>",
    );
    shell.push_str("<p><a href=\"");
    shell.push_str(&authorization_url);
    shell.push_str("\">Open in Bitkit</a></p><div aria-label=\"Bitkit connection QR code\">");
    shell.push_str(&qr_svg);
    shell.push_str(
        "</div><p>Bitkit 2.5 or newer is required.</p><p id=\"status\" role=\"status\" aria-live=\"polite\">Waiting for Bitkit…</p><p><a id=\"restart\" hidden>Start again</a></p></main><script>\nif(window.location.hash==='#embed'){document.getElementById('setup-title')?.classList.add('is-embedded');document.getElementById('setup-instructions')?.classList.add('is-embedded');}\nconst flowId=",
    );
    shell.push_str(&flow_id);
    shell.push_str(";const state=");
    shell.push_str(&state);
    shell.push_str(";const targetOrigin=");
    shell.push_str(&origin);
    shell.push_str(
        ";\nconst status=document.getElementById('status');const restart=document.getElementById('restart');const retryable=new Set([408,425,429,502,503,504]);const waitLimit=6*60*1000;let delay=500;let finished=false;\nfunction finish(){finished=true;}\nfunction stopWaiting(){if(finished)return;finished=true;status.textContent='No approval received. Update Bitkit to 2.5 or newer and start again.';restart.href=window.location.pathname+window.location.search+window.location.hash;restart.hidden=false;}\nsetTimeout(stopWaiting,waitLimit);\nasync function poll(){if(finished)return;try{const response=await fetch('/setup/'+flowId+'/complete',{method:'POST'});if(response.status===200){finish();status.textContent='Connected';window.parent.postMessage({type:'paykit-setup-callback',state},targetOrigin);return;}if(response.status===409){finish();status.textContent='Setup failed… identity mismatch';window.parent.postMessage({type:'paykit-setup-callback',state,error:'identity-mismatch'},targetOrigin);return;}if(!retryable.has(response.status)){finish();status.textContent='Setup failed… try again';window.parent.postMessage({type:'paykit-setup-callback',state,error:'setup-failed'},targetOrigin);return;}}catch(_error){}if(!finished){setTimeout(poll,delay);delay=Math.min(delay*2,5000);}}setTimeout(poll,delay);\n</script></body></html>",
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
    let response = match result {
        PollResult::Complete => safe_response(StatusCode::OK, json!({"status":"complete"})),
        PollResult::IdentityMismatch => {
            safe_response(StatusCode::CONFLICT, json!({"status":"identity_mismatch"}))
        }
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
    with_no_store(response)
}

fn with_no_store(mut response: Response<Body>) -> Response<Body> {
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
