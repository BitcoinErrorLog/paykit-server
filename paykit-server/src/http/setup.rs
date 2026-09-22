use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use qrcode::{EcLevel, QrCode, render::svg};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};

use crate::http::claim_limiter::{client_ip, ip_prefix_key};
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
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response<Body> {
    maybe_log_client_ip_debug(&service, peer.ip(), &headers);
    let Some((return_to, state, creator)) = parse_setup_query(query.as_deref()) else {
        return invalid_request();
    };
    match service
        .begin(
            request_client_ip(&service, peer.ip(), &headers),
            &return_to,
            &state,
            &creator,
        )
        .await
    {
        Ok(flow) => match iframe_response(flow) {
            Ok(response) => response,
            Err(()) => safe_response_with_retry(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"unavailable"}),
                "1",
            ),
        },
        Err(BeginError::InvalidRequest) => invalid_request(),
        Err(BeginError::RateLimited { retry_after_secs }) => safe_response_with_retry_after(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error":"rate_limited"}),
            retry_after_secs,
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Response<Body> {
    let result = match service
        .cancel(request_client_ip(&service, peer.ip(), &headers), &flow_id)
        .await
    {
        CancelResult::Cancelled => safe_response(StatusCode::OK, json!({"status":"cancelled"})),
        CancelResult::Complete => safe_response(StatusCode::CONFLICT, json!({"error":"completed"})),
        CancelResult::Unknown => safe_response(StatusCode::NOT_FOUND, json!({"error":"not_found"})),
        CancelResult::Expired => safe_response(StatusCode::GONE, json!({"error":"expired"})),
        CancelResult::Failed => safe_response(StatusCode::CONFLICT, json!({"error":"failed"})),
        CancelResult::Completing => {
            safe_response(StatusCode::CONFLICT, json!({"error":"completing"}))
        }
        CancelResult::RateLimited => safe_response_with_retry(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error":"rate_limited"}),
            "60",
        ),
        CancelResult::Unavailable => safe_response_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"unavailable"}),
            "1",
        ),
    };
    with_no_store(result)
}

fn request_client_ip(service: &SetupService, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    client_ip(
        peer,
        service.trusted_proxy_hops(),
        header_str(headers, "x-forwarded-for"),
        header_str(headers, "x-real-ip"),
    )
}

fn client_ip_debug_enabled() -> bool {
    matches!(std::env::var("PAYKIT_DEBUG_CLIENT_IP"), Ok(value) if value == "1")
}

fn maybe_log_client_ip_debug(service: &SetupService, peer: IpAddr, headers: &HeaderMap) {
    if !client_ip_debug_enabled() {
        return;
    }
    let hops = service.trusted_proxy_hops();
    let (ipv4_prefix, ipv6_prefix) = service.claim_ip_prefixes();
    let resolved = client_ip(
        peer,
        hops,
        header_str(headers, "x-forwarded-for"),
        header_str(headers, "x-real-ip"),
    );
    let dump = ClientIpDebugDump::capture(peer, headers, hops, ipv4_prefix, ipv6_prefix, resolved);
    tracing::info!(
        target: "paykit.claim_limiter",
        x_forwarded_for_first = dump.x_forwarded_for_first.as_str(),
        x_forwarded_for_all = dump.x_forwarded_for_all.as_str(),
        x_forwarded_for_count = dump.x_forwarded_for_count,
        x_real_ip_first = dump.x_real_ip_first.as_str(),
        x_real_ip_all = dump.x_real_ip_all.as_str(),
        forwarded = dump.forwarded.as_str(),
        cf_connecting_ip = dump.cf_connecting_ip.as_str(),
        x_envoy_headers = dump.x_envoy_headers.as_str(),
        forwarding_headers = dump.forwarding_headers.as_str(),
        tcp_peer = dump.tcp_peer.as_str(),
        trusted_proxy_hops = dump.trusted_proxy_hops,
        railway_environment_set = dump.railway_environment_set,
        client_ip = dump.client_ip.as_str(),
        prefix_key = dump.prefix_key.as_str(),
        "claim client-ip debug dump"
    );
}

struct ClientIpDebugDump {
    x_forwarded_for_first: String,
    x_forwarded_for_all: String,
    x_forwarded_for_count: usize,
    x_real_ip_first: String,
    x_real_ip_all: String,
    forwarded: String,
    cf_connecting_ip: String,
    x_envoy_headers: String,
    forwarding_headers: String,
    tcp_peer: String,
    trusted_proxy_hops: u32,
    railway_environment_set: bool,
    client_ip: String,
    prefix_key: String,
}

impl ClientIpDebugDump {
    fn capture(
        peer: IpAddr,
        headers: &HeaderMap,
        trusted_proxy_hops: u32,
        ipv4_prefix: u8,
        ipv6_prefix: u8,
        resolved: IpAddr,
    ) -> Self {
        let xff_values = header_values(headers, "x-forwarded-for");
        let real_values = header_values(headers, "x-real-ip");
        Self {
            x_forwarded_for_first: header_str(headers, "x-forwarded-for")
                .unwrap_or("")
                .to_owned(),
            x_forwarded_for_all: xff_values.join(","),
            x_forwarded_for_count: xff_values.len(),
            x_real_ip_first: header_str(headers, "x-real-ip").unwrap_or("").to_owned(),
            x_real_ip_all: real_values.join(","),
            forwarded: header_str(headers, "forwarded").unwrap_or("").to_owned(),
            cf_connecting_ip: header_str(headers, "cf-connecting-ip")
                .unwrap_or("")
                .to_owned(),
            x_envoy_headers: named_headers(headers, |name| name.starts_with("x-envoy-")),
            forwarding_headers: named_headers(headers, is_client_ip_debug_header),
            tcp_peer: peer.to_string(),
            trusted_proxy_hops,
            railway_environment_set: std::env::var_os("RAILWAY_ENVIRONMENT").is_some(),
            client_ip: resolved.to_string(),
            prefix_key: ip_prefix_key(resolved, ipv4_prefix, ipv6_prefix),
        }
    }
}

fn is_client_ip_debug_header(name: &str) -> bool {
    name == "x-forwarded-for"
        || name == "x-real-ip"
        || name == "forwarded"
        || name == "cf-connecting-ip"
        || name.starts_with("x-envoy-")
        || name.contains("forwarded")
        || name.contains("real-ip")
        || name.contains("connecting-ip")
}

fn named_headers(headers: &HeaderMap, keep: impl Fn(&str) -> bool) -> String {
    let mut parts = Vec::new();
    for (name, value) in headers.iter() {
        let name = name.as_str();
        if !keep(name) {
            continue;
        }
        let value = value.to_str().unwrap_or("<non-utf8>");
        parts.push(format!("{name}={value}"));
    }
    parts.join("; ")
}

fn header_str<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn header_values<'a>(headers: &'a HeaderMap, name: &'static str) -> Vec<&'a str> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .collect()
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
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Connect Bitkit</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b0b0b;color:#f5f5f5;font-family:system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif}main{display:grid;justify-items:center;gap:1rem;max-width:32rem;margin:0 auto;padding:2rem;text-align:center}h1,p{margin:0}a{color:#f59e0b;font-weight:600}div[aria-label]{padding:1rem;background:#fff;border-radius:.75rem;line-height:0}svg{display:block;width:min(16rem,100%);height:auto}#status{color:#d4d4d4}.is-embedded{display:none}</style></head><body><main><h1 id=\"setup-title\">Connect Bitkit</h1><p><strong>Bitkit required.</strong> Pubky Ring cannot complete this setup.</p><p id=\"setup-instructions\">Scan this code with Bitkit, or open this page on your phone and tap <em>Open in Bitkit</em>.</p>",
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

fn safe_response_with_retry_after(
    status: StatusCode,
    payload: serde_json::Value,
    retry_after_secs: u64,
) -> Response<Body> {
    let mut response = safe_response(status, payload);
    let retry = retry_after_secs.max(1).to_string();
    if let Ok(value) = HeaderValue::from_str(&retry) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    #[test]
    fn debug_dump_distinguishes_first_xff_from_all_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        headers.insert("x-real-ip", HeaderValue::from_static("192.0.2.9"));
        headers.insert("forwarded", HeaderValue::from_static("for=203.0.113.10"));
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.10"));
        headers.insert(
            "x-envoy-external-address",
            HeaderValue::from_static("198.51.100.7"),
        );
        headers.insert("x-request-id", HeaderValue::from_static("not-an-ip"));
        let resolved = client_ip(
            peer(),
            1,
            header_str(&headers, "x-forwarded-for"),
            header_str(&headers, "x-real-ip"),
        );
        let dump = ClientIpDebugDump::capture(peer(), &headers, 1, 32, 64, resolved);
        assert_eq!(dump.x_forwarded_for_first, "203.0.113.10");
        assert_eq!(dump.x_forwarded_for_all, "203.0.113.10,198.51.100.7");
        assert_eq!(dump.x_forwarded_for_count, 2);
        assert_eq!(dump.client_ip, "203.0.113.10");
        assert_eq!(dump.prefix_key, "203.0.113.10/32");
        assert_eq!(dump.trusted_proxy_hops, 1);
        assert_eq!(dump.tcp_peer, "10.0.0.1");
        assert!(
            dump.forwarding_headers
                .contains("x-forwarded-for=203.0.113.10")
        );
        assert!(
            dump.forwarding_headers
                .contains("x-forwarded-for=198.51.100.7")
        );
        assert!(
            dump.x_envoy_headers
                .contains("x-envoy-external-address=198.51.100.7")
        );
        assert!(!dump.forwarding_headers.contains("x-request-id"));
        assert_eq!(dump.forwarded, "for=203.0.113.10");
        assert_eq!(dump.cf_connecting_ip, "203.0.113.10");
    }

    #[test]
    fn debug_dump_empty_headers_uses_peer_when_hops_one() {
        let headers = HeaderMap::new();
        let resolved = client_ip(peer(), 1, None, None);
        let dump = ClientIpDebugDump::capture(peer(), &headers, 1, 32, 64, resolved);
        assert_eq!(dump.x_forwarded_for_count, 0);
        assert_eq!(dump.x_forwarded_for_first, "");
        assert_eq!(dump.client_ip, "10.0.0.1");
        assert_eq!(dump.prefix_key, "10.0.0.1/32");
        assert!(dump.forwarding_headers.is_empty());
        assert!(!client_ip_debug_enabled());
    }
}
