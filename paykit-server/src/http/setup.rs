use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, RawQuery, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
    routing::{get, post},
};
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
        Ok(flow) => iframe_response(flow),
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

fn iframe_response(flow: StartedFlow) -> Response<Body> {
    let flow_id = json_for_script(&flow.flow_id);
    let state = json_for_script(&flow.state);
    let origin = json_for_script(&flow.origin);
    let authorization_url = html_for_text(&flow.authorization_url);
    let bitkit_action = bitkit_setup_url(&flow.authorization_url)
        .map(|url| {
            format!(
                "<p><a href=\"{}\">Open in Bitkit</a></p>",
                html_for_text(&url)
            )
        })
        .unwrap_or_default();
    let shell = format!(
        "<!doctype html><meta charset=\"utf-8\"><main><p>Paykit auth URL:</p><code>{authorization_url}</code>{bitkit_action}<p>Generate the regtest BIP84 account tpub:</p><code>npm --prefix examples/js-sdk run generate-paykit-account-tpub</code><p>Then authenticate and paste the auth URL, tpub, and account index:</p><code>docker compose exec creator-demo npm --prefix examples/js-sdk run authenticate-paykit -- --role content-creator</code></main><script>\nconst flowId={flow_id};const state={state};const targetOrigin={origin};\nconst retryable=new Set([408,425,429,502,503,504]);let delay=500;\nasync function poll(){{try{{const response=await fetch('/setup/'+flowId+'/complete',{{method:'POST'}});if(response.status===200){{window.parent.postMessage({{type:'paykit-setup-callback',state}},targetOrigin);return;}}if(!retryable.has(response.status)){{window.parent.postMessage({{type:'paykit-setup-callback',state,error:'setup-failed'}},targetOrigin);return;}}}}catch(_error){{}}setTimeout(poll,delay);delay=Math.min(delay*2,5000);}}setTimeout(poll,delay);\n</script>"
    );
    let mut response = Response::new(Body::from(shell));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!("frame-ancestors {}", flow.origin))
            .expect("validated origin is a header value"),
    );
    response
}

fn bitkit_setup_url(authorization_url: &str) -> Option<String> {
    let url = url::Url::parse(authorization_url).ok()?;
    if url.scheme() != "pubkyauth"
        || url.host_str() != Some("signin")
        || !url.path().is_empty()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return None;
    }
    url.query().filter(|query| !query.is_empty())?;
    let query_and_fragment = authorization_url.strip_prefix("pubkyauth://signin?")?;
    let query = query_and_fragment
        .split_once('#')
        .map_or(query_and_fragment, |(query, _)| query);
    if query.is_empty() || query.starts_with('?') {
        return None;
    }
    Some(format!("bitkit://pubky-auth/setup?{query}"))
}

fn html_for_text(value: &str) -> String {
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
    match result {
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
    }
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

#[cfg(test)]
mod tests {
    use super::bitkit_setup_url;

    #[test]
    fn bitkit_setup_url_preserves_the_original_encoded_query() {
        let authorization_url = "pubkyauth://signin?caps=a%2Fb&relay=https%3A%2F%2Fx&secret=s&x-bitkit-claim=watch-only-account-v1&label=<approve>";

        assert_eq!(
            bitkit_setup_url(authorization_url).as_deref(),
            Some(
                "bitkit://pubky-auth/setup?caps=a%2Fb&relay=https%3A%2F%2Fx&secret=s&x-bitkit-claim=watch-only-account-v1&label=<approve>"
            )
        );
    }

    #[test]
    fn bitkit_setup_url_preserves_duplicate_keys_and_omits_the_fragment() {
        let authorization_url = "pubkyauth://signin?caps=first&caps=second&secret=s#ignored";
        let target = bitkit_setup_url(authorization_url).expect("valid Bitkit setup target");

        assert_eq!(
            target,
            "bitkit://pubky-auth/setup?caps=first&caps=second&secret=s"
        );
        assert_eq!(target.matches('?').count(), 1);
    }

    #[test]
    fn bitkit_setup_url_requires_a_signin_query() {
        for authorization_url in [
            "pubkyauth://signin",
            "pubkyauth://signin?",
            "pubkyauth://signin??secret=s",
            "pubkyauth://signin#ignored?secret=s",
            "pubkyauth://other?secret=s",
            "pubkyauth://signin/other?secret=s",
            "pubkyauth://@signin?secret=s",
            "pubkyauth://:@signin?secret=s",
            "pubkyauth://user@signin?secret=s",
            "pubkyauth://user:password@signin?secret=s",
            "pubkyauth://signin:?secret=s",
            "pubkyauth://signin:123?secret=s",
            "https://signin?secret=s",
            "not a URL",
        ] {
            assert_eq!(
                bitkit_setup_url(authorization_url),
                None,
                "unexpected Bitkit target for {authorization_url:?}"
            );
        }
    }
}
