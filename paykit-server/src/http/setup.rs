use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use qrcode::{QrCode, render::svg};
use serde_json::json;
use std::net::SocketAddr;
use url::Url;

use crate::config::BitcoinNetwork;
use crate::domain::locks::{CreatorPubky, parse_creator};
use crate::http::client_ip::client_ip;
use crate::setup::{BeginError, PollResult, SetupService, StartedFlow};

/// Setup routes keyed by the TCP peer, for a listener with no reverse proxy in front.
pub fn setup_router(service: SetupService) -> Router {
    setup_router_with_trusted_proxy_hops(service, 0)
}

/// Setup routes keyed by the client that `trusted_proxy_hops` reverse proxies forwarded; see
/// [`client_ip`].
pub fn setup_router_with_trusted_proxy_hops(
    service: SetupService,
    trusted_proxy_hops: u8,
) -> Router {
    Router::new()
        .route("/setup", get(begin))
        .route("/setup/reconnect", get(reconnect))
        .route("/setup/{flow_id}/complete", post(complete))
        .with_state(SetupRoutes {
            service,
            trusted_proxy_hops,
        })
}

#[derive(Clone)]
struct SetupRoutes {
    service: SetupService,
    trusted_proxy_hops: u8,
}

async fn begin(
    State(SetupRoutes {
        service,
        trusted_proxy_hops,
    }): State<SetupRoutes>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response<Body> {
    let Some((return_to, state, None)) = parse_setup_query(query.as_deref(), false) else {
        return invalid_request();
    };
    let client = client_ip(peer, &headers, trusted_proxy_hops);
    response_for_begin(
        service.begin(client, &return_to, &state).await,
        service.bitcoin_network(),
    )
}

async fn reconnect(
    State(SetupRoutes {
        service,
        trusted_proxy_hops,
    }): State<SetupRoutes>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response<Body> {
    let Some((return_to, state, Some(creator))) = parse_setup_query(query.as_deref(), true) else {
        return invalid_request();
    };
    let client = client_ip(peer, &headers, trusted_proxy_hops);
    response_for_begin(
        service
            .begin_reconnect(client, &return_to, &state, &creator)
            .await,
        service.bitcoin_network(),
    )
}

fn response_for_begin(
    result: Result<StartedFlow, BeginError>,
    bitcoin_network: Option<&BitcoinNetwork>,
) -> Response<Body> {
    match result {
        Ok(flow) => iframe_response(flow, bitcoin_network),
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
    State(SetupRoutes { service, .. }): State<SetupRoutes>,
    Path(flow_id): Path<String>,
) -> Response<Body> {
    response_for_poll(service.complete_and_poll(&flow_id).await)
}

fn parse_setup_query(
    query: Option<&str>,
    reconnect: bool,
) -> Option<(String, String, Option<CreatorPubky>)> {
    let mut return_to = None;
    let mut state = None;
    let mut creator = None;
    for (key, value) in url::form_urlencoded::parse(query?.as_bytes()) {
        match key.as_ref() {
            "return_to" if return_to.is_none() => return_to = Some(value.into_owned()),
            "state" if state.is_none() => state = Some(value.into_owned()),
            "creator" if reconnect && creator.is_none() => {
                creator = Some(parse_creator(&value).ok()?)
            }
            _ => return None,
        }
    }
    Some((return_to?, state?, creator))
}

fn iframe_response(flow: StartedFlow, bitcoin_network: Option<&BitcoinNetwork>) -> Response<Body> {
    let flow_id = json_for_script(&flow.flow_id);
    let state = json_for_script(&flow.state);
    let origin = json_for_script(&flow.origin);
    let authorization_url = html_for_text(&flow.authorization_url);
    // Like the plain link, the intent URL stays in the markup and out of the script source.
    let android_href = bitcoin_network
        .and_then(bitkit_android_package)
        .and_then(|package| bitkit_android_intent_url(&flow.authorization_url, package))
        .map(|intent_url| format!(" data-android-href=\"{}\"", html_for_text(&intent_url)))
        .unwrap_or_default();
    let qr_svg = render_authorization_qr_svg(&flow.authorization_url);
    let css = SETUP_CSS;
    let shell = format!(
        "<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>{css}</style><main><span class=\"qr\" data-testid=\"paykit-auth-qr\">{qr_svg}</span><a class=\"bitkit-btn\" href=\"{authorization_url}\"{android_href}>Continue with Bitkit</a></main><script>\nconst bitkitButton=document.querySelector('.bitkit-btn');if(bitkitButton.dataset.androidHref&&/Android/i.test(navigator.userAgent)){{bitkitButton.href=bitkitButton.dataset.androidHref;}}\nconst flowId={flow_id};const state={state};const targetOrigin={origin};\nconst retryable=new Set([408,425,429,502,503,504]);let delay=500;\nasync function poll(){{try{{const response=await fetch('/setup/'+flowId+'/complete',{{method:'POST'}});if(response.status===200){{window.parent.postMessage({{type:'paykit-setup-callback',state}},targetOrigin);return;}}if(!retryable.has(response.status)){{window.parent.postMessage({{type:'paykit-setup-callback',state,error:'setup-failed'}},targetOrigin);return;}}}}catch(_error){{}}setTimeout(poll,delay);delay=Math.min(delay*2,5000);}}setTimeout(poll,delay);\n</script>"
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
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!("frame-ancestors {}", flow.origin))
            .expect("validated origin is a header value"),
    );
    response
}

/// Setup shell styles. The embedding app owns the modal chrome, so this page paints only the code
/// the creator acts on.
const SETUP_CSS: &str = r#"html,body{margin:0;height:100%}
body{display:flex;align-items:center;justify-content:center;background:transparent;font:700 14px/20px system-ui,-apple-system,sans-serif;color:#d4d4db}
/* Without this the flex item shrinks to its content, so the touch button's width:100% only
   reaches the QR panel's width instead of the frame's. */
main{width:100%;display:flex;align-items:center;justify-content:center}
.qr{display:flex;align-items:center;justify-content:center;box-sizing:border-box;width:192px;height:192px;padding:12px;border-radius:8px;background:#fff}
.qr svg{display:block;width:100%;height:100%}
.bitkit-btn{display:none}

/* Touch devices cannot scan their own screen, so they get the same URL as a deep link. Keyed on the
   pointer type, not viewport width: this page renders inside a small parent iframe, which would
   always read as narrow. */
@media (hover:none) and (pointer:coarse){.qr{display:none}.bitkit-btn{display:flex;align-items:center;justify-content:center;box-sizing:border-box;width:100%;height:60px;padding:20px 32px;border-radius:9999px;background:#303034;color:#d4d4db;text-decoration:none}}
"#;

/// The QR a creator scans with Bitkit. High error correction so a centered brand badge added by the
/// embedder stays scannable.
fn render_authorization_qr_svg(authorization_url: &str) -> String {
    QrCode::with_error_correction_level(authorization_url.as_bytes(), qrcode::EcLevel::H)
        .expect("Pubky authorization URL fits QR capacity")
        .render::<svg::Color>()
        .min_dimensions(192, 192)
        // No built-in quiet zone: the white panel's padding is the margin.
        .quiet_zone(false)
        .dark_color(svg::Color("#111111"))
        .light_color(svg::Color("transparent"))
        .build()
        // Strip the XML prolog — this SVG is inlined into HTML, not served as a document.
        .replace("<?xml version=\"1.0\" standalone=\"yes\"?>", "")
        .replace(
            "<svg",
            "<svg aria-label=\"Bitkit authorization QR code\" role=\"img\"",
        )
}

/// Bitkit Android application ID per network (synonymdev/bitkit-android product flavors). Bitkit
/// ships no signet build, so signet keeps the plain link.
fn bitkit_android_package(network: &BitcoinNetwork) -> Option<&'static str> {
    match network {
        BitcoinNetwork::Mainnet => Some("to.bitkit"),
        BitcoinNetwork::Testnet => Some("to.bitkit.tnet"),
        BitcoinNetwork::Regtest => Some("to.bitkit.dev"),
        BitcoinNetwork::Signet => None,
    }
}

const PUBKYAUTH_PREFIX: &str = "pubkyauth://";

/// The `pubkyauth` hosts Bitkit Android registers.
const BITKIT_PUBKYAUTH_HOSTS: [&str; 2] = ["signin_grant", "signup_grant"];

/// Android intent URL that opens `authorization_url` only in the given Bitkit package.
///
/// Pubky Ring registers the whole `pubkyauth` scheme and an intent filter cannot match the
/// `x-bitkit-claim` parameter, so on Android the plain link opens an app chooser. Everything after
/// the scheme is kept byte for byte. Android reads the intent parameters after the last `#`, so a
/// `;` in the query is plain data, while a URL with a fragment is refused rather than rewritten.
/// Anything other than a canonical Bitkit grant URL gets no intent and keeps the plain link.
fn bitkit_android_intent_url(authorization_url: &str, package: &str) -> Option<String> {
    let rest = authorization_url.strip_prefix(PUBKYAUTH_PREFIX)?;
    let url = Url::parse(authorization_url).ok()?;
    let canonical_grant = url.as_str() == authorization_url
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url
            .host_str()
            .is_some_and(|host| BITKIT_PUBKYAUTH_HOSTS.contains(&host));
    canonical_grant
        .then(|| format!("intent://{rest}#Intent;scheme=pubkyauth;package={package};end"))
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
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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
    use super::*;

    const GRANT_URL: &str = "pubkyauth://signin_grant?caps=%2Fpub%2Fpaykit%2F%3Arw&relay=https%3A%2F%2Frelay.example%2Finbox&secret=abc-_123&x-bitkit-claim=watch-only-account-v1";

    #[test]
    fn bitkit_package_follows_the_configured_network() {
        assert_eq!(
            bitkit_android_package(&BitcoinNetwork::Mainnet),
            Some("to.bitkit")
        );
        assert_eq!(
            bitkit_android_package(&BitcoinNetwork::Testnet),
            Some("to.bitkit.tnet")
        );
        assert_eq!(
            bitkit_android_package(&BitcoinNetwork::Regtest),
            Some("to.bitkit.dev")
        );
        assert_eq!(bitkit_android_package(&BitcoinNetwork::Signet), None);
    }

    #[test]
    fn intent_url_names_the_package_and_keeps_the_grant_byte_for_byte() {
        for package in ["to.bitkit", "to.bitkit.tnet", "to.bitkit.dev"] {
            assert_eq!(
                bitkit_android_intent_url(GRANT_URL, package).as_deref(),
                Some(
                    format!(
                        "intent://{}#Intent;scheme=pubkyauth;package={package};end",
                        &GRANT_URL[PUBKYAUTH_PREFIX.len()..]
                    )
                    .as_str()
                )
            );
        }
        assert_eq!(
            bitkit_android_intent_url("pubkyauth://signup_grant/path?a=%3B%23&b=;&c", "to.bitkit")
                .as_deref(),
            Some(
                "intent://signup_grant/path?a=%3B%23&b=;&c#Intent;scheme=pubkyauth;package=to.bitkit;end"
            )
        );
    }

    #[test]
    fn intent_url_is_refused_for_anything_but_a_canonical_bitkit_grant() {
        for authorization_url in [
            "",
            "signin_grant?secret=abc",
            "https://signin_grant?secret=abc",
            "PUBKYAUTH://signin_grant?secret=abc",
            "pubkyring://signin_grant?secret=abc",
            "pubkyauth://signin?secret=abc",
            "pubkyauth:///signin_grant?secret=abc",
            "pubkyauth://signin_grant.example?secret=abc",
            "pubkyauth://user@signin_grant?secret=abc",
            "pubkyauth://signin_grant:1?secret=abc",
            "pubkyauth://signin_grant?secret=abc#Intent;package=evil.app;end",
            "pubkyauth://signin_grant?secret=abc#",
            "pubkyauth://signin_grant?label=\"><script>",
            "pubkyauth://signin_grant?label=a b",
        ] {
            assert_eq!(
                bitkit_android_intent_url(authorization_url, "to.bitkit"),
                None,
                "{authorization_url}"
            );
        }
    }
}
