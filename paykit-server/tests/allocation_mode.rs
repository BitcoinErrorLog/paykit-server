//! Claim-channel allocation checks (design §B.8.6, W1.13) — handler-level
//! and invariant tests.
//!
//! The behavioural 200-level assertions (accepted downgrades, `exclusive`
//! grants, re-claim keep-or-downgrade, the owner 200 on the status surface)
//! are in the e2e suite, which drives the real session minter, marker
//! publication and Postgres. These tests pin everything provable without a
//! homeserver: the unconditional `pasted_auto` refusal matrix, the
//! channel-scoped declared-vs-hardened cross-check, the zero-extra-Electrum
//! -call budget of the corroborating checks, the status surface's 401/403,
//! and the grep-level no-upgrade/no-flag invariants.

use std::sync::{Arc, Mutex};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use paykit_lib::PaykitReceiverPath;
use paykit_sdk::PaykitSdkConfig;
use paykit_server::{
    chain_history::{ChainHistoryPort, ClaimScanError},
    config::{BitcoinNetwork, StackRole},
    crypto::Crypto,
    domain::locks::CreatorPubky,
    http::accounts::{AccountsState, accounts_router},
    manual_claim::{ClaimedKeyLookup, ManualClaimError, ManualClaimService, SessionMinter},
    persistence::CreatorStore,
    real_setup::DirectMarkerPublisher,
};
use pubky::{AuthToken, Capabilities, Keypair, PubkySession};
use tower::ServiceExt;

struct RefusingMinter;

#[async_trait::async_trait]
impl SessionMinter for RefusingMinter {
    async fn mint(
        &self,
        _token_bytes: &[u8],
        _capabilities: &Capabilities,
    ) -> Result<PubkySession, ManualClaimError> {
        Err(ManualClaimError::SessionUnavailable)
    }
}

struct UnclaimedKeys;

#[async_trait::async_trait]
impl ClaimedKeyLookup for UnclaimedKeys {
    async fn key_tail_claimed_by_other(
        &self,
        _key_tail: &[u8; 65],
        _creator: &CreatorPubky,
    ) -> Result<bool, ManualClaimError> {
        Ok(false)
    }
}

/// Scripted claim-scan port with an exact call counter: the corroborating
/// checks must add ZERO Electrum calls beyond the §B.5 scan.
struct ScriptedHistory {
    calls: Mutex<usize>,
    /// Reports usage in window 0 (so the scan needs a second window and
    /// `saw_history` is true).
    used_in_first_window: bool,
}

#[async_trait::async_trait]
impl ChainHistoryPort for ScriptedHistory {
    async fn history_presence_batch(
        &self,
        scripts: &[bitcoin::ScriptBuf],
    ) -> Result<Vec<bool>, ClaimScanError> {
        let window = {
            let mut calls = self.calls.lock().unwrap();
            let window = *calls;
            *calls += 1;
            window
        };
        Ok(scripts
            .iter()
            .map(|_| self.used_in_first_window && window == 0)
            .collect())
    }
}

fn regtest_account_tpub(account_index: u32) -> String {
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Regtest, &[7; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(account_index).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account).to_string()
}

fn required_capabilities() -> String {
    PaykitSdkConfig::new(PaykitReceiverPath::new("paykit/server").unwrap())
        .required_session_capabilities()
}

fn claim_router(stack_role: StackRole, history: Arc<ScriptedHistory>) -> axum::Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://127.0.0.1:1/paykit")
        .unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let service = Arc::new(ManualClaimService::new(
        pubky::Pubky::new().unwrap(),
        Arc::new(RefusingMinter),
        CreatorStore::new(&pool, crypto),
        Arc::new(UnclaimedKeys),
        Arc::new(DirectMarkerPublisher),
        history,
        BitcoinNetwork::Regtest,
        stack_role,
        format!(
            "{}:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19",
            stack_role.as_str()
        ),
        PaykitReceiverPath::new("paykit/server").unwrap(),
    ));
    accounts_router(AccountsState::new(service, 100, vec![]))
}

fn claim_body(body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v0/accounts/claim")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn valid_claim_body(account_index: u32) -> serde_json::Value {
    let capabilities = Capabilities::try_from(required_capabilities().as_str()).unwrap();
    let auth_token =
        URL_SAFE_NO_PAD.encode(AuthToken::sign(&Keypair::random(), capabilities).serialize());
    serde_json::json!({
        "auth_token": auth_token,
        "account_xpub": regtest_account_tpub(account_index),
        "account_index": account_index,
    })
}

async fn response_parts(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
    )
}

// ---------------------------------------------------------------------------
// `pasted_auto`: refused unconditionally, with no enabling flag anywhere
// (design §B.8.6 r6, Sol P1). The matrix drives every channel-affecting
// knob at every value: both stack roles, every channel (missing, `manual`,
// `bitkit_watch_only_v1`, unknown), account indices 0 and 1, and an
// INVALID auth token — the refusal precedes even token verification.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pasted_auto_is_refused_unconditionally_across_every_configuration() {
    for stack_role in [StackRole::Production, StackRole::Proof] {
        for channel in [
            None,
            Some("manual"),
            Some("bitkit_watch_only_v1"),
            Some("carrier_pigeon"),
        ] {
            for account_index in [0u32, 1] {
                for valid_token in [true, false] {
                    let history = Arc::new(ScriptedHistory {
                        calls: Mutex::new(0),
                        used_in_first_window: false,
                    });
                    let router = claim_router(stack_role, history.clone());
                    let mut body = valid_claim_body(account_index);
                    if !valid_token {
                        body["auth_token"] = serde_json::json!("not-a-token");
                    }
                    if let Some(channel) = channel {
                        body["claim_channel"] = serde_json::json!(channel);
                    }
                    body["allocation_mode"] = serde_json::json!("pasted_auto");

                    let (status, body) =
                        response_parts(router.oneshot(claim_body(body)).await.unwrap()).await;

                    assert_eq!(
                        (status, body["error"]["code"].as_str()),
                        (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Some("allocation_mode_not_enabled")
                        ),
                        "role={stack_role:?} channel={channel:?} index={account_index} valid_token={valid_token}"
                    );
                    assert_eq!(
                        *history.calls.lock().unwrap(),
                        0,
                        "the refusal precedes the scan: zero Electrum calls"
                    );
                }
            }
        }
    }
}

/// Grep-level: no configuration, environment or code path can ENABLE
/// `pasted_auto`. The only source-tree mentions of the string are the
/// refusal constant, the refusal check, the schema's CHECK constraint (the
/// design keeps the value addressable, §B.8.6 r6), and tests.
#[test]
fn no_enabling_flag_for_pasted_auto_exists_anywhere() {
    let crate_root = env!("CARGO_MANIFEST_DIR");
    // The runtime configuration surface must not mention allocation at all.
    let config =
        std::fs::read_to_string(format!("{crate_root}/src/config.rs")).expect("read config.rs");
    assert!(
        !config.to_ascii_lowercase().contains("allocation"),
        "config.rs must carry no allocation knob"
    );
    // Every `pasted_auto` mention in src/ must be one of the three sanctioned
    // sites: the constant definition, the refusal comparison, or a comment/doc.
    let mut constructing_mentions = Vec::new();
    for entry in std::fs::read_dir(format!("{crate_root}/src"))
        .expect("read src dir")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read source");
        for (line_number, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.contains("pasted_auto") {
                continue;
            }
            let sanctioned = trimmed.starts_with("//")
                || trimmed.starts_with("///")
                || trimmed.starts_with('*')
                || trimmed.contains("REQUESTED_MODE_PASTED_AUTO")
                || trimmed.contains("\"pasted_auto\"");
            if !sanctioned {
                constructing_mentions.push(format!("{}:{}", path.display(), line_number + 1));
            }
        }
    }
    assert!(
        constructing_mentions.is_empty(),
        "unsanctioned `pasted_auto` code paths: {constructing_mentions:?}"
    );
}

// ---------------------------------------------------------------------------
// The channel-scoped declared-vs-hardened cross-check (§B.8.6): a refusal
// under paste, a downgrade under `bitkit_watch_only_v1`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_mismatched_declared_index_is_refused_on_paste_but_downgraded_on_the_bitkit_channel() {
    // Paste: the §B.6 refusal is unchanged, before any Electrum call.
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        used_in_first_window: false,
    });
    let router = claim_router(StackRole::Production, history.clone());
    let mut body = valid_claim_body(2);
    body["account_index"] = serde_json::json!(4); // key is account 2
    let (status, body) = response_parts(router.oneshot(claim_body(body)).await.unwrap()).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_xpub"))
    );
    assert_eq!(*history.calls.lock().unwrap(), 0);

    // Bitkit channel: NOT refused — the claim is downgraded
    // (account_index_mismatch) and proceeds on the key's own index through
    // exactly the §B.5 scan (one window, one batched call) to the session
    // boundary. The accepted 200 + reason is asserted in the e2e suite.
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        used_in_first_window: false,
    });
    let router = claim_router(StackRole::Production, history.clone());
    let mut body = valid_claim_body(2);
    body["account_index"] = serde_json::json!(4);
    body["claim_channel"] = serde_json::json!("bitkit_watch_only_v1");
    let (status, body) = response_parts(router.oneshot(claim_body(body)).await.unwrap()).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("session_unavailable")),
        "a bitkit-channel mismatch downgrades instead of refusing: {body}"
    );
    assert_eq!(
        *history.calls.lock().unwrap(),
        1,
        "the corroborating checks add zero Electrum calls beyond the scan"
    );
}

/// `account_index = 0` on the Bitkit channel downgrades rather than refuses
/// (the r4 range accepts 0; §B.8.6 downgrades it to `shared_manual`).
#[tokio::test]
async fn a_bitkit_claim_at_account_index_zero_is_downgraded_not_refused() {
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        used_in_first_window: false,
    });
    let router = claim_router(StackRole::Production, history.clone());
    let mut body = valid_claim_body(0);
    body["claim_channel"] = serde_json::json!("bitkit_watch_only_v1");
    let (status, body) = response_parts(router.oneshot(claim_body(body)).await.unwrap()).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("session_unavailable")),
        "index 0 downgrades rather than refusing: {body}"
    );
    assert_eq!(*history.calls.lock().unwrap(), 1);
}

/// Scan history downgrades rather than refuses — here the claim proceeds
/// through the full two-window scan to the session boundary, proving the
/// `account_has_history` decision consumes the scan result with no extra
/// Electrum call.
#[tokio::test]
async fn a_bitkit_claim_with_scan_history_is_downgraded_not_refused() {
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        used_in_first_window: true,
    });
    let router = claim_router(StackRole::Production, history.clone());
    let mut body = valid_claim_body(3);
    body["claim_channel"] = serde_json::json!("bitkit_watch_only_v1");
    let (status, body) = response_parts(router.oneshot(claim_body(body)).await.unwrap()).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("session_unavailable")),
        "scan history downgrades rather than refusing: {body}"
    );
    assert_eq!(
        *history.calls.lock().unwrap(),
        2,
        "exactly the two scan windows; the history check adds no Electrum call"
    );
}

/// An unknown channel is neither refused nor honored: recorded verbatim and
/// treated as manual entry (§B.8.6 — anything that is not the Bitkit
/// channel is a bare key).
#[tokio::test]
async fn an_unknown_claim_channel_is_treated_as_manual_not_refused() {
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        used_in_first_window: false,
    });
    let router = claim_router(StackRole::Production, history.clone());
    let mut body = valid_claim_body(1);
    body["claim_channel"] = serde_json::json!("carrier_pigeon");
    let (status, body) = response_parts(router.oneshot(claim_body(body)).await.unwrap()).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("session_unavailable")),
        "an unknown channel takes the manual path: {body}"
    );
    assert_eq!(*history.calls.lock().unwrap(), 1);
}

// ---------------------------------------------------------------------------
// No-upgrade invariant (design §B.8.6: "There is no edit that moves a
// creator into `exclusive`"): grep-level assertion over migrations and
// queries — no UPDATE can write `exclusive`, and no parameterized write can
// smuggle it.
// ---------------------------------------------------------------------------

#[test]
fn no_write_path_edits_a_creator_into_exclusive() {
    let crate_root = env!("CARGO_MANIFEST_DIR");
    let mut sources = Vec::new();
    let migrations = format!("{crate_root}/migrations");
    for entry in std::fs::read_dir(&migrations)
        .expect("read migrations")
        .flatten()
    {
        sources.push(entry.path());
    }
    let src = format!("{crate_root}/src");
    let mut stack = vec![std::path::PathBuf::from(src)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).expect("read src").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                sources.push(path);
            }
        }
    }
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("read source");
        let lowered = source.to_ascii_lowercase();
        assert!(
            !lowered.contains("allocation_mode = 'exclusive'"),
            "{} writes allocation_mode = 'exclusive'",
            path.display()
        );
        // No parameterized UPDATE write either: the only UPDATE that moves
        // the mode uses the 'shared_manual' literal (the keep-or-downgrade
        // rule); creation's INSERT is the sole path to 'exclusive', and its
        // value comes from decide_allocation alone.
        assert!(
            !lowered.contains("set allocation_mode = $"),
            "{} parameterizes an allocation_mode UPDATE",
            path.display()
        );
        assert!(
            !lowered.contains("set allocation_mode = case"),
            "{} computes an allocation_mode UPDATE in SQL",
            path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// The authenticated seller status surface (§B.8.6): 401 unauthenticated,
// 403 for any other authenticated identity. The owner 200 is e2e (it needs
// a real claim row).
// ---------------------------------------------------------------------------

fn status_request(creator: &str, authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(format!("/v0/accounts/{creator}/status"));
    if let Some(authorization) = authorization {
        builder = builder.header(header::AUTHORIZATION, authorization);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn the_status_surface_is_401_without_a_valid_token() {
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        used_in_first_window: false,
    });
    let router = claim_router(StackRole::Production, history);
    let creator = format!("pubky{}", Keypair::random().public_key().z32());

    // No header at all.
    let (status, body) = response_parts(
        router
            .clone()
            .oneshot(status_request(&creator, None))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_token"))
    );

    // A garbage bearer token.
    let (status, body) = response_parts(
        router
            .clone()
            .oneshot(status_request(&creator, Some("Bearer not-a-token")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_token"))
    );

    // A well-formed token with the wrong capability set.
    let wrong = Capabilities::try_from("/:rw").unwrap();
    let token = URL_SAFE_NO_PAD.encode(AuthToken::sign(&Keypair::random(), wrong).serialize());
    let (status, body) = response_parts(
        router
            .oneshot(status_request(&creator, Some(&format!("Bearer {token}"))))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_token"))
    );
}

#[tokio::test]
async fn the_status_surface_is_403_for_any_other_authenticated_identity() {
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        used_in_first_window: false,
    });
    let router = claim_router(StackRole::Production, history);
    let creator = format!("pubky{}", Keypair::random().public_key().z32());
    // A VALID claim-scoped token — signed by a DIFFERENT seller.
    let capabilities = Capabilities::try_from(required_capabilities().as_str()).unwrap();
    let token =
        URL_SAFE_NO_PAD.encode(AuthToken::sign(&Keypair::random(), capabilities).serialize());

    let (status, body) = response_parts(
        router
            .oneshot(status_request(&creator, Some(&format!("Bearer {token}"))))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );
}
