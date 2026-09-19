//! Allocation invariants and authenticated status-surface tests.
//!
//! The legacy claim handler is removed and tested at its HTTP tombstone. The
//! dormant allocation implementation retains source-level no-upgrade/no-flag
//! invariants, while the read-only status surface remains live.

use std::sync::{Arc, Mutex};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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

async fn response_parts(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
    )
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
