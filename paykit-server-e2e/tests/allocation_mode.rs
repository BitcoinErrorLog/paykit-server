//! Safe-subset gate for the removed legacy manual-claim endpoint.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use paykit_lib::PaykitReceiverPath;
use paykit_server::{
    chain_history::{ChainHistoryPort, ClaimScanError},
    config::{BitcoinNetwork, StackRole},
    crypto::Crypto,
    domain::locks::CreatorPubky,
    http::accounts::{AccountsState, accounts_router},
    manual_claim::{ClaimedKeyLookup, ManualClaimError, ManualClaimService, SessionMinter},
    persistence::{CreatorStore, run_migrations},
    real_setup::DirectMarkerPublisher,
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky::{Capabilities, PubkySession};
use tower::ServiceExt;

struct CountingMinter(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl SessionMinter for CountingMinter {
    async fn mint(
        &self,
        _token_bytes: &[u8],
        _capabilities: &Capabilities,
    ) -> Result<PubkySession, ManualClaimError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ManualClaimError::SessionUnavailable)
    }
}

struct CountingHistory(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ChainHistoryPort for CountingHistory {
    async fn history_presence_batch(
        &self,
        scripts: &[bitcoin::ScriptBuf],
    ) -> Result<Vec<bool>, ClaimScanError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![false; scripts.len()])
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

#[tokio::test]
async fn removed_manual_claim_returns_named_refusal_and_persists_nothing() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let minter_calls = Arc::new(AtomicUsize::new(0));
    let history_calls = Arc::new(AtomicUsize::new(0));
    let creators = CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[1; 32]).unwrap()),
    );
    let service = Arc::new(ManualClaimService::new(
        pubky::Pubky::new().unwrap(),
        Arc::new(CountingMinter(minter_calls.clone())),
        creators,
        Arc::new(UnclaimedKeys),
        Arc::new(DirectMarkerPublisher),
        Arc::new(CountingHistory(history_calls.clone())),
        BitcoinNetwork::Regtest,
        StackRole::Proof,
        "proof:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19".into(),
        PaykitReceiverPath::new("paykit/server").unwrap(),
    ));
    let router = accounts_router(AccountsState::new(service, 10, vec![]));

    let response = router
        .oneshot(
            Request::post("/v0/accounts/claim")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"ignored":"legacy payload"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "manual_claim_removed");
    assert_eq!(minter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(history_calls.load(Ordering::SeqCst), 0);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(rows, 0, "removed claims must not persist creator state");

    database.cleanup().await;
}
