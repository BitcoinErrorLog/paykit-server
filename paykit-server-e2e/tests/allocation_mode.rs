//! End-to-end creator allocation mode (design §B.8.6, W1.13) over the exact
//! production path: real ephemeral Pubky testnet, real relay loopback
//! session minting, real marker publication, real encrypted persistence —
//! with only the Electrum claim-scan port scripted. Every accepted
//! configuration asserts its exact scan-call count, proving the four
//! corroborating checks add ZERO Electrum calls beyond the §B.5 scan.

use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use paykit_lib::{
    PaykitReceiverCapabilities, PaykitReceiverMarker, PaykitReceiverPath, PaymentAmount,
    PaymentEndpointIdentifier, PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
    PublicKey,
};
use paykit_sdk::PaykitSdkConfig;
use paykit_server::{
    application::semantic_intent::DeliveryIntentV1,
    chain_history::{ChainHistoryPort, ClaimScanError},
    config::{BitcoinNetwork, StackRole},
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    manual_claim::{
        ManualClaimError, ManualClaimRequest, ManualClaimService, RelayLoopbackSessionMinter,
    },
    persistence::{
        AtomicInvoiceInput, CreatorStore, DeploymentStore, InvoiceStore, NewReaderPayloadFactory,
        NewReaderPayloads, PersistenceError, run_migrations,
    },
    real_setup::DirectMarkerPublisher,
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{
    EphemeralTestnet,
    pubky::{AuthToken, Capabilities, Keypair},
};
use tower::ServiceExt;

static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Scripted claim-scan port (the only mocked seam), with an exact call
/// counter: the n-th batched call answers window n, reporting usage exactly
/// at the absolute external-chain child indices in `used_indices`.
struct ScriptedHistory {
    used_indices: Vec<u32>,
    calls: std::sync::Mutex<u32>,
}

impl ScriptedHistory {
    fn clean() -> Arc<Self> {
        Arc::new(Self {
            used_indices: vec![],
            calls: std::sync::Mutex::new(0),
        })
    }

    fn used(used_indices: Vec<u32>) -> Arc<Self> {
        Arc::new(Self {
            used_indices,
            calls: std::sync::Mutex::new(0),
        })
    }

    fn calls(&self) -> u32 {
        *self.calls.lock().unwrap()
    }
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
            .enumerate()
            .map(|(offset, _)| self.used_indices.contains(&(window * 20 + offset as u32)))
            .collect())
    }
}

fn account_xpub(seed: u8, account_index: u32) -> String {
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Testnet, &[seed; 32])
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

fn claim_token(keypair: &Keypair, capabilities: &str) -> String {
    let capabilities = Capabilities::try_from(capabilities).unwrap();
    URL_SAFE_NO_PAD.encode(AuthToken::sign(keypair, capabilities).serialize())
}

fn creator_of(keypair: &Keypair) -> CreatorPubky {
    parse_creator(&format!("pubky{}", keypair.public_key().z32())).unwrap()
}

fn reader_of(keypair: &Keypair) -> ReaderPubky {
    parse_reader(&format!("pubky{}", keypair.public_key().z32())).unwrap()
}

/// The marker the invoice intents reference; only its serialized shape
/// matters to the persistence path, so the noise key is a fixed valid one.
fn marker() -> PaykitReceiverMarker {
    PaykitReceiverMarker::new(
        PaykitReceiverPath::new("bitkit/wallet").unwrap(),
        PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: false,
        },
        PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap(),
    )
}

/// Real `NewReaderPayloadFactory`: the invoice store calls it with the
/// allocated child index inside the allocation transaction.
struct InvoicePayloads {
    reader: ReaderPubky,
}

impl NewReaderPayloadFactory for InvoicePayloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        let address = format!("test-address-{child_index}");
        let endpoint_intent = DeliveryIntentV1::endpoint(
            self.reader.to_string(),
            &marker(),
            PaykitReceiverPath::new("paykit/server").unwrap(),
            vec![(
                PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                PaymentEndpointPayload::new(address.clone()),
            )],
        )
        .unwrap();
        Ok(NewReaderPayloads {
            endpoint_intent,
            bitcoin_address: address,
        })
    }
}

fn payment_request_intent(reader: &ReaderPubky) -> DeliveryIntentV1 {
    DeliveryIntentV1::payment_request(
        reader.to_string(),
        &marker(),
        PaykitReceiverPath::new("paykit/server").unwrap(),
        &PaymentRequestTerms {
            amount: PaymentAmount::new("0.00000100", "BTC").unwrap(),
            payment_reference: PaymentReference::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            proposal_expires_at: None,
            recurrence: None,
            accepted_payment_endpoint_identifiers: vec![
                PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
            ],
            metadata: Default::default(),
        },
    )
    .unwrap()
}

struct Fixture {
    database: TestDatabase,
    testnet: EphemeralTestnet,
    pubky: pubky_testnet::pubky::Pubky,
    relay_inbox: url::Url,
    creators: CreatorStore,
    required_capabilities: String,
    stack_id: String,
}

async fn fixture() -> Fixture {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap();
    let testnet = EphemeralTestnet::builder()
        .postgres(postgres)
        .with_http_relay()
        .build()
        .await
        .unwrap();
    let pubky = testnet.sdk().unwrap();
    let relay_inbox = testnet.http_relay().local_url().join("inbox").unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(database.pool(), crypto);
    let receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let required_capabilities = PaykitSdkConfig::new(receiver_path).required_session_capabilities();
    let stack_id = DeploymentStore::new(database.pool())
        .stack_identity(StackRole::Proof)
        .await
        .unwrap()
        .stack_id();
    Fixture {
        database,
        testnet,
        pubky,
        relay_inbox,
        creators,
        required_capabilities,
        stack_id,
    }
}

impl Fixture {
    fn service(&self, stack_role: StackRole, history: Arc<ScriptedHistory>) -> ManualClaimService {
        ManualClaimService::new(
            self.pubky.clone(),
            Arc::new(RelayLoopbackSessionMinter::new(
                self.pubky.clone(),
                self.relay_inbox.clone(),
            )),
            self.creators.clone(),
            Arc::new(self.creators.clone()),
            Arc::new(DirectMarkerPublisher),
            history,
            BitcoinNetwork::Testnet,
            stack_role,
            self.stack_id.clone(),
            PaykitReceiverPath::new("paykit/server").unwrap(),
        )
    }

    fn router(&self, service: ManualClaimService) -> axum::Router {
        paykit_server::http::accounts::accounts_router(
            paykit_server::http::accounts::AccountsState::new(Arc::new(service), 100, vec![]),
        )
    }

    async fn seller(&self) -> Keypair {
        let keypair = Keypair::random();
        self.pubky
            .signer(keypair.clone())
            .signup(&self.testnet.homeserver_app().public_key(), None)
            .await
            .unwrap();
        keypair
    }
}

async fn post_claim(
    router: &axum::Router,
    keypair: &Keypair,
    capabilities: &str,
    xpub: &str,
    account_index: u32,
    claim_channel: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut body = serde_json::json!({
        "auth_token": claim_token(keypair, capabilities),
        "account_xpub": xpub,
        "account_index": account_index,
    });
    if let Some(channel) = claim_channel {
        body["claim_channel"] = serde_json::json!(channel);
    }
    let response = router
        .clone()
        .oneshot(
            Request::post("/v0/accounts/claim")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
    )
}

async fn get_status(
    router: &axum::Router,
    creator: &CreatorPubky,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::get(format!("/v0/accounts/{creator}/status"));
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
    )
}

/// A paste is `shared_manual`; a fully corroborated `bitkit_watch_only_v1`
/// claim is `exclusive`; the seller status surface serves the owner only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paste_is_shared_manual_bitkit_corroborated_is_exclusive_and_status_is_owner_only() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let fixture = fixture().await;

    // Seller A pastes (no claim_channel at all).
    let seller_a = fixture.seller().await;
    let history_a = ScriptedHistory::clean();
    let router_a = fixture.router(fixture.service(StackRole::Proof, history_a.clone()));
    let xpub_a = account_xpub(101, 1);
    let (status, body) = post_claim(
        &router_a,
        &seller_a,
        &fixture.required_capabilities,
        &xpub_a,
        1,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "A's paste claim: {body}");
    assert_eq!(body["allocation_mode"], "shared_manual");
    assert_eq!(body["downgrade_reason"], "claim_channel_not_bitkit");
    let claim_fingerprint_a = body["key_fingerprint"].clone();
    let claim_address_a = body["first_derived_address"].clone();
    // Every pre-existing claim response field survives.
    assert_eq!(body["status"], "claimed");
    assert_eq!(body["account_index"], 1);
    assert_eq!(body["next_child_index"], 0);
    assert_eq!(
        body["first_child_index"], 0,
        "the claim-time index is the cursor the scan left behind"
    );
    assert!(body["key_fingerprint"].is_string());
    assert!(body["first_derived_address"].is_string());
    assert_eq!(body["stack_id"], fixture.stack_id);
    assert_eq!(
        history_a.calls(),
        1,
        "one scan window, zero extra Electrum calls"
    );
    // The persisted row records the default channel and the named reason.
    let row: (String, String, String) =
        sqlx::query_as("SELECT allocation_mode, claim_channel, downgrade_reason FROM creators")
            .fetch_one(fixture.database.pool())
            .await
            .unwrap();
    assert_eq!(
        row,
        (
            "shared_manual".to_owned(),
            "manual".to_owned(),
            "claim_channel_not_bitkit".to_owned()
        )
    );

    // Seller B: bitkit_watch_only_v1, index >= 1, index agreeing, scan
    // clean, fingerprint unclaimed -> exclusive.
    let seller_b = fixture.seller().await;
    let history_b = ScriptedHistory::clean();
    let router_b = fixture.router(fixture.service(StackRole::Proof, history_b.clone()));
    let xpub_b = account_xpub(102, 2);
    let (status, body) = post_claim(
        &router_b,
        &seller_b,
        &fixture.required_capabilities,
        &xpub_b,
        2,
        Some("bitkit_watch_only_v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B's bitkit claim: {body}");
    assert_eq!(body["allocation_mode"], "exclusive");
    assert!(body["downgrade_reason"].is_null());
    let claim_fingerprint_b = body["key_fingerprint"].clone();
    let claim_address_b = body["first_derived_address"].clone();
    assert_eq!(
        history_b.calls(),
        1,
        "one scan window, zero extra Electrum calls"
    );
    let row: (String, String, Option<String>) = sqlx::query_as(
        "SELECT allocation_mode, claim_channel, downgrade_reason FROM creators WHERE claim_channel = 'bitkit_watch_only_v1'",
    )
    .fetch_one(fixture.database.pool())
    .await
    .unwrap();
    assert_eq!(row.0, "exclusive");
    assert_eq!(row.2, None);

    // The status surface: the owner gets every field...
    let creator_b = creator_of(&seller_b);
    let (status, body) = get_status(
        &router_b,
        &creator_b,
        Some(&claim_token(&seller_b, &fixture.required_capabilities)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner status: {body}");
    assert_eq!(body["creator"], creator_b.to_string());
    assert_eq!(body["allocation_mode"], "exclusive");
    assert_eq!(body["claim_channel"], "bitkit_watch_only_v1");
    assert!(body["downgrade_reason"].is_null());
    // The Ring-verification client's required evidence (it fails closed
    // without both): exactly the claim response's values for this creator.
    assert_eq!(body["key_fingerprint"], claim_fingerprint_b);
    assert_eq!(body["first_derived_address"], claim_address_b);
    // The derivation coordinates (W1.13 r3): the client re-derives
    // `first_derived_address` from its own xpub at
    // (`account_index`, `first_child_index`); `next_child_index` is
    // informational.
    assert_eq!(body["account_index"], 2);
    assert_eq!(body["first_child_index"], 0);
    assert_eq!(body["next_child_index"], 0);
    assert_eq!(body["evidence"], serde_json::json!([]));
    // No key material beyond the claim response's fields is present.
    let object = body.as_object().unwrap();
    for key in object.keys() {
        assert!(
            matches!(
                key.as_str(),
                "creator"
                    | "allocation_mode"
                    | "claim_channel"
                    | "downgrade_reason"
                    | "key_fingerprint"
                    | "first_derived_address"
                    | "account_index"
                    | "first_child_index"
                    | "next_child_index"
                    | "evidence"
            ),
            "unexpected status field: {key}"
        );
    }
    // ...any other authenticated identity gets 403...
    let (status, body) = get_status(
        &router_b,
        &creator_b,
        Some(&claim_token(&seller_a, &fixture.required_capabilities)),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );
    // ...the anonymous get 401...
    let (status, body) = get_status(&router_b, &creator_b, None).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_token"))
    );
    // ...and an authenticated seller with no claim gets 404.
    let seller_c = fixture.seller().await;
    let creator_c = creator_of(&seller_c);
    let (status, body) = get_status(
        &router_b,
        &creator_c,
        Some(&claim_token(&seller_c, &fixture.required_capabilities)),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );

    // The downgraded seller's status shows the recorded reason.
    let creator_a = creator_of(&seller_a);
    let (status, body) = get_status(
        &router_a,
        &creator_a,
        Some(&claim_token(&seller_a, &fixture.required_capabilities)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "A's status: {body}");
    assert_eq!(body["allocation_mode"], "shared_manual");
    assert_eq!(body["claim_channel"], "manual");
    assert_eq!(body["downgrade_reason"], "claim_channel_not_bitkit");
    assert_eq!(body["key_fingerprint"], claim_fingerprint_a);
    assert_eq!(body["first_derived_address"], claim_address_a);

    fixture.database.cleanup().await;
}

/// Each failed corroborating check downgrades with its exact fixed §B.8.8
/// identifier — accepted (200), never refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_failed_corroborating_check_downgrades_with_its_named_reason() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let fixture = fixture().await;

    // account_index = 0 -> account_index_zero.
    let seller = fixture.seller().await;
    let history = ScriptedHistory::clean();
    let router = fixture.router(fixture.service(StackRole::Proof, history.clone()));
    let (status, body) = post_claim(
        &router,
        &seller,
        &fixture.required_capabilities,
        &account_xpub(111, 0),
        0,
        Some("bitkit_watch_only_v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "index-0 claim: {body}");
    assert_eq!(body["allocation_mode"], "shared_manual");
    assert_eq!(body["downgrade_reason"], "account_index_zero");
    assert_eq!(history.calls(), 1, "zero extra Electrum calls");

    // Declared index disagreeing with the key's hardened child ->
    // account_index_mismatch, accepted on the key's own index.
    let seller = fixture.seller().await;
    let history = ScriptedHistory::clean();
    let router = fixture.router(fixture.service(StackRole::Proof, history.clone()));
    let xpub = account_xpub(112, 3);
    let (status, body) = post_claim(
        &router,
        &seller,
        &fixture.required_capabilities,
        &xpub,
        5,
        Some("bitkit_watch_only_v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mismatched claim: {body}");
    assert_eq!(body["allocation_mode"], "shared_manual");
    assert_eq!(body["downgrade_reason"], "account_index_mismatch");
    assert_eq!(
        body["account_index"], 3,
        "the claim proceeds on the key's own hardened child index"
    );
    assert_eq!(
        body["first_derived_address"],
        paykit_server::application::create_invoice::derive_bip84_p2wpkh_address(
            &xpub,
            3,
            &BitcoinNetwork::Testnet,
            0
        )
        .unwrap()
    );
    let persisted = fixture.creators.load(&creator_of(&seller)).await.unwrap();
    assert_eq!(persisted.account_index(), 3);
    assert_eq!(persisted.xpub(), xpub);
    assert_eq!(history.calls(), 1, "zero extra Electrum calls");

    // Any scan history at all -> account_has_history (accepted, cursor at
    // the scanned start index).
    let seller = fixture.seller().await;
    let history = ScriptedHistory::used(vec![0, 1, 2, 3]);
    let router = fixture.router(fixture.service(StackRole::Proof, history.clone()));
    let (status, body) = post_claim(
        &router,
        &seller,
        &fixture.required_capabilities,
        &account_xpub(113, 4),
        4,
        Some("bitkit_watch_only_v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "history claim: {body}");
    assert_eq!(body["allocation_mode"], "shared_manual");
    assert_eq!(body["downgrade_reason"], "account_has_history");
    assert_eq!(body["next_child_index"], 3 + 1 + 20);
    assert_eq!(
        body["first_child_index"],
        3 + 1 + 20,
        "the claim-time index is the scanned start index, not necessarily 0"
    );
    assert_eq!(
        body["first_derived_address"],
        paykit_server::application::create_invoice::derive_bip84_p2wpkh_address(
            &account_xpub(113, 4),
            4,
            &BitcoinNetwork::Testnet,
            3 + 1 + 20
        )
        .unwrap(),
        "the claim response's address derives at the claim-time index"
    );
    assert_eq!(
        history.calls(),
        2,
        "exactly the two scan windows; the history check adds no Electrum call"
    );

    fixture.database.cleanup().await;
}

/// `pasted_auto` is refused with `allocation_mode_not_enabled` under both
/// stack roles, persisting nothing (design §B.8.6 r6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pasted_auto_is_refused_under_production_and_proof_roles() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let fixture = fixture().await;
    let seller = fixture.seller().await;

    for stack_role in [StackRole::Production, StackRole::Proof] {
        let router = fixture.router(fixture.service(stack_role, ScriptedHistory::clean()));
        let mut body = serde_json::json!({
            "auth_token": claim_token(&seller, &fixture.required_capabilities),
            "account_xpub": account_xpub(121, 1),
            "account_index": 1,
            "claim_channel": "bitkit_watch_only_v1",
            "allocation_mode": "pasted_auto",
        });
        let response = router
            .oneshot(
                Request::post("/v0/accounts/claim")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            (status, body_json["error"]["code"].as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Some("allocation_mode_not_enabled")
            ),
            "role {stack_role:?}"
        );
        body["allocation_mode"] = serde_json::json!(null);
    }
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM creators")
        .fetch_one(fixture.database.pool())
        .await
        .unwrap();
    assert_eq!(rows, 0, "the refusal persists nothing");

    fixture.database.cleanup().await;
}

/// An unknown `claim_channel` is refused with `unknown_claim_channel` (fail
/// closed, §B.8.6: the field is one of `manual` | `bitkit_watch_only_v1`) —
/// never canonicalized silently, never persisted verbatim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_claim_channel_is_refused_and_persists_nothing() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let fixture = fixture().await;
    let seller = fixture.seller().await;

    let history = ScriptedHistory::clean();
    let calls = history.clone();
    let router = fixture.router(fixture.service(StackRole::Proof, history));
    let (status, body) = post_claim(
        &router,
        &seller,
        &fixture.required_capabilities,
        &account_xpub(151, 1),
        1,
        Some("carrier_pigeon"),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("unknown_claim_channel")
        ),
        "unknown channel refused: {body}"
    );
    assert_eq!(calls.calls(), 0, "the refusal precedes the scan");
    let creator_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM creators")
        .fetch_one(fixture.database.pool())
        .await
        .unwrap();
    let binding_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claimed_key_fingerprints")
        .fetch_one(fixture.database.pool())
        .await
        .unwrap();
    assert_eq!(
        (creator_rows, binding_rows),
        (0, 0),
        "the refusal persists nothing"
    );

    fixture.database.cleanup().await;
}

/// The no-upgrade invariant, behaviourally: re-authentication may only keep
/// or downgrade (design §B.8.6's transition table).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reclaim_may_only_keep_or_downgrade_never_upgrade() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let fixture = fixture().await;

    // Seller A pastes account 1: shared_manual. A later fully-corroborated
    // bitkit re-claim of the SAME key computes exclusive but must NOT
    // upgrade the row.
    let seller_a = fixture.seller().await;
    let xpub_a = account_xpub(131, 1);
    let router = fixture.router(fixture.service(StackRole::Proof, ScriptedHistory::clean()));
    let (status, body) = post_claim(
        &router,
        &seller_a,
        &fixture.required_capabilities,
        &xpub_a,
        1,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "A's paste: {body}");
    assert_eq!(body["allocation_mode"], "shared_manual");

    let router = fixture.router(fixture.service(StackRole::Proof, ScriptedHistory::clean()));
    let (status, body) = post_claim(
        &router,
        &seller_a,
        &fixture.required_capabilities,
        &xpub_a,
        1,
        Some("bitkit_watch_only_v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "A's bitkit re-claim: {body}");
    assert_eq!(
        body["allocation_mode"], "shared_manual",
        "a re-claim never edits a creator into exclusive"
    );
    let status_row = fixture
        .creators
        .allocation_status(&creator_of(&seller_a))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status_row.allocation.allocation_mode, "shared_manual");
    assert_eq!(
        status_row.allocation.downgrade_reason.as_deref(),
        Some("claim_channel_not_bitkit"),
        "a passing re-claim keeps the recorded reason"
    );

    // Seller B claims exclusive, re-claims exclusive-clean (keep), then
    // re-claims with history now present (downgrade).
    let seller_b = fixture.seller().await;
    let xpub_b = account_xpub(132, 2);
    let router = fixture.router(fixture.service(StackRole::Proof, ScriptedHistory::clean()));
    let (status, body) = post_claim(
        &router,
        &seller_b,
        &fixture.required_capabilities,
        &xpub_b,
        2,
        Some("bitkit_watch_only_v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B's bitkit claim: {body}");
    assert_eq!(body["allocation_mode"], "exclusive");

    let router = fixture.router(fixture.service(StackRole::Proof, ScriptedHistory::clean()));
    let (status, body) = post_claim(
        &router,
        &seller_b,
        &fixture.required_capabilities,
        &xpub_b,
        2,
        Some("bitkit_watch_only_v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B's clean re-claim: {body}");
    assert_eq!(
        body["allocation_mode"], "exclusive",
        "an exclusive creator whose re-claim re-passes every check keeps the mode"
    );

    let history = ScriptedHistory::used(vec![0]);
    let calls = history.clone();
    let router = fixture.router(fixture.service(StackRole::Proof, history));
    let (status, body) = post_claim(
        &router,
        &seller_b,
        &fixture.required_capabilities,
        &xpub_b,
        2,
        Some("bitkit_watch_only_v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B's history re-claim: {body}");
    assert_eq!(body["allocation_mode"], "shared_manual");
    assert_eq!(body["downgrade_reason"], "account_has_history");
    assert_eq!(calls.calls(), 2, "two scan windows, zero extra calls");
    let status_row = fixture
        .creators
        .allocation_status(&creator_of(&seller_b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status_row.allocation.allocation_mode, "shared_manual");
    assert_eq!(
        status_row.allocation.downgrade_reason.as_deref(),
        Some("account_has_history")
    );

    // ...and the one-way door: a further clean re-claim cannot restore it.
    let router = fixture.router(fixture.service(StackRole::Proof, ScriptedHistory::clean()));
    let (status, body) = post_claim(
        &router,
        &seller_b,
        &fixture.required_capabilities,
        &xpub_b,
        2,
        Some("bitkit_watch_only_v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B's final re-claim: {body}");
    assert_eq!(
        body["allocation_mode"], "shared_manual",
        "the downgrade is one-way: no re-claim restores exclusive"
    );

    fixture.database.cleanup().await;
}

/// The claimed-account existence semantics are unchanged: a refused
/// `pasted_auto` claim does not even reach the account-claim logic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pasted_auto_refusal_precedes_token_verification_and_persistence() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let fixture = fixture().await;
    let service = fixture.service(StackRole::Production, ScriptedHistory::clean());
    let result = service
        .claim(ManualClaimRequest {
            auth_token: "not-a-token".to_owned(),
            account_xpub: account_xpub(141, 1),
            account_index: 1,
            claim_channel: Some("bitkit_watch_only_v1".to_owned()),
            allocation_mode: Some("pasted_auto".to_owned()),
        })
        .await;
    assert_eq!(result, Err(ManualClaimError::AllocationModeNotEnabled));
    fixture.database.cleanup().await;
}

/// W1.13 r3 P1: the status's `first_derived_address` is the claim-time
/// address forever. Invoice allocation advances `next_child_index`; the
/// claim-time `first_child_index` — and the address derived at it — never
/// move, and both equal the claim response's values.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_first_address_is_stable_across_invoice_allocation() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let fixture = fixture().await;
    let seller = fixture.seller().await;
    let router = fixture.router(fixture.service(StackRole::Proof, ScriptedHistory::clean()));
    let xpub = account_xpub(161, 1);
    let (status, claim) = post_claim(
        &router,
        &seller,
        &fixture.required_capabilities,
        &xpub,
        1,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "claim: {claim}");
    let claim_address = claim["first_derived_address"].clone();
    let claim_first_child_index = claim["first_child_index"].clone();
    assert_eq!(claim["first_child_index"], 0);
    assert_eq!(
        claim["first_child_index"], claim["next_child_index"],
        "on a first claim the claim-time index IS the cursor"
    );

    // Issue an invoice through the real invoice-allocation path: it
    // allocates child index 0 and advances the derivation cursor to 1.
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let invoices = InvoiceStore::new(fixture.database.pool(), crypto);
    let creator = creator_of(&seller);
    let reader = reader_of(&Keypair::random());
    invoices
        .create_awaiting_baseline(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"status-stability-bundle",
            payment_request_binding: b"status-stability-request",
            new_reader_payloads: &InvoicePayloads {
                reader: reader.clone(),
            },
            payment_request_intent: payment_request_intent(&reader),
            required_sats: 100,
            nonce_sats: 1,
        })
        .await
        .unwrap();
    let cursor: i64 = sqlx::query_scalar("SELECT next_child_index FROM creators")
        .fetch_one(fixture.database.pool())
        .await
        .unwrap();
    assert_eq!(cursor, 1, "invoice allocation advanced the cursor");

    // The status still serves the claim response's address and claim-time
    // index; only the informational cursor moved.
    let (status, body) = get_status(
        &router,
        &creator,
        Some(&claim_token(&seller, &fixture.required_capabilities)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "status: {body}");
    assert_eq!(
        body["first_derived_address"], claim_address,
        "the status address is the claim-time address forever"
    );
    assert_eq!(body["first_child_index"], claim_first_child_index);
    assert_eq!(body["account_index"], 1);
    assert_eq!(body["next_child_index"], 1);
    assert!(
        body["next_child_index"].as_u64().unwrap() > body["first_child_index"].as_u64().unwrap(),
        "the cursor moved past the stable claim-time index"
    );
    // The client's own re-derivation at (account_index, first_child_index)
    // reproduces `first_derived_address`.
    assert_eq!(
        body["first_derived_address"],
        paykit_server::application::create_invoice::derive_bip84_p2wpkh_address(
            &xpub,
            1,
            &BitcoinNetwork::Testnet,
            0
        )
        .unwrap()
    );

    fixture.database.cleanup().await;
}
