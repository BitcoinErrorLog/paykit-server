//! W1.4b — the §B.9 `resolve` endpoint (design L3040–3053, §B.11.1
//! L3272–3295), against real Postgres and the production HTTP path.
//!
//! Covered here, each test named in the work-item report:
//! - the twelve-row §B.9 table, table-driven, one case per row: accept /
//!   refuse, the named error, the resulting `baseline_state`, the retained
//!   observation and the mismatch flag on the `amount_matched: false`
//!   row, and `observation_targets()` membership immediately before and
//!   after the call;
//! - idempotent replay (identical body, `updated_at` unchanged) and the
//!   one-way `invoice_already_resolved` conflict naming the existing
//!   resolution;
//! - `stack_id` mismatch refused with zero state change;
//! - phase-1 replay against both resolved states on BOTH creation
//!   entrypoints → 409 `invoice_finalized` with zero writes (the W1.1c
//!   round-2 classification hole, closed with the states now reachable).

use std::{collections::BTreeMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{
    Network, OutPoint, Txid,
    bip32::{ChildNumber, Xpriv, Xpub},
    hashes::Hash,
    secp256k1::Secp256k1,
};
use ed25519_dalek::{Signer, SigningKey};
use locks_core::{
    ids::CreatorPubky as RawCreatorPubky,
    lock_policy::{
        AccessPolicy, CONTENT_LOCK_VERSION, ContentLock, Criterion, LockLogic, LockServerConfig,
        VerifierType,
    },
};
use paykit_lib::{PaykitReceiverCapabilities, PaykitReceiverPath};
use paykit_sdk::{
    InMemoryStorage, PaykitSdk, PaykitSdkConfig, PubkyLocalSecretKey, PubkyPublicKey,
    PubkySessionBootstrap, ReceiverNoiseSecretKey,
};
use paykit_server::{
    Server,
    allocation::ClaimAllocation,
    application::create_invoice::derive_bip84_p2wpkh_address,
    bitcoin::ObservationTarget,
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    domain::payment::BitcoinOutpoint,
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoiceStore,
        NewReaderPayloadFactory, NewReaderPayloads, OutboxStore, PersistenceError,
    },
    runtime::ElectrumProbe,
    startup::initialize_database,
    workers::observer::{
        CreationSnapshot, ElectrumPort, ObservationReport, ObserverError, RequestLimiter, TipProbe,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

use sdk_fixtures::{TestPaymentAdapter, TestSessionProvider};

mod common;

const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
/// Twelve distinct creator-scoped references, one per table row (the
/// Locks-family cases use the two BUNDLE constants).
const REFERENCES: [&str; 12] = [
    "000G40R40M30E209185GR38E1W",
    "000G40R40M30E209185GR38E2W",
    "000G40R40M30E209185GR38E3W",
    "000G40R40M30E209185GR38E5W",
    "000G40R40M30E209185GR38E6W",
    "000G40R40M30E209185GR38E7W",
    "000G40R40M30E209185GR38E8W",
    "000G40R40M30E209185GR38E9W",
    "000G40R40M30E209185GR38EAW",
    "000G40R40M30E209185GR38EBW",
    "000G40R40M30E209185GR38ECW",
    "000G40R40M30E209185GR38EDW",
];
const BUNDLE_LOCKS_A: &str = "000G40R40M30E209185GR38E4W";
const BUNDLE_LOCKS_B: &str = "000G40R40M30E209185GR38E4M";
const TAIL: Duration = Duration::from_secs(24 * 60 * 60);
static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn expires_in(hours: i64) -> String {
    (time::OffsetDateTime::now_utc() + time::Duration::hours(hours))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// The marketplace's resolution timestamp: RECORDED only, never trusted
/// for a state decision, so a fixed value is fine and round-trips exactly.
fn resolved_at() -> String {
    time::OffsetDateTime::from_unix_timestamp(1_800_000_000)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

struct ScriptedElectrum;

#[async_trait]
impl ElectrumPort for ScriptedElectrum {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        Ok(CreationSnapshot {
            tip_height: 300,
            baseline_outputs: Vec::new(),
            unconfirmed_inputs: Vec::new(),
            unconfirmed_outputs: Vec::new(),
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        Ok(ObservationReport {
            outputs: Vec::new(),
            observed: targets
                .iter()
                .map(|target| target.address().to_owned())
                .collect(),
            failed: Vec::new(),
        })
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 300,
            time_unix: fresh_tip_time(),
        })
    }
}

fn fresh_tip_time() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn config(database_url: &str, signing_key: &SigningKey) -> Config {
    let trusted_key = pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(signing_key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string();
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:0"
[locks]
trusted_public_key = "{trusted_key}"
[setup]
allowed_origins = ["https://app.example"]
[paykit]
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
network = "testnet"
[deployment]
stack_role = "proof"
[electrum]
endpoint = "tcp://127.0.0.1:1"
poll_interval = "1s"
request_timeout = "1s"
max_concurrent_creation_snapshots = 1
[outbox]
poll_interval = "1h"
batch_size = 16
lease_duration = "5s"
retry_initial = "1s"
retry_max = "2s"
[shutdown]
drain_timeout = "2s"
"#
        ),
        ConfigEnvironment {
            database_url: Some(database_url.to_owned()),
            master_key: Some(MASTER_KEY.to_owned()),
        },
    )
    .unwrap()
}

struct CreatorFixture {
    creator: CreatorPubky,
    lock_resource: String,
    xpub: String,
    account_index: u32,
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

fn content_lock(creator: &CreatorPubky, amount_sats: u64) -> ContentLock {
    ContentLock {
        version: CONTENT_LOCK_VERSION,
        creator: RawCreatorPubky::from_str(&creator.to_string()).unwrap(),
        primary_resource: None,
        secondary_resources: BTreeMap::new(),
        criteria: vec![Criterion {
            criterion_id: "payment".into(),
            verifier_type: VerifierType::PaykitPayment,
            params: serde_json::json!({
                "recipient_pubky": creator.to_string(),
                "amount": amount_sats.to_string(),
                "asset": "BTC"
            }),
        }],
        lock_logic: LockLogic::All {
            criteria: vec!["payment".into()],
        },
        access_policy: AccessPolicy {
            requested_credential_ttl_seconds: 900,
        },
        lock_server: LockServerConfig { override_: None },
        created_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

struct BootedStack {
    address: SocketAddr,
    pool: PgPool,
    stack_id: String,
    store: InvoiceStore,
    #[allow(dead_code)]
    outbox: OutboxStore,
    signing_key: SigningKey,
    creator: CreatorFixture,
    reader: ReaderPubky,
    _testnet: EphemeralTestnet,
    database: TestDatabase,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    running: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl BootedStack {
    fn invoice_address(&self, child_index: i64) -> String {
        derive_bip84_p2wpkh_address(
            &self.creator.xpub,
            self.creator.account_index,
            &BitcoinNetwork::Testnet,
            child_index,
        )
        .unwrap()
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        self.running.await.unwrap().unwrap();
        self.pool.close().await;
        self.database.cleanup().await;
    }
}

async fn boot(seed: u8) -> BootedStack {
    let database = TestDatabase::create().await;
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let server_config = config(database.database_url(), &signing_key);
    let initialized = initialize_database(&server_config).await.unwrap();
    let pool = initialized.pool.clone();
    let stack_identity = initialized.stack_identity.clone();
    let testnet = EphemeralTestnet::builder()
        .postgres(
            pubky_testnet::pubky_homeserver::ConnectionString::new(
                &std::env::var("TEST_DATABASE_URL").unwrap(),
            )
            .unwrap(),
        )
        .build()
        .await
        .unwrap();
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone());
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(&pool, crypto.clone());

    let reader_account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            ReceiverNoiseSecretKey::random(),
            &homeserver,
            None,
            &PaykitSdkConfig::new(PaykitReceiverPath::new("bitkit/server").unwrap())
                .required_session_capabilities(),
        )
        .await
        .unwrap();
    let reader_sdk = PaykitSdk::new(
        InMemoryStorage::default(),
        TestSessionProvider::new(reader_account.access),
        TestPaymentAdapter,
        PaykitSdkConfig::new(PaykitReceiverPath::new("bitkit/server").unwrap()),
    )
    .unwrap();
    reader_sdk.initialize().await.unwrap();
    reader_sdk
        .publish_paykit_receiver_marker(PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: true,
            outgoing_payments: true,
        })
        .await
        .unwrap();
    let reader = parse_reader(&format!("pubky{}", reader_account.public_key)).unwrap();

    let creator_account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            ReceiverNoiseSecretKey::random(),
            &homeserver,
            None,
            &PaykitSdkConfig::new(PaykitReceiverPath::new("paykit/server").unwrap())
                .required_session_capabilities(),
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", creator_account.public_key)).unwrap();
    let xpub = account_xpub(seed, 0);
    let amount_sats = 50_000;
    let lock = content_lock(&creator, amount_sats);
    let lock_path = lock.content_lock_path().unwrap().to_string();
    creator_account
        .access
        .session
        .storage()
        .put_json(lock_path.clone(), &lock)
        .await
        .unwrap();
    creators
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                creator_account.access.session.export_secret(),
                creator_account.access.receiver_noise_secret_key.clone(),
                xpub.clone(),
                0,
            ),
            &Default::default(),
            &key_tail(seed),
            &ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();

    let server = Server::build_with_transports(
        server_config,
        pool.clone(),
        stack_identity.clone(),
        pubky,
        Arc::new(ScriptedElectrum),
    )
    .await
    .unwrap();
    let runtime = server.runtime();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(server.run_until(listener, async move {
        let _ = shutdown_rx.await;
    }));
    wait_until_listening(address).await;
    wait_until_ready(address).await;
    for _ in 0..3 {
        runtime.record_electrum_probe(ElectrumProbe::success(300, fresh_tip_time()));
    }
    assert!(runtime.readiness().await.bitcoin_offer_available);

    BootedStack {
        address,
        store: InvoiceStore::new(&pool, crypto.clone()),
        outbox: OutboxStore::new(&pool, crypto.clone()),
        pool,
        stack_id: stack_identity.stack_id(),
        signing_key,
        creator: CreatorFixture {
            creator: creator.clone(),
            lock_resource: format!("{creator}{lock_path}"),
            xpub,
            account_index: 0,
        },
        reader,
        _testnet: testnet,
        database,
        shutdown_tx,
        running,
    }
}

fn key_tail(seed: u8) -> [u8; 65] {
    [seed; 65]
}

struct HttpResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "response body is not JSON ({error}): {}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }
}

fn signed_request(signing_key: &SigningKey, uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(signing_key.sign(body.as_bytes()).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
}

fn canonical_json(value: serde_json::Value) -> String {
    serde_json_canonicalizer::to_vec(&value)
        .unwrap()
        .into_iter()
        .map(char::from)
        .collect()
}

fn payment_request_body(
    creator: &CreatorPubky,
    reader: &ReaderPubky,
    reference: &str,
    expires_at: &str,
) -> String {
    canonical_json(serde_json::json!({
        "amount_sats": 50_000,
        "creator": creator.to_string(),
        "reader": reader.to_string(),
        "reference": reference,
        "expires_at": expires_at,
        "idempotency_key": format!("{reference}:1"),
    }))
}

fn locks_invoice_body(
    fixture: &CreatorFixture,
    reader: &ReaderPubky,
    bundle: &str,
    expires_at: &str,
) -> String {
    canonical_json(serde_json::json!({
        "bundle_id": bundle,
        "expires_at": expires_at,
        "lock_resource": fixture.lock_resource,
        "reader": reader.to_string(),
    }))
}

fn activate_body(invoice_id: &str, stack_id: &str, total_sats: u64) -> String {
    canonical_json(serde_json::json!({
        "activation_attempt": 1,
        "invoice_id": invoice_id,
        "stack_id": stack_id,
        "total_sats": total_sats,
    }))
}

fn void_body(invoice_id: &str, stack_id: &str) -> String {
    canonical_json(serde_json::json!({
        "invoice_id": invoice_id,
        "reason": "marketplace_bind_rolled_back",
        "stack_id": stack_id,
    }))
}

fn resolve_body(invoice_id: &str, stack_id: &str, resolution: &str) -> String {
    canonical_json(serde_json::json!({
        "invoice_id": invoice_id,
        "resolution": resolution,
        "resolved_at": resolved_at(),
        "stack_id": stack_id,
    }))
}

async fn post(stack: &BootedStack, uri: &str, body: String) -> HttpResponse {
    send_http(stack.address, signed_request(&stack.signing_key, uri, body)).await
}

async fn post_prepare_body(stack: &BootedStack, body: String) -> serde_json::Value {
    let response = post(stack, "/v0/payment-requests", body).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "prepare body: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()
}

async fn prepare(stack: &BootedStack, reference: &str) -> serde_json::Value {
    post_prepare_body(
        stack,
        payment_request_body(
            &stack.creator.creator,
            &stack.reader,
            reference,
            &expires_in(1),
        ),
    )
    .await
}

async fn activate(stack: &BootedStack, invoice_id: &str, total_sats: u64) -> HttpResponse {
    post(
        stack,
        &format!("/v0/payment-requests/{invoice_id}/activate"),
        activate_body(invoice_id, &stack.stack_id.clone(), total_sats),
    )
    .await
}

/// Resolve on the marketplace family.
async fn resolve(stack: &BootedStack, invoice_id: &str, resolution: &str) -> HttpResponse {
    post(
        stack,
        &format!("/v0/payment-requests/{invoice_id}/resolve"),
        resolve_body(invoice_id, &stack.stack_id.clone(), resolution),
    )
    .await
}

/// Resolve on the Locks family.
async fn resolve_locks(stack: &BootedStack, invoice_id: &str, resolution: &str) -> HttpResponse {
    post(
        stack,
        &format!("/invoices/{invoice_id}/resolve"),
        resolve_body(invoice_id, &stack.stack_id.clone(), resolution),
    )
    .await
}

/// Prepare + activate on the marketplace entrypoint.
async fn activated_invoice(
    stack: &BootedStack,
    reference: &str,
    child_index: i64,
) -> (String, String, u64) {
    let body = prepare(stack, reference).await;
    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
    let total_sats = body["total_sats"].as_u64().unwrap();
    let response = activate(stack, &invoice_id, total_sats).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "activate body: {}",
        String::from_utf8_lossy(&response.body)
    );
    (invoice_id, stack.invoice_address(child_index), total_sats)
}

async fn send_http(address: SocketAddr, request: Request<Body>) -> HttpResponse {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 32 * 1024).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        parts.method,
        parts.uri,
        address,
        body.len()
    );
    for (name, value) in &parts.headers {
        head.push_str(name.as_str());
        head.push_str(": ");
        head.push_str(value.to_str().unwrap());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&response[..header_end]).unwrap();
    let status = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    HttpResponse {
        status: StatusCode::from_u16(status).unwrap(),
        body: response[(header_end + 4)..].to_vec(),
    }
}

async fn wait_until_listening(address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start listening");
}

async fn wait_until_ready(address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(address).await {
            let _ = stream
                .write_all(b"GET /health/ready HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await;
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response).await;
            let head = String::from_utf8_lossy(&response);
            if head.starts_with("HTTP/1.1 200") {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("server did not become ready");
}

async fn baseline_state(pool: &PgPool, invoice_id: &str) -> String {
    sqlx::query_scalar("SELECT baseline_state FROM invoices WHERE id = $1")
        .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn updated_at(pool: &PgPool, invoice_id: &str) -> time::OffsetDateTime {
    sqlx::query_scalar("SELECT updated_at FROM invoices WHERE id = $1")
        .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn shift_expires_at(pool: &PgPool, invoice_id: &str, seconds: i64) {
    sqlx::query("UPDATE invoices SET expires_at = NOW() + make_interval(secs => $2) WHERE id = $1")
        .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
        .bind(seconds)
        .execute(pool)
        .await
        .unwrap();
}

async fn apply_transitions(stack: &BootedStack) {
    stack.store.apply_expiry_transitions(TAIL).await.unwrap();
}

async fn plan_contains(stack: &BootedStack, address: &str) -> bool {
    stack
        .store
        .observation_plan()
        .await
        .unwrap()
        .iter()
        .any(|planned| planned.target().address() == address)
}

/// One table row's expected outcome.
struct Row {
    /// State the row is driven to before `resolve`.
    state: &'static str,
    /// Observation to record while `observing`: (sats delta from total,
    /// confirmations). `None` records nothing.
    observation: Option<(i64, u32)>,
    resolution: &'static str,
    /// `Ok(expected_final_state)` for an accepting row (on `expired_final`
    /// the expected state IS `expired_final` — metadata only); `Err(code)`
    /// for a refusing row.
    outcome: Result<&'static str, &'static str>,
    /// Whether the invoice is in `observation_targets()` before the call.
    in_plan_before: bool,
    /// Locks route family instead of the marketplace family.
    locks_family: bool,
}

/// The twelve-row §B.9 table (design L3040–3053), one case per row.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn resolve_table_covers_all_twelve_b9_rows() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(71).await;
    let mut child_index = 0_i64;
    let mut next_reference = 0_usize;
    let mut next_ref = move || {
        let reference = REFERENCES[next_reference];
        next_reference += 1;
        reference
    };

    let rows = [
        Row {
            state: "observing",
            observation: None,
            resolution: "paid_manually",
            outcome: Ok("resolved_paid_manually"),
            in_plan_before: true,
            locks_family: false,
        },
        Row {
            state: "observing",
            observation: Some((0, 0)), // detected (0-conf match)
            resolution: "refunded",
            outcome: Ok("resolved_closed"),
            in_plan_before: true,
            locks_family: false,
        },
        Row {
            state: "observing",
            observation: Some((0, 1)), // confirmed, amount_matched
            resolution: "abandoned",
            outcome: Ok("resolved_closed"),
            in_plan_before: true,
            locks_family: false,
        },
        Row {
            state: "observing",
            observation: Some((-1, 1)), // confirmed, amount_matched: false
            resolution: "paid_manually",
            outcome: Ok("resolved_paid_manually"),
            in_plan_before: true,
            locks_family: false,
        },
        Row {
            state: "expired_tail",
            observation: None,
            resolution: "paid_manually",
            outcome: Ok("resolved_paid_manually"),
            in_plan_before: true,
            locks_family: false,
        },
        Row {
            state: "expired_final",
            observation: None,
            resolution: "paid_manually",
            outcome: Ok("expired_final"), // metadata only: state unchanged
            in_plan_before: false,
            locks_family: false,
        },
        Row {
            state: "prepared",
            observation: None,
            resolution: "paid_manually",
            outcome: Err("invoice_not_activated"),
            in_plan_before: false,
            locks_family: false,
        },
        Row {
            state: "awaiting_baseline",
            observation: None,
            resolution: "paid_manually",
            outcome: Err("invoice_baseline_in_progress"),
            in_plan_before: false,
            locks_family: false,
        },
        Row {
            state: "void_baseline_failed",
            observation: None,
            resolution: "paid_manually",
            outcome: Err("invoice_finalized"),
            in_plan_before: false,
            locks_family: false,
        },
        Row {
            state: "void_prepare_expired",
            observation: None,
            resolution: "paid_manually",
            outcome: Err("prepare_expired"),
            in_plan_before: false,
            locks_family: false,
        },
        Row {
            state: "void_cancelled",
            observation: None,
            resolution: "paid_manually",
            outcome: Err("invoice_finalized"),
            in_plan_before: false,
            locks_family: false,
        },
        // The Locks-family accepting row proves the second route mount;
        // the unknown-id row needs no setup and runs after the table.
        Row {
            state: "observing",
            observation: None,
            resolution: "paid_manually",
            outcome: Ok("resolved_paid_manually"),
            in_plan_before: true,
            locks_family: true,
        },
    ];

    for (row_index, row) in rows.iter().enumerate() {
        let label = format!(
            "row {} {} {:?} {}",
            row_index,
            row.state,
            row.observation.map(|(delta, conf)| (delta, conf)),
            row.resolution
        );
        // --- Drive a fresh invoice into the row's state.
        let (invoice_id, address) = match row.state {
            "awaiting_baseline" | "void_baseline_failed" => {
                // Direct store creation parks the row mid-baseline.
                let payloads = Payloads {
                    reader: stack.reader.clone(),
                    address: stack.invoice_address(child_index),
                };
                let bundle = next_ref();
                let created = stack
                    .store
                    .create_awaiting_baseline(AtomicInvoiceInput {
                        creator: &stack.creator.creator,
                        reader: &stack.reader,
                        bundle_binding: bundle.as_bytes(),
                        payment_request_binding: format!("{bundle}:1").as_bytes(),
                        new_reader_payloads: &payloads,
                        payment_request_intent: common::payment_intent(&stack.reader),
                        required_sats: 50_437,
                        nonce_sats: 437,
                        prepare_ttl: std::time::Duration::from_secs(900),
                        expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
                    })
                    .await
                    .unwrap();
                if row.state == "void_baseline_failed" {
                    stack
                        .store
                        .fail_creation_baseline(created.invoice_id())
                        .await
                        .unwrap();
                }
                let address = stack.invoice_address(child_index);
                child_index += 1;
                (created.invoice_id().to_string(), address)
            }
            "observing" | "expired_tail" | "expired_final" => {
                let (invoice_id, address, _total) = if row.locks_family {
                    let response = post(
                        &stack,
                        "/invoices",
                        locks_invoice_body(
                            &stack.creator,
                            &stack.reader,
                            BUNDLE_LOCKS_A,
                            &expires_in(1),
                        ),
                    )
                    .await;
                    assert_eq!(response.status, StatusCode::OK, "{label}: locks prepare");
                    let body = response.json();
                    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
                    let total_sats = body["total_sats"].as_u64().unwrap();
                    let activated = activate(&stack, &invoice_id, total_sats).await;
                    assert_eq!(activated.status, StatusCode::OK, "{label}: locks activate");
                    (invoice_id, stack.invoice_address(child_index), total_sats)
                } else {
                    activated_invoice(&stack, next_ref(), child_index).await
                };
                child_index += 1;
                match row.state {
                    "expired_tail" => {
                        shift_expires_at(&stack.pool, &invoice_id, -60).await;
                        apply_transitions(&stack).await;
                    }
                    "expired_final" => {
                        shift_expires_at(&stack.pool, &invoice_id, -(24 * 3600 + 60)).await;
                        apply_transitions(&stack).await;
                    }
                    _ => {}
                }
                (invoice_id, address)
            }
            "prepared" | "void_prepare_expired" | "void_cancelled" => {
                let body = prepare(&stack, next_ref()).await;
                let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
                let address = stack.invoice_address(child_index);
                child_index += 1;
                match row.state {
                    "void_prepare_expired" => {
                        sqlx::query(
                            "UPDATE invoices SET prepare_expires_at = NOW() - INTERVAL '1 second'
                             WHERE id = $1",
                        )
                        .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
                        .execute(&stack.pool)
                        .await
                        .unwrap();
                        let reaped = stack.store.reap_expired_prepares().await.unwrap();
                        assert_eq!(reaped, 1, "{label}: the stale prepare reaps");
                    }
                    "void_cancelled" => {
                        let response = post(
                            &stack,
                            &format!("/v0/payment-requests/{invoice_id}/void"),
                            void_body(&invoice_id, &stack.stack_id.clone()),
                        )
                        .await;
                        assert_eq!(response.status, StatusCode::OK, "{label}: void");
                    }
                    _ => {}
                }
                (invoice_id, address)
            }
            other => unreachable!("row state {other}"),
        };
        assert_eq!(
            baseline_state(&stack.pool, &invoice_id).await,
            row.state,
            "{label}: driven state"
        );

        // --- Record the row's observation, if any.
        if let Some((delta, conf)) = row.observation {
            let view = stack
                .store
                .prepare_view(uuid::Uuid::parse_str(&invoice_id).unwrap())
                .await
                .unwrap()
                .unwrap();
            let sats = u64::try_from(i64::try_from(view.total_sats).unwrap() + delta).unwrap();
            assert!(
                stack
                    .store
                    .apply_bitcoin_observation(
                        &address,
                        &BitcoinOutpoint::from_bitcoin(OutPoint::new(
                            Txid::from_byte_array([31 + row_index as u8; 32]),
                            0
                        )),
                        sats,
                        conf,
                        if conf > 0 { Some(301) } else { None },
                        true,
                    )
                    .await
                    .unwrap(),
                "{label}: observation recorded"
            );
            if delta < 0 {
                let amount_matched: bool =
                    sqlx::query_scalar("SELECT amount_matched FROM invoices WHERE id = $1")
                        .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
                        .fetch_one(&stack.pool)
                        .await
                        .unwrap();
                assert!(!amount_matched, "{label}: mismatch staged");
            }
        }

        // --- observation_targets() membership BEFORE the call.
        let before = plan_contains(&stack, &address).await;
        assert_eq!(before, row.in_plan_before, "{label}: plan before");

        let updated_before = updated_at(&stack.pool, &invoice_id).await;

        // --- The call.
        let response = if row.locks_family {
            resolve_locks(&stack, &invoice_id, row.resolution).await
        } else {
            resolve(&stack, &invoice_id, row.resolution).await
        };
        match row.outcome {
            Ok(expected_state) => {
                assert_eq!(
                    response.status,
                    StatusCode::OK,
                    "{label}: resolve body: {}",
                    String::from_utf8_lossy(&response.body)
                );
                let body = response.json();
                assert_eq!(body["state"], expected_state, "{label}");
                assert_eq!(body["resolution"], row.resolution, "{label}");
                assert_eq!(body["resolved_at"], resolved_at(), "{label}");
                assert_eq!(
                    baseline_state(&stack.pool, &invoice_id).await,
                    expected_state,
                    "{label}: resulting baseline_state"
                );
                let recorded: (Option<String>, Option<time::OffsetDateTime>) =
                    sqlx::query_as("SELECT resolution, resolved_at FROM invoices WHERE id = $1")
                        .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
                        .fetch_one(&stack.pool)
                        .await
                        .unwrap();
                assert_eq!(recorded.0.as_deref(), Some(row.resolution), "{label}");
                assert!(recorded.1.is_some(), "{label}: resolved_at recorded");
            }
            Err(code) => {
                assert_eq!(
                    response.status,
                    StatusCode::CONFLICT,
                    "{label}: {}",
                    String::from_utf8_lossy(&response.body)
                );
                assert_eq!(response.json()["error"]["code"], code, "{label}");
                assert_eq!(
                    baseline_state(&stack.pool, &invoice_id).await,
                    row.state,
                    "{label}: a refusal changes no state"
                );
                assert_eq!(
                    updated_at(&stack.pool, &invoice_id).await,
                    updated_before,
                    "{label}: a refusal writes nothing"
                );
            }
        }

        // --- observation_targets() membership AFTER the call.
        let after = plan_contains(&stack, &address).await;
        match row.outcome {
            Ok(expected) if expected != "expired_final" => {
                assert!(
                    !after,
                    "{label}: leaves observation_targets in the same transaction"
                );
            }
            _ => assert_eq!(after, before, "{label}: plan membership unchanged"),
        }

        // --- The observation is RETAINED (and the mismatch flagged) on
        // the amount_matched: false row.
        if let Some((delta, _)) = row.observation {
            let retained: (i64, bool) = sqlx::query_as(
                "SELECT (SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1),
                        amount_matched
                 FROM invoices WHERE id = $1",
            )
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_one(&stack.pool)
            .await
            .unwrap();
            assert_eq!(retained.0, 1, "{label}: observation retained");
            if delta < 0 {
                assert!(!retained.1, "{label}: the mismatch is retained AND flagged");
            }
        }
    }

    // Row 12: unknown invoice id → 404 unknown_invoice, nothing to change.
    let unknown = uuid::Uuid::new_v4().to_string();
    let response = resolve(&stack, &unknown, "paid_manually").await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.json()["error"]["code"], "unknown_invoice");

    stack.shutdown().await;
}

/// Payloads for direct store creation of `awaiting_baseline` rows.
struct Payloads {
    reader: ReaderPubky,
    address: String,
}

impl NewReaderPayloadFactory for Payloads {
    fn for_child_index(&self, _child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        Ok(NewReaderPayloads {
            endpoint_intent: common::endpoint_intent(&self.reader, self.address.clone()),
            bitcoin_address: self.address.clone(),
        })
    }
}

/// Idempotency on `(invoice_id, resolution)`: the replay returns the
/// identical body with zero writes; a different resolution is the one-way
/// `invoice_already_resolved` naming the existing one. A path/body
/// `invoice_id` mismatch is a plain `invalid_request`.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn resolve_is_idempotent_one_way_and_path_checked() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(72).await;
    let (invoice_id, _address, _total) = activated_invoice(&stack, REFERENCES[0], 0).await;

    let first = resolve(&stack, &invoice_id, "paid_manually").await;
    assert_eq!(first.status, StatusCode::OK);
    let first_body = first.json();
    assert_eq!(first_body["state"], "resolved_paid_manually");
    let updated = updated_at(&stack.pool, &invoice_id).await;

    // Same resolution again: identical body, zero writes.
    let replay = resolve(&stack, &invoice_id, "paid_manually").await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(
        replay.json(),
        first_body,
        "an idempotent replay returns the existing record byte-for-byte"
    );
    assert_eq!(
        updated_at(&stack.pool, &invoice_id).await,
        updated,
        "a replay writes nothing"
    );

    // A different resolution: one-way conflict naming the existing one.
    for other in ["refunded", "abandoned"] {
        let conflict = resolve(&stack, &invoice_id, other).await;
        assert_eq!(conflict.status, StatusCode::CONFLICT);
        assert_eq!(conflict.json()["error"]["code"], "invoice_already_resolved");
        assert!(
            conflict.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("paid_manually"),
            "the conflict names the existing resolution: {}",
            String::from_utf8_lossy(&conflict.body)
        );
    }
    assert_eq!(
        baseline_state(&stack.pool, &invoice_id).await,
        "resolved_paid_manually"
    );
    assert_eq!(updated_at(&stack.pool, &invoice_id).await, updated);

    // Path/body invoice_id disagreement: the signature covers the body,
    // not the path, so this is a plain invalid request.
    let mismatch = post(
        &stack,
        &format!("/v0/payment-requests/{}/resolve", uuid::Uuid::new_v4()),
        resolve_body(&invoice_id, &stack.stack_id.clone(), "refunded"),
    )
    .await;
    assert_eq!(mismatch.status, StatusCode::BAD_REQUEST);
    assert_eq!(mismatch.json()["error"]["code"], "invalid_request");

    stack.shutdown().await;
}

/// A body echoing another stack's `stack_id` is refused with
/// `stack_identity_mismatch` and changes nothing (§B.8.8's pin).
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn resolve_echoing_another_stacks_id_is_refused_with_zero_change() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(73).await;
    let (invoice_id, address, _total) = activated_invoice(&stack, REFERENCES[0], 0).await;
    let updated = updated_at(&stack.pool, &invoice_id).await;

    let response = post(
        &stack,
        &format!("/v0/payment-requests/{invoice_id}/resolve"),
        resolve_body(
            &invoice_id,
            "production:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19",
            "paid_manually",
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "stack_identity_mismatch");
    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "observing");
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT resolution IS NULL FROM invoices WHERE id = $1")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_one(&stack.pool)
            .await
            .unwrap()
    );
    assert_eq!(updated_at(&stack.pool, &invoice_id).await, updated);
    assert!(plan_contains(&stack, &address).await);

    stack.shutdown().await;
}

/// Phase-1 replay against both resolved states, on BOTH creation
/// entrypoints: 409 `invoice_finalized`, zero writes (the W1.1c round-2
/// classification hole — preflight's catch-all and `prepare_outcome`'s
/// catch-all both classify the resolved states as finalized).
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn phase_one_replay_against_resolved_states_is_invoice_finalized() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(74).await;

    // (create body, uri, resolution that produced the resolved state)
    let mut cases: Vec<(String, &'static str, &'static str)> = Vec::new();
    for (reference, resolution) in [
        (REFERENCES[0], "paid_manually"),
        (REFERENCES[1], "refunded"),
    ] {
        let create_body = payment_request_body(
            &stack.creator.creator,
            &stack.reader,
            reference,
            &expires_in(1),
        );
        let body = post_prepare_body(&stack, create_body.clone()).await;
        let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
        let total_sats = body["total_sats"].as_u64().unwrap();
        let response = activate(&stack, &invoice_id, total_sats).await;
        assert_eq!(response.status, StatusCode::OK);
        let response = resolve(&stack, &invoice_id, resolution).await;
        assert_eq!(response.status, StatusCode::OK, "{resolution}");
        cases.push((create_body, "/v0/payment-requests", resolution));
    }
    for (bundle, resolution) in [
        (BUNDLE_LOCKS_A, "paid_manually"),
        (BUNDLE_LOCKS_B, "abandoned"),
    ] {
        let create_body = locks_invoice_body(&stack.creator, &stack.reader, bundle, &expires_in(1));
        let response = post(&stack, "/invoices", create_body.clone()).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "locks prepare {bundle}: {}",
            String::from_utf8_lossy(&response.body)
        );
        let body = response.json();
        let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
        let total_sats = body["total_sats"].as_u64().unwrap();
        let response = activate(&stack, &invoice_id, total_sats).await;
        assert_eq!(response.status, StatusCode::OK);
        // The Locks cases resolve through the Locks route family.
        let response = resolve_locks(&stack, &invoice_id, resolution).await;
        assert_eq!(response.status, StatusCode::OK, "{resolution}");
        cases.push((create_body, "/invoices", resolution));
    }

    for (create_body, uri, resolution) in cases {
        let before: (i64, i64) =
            sqlx::query_as("SELECT (SELECT COUNT(*) FROM invoices), (SELECT COUNT(*) FROM outbox)")
                .fetch_one(&stack.pool)
                .await
                .unwrap();
        let replay = post(&stack, uri, create_body).await;
        assert_eq!(
            replay.status,
            StatusCode::CONFLICT,
            "{uri} replay after {resolution}: {}",
            String::from_utf8_lossy(&replay.body)
        );
        assert_eq!(replay.json()["error"]["code"], "invoice_finalized");
        let after: (i64, i64) =
            sqlx::query_as("SELECT (SELECT COUNT(*) FROM invoices), (SELECT COUNT(*) FROM outbox)")
                .fetch_one(&stack.pool)
                .await
                .unwrap();
        assert_eq!(
            after, before,
            "{uri} replay after {resolution}: zero writes"
        );
    }

    stack.shutdown().await;
}
