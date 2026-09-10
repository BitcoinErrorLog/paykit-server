//! W1.1c — two-phase creation and activation (design §B.11), against real
//! Postgres and the production HTTP path.
//!
//! Covered here, each test named in the work-item report:
//! - phase 1 returns 200 with the verbatim §B.11.3 body on BOTH entrypoints,
//!   lands the invoice `prepared`, writes both outbox rows `'prepared'`, and
//!   `OutboxStore::claim` returns zero rows for them (zero-claims);
//! - §B.11.5 immutability: a funded `prepared` address is never observed,
//!   never published, never payable;
//! - activate: signature/total/stack_id refusals change nothing; success
//!   flips `prepared → observing`, queues both rows, persists the §B.4.6
//!   tick-1 snapshot and `activated_at`; replay is byte-identical and
//!   write-free;
//! - void: `prepared → void_cancelled`, idempotent replay, and the §B.11.3 /
//!   §B.11.6 named errors for every other state;
//! - the §B.11.1 reaper voids only expired prepares;
//! - a phase-1 replay on `prepared` mints nothing (index cursor, nonce,
//!   outbox rows all equal before/after);
//! - W1.4 continuity: a hidden offer refuses a New prepare with 503
//!   `bitcoin_offer_unavailable` while activate/void keep working.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

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
        NewReaderPayloadFactory, NewReaderPayloads, OutboxStore, PersistenceError, run_migrations,
    },
    runtime::{ElectrumProbe, Runtime},
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

const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const REFERENCE_A: &str = "000G40R40M30E209185GR38E1W";
const REFERENCE_B: &str = "000G40R40M30E209185GR38E2W";
const REFERENCE_C: &str = "000G40R40M30E209185GR38E3W";
const BUNDLE_LOCKS: &str = "000G40R40M30E209185GR38E4W";
const EXPIRES_AT: &str = "2030-01-01T00:00:00Z";
static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Electrum fake: a fundable UTXO map for observations, plus a scriptable
/// set of unconfirmed outputs/inputs returned by the next creation-style
/// snapshot (the §B.4.6 tick-1 snapshot inside activation reuses that
/// snapshot shape).
/// (unconfirmed outputs, their inputs) scripted for one address's next
/// creation-style snapshot.
type ScriptedSnapshot = (Vec<OutPoint>, Vec<OutPoint>);

struct ScriptedElectrum {
    outputs: Mutex<HashMap<String, (u64, OutPoint)>>,
    snapshot_unconfirmed: Mutex<HashMap<String, ScriptedSnapshot>>,
}

impl ScriptedElectrum {
    fn new() -> Self {
        Self {
            outputs: Mutex::new(HashMap::new()),
            snapshot_unconfirmed: Mutex::new(HashMap::new()),
        }
    }

    fn fund(&self, address: &str, sats: u64, outpoint: OutPoint) {
        self.outputs
            .lock()
            .unwrap()
            .insert(address.to_owned(), (sats, outpoint));
    }

    /// The next creation-style snapshot of `address` reports these
    /// unconfirmed outputs (and their inputs) — scripted AFTER the creation
    /// baseline so only the activation tick-1 snapshot can see them.
    fn script_unconfirmed_at_snapshot(
        &self,
        address: &str,
        outputs: Vec<OutPoint>,
        inputs: Vec<OutPoint>,
    ) {
        self.snapshot_unconfirmed
            .lock()
            .unwrap()
            .insert(address.to_owned(), (outputs, inputs));
    }
}

#[async_trait]
impl ElectrumPort for ScriptedElectrum {
    async fn creation_snapshot(
        &self,
        address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        let (unconfirmed_outputs, unconfirmed_inputs) = self
            .snapshot_unconfirmed
            .lock()
            .unwrap()
            .remove(address)
            .unwrap_or_default();
        Ok(CreationSnapshot {
            tip_height: 300,
            baseline_outputs: unconfirmed_outputs.clone(),
            unconfirmed_inputs,
            unconfirmed_outputs,
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        let outputs = self.outputs.lock().unwrap();
        Ok(ObservationReport {
            outputs: targets
                .iter()
                .filter_map(|target| {
                    outputs.get(target.address()).map(|(sats, outpoint)| {
                        paykit_server::bitcoin::ObservedOutput {
                            network: BitcoinNetwork::Testnet,
                            address: target.address().to_owned(),
                            outpoint: *outpoint,
                            sats: *sats,
                            confirmations: 6,
                            confirmed_height: Some(301),
                            present: true,
                        }
                    })
                })
                .collect(),
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
    runtime: Arc<Runtime>,
    stack_id: String,
    store: InvoiceStore,
    outbox: OutboxStore,
    signing_key: SigningKey,
    creator: CreatorFixture,
    reader: ReaderPubky,
    electrum: Arc<ScriptedElectrum>,
    /// Held only for its Drop: dropping the testnet shuts the homeserver
    /// down, and every pubky read (session validation, marker discovery)
    /// fails from that moment.
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

/// Boots the production server over a real database and an ephemeral pubky
/// testnet, with one creator (credentials stored, content lock published)
/// and one reader (marker published). The outbox worker is configured at a
/// 1 h poll so NOTHING delivers unless a test drives the store directly —
/// 'queued' vs 'prepared' visibility is asserted, never raced.
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

    // Reader: marker published, nothing else.
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

    // Creator: credentials in the store, content lock published.
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

    let electrum = Arc::new(ScriptedElectrum::new());
    let server = Server::build_with_transports(
        server_config,
        pool.clone(),
        stack_identity.clone(),
        pubky,
        electrum.clone(),
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
        runtime,
        stack_id: stack_identity.stack_id(),
        signing_key,
        creator: CreatorFixture {
            creator: creator.clone(),
            lock_resource: format!("{creator}{lock_path}"),
            xpub,
            account_index: 0,
        },
        reader,
        electrum,
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

/// Canonical JSON (sorted keys) — the signed-body middleware rejects
/// anything else.
fn payment_request_body(creator: &CreatorPubky, reader: &ReaderPubky, reference: &str) -> String {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "amount_sats": 50_000,
        "creator": creator.to_string(),
        "reader": reader.to_string(),
        "reference": reference,
        "expires_at": EXPIRES_AT,
        "idempotency_key": format!("{reference}:1"),
    }))
    .unwrap()
    .into_iter()
    .map(char::from)
    .collect()
}

fn locks_invoice_body(fixture: &CreatorFixture, reader: &ReaderPubky, bundle: &str) -> String {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": bundle,
        "lock_resource": fixture.lock_resource,
        "reader": reader.to_string(),
    }))
    .unwrap()
    .into_iter()
    .map(char::from)
    .collect()
}

fn activate_body(invoice_id: &str, stack_id: &str, total_sats: u64) -> String {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "activation_attempt": 1,
        "invoice_id": invoice_id,
        "stack_id": stack_id,
        "total_sats": total_sats,
    }))
    .unwrap()
    .into_iter()
    .map(char::from)
    .collect()
}

fn void_body(invoice_id: &str, stack_id: &str) -> String {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "invoice_id": invoice_id,
        "reason": "marketplace_bind_rolled_back",
        "stack_id": stack_id,
    }))
    .unwrap()
    .into_iter()
    .map(char::from)
    .collect()
}

async fn post(stack: &BootedStack, uri: &str, body: String) -> HttpResponse {
    send_http(stack.address, signed_request(&stack.signing_key, uri, body)).await
}

/// Phase 1 on the marketplace entrypoint; asserts 200 and returns the body.
async fn prepare(stack: &BootedStack, reference: &str) -> serde_json::Value {
    let response = post(
        stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, reference),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "prepare body: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()
}

async fn activate(stack: &BootedStack, invoice_id: &str, total_sats: u64) -> HttpResponse {
    post(
        stack,
        &format!("/v0/payment-requests/{invoice_id}/activate"),
        activate_body(invoice_id, &stack.stack_id.clone(), total_sats),
    )
    .await
}

async fn void(stack: &BootedStack, invoice_id: &str) -> HttpResponse {
    post(
        stack,
        &format!("/v0/payment-requests/{invoice_id}/void"),
        void_body(invoice_id, &stack.stack_id.clone()),
    )
    .await
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

async fn outbox_statuses(pool: &PgPool, invoice_id: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT status FROM outbox WHERE invoice_id = $1 ORDER BY depends_on_id NULLS FIRST",
    )
    .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
    .fetch_all(pool)
    .await
    .unwrap()
}

fn assert_b11_prepare_body(body: &serde_json::Value, stack_id: &str, amount_sats: u64) {
    assert_eq!(body["state"], "prepared");
    assert_eq!(body["stack_id"], stack_id);
    assert_eq!(body["allocation_mode"], "shared_manual");
    let nonce = body["nonce_sats"].as_u64().unwrap();
    assert!((1..=999).contains(&nonce), "nonce {nonce} outside [1, 999]");
    assert_eq!(body["total_sats"].as_u64().unwrap(), amount_sats + nonce);
    assert_eq!(body["expires_at"], EXPIRES_AT);
    assert!(
        body["prepare_expires_at"].as_str().is_some(),
        "prepare_expires_at must be set: {body}"
    );
    let fingerprint = body["derived_address_fingerprint"].as_str().unwrap();
    assert_eq!(fingerprint.len(), 16);
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    // The address itself is NEVER in the body (§B.11.3): only its
    // fingerprint leaves the server before activation.
    let serialized = serde_json::to_string(body).unwrap();
    assert!(!serialized.contains("bcrt1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn prepare_returns_the_b11_body_and_zero_claims_on_both_entrypoints() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(61).await;

    // Marketplace entrypoint.
    let body = prepare(&stack, REFERENCE_A).await;
    assert_b11_prepare_body(&body, &stack.stack_id, 50_000);
    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "prepared");
    assert_eq!(
        outbox_statuses(&stack.pool, &invoice_id).await,
        vec!["prepared".to_owned(), "prepared".to_owned()]
    );
    // Zero-claims: `OutboxStore::claim` must never select a 'prepared' row.
    assert!(
        stack
            .outbox
            .claim(uuid::Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "a 'prepared' outbox row must never be claimable"
    );
    // And the invoice is not an observation target while prepared.
    assert!(stack.store.observation_plan().await.unwrap().is_empty());

    // Locks entrypoint: same body shape (expires_at is null until the §B.9
    // expiry edges land for this path), same prepared landing, same
    // zero-claims.
    let locks_response = post(
        &stack,
        "/invoices",
        locks_invoice_body(&stack.creator, &stack.reader, BUNDLE_LOCKS),
    )
    .await;
    assert_eq!(
        locks_response.status,
        StatusCode::OK,
        "locks prepare body: {}",
        String::from_utf8_lossy(&locks_response.body)
    );
    let locks_body = locks_response.json();
    assert_eq!(locks_body["state"], "prepared");
    assert_eq!(locks_body["stack_id"], stack.stack_id);
    assert_eq!(locks_body["allocation_mode"], "shared_manual");
    let locks_nonce = locks_body["nonce_sats"].as_u64().unwrap();
    assert_eq!(
        locks_body["total_sats"].as_u64().unwrap(),
        50_000 + locks_nonce
    );
    assert!(locks_body["expires_at"].is_null());
    let locks_invoice_id = locks_body["invoice_id"].as_str().unwrap().to_owned();
    assert_eq!(
        baseline_state(&stack.pool, &locks_invoice_id).await,
        "prepared"
    );
    assert_eq!(
        outbox_statuses(&stack.pool, &locks_invoice_id).await,
        vec!["prepared".to_owned(), "prepared".to_owned()]
    );
    assert!(
        stack
            .outbox
            .claim(uuid::Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(stack.store.observation_plan().await.unwrap().is_empty());

    stack.shutdown().await;
}

/// §B.11.5: a funded `prepared` address is never observed, never published,
/// never payable.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_funded_prepared_address_is_never_observed_published_or_payable() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(62).await;
    let body = prepare(&stack, REFERENCE_A).await;
    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
    let total_sats = body["total_sats"].as_u64().unwrap();
    let address = stack.invoice_address(0);

    // Fund the derived address (as if a buyer somehow obtained it) with the
    // exact nonce'd total, confirmed well above the creation floor.
    let funding = OutPoint::new(Txid::from_byte_array([77; 32]), 0);
    stack.electrum.fund(&address, total_sats, funding);

    // Zero targets: the invoice is not in the observation plan.
    assert!(
        stack.store.observation_plan().await.unwrap().is_empty(),
        "a prepared invoice must never be an observation target"
    );
    // Zero observations: even a direct application of the funded output
    // changes nothing (the store gate admits only `observing` invoices and
    // reports the no-op as handled).
    assert!(
        stack
            .store
            .apply_bitcoin_observation_at_height(
                &address,
                &BitcoinOutpoint::from_bitcoin(funding),
                total_sats,
                6,
                Some(301),
                true,
            )
            .await
            .unwrap(),
        "a non-observing invoice must no-op the observation"
    );
    let facts: (String, i64) = sqlx::query_as(
        "SELECT payment_status, (SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1) FROM invoices WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    assert_eq!(facts.0, "undetected");
    assert_eq!(facts.1, 0, "no observation row may be written");
    // Zero publishes: both outbox rows are still 'prepared', never claimed.
    assert_eq!(
        outbox_statuses(&stack.pool, &invoice_id).await,
        vec!["prepared".to_owned(), "prepared".to_owned()]
    );
    assert!(
        stack
            .outbox
            .claim(uuid::Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "prepared");

    stack.shutdown().await;
}

/// activate: signature, total and stack_id refusals each leave the invoice
/// and its outbox rows exactly as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn activate_refusals_leave_the_invoice_untouched() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(63).await;
    let body = prepare(&stack, REFERENCE_A).await;
    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
    let total_sats = body["total_sats"].as_u64().unwrap();
    let updated_at: time::OffsetDateTime =
        sqlx::query_scalar("SELECT updated_at FROM invoices WHERE id = $1")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_one(&stack.pool)
            .await
            .unwrap();

    // A stranger's signature is refused by the same middleware the create
    // routes use — the request never reaches the state machine.
    let stranger = SigningKey::from_bytes(&[250; 32]);
    let response = send_http(
        stack.address,
        signed_request(
            &stranger,
            &format!("/v0/payment-requests/{invoice_id}/activate"),
            activate_body(&invoice_id, &stack.stack_id, total_sats),
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    // A wrong echoed total is the R3-3 guard: activation_total_mismatch,
    // no activation.
    let response = activate(&stack, &invoice_id, total_sats - 1).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(
        response.json()["error"]["code"],
        "activation_total_mismatch"
    );

    // A body naming another stack is refused at the first message.
    let response = post(
        &stack,
        &format!("/v0/payment-requests/{invoice_id}/activate"),
        activate_body(
            &invoice_id,
            "production:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19",
            total_sats,
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "stack_identity_mismatch");

    // A path/body invoice-id disagreement is a plain invalid request (the
    // signature covers the body, not the path).
    let response = post(
        &stack,
        &format!("/v0/payment-requests/{}/activate", uuid::Uuid::new_v4()),
        activate_body(&invoice_id, &stack.stack_id, total_sats),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    // NO state change anywhere.
    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "prepared");
    assert_eq!(
        outbox_statuses(&stack.pool, &invoice_id).await,
        vec!["prepared".to_owned(), "prepared".to_owned()]
    );
    let after: time::OffsetDateTime =
        sqlx::query_scalar("SELECT updated_at FROM invoices WHERE id = $1")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_one(&stack.pool)
            .await
            .unwrap();
    assert_eq!(
        after, updated_at,
        "a refusal must not touch the invoice row"
    );

    stack.shutdown().await;
}

/// activate success: `prepared → observing`, both rows queued, the §B.4.6
/// tick-1 snapshot persisted, `activated_at` set — and a replay returns the
/// identical body while writing nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn activate_flips_persists_the_tick1_snapshot_and_replays_without_writes() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(64).await;
    let body = prepare(&stack, REFERENCE_A).await;
    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
    let total_sats = body["total_sats"].as_u64().unwrap();
    let address = stack.invoice_address(0);

    // R1's case: a transaction the Electrum had not indexed at the creation
    // baseline is unconfirmed at the activation (tick-1) snapshot.
    let pre_existing = OutPoint::new(Txid::from_byte_array([88; 32]), 1);
    let spent_input = OutPoint::new(Txid::from_byte_array([89; 32]), 0);
    stack
        .electrum
        .script_unconfirmed_at_snapshot(&address, vec![pre_existing], vec![spent_input]);

    let response = activate(&stack, &invoice_id, total_sats).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "activate body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let activated = response.json();
    assert_eq!(activated["state"], "observing");
    assert_eq!(activated["invoice_id"], invoice_id);
    assert_eq!(activated["total_sats"], total_sats);
    assert_eq!(activated["expires_at"], EXPIRES_AT);
    assert!(activated["activated_at"].as_str().is_some());

    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "observing");
    assert_eq!(
        outbox_statuses(&stack.pool, &invoice_id).await,
        vec!["queued".to_owned(), "queued".to_owned()]
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT activated_at IS NOT NULL FROM invoices WHERE id = $1"
        )
        .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
        .fetch_one(&stack.pool)
        .await
        .unwrap()
    );
    // The tick-1 snapshot is persisted: the unconfirmed output is a
    // `pre_existing` baseline member and its inputs are recorded for the
    // §B.4.3 replacement rule.
    let baseline_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT txid || ':' || vout, kind FROM invoice_baseline_outpoints WHERE invoice_id = $1 ORDER BY kind",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_all(&stack.pool)
    .await
    .unwrap();
    assert_eq!(
        baseline_rows,
        vec![
            (pre_existing.to_string(), "pre_existing".to_owned()),
            (spent_input.to_string(), "replaced_input".to_owned()),
        ]
    );

    // The `pre_existing` output is permanently ineligible: funded confirmed
    // above the floor, it writes no observation and changes no status.
    assert!(
        stack
            .store
            .apply_bitcoin_observation_at_height(
                &address,
                &BitcoinOutpoint::from_bitcoin(pre_existing),
                total_sats,
                1,
                Some(301),
                true,
            )
            .await
            .unwrap()
    );
    let facts: (String, i64) = sqlx::query_as(
        "SELECT payment_status, (SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1) FROM invoices WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    assert_eq!(facts.0, "undetected");
    assert_eq!(facts.1, 0);

    // Replay: the same body, and provably no writes (row counts and
    // updated_at columns unchanged).
    let before: (time::OffsetDateTime, i64, i64) = sqlx::query_as(
        "SELECT updated_at, \
                (SELECT COUNT(*) FROM outbox WHERE invoice_id = $1), \
                (SELECT COUNT(*) FROM invoice_baseline_outpoints WHERE invoice_id = $1) \
         FROM invoices WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    let outbox_updated: Vec<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT updated_at FROM outbox WHERE invoice_id = $1 ORDER BY id")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_all(&stack.pool)
            .await
            .unwrap();
    let replay = activate(&stack, &invoice_id, total_sats).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(
        replay.body, response.body,
        "activate replay must be byte-identical"
    );
    let after: (time::OffsetDateTime, i64, i64) = sqlx::query_as(
        "SELECT updated_at, \
                (SELECT COUNT(*) FROM outbox WHERE invoice_id = $1), \
                (SELECT COUNT(*) FROM invoice_baseline_outpoints WHERE invoice_id = $1) \
         FROM invoices WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    assert_eq!(after, before, "an activate replay must write nothing");
    let outbox_updated_after: Vec<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT updated_at FROM outbox WHERE invoice_id = $1 ORDER BY id")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_all(&stack.pool)
            .await
            .unwrap();
    assert_eq!(outbox_updated_after, outbox_updated);

    stack.shutdown().await;
}

/// void: `prepared → void_cancelled`, an idempotent replay, and the named
/// errors of §B.11.3/§B.11.6 for every other state.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn void_and_activate_named_errors_for_every_state() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(65).await;

    // prepared → void_cancelled; the replay returns the same body.
    let body = prepare(&stack, REFERENCE_A).await;
    let voided_id = body["invoice_id"].as_str().unwrap().to_owned();
    let response = void(&stack, &voided_id).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "void body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let voided = response.json();
    assert_eq!(voided["state"], "void_cancelled");
    assert_eq!(voided["invoice_id"], voided_id);
    assert!(voided["voided_at"].as_str().is_some());
    assert_eq!(
        baseline_state(&stack.pool, &voided_id).await,
        "void_cancelled"
    );
    let replay = void(&stack, &voided_id).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(
        replay.body, response.body,
        "void replay must be byte-identical"
    );
    // activate on a voided invoice is the named finalized refusal.
    let response = activate(&stack, &voided_id, body["total_sats"].as_u64().unwrap()).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "invoice_finalized");
    // A phase-1 replay against the voided binding is the same named error.
    let response = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, REFERENCE_A),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "invoice_finalized");

    // void on `observing` is refused: a published request expires through
    // the tail, it never vanishes.
    let body = prepare(&stack, REFERENCE_B).await;
    let observing_id = body["invoice_id"].as_str().unwrap().to_owned();
    let total_b = body["total_sats"].as_u64().unwrap();
    let response = activate(&stack, &observing_id, total_b).await;
    assert_eq!(response.status, StatusCode::OK);
    let response = void(&stack, &observing_id).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "invoice_finalized");
    assert_eq!(
        baseline_state(&stack.pool, &observing_id).await,
        "observing"
    );
    // A phase-1 replay on `observing` returns the stored body (B.11.6).
    let response = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, REFERENCE_B),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    let replayed = response.json();
    assert_eq!(replayed["state"], "observing");
    assert_eq!(replayed["invoice_id"], observing_id);
    assert_eq!(replayed["total_sats"], total_b);

    // Reaped at prepare_expires_at: activate is `prepare_expired`, void is
    // the already-satisfied 200, and a phase-1 replay is `prepare_expired`.
    let body = prepare(&stack, REFERENCE_C).await;
    let reaped_id = body["invoice_id"].as_str().unwrap().to_owned();
    sqlx::query(
        "UPDATE invoices SET prepare_expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&reaped_id).unwrap())
    .execute(&stack.pool)
    .await
    .unwrap();
    assert_eq!(stack.store.reap_expired_prepares().await.unwrap(), 1);
    assert_eq!(
        baseline_state(&stack.pool, &reaped_id).await,
        "void_prepare_expired"
    );
    let response = activate(&stack, &reaped_id, body["total_sats"].as_u64().unwrap()).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "prepare_expired");
    let response = void(&stack, &reaped_id).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["state"], "void_prepare_expired");
    let response = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, REFERENCE_C),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "prepare_expired");

    // unknown_invoice on both phase-2 routes (404), behind a valid
    // signature and the correct stack_id.
    let unknown = uuid::Uuid::new_v4().to_string();
    let response = activate(&stack, &unknown, 1).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.json()["error"]["code"], "unknown_invoice");
    let response = void(&stack, &unknown).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.json()["error"]["code"], "unknown_invoice");

    // void naming another stack is refused before touching anything.
    let response = post(
        &stack,
        &format!("/v0/payment-requests/{observing_id}/void"),
        void_body(
            &observing_id,
            "production:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19",
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "stack_identity_mismatch");
    assert_eq!(
        baseline_state(&stack.pool, &observing_id).await,
        "observing"
    );

    stack.shutdown().await;
}

const REAPER_CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

fn reaper_reader() -> ReaderPubky {
    for character in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = REAPER_CREATOR.to_owned();
        candidate.replace_range(5..6, &character.to_string());
        if let Ok(reader) = parse_reader(&candidate) {
            return reader;
        }
    }
    panic!("valid reader fixture")
}

fn test_marker() -> paykit_lib::PaykitReceiverMarker {
    paykit_lib::PaykitReceiverMarker::new(
        PaykitReceiverPath::new("bitkit/wallet").unwrap(),
        PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: false,
        },
        paykit_lib::PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy")
            .unwrap(),
    )
}

struct ReaperPayloads(ReaderPubky);
impl NewReaderPayloadFactory for ReaperPayloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        Ok(NewReaderPayloads {
            endpoint_intent:
                paykit_server::application::semantic_intent::DeliveryIntentV1::endpoint(
                    self.0.to_string(),
                    &test_marker(),
                    PaykitReceiverPath::new("paykit/server").unwrap(),
                    vec![(
                        paykit_lib::PaymentEndpointIdentifier::new("btc-testnet-p2wpkh").unwrap(),
                        paykit_lib::PaymentEndpointPayload::new(
                            serde_json::json!({ "value": format!("reaper-address-{child_index}") })
                                .to_string(),
                        ),
                    )],
                )
                .unwrap(),
            bitcoin_address: format!("reaper-address-{child_index}"),
        })
    }
}

/// The §B.11.1 reaper: one query per tick, `prepared` past
/// `prepare_expires_at` → `void_prepare_expired`; anything else untouched.
#[tokio::test]
async fn reaper_voids_expired_prepares_and_nothing_else() {
    let database = TestDatabase::create().await;
    let pool = database.pool();
    run_migrations(pool).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = parse_creator(REAPER_CREATOR).unwrap();
    CreatorStore::new(pool, crypto.clone())
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                "session".into(),
                ReceiverNoiseSecretKey::new([9; 32]),
                "xpub".into(),
                0,
            ),
            &Default::default(),
            &key_tail(66),
            &ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let store = InvoiceStore::new(pool, crypto);
    let reader = reaper_reader();
    let payloads = ReaperPayloads(reader.clone());

    fn input<'a>(
        creator: &'a CreatorPubky,
        reader: &'a ReaderPubky,
        payloads: &'a ReaperPayloads,
        bundle: &'a [u8],
    ) -> AtomicInvoiceInput<'a> {
        AtomicInvoiceInput {
            creator,
            reader,
            bundle_binding: bundle,
            payment_request_binding: bundle,
            new_reader_payloads: payloads,
            payment_request_intent:
                paykit_server::application::semantic_intent::DeliveryIntentV1::payment_request(
                    reader.to_string(),
                    &test_marker(),
                    PaykitReceiverPath::new("paykit/server").unwrap(),
                    &paykit_lib::PaymentRequestTerms {
                        amount: paykit_lib::PaymentAmount::new("0.00001010", "btc").unwrap(),
                        payment_reference: paykit_lib::PaymentReference::new(
                            uuid::Uuid::new_v4().hyphenated().to_string(),
                        )
                        .unwrap(),
                        proposal_expires_at: None,
                        recurrence: None,
                        accepted_payment_endpoint_identifiers: vec![
                            paykit_lib::PaymentEndpointIdentifier::new("btc-testnet-p2wpkh")
                                .unwrap(),
                        ],
                        metadata: Default::default(),
                    },
                )
                .unwrap(),
            required_sats: 101,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: None,
        }
    }

    // Three invoices: an expired prepare, a live prepare, an observing one.
    let expired = store
        .create_awaiting_baseline(input(&creator, &reader, &payloads, b"reaper-expired"))
        .await
        .unwrap();
    let live = store
        .create_awaiting_baseline(input(&creator, &reader, &payloads, b"reaper-live"))
        .await
        .unwrap();
    let observing = store
        .create_awaiting_baseline(input(&creator, &reader, &payloads, b"reaper-observing"))
        .await
        .unwrap();
    for created in [&expired, &live, &observing] {
        store
            .complete_creation_baseline(created.invoice_id(), 100, &[], &[])
            .await
            .unwrap();
    }
    store
        .activate_invoice(observing.invoice_id(), &[], &[])
        .await
        .unwrap();
    sqlx::query(
        "UPDATE invoices SET prepare_expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
    )
    .bind(expired.invoice_id())
    .execute(pool)
    .await
    .unwrap();

    assert_eq!(store.reap_expired_prepares().await.unwrap(), 1);
    let states: Vec<String> =
        sqlx::query_scalar("SELECT baseline_state FROM invoices ORDER BY created_at, id")
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(
        states,
        vec!["void_prepare_expired", "prepared", "observing"]
    );
    // Final and never a target; the reaper is idempotent and never selects
    // `observing`.
    assert_eq!(store.reap_expired_prepares().await.unwrap(), 0);
    assert_eq!(store.observation_plan().await.unwrap().len(), 1);

    database.cleanup().await;
}

/// A phase-1 replay on `prepared` mints nothing: the derivation cursor, the
/// nonce, the outbox row count and every body field are equal before/after.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn prepare_replay_on_prepared_mints_nothing_and_returns_the_stored_body() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(67).await;
    let body = prepare(&stack, REFERENCE_A).await;

    let cursor_before: i64 = sqlx::query_scalar("SELECT next_child_index FROM creators")
        .fetch_one(&stack.pool)
        .await
        .unwrap();
    let outbox_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox")
        .fetch_one(&stack.pool)
        .await
        .unwrap();

    let replay = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, REFERENCE_A),
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(
        replay.json(),
        body,
        "a replay returns the stored body byte-for-byte"
    );

    let cursor_after: i64 = sqlx::query_scalar("SELECT next_child_index FROM creators")
        .fetch_one(&stack.pool)
        .await
        .unwrap();
    let outbox_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox")
        .fetch_one(&stack.pool)
        .await
        .unwrap();
    assert_eq!(cursor_after, cursor_before, "no second index is burned");
    assert_eq!(
        outbox_after, outbox_before,
        "no second outbox row is minted"
    );

    stack.shutdown().await;
}

/// W1.4 continuity: a hidden offer refuses a New prepare with 503
/// `bitcoin_offer_unavailable`, while activate and void of an existing
/// `prepared` invoice keep working (they are never gated).
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn hidden_offer_gates_prepare_but_never_activate_or_void() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(68).await;
    let first = prepare(&stack, REFERENCE_A).await;
    let second = prepare(&stack, REFERENCE_B).await;

    // Drive the offer-availability hysteresis to hidden.
    for _ in 0..3 {
        stack.runtime.record_electrum_probe_failure();
    }
    assert!(!stack.runtime.readiness().await.bitcoin_offer_available);

    let response = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, REFERENCE_C),
    )
    .await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json()["error"]["code"],
        "bitcoin_offer_unavailable"
    );

    // activate/void are never gated by offer availability (§C.16: refusing
    // them would strand exactly the prepared invoices the switch drains).
    let response = activate(
        &stack,
        first["invoice_id"].as_str().unwrap(),
        first["total_sats"].as_u64().unwrap(),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "activate under a hidden offer: {}",
        String::from_utf8_lossy(&response.body)
    );
    let response = void(&stack, second["invoice_id"].as_str().unwrap()).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "void under a hidden offer: {}",
        String::from_utf8_lossy(&response.body)
    );

    stack.shutdown().await;
}
