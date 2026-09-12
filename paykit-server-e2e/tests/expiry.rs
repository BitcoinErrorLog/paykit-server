//! W1.4b — Payment Request expiry and the observation tail (design §B.9,
//! §B.11.1), against real Postgres and the production HTTP path.
//!
//! Covered here, each test named in the work-item report:
//! - missing / past / over-maximum `expires_at` refused on BOTH prepare
//!   entrypoints with the named `invalid_request` reasons and zero
//!   allocation;
//! - `proposal_expires_at` present on the published request and equal to
//!   the persisted column;
//! - `observing → expired_tail` at the boundary (and not before),
//!   `expired_tail → expired_final` at `expires_at + 24 h` — the clock is
//!   injected through the test seam (SQL timestamp moves plus direct
//!   `apply_expiry_transitions` calls), never by sleeping;
//! - `observation_plan()` order: tail targets after every live target,
//!   `expired_final` absent;
//! - the long-outage case through the real observer seam: one production
//!   `observe_tick` over the real `InvoiceStore` leaves a long-overdue
//!   `observing` invoice `expired_final` and absent from the plan, never
//!   observed and never a late settlement;
//! - an eligible observation in the tail is recorded with
//!   `late_settlement = true` and can never drive settlement — for an
//!   `exclusive` creator and for a `shared_manual` creator at the exact
//!   amount, with the flag carried on `/transactions/status`.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
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
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    bitcoin::ObservationTarget,
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext},
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    domain::payment::BitcoinOutpoint,
    persistence::{CreatorCredentials, CreatorStore, InvoiceStore, OutboxStore},
    runtime::{ElectrumProbe, Runtime},
    startup::initialize_database,
    workers::observer::{
        CreationSnapshot, ElectrumPort, ObservationReport, ObserverError, ObserverPolicy,
        ObserverTickOutcome, ObserverTickState, RequestLimiter, TipProbe, observe_tick,
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
const TAIL: Duration = Duration::from_secs(24 * 60 * 60);
static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// §B.9: a valid expiry inside the default 24 h `max_request_expiry`.
fn expires_in(hours: i64) -> String {
    (time::OffsetDateTime::now_utc() + time::Duration::hours(hours))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

struct ScriptedElectrum {
    outputs: Mutex<HashMap<String, (u64, OutPoint)>>,
    probes: AtomicUsize,
    probe_completed: tokio::sync::Notify,
}

impl ScriptedElectrum {
    fn new() -> Self {
        Self {
            outputs: Mutex::new(HashMap::new()),
            probes: AtomicUsize::new(0),
            probe_completed: tokio::sync::Notify::new(),
        }
    }

    fn probe_count(&self) -> usize {
        self.probes.load(Ordering::Acquire)
    }

    /// Completes once at least one `probe` call has finished — at boot
    /// that is the background observer's initial zero-delay tick.
    /// `notify_one` stores a permit when no waiter is registered yet, so
    /// this is lost-wakeup-safe in both orders: a probe that finished
    /// before the await still releases it, and a later probe wakes an
    /// already-registered waiter.
    async fn first_probe_completed(&self) {
        self.probe_completed.notified().await
    }
}

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
        let tip = TipProbe {
            height: 300,
            time_unix: fresh_tip_time(),
        };
        self.probes.fetch_add(1, Ordering::AcqRel);
        self.probe_completed.notify_one();
        Ok(tip)
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
creation_enabled = true
network = "testnet"
[deployment]
stack_role = "proof"
[electrum]
endpoint = "tcp://127.0.0.1:1"
poll_interval = "1h"
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
    #[allow(dead_code)]
    outbox: OutboxStore,
    signing_key: SigningKey,
    creator: CreatorFixture,
    reader: ReaderPubky,
    electrum: Arc<ScriptedElectrum>,
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
/// 1 h poll so NOTHING delivers unless a test drives the store directly,
/// and the observer at a 1 h poll so its only background tick runs at boot
/// — before any invoice exists — and every expiry transition in this file
/// is driven explicitly by the test (directly, or through one
/// `observe_tick` call), never stolen by a background tick mid-assertion.
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
    // `observation_loop`'s first tick runs at zero delay regardless of
    // the configured 1 h poll interval, so boot must not return before
    // that initial background probe completed: a test invoice created
    // right after boot would otherwise be visible to a still-running
    // first tick. The `Notify` permit makes this await race-free even
    // when the probe finished before we got here; the 1 h poll keeps
    // the next background tick outside every test's lifetime.
    electrum.first_probe_completed().await;
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

fn canonical_json(value: serde_json::Value) -> String {
    serde_json_canonicalizer::to_vec(&value)
        .unwrap()
        .into_iter()
        .map(char::from)
        .collect()
}

/// Marketplace prepare body; `expires_at` is omitted entirely when `None`
/// (the missing-field case) rather than nulled.
fn payment_request_body(
    creator: &CreatorPubky,
    reader: &ReaderPubky,
    reference: &str,
    expires_at: Option<&str>,
) -> String {
    let mut body = serde_json::json!({
        "amount_sats": 50_000,
        "creator": creator.to_string(),
        "reader": reader.to_string(),
        "reference": reference,
        "idempotency_key": format!("{reference}:1"),
    });
    if let Some(expires_at) = expires_at {
        body["expires_at"] = serde_json::json!(expires_at);
    }
    canonical_json(body)
}

fn locks_invoice_body(
    fixture: &CreatorFixture,
    reader: &ReaderPubky,
    bundle: &str,
    expires_at: Option<&str>,
) -> String {
    let mut body = serde_json::json!({
        "bundle_id": bundle,
        "lock_resource": fixture.lock_resource,
        "reader": reader.to_string(),
    });
    if let Some(expires_at) = expires_at {
        body["expires_at"] = serde_json::json!(expires_at);
    }
    canonical_json(body)
}

fn activate_body(invoice_id: &str, stack_id: &str, total_sats: u64) -> String {
    canonical_json(serde_json::json!({
        "activation_attempt": 1,
        "invoice_id": invoice_id,
        "stack_id": stack_id,
        "total_sats": total_sats,
    }))
}

async fn post(stack: &BootedStack, uri: &str, body: String) -> HttpResponse {
    send_http(stack.address, signed_request(&stack.signing_key, uri, body)).await
}

/// Marketplace prepare with an explicit expiry; asserts 200.
async fn prepare(stack: &BootedStack, reference: &str, expires_at: &str) -> serde_json::Value {
    let response = post(
        stack,
        "/v0/payment-requests",
        payment_request_body(
            &stack.creator.creator,
            &stack.reader,
            reference,
            Some(expires_at),
        ),
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

/// Locks prepare with an explicit expiry; asserts 200.
async fn prepare_locks(stack: &BootedStack, bundle: &str, expires_at: &str) -> serde_json::Value {
    let response = post(
        stack,
        "/invoices",
        locks_invoice_body(&stack.creator, &stack.reader, bundle, Some(expires_at)),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "locks prepare body: {}",
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

/// Prepare + activate on the marketplace entrypoint; returns
/// (invoice_id, derived address, total_sats).
async fn activated_invoice(
    stack: &BootedStack,
    reference: &str,
    child_index: i64,
) -> (String, String, u64) {
    let body = prepare(stack, reference, &expires_in(1)).await;
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

async fn invoice_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Moves one invoice's `expires_at` relative to the database clock — the
/// test's clock-injection seam; no sleeps anywhere.
async fn shift_expires_at(pool: &PgPool, invoice_id: &str, seconds: i64) {
    sqlx::query("UPDATE invoices SET expires_at = NOW() + make_interval(secs => $2) WHERE id = $1")
        .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
        .bind(seconds)
        .execute(pool)
        .await
        .unwrap();
}

async fn apply_transitions(stack: &BootedStack) -> paykit_server::persistence::ExpiryTransitions {
    stack.store.apply_expiry_transitions(TAIL).await.unwrap()
}

async fn plan_addresses(stack: &BootedStack) -> Vec<String> {
    stack
        .store
        .observation_plan()
        .await
        .unwrap()
        .iter()
        .map(|planned| planned.target().address().to_owned())
        .collect()
}

/// The payment-request terms the buyer's wallet would receive: the sealed
/// outbox intent, decrypted exactly as the delivery worker reads it.
async fn published_terms(
    stack: &BootedStack,
    invoice_id: &str,
) -> paykit_server::application::semantic_intent::PaymentTermsV1 {
    let crypto = Crypto::from_master_key(&[1; 32]).unwrap();
    let row: (uuid::Uuid, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT outbox.id, outbox.intent_envelope, creators.creator_lookup_hash
         FROM outbox
         JOIN invoices ON invoices.id = outbox.invoice_id
         JOIN creators ON creators.id = invoices.creator_id
         WHERE outbox.invoice_id = $1 AND outbox.depends_on_id IS NOT NULL",
    )
    .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    let creator_hash: [u8; 32] = row.2.as_slice().try_into().unwrap();
    let plaintext = crypto
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(
                paykit_server::crypto::LookupHash::from_bytes(creator_hash),
                row.0,
            ),
            &EncryptedEnvelope::from_bytes(row.1),
        )
        .unwrap();
    let intent = DeliveryIntentV1::decode(&plaintext).unwrap();
    match intent.operation() {
        DeliveryOperationV1::PaymentRequestProposal { terms } => terms.clone(),
        DeliveryOperationV1::EndpointPublication { .. } => panic!("claimed endpoint row"),
    }
}

async fn status(stack: &BootedStack, reference: &str) -> serde_json::Value {
    let response = post(
        stack,
        "/transactions/status",
        canonical_json(serde_json::json!({
            "bundle_id": reference,
            "creator": stack.creator.creator.to_string(),
        })),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "status body: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()
}

async fn late_settlement_flag(pool: &PgPool, invoice_id: &str) -> bool {
    sqlx::query_scalar(
        "SELECT late_settlement FROM bitcoin_observations WHERE invoice_id = $1 AND active",
    )
    .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
    .fetch_one(pool)
    .await
    .unwrap()
}

/// missing `expires_at` is refused on BOTH prepare entrypoints with
/// `invalid_request` and allocates nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn missing_expires_at_is_refused_with_zero_allocation() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(91).await;

    let marketplace = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, REFERENCE_A, None),
    )
    .await;
    assert_eq!(marketplace.status, StatusCode::BAD_REQUEST);
    assert_eq!(marketplace.json()["error"]["code"], "invalid_request");

    let locks = post(
        &stack,
        "/invoices",
        locks_invoice_body(&stack.creator, &stack.reader, BUNDLE_LOCKS, None),
    )
    .await;
    assert_eq!(locks.status, StatusCode::BAD_REQUEST);
    assert_eq!(locks.json()["error"]["code"], "invalid_request");

    assert_eq!(
        invoice_count(&stack.pool).await,
        0,
        "a refused prepare must allocate nothing"
    );
    stack.shutdown().await;
}

/// A past `expires_at` is refused on both entrypoints with the named
/// `expires_at_past` reason and allocates nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn past_expires_at_is_refused_with_the_named_reason() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(92).await;
    let past = expires_in(-1);

    let marketplace = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(
            &stack.creator.creator,
            &stack.reader,
            REFERENCE_A,
            Some(&past),
        ),
    )
    .await;
    assert_eq!(marketplace.status, StatusCode::BAD_REQUEST);
    assert_eq!(marketplace.json()["error"]["code"], "invalid_request");
    assert_eq!(marketplace.json()["error"]["reason"], "expires_at_past");

    let locks = post(
        &stack,
        "/invoices",
        locks_invoice_body(&stack.creator, &stack.reader, BUNDLE_LOCKS, Some(&past)),
    )
    .await;
    assert_eq!(locks.status, StatusCode::BAD_REQUEST);
    assert_eq!(locks.json()["error"]["code"], "invalid_request");
    assert_eq!(locks.json()["error"]["reason"], "expires_at_past");

    assert_eq!(invoice_count(&stack.pool).await, 0);
    stack.shutdown().await;
}

/// An `expires_at` beyond `max_request_expiry` (default 24 h) is refused
/// with the named `expires_at_over_maximum` reason and allocates nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn over_maximum_expires_at_is_refused_with_the_named_reason() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(93).await;
    let over_max = expires_in(25);

    let marketplace = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(
            &stack.creator.creator,
            &stack.reader,
            REFERENCE_A,
            Some(&over_max),
        ),
    )
    .await;
    assert_eq!(marketplace.status, StatusCode::BAD_REQUEST);
    assert_eq!(marketplace.json()["error"]["code"], "invalid_request");
    assert_eq!(
        marketplace.json()["error"]["reason"],
        "expires_at_over_maximum"
    );

    let locks = post(
        &stack,
        "/invoices",
        locks_invoice_body(&stack.creator, &stack.reader, BUNDLE_LOCKS, Some(&over_max)),
    )
    .await;
    assert_eq!(locks.status, StatusCode::BAD_REQUEST);
    assert_eq!(locks.json()["error"]["code"], "invalid_request");
    assert_eq!(locks.json()["error"]["reason"], "expires_at_over_maximum");

    assert_eq!(invoice_count(&stack.pool).await, 0);
    stack.shutdown().await;
}

/// `proposal_expires_at` is set on the published request (both entrypoints)
/// and equals the persisted `invoices.expires_at` column.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn published_request_carries_proposal_expires_at_equal_to_the_column() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(94).await;

    for (reference, bundle) in [(REFERENCE_A, None), (BUNDLE_LOCKS, Some(()))] {
        let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::hours(1))
            .replace_nanosecond(123_456_789)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let canonical_expires_at = time::OffsetDateTime::parse(
            &expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
        .replace_nanosecond(123_456_000)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
        let body = if bundle.is_some() {
            prepare_locks(&stack, reference, &expires_at).await
        } else {
            prepare(&stack, reference, &expires_at).await
        };
        assert_eq!(body["expires_at"], canonical_expires_at);
        let invoice_id = body["invoice_id"].as_str().unwrap();
        let terms = published_terms(&stack, invoice_id).await;
        assert_eq!(
            terms.proposal_expires_at.as_deref(),
            Some(canonical_expires_at.as_str()),
            "the published request must carry the expiry for the wallet"
        );
        let column: time::OffsetDateTime =
            sqlx::query_scalar("SELECT expires_at FROM invoices WHERE id = $1")
                .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
                .fetch_one(&stack.pool)
                .await
                .unwrap();
        let column = column
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        assert_eq!(
            column, canonical_expires_at,
            "column and envelope must agree"
        );
    }
    stack.shutdown().await;
}

/// `observing → expired_tail` at `expires_at` — and not before it. The
/// transition is the observer tick's conditional UPDATE, driven here
/// directly; the tail keeps the invoice in the observation plan.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn observing_moves_to_expired_tail_at_the_boundary_and_not_before() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(95).await;
    let (invoice_id, address, _total) = activated_invoice(&stack, REFERENCE_A, 0).await;

    // Not yet: expires in the future (and then two seconds out) — still
    // observing, zero rows transitioned.
    let transitions = apply_transitions(&stack).await;
    assert_eq!(transitions.tailed, 0);
    shift_expires_at(&stack.pool, &invoice_id, 2).await;
    let transitions = apply_transitions(&stack).await;
    assert_eq!(
        transitions.tailed, 0,
        "an invoice must not tail before its expiry"
    );
    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "observing");

    // At the boundary (one second past): the tick moves it, records
    // `expired_tail_at`, and the tail stays observed.
    shift_expires_at(&stack.pool, &invoice_id, -1).await;
    let transitions = apply_transitions(&stack).await;
    assert_eq!(transitions.tailed, 1);
    assert_eq!(
        baseline_state(&stack.pool, &invoice_id).await,
        "expired_tail"
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT expired_tail_at IS NOT NULL FROM invoices WHERE id = $1"
        )
        .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
        .fetch_one(&stack.pool)
        .await
        .unwrap()
    );
    assert_eq!(
        plan_addresses(&stack).await,
        vec![address],
        "the tail is still observed"
    );
    stack.shutdown().await;
}

/// `expired_tail → expired_final` at `expires_at + 24 h` — and not one
/// minute before it. The final state leaves the observation plan.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn expired_tail_moves_to_expired_final_after_the_tail() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(96).await;
    let (invoice_id, address, _total) = activated_invoice(&stack, REFERENCE_A, 0).await;

    shift_expires_at(&stack.pool, &invoice_id, -60).await;
    let transitions = apply_transitions(&stack).await;
    assert_eq!(transitions.tailed, 1);
    assert_eq!(
        baseline_state(&stack.pool, &invoice_id).await,
        "expired_tail"
    );

    // One minute short of the full tail: still expired_tail.
    shift_expires_at(&stack.pool, &invoice_id, -(23 * 3600 + 59 * 60)).await;
    let transitions = apply_transitions(&stack).await;
    assert_eq!(transitions.finalized, 0);
    assert_eq!(
        baseline_state(&stack.pool, &invoice_id).await,
        "expired_tail"
    );

    // Past expires_at + 24 h: final, recorded, and out of the plan.
    shift_expires_at(&stack.pool, &invoice_id, -(24 * 3600 + 60)).await;
    let transitions = apply_transitions(&stack).await;
    assert_eq!(transitions.finalized, 1);
    assert_eq!(
        baseline_state(&stack.pool, &invoice_id).await,
        "expired_final"
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT expired_final_at IS NOT NULL FROM invoices WHERE id = $1"
        )
        .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
        .fetch_one(&stack.pool)
        .await
        .unwrap()
    );
    assert!(
        plan_addresses(&stack).await.is_empty(),
        "expired_final leaves observation_targets (was {address})"
    );
    stack.shutdown().await;
}

/// A long outage must not leave an observing invoice in `expired_tail` for
/// one extra observer tick: the same transition call must finalize it before
/// the plan is loaded. The primary proof is the production transaction in
/// `apply_expiry_transitions` — both UPDATEs commit atomically, so the row
/// is never externally visible in the intermediate tail state. The
/// timestamps are supporting regression evidence: PostgreSQL `NOW()` is
/// transaction-stable, so one transaction stamps `expired_tail_at`,
/// `expired_final_at`, and `updated_at` with one clock value, while two
/// autocommitted statements read the clock independently and would
/// diverge on any clock tick between them.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn long_overdue_observing_invoice_finalizes_in_one_transition_call() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(160).await;
    let (invoice_id, _address, _total) = activated_invoice(&stack, REFERENCE_A, 0).await;

    shift_expires_at(&stack.pool, &invoice_id, -(24 * 3600 + 60)).await;
    let transitions = apply_transitions(&stack).await;

    assert_eq!(transitions.tailed, 1);
    assert_eq!(transitions.finalized, 1);
    assert_eq!(
        baseline_state(&stack.pool, &invoice_id).await,
        "expired_final"
    );
    let (tail_at, final_at, touched_at): (
        time::OffsetDateTime,
        time::OffsetDateTime,
        time::OffsetDateTime,
    ) = sqlx::query_as(
        "SELECT expired_tail_at, expired_final_at, updated_at FROM invoices WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    assert_eq!(
        tail_at, final_at,
        "both transitions stamped one NOW() value, consistent with the single transaction"
    );
    assert_eq!(final_at, touched_at);
    assert!(plan_addresses(&stack).await.is_empty());
    stack.shutdown().await;
}

/// The same long-outage case through the REAL observer seam: the exact
/// `observe_tick` entry point `observation_loop` invokes (server wiring
/// passes the `InvoiceStore` as its `ObservationBackend` and this stack's
/// Electrum port), driven here once over the booted stack's real store,
/// runtime, and port. A long-overdue `observing` invoice must be
/// `expired_final` BEFORE the plan loads inside that same tick: the tick
/// admits zero targets, records zero observations (no late settlement can
/// appear), and never stamps the invoice. The boot's 1 h observer poll
/// guarantees this explicit tick is the only one that sees the invoice.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn long_overdue_observing_invoice_is_final_before_the_plan_inside_one_observer_tick() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(161).await;
    assert_eq!(
        stack.electrum.probe_count(),
        1,
        "exactly the boot-time background probe has run: no background tick can see \
         the invoice created below, and the 1 h poll keeps the next one out of this test"
    );
    let (invoice_id, address, _total) = activated_invoice(&stack, REFERENCE_A, 0).await;
    assert_eq!(
        stack.electrum.probe_count(),
        2,
        "the prepare's creation-baseline probe is the only probe since boot"
    );

    shift_expires_at(&stack.pool, &invoice_id, -(24 * 3600 + 60)).await;
    assert_eq!(
        baseline_state(&stack.pool, &invoice_id).await,
        "observing",
        "no background tick may touch the invoice before the explicit one"
    );

    let policy = ObserverPolicy {
        poll_interval: Duration::from_secs(10),
        max_requests_per_tick: 100,
        max_requests_per_second: 100,
        max_transaction_bytes: 400_000,
        baseline_completion_timeout: Duration::from_secs(60),
        expiry_tail: TAIL,
    };
    let mut tick_state = ObserverTickState::new(&policy);
    let outcome = observe_tick(
        stack.electrum.as_ref(),
        &stack.store,
        &BitcoinNetwork::Testnet,
        &stack.runtime,
        &mut tick_state,
    )
    .await;

    assert_eq!(
        outcome,
        ObserverTickOutcome::Observed {
            processed: 0,
            deferred: 0,
            failed: 0,
        },
        "the invoice must be out of the plan already this tick: {address} observed zero times"
    );
    assert_eq!(
        stack.electrum.probe_count(),
        3,
        "the explicit tick's probe is the third and last: the background loop cannot tick again for 1 h"
    );
    assert_eq!(
        baseline_state(&stack.pool, &invoice_id).await,
        "expired_final"
    );
    assert!(plan_addresses(&stack).await.is_empty());
    let observations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_one(&stack.pool)
            .await
            .unwrap();
    assert_eq!(
        observations, 0,
        "never observed, so never a late settlement"
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT last_attempted_at IS NULL AND last_observed_at IS NULL
             FROM invoices WHERE id = $1"
        )
        .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
        .fetch_one(&stack.pool)
        .await
        .unwrap(),
        "a finalized invoice must not carry an observation stamp"
    );
    stack.shutdown().await;
}

/// `boot()` must return only after the background observer's initial
/// (zero-delay) tick has completed at least one probe: the first tick
/// already ran before any test invoice exists, and the 1 h poll
/// interval keeps the next background tick outside the test's lifetime,
/// so no background tick can ever see a test invoice.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn boot_returns_only_after_the_background_observers_initial_probe() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(162).await;
    assert!(
        stack.electrum.probe_count() >= 1,
        "boot() returned before the background observer's initial probe completed"
    );
    stack.shutdown().await;
}

/// The §B.7 budget admits the plan's prefix, so tail targets are ordered
/// AFTER every live target — asserted on order, not just membership.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn observation_plan_orders_tail_after_live_and_excludes_final() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(97).await;
    let (live_id, live_address, _) = activated_invoice(&stack, REFERENCE_A, 0).await;
    let (tail_id, tail_address, _) = activated_invoice(&stack, REFERENCE_B, 1).await;

    // Tail the SECOND-created invoice: without the live-first ordering the
    // older (first-created) live target would sort behind it by attempt
    // time, so this assertion only passes on the explicit order.
    shift_expires_at(&stack.pool, &tail_id, -60).await;
    apply_transitions(&stack).await;
    assert_eq!(baseline_state(&stack.pool, &tail_id).await, "expired_tail");
    assert_eq!(
        plan_addresses(&stack).await,
        vec![live_address.clone(), tail_address.clone()],
        "every live target precedes every tail target"
    );

    // Finalize the tail target: it leaves the plan; the live target stays.
    shift_expires_at(&stack.pool, &tail_id, -(24 * 3600 + 60)).await;
    apply_transitions(&stack).await;
    assert_eq!(baseline_state(&stack.pool, &tail_id).await, "expired_final");
    assert_eq!(plan_addresses(&stack).await, vec![live_address]);
    // And the live invoice is untouched.
    assert_eq!(baseline_state(&stack.pool, &live_id).await, "observing");
    stack.shutdown().await;
}

/// An eligible observation recorded while the invoice is `expired_tail`
/// carries `late_settlement = true` and can never produce a settlement in
/// the status the marketplace reads — even `confirmed` at the exact
/// nonce'd total, even for an `exclusive` creator. An observation recorded
/// while `observing` carries `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn funded_during_tail_is_late_settlement_and_never_a_settlement() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(98).await;
    // This case is the `exclusive` creator; the shared_manual case has its
    // own test below.
    sqlx::query("UPDATE creators SET allocation_mode = 'exclusive'")
        .execute(&stack.pool)
        .await
        .unwrap();

    // Control: funded while `observing` — not a late settlement.
    let (live_id, live_address, live_total) = activated_invoice(&stack, REFERENCE_A, 0).await;
    assert!(
        stack
            .store
            .apply_bitcoin_observation(
                &live_address,
                &BitcoinOutpoint::from_bitcoin(OutPoint::new(Txid::from_byte_array([71; 32]), 0)),
                live_total,
                6,
                Some(301),
                true,
            )
            .await
            .unwrap()
    );
    assert!(!late_settlement_flag(&stack.pool, &live_id).await);
    let live_status = status(&stack, REFERENCE_A).await;
    assert_eq!(live_status["late_settlement"], false);

    // Tail the second invoice, then fund it at the exact total with six
    // confirmations.
    let (tail_id, tail_address, tail_total) = activated_invoice(&stack, REFERENCE_B, 1).await;
    shift_expires_at(&stack.pool, &tail_id, -60).await;
    apply_transitions(&stack).await;
    assert_eq!(baseline_state(&stack.pool, &tail_id).await, "expired_tail");

    assert!(
        stack
            .store
            .apply_bitcoin_observation(
                &tail_address,
                &BitcoinOutpoint::from_bitcoin(OutPoint::new(Txid::from_byte_array([72; 32]), 0)),
                tail_total,
                6,
                Some(301),
                true,
            )
            .await
            .unwrap(),
        "the tail observation is recorded, never dropped"
    );
    assert!(
        late_settlement_flag(&stack.pool, &tail_id).await,
        "an observation in the tail is a late settlement"
    );
    let late_status = status(&stack, REFERENCE_B).await;
    // The marketplace reads the flag and routes to `manual_review`: this
    // observation can never be the `confirmed` that settles an order.
    assert_eq!(
        late_status["late_settlement"], true,
        "the flag the marketplace's late-settlement path routes on"
    );
    assert_eq!(late_status["status"], "confirmed");
    assert_eq!(late_status["amount_matched"], true);
    // The invoice itself never left the tail on account of the payment.
    assert_eq!(baseline_state(&stack.pool, &tail_id).await, "expired_tail");
    stack.shutdown().await;
}

/// The same rule for a `shared_manual` creator at the exact amount: the
/// `late_settlement` edge fires and the observation can never enter the
/// seller-confirmation path as a settlement (§B.9 / §B.8.8, Kimi P2).
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn late_settlement_holds_for_a_shared_manual_creator_with_exact_amount() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(99).await;
    let mode: String = sqlx::query_scalar("SELECT allocation_mode FROM creators LIMIT 1")
        .fetch_one(&stack.pool)
        .await
        .unwrap();
    assert_eq!(mode, "shared_manual", "the boot fixture is shared_manual");

    let (tail_id, tail_address, tail_total) = activated_invoice(&stack, REFERENCE_C, 0).await;
    shift_expires_at(&stack.pool, &tail_id, -60).await;
    apply_transitions(&stack).await;
    assert_eq!(baseline_state(&stack.pool, &tail_id).await, "expired_tail");

    assert!(
        stack
            .store
            .apply_bitcoin_observation(
                &tail_address,
                &BitcoinOutpoint::from_bitcoin(OutPoint::new(Txid::from_byte_array([73; 32]), 0)),
                tail_total,
                6,
                Some(301),
                true,
            )
            .await
            .unwrap()
    );
    assert!(late_settlement_flag(&stack.pool, &tail_id).await);
    let late_status = status(&stack, REFERENCE_C).await;
    assert_eq!(late_status["late_settlement"], true);
    assert_eq!(late_status["status"], "confirmed");
    assert_eq!(late_status["amount_matched"], true);
    stack.shutdown().await;
}
