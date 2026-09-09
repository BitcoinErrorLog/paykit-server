use std::{
    collections::{BTreeMap, HashMap, HashSet},
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
    InMemoryStorage, LinkedPeerState, PaykitSdk, PaykitSdkConfig, PubkyLocalSecretKey,
    PubkyPublicKey, PubkySessionBootstrap, ReceiverNoiseSecretKey, storage::StorageState,
};
use paykit_server::{
    Server,
    application::create_invoice::derive_bip84_p2wpkh_address,
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    bitcoin::{ObservationTarget, ObservedOutput},
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext},
    domain::locks::{CreatorPubky, ReaderPubky, parse_bundle_id, parse_creator, parse_reader},
    persistence::{
        CreatorCredentials, CreatorStore, InvoiceStore, PostgresStorageAdapter, SdkStateStore,
    },
    startup::initialize_database,
    workers::observer::{
        CandidateTransaction, CreationSnapshot, ElectrumPort, ObservationReport, ObserverError,
        RequestLimiter, TipProbe,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

use sdk_fixtures::{TestPaymentAdapter, TestSessionProvider};

const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const BUNDLE_A: &str = "000G40R40M30E209185GR38E1W";
const BUNDLE_B: &str = "000G40R40M30E209185GR38E2W";
static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

type CreatorSdk = PaykitSdk<PostgresStorageAdapter, TestSessionProvider, TestPaymentAdapter>;
type PeerSdk = PaykitSdk<InMemoryStorage, TestSessionProvider, TestPaymentAdapter>;

struct CreatorFixture {
    creator: CreatorPubky,
    sdk: CreatorSdk,
    lock_resource: String,
    xpub: String,
    account_index: u32,
    address: String,
    amount_sats: u64,
    counter_seed: u64,
}

struct CreatorSpec {
    seed: u8,
    account_index: u32,
    amount_sats: u64,
    counter_seed: u64,
}

type OutboxDiagnostic = (String, bool, i32, Option<String>);

struct DeterministicElectrum {
    outputs: std::sync::Mutex<HashMap<String, (u64, OutPoint)>>,
    requests: Mutex<Vec<String>>,
    active_creation_snapshots: AtomicUsize,
    max_active_creation_snapshots: AtomicUsize,
}

impl DeterministicElectrum {
    fn new(fixtures: &[&CreatorFixture]) -> Self {
        Self {
            outputs: std::sync::Mutex::new(
                fixtures
                    .iter()
                    .enumerate()
                    .map(|(index, fixture)| {
                        (
                            fixture.address.clone(),
                            (
                                fixture.amount_sats,
                                OutPoint::new(Txid::from_byte_array([(index + 11) as u8; 32]), 0),
                            ),
                        )
                    })
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
            active_creation_snapshots: AtomicUsize::new(0),
            max_active_creation_snapshots: AtomicUsize::new(0),
        }
    }

    /// Reprices a fixture output to the nonce'd total its invoice binds at
    /// (§B.8.2): the lock price alone is an underpayment once the invoice's
    /// CSPRNG nonce is added.
    fn set_amount(&self, address: &str, sats: u64) {
        let mut outputs = self.outputs.lock().unwrap();
        let (_, outpoint) = outputs.get(address).unwrap().to_owned();
        outputs.insert(address.to_owned(), (sats, outpoint));
    }
}

#[async_trait]
impl ElectrumPort for DeterministicElectrum {
    async fn creation_snapshot(
        &self,
        _address: &str,
        max_history_entries: usize,
        max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        let active = self
            .active_creation_snapshots
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        self.max_active_creation_snapshots
            .fetch_max(active, Ordering::SeqCst);
        {
            let mut requests = self.requests.lock().unwrap();
            requests.push(format!("script_get_history cap={max_history_entries}"));
            requests.push("script_list_unspent".into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        self.requests.lock().unwrap().push(format!(
            "headers_subscribe tx_bytes={max_transaction_bytes}"
        ));
        self.active_creation_snapshots
            .fetch_sub(1, Ordering::SeqCst);
        Ok(CreationSnapshot {
            tip_height: 300,
            baseline_outputs: Vec::new(),
            unconfirmed_inputs: Vec::new(),
        })
    }

    async fn candidate_transaction(
        &self,
        txid: Txid,
        max_transaction_bytes: usize,
    ) -> Result<CandidateTransaction, ObserverError> {
        self.requests.lock().unwrap().push(format!(
            "transaction_get candidate tx_bytes={max_transaction_bytes}"
        ));
        Ok(CandidateTransaction {
            txid,
            inputs: Vec::new(),
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        self.requests
            .lock()
            .unwrap()
            .push(format!("observer_list_unspent targets={}", targets.len()));
        let outputs = self.outputs.lock().unwrap();
        Ok(ObservationReport {
            outputs: targets
                .iter()
                .filter_map(|target| {
                    outputs
                        .get(target.address())
                        .map(|(sats, outpoint)| ObservedOutput {
                            network: BitcoinNetwork::Testnet,
                            address: target.address().to_owned(),
                            outpoint: *outpoint,
                            sats: *sats,
                            confirmations: 6,
                            confirmed_height: Some(301),
                            present: true,
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
        self.requests
            .lock()
            .unwrap()
            .push("probe headers_subscribe+block_header".into());
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

async fn build_pubky_testnet() -> EphemeralTestnet {
    let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap();
    EphemeralTestnet::builder()
        .postgres(postgres)
        .build()
        .await
        .unwrap()
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

async fn create_creator(
    bootstrap: &PubkySessionBootstrap,
    homeserver: &PubkyPublicKey,
    store: &CreatorStore,
    pool: &PgPool,
    crypto: Arc<Crypto>,
    spec: CreatorSpec,
) -> CreatorFixture {
    let CreatorSpec {
        seed,
        account_index,
        amount_sats,
        counter_seed,
    } = spec;
    let receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            ReceiverNoiseSecretKey::random(),
            homeserver,
            None,
            &PaykitSdkConfig::new(receiver_path.clone()).required_session_capabilities(),
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", account.public_key)).unwrap();
    let xpub = account_xpub(seed, account_index);
    let address =
        derive_bip84_p2wpkh_address(&xpub, account_index, &BitcoinNetwork::Testnet, 0).unwrap();
    let lock = content_lock(&creator, amount_sats);
    let lock_path = lock.content_lock_path().unwrap().to_string();
    account
        .access
        .session
        .storage()
        .put_json(lock_path.clone(), &lock)
        .await
        .unwrap();
    let lock_resource = format!("{creator}{lock_path}");
    let state = StorageState {
        next_outbound_private_message_id: counter_seed,
        ..StorageState::default()
    };
    let row = store
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                account.access.session.export_secret(),
                account.access.receiver_noise_secret_key.clone(),
                xpub.clone(),
                account_index,
            ),
            &state,
        )
        .await
        .unwrap();
    let sdk = PaykitSdk::new(
        PostgresStorageAdapter::new(pool, crypto, row.id()),
        TestSessionProvider::new(account.access),
        TestPaymentAdapter,
        PaykitSdkConfig::new(receiver_path),
    )
    .unwrap();
    sdk.initialize().await.unwrap();
    sdk.publish_paykit_receiver_marker(PaykitReceiverCapabilities {
        private_payments: true,
        payment_requests: true,
        receipts: true,
        outgoing_payments: true,
    })
    .await
    .unwrap();
    CreatorFixture {
        creator,
        sdk,
        lock_resource,
        xpub,
        account_index,
        address,
        amount_sats,
        counter_seed,
    }
}

async fn create_peer(
    bootstrap: &PubkySessionBootstrap,
    homeserver: &PubkyPublicKey,
) -> (ReaderPubky, PubkyPublicKey, PeerSdk) {
    let path = PaykitReceiverPath::new("bitkit/server").unwrap();
    let account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            ReceiverNoiseSecretKey::random(),
            homeserver,
            None,
            &PaykitSdkConfig::new(path.clone()).required_session_capabilities(),
        )
        .await
        .unwrap();
    let key = account.public_key.clone();
    let sdk = PaykitSdk::new(
        InMemoryStorage::default(),
        TestSessionProvider::new(account.access),
        TestPaymentAdapter,
        PaykitSdkConfig::new(path),
    )
    .unwrap();
    sdk.initialize().await.unwrap();
    sdk.publish_paykit_receiver_marker(PaykitReceiverCapabilities {
        private_payments: true,
        payment_requests: true,
        receipts: true,
        outgoing_payments: true,
    })
    .await
    .unwrap();
    (parse_reader(&format!("pubky{key}")).unwrap(), key, sdk)
}

async fn link(
    creator: &CreatorSdk,
    creator_key: PubkyPublicKey,
    peer: &PeerSdk,
    peer_key: PubkyPublicKey,
) {
    let creator_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let peer_path = PaykitReceiverPath::new("bitkit/server").unwrap();
    creator
        .initiate_link_with_peer(peer_key.clone(), peer_path.clone())
        .await
        .unwrap();
    peer.accept_link_with_peer(creator_key.clone(), creator_path.clone())
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut creator_state = LinkedPeerState::Linking;
    let mut peer_state = LinkedPeerState::Linking;
    while creator_state != LinkedPeerState::Linked || peer_state != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "link timed out");
        if creator_state != LinkedPeerState::Linked {
            creator_state = creator
                .advance_link_handshake(peer_key.clone(), peer_path.clone())
                .await
                .unwrap()
                .state;
        }
        if peer_state != LinkedPeerState::Linked {
            peer_state = peer
                .advance_link_handshake(creator_key.clone(), creator_path.clone())
                .await
                .unwrap()
                .state;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn config(database_url: &str, signing_key: &SigningKey, poll_interval: &str) -> Config {
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
poll_interval = "{poll_interval}"
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

fn signed_request(
    signing_key: &SigningKey,
    method: Method,
    uri: &str,
    body: String,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(signing_key.sign(body.as_bytes()).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
}

fn invoice_request(
    signing_key: &SigningKey,
    fixture: &CreatorFixture,
    reader: &ReaderPubky,
    bundle: &str,
) -> Request<Body> {
    signed_request(
        signing_key,
        Method::POST,
        "/invoices",
        format!(
            r#"{{"bundle_id":"{bundle}","lock_resource":"{}","reader":"{reader}"}}"#,
            fixture.lock_resource
        ),
    )
}

fn status_request(
    signing_key: &SigningKey,
    fixture: &CreatorFixture,
    bundle: &str,
) -> Request<Body> {
    signed_request(
        signing_key,
        Method::POST,
        "/transactions/status",
        format!(
            r#"{{"bundle_id":"{bundle}","creator":"{}"}}"#,
            fixture.creator
        ),
    )
}

fn readiness_request() -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri("/health/ready")
        .body(Body::empty())
        .unwrap()
}

struct HttpResponse {
    status: StatusCode,
    body: Vec<u8>,
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
    loop {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server did not bind"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_until_ready(address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if send_http(address, readiness_request()).await.status == StatusCode::OK {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "workers did not publish initial readiness evidence"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_completion(
    pool: &PgPool,
    address: SocketAddr,
    signing_key: &SigningKey,
    fixtures: &[(&CreatorFixture, &str)],
    peer: &PeerSdk,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let intake = peer
            .receive_private_messages_from_linked_peers()
            .await
            .unwrap();
        let intake_errors = intake
            .iter()
            .filter_map(|report| report.error.as_deref())
            .collect::<Vec<_>>();
        assert!(
            intake_errors.is_empty(),
            "peer private-message intake failed for {} peer(s)",
            intake_errors.len()
        );
        let delivered: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM outbox WHERE status = 'delivered'")
                .fetch_one(pool)
                .await
                .unwrap();
        let mut statuses_confirmed = true;
        for (fixture, bundle) in fixtures {
            let response = send_http(address, status_request(signing_key, fixture, bundle)).await;
            if response.status != StatusCode::OK {
                statuses_confirmed = false;
                continue;
            }
            let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            statuses_confirmed &= body
                == serde_json::json!({
                    "status": "confirmed",
                    "confirmations": 6,
                    "amount_matched": true
                });
        }
        if delivered == 4 && statuses_confirmed {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            let rows: Vec<OutboxDiagnostic> = sqlx::query_as(
                "SELECT status, depends_on_id IS NOT NULL, attempt_count, error_class FROM outbox ORDER BY depends_on_id NULLS FIRST",
            )
            .fetch_all(pool)
            .await
            .unwrap();
            let received = peer.payment_requests().await.unwrap().len();
            panic!(
                "composed workflow did not finish: delivered={delivered}, statuses_confirmed={statuses_confirmed}, received={received}, rows={rows:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn raw_database_bytes(pool: &PgPool) -> Vec<Vec<u8>> {
    let mut values = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT value FROM (
             SELECT convert_to(to_jsonb(c)::text, 'UTF8') AS value FROM creators c
             UNION ALL SELECT convert_to(to_jsonb(s)::text, 'UTF8') FROM sdk_states s
             UNION ALL SELECT convert_to(to_jsonb(r)::text, 'UTF8') FROM reader_assignments r
             UNION ALL SELECT convert_to(to_jsonb(i)::text, 'UTF8') FROM invoices i
             UNION ALL SELECT convert_to(to_jsonb(o)::text, 'UTF8') FROM outbox o
             UNION ALL SELECT convert_to(to_jsonb(b)::text, 'UTF8') FROM bitcoin_observations b
         ) protected_bytes",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    let bytea_columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND data_type = 'bytea'
           AND table_name = ANY($1)
         ORDER BY table_name, ordinal_position",
    )
    .bind(
        &[
            "creators",
            "sdk_states",
            "reader_assignments",
            "invoices",
            "outbox",
            "bitcoin_observations",
        ][..],
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(!bytea_columns.is_empty());
    for (table, column) in bytea_columns {
        assert!(
            table
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                && column
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "PostgreSQL returned an invalid durable identifier"
        );
        let query = format!("SELECT \"{column}\" FROM \"{table}\" WHERE \"{column}\" IS NOT NULL");
        values.extend(
            sqlx::query_scalar::<_, Vec<u8>>(&query)
                .fetch_all(pool)
                .await
                .unwrap(),
        );
    }
    values
}

/// Deserialization mirror of the sealed invoice payment record written from
/// W1.1b on; field order must match the product struct exactly.
#[derive(serde::Deserialize)]
struct InvoicePaymentRecordV3 {
    version: u8,
    derivation_index: i64,
    bitcoin_address: String,
    required_sats: u64,
    nonce_sats: u64,
    creation_chain_height: u32,
    baseline_set_hash: [u8; 32],
}

/// Asserts the persisted workflow inputs and returns each fixture's
/// `(address, total_sats)` pair, where the total is the nonce'd amount the
/// invoice binds at (§B.8.2).
async fn assert_persisted_workflow_inputs(
    pool: &PgPool,
    crypto: &Crypto,
    reader: &ReaderPubky,
    fixtures: &[(&CreatorFixture, &str)],
) -> Vec<(String, u64)> {
    type Row = (
        Vec<u8>,
        i64,
        uuid::Uuid,
        Vec<u8>,
        uuid::Uuid,
        Vec<u8>,
        Vec<u8>,
        uuid::Uuid,
        Vec<u8>,
        uuid::Uuid,
        Vec<u8>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT c.creator_lookup_hash, c.next_child_index,
                r.id, r.assignment_envelope,
                i.id, i.invoice_envelope, i.payment_record_envelope,
                endpoint.id, endpoint.intent_envelope,
                payment.id, payment.intent_envelope
         FROM creators c
         JOIN reader_assignments r ON r.creator_id = c.id
         JOIN invoices i ON i.creator_id = c.id
         JOIN outbox payment ON payment.invoice_id = i.id AND payment.depends_on_id IS NOT NULL
         JOIN outbox endpoint ON endpoint.id = payment.depends_on_id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);

    let mut ids = HashSet::new();
    let mut envelopes = HashSet::new();
    let mut totals = Vec::new();
    for (
        creator_hash,
        next_child_index,
        assignment_id,
        assignment_envelope,
        invoice_id,
        invoice_envelope,
        payment_record_envelope,
        endpoint_id,
        endpoint_envelope,
        payment_id,
        payment_envelope,
    ) in rows
    {
        let (fixture, bundle) = fixtures
            .iter()
            .find(|(fixture, _)| {
                crypto
                    .lookup_hash(fixture.creator.to_string().as_bytes())
                    .as_bytes()
                    .as_slice()
                    == creator_hash
            })
            .unwrap();
        assert_eq!(next_child_index, 1, "each Creator must allocate child 0");
        ids.extend([assignment_id, invoice_id, endpoint_id, payment_id]);
        envelopes.extend([
            assignment_envelope,
            invoice_envelope,
            payment_record_envelope.clone(),
            endpoint_envelope.clone(),
            payment_envelope.clone(),
        ]);

        let creator_hash = crypto.lookup_hash(fixture.creator.to_string().as_bytes());
        let endpoint_plaintext = crypto
            .decrypt(
                &EnvelopeContext::outbox_semantic_intent(creator_hash, endpoint_id),
                &EncryptedEnvelope::from_bytes(endpoint_envelope),
            )
            .unwrap();
        let endpoint = DeliveryIntentV1::decode(&endpoint_plaintext).unwrap();
        assert_eq!(endpoint.version(), 2);
        assert_eq!(endpoint.reader_pubky(), reader.to_string());
        assert_eq!(
            endpoint.selected_reader_path().unwrap().as_str(),
            "bitkit/server"
        );
        assert_eq!(
            endpoint.local_receiver_path().unwrap().as_str(),
            "paykit/server"
        );
        assert_ne!(endpoint.marker_fingerprint(), [0; 32]);
        assert!(matches!(
            endpoint.operation(),
            DeliveryOperationV1::EndpointPublication { receiving_details }
                if receiving_details.len() == 1
                    && receiving_details[0].identifier == "btc-testnet-p2wpkh"
                    && serde_json::from_str::<serde_json::Value>(&receiving_details[0].payload)
                        .ok()
                        == Some(serde_json::json!({ "value": fixture.address }))
        ));

        let payment_plaintext = crypto
            .decrypt(
                &EnvelopeContext::outbox_semantic_intent(creator_hash, payment_id),
                &EncryptedEnvelope::from_bytes(payment_envelope),
            )
            .unwrap();
        let payment = DeliveryIntentV1::decode(&payment_plaintext).unwrap();
        assert_eq!(payment.version(), 2);
        assert_eq!(payment.reader_pubky(), reader.to_string());
        assert_eq!(
            payment.selected_reader_path().unwrap().as_str(),
            "bitkit/server"
        );
        assert_eq!(
            payment.local_receiver_path().unwrap().as_str(),
            "paykit/server"
        );
        assert_eq!(payment.marker_fingerprint(), endpoint.marker_fingerprint());
        // The sealed payment record carries the CSPRNG nonce and the nonce'd
        // total (§B.8.2): the total the marketplace would record equals the
        // lock price plus the nonce, and the buyer-facing Payment Request
        // amount is that same total.
        let record_plaintext = crypto
            .decrypt(
                &EnvelopeContext::invoice_payment_record(creator_hash, invoice_id),
                &EncryptedEnvelope::from_bytes(payment_record_envelope),
            )
            .unwrap();
        let record: InvoicePaymentRecordV3 = postcard::from_bytes(&record_plaintext).unwrap();
        assert_eq!(record.version, 3);
        assert_eq!(record.derivation_index, 0);
        assert_eq!(record.bitcoin_address, fixture.address);
        assert_eq!(record.creation_chain_height, 300);
        assert_eq!(
            record.baseline_set_hash,
            bitcoin::hashes::sha256::Hash::hash(b"").to_byte_array()
        );
        assert!(
            (1..=999).contains(&record.nonce_sats),
            "nonce {} outside [1, 999]",
            record.nonce_sats
        );
        let total_sats = fixture.amount_sats + record.nonce_sats;
        assert_eq!(record.required_sats, total_sats);
        totals.push((fixture.address.clone(), total_sats));
        let amount = format!(
            "{}.{:08}",
            total_sats / 100_000_000,
            total_sats % 100_000_000
        );
        assert!(matches!(
            payment.operation(),
            DeliveryOperationV1::PaymentRequestProposal { terms }
                if terms.amount == amount
                    && terms.asset == "btc"
                    && uuid::Uuid::parse_str(&terms.payment_reference)
                        .is_ok_and(|reference| reference.get_version_num() == 4
                            && reference.get_variant() == uuid::Variant::RFC4122
                            && terms.payment_reference == reference.hyphenated().to_string())
                    && terms.proposal_expires_at.is_none()
                    && terms.accepted_endpoint_identifiers == ["btc-testnet-p2wpkh"]
                    && terms.metadata.get("bundle_id") == Some(&serde_json::json!(bundle))
                    && terms.metadata.get("lock_resource")
                        == Some(&serde_json::json!(fixture.lock_resource))
        ));
    }
    assert_eq!(ids.len(), 8, "workflow row identifiers must be distinct");
    assert_eq!(
        envelopes.len(),
        10,
        "Creator-bound envelopes must be distinct"
    );
    totals
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn composed_two_creator_receiver_workflow_survives_restart() {
    parse_bundle_id(BUNDLE_A).unwrap();
    parse_bundle_id(BUNDLE_B).unwrap();
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let first_config = config(database.database_url(), &signing_key, "1h");
    let first_pool = initialize_database(&first_config).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone());
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(&first_pool, crypto.clone());

    let (reader, peer_key, peer_sdk) = create_peer(&bootstrap, &homeserver).await;
    let creator_a = create_creator(
        &bootstrap,
        &homeserver,
        &creators,
        &first_pool,
        crypto.clone(),
        CreatorSpec {
            seed: 41,
            account_index: 0,
            amount_sats: 100,
            counter_seed: 100,
        },
    )
    .await;
    let creator_b = create_creator(
        &bootstrap,
        &homeserver,
        &creators,
        &first_pool,
        crypto.clone(),
        CreatorSpec {
            seed: 42,
            account_index: 1,
            amount_sats: 200,
            counter_seed: 1_000,
        },
    )
    .await;
    assert_ne!(creator_a.creator, creator_b.creator);
    assert_ne!(creator_a.xpub, creator_b.xpub);
    assert_ne!(creator_a.account_index, creator_b.account_index);
    assert_ne!(creator_a.address, creator_b.address);

    link(
        &creator_a.sdk,
        PubkyPublicKey::from_raw_or_app_key(creator_a.creator.to_string()).unwrap(),
        &peer_sdk,
        peer_key.clone(),
    )
    .await;
    link(
        &creator_b.sdk,
        PubkyPublicKey::from_raw_or_app_key(creator_b.creator.to_string()).unwrap(),
        &peer_sdk,
        peer_key,
    )
    .await;

    let observer = Arc::new(DeterministicElectrum::new(&[&creator_a, &creator_b]));
    let first_server = Server::build_with_transports(
        first_config,
        first_pool.clone(),
        pubky.clone(),
        observer.clone(),
    )
    .await
    .unwrap();
    let first_runtime = first_server.runtime();
    let first_router = first_server.router();
    let first_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_address = first_listener.local_addr().unwrap();
    let (_first_shutdown_tx, first_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let first_running = tokio::spawn(first_server.run_until(first_listener, async move {
        let _ = first_shutdown_rx.await;
    }));
    wait_until_listening(first_address).await;
    wait_until_ready(first_address).await;

    let (invoice_a, invoice_b) = tokio::join!(
        send_http(
            first_address,
            invoice_request(&signing_key, &creator_a, &reader, BUNDLE_A)
        ),
        send_http(
            first_address,
            invoice_request(&signing_key, &creator_b, &reader, BUNDLE_B)
        ),
    );
    assert_eq!(
        invoice_a.status,
        StatusCode::NO_CONTENT,
        "Creator A invoice body: {}",
        String::from_utf8_lossy(&invoice_a.body)
    );
    assert_eq!(
        invoice_b.status,
        StatusCode::NO_CONTENT,
        "Creator B invoice body: {}",
        String::from_utf8_lossy(&invoice_b.body)
    );
    let totals = assert_persisted_workflow_inputs(
        &first_pool,
        &crypto,
        &reader,
        &[(&creator_a, BUNDLE_A), (&creator_b, BUNDLE_B)],
    )
    .await;
    // Pay what each invoice actually binds at: the nonce'd total, not the
    // bare lock price (an exact-amount predicate underpays otherwise).
    for (address, total_sats) in totals {
        observer.set_amount(&address, total_sats);
    }

    let queued_before: Vec<(String, i32)> =
        sqlx::query_as("SELECT status, attempt_count FROM outbox ORDER BY id")
            .fetch_all(&first_pool)
            .await
            .unwrap();
    assert_eq!(queued_before.len(), 4);
    assert!(
        queued_before
            .iter()
            .all(|(status, attempts)| status == "queued" && *attempts == 0)
    );

    first_runtime.begin_shutdown();
    let rejected = first_router
        .oneshot(invoice_request(
            &signing_key,
            &creator_a,
            &reader,
            "000G40R40M30E209185GR38E1Y",
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    first_running.await.unwrap().unwrap();
    let queued_after: Vec<(String, i32)> =
        sqlx::query_as("SELECT status, attempt_count FROM outbox ORDER BY id")
            .fetch_all(&first_pool)
            .await
            .unwrap();
    assert_eq!(queued_after, queued_before);

    let second_config = config(database.database_url(), &signing_key, "25ms");
    let second_pool = initialize_database(&second_config).await.unwrap();
    let second_server =
        Server::build_with_transports(second_config, second_pool.clone(), pubky, observer.clone())
            .await
            .unwrap();
    let second_runtime = second_server.runtime();
    let second_router = second_server.router();
    let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_address = second_listener.local_addr().unwrap();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(second_server.run_until(second_listener, async move {
        let _ = shutdown_rx.await;
    }));
    wait_until_listening(second_address).await;
    wait_until_ready(second_address).await;

    wait_for_completion(
        &second_pool,
        second_address,
        &signing_key,
        &[(&creator_a, BUNDLE_A), (&creator_b, BUNDLE_B)],
        &peer_sdk,
    )
    .await;
    assert_eq!(peer_sdk.payment_requests().await.unwrap().len(), 2);
    assert_eq!(
        observer
            .max_active_creation_snapshots
            .load(Ordering::SeqCst),
        1,
        "the configured creation-snapshot semaphore must serialize concurrent creations"
    );
    let requests = observer.requests.lock().unwrap().clone();
    let creation_starts = requests
        .iter()
        .enumerate()
        .filter(|(_, request)| request.as_str() == "script_get_history cap=50")
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(creation_starts.len(), 2, "request log: {requests:?}");
    for start in creation_starts {
        assert_eq!(requests[start + 1], "script_list_unspent");
        assert_eq!(
            requests[start + 2],
            "headers_subscribe tx_bytes=400000",
            "the creation floor tip must be taken after history and unspent"
        );
    }
    assert!(
        requests
            .iter()
            .filter(|request| request.starts_with("transaction_get candidate"))
            .all(|request| request.ends_with("tx_bytes=400000")),
        "candidate fetches must carry the configured byte cap: {requests:?}"
    );
    let mut candidates_since_tick = 0;
    for request in &requests {
        if request.starts_with("observer_list_unspent") {
            assert!(
                candidates_since_tick <= 1,
                "more than one candidate fetch occurred in one observer interval: {requests:?}"
            );
            candidates_since_tick = 0;
        } else if request.starts_with("transaction_get candidate") {
            candidates_since_tick += 1;
        }
    }
    assert!(
        candidates_since_tick <= 1,
        "more than one candidate fetch occurred after the final observer interval: {requests:?}"
    );

    let outbox_rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT status, depends_on_id IS NOT NULL FROM outbox ORDER BY invoice_id, depends_on_id NULLS FIRST",
    )
    .fetch_all(&second_pool)
    .await
    .unwrap();
    assert_eq!(
        outbox_rows,
        vec![
            ("delivered".into(), false),
            ("delivered".into(), true),
            ("delivered".into(), false),
            ("delivered".into(), true),
        ]
    );

    let state_store = SdkStateStore::new(&second_pool, crypto.clone());
    let state_a = state_store.load(&creator_a.creator).await.unwrap();
    let state_b = state_store.load(&creator_b.creator).await.unwrap();
    assert!(state_a.next_outbound_private_message_id > creator_a.counter_seed);
    assert!(state_b.next_outbound_private_message_id > creator_b.counter_seed);

    let raw_rows = raw_database_bytes(&second_pool).await;
    let protected_text = [
        creator_a.creator.to_string(),
        creator_b.creator.to_string(),
        reader.to_string(),
        creator_a.xpub.clone(),
        creator_b.xpub.clone(),
        creator_a.address.clone(),
        creator_b.address.clone(),
        creator_a.lock_resource.clone(),
        creator_b.lock_resource.clone(),
        BUNDLE_A.into(),
        BUNDLE_B.into(),
        "0.00000100".into(),
        "0.00000200".into(),
        Txid::from_byte_array([11; 32]).to_string(),
        Txid::from_byte_array([12; 32]).to_string(),
        format!("{}:0", Txid::from_byte_array([11; 32])),
        format!("{}:0", Txid::from_byte_array([12; 32])),
    ];
    let mut protected = protected_text
        .into_iter()
        .map(String::into_bytes)
        .collect::<Vec<_>>();
    for identity in [
        creator_a.creator.to_string(),
        creator_b.creator.to_string(),
        reader.to_string(),
    ] {
        protected.push(
            PubkyPublicKey::from_raw_or_app_key(identity)
                .unwrap()
                .to_public_key()
                .unwrap()
                .as_bytes()
                .to_vec(),
        );
    }
    protected.extend([
        Txid::from_byte_array([11; 32]).to_byte_array().to_vec(),
        Txid::from_byte_array([12; 32]).to_byte_array().to_vec(),
        creator_a.amount_sats.to_le_bytes().to_vec(),
        creator_a.amount_sats.to_be_bytes().to_vec(),
        creator_b.amount_sats.to_le_bytes().to_vec(),
        creator_b.amount_sats.to_be_bytes().to_vec(),
    ]);
    for plaintext in protected {
        assert!(
            raw_rows.iter().all(|row| {
                !row.windows(plaintext.len())
                    .any(|window| window == plaintext.as_slice())
            }),
            "protected workflow value appeared in raw persistence"
        );
    }

    let structured_numeric_leakage: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM (
                 SELECT to_jsonb(c) AS value FROM creators c
                 UNION ALL SELECT to_jsonb(s) FROM sdk_states s
                 UNION ALL SELECT to_jsonb(r) FROM reader_assignments r
                 UNION ALL SELECT to_jsonb(i) FROM invoices i
                 UNION ALL SELECT to_jsonb(o) FROM outbox o
                 UNION ALL SELECT to_jsonb(b) FROM bitcoin_observations b
             ) rows
             WHERE jsonb_path_exists(value, '$.** ? (@ == 100 || @ == 200)')
         )",
    )
    .fetch_one(&second_pool)
    .await
    .unwrap();
    assert!(
        !structured_numeric_leakage,
        "protected payment amount appeared as a structured numeric value"
    );

    second_runtime.begin_shutdown();
    let rejected_after_final_shutdown = second_router
        .oneshot(status_request(&signing_key, &creator_a, BUNDLE_A))
        .await
        .unwrap();
    assert_eq!(
        rejected_after_final_shutdown.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    running.await.unwrap().unwrap();

    first_pool.close().await;
    second_pool.close().await;
    database.cleanup().await;
}

/// A fault-injection port whose creation snapshot parks on a gate, so a
/// test can drop the HTTP request (client disconnect) after
/// `create_atomic` has committed but before the baseline resolves.
struct GatedSnapshotElectrum {
    snapshot_starts: AtomicUsize,
    release: tokio::sync::Notify,
}

#[async_trait]
impl ElectrumPort for GatedSnapshotElectrum {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        self.snapshot_starts.fetch_add(1, Ordering::SeqCst);
        self.release.notified().await;
        Ok(CreationSnapshot {
            tip_height: 300,
            baseline_outputs: Vec::new(),
            unconfirmed_inputs: Vec::new(),
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        _targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        Ok(ObservationReport::default())
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 300,
            time_unix: fresh_tip_time(),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_creation_cancelled_after_commit_is_in_progress_on_retry_and_voided_by_the_sweeper() {
    parse_bundle_id(BUNDLE_A).unwrap();
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    let signing_key = SigningKey::from_bytes(&[9; 32]);
    let server_config = config(database.database_url(), &signing_key, "1h");
    let pool = initialize_database(&server_config).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone());
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(&pool, crypto.clone());

    let (reader, peer_key, peer_sdk) = create_peer(&bootstrap, &homeserver).await;
    let creator = create_creator(
        &bootstrap,
        &homeserver,
        &creators,
        &pool,
        crypto.clone(),
        CreatorSpec {
            seed: 51,
            account_index: 0,
            amount_sats: 100,
            counter_seed: 500,
        },
    )
    .await;
    link(
        &creator.sdk,
        PubkyPublicKey::from_raw_or_app_key(creator.creator.to_string()).unwrap(),
        &peer_sdk,
        peer_key,
    )
    .await;

    let electrum = Arc::new(GatedSnapshotElectrum {
        snapshot_starts: AtomicUsize::new(0),
        release: tokio::sync::Notify::new(),
    });
    let server =
        Server::build_with_transports(server_config, pool.clone(), pubky, electrum.clone())
            .await
            .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(server.run_until(listener, async move {
        let _ = shutdown_rx.await;
    }));
    wait_until_listening(address).await;
    wait_until_ready(address).await;

    // Drive the creation until the invoice row is committed
    // (`awaiting_baseline`) and the snapshot read is parked on the gate —
    // synchronized on database state and the port counter, not on sleeps.
    let request_task = tokio::spawn(send_http(
        address,
        invoice_request(&signing_key, &creator, &reader, BUNDLE_A),
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if request_task.is_finished() {
            let response = request_task.await.unwrap();
            panic!(
                "creation request finished before the parked snapshot: {} {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            );
        }
        let awaiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invoices WHERE baseline_state = 'awaiting_baseline'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if awaiting == 1 && electrum.snapshot_starts.load(Ordering::SeqCst) == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "creation never reached the parked snapshot"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Client disconnect: the request future is dropped after create_atomic
    // committed, orphaning the awaiting_baseline row.
    request_task.abort();
    let _ = request_task.await;

    // The identical retry must NEVER be an exact replay of an unpublished
    // invoice: it is told the baseline is still resolving.
    let retry = send_http(
        address,
        invoice_request(&signing_key, &creator, &reader, BUNDLE_A),
    )
    .await;
    assert_eq!(
        retry.status,
        StatusCode::CONFLICT,
        "retry body: {}",
        String::from_utf8_lossy(&retry.body)
    );
    let retry_body: serde_json::Value = serde_json::from_slice(&retry.body).unwrap();
    assert_eq!(retry_body["error"]["code"], "invoice_baseline_in_progress");

    // Nothing published: both outbox intents stay `prepared`.
    let statuses: Vec<String> = sqlx::query_scalar("SELECT status FROM outbox ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(statuses, vec!["prepared".to_owned(), "prepared".to_owned()]);

    // The sweeper is the terminal fallback: the orphan is voided and the
    // outbox is never queued.
    let store = InvoiceStore::new(&pool, crypto.clone());
    assert_eq!(
        store
            .sweep_stale_creation_baselines(Duration::ZERO)
            .await
            .unwrap(),
        1
    );
    let state: String = sqlx::query_scalar("SELECT baseline_state FROM invoices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "void_baseline_failed");
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox WHERE status = 'queued'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(queued, 0, "a voided orphan's outbox is never queued");

    // The voided binding is spent: a further retry is a conflict, still
    // never replay success for an invoice that never published.
    let after_void = send_http(
        address,
        invoice_request(&signing_key, &creator, &reader, BUNDLE_A),
    )
    .await;
    assert_eq!(after_void.status, StatusCode::CONFLICT);
    let after_void_body: serde_json::Value = serde_json::from_slice(&after_void.body).unwrap();
    assert_eq!(after_void_body["error"]["code"], "invoice_conflict");

    electrum.release.notify_waiters();
    let _ = shutdown_tx.send(());
    running.await.unwrap().unwrap();
    pool.close().await;
    database.cleanup().await;
}
