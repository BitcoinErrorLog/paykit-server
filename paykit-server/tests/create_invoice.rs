use std::{
    collections::{BTreeMap, VecDeque},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::{
    Extension,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use locks_core::{
    ids::CreatorPubky as RawCreatorPubky,
    lock_policy::{
        AccessPolicy, CONTENT_LOCK_VERSION, ContentLock, Criterion, LockLogic, LockServerConfig,
        VerifierType,
    },
};
use paykit_server::{
    application::create_invoice::{
        AppRegistryDiscovery, CreateInvoiceError, CreateInvoiceRequest, CreateInvoiceService,
        CreatorXpubProvider, DeadlineClock, IntentBuilder, InvoicePersistence, LockFetchError,
        LockFetcher, PaykitIntentBuilder, SessionValidationError, SessionValidator,
        derive_bip84_p2wpkh_address,
    },
    application::semantic_intent::DeliveryIntentV1,
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    domain::locks::{CreatorPubky, parse_addressed_lock_resource, parse_bundle_id, parse_reader},
    http::{
        auth::{SignedLocksAuth, signature_preimage},
        invoices::invoices_router,
    },
    persistence::{AtomicInvoiceInput, AtomicInvoiceResult, InvoicePreflight, PersistenceError},
};
use tower::ServiceExt;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const LOCK_RESOURCE: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/locks.app/000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG.json";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";

fn reader() -> String {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &replacement.to_string());
        if parse_reader(&candidate).is_ok() {
            return candidate;
        }
    }
    panic!("valid reader fixture")
}

fn request() -> CreateInvoiceRequest {
    CreateInvoiceRequest {
        bundle_id: parse_bundle_id(BUNDLE).unwrap(),
        lock_resource: parse_addressed_lock_resource(LOCK_RESOURCE).unwrap(),
        reader: parse_reader(&reader()).unwrap(),
        payment_in: paykit_server::domain::invoice::CriterionPaymentWindowHours::new(24).unwrap(),
    }
}

fn valid_lock() -> ContentLock {
    ContentLock {
        version: CONTENT_LOCK_VERSION,
        creator: RawCreatorPubky::from_str(CREATOR).unwrap(),
        primary_resource: None,
        secondary_resources: BTreeMap::new(),
        criteria: vec![Criterion {
            criterion_id: "payment".into(),
            verifier_type: VerifierType::PaykitPayment,
            params: serde_json::json!({"recipient_pubky":CREATOR,"amount":"50000","asset":"BTC"}),
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

fn capable_registry() -> paykit_lib::PaykitAppRegistry {
    let mut registry = paykit_lib::PaykitAppRegistry::new(Some(
        paykit_lib::derive_paykit_noise_public_key(&[8; 32]),
    ));
    registry
        .register_app(
            paykit_lib::PaykitAppId::new("bitkit").unwrap(),
            paykit_lib::PaykitApp::new(
                "Bitkit",
                paykit_lib::PaykitAppCapabilities {
                    private_payments: true,
                    payment_requests: true,
                    receipts: false,
                    outgoing_payments: true,
                },
            )
            .unwrap(),
        )
        .unwrap();
    registry
}

#[test]
fn library_payment_request_has_exact_terms_amount_and_metadata() {
    let request = request();
    let terms = PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)
        .payment_request_terms(&request, &valid_lock(), "address")
        .unwrap();
    assert_eq!(terms.amount().value(), "0.00050000");
    assert_eq!(terms.amount().asset(), "btc");
    assert_eq!(terms.proposal_expires_at(), &None);
    assert_eq!(terms.recurrence(), &None);
    assert_eq!(
        terms.accepted_payment_endpoint_identifiers()[0].as_str(),
        "btc-bitcoin-p2wpkh"
    );
    assert_eq!(
        serde_json::Value::Object(terms.metadata().clone()),
        serde_json::json!({"bundle_id":BUNDLE,"lock_resource":LOCK_RESOURCE,"reader":reader()})
    );
}

#[test]
fn payment_request_bound_endpoint_uses_the_configured_network() {
    for (network, expected_identifier) in [
        (BitcoinNetwork::Mainnet, "btc-bitcoin-p2wpkh"),
        (BitcoinNetwork::Testnet, "btc-testnet-p2wpkh"),
        (BitcoinNetwork::Signet, "btc-signet-p2wpkh"),
        (BitcoinNetwork::Regtest, "btc-regtest-p2wpkh"),
    ] {
        let builder = PaykitIntentBuilder::new(network);
        let terms = builder
            .payment_request_terms(&request(), &valid_lock(), "address")
            .unwrap();

        assert_eq!(
            terms.accepted_payment_endpoint_identifiers()[0].as_str(),
            expected_identifier
        );
        assert_eq!(
            terms
                .payment_endpoints()
                .unwrap()
                .keys()
                .next()
                .unwrap()
                .as_str(),
            expected_identifier
        );
    }
}

#[test]
fn payment_request_binds_derived_bech32_p2wpkh_address() {
    use bitcoin::{
        Network,
        bip32::{ChildNumber, Xpriv, Xpub},
        secp256k1::Secp256k1,
    };

    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Bitcoin, &[42; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
            ],
        )
        .unwrap();
    let xpub = Xpub::from_priv(&secp, &account).to_string();
    let address = derive_bip84_p2wpkh_address(&xpub, 0, &BitcoinNetwork::Mainnet, 0)
        .expect("valid account xpub derives an address");
    let terms = PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)
        .payment_request_terms(&request(), &valid_lock(), &address)
        .expect("canonical library types accept endpoint");
    let (identifier, payload) = terms.payment_endpoints().unwrap().iter().next().unwrap();
    assert_eq!(identifier.as_str(), "btc-bitcoin-p2wpkh");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(payload.as_str()).unwrap(),
        serde_json::json!({ "value": address })
    );
}

struct FakeStore {
    preflight: Mutex<InvoicePreflight>,
    preflight_calls: AtomicUsize,
    create_calls: AtomicUsize,
}

impl FakeStore {
    fn with_preflight(preflight: InvoicePreflight) -> Self {
        Self {
            preflight: Mutex::new(preflight),
            preflight_calls: AtomicUsize::default(),
            create_calls: AtomicUsize::default(),
        }
    }
}

#[async_trait]
impl InvoicePersistence for FakeStore {
    async fn preflight(
        &self,
        _creator: &CreatorPubky,
        _bundle_binding: &[u8],
        _payment_binding: &[u8],
    ) -> Result<InvoicePreflight, PersistenceError> {
        self.preflight_calls.fetch_add(1, Ordering::SeqCst);
        Ok(*self.preflight.lock().unwrap())
    }

    async fn exact_replay(
        &self,
        _creator: &CreatorPubky,
        _reader: &paykit_server::domain::locks::ReaderPubky,
        _bundle_binding: &[u8],
        _payment_binding: &[u8],
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        Ok(AtomicInvoiceResult::new(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            0,
            time::OffsetDateTime::UNIX_EPOCH,
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(24),
            true,
        ))
    }

    async fn create_atomic(
        &self,
        _input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        Ok(AtomicInvoiceResult::new(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            0,
            time::OffsetDateTime::UNIX_EPOCH,
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(24),
            true,
        ))
    }
}

struct FakeSession {
    result: Result<(), SessionValidationError>,
    calls: AtomicUsize,
    creators: Mutex<Vec<String>>,
}

#[async_trait]
impl SessionValidator for FakeSession {
    async fn validate(&self, creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.creators.lock().unwrap().push(creator.to_string());
        self.result
    }
}

struct FakeLocks {
    result: Result<ContentLock, LockFetchError>,
    calls: AtomicUsize,
}

#[async_trait]
impl LockFetcher for FakeLocks {
    async fn fetch(
        &self,
        _resource: &paykit_server::domain::locks::PubkyLockResource,
    ) -> Result<ContentLock, LockFetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

struct FakeCredentials;

fn account_xpub() -> String {
    use bitcoin::{
        Network,
        bip32::{ChildNumber, Xpriv, Xpub},
        secp256k1::Secp256k1,
    };
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Bitcoin, &[42; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account).to_string()
}

#[async_trait]
impl CreatorXpubProvider for FakeCredentials {
    async fn xpub(&self, _creator: &CreatorPubky) -> Result<(String, u32), PersistenceError> {
        Ok((account_xpub(), 0))
    }
}

struct FixedClock(Mutex<VecDeque<Instant>>);
impl FixedClock {
    fn new(values: impl IntoIterator<Item = Instant>) -> Self {
        Self(Mutex::new(values.into_iter().collect()))
    }
}
impl DeadlineClock for FixedClock {
    fn now(&self) -> Instant {
        self.0.lock().unwrap().pop_front().unwrap()
    }
}

fn service(
    session: Arc<FakeSession>,
    locks: Arc<FakeLocks>,
    store: Arc<FakeStore>,
) -> CreateInvoiceService {
    CreateInvoiceService::new(
        session,
        locks,
        Arc::new(FakeRegistries {
            registry: Some(capable_registry()),
            calls: AtomicUsize::default(),
        }),
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        store,
        Arc::new(PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)),
    )
}

#[tokio::test]
async fn invalid_locks_policy_never_persists_an_invoice() {
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let mut invalid = valid_lock();
    invalid.criteria[0].params = serde_json::json!({
        "recipient_pubky": CREATOR,
        "amount": "0",
        "asset": "BTC"
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(invalid),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));

    assert_eq!(
        service(session.clone(), locks.clone(), store.clone())
            .create(request())
            .await,
        Err(CreateInvoiceError::InvalidRequest)
    );
    assert_eq!(session.calls.load(Ordering::SeqCst), 1);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_and_unavailable_sessions_return_without_store_mutation() {
    for (result, expected) in [
        (
            SessionValidationError::Invalid,
            CreateInvoiceError::CreatorSessionInvalid,
        ),
        (
            SessionValidationError::Unavailable,
            CreateInvoiceError::CreatorSessionUnavailable,
        ),
    ] {
        let session = Arc::new(FakeSession {
            result: Err(result),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        });
        let locks = Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        });
        let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));

        assert_eq!(
            service(session, locks.clone(), store.clone())
                .create(request())
                .await,
            Err(expected)
        );
        assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn exact_replay_returns_persisted_result_without_validator_or_lock_fetch() {
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(valid_lock()),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::ExactReplay));
    let result = service(session.clone(), locks.clone(), store.clone())
        .create(request())
        .await
        .unwrap();
    assert!(result.replayed());
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn changed_binding_returns_conflict_without_validator_or_lock_fetch() {
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(valid_lock()),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::Conflict));

    assert_eq!(
        service(session.clone(), locks.clone(), store.clone())
            .create(request())
            .await,
        Err(CreateInvoiceError::Conflict)
    );
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fifteen_second_deadline_is_safe_and_does_not_commit() {
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(valid_lock()),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let start = Instant::now();
    let service = CreateInvoiceService::with_clock(
        session.clone(),
        locks.clone(),
        Arc::new(FakeRegistries {
            registry: Some(capable_registry()),
            calls: AtomicUsize::default(),
        }),
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        store.clone(),
        Arc::new(PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)),
        Arc::new(FixedClock::new([start, start + Duration::from_secs(15)])),
    );

    assert_eq!(
        service.create(request()).await,
        Err(CreateInvoiceError::DeadlineExceeded)
    );
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn registry_discovery_cannot_start_after_the_whole_request_deadline() {
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(valid_lock()),
        calls: AtomicUsize::default(),
    });
    let registries = Arc::new(FakeRegistries {
        registry: Some(capable_registry()),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let start = Instant::now();
    let service = CreateInvoiceService::with_clock(
        session,
        locks,
        registries.clone(),
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        store.clone(),
        Arc::new(PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)),
        Arc::new(FixedClock::new([
            start,
            start,
            start,
            start,
            start + Duration::from_secs(15),
        ])),
    );

    assert_eq!(
        service.create(request()).await,
        Err(CreateInvoiceError::DeadlineExceeded)
    );
    assert_eq!(registries.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn signed_router_maps_deadline_exhaustion_to_dependency_timeout() {
    let key = SigningKey::from_bytes(&[13; 32]);
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(valid_lock()),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let start = Instant::now();
    let service = CreateInvoiceService::with_clock(
        session,
        locks,
        Arc::new(FakeRegistries {
            registry: Some(capable_registry()),
            calls: AtomicUsize::default(),
        }),
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        store,
        Arc::new(PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)),
        Arc::new(FixedClock::new([start, start + Duration::from_secs(15)])),
    );
    let router = invoices_router(Arc::new(service)).layer(Extension(signed_auth(&key)));
    let body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": BUNDLE,
        "lock_resource": LOCK_RESOURCE,
        "reader": reader()
    }))
    .unwrap();

    let response = router
        .oneshot(signed_invoice_request(&key, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"error":{"code":"dependency_timeout","message":"request deadline exceeded"}})
    );
}

#[tokio::test]
async fn signed_router_distinguishes_session_and_lock_unavailability() {
    let key = SigningKey::from_bytes(&[14; 32]);
    let request_body = || {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "bundle_id": BUNDLE,
            "lock_resource": LOCK_RESOURCE,
            "reader": reader()
        }))
        .unwrap()
    };

    let dependency_router = invoices_router(Arc::new(service(
        Arc::new(FakeSession {
            result: Err(SessionValidationError::Unavailable),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        }),
        Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        }),
        Arc::new(FakeStore::with_preflight(InvoicePreflight::New)),
    )))
    .layer(Extension(signed_auth(&key)));
    let response = dependency_router
        .oneshot(signed_invoice_request(&key, request_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"error":{"code":"creator_session_unavailable","message":"creator session is unavailable"}})
    );

    let lock_router = invoices_router(Arc::new(service(
        Arc::new(FakeSession {
            result: Ok(()),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        }),
        Arc::new(FakeLocks {
            result: Err(LockFetchError::Unavailable),
            calls: AtomicUsize::default(),
        }),
        Arc::new(FakeStore::with_preflight(InvoicePreflight::New)),
    )))
    .layer(Extension(signed_auth(&key)));
    let response = lock_router
        .oneshot(signed_invoice_request(&key, request_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"error":{"code":"lock_resource_unavailable","message":"lock resource is unavailable"}})
    );
}

fn signed_auth(key: &SigningKey) -> Arc<SignedLocksAuth> {
    let key = pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string();
    let config = Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:8080"
[locks]
trusted_public_key = "{key}"
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "mainnet"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "5s"
[limits]
request_body_bytes = 16384
[rate_limits]
signed_requests_per_second = 100
signed_burst = 100
"#
        ),
        ConfigEnvironment {
            database_url: Some("postgres://paykit:secret@localhost/paykit".into()),
            master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()),
        },
    )
    .unwrap();
    Arc::new(SignedLocksAuth::from_config(&config))
}

fn signed_invoice_request(key: &SigningKey, body: Vec<u8>) -> Request<Body> {
    let preimage = signature_preimage("POST", "/invoices", &body);
    Request::builder()
        .method(Method::POST)
        .uri("/invoices")
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn signed_router_parses_canonical_invoice_and_derives_creator_from_lock_resource() {
    let key = SigningKey::from_bytes(&[11; 32]);
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(valid_lock()),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let router = invoices_router(Arc::new(service(session.clone(), locks, store)))
        .layer(Extension(signed_auth(&key)));
    let body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": BUNDLE,
        "lock_resource": LOCK_RESOURCE,
        "reader": reader()
    }))
    .unwrap();

    let response = router
        .oneshot(signed_invoice_request(&key, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({
            "invoice_created_at": "1970-01-01T00:00:00Z",
            "payment_deadline": "1970-01-02T00:00:00Z"
        })
    );
    assert_eq!(session.creators.lock().unwrap().as_slice(), [CREATOR]);
}

#[tokio::test]
async fn signed_router_maps_session_invalid_and_unavailable_and_rejects_bad_identifiers() {
    let key = SigningKey::from_bytes(&[12; 32]);
    for (result, expected) in [
        (SessionValidationError::Invalid, StatusCode::CONFLICT),
        (
            SessionValidationError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let session = Arc::new(FakeSession {
            result: Err(result),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        });
        let locks = Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        });
        let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
        let router = invoices_router(Arc::new(service(session, locks, store)))
            .layer(Extension(signed_auth(&key)));
        let body = serde_json_canonicalizer::to_vec(&serde_json::json!({
            "bundle_id": BUNDLE,
            "lock_resource": LOCK_RESOURCE,
            "reader": reader()
        }))
        .unwrap();
        assert_eq!(
            router
                .oneshot(signed_invoice_request(&key, body))
                .await
                .unwrap()
                .status(),
            expected
        );
    }

    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(valid_lock()),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let router = invoices_router(Arc::new(service(session.clone(), locks, store)))
        .layer(Extension(signed_auth(&key)));
    let body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": BUNDLE,
        "lock_resource": "not-a-lock-resource",
        "reader": reader()
    }))
    .unwrap();
    assert_eq!(
        router
            .oneshot(signed_invoice_request(&key, body))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
}

struct FakeRegistries {
    registry: Option<paykit_lib::PaykitAppRegistry>,
    calls: AtomicUsize,
}

#[async_trait]
impl AppRegistryDiscovery for FakeRegistries {
    async fn discover(
        &self,
        _reader: &paykit_server::domain::locks::ReaderPubky,
    ) -> Result<Option<paykit_lib::PaykitAppRegistry>, CreateInvoiceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.registry.clone())
    }
}

struct CapturingIntentStore {
    captured: Mutex<Vec<DeliveryIntentV1>>,
}

#[async_trait]
impl InvoicePersistence for CapturingIntentStore {
    async fn preflight(
        &self,
        _creator: &CreatorPubky,
        _bundle_binding: &[u8],
        _payment_binding: &[u8],
    ) -> Result<InvoicePreflight, PersistenceError> {
        Ok(InvoicePreflight::New)
    }

    async fn exact_replay(
        &self,
        _creator: &CreatorPubky,
        _reader: &paykit_server::domain::locks::ReaderPubky,
        _bundle_binding: &[u8],
        _payment_binding: &[u8],
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        Err(PersistenceError::CorruptOrMissing)
    }

    async fn create_atomic(
        &self,
        input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        let invoice = input.invoice_payloads.for_child_index(0)?;
        self.captured
            .lock()
            .unwrap()
            .push(invoice.payment_request_intent);
        Ok(AtomicInvoiceResult::new(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            0,
            time::OffsetDateTime::UNIX_EPOCH,
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(24),
            false,
        ))
    }
}

#[tokio::test]
async fn new_invoice_checks_registry_and_binds_invoice_address_to_request() {
    let registry = capable_registry();
    let registries = Arc::new(FakeRegistries {
        registry: Some(registry.clone()),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(CapturingIntentStore {
        captured: Mutex::new(vec![]),
    });
    let service = CreateInvoiceService::new(
        Arc::new(FakeSession {
            result: Ok(()),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        }),
        Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        }),
        registries.clone(),
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        store.clone(),
        Arc::new(PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)),
    );

    service.create(request()).await.unwrap();

    assert_eq!(registries.calls.load(Ordering::SeqCst), 1);
    let captured = store.captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    for intent in captured.iter() {
        assert_eq!(intent.app_id(), "paykit-server");
    }
    assert!(uuid::Uuid::parse_str(&captured[0].terms().unwrap().payment_reference).is_ok());
    assert_eq!(captured[0].terms().unwrap().payment_endpoints.len(), 1);
}

#[test]
fn delivery_intent_is_closed_and_contains_complete_sdk_inputs_not_final_wire_ids() {
    let terms = PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)
        .payment_request_terms(&request(), &valid_lock(), "bc1qmeaningfuladdress")
        .unwrap();
    let intent = DeliveryIntentV1::payment_request(
        reader(),
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        &terms,
    )
    .unwrap();

    assert_eq!(intent.app_id(), "paykit-server");
    assert_eq!(intent.terms().unwrap().payment_endpoints.len(), 1);
    let serialized = postcard::to_allocvec(&intent).unwrap();
    assert!(
        !serialized
            .windows(b"event_id".len())
            .any(|window| window == b"event_id")
    );
    assert!(
        !serialized
            .windows(b"payment_request_id".len())
            .any(|window| window == b"payment_request_id")
    );
}
