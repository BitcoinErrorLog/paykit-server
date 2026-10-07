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
        CreatorReceivingProvider, DeadlineClock, IntentBuilder, InvoicePersistence, LockFetchError,
        LockFetcher, PaykitIntentBuilder, RegistryDiscoveryError, RegistryRetryDelay,
        SessionValidationError, SessionValidator, derive_bip84_p2wpkh_address,
    },
    application::semantic_intent::DeliveryIntentV1,
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    domain::locks::{CreatorPubky, parse_addressed_lock_resource, parse_bundle_id, parse_reader},
    http::{
        auth::{SignedLocksAuth, signature_preimage},
        invoices::invoices_router,
    },
    persistence::{AtomicInvoiceInput, AtomicInvoiceResult, InvoicePreflight, PersistenceError},
    runtime::{DependencyCheck, Runtime, operational_router},
};
use tower::ServiceExt;
use tracing::{Event, Subscriber, instrument::WithSubscriber};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const LOCK_RESOURCE: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/app.locks/000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG.json";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";

type CapturedEvents = Vec<Vec<(String, String)>>;

#[derive(Clone, Default)]
struct EventCapture(Arc<Mutex<CapturedEvents>>);

impl<S> Layer<S> for EventCapture
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = Vec::new();
        event.record(&mut FieldVisitor(&mut fields));
        self.0.lock().unwrap().push(fields);
    }
}

struct FieldVisitor<'a>(&'a mut Vec<(String, String)>);

impl tracing::field::Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }
}

fn event_field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value.trim_matches('"'))
}

struct ReadyDependency;

#[async_trait]
impl DependencyCheck for ReadyDependency {
    async fn postgres_ready(&self) -> bool {
        true
    }
}

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
        .payment_request_terms(&request, &valid_lock(), &bitcoin_receiving("address"), &[])
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
        serde_json::json!({"bundle_id":BUNDLE})
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
            .payment_request_terms(
                &request(),
                &valid_lock(),
                &bitcoin_receiving("address"),
                &[],
            )
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
        .payment_request_terms(&request(), &valid_lock(), &bitcoin_receiving(&address), &[])
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
    created: Mutex<Vec<(DeliveryIntentV1, u64, u64)>>,
}

impl FakeStore {
    fn with_preflight(preflight: InvoicePreflight) -> Self {
        Self {
            preflight: Mutex::new(preflight),
            preflight_calls: AtomicUsize::default(),
            create_calls: AtomicUsize::default(),
            created: Mutex::new(Vec::new()),
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
        input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        self.created.lock().unwrap().push((
            input
                .invoice_payloads
                .for_child_index(0)?
                .payment_request_intent,
            input.proposal_acceptance_seconds,
            input.payment_window_seconds,
        ));
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
impl CreatorReceivingProvider for FakeCredentials {
    async fn receiving(
        &self,
        _creator: &CreatorPubky,
    ) -> Result<paykit_server::application::create_invoice::ReceivingDetails, PersistenceError>
    {
        Ok(
            paykit_server::application::create_invoice::ReceivingDetails {
                bitcoin: Some(paykit_server::domain::receiving::BitcoinAccount {
                    xpub: account_xpub().into(),
                    account_index: 0,
                }),
                usdt: None,
            },
        )
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
    ) -> Result<Option<paykit_lib::PaykitAppRegistry>, RegistryDiscoveryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.registry.clone())
    }
}

struct SequencedRegistries {
    results: Mutex<VecDeque<Result<Option<paykit_lib::PaykitAppRegistry>, RegistryDiscoveryError>>>,
    calls: AtomicUsize,
}

#[async_trait]
impl AppRegistryDiscovery for SequencedRegistries {
    async fn discover(
        &self,
        _reader: &paykit_server::domain::locks::ReaderPubky,
    ) -> Result<Option<paykit_lib::PaykitAppRegistry>, RegistryDiscoveryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.results.lock().unwrap().pop_front().unwrap()
    }
}

#[derive(Default)]
struct ImmediateRetryDelay {
    calls: AtomicUsize,
}

#[async_trait]
impl RegistryRetryDelay for ImmediateRetryDelay {
    async fn wait(&self, _retry_index: usize) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

struct CountingCredentials {
    calls: AtomicUsize,
}

#[async_trait]
impl CreatorReceivingProvider for CountingCredentials {
    async fn receiving(
        &self,
        creator: &CreatorPubky,
    ) -> Result<paykit_server::application::create_invoice::ReceivingDetails, PersistenceError>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        FakeCredentials.receiving(creator).await
    }
}

fn registry_service(
    registries: Arc<dyn AppRegistryDiscovery>,
    retry_delay: Arc<dyn RegistryRetryDelay>,
    credentials: Arc<dyn CreatorReceivingProvider>,
    store: Arc<FakeStore>,
) -> CreateInvoiceService {
    CreateInvoiceService::with_registry_retry(
        Arc::new(FakeSession {
            result: Ok(()),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        }),
        Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        }),
        registries,
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        credentials,
        BitcoinNetwork::Mainnet,
        store,
        Arc::new(PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)),
        retry_delay,
    )
}

#[tokio::test]
async fn missing_registry_retries_twice_then_accepts_capable_reader() {
    let registries = Arc::new(SequencedRegistries {
        results: Mutex::new(VecDeque::from([
            Ok(None),
            Ok(None),
            Ok(Some(capable_registry())),
        ])),
        calls: AtomicUsize::default(),
    });
    let retry_delay = Arc::new(ImmediateRetryDelay::default());
    let credentials = Arc::new(CountingCredentials {
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));

    let result = registry_service(
        registries.clone(),
        retry_delay.clone(),
        credentials.clone(),
        store.clone(),
    )
    .create(request())
    .await;

    assert!(result.is_ok());
    assert_eq!(registries.calls.load(Ordering::SeqCst), 3);
    assert_eq!(retry_delay.calls.load(Ordering::SeqCst), 2);
    assert_eq!(credentials.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exhausted_missing_registry_returns_setup_pending_without_side_effects() {
    let registries = Arc::new(SequencedRegistries {
        results: Mutex::new(VecDeque::from([Ok(None), Ok(None), Ok(None)])),
        calls: AtomicUsize::default(),
    });
    let retry_delay = Arc::new(ImmediateRetryDelay::default());
    let credentials = Arc::new(CountingCredentials {
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));

    assert_eq!(
        registry_service(
            registries.clone(),
            retry_delay.clone(),
            credentials.clone(),
            store.clone(),
        )
        .create(request())
        .await,
        Err(CreateInvoiceError::ReaderSetupPending)
    );
    assert_eq!(registries.calls.load(Ordering::SeqCst), 3);
    assert_eq!(retry_delay.calls.load(Ordering::SeqCst), 2);
    assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn setup_pending_emits_one_redacted_source_diagnostic_with_request_id() {
    let request_id = "d9428888-122b-4b85-bc8f-2c2e0bf7c874";
    let key = SigningKey::from_bytes(&[15; 32]);
    let registries = Arc::new(SequencedRegistries {
        results: Mutex::new(VecDeque::from([Ok(None), Ok(None), Ok(None)])),
        calls: AtomicUsize::default(),
    });
    let service = registry_service(
        registries,
        Arc::new(ImmediateRetryDelay::default()),
        Arc::new(CountingCredentials {
            calls: AtomicUsize::default(),
        }),
        Arc::new(FakeStore::with_preflight(InvoicePreflight::New)),
    );
    let router = operational_router(
        invoices_router(Arc::new(service)).layer(Extension(signed_auth(&key))),
        Arc::new(Runtime::new(Arc::new(ReadyDependency), 1)),
    );
    let body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": BUNDLE,
        "lock_resource": LOCK_RESOURCE,
        "reader": reader()
    }))
    .unwrap();
    let mut request = signed_invoice_request(&key, body);
    request
        .headers_mut()
        .insert("x-request-id", request_id.parse().unwrap());
    let capture = EventCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());

    let response = router
        .oneshot(request)
        .with_subscriber(subscriber)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("retry-after"));
    assert_eq!(response.headers()["x-request-id"], request_id);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"error":{"code":"reader_setup_pending","message":"reader wallet setup needed"}})
    );
    let events: Vec<_> = capture
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event_field(event, "event") == Some("paykit_request_failure"))
        .cloned()
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(
        event_field(&events[0], "stage"),
        Some("reader_app_registry_check")
    );
    assert_eq!(
        event_field(&events[0], "category"),
        Some("reader_setup_pending")
    );
    assert_eq!(event_field(&events[0], "request_id"), Some(request_id));
    assert!(events[0].iter().all(|(name, _)| {
        matches!(
            name.as_str(),
            "message" | "event" | "operation" | "stage" | "category" | "request_id"
        )
    }));
}

#[tokio::test]
async fn incapable_transport_and_malformed_registry_are_not_retried_or_persisted() {
    let cases = [
        (
            Err(RegistryDiscoveryError::InvalidRequest),
            CreateInvoiceError::InvalidRequest,
        ),
        (
            Ok(Some(paykit_lib::PaykitAppRegistry::new(None))),
            CreateInvoiceError::ReaderNotPayable,
        ),
        (
            Err(RegistryDiscoveryError::Unavailable),
            CreateInvoiceError::ReaderRegistryUnavailable,
        ),
        (
            Err(RegistryDiscoveryError::Malformed),
            CreateInvoiceError::ReaderRegistryMalformed,
        ),
    ];

    for (registry_result, expected) in cases {
        let registries = Arc::new(SequencedRegistries {
            results: Mutex::new(VecDeque::from([registry_result])),
            calls: AtomicUsize::default(),
        });
        let retry_delay = Arc::new(ImmediateRetryDelay::default());
        let credentials = Arc::new(CountingCredentials {
            calls: AtomicUsize::default(),
        });
        let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));

        assert_eq!(
            registry_service(
                registries.clone(),
                retry_delay.clone(),
                credentials.clone(),
                store.clone(),
            )
            .create(request())
            .await,
            Err(expected)
        );
        assert_eq!(registries.calls.load(Ordering::SeqCst), 1);
        assert_eq!(retry_delay.calls.load(Ordering::SeqCst), 0);
        assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn signed_router_distinguishes_invalid_reader_from_malformed_remote_registry() {
    let key = SigningKey::from_bytes(&[16; 32]);
    let invalid_registries = Arc::new(SequencedRegistries {
        results: Mutex::new(VecDeque::from([Ok(Some(capable_registry()))])),
        calls: AtomicUsize::default(),
    });
    let invalid_store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let invalid_router = invoices_router(Arc::new(registry_service(
        invalid_registries.clone(),
        Arc::new(ImmediateRetryDelay::default()),
        Arc::new(CountingCredentials {
            calls: AtomicUsize::default(),
        }),
        invalid_store.clone(),
    )))
    .layer(Extension(signed_auth(&key)));
    let invalid_body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": BUNDLE,
        "lock_resource": LOCK_RESOURCE,
        "reader": "not-a-reader"
    }))
    .unwrap();

    let invalid_response = invalid_router
        .oneshot(signed_invoice_request(&key, invalid_body))
        .await
        .unwrap();
    assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);
    assert!(!invalid_response.headers().contains_key("retry-after"));
    let invalid_response_body = axum::body::to_bytes(invalid_response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&invalid_response_body).unwrap(),
        serde_json::json!({"error":{"code":"invalid_request","message":"request is invalid"}})
    );
    assert_eq!(invalid_registries.calls.load(Ordering::SeqCst), 0);
    assert_eq!(invalid_store.create_calls.load(Ordering::SeqCst), 0);

    let malformed_registries = Arc::new(SequencedRegistries {
        results: Mutex::new(VecDeque::from([Err(RegistryDiscoveryError::Malformed)])),
        calls: AtomicUsize::default(),
    });
    let malformed_store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let malformed_router = invoices_router(Arc::new(registry_service(
        malformed_registries.clone(),
        Arc::new(ImmediateRetryDelay::default()),
        Arc::new(CountingCredentials {
            calls: AtomicUsize::default(),
        }),
        malformed_store.clone(),
    )))
    .layer(Extension(signed_auth(&key)));
    let malformed_body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": BUNDLE,
        "lock_resource": LOCK_RESOURCE,
        "reader": reader()
    }))
    .unwrap();

    let malformed_response = malformed_router
        .oneshot(signed_invoice_request(&key, malformed_body))
        .await
        .unwrap();
    assert_eq!(malformed_response.status(), StatusCode::BAD_GATEWAY);
    assert!(!malformed_response.headers().contains_key("retry-after"));
    let malformed_response_body = axum::body::to_bytes(malformed_response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&malformed_response_body).unwrap(),
        serde_json::json!({"error":{"code":"reader_registry_malformed","message":"reader registry is malformed"}})
    );
    assert_eq!(malformed_registries.calls.load(Ordering::SeqCst), 1);
    assert_eq!(malformed_store.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn exact_replay_skips_missing_registry_and_retry_delay() {
    let registries = Arc::new(SequencedRegistries {
        results: Mutex::new(VecDeque::from([Ok(None)])),
        calls: AtomicUsize::default(),
    });
    let retry_delay = Arc::new(ImmediateRetryDelay::default());
    let credentials = Arc::new(CountingCredentials {
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::ExactReplay));

    let result = registry_service(
        registries.clone(),
        retry_delay.clone(),
        credentials.clone(),
        store,
    )
    .create(request())
    .await
    .unwrap();

    assert!(result.replayed());
    assert_eq!(registries.calls.load(Ordering::SeqCst), 0);
    assert_eq!(retry_delay.calls.load(Ordering::SeqCst), 0);
    assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_registry_retry_stays_inside_request_deadline() {
    let registries = Arc::new(SequencedRegistries {
        results: Mutex::new(VecDeque::from([Ok(None), Ok(Some(capable_registry()))])),
        calls: AtomicUsize::default(),
    });
    let retry_delay = Arc::new(ImmediateRetryDelay::default());
    let credentials = Arc::new(CountingCredentials {
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let start = Instant::now();
    let service = CreateInvoiceService::with_clock_and_registry_retry(
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
        credentials.clone(),
        BitcoinNetwork::Mainnet,
        store.clone(),
        Arc::new(PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)),
        Arc::new(FixedClock::new([
            start,
            start,
            start,
            start,
            start,
            start + Duration::from_secs(15),
        ])),
        retry_delay.clone(),
    );

    assert_eq!(
        service.create(request()).await,
        Err(CreateInvoiceError::DeadlineExceeded)
    );
    assert_eq!(registries.calls.load(Ordering::SeqCst), 1);
    assert_eq!(retry_delay.calls.load(Ordering::SeqCst), 0);
    assert_eq!(credentials.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
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
        .payment_request_terms(
            &request(),
            &valid_lock(),
            &bitcoin_receiving("bc1qmeaningfuladdress"),
            &[],
        )
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

#[test]
fn usdt_request_uses_exact_token_units_and_the_approved_address() {
    use paykit_server::domain::receiving::{USDT_ENDPOINT, USDT_TOKEN};
    let mut lock = valid_lock();
    lock.criteria[0].params["asset"] = serde_json::json!("USDT");
    lock.criteria[0].params["amount"] = serde_json::json!("50001");
    let address = "0x2222222222222222222222222222222222222222";
    let terms = PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)
        .payment_request_terms(
            &request(),
            &lock,
            &paykit_server::application::create_invoice::ReceivingAddresses {
                bitcoin: None,
                usdt: Some(
                    paykit_server::domain::receiving::UsdtAddress::try_from(address.to_owned())
                        .unwrap(),
                ),
            },
            &[],
        )
        .unwrap();
    assert_eq!(terms.amount().value(), "0.050001");
    assert_eq!(terms.amount().asset(), "usdt");
    let endpoints = terms.payment_endpoints().unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(
        terms.accepted_payment_endpoint_identifiers()[0].as_str(),
        USDT_ENDPOINT
    );
    let endpoint = endpoints.values().next().unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(endpoint.as_str()).unwrap(),
        serde_json::json!({"value":address,"chain_id":"42161","token":USDT_TOKEN})
    );
}

#[tokio::test]
async fn disabled_usdt_never_creates_an_invoice() {
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let mut lock = valid_lock();
    lock.criteria[0].params["asset"] = serde_json::json!("USDT");
    let locks = Arc::new(FakeLocks {
        result: Ok(lock),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    assert_eq!(
        service(session, locks, store.clone())
            .create(request())
            .await,
        Err(CreateInvoiceError::InvalidRequest)
    );
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

fn bitcoin_receiving(
    address: &str,
) -> paykit_server::application::create_invoice::ReceivingAddresses {
    paykit_server::application::create_invoice::ReceivingAddresses {
        bitcoin: Some(address.to_owned()),
        usdt: None,
    }
}

struct BothReceiving;
#[async_trait]
impl CreatorReceivingProvider for BothReceiving {
    async fn receiving(
        &self,
        creator: &CreatorPubky,
    ) -> Result<paykit_server::application::create_invoice::ReceivingDetails, PersistenceError>
    {
        let mut receiving = FakeCredentials.receiving(creator).await?;
        receiving.usdt = Some(
            paykit_server::domain::receiving::UsdtAddress::try_from(
                "0x2222222222222222222222222222222222222222".to_owned(),
            )
            .unwrap(),
        );
        Ok(receiving)
    }
}
struct Rates(Result<String, CreateInvoiceError>);
#[async_trait]
impl paykit_server::application::invoice_pricing::ExchangeRates for Rates {
    async fn usd_per_btc(&self) -> Result<String, CreateInvoiceError> {
        self.0.clone()
    }
}

#[tokio::test]
async fn invoices_publish_both_approved_methods_with_fixed_rates_and_configured_expiry() {
    for (asset, amount, window) in [
        ("BTC", "50000", 3600),
        ("USD", "500", 7200),
        ("USDT", "5000000", 3600),
    ] {
        let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
        let mut lock = valid_lock();
        lock.criteria[0].params["asset"] = serde_json::json!(asset);
        lock.criteria[0].params["amount"] = serde_json::json!(amount);
        let service = CreateInvoiceService::new(
            Arc::new(FakeSession {
                result: Ok(()),
                calls: AtomicUsize::default(),
                creators: Mutex::new(vec![]),
            }),
            Arc::new(FakeLocks {
                result: Ok(lock),
                calls: AtomicUsize::default(),
            }),
            Arc::new(FakeRegistries {
                registry: Some(capable_registry()),
                calls: AtomicUsize::default(),
            }),
            paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
            Arc::new(BothReceiving),
            BitcoinNetwork::Mainnet,
            store.clone(),
            Arc::new(PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)),
        )
        .with_usdt(true)
        .with_exchange_rates(Arc::new(Rates(Ok("81000".into()))))
        .with_conversion_payment_window(Duration::from_secs(window));
        service.create(request()).await.unwrap();
        let created = store.created.lock().unwrap();
        let (intent, acceptance, payment) = &created[0];
        assert_eq!((*acceptance, *payment), (window / 2, window));
        let terms = intent.terms().unwrap();
        assert_eq!(terms.asset, asset.to_ascii_lowercase());
        assert_eq!(
            terms.accepted_endpoint_identifiers,
            vec!["btc-bitcoin-p2wpkh", "usdt-arbitrum-address"]
        );
        assert_eq!(terms.payment_endpoints.len(), 2);
        assert_eq!(terms.rates.len(), if asset == "USD" { 2 } else { 1 });
        let encoded = postcard::to_allocvec(intent).unwrap();
        let restored = DeliveryIntentV1::decode(&encoded).unwrap();
        assert_eq!(restored.terms().unwrap().rates, terms.rates);
        let mut ready = restored;
        ready
            .set_deadlines(
                "2026-10-07T12:30:00.123456Z".into(),
                "2026-10-07T13:00:00.123456Z".into(),
            )
            .unwrap();
        let event = paykit_lib::PaymentRequestEvent::Request(paykit_lib::PaymentRequest::new(
            paykit_lib::EventId::new_v4(),
            paykit_lib::PaymentRequestId::new_v4(),
            ready.terms().unwrap().to_sdk().unwrap(),
        ));
        let wire = paykit_lib::serialize_payment_request_event(
            &paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
            &event,
        )
        .unwrap();
        assert!(
            wire.len() <= paykit_lib::pubky_noise::snow_crypto::PUBKY_NOISE_MSG_LEN,
            "{asset}: {} bytes",
            wire.len()
        );
    }
}

#[tokio::test]
async fn rate_failure_prevents_new_quotes_but_does_not_block_an_exact_replay() {
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
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
        Arc::new(FakeRegistries {
            registry: Some(capable_registry()),
            calls: AtomicUsize::default(),
        }),
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        Arc::new(BothReceiving),
        BitcoinNetwork::Mainnet,
        store.clone(),
        Arc::new(PaykitIntentBuilder::new(BitcoinNetwork::Mainnet)),
    )
    .with_usdt(true)
    .with_exchange_rates(Arc::new(Rates(Err(CreateInvoiceError::Unavailable))));
    assert_eq!(
        service.create(request()).await,
        Err(CreateInvoiceError::Unavailable)
    );
    assert!(store.created.lock().unwrap().is_empty());
    *store.preflight.lock().unwrap() = InvoicePreflight::ExactReplay;
    assert!(service.create(request()).await.is_ok());
}
