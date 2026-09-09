use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use axum::{
    Extension,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use paykit_server::{
    application::create_invoice::{
        CreateInvoiceError, CreatorXpubProvider, InvoicePersistence, MarkerDiscovery,
        PaykitIntentBuilder, SessionValidationError, SessionValidator, derive_bip84_p2wpkh_address,
    },
    application::create_payment_request::{
        MarketplacePaymentRequest, MarketplacePaymentRequestService,
    },
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    domain::locks::{CreatorPubky, parse_bundle_id, parse_creator, parse_reader},
    http::{auth::SignedLocksAuth, payment_requests::payment_requests_router},
    persistence::{AtomicInvoiceInput, AtomicInvoiceResult, InvoicePreflight, PersistenceError},
    workers::observer::{
        CreationSnapshot, ElectrumPort, ObservationReport, ObserverError, RequestLimiter, TipProbe,
    },
};
use tower::ServiceExt;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const REFERENCE: &str = "000G40R40M30E209185GR38E1W";

struct EmptyBaselineElectrum;

#[async_trait]
impl ElectrumPort for EmptyBaselineElectrum {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        Ok(CreationSnapshot {
            tip_height: 100,
            baseline_outputs: Vec::new(),
            unconfirmed_inputs: Vec::new(),
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        _targets: &[paykit_server::bitcoin::ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        unreachable!()
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 100,
            time_unix: 0,
        })
    }
}

struct FailingBaselineElectrum;

#[async_trait]
impl ElectrumPort for FailingBaselineElectrum {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        Err(ObserverError::Unavailable)
    }

    async fn observations(
        &self,
        _tip_height: u32,
        _targets: &[paykit_server::bitcoin::ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        unreachable!()
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        unreachable!()
    }
}

struct StaleBaselineElectrum;

#[async_trait]
impl ElectrumPort for StaleBaselineElectrum {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        Ok(CreationSnapshot {
            tip_height: 96,
            baseline_outputs: Vec::new(),
            unconfirmed_inputs: Vec::new(),
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        _targets: &[paykit_server::bitcoin::ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        unreachable!()
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 100,
            time_unix: 0,
        })
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

fn request(amount_sats: u64) -> MarketplacePaymentRequest {
    MarketplacePaymentRequest {
        creator: parse_creator(CREATOR).unwrap(),
        reader: parse_reader(&reader()).unwrap(),
        reference: parse_bundle_id(REFERENCE).unwrap(),
        amount_sats,
    }
}

fn capable_marker() -> paykit_lib::PaykitReceiverMarker {
    paykit_lib::PaykitReceiverMarker::new(
        paykit_lib::PaykitReceiverPath::new("bitkit/wallet").unwrap(),
        paykit_lib::PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: false,
        },
        paykit_lib::PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy")
            .unwrap(),
    )
}

struct FakeSession {
    result: Result<(), SessionValidationError>,
    calls: AtomicUsize,
}

#[async_trait]
impl SessionValidator for FakeSession {
    async fn validate(&self, _creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result
    }
}

struct FakeMarkers {
    markers: Vec<paykit_lib::PaykitReceiverMarker>,
    calls: AtomicUsize,
}

#[async_trait]
impl MarkerDiscovery for FakeMarkers {
    async fn discover(
        &self,
        _reader: &paykit_server::domain::locks::ReaderPubky,
    ) -> Result<Vec<paykit_lib::PaykitReceiverMarker>, CreateInvoiceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.markers.clone())
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

struct CapturedInput {
    bundle_binding: Vec<u8>,
    payment_request_binding: Vec<u8>,
    required_sats: u64,
    payment_request_intent: DeliveryIntentV1,
    new_reader_bitcoin_address: String,
}

struct CapturingStore {
    preflight: Mutex<InvoicePreflight>,
    preflight_calls: AtomicUsize,
    replay_calls: AtomicUsize,
    create_calls: AtomicUsize,
    baseline_failures: AtomicUsize,
    captured: Mutex<Vec<CapturedInput>>,
}

impl CapturingStore {
    fn with_preflight(preflight: InvoicePreflight) -> Self {
        Self {
            preflight: Mutex::new(preflight),
            preflight_calls: AtomicUsize::default(),
            replay_calls: AtomicUsize::default(),
            create_calls: AtomicUsize::default(),
            baseline_failures: AtomicUsize::default(),
            captured: Mutex::new(vec![]),
        }
    }
}

#[async_trait]
impl InvoicePersistence for CapturingStore {
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
        self.replay_calls.fetch_add(1, Ordering::SeqCst);
        Ok(AtomicInvoiceResult::new(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            None,
            uuid::Uuid::nil(),
            0,
            true,
        ))
    }

    async fn create_atomic(
        &self,
        input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        let payloads = input.new_reader_payloads.for_child_index(0)?;
        self.captured.lock().unwrap().push(CapturedInput {
            bundle_binding: input.bundle_binding.to_vec(),
            payment_request_binding: input.payment_request_binding.to_vec(),
            required_sats: input.required_sats,
            payment_request_intent: input.payment_request_intent.clone(),
            new_reader_bitcoin_address: payloads.bitcoin_address,
        });
        Ok(AtomicInvoiceResult::new(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            Some(uuid::Uuid::new_v4()),
            uuid::Uuid::new_v4(),
            0,
            false,
        ))
    }

    async fn fail_creation_baseline(
        &self,
        _invoice_id: uuid::Uuid,
    ) -> Result<(), PersistenceError> {
        self.baseline_failures.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn service(
    session: Arc<FakeSession>,
    store: Arc<CapturingStore>,
    network: BitcoinNetwork,
) -> MarketplacePaymentRequestService {
    service_with_creation(session, store, network, true)
}

fn service_with_creation(
    session: Arc<FakeSession>,
    store: Arc<CapturingStore>,
    network: BitcoinNetwork,
    bitcoin_creation_enabled: bool,
) -> MarketplacePaymentRequestService {
    service_with_port(
        session,
        store,
        network,
        bitcoin_creation_enabled,
        Arc::new(EmptyBaselineElectrum),
    )
}

fn service_with_port(
    session: Arc<FakeSession>,
    store: Arc<CapturingStore>,
    network: BitcoinNetwork,
    bitcoin_creation_enabled: bool,
    electrum: Arc<dyn ElectrumPort>,
) -> MarketplacePaymentRequestService {
    MarketplacePaymentRequestService::new(
        session,
        Arc::new(FakeMarkers {
            markers: vec![capable_marker()],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        network.clone(),
        bitcoin_creation_enabled,
        store,
        electrum,
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::for_network(&network)),
    )
}

fn ok_session() -> Arc<FakeSession> {
    Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
    })
}

#[tokio::test]
async fn persists_exact_terms_bindings_and_derived_address_without_a_lock() {
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let result = service(ok_session(), store.clone(), BitcoinNetwork::Mainnet)
        .create(request(50_000))
        .await
        .unwrap();
    assert!(!result.replayed());

    let captured = store.captured.lock().unwrap();
    let input = &captured[0];
    assert_eq!(input.bundle_binding, REFERENCE.as_bytes());
    assert_eq!(input.required_sats, 50_000);
    assert_eq!(
        input.payment_request_binding,
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "amount_sats": 50_000,
            "creator": CREATOR,
            "reader": reader(),
            "reference": REFERENCE,
        }))
        .unwrap()
    );
    assert_eq!(
        input.new_reader_bitcoin_address,
        derive_bip84_p2wpkh_address(&account_xpub(), 0, &BitcoinNetwork::Mainnet, 0).unwrap()
    );
    match input.payment_request_intent.operation() {
        DeliveryOperationV1::PaymentRequestProposal { terms } => {
            assert_eq!(terms.amount, "0.00050000");
            assert_eq!(terms.asset, "btc");
            let reference = uuid::Uuid::parse_str(&terms.payment_reference).unwrap();
            assert_eq!(reference.get_version_num(), 4);
            assert_eq!(terms.proposal_expires_at, None);
            assert_eq!(terms.accepted_endpoint_identifiers, ["btc-bitcoin-p2wpkh"]);
            assert_eq!(
                serde_json::Value::Object(terms.metadata.clone()),
                serde_json::json!({"order_reference": REFERENCE, "reader": reader()})
            );
        }
        DeliveryOperationV1::EndpointPublication { .. } => {
            panic!("payment request intent expected")
        }
    }
}

#[tokio::test]
async fn regtest_deployments_advertise_the_regtest_endpoint_identifier() {
    use bitcoin::{
        Network,
        bip32::{ChildNumber, Xpriv, Xpub},
        secp256k1::Secp256k1,
    };
    struct RegtestCredentials;
    #[async_trait]
    impl CreatorXpubProvider for RegtestCredentials {
        async fn xpub(&self, _creator: &CreatorPubky) -> Result<(String, u32), PersistenceError> {
            let secp = Secp256k1::new();
            let account = Xpriv::new_master(Network::Regtest, &[9; 32])
                .unwrap()
                .derive_priv(
                    &secp,
                    &[
                        ChildNumber::from_hardened_idx(84).unwrap(),
                        ChildNumber::from_hardened_idx(1).unwrap(),
                        ChildNumber::from_hardened_idx(0).unwrap(),
                    ],
                )
                .unwrap();
            Ok((Xpub::from_priv(&secp, &account).to_string(), 0))
        }
    }

    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let service = MarketplacePaymentRequestService::new(
        ok_session(),
        Arc::new(FakeMarkers {
            markers: vec![capable_marker()],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(RegtestCredentials),
        BitcoinNetwork::Regtest,
        true,
        store.clone(),
        Arc::new(EmptyBaselineElectrum),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::for_network(&BitcoinNetwork::Regtest)),
    );
    service.create(request(21_000)).await.unwrap();
    let captured = store.captured.lock().unwrap();
    match captured[0].payment_request_intent.operation() {
        DeliveryOperationV1::PaymentRequestProposal { terms } => {
            assert_eq!(terms.accepted_endpoint_identifiers, ["btc-regtest-p2wpkh"]);
        }
        DeliveryOperationV1::EndpointPublication { .. } => {
            panic!("payment request intent expected")
        }
    }
    assert!(captured[0].new_reader_bitcoin_address.starts_with("bcrt1"));
}

#[tokio::test]
async fn zero_amount_is_rejected_before_any_dependency_access() {
    let session = ok_session();
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    assert_eq!(
        service(session.clone(), store.clone(), BitcoinNetwork::Mainnet)
            .create(request(0))
            .await,
        Err(CreateInvoiceError::InvalidRequest)
    );
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.preflight_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_creation_snapshot_returns_unavailable() {
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let service = service_with_port(
        ok_session(),
        store,
        BitcoinNetwork::Mainnet,
        true,
        Arc::new(FailingBaselineElectrum),
    );
    assert_eq!(
        service.create(request(50_000)).await,
        Err(CreateInvoiceError::Unavailable)
    );
}

#[tokio::test]
async fn snapshot_tip_more_than_three_blocks_stale_refuses_creation() {
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let service = service_with_port(
        ok_session(),
        store,
        BitcoinNetwork::Mainnet,
        true,
        Arc::new(StaleBaselineElectrum),
    );
    assert_eq!(
        service.create(request(50_000)).await,
        Err(CreateInvoiceError::Unavailable)
    );
}

/// A deadline clock that returns `start` for the first `shift_after` calls
/// and `start + shift` afterwards, so one chosen step's remaining budget
/// shrinks to `REQUEST_DEADLINE - shift` while every earlier step sees the
/// full budget.
struct ShiftClock {
    calls: AtomicUsize,
    start: std::time::Instant,
    shift_after: usize,
    shift: std::time::Duration,
}

impl paykit_server::application::create_invoice::DeadlineClock for ShiftClock {
    fn now(&self) -> std::time::Instant {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call < self.shift_after {
            self.start
        } else {
            self.start + self.shift
        }
    }
}

#[tokio::test]
async fn snapshot_slot_acquisition_is_bounded_by_the_request_deadline() {
    // The only snapshot slot is already taken, so acquisition can only
    // complete within the remaining request-deadline budget.
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let _held = slots.clone().acquire_owned().await.unwrap();
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    // The eighth clock read (the slot step) is the first shifted one, so
    // the acquisition has 300ms of budget left.
    let clock = Arc::new(ShiftClock {
        calls: AtomicUsize::new(0),
        start: std::time::Instant::now(),
        shift_after: 7,
        shift: std::time::Duration::from_millis(14_700),
    });
    let service = MarketplacePaymentRequestService::with_clock(
        ok_session(),
        Arc::new(FakeMarkers {
            markers: vec![capable_marker()],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        true,
        store.clone(),
        Arc::new(EmptyBaselineElectrum),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
        clock,
    )
    .with_electrum_controls(RequestLimiter::new(100, 100), slots);

    let created = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        service.create(request(50_000)),
    )
    .await
    .expect("the creation returns within the request-deadline bound");
    assert_eq!(created, Err(CreateInvoiceError::DeadlineExceeded));
    assert_eq!(store.baseline_failures.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exact_replay_returns_without_session_validation() {
    let session = ok_session();
    let store = Arc::new(CapturingStore::with_preflight(
        InvoicePreflight::ExactReplay,
    ));
    let result = service(session.clone(), store.clone(), BitcoinNetwork::Mainnet)
        .create(request(50_000))
        .await
        .unwrap();
    assert!(result.replayed());
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.replay_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unresolved_baseline_is_in_progress_and_never_an_exact_replay() {
    let session = ok_session();
    let store = Arc::new(CapturingStore::with_preflight(
        InvoicePreflight::BaselineInProgress,
    ));
    assert_eq!(
        service(session.clone(), store.clone(), BitcoinNetwork::Mainnet)
            .create(request(50_000))
            .await,
        Err(CreateInvoiceError::BaselineInProgress)
    );
    // The retry must not replay, must not create a second invoice, and
    // must not spend any downstream validation work.
    assert_eq!(store.replay_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn changed_binding_is_a_conflict_without_store_mutation() {
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::Conflict));
    assert_eq!(
        service(ok_session(), store.clone(), BitcoinNetwork::Mainnet)
            .create(request(50_000))
            .await,
        Err(CreateInvoiceError::Conflict)
    );
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
        });
        let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
        assert_eq!(
            service(session, store.clone(), BitcoinNetwork::Mainnet)
                .create(request(50_000))
                .await,
            Err(expected)
        );
        assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn a_reader_without_a_capable_marker_is_unavailable() {
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let service = MarketplacePaymentRequestService::new(
        ok_session(),
        Arc::new(FakeMarkers {
            markers: vec![],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        true,
        store.clone(),
        Arc::new(EmptyBaselineElectrum),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    );
    assert_eq!(
        service.create(request(50_000)).await,
        Err(CreateInvoiceError::Unavailable)
    );
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

fn encode(key: &SigningKey) -> String {
    pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string()
}

fn auth_config(locks_key: &SigningKey, marketplace_key: Option<&SigningKey>) -> Config {
    let marketplace_section = marketplace_key
        .map(|key| format!("[marketplace]\ntrusted_public_key = \"{}\"\n", encode(key)))
        .unwrap_or_default();
    auth_config_with_marketplace_section(locks_key, &marketplace_section)
}

fn auth_config_with_marketplace_list(
    locks_key: &SigningKey,
    marketplace_keys: &[&SigningKey],
) -> Config {
    let keys = marketplace_keys
        .iter()
        .map(|key| format!("\"{}\"", encode(key)))
        .collect::<Vec<_>>()
        .join(", ");
    auth_config_with_marketplace_section(
        locks_key,
        &format!("[marketplace]\ntrusted_public_keys = [{keys}]\n"),
    )
}

fn auth_config_with_marketplace_section(
    locks_key: &SigningKey,
    marketplace_section: &str,
) -> Config {
    let locks_key = encode(locks_key);
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:8080"
[locks]
trusted_public_key = "{locks_key}"
{marketplace_section}
[setup]
allowed_origins = ["https://app.example"]
[paykit]
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
network = "mainnet"
[deployment]
stack_role = "proof"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "1s"
"#
        ),
        ConfigEnvironment {
            database_url: Some("postgres://127.0.0.1:1/paykit".into()),
            master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()),
        },
    )
    .unwrap()
}

fn canonical_body() -> String {
    String::from_utf8(
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "amount_sats": 50_000,
            "creator": CREATOR,
            "reader": reader(),
            "reference": REFERENCE,
        }))
        .unwrap(),
    )
    .unwrap()
}

fn signed_request(signing_key: &SigningKey, body: String) -> Request<Body> {
    let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(body.as_bytes()).to_bytes());
    Request::builder()
        .method(Method::POST)
        .uri("/v0/payment-requests")
        .header("x-paykit-signature", signature)
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn signed_route_accepts_locks_and_marketplace_keys_and_refuses_others() {
    let locks_key = SigningKey::from_bytes(&[3; 32]);
    let marketplace_key = SigningKey::from_bytes(&[4; 32]);
    let stranger_key = SigningKey::from_bytes(&[5; 32]);
    let config = auth_config(&locks_key, Some(&marketplace_key));
    let auth = Arc::new(SignedLocksAuth::from_config(&config));
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let router = payment_requests_router(Arc::new(service(
        ok_session(),
        store.clone(),
        BitcoinNetwork::Mainnet,
    )))
    .layer(Extension(auth));

    for (key, expected) in [
        (&locks_key, StatusCode::NO_CONTENT),
        (&marketplace_key, StatusCode::NO_CONTENT),
        (&stranger_key, StatusCode::UNAUTHORIZED),
    ] {
        let response = router
            .clone()
            .oneshot(signed_request(key, canonical_body()))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }

    let unsigned = Request::builder()
        .method(Method::POST)
        .uri("/v0/payment-requests")
        .body(Body::from(canonical_body()))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(unsigned).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn marketplace_key_list_accepts_every_listed_key_and_refuses_others() {
    let locks_key = SigningKey::from_bytes(&[3; 32]);
    let staging_key = SigningKey::from_bytes(&[4; 32]);
    let production_key = SigningKey::from_bytes(&[6; 32]);
    let stranger_key = SigningKey::from_bytes(&[5; 32]);
    let config = auth_config_with_marketplace_list(&locks_key, &[&staging_key, &production_key]);
    let auth = Arc::new(SignedLocksAuth::from_config(&config));
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let router = payment_requests_router(Arc::new(service(
        ok_session(),
        store.clone(),
        BitcoinNetwork::Mainnet,
    )))
    .layer(Extension(auth));

    // The second listed key verifies exactly like the first.
    for (key, expected) in [
        (&staging_key, StatusCode::NO_CONTENT),
        (&production_key, StatusCode::NO_CONTENT),
        (&locks_key, StatusCode::NO_CONTENT),
        (&stranger_key, StatusCode::UNAUTHORIZED),
    ] {
        let response = router
            .clone()
            .oneshot(signed_request(key, canonical_body()))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn without_a_marketplace_key_only_the_locks_key_is_trusted() {
    let locks_key = SigningKey::from_bytes(&[3; 32]);
    let marketplace_key = SigningKey::from_bytes(&[4; 32]);
    let config = auth_config(&locks_key, None);
    let auth = Arc::new(SignedLocksAuth::from_config(&config));
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let router = payment_requests_router(Arc::new(service(
        ok_session(),
        store,
        BitcoinNetwork::Mainnet,
    )))
    .layer(Extension(auth));

    let response = router
        .clone()
        .oneshot(signed_request(&marketplace_key, canonical_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .oneshot(signed_request(&locks_key, canonical_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn malformed_identifiers_are_invalid_requests() {
    let locks_key = SigningKey::from_bytes(&[3; 32]);
    let config = auth_config(&locks_key, None);
    let auth = Arc::new(SignedLocksAuth::from_config(&config));
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let router = payment_requests_router(Arc::new(service(
        ok_session(),
        store.clone(),
        BitcoinNetwork::Mainnet,
    )))
    .layer(Extension(auth));

    let body = String::from_utf8(
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "amount_sats": 50_000,
            "creator": CREATOR,
            "reader": reader(),
            "reference": "not-a-reference",
        }))
        .unwrap(),
    )
    .unwrap();
    let response = router
        .oneshot(signed_request(&locks_key, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn disabled_creation_refuses_new_binds_but_replays_exact_requests() {
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let service =
        service_with_creation(ok_session(), store.clone(), BitcoinNetwork::Mainnet, false);
    assert_eq!(
        service.create(request(50_000)).await,
        Err(CreateInvoiceError::BitcoinCreationDisabled)
    );
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);

    // An exact replay binds nothing new and is still served.
    let replay_store = Arc::new(CapturingStore::with_preflight(
        InvoicePreflight::ExactReplay,
    ));
    let replayed =
        service_with_creation(ok_session(), replay_store, BitcoinNetwork::Mainnet, false)
            .create(request(50_000))
            .await
            .unwrap();
    assert!(replayed.replayed());
}

#[tokio::test]
async fn disabled_creation_maps_to_the_stable_http_code() {
    let locks_key = SigningKey::from_bytes(&[3; 32]);
    let config = auth_config(&locks_key, None);
    let auth = Arc::new(SignedLocksAuth::from_config(&config));
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let router = payment_requests_router(Arc::new(service_with_creation(
        ok_session(),
        store,
        BitcoinNetwork::Mainnet,
        false,
    )))
    .layer(Extension(auth));

    let response = router
        .oneshot(signed_request(&locks_key, canonical_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"]["code"], "bitcoin_creation_disabled");
}

#[tokio::test]
async fn disabled_creation_keeps_observing_existing_invoices() {
    use paykit_server::{
        bitcoin::{ObservationTarget, PlannedObservation},
        runtime::{DependencyCheck, Runtime},
        workers::observer::{
            ElectrumPort, ObservationBackend, ObservationReport, ObserverError, ObserverPolicy,
            ObserverTickOutcome, ObserverTickState, TipProbe, observe_tick,
        },
    };

    struct ReadyPostgres;
    #[async_trait]
    impl DependencyCheck for ReadyPostgres {
        async fn postgres_ready(&self) -> bool {
            true
        }
    }

    struct HealthyPort;
    #[async_trait]
    impl ElectrumPort for HealthyPort {
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
                height: 1,
                time_unix: 1,
            })
        }
    }

    struct ExistingInvoice;
    #[async_trait]
    impl ObservationBackend for ExistingInvoice {
        async fn observation_plan(&self) -> Result<Vec<PlannedObservation>, ObserverError> {
            Ok(vec![PlannedObservation::new(
                ObservationTarget::new("bc1qexisting-invoice", None),
                std::time::Duration::from_secs(30),
            )])
        }

        async fn apply_observations(
            &self,
            _network: &BitcoinNetwork,
            _targets: &[ObservationTarget],
            _outputs: Vec<paykit_server::bitcoin::ObservedOutput>,
        ) -> Result<usize, ObserverError> {
            Ok(0)
        }

        async fn record_observation_tick(
            &self,
            _observed: &[String],
            _failed: &[String],
        ) -> Result<u64, ObserverError> {
            Ok(0)
        }
    }

    // Creation is disabled on this service, yet the observer tick still
    // processes the pre-existing invoice target unchanged.
    let store = Arc::new(CapturingStore::with_preflight(InvoicePreflight::New));
    let disabled = service_with_creation(ok_session(), store, BitcoinNetwork::Mainnet, false);
    assert_eq!(
        disabled.create(request(50_000)).await,
        Err(CreateInvoiceError::BitcoinCreationDisabled)
    );

    let runtime = Runtime::new(Arc::new(ReadyPostgres), 1);
    runtime.set_bitcoin_creation_enabled(false);
    let outcome = observe_tick(
        &HealthyPort,
        &ExistingInvoice,
        &BitcoinNetwork::Mainnet,
        &runtime,
        &mut ObserverTickState::new(&ObserverPolicy {
            poll_interval: std::time::Duration::from_secs(10),
            max_requests_per_tick: 100,
            max_requests_per_second: 5,
            max_transaction_bytes: 400_000,
            baseline_completion_timeout: std::time::Duration::from_secs(60),
        }),
    )
    .await;
    assert_eq!(
        outcome,
        ObserverTickOutcome::Observed {
            processed: 1,
            deferred: 0,
            failed: 0,
        }
    );
    assert!(!runtime.readiness().await.bitcoin_creation_enabled);
}
