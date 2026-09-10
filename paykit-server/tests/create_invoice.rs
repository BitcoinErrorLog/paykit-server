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
        CreateInvoiceError, CreateInvoiceRequest, CreateInvoiceService, CreatorXpubProvider,
        DeadlineClock, IntentBuilder, InvoicePersistence, LockFetchError, LockFetcher,
        MarkerDiscovery, OFFER_AVAILABILITY_TIMEOUT, OfferAvailability, PaykitIntentBuilder,
        SessionValidationError, SessionValidator, derive_bip84_p2wpkh_address,
    },
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    domain::locks::{CreatorPubky, parse_addressed_lock_resource, parse_bundle_id, parse_reader},
    http::{auth::SignedLocksAuth, invoices::invoices_router},
    persistence::{AtomicInvoiceInput, AtomicInvoiceResult, InvoicePreflight, PersistenceError},
    runtime::{DependencyCheck, ElectrumProbe, Runtime},
    workers::observer::{CreationSnapshot, ElectrumPort, ObserverError, RequestLimiter, TipProbe},
};
use tower::ServiceExt;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const LOCK_RESOURCE: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/locks.app/000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG.json";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";

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
            unconfirmed_outputs: Vec::new(),
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        _targets: &[paykit_server::bitcoin::ObservationTarget],
    ) -> Result<paykit_server::workers::observer::ObservationReport, ObserverError> {
        unreachable!()
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 100,
            time_unix: 0,
        })
    }
}

struct CountingBaselineElectrum(AtomicUsize);

#[async_trait]
impl ElectrumPort for CountingBaselineElectrum {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(CreationSnapshot {
            tip_height: 100,
            baseline_outputs: Vec::new(),
            unconfirmed_inputs: Vec::new(),
            unconfirmed_outputs: Vec::new(),
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        _targets: &[paykit_server::bitcoin::ObservationTarget],
    ) -> Result<paykit_server::workers::observer::ObservationReport, ObserverError> {
        unreachable!()
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        self.0.fetch_add(1, Ordering::SeqCst);
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

fn request() -> CreateInvoiceRequest {
    CreateInvoiceRequest {
        bundle_id: parse_bundle_id(BUNDLE).unwrap(),
        lock_resource: parse_addressed_lock_resource(LOCK_RESOURCE).unwrap(),
        reader: parse_reader(&reader()).unwrap(),
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

#[test]
fn library_payment_request_has_exact_terms_amount_and_metadata() {
    let request = request();
    let terms = PaykitIntentBuilder::default()
        .payment_request_terms(&request, &valid_lock(), 500)
        .unwrap();
    // The terms amount is the nonce'd total: lock price 50000 + nonce 500.
    assert_eq!(terms.amount.value, "0.00050500");
    assert_eq!(terms.amount.asset, "btc");
    assert_eq!(terms.proposal_expires_at, None);
    assert_eq!(terms.recurrence, None);
    assert_eq!(
        terms.accepted_payment_endpoint_identifiers[0].as_str(),
        "btc-bitcoin-p2wpkh"
    );
    assert_eq!(
        serde_json::Value::Object(terms.metadata),
        serde_json::json!({"bundle_id":BUNDLE,"lock_resource":LOCK_RESOURCE,"reader":reader()})
    );
}

#[test]
fn private_payment_list_uses_derived_bech32_p2wpkh_address() {
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
    let details = PaykitIntentBuilder::default()
        .receiving_details(&address)
        .expect("canonical library types accept endpoint");
    assert_eq!(details[0].0.as_str(), "btc-bitcoin-p2wpkh");
    assert_eq!(
        details[0].1.as_str(),
        serde_json::json!({ "value": address }).to_string()
    );
}

struct FakeStore {
    preflight: Mutex<InvoicePreflight>,
    preflight_calls: AtomicUsize,
    create_calls: AtomicUsize,
    baseline_failures: AtomicUsize,
    baseline_completions: AtomicUsize,
    /// What `create_atomic` reports: a fresh allocation (`false`, the
    /// honest answer for a `New` preflight) or a race-losing replay of the
    /// winner's published row (`true`).
    create_replayed: bool,
    create_error: Option<PersistenceError>,
}

impl FakeStore {
    fn with_preflight(preflight: InvoicePreflight) -> Self {
        Self {
            preflight: Mutex::new(preflight),
            preflight_calls: AtomicUsize::default(),
            create_calls: AtomicUsize::default(),
            baseline_failures: AtomicUsize::default(),
            baseline_completions: AtomicUsize::default(),
            create_replayed: false,
            create_error: None,
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
            None,
            uuid::Uuid::nil(),
            0,
            true,
        ))
    }

    async fn create_atomic(
        &self,
        _input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.create_error {
            return Err(error);
        }
        Ok(AtomicInvoiceResult::new(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            None,
            uuid::Uuid::nil(),
            0,
            self.create_replayed,
        ))
    }

    async fn fail_creation_baseline(
        &self,
        _invoice_id: uuid::Uuid,
    ) -> Result<(), PersistenceError> {
        self.baseline_failures.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn complete_creation_baseline(
        &self,
        _invoice_id: uuid::Uuid,
        _snapshot: &CreationSnapshot,
    ) -> Result<(), PersistenceError> {
        self.baseline_completions.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn prepare_view(
        &self,
        invoice_id: uuid::Uuid,
    ) -> Result<Option<paykit_server::persistence::InvoicePhaseView>, PersistenceError> {
        Ok(fake_phase_view(invoice_id))
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
    service_with_creation(session, locks, store, true)
}

fn service_with_creation(
    session: Arc<FakeSession>,
    locks: Arc<FakeLocks>,
    store: Arc<FakeStore>,
    bitcoin_creation_enabled: bool,
) -> CreateInvoiceService {
    CreateInvoiceService::new(
        session,
        locks,
        Arc::new(FakeMarkers {
            markers: vec![capable_marker()],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        bitcoin_creation_enabled,
        store,
        Arc::new(EmptyBaselineElectrum),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    )
}

#[tokio::test]
async fn exhausted_shared_limiter_voids_baseline_before_any_electrum_rpc() {
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
    let electrum = Arc::new(CountingBaselineElectrum(AtomicUsize::new(0)));
    let service = CreateInvoiceService::new(
        session,
        locks,
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
        electrum.clone(),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    )
    .with_electrum_controls(
        RequestLimiter::new(0, 0),
        Arc::new(tokio::sync::Semaphore::new(1)),
    );

    assert_eq!(
        service.create(request()).await,
        Err(CreateInvoiceError::Unavailable)
    );
    assert_eq!(electrum.0.load(Ordering::SeqCst), 0);
    assert_eq!(store.baseline_failures.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn real_creation_path_charges_snapshot_and_probe_to_the_shared_pool() {
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
    let electrum = Arc::new(CountingBaselineElectrum(AtomicUsize::new(0)));
    let limiter = RequestLimiter::new(5, 0);
    let service = CreateInvoiceService::new(
        session,
        locks,
        Arc::new(FakeMarkers {
            markers: vec![capable_marker()],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        true,
        store,
        electrum.clone(),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    )
    .with_electrum_controls(limiter.clone(), Arc::new(tokio::sync::Semaphore::new(1)));

    service.create(request()).await.unwrap();
    assert_eq!(electrum.0.load(Ordering::SeqCst), 2);
    assert_eq!(limiter.available(), 0);
}

/// A fake port whose snapshot parks on a condvar inside a detached
/// blocking read, mirroring the production adapter's contract: the owned
/// snapshot slot is held by the blocking read itself and released only
/// when that read returns — never when the awaiting side is dropped.
struct GatedSnapshotElectrum {
    rpc_calls: AtomicUsize,
    gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

impl GatedSnapshotElectrum {
    fn new() -> (Self, Arc<(Mutex<bool>, std::sync::Condvar)>) {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        (
            Self {
                rpc_calls: AtomicUsize::new(0),
                gate: gate.clone(),
            },
            gate,
        )
    }

    fn release(gate: &(Mutex<bool>, std::sync::Condvar)) {
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
    }
}

#[async_trait]
impl ElectrumPort for GatedSnapshotElectrum {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        self.rpc_calls.fetch_add(1, Ordering::SeqCst);
        let gate = self.gate.clone();
        tokio::task::spawn_blocking(move || {
            let _snapshot_slot = snapshot_slot;
            let (released, condvar) = &*gate;
            let mut released = released.lock().unwrap();
            while !*released {
                released = condvar.wait(released).unwrap();
            }
            Ok(CreationSnapshot {
                tip_height: 100,
                baseline_outputs: Vec::new(),
                unconfirmed_inputs: Vec::new(),
                unconfirmed_outputs: Vec::new(),
            })
        })
        .await
        .map_err(|_| ObserverError::Unavailable)?
    }

    async fn observations(
        &self,
        _tip_height: u32,
        _targets: &[paykit_server::bitcoin::ObservationTarget],
    ) -> Result<paykit_server::workers::observer::ObservationReport, ObserverError> {
        unreachable!()
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 100,
            time_unix: 0,
        })
    }
}

/// A deadline clock that returns `start` for the first `shift_after` calls
/// and `start + shift` afterwards, so one chosen step's remaining budget
/// shrinks to `REQUEST_DEADLINE - shift` while every earlier step sees the
/// full budget.
struct ShiftClock {
    calls: AtomicUsize,
    start: Instant,
    shift_after: usize,
    shift: Duration,
}

impl DeadlineClock for ShiftClock {
    fn now(&self) -> Instant {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call < self.shift_after {
            self.start
        } else {
            self.start + self.shift
        }
    }
}

fn service_with_port(
    store: Arc<FakeStore>,
    electrum: Arc<dyn ElectrumPort>,
    slots: Arc<tokio::sync::Semaphore>,
) -> CreateInvoiceService {
    CreateInvoiceService::new(
        Arc::new(FakeSession {
            result: Ok(()),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        }),
        Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        }),
        Arc::new(FakeMarkers {
            markers: vec![capable_marker()],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        true,
        store,
        electrum,
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    )
    .with_electrum_controls(RequestLimiter::new(100, 100), slots)
}

#[tokio::test]
async fn abandoned_snapshot_keeps_its_slot_until_the_blocking_read_returns() {
    let (electrum, gate) = GatedSnapshotElectrum::new();
    let electrum = Arc::new(electrum);
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let first_store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let first_service = service_with_port(first_store, electrum.clone(), slots.clone());
    let first = tokio::spawn(async move { first_service.create(request()).await });
    for _ in 0..200 {
        if electrum.rpc_calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(electrum.rpc_calls.load(Ordering::SeqCst), 1);

    // The first caller gives up (its request deadline passed); the HTTP
    // handler future is dropped while the blocking read is still parked.
    first.abort();
    let _ = first.await;
    assert_eq!(
        slots.available_permits(),
        0,
        "the orphaned blocking read must retain the only snapshot slot"
    );

    // A second creation must make ZERO snapshot RPCs until the first
    // blocking read returns.
    let second_store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let second_service = service_with_port(second_store.clone(), electrum.clone(), slots.clone());
    let second = tokio::spawn(async move { second_service.create(request()).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        electrum.rpc_calls.load(Ordering::SeqCst),
        1,
        "no second snapshot RPC may start while the first read holds the slot"
    );

    GatedSnapshotElectrum::release(&gate);
    let created = tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .expect("the second creation proceeds once the first read returns")
        .expect("the second creation task is not cancelled");
    assert!(created.is_ok());
    assert_eq!(electrum.rpc_calls.load(Ordering::SeqCst), 2);
    assert_eq!(second_store.baseline_completions.load(Ordering::SeqCst), 1);
    assert_eq!(slots.available_permits(), 1);
}

#[tokio::test]
async fn snapshot_slot_acquisition_is_bounded_by_the_request_deadline() {
    let (electrum, gate) = GatedSnapshotElectrum::new();
    let electrum = Arc::new(electrum);
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let first_store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let first_service = service_with_port(first_store, electrum.clone(), slots.clone());
    let first = tokio::spawn(async move { first_service.create(request()).await });
    for _ in 0..200 {
        if electrum.rpc_calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(electrum.rpc_calls.load(Ordering::SeqCst), 1);

    // The second creation reaches the snapshot-slot acquisition with only
    // 300ms of request-deadline budget left (the ninth clock read — the
    // slot step — is the first shifted one).
    let start = Instant::now();
    let clock = Arc::new(ShiftClock {
        calls: AtomicUsize::new(0),
        start,
        shift_after: 8,
        shift: Duration::from_millis(14_700),
    });
    let second_store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let second_service = CreateInvoiceService::with_clock(
        Arc::new(FakeSession {
            result: Ok(()),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        }),
        Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        }),
        Arc::new(FakeMarkers {
            markers: vec![capable_marker()],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        true,
        second_store.clone(),
        electrum.clone(),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
        clock,
    )
    .with_electrum_controls(RequestLimiter::new(100, 100), slots.clone());

    let created = tokio::time::timeout(Duration::from_secs(3), second_service.create(request()))
        .await
        .expect("the creation returns within the request-deadline bound");
    assert_eq!(created, Err(CreateInvoiceError::DeadlineExceeded));
    // The baseline was failed to completion: no `observing` invoice and no
    // `queued` outbox row can exist for this creation.
    assert_eq!(second_store.baseline_failures.load(Ordering::SeqCst), 1);
    assert_eq!(second_store.baseline_completions.load(Ordering::SeqCst), 0);
    assert_eq!(
        slots.available_permits(),
        0,
        "the parked first read still owns the only slot"
    );

    GatedSnapshotElectrum::release(&gate);
    let first_created = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .expect("the first creation completes once its read is released")
        .expect("the first creation task is not cancelled");
    assert!(first_created.is_ok());
    assert_eq!(slots.available_permits(), 1);
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
async fn exact_replay_returns_without_validator_or_lock_fetch() {
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
    assert_eq!(result.state, "prepared");
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unresolved_baseline_is_in_progress_and_never_an_exact_replay() {
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(valid_lock()),
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(
        InvoicePreflight::BaselineInProgress,
    ));

    assert_eq!(
        service(session.clone(), locks.clone(), store.clone())
            .create(request())
            .await,
        Err(CreateInvoiceError::BaselineInProgress)
    );
    // The retry must not replay, must not create a second invoice, and
    // must not spend any downstream validation work.
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
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
async fn disabled_creation_refuses_new_locks_invoice_binds_but_replays_exact_requests() {
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

    assert_eq!(
        service_with_creation(session.clone(), locks.clone(), store.clone(), false)
            .create(request())
            .await,
        Err(CreateInvoiceError::BitcoinCreationDisabled)
    );
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);

    // An exact replay binds nothing new and is still served.
    let replay_store = Arc::new(FakeStore::with_preflight(InvoicePreflight::ExactReplay));
    let replayed = service_with_creation(session, locks, replay_store, false)
        .create(request())
        .await
        .unwrap();
    assert_eq!(replayed.state, "prepared");
}

#[tokio::test]
async fn disabled_creation_maps_to_the_stable_http_code_on_the_locks_route() {
    let key = SigningKey::from_bytes(&[14; 32]);
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
    let router = invoices_router(Arc::new(service_with_creation(
        session, locks, store, false,
    )))
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
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"error":{"code":"bitcoin_creation_disabled","message":"bitcoin payment request creation is disabled"}})
    );
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
async fn marker_discovery_cannot_start_after_the_whole_request_deadline() {
    let session = Arc::new(FakeSession {
        result: Ok(()),
        calls: AtomicUsize::default(),
        creators: Mutex::new(vec![]),
    });
    let locks = Arc::new(FakeLocks {
        result: Ok(valid_lock()),
        calls: AtomicUsize::default(),
    });
    let markers = Arc::new(FakeMarkers {
        markers: vec![capable_marker()],
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let start = Instant::now();
    let service = CreateInvoiceService::with_clock(
        session,
        locks,
        markers.clone(),
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
    assert_eq!(markers.calls.load(Ordering::SeqCst), 0);
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
        Arc::new(FakeMarkers {
            markers: vec![capable_marker()],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        true,
        store,
        Arc::new(EmptyBaselineElectrum),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
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
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
network = "mainnet"
[deployment]
stack_role = "proof"
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
    Request::builder()
        .method(Method::POST)
        .uri("/invoices")
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(&body).to_bytes()),
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

struct CapturingIntentStore {
    captured: Mutex<Vec<DeliveryIntentV1>>,
}

fn fake_phase_view(invoice_id: uuid::Uuid) -> Option<paykit_server::persistence::InvoicePhaseView> {
    Some(paykit_server::persistence::InvoicePhaseView {
        invoice_id,
        baseline_state: "prepared".into(),
        nonce_sats: 437,
        total_sats: 50_437,
        expires_at: None,
        prepare_expires_at: Some(time::OffsetDateTime::now_utc()),
        activated_at: None,
        updated_at: time::OffsetDateTime::now_utc(),
        allocation_mode: "shared_manual".into(),
        derived_address_fingerprint: "3f7a1c9e5b204d86".into(),
        bitcoin_address: "test-address".into(),
    })
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
        let endpoint = input.new_reader_payloads.for_child_index(0)?;
        self.captured
            .lock()
            .unwrap()
            .extend([endpoint.endpoint_intent, input.payment_request_intent]);
        Ok(AtomicInvoiceResult::new(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            Some(uuid::Uuid::nil()),
            uuid::Uuid::nil(),
            0,
            false,
        ))
    }

    async fn prepare_view(
        &self,
        invoice_id: uuid::Uuid,
    ) -> Result<Option<paykit_server::persistence::InvoicePhaseView>, PersistenceError> {
        Ok(fake_phase_view(invoice_id))
    }
}

#[tokio::test]
async fn new_invoice_discovers_marker_before_atomic_persistence_and_pins_it_in_both_intents() {
    use paykit_lib::{
        PaykitReceiverCapabilities, PaykitReceiverMarker, PaykitReceiverPath, PublicKey,
    };
    let marker = PaykitReceiverMarker::new(
        PaykitReceiverPath::new("bitkit/wallet").unwrap(),
        PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: false,
        },
        PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap(),
    );
    let markers = Arc::new(FakeMarkers {
        markers: vec![marker.clone()],
        calls: AtomicUsize::default(),
    });
    let store = Arc::new(CapturingIntentStore {
        captured: Mutex::new(vec![]),
    });
    let service = CreateInvoiceService::with_delivery_intents(
        Arc::new(FakeSession {
            result: Ok(()),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        }),
        Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        }),
        markers.clone(),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        true,
        store.clone(),
        Arc::new(EmptyBaselineElectrum),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    );

    service.create(request()).await.unwrap();

    assert_eq!(markers.calls.load(Ordering::SeqCst), 1);
    let captured = store.captured.lock().unwrap();
    assert_eq!(captured.len(), 2);
    for intent in captured.iter() {
        assert_eq!(
            intent.selected_reader_path().unwrap().as_str(),
            "bitkit/wallet"
        );
        assert_eq!(
            intent.marker_fingerprint(),
            DeliveryIntentV1::fingerprint(&marker).unwrap()
        );
    }
    assert!(
        matches!(captured[0].operation(), DeliveryOperationV1::EndpointPublication { receiving_details } if !receiving_details.is_empty())
    );
    assert!(
        matches!(captured[1].operation(), DeliveryOperationV1::PaymentRequestProposal { terms } if uuid::Uuid::parse_str(&terms.payment_reference).is_ok())
    );
}

struct FixedAvailability(bool);

#[async_trait]
impl OfferAvailability for FixedAvailability {
    async fn bitcoin_offer_available(&self) -> bool {
        self.0
    }
}

struct ReadyPostgres;

#[async_trait]
impl DependencyCheck for ReadyPostgres {
    async fn postgres_ready(&self) -> bool {
        true
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

#[tokio::test]
async fn hidden_offer_refuses_first_time_binds_without_consuming_anything() {
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
    let electrum = Arc::new(CountingBaselineElectrum(AtomicUsize::new(0)));
    // Calibration: the static creation flag is ON, so the refusing
    // predicate here is the runtime gate and nothing else.
    let service = CreateInvoiceService::new(
        session.clone(),
        locks.clone(),
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
        electrum.clone(),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    )
    .with_offer_availability(Arc::new(FixedAvailability(false)));

    assert_eq!(
        service.create(request()).await,
        Err(CreateInvoiceError::BitcoinOfferUnavailable)
    );
    // The read-only preflight ran (no cursor advance); nothing else did:
    // no session validation, no lock fetch, no store mutation, and no
    // Electrum request (no listunspent, no snapshot, no probe).
    assert_eq!(store.preflight_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.baseline_completions.load(Ordering::SeqCst), 0);
    assert_eq!(store.baseline_failures.load(Ordering::SeqCst), 0);
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
    assert_eq!(electrum.0.load(Ordering::SeqCst), 0);
}

/// A readiness read that never resolves. The gate must not wait on it
/// forever: OFFER_AVAILABILITY_TIMEOUT bounds the read and the branch
/// fails CLOSED (unavailable), never open.
struct HangingAvailability;

#[async_trait]
impl OfferAvailability for HangingAvailability {
    async fn bitcoin_offer_available(&self) -> bool {
        std::future::pending().await
    }
}

#[tokio::test]
async fn hanging_availability_read_times_out_fail_closed_without_consuming_anything() {
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
    let electrum = Arc::new(CountingBaselineElectrum(AtomicUsize::new(0)));
    let service = CreateInvoiceService::new(
        session.clone(),
        locks.clone(),
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
        electrum.clone(),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    )
    .with_offer_availability(Arc::new(HangingAvailability));

    let started = Instant::now();
    assert_eq!(
        service.create(request()).await,
        Err(CreateInvoiceError::BitcoinOfferUnavailable)
    );
    let elapsed = started.elapsed();
    // The refusal comes from the timeout expiring, not from the read
    // resolving: at least the full timeout elapses, and the bounded read
    // returns promptly after it (well under a further second).
    assert!(
        elapsed >= OFFER_AVAILABILITY_TIMEOUT,
        "gate answered before the timeout expired ({elapsed:?})"
    );
    assert!(
        elapsed < OFFER_AVAILABILITY_TIMEOUT + Duration::from_secs(1),
        "gate held the request past the timeout ({elapsed:?})"
    );
    // Fail-closed consumed nothing: the read-only preflight ran, but no
    // store write, no session validation, no lock fetch, no Electrum call.
    assert_eq!(store.preflight_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.create_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.baseline_completions.load(Ordering::SeqCst), 0);
    assert_eq!(store.baseline_failures.load(Ordering::SeqCst), 0);
    assert_eq!(session.calls.load(Ordering::SeqCst), 0);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
    assert_eq!(electrum.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn three_failed_probes_refuse_then_three_successes_permit_a_first_time_bind() {
    let runtime = Arc::new(Runtime::new(Arc::new(ReadyPostgres), 1));
    runtime.set_electrum_available(true);
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let electrum = Arc::new(CountingBaselineElectrum(AtomicUsize::new(0)));
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
        Arc::new(FakeMarkers {
            markers: vec![capable_marker()],
            calls: AtomicUsize::default(),
        }),
        vec![paykit_server::config::ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        paykit_lib::PaykitReceiverPath::new("paykit/server").unwrap(),
        Arc::new(FakeCredentials),
        BitcoinNetwork::Mainnet,
        true,
        store,
        electrum.clone(),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    )
    .with_electrum_controls(
        RequestLimiter::new(100, 100),
        Arc::new(tokio::sync::Semaphore::new(1)),
    )
    .with_offer_availability(runtime.clone());

    for _ in 0..3 {
        runtime.record_electrum_probe_failure();
    }
    assert!(!runtime.readiness().await.bitcoin_offer_available);
    assert_eq!(
        service.create(request()).await,
        Err(CreateInvoiceError::BitcoinOfferUnavailable)
    );
    assert_eq!(electrum.0.load(Ordering::SeqCst), 0);

    for height in 1..=3 {
        runtime.record_electrum_probe(ElectrumProbe::success(height, fresh_tip_time()));
    }
    assert!(runtime.readiness().await.bitcoin_offer_available);
    let created = service.create(request()).await.unwrap();
    assert_eq!(created.state, "prepared");
    assert_eq!(electrum.0.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn exact_replay_is_served_while_the_offer_is_hidden() {
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::ExactReplay));
    let replayed = service(
        Arc::new(FakeSession {
            result: Ok(()),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        }),
        Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        }),
        store,
    )
    .with_offer_availability(Arc::new(FixedAvailability(false)))
    .create(request())
    .await
    .unwrap();
    // An exact replay binds nothing new: the gate must not see it.
    assert_eq!(replayed.state, "prepared");
}

#[tokio::test]
async fn hidden_offer_maps_to_503_bitcoin_offer_unavailable_on_the_locks_route() {
    let key = SigningKey::from_bytes(&[15; 32]);
    let store = Arc::new(FakeStore::with_preflight(InvoicePreflight::New));
    let router = invoices_router(Arc::new(
        service(
            Arc::new(FakeSession {
                result: Ok(()),
                calls: AtomicUsize::default(),
                creators: Mutex::new(vec![]),
            }),
            Arc::new(FakeLocks {
                result: Ok(valid_lock()),
                calls: AtomicUsize::default(),
            }),
            store,
        )
        .with_offer_availability(Arc::new(FixedAvailability(false))),
    ))
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
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"error":{"code":"bitcoin_offer_unavailable","message":"bitcoin offer is temporarily unavailable; retry later"}})
    );
}

#[tokio::test]
async fn replayed_create_atomic_returns_the_published_invoice_without_a_second_baseline() {
    // The race the FOR UPDATE loser wins late: both preflights read `New`,
    // the winner committed AND published before the loser's create_atomic
    // took the row lock. The replayed row must be served as-is — running
    // the baseline sequence again would double-charge the shared limiter
    // for one invoice and end in a Conflict.
    let mut store = FakeStore::with_preflight(InvoicePreflight::New);
    store.create_replayed = true;
    let store = Arc::new(store);
    let electrum = Arc::new(CountingBaselineElectrum(AtomicUsize::new(0)));
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
        electrum.clone(),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    );

    let replayed = service.create(request()).await.unwrap();
    assert_eq!(replayed.state, "prepared");
    assert_eq!(store.baseline_completions.load(Ordering::SeqCst), 0);
    assert_eq!(store.baseline_failures.load(Ordering::SeqCst), 0);
    assert_eq!(electrum.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn raced_awaiting_baseline_row_is_in_progress_and_never_snapshotted_twice() {
    // The FOR UPDATE loser receives the winner's still-unresolved
    // `awaiting_baseline` row: the store answers BaselineInProgress under
    // the row lock (exactly like preflight), and the service must surface
    // it without touching Electrum or the baseline lifecycle.
    let mut store = FakeStore::with_preflight(InvoicePreflight::New);
    store.create_error = Some(PersistenceError::BaselineInProgress);
    let store = Arc::new(store);
    let electrum = Arc::new(CountingBaselineElectrum(AtomicUsize::new(0)));
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
        electrum.clone(),
        50,
        400_000,
        Arc::new(PaykitIntentBuilder::default()),
    );

    assert_eq!(
        service.create(request()).await,
        Err(CreateInvoiceError::BaselineInProgress)
    );
    assert_eq!(store.baseline_completions.load(Ordering::SeqCst), 0);
    assert_eq!(store.baseline_failures.load(Ordering::SeqCst), 0);
    assert_eq!(electrum.0.load(Ordering::SeqCst), 0);
}

#[test]
fn delivery_intent_is_closed_and_contains_complete_sdk_inputs_not_final_wire_ids() {
    use paykit_lib::{
        PaykitReceiverCapabilities, PaykitReceiverMarker, PaykitReceiverPath, PublicKey,
    };

    let marker = PaykitReceiverMarker::new(
        PaykitReceiverPath::new("bitkit/wallet").unwrap(),
        PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: false,
        },
        PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap(),
    );
    let intent = DeliveryIntentV1::endpoint(
        reader(),
        &marker,
        PaykitReceiverPath::new("paykit/server").unwrap(),
        vec![(
            paykit_lib::PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
            paykit_lib::PaymentEndpointPayload::new("bc1qmeaningfuladdress"),
        )],
    )
    .unwrap();

    assert_eq!(
        intent.selected_reader_path().unwrap().as_str(),
        "bitkit/wallet"
    );
    assert_eq!(
        intent.marker_fingerprint(),
        DeliveryIntentV1::fingerprint(&marker).unwrap()
    );
    assert!(matches!(
        intent.operation(),
        DeliveryOperationV1::EndpointPublication { receiving_details }
            if receiving_details.len() == 1
    ));
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

struct CapturedAmounts {
    nonce_sats: u64,
    required_sats: u64,
    terms_amount: String,
}

struct CapturingAmountsStore {
    captured: Mutex<Vec<CapturedAmounts>>,
}

#[async_trait]
impl InvoicePersistence for CapturingAmountsStore {
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
        let terms_amount = match input.payment_request_intent.operation() {
            DeliveryOperationV1::PaymentRequestProposal { terms } => terms.amount.clone(),
            DeliveryOperationV1::EndpointPublication { .. } => {
                panic!("payment request intent expected")
            }
        };
        self.captured.lock().unwrap().push(CapturedAmounts {
            nonce_sats: input.nonce_sats,
            required_sats: input.required_sats,
            terms_amount,
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

    async fn prepare_view(
        &self,
        invoice_id: uuid::Uuid,
    ) -> Result<Option<paykit_server::persistence::InvoicePhaseView>, PersistenceError> {
        Ok(fake_phase_view(invoice_id))
    }
}

#[tokio::test]
async fn every_invoice_draws_a_csprng_nonce_and_binds_at_price_plus_nonce() {
    let store = Arc::new(CapturingAmountsStore {
        captured: Mutex::new(vec![]),
    });
    let service = CreateInvoiceService::with_delivery_intents(
        Arc::new(FakeSession {
            result: Ok(()),
            calls: AtomicUsize::default(),
            creators: Mutex::new(vec![]),
        }),
        Arc::new(FakeLocks {
            result: Ok(valid_lock()),
            calls: AtomicUsize::default(),
        }),
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
    );

    // Two hundred invoices for one seller: every nonce is in [1, 999], the
    // amount the marketplace would record (required_sats) is price + nonce,
    // and the buyer-facing terms amount is the same total (§B.8.2).
    for _ in 0..200 {
        service.create(request()).await.unwrap();
    }
    let captured = store.captured.lock().unwrap();
    assert_eq!(captured.len(), 200);
    for draw in captured.iter() {
        assert!(
            (1..=999).contains(&draw.nonce_sats),
            "nonce {} outside [1, 999]",
            draw.nonce_sats
        );
        assert_eq!(draw.required_sats, 50_000 + draw.nonce_sats);
        assert_eq!(
            draw.terms_amount,
            format!(
                "{}.{:08}",
                draw.required_sats / 100_000_000,
                draw.required_sats % 100_000_000
            )
        );
    }
    let nonces = captured
        .iter()
        .map(|draw| draw.nonce_sats)
        .collect::<Vec<_>>();
    assert!(
        nonces.iter().any(|nonce| *nonce != nonces[0]),
        "200 independent CSPRNG draws are all equal"
    );
    let nondecreasing = nonces.windows(2).all(|pair| pair[0] <= pair[1]);
    let nonincreasing = nonces.windows(2).all(|pair| pair[0] >= pair[1]);
    assert!(
        !(nondecreasing || nonincreasing),
        "200 independent CSPRNG draws are monotonic"
    );
}
