//! Invoice application service: replay-first validation and atomic intent persistence.

use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bitcoin::{
    Address, NetworkKind,
    bip32::{ChildNumber, Xpub},
    secp256k1::Secp256k1,
};
use locks_core::{
    ids::CreatorPubky as RawCreatorPubky,
    lock_policy::{ContentLock, VerifierType},
};
use paykit_lib::{
    PaykitReceiverMarker, PaykitReceiverPath, PaymentAmount, PaymentEndpointIdentifier,
    PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
};
use rand::Rng;
use serde_json::{Map, Value};

use crate::{
    application::{reader_marker::select_reader_marker, semantic_intent::DeliveryIntentV1},
    config::ReceiverPathPriority,
    domain::{
        invoice::{CriterionAmount, CriterionAsset},
        locks::{BundleId, CreatorPubky, PubkyLockResource, ReaderPubky},
    },
    persistence::{
        AtomicInvoiceInput, AtomicInvoiceResult, CreatorStore, InvoicePreflight, InvoiceStore,
        NewReaderPayloadFactory, NewReaderPayloads, PersistenceError,
    },
    workers::observer::{CreationSnapshot, ElectrumPort, PROBE_REQUESTS_PER_TICK, RequestLimiter},
};

const REQUEST_DEADLINE: Duration = Duration::from_secs(15);

/// Stack identity reported on phase-1 bodies when none was installed —
/// test compositions only. Production always installs the minted
/// `stack_identity` via [`CreateInvoiceService::with_stack_identity`]; a
/// body carrying this value can never pass an activation's identity check
/// on any real stack.
pub const UNSPECIFIED_STACK_ID: &str = "unspecified:00000000-0000-0000-0000-000000000000";

/// §B.11.1's `prepare_ttl` when none is installed — test compositions
/// only; production wires `bitcoin.prepare_ttl` from configuration.
pub const DEFAULT_PREPARE_TTL: Duration = Duration::from_secs(15 * 60);

/// §B.9's `max_request_expiry` when none is installed — test compositions
/// only; production wires `bitcoin.max_request_expiry` from configuration.
pub const DEFAULT_MAX_REQUEST_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

/// Draws one invoice's amount nonce from the operating system's CSPRNG
/// (design §B.8.2): `nonce_sats ∈ [1, 999]`, never derived from the order
/// id, the price, a counter, or time, because a predictable nonce is not a
/// nonce. The invoice then binds at exactly `price + nonce_sats`, and the
/// nonce is absorbed in the price — never refunded on chain.
pub fn draw_nonce_sats() -> u64 {
    rand::rng().random_range(
        crate::domain::invoice::NONCE_SATS_MIN..=crate::domain::invoice::NONCE_SATS_MAX,
    )
}

#[derive(Clone, Debug)]
pub struct CreateInvoiceRequest {
    pub bundle_id: BundleId,
    pub lock_resource: PubkyLockResource,
    pub reader: ReaderPubky,
    /// The Payment Request expiry (design §B.9): required on this
    /// entrypoint exactly as on `/v0/payment-requests`, refused when past
    /// or further out than `max_request_expiry`, persisted on the invoice,
    /// and carried into the published request's `proposal_expires_at` so
    /// the buyer's wallet enforces it.
    pub expires_at: time::OffsetDateTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionValidationError {
    Invalid,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockFetchError {
    NotFound,
    Unavailable,
    Invalid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateInvoiceError {
    InvalidRequest,
    CreatorSessionInvalid,
    CreatorSessionUnavailable,
    LockNotFound,
    LockUnavailable,
    Conflict,
    /// The idempotent payload matches an invoice whose creation baseline
    /// is still unresolved: its outcome (published or voided) is not yet
    /// knowable, so the retry gets a machine-readable in-progress answer
    /// instead of replay success for an invoice that never published.
    BaselineInProgress,
    DeadlineExceeded,
    Unavailable,
    /// New Bitcoin binds are administratively disabled on this stack.
    BitcoinCreationDisabled,
    /// The runtime's Bitcoin offer is currently hidden (Electrum probe
    /// hysteresis, component readiness, or postgres folded into
    /// `bitcoin_offer_available`): a first-time bind is refused before any
    /// address is allocated, any cursor advances, or any Electrum request
    /// is charged. Exact replays are never gated.
    BitcoinOfferUnavailable,
    /// A phase-1 replay matched an invoice in a final void state
    /// (`void_baseline_failed`, `void_cancelled`, or `expired_final`):
    /// §B.11.6 answers with the named `invoice_finalized` refusal, never
    /// replay success.
    InvoiceFinalized,
    /// A phase-1 replay matched an invoice reaped at `prepare_expires_at`:
    /// §B.11.6 answers with the named `prepare_expired` refusal.
    PrepareExpired,
    /// §B.9: `expires_at` failed the fail-closed creation check — past the
    /// server clock or beyond `max_request_expiry`. Reported as
    /// `invalid_request` with the named reason at the HTTP boundary.
    InvalidExpiry(ExpiryRefusal),
}

/// Why an `expires_at` was refused at creation (§B.9). "Missing" never
/// reaches the service: the route schema rejects it as `invalid_request`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryRefusal {
    /// Already in the past on the server clock.
    Past,
    /// Further out than the configured `max_request_expiry`.
    OverMaximum,
}

impl ExpiryRefusal {
    /// Stable machine-readable reason carried on the 400 body.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Past => "expires_at_past",
            Self::OverMaximum => "expires_at_over_maximum",
        }
    }
}

/// Live read of the runtime's `bitcoin_offer_available` verdict. This is
/// the creation gate's only coupling to runtime readiness: observation of
/// existing invoices never consults it. Production wires [`crate::runtime::Runtime`];
/// tests inject a fixed verdict.
#[async_trait]
pub trait OfferAvailability: Send + Sync {
    async fn bitcoin_offer_available(&self) -> bool;
}

/// Default for constructors that predate the runtime gate: offer visible.
pub struct AlwaysAvailableOffer;
#[async_trait]
impl OfferAvailability for AlwaysAvailableOffer {
    async fn bitcoin_offer_available(&self) -> bool {
        true
    }
}

/// Bound on the runtime availability read itself. The read is a readiness
/// evaluation (atomic state plus one `SELECT 1`), so two seconds is
/// generous; on expiry the gate fails closed rather than hold the request.
pub const OFFER_AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(2);

#[async_trait]
pub trait SessionValidator: Send + Sync {
    async fn validate(&self, creator: &CreatorPubky) -> Result<(), SessionValidationError>;
}
#[async_trait]
pub trait LockFetcher: Send + Sync {
    async fn fetch(&self, resource: &PubkyLockResource) -> Result<ContentLock, LockFetchError>;
}
#[async_trait]
pub trait MarkerDiscovery: Send + Sync {
    async fn discover(
        &self,
        reader: &ReaderPubky,
    ) -> Result<Vec<paykit_lib::PaykitReceiverMarker>, CreateInvoiceError>;
}
#[async_trait]
pub trait CreatorXpubProvider: Send + Sync {
    async fn xpub(&self, creator: &CreatorPubky) -> Result<(String, u32), PersistenceError>;
}
#[async_trait]
impl CreatorXpubProvider for CreatorStore {
    async fn xpub(&self, creator: &CreatorPubky) -> Result<(String, u32), PersistenceError> {
        let credentials = self.load(creator).await?;
        Ok((credentials.xpub().to_owned(), credentials.account_index()))
    }
}
#[async_trait]
pub trait InvoicePersistence: Send + Sync {
    async fn preflight(
        &self,
        creator: &CreatorPubky,
        bundle_binding: &[u8],
        payment_binding: &[u8],
    ) -> Result<InvoicePreflight, PersistenceError>;
    async fn exact_replay(
        &self,
        creator: &CreatorPubky,
        reader: &ReaderPubky,
        bundle_binding: &[u8],
        payment_binding: &[u8],
    ) -> Result<AtomicInvoiceResult, PersistenceError>;
    async fn create_atomic(
        &self,
        input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError>;
    async fn complete_creation_baseline(
        &self,
        _invoice_id: uuid::Uuid,
        _snapshot: &CreationSnapshot,
    ) -> Result<(), PersistenceError> {
        Ok(())
    }
    async fn fail_creation_baseline(
        &self,
        _invoice_id: uuid::Uuid,
    ) -> Result<(), PersistenceError> {
        Ok(())
    }
    /// Loads the §B.11.3 body facts for one invoice. The phase-1 response
    /// is built from this view — after baseline completion for a fresh
    /// prepare, and directly for a replay — so a response never reports
    /// anything the database does not.
    async fn prepare_view(
        &self,
        _invoice_id: uuid::Uuid,
    ) -> Result<Option<crate::persistence::InvoicePhaseView>, PersistenceError> {
        Ok(None)
    }
}
#[async_trait]
impl InvoicePersistence for InvoiceStore {
    async fn preflight(
        &self,
        creator: &CreatorPubky,
        bundle_binding: &[u8],
        payment_binding: &[u8],
    ) -> Result<InvoicePreflight, PersistenceError> {
        InvoiceStore::preflight(self, creator, bundle_binding, payment_binding).await
    }
    async fn exact_replay(
        &self,
        creator: &CreatorPubky,
        reader: &ReaderPubky,
        bundle_binding: &[u8],
        payment_binding: &[u8],
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        InvoiceStore::exact_replay(self, creator, reader, bundle_binding, payment_binding).await
    }
    async fn create_atomic(
        &self,
        input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        InvoiceStore::create_awaiting_baseline(self, input).await
    }
    async fn complete_creation_baseline(
        &self,
        invoice_id: uuid::Uuid,
        snapshot: &CreationSnapshot,
    ) -> Result<(), PersistenceError> {
        InvoiceStore::complete_creation_baseline(
            self,
            invoice_id,
            snapshot.tip_height,
            &snapshot.baseline_outputs,
            &snapshot.unconfirmed_inputs,
        )
        .await
    }
    async fn fail_creation_baseline(&self, invoice_id: uuid::Uuid) -> Result<(), PersistenceError> {
        InvoiceStore::fail_creation_baseline(self, invoice_id).await
    }
    async fn prepare_view(
        &self,
        invoice_id: uuid::Uuid,
    ) -> Result<Option<crate::persistence::InvoicePhaseView>, PersistenceError> {
        InvoiceStore::prepare_view(self, invoice_id).await
    }
}

/// Builds canonical paykit-lib inputs without allocating SDK-owned wire IDs.
pub trait IntentBuilder: Send + Sync {
    /// Builds the Payment Request terms. The amount is the nonce'd total
    /// (`lock price + nonce_sats`, design §B.8.2): the buyer's checkout
    /// figure, the Payment Request amount and the recorded total all agree.
    /// `expires_at` is carried as `proposal_expires_at` so the buyer's
    /// wallet enforces the expiry (design §B.9).
    fn payment_request_terms(
        &self,
        request: &CreateInvoiceRequest,
        lock: &ContentLock,
        nonce_sats: u64,
        expires_at: time::OffsetDateTime,
    ) -> Result<PaymentRequestTerms, CreateInvoiceError>;
    fn receiving_details(
        &self,
        address: &str,
    ) -> Result<Vec<(PaymentEndpointIdentifier, PaymentEndpointPayload)>, CreateInvoiceError>;
}

pub struct PaykitIntentBuilder {
    onchain_endpoint_identifier: &'static str,
}
impl PaykitIntentBuilder {
    /// Real wallets (Bitkit) reject payment endpoint identifiers whose network
    /// component does not match their configured chain, so non-mainnet
    /// deployments must not advertise `btc-bitcoin-p2wpkh`.
    pub fn for_network(network: &crate::config::BitcoinNetwork) -> Self {
        let onchain_endpoint_identifier = match network {
            crate::config::BitcoinNetwork::Mainnet => "btc-bitcoin-p2wpkh",
            crate::config::BitcoinNetwork::Testnet => "btc-testnet-p2wpkh",
            crate::config::BitcoinNetwork::Signet => "btc-signet-p2wpkh",
            crate::config::BitcoinNetwork::Regtest => "btc-regtest-p2wpkh",
        };
        Self {
            onchain_endpoint_identifier,
        }
    }

    /// The network-correct on-chain payment endpoint identifier this builder
    /// advertises. Shared with the marketplace payment-request service so
    /// lock-free requests carry the same identifier wallets accept.
    pub fn onchain_endpoint_identifier(&self) -> &'static str {
        self.onchain_endpoint_identifier
    }
}
impl Default for PaykitIntentBuilder {
    fn default() -> Self {
        Self {
            onchain_endpoint_identifier: "btc-bitcoin-p2wpkh",
        }
    }
}
impl IntentBuilder for PaykitIntentBuilder {
    fn payment_request_terms(
        &self,
        request: &CreateInvoiceRequest,
        lock: &ContentLock,
        nonce_sats: u64,
        expires_at: time::OffsetDateTime,
    ) -> Result<PaymentRequestTerms, CreateInvoiceError> {
        let amount = extract_terms(lock)?;
        let sats = amount
            .as_sats()
            .checked_add(nonce_sats)
            .ok_or(CreateInvoiceError::InvalidRequest)?;
        let mut metadata = Map::new();
        metadata.insert(
            "bundle_id".into(),
            Value::String(request.bundle_id.to_string()),
        );
        metadata.insert(
            "lock_resource".into(),
            Value::String(request.lock_resource.to_string()),
        );
        metadata.insert("reader".into(), Value::String(request.reader.to_string()));
        Ok(PaymentRequestTerms {
            // Paykit payment-requests spec: amount.asset is case-sensitive and
            // SHOULD use the same lowercase asset string as the endpoint
            // identifier asset segment; wallets (Bitkit) enforce "btc".
            amount: PaymentAmount::new(
                format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000),
                "btc",
            )
            .map_err(|_| CreateInvoiceError::InvalidRequest)?,
            payment_reference: PaymentReference::new(uuid::Uuid::new_v4().hyphenated().to_string())
                .map_err(|_| CreateInvoiceError::InvalidRequest)?,
            // §B.9: the expiry rides in the published request so the
            // buyer's wallet refuses to pay it once expired.
            proposal_expires_at: Some(
                expires_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|_| CreateInvoiceError::InvalidRequest)?,
            ),
            recurrence: None,
            accepted_payment_endpoint_identifiers: vec![
                PaymentEndpointIdentifier::new(self.onchain_endpoint_identifier)
                    .map_err(|_| CreateInvoiceError::InvalidRequest)?,
            ],
            metadata,
        })
    }

    fn receiving_details(
        &self,
        address: &str,
    ) -> Result<Vec<(PaymentEndpointIdentifier, PaymentEndpointPayload)>, CreateInvoiceError> {
        if address.is_empty() {
            return Err(CreateInvoiceError::InvalidRequest);
        }
        let identifier = PaymentEndpointIdentifier::new(self.onchain_endpoint_identifier)
            .map_err(|_| CreateInvoiceError::InvalidRequest)?;
        // Payment-endpoint-identifier spec section 7: the interoperable payload
        // convention is a JSON object with the receiving handle under "value".
        // Wallets (Bitkit) reject bare-string payloads; the demo reader masked
        // this by accepting raw addresses.
        let payload = serde_json::json!({ "value": address }).to_string();
        Ok(vec![(identifier, PaymentEndpointPayload::new(payload))])
    }
}

/// Derives the account xpub's BIP84 external-chain `0/index` P2WPKH address.
/// Hardened derivation is rejected: an account xpub must be depth three and its
/// hardened child number must agree with the persisted claim account index.
pub fn derive_bip84_p2wpkh_address(
    serialized_xpub: &str,
    account_index: u32,
    configured_network: &crate::config::BitcoinNetwork,
    child_index: i64,
) -> Result<String, CreateInvoiceError> {
    let index = u32::try_from(child_index).map_err(|_| CreateInvoiceError::Unavailable)?;
    let xpub = Xpub::from_str(serialized_xpub).map_err(|_| CreateInvoiceError::Unavailable)?;
    let expected = match configured_network {
        crate::config::BitcoinNetwork::Mainnet => NetworkKind::Main,
        crate::config::BitcoinNetwork::Testnet
        | crate::config::BitcoinNetwork::Signet
        | crate::config::BitcoinNetwork::Regtest => NetworkKind::Test,
    };
    if xpub.network != expected
        || xpub.depth != 3
        || xpub.child_number
            != ChildNumber::from_hardened_idx(account_index)
                .map_err(|_| CreateInvoiceError::Unavailable)?
    {
        return Err(CreateInvoiceError::Unavailable);
    }
    let path = [
        ChildNumber::from_normal_idx(0).map_err(|_| CreateInvoiceError::Unavailable)?,
        ChildNumber::from_normal_idx(index).map_err(|_| CreateInvoiceError::Unavailable)?,
    ];
    let derived = xpub
        .derive_pub(&Secp256k1::verification_only(), &path)
        .map_err(|_| CreateInvoiceError::Unavailable)?;
    let network = configured_network.as_bitcoin_network();
    Ok(Address::p2wpkh(&derived.to_pub(), network).to_string())
}

pub(crate) struct DerivedNewReaderPayloads {
    pub(crate) intents: Arc<dyn IntentBuilder>,
    pub(crate) xpub: String,
    pub(crate) account_index: u32,
    pub(crate) network: crate::config::BitcoinNetwork,
    pub(crate) reader: String,
    pub(crate) marker: PaykitReceiverMarker,
    pub(crate) local_receiver_path: PaykitReceiverPath,
}
impl NewReaderPayloadFactory for DerivedNewReaderPayloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        let address =
            derive_bip84_p2wpkh_address(&self.xpub, self.account_index, &self.network, child_index)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let receiving_details = self
            .intents
            .receiving_details(&address)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let endpoint_intent = DeliveryIntentV1::endpoint(
            self.reader.clone(),
            &self.marker,
            self.local_receiver_path.clone(),
            receiving_details,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        Ok(NewReaderPayloads {
            endpoint_intent,
            bitcoin_address: address,
        })
    }
}

pub trait DeadlineClock: Send + Sync {
    fn now(&self) -> Instant;
}
#[derive(Default)]
pub struct SystemDeadlineClock;
impl DeadlineClock for SystemDeadlineClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub struct CreateInvoiceService {
    sessions: Arc<dyn SessionValidator>,
    locks: Arc<dyn LockFetcher>,
    markers: Arc<dyn MarkerDiscovery>,
    marker_priority: Vec<ReceiverPathPriority>,
    local_receiver_path: PaykitReceiverPath,
    credentials: Arc<dyn CreatorXpubProvider>,
    bitcoin_network: crate::config::BitcoinNetwork,
    bitcoin_creation_enabled: bool,
    offer_availability: Arc<dyn OfferAvailability>,
    store: Arc<dyn InvoicePersistence>,
    electrum: Arc<dyn ElectrumPort>,
    max_creation_history_entries: usize,
    max_transaction_bytes: usize,
    electrum_limiter: RequestLimiter,
    creation_snapshot_slots: Arc<tokio::sync::Semaphore>,
    intents: Arc<dyn IntentBuilder>,
    clock: Arc<dyn DeadlineClock>,
    stack_id: String,
    prepare_ttl: Duration,
    max_request_expiry: Duration,
}
impl CreateInvoiceService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: Arc<dyn SessionValidator>,
        locks: Arc<dyn LockFetcher>,
        markers: Arc<dyn MarkerDiscovery>,
        marker_priority: Vec<ReceiverPathPriority>,
        local_receiver_path: PaykitReceiverPath,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        bitcoin_creation_enabled: bool,
        store: Arc<dyn InvoicePersistence>,
        electrum: Arc<dyn ElectrumPort>,
        max_creation_history_entries: usize,
        max_transaction_bytes: usize,
        intents: Arc<dyn IntentBuilder>,
    ) -> Self {
        Self::with_clock(
            sessions,
            locks,
            markers,
            marker_priority,
            local_receiver_path,
            credentials,
            bitcoin_network,
            bitcoin_creation_enabled,
            store,
            electrum,
            max_creation_history_entries,
            max_transaction_bytes,
            intents,
            Arc::new(SystemDeadlineClock),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_clock(
        sessions: Arc<dyn SessionValidator>,
        locks: Arc<dyn LockFetcher>,
        markers: Arc<dyn MarkerDiscovery>,
        marker_priority: Vec<ReceiverPathPriority>,
        local_receiver_path: PaykitReceiverPath,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        bitcoin_creation_enabled: bool,
        store: Arc<dyn InvoicePersistence>,
        electrum: Arc<dyn ElectrumPort>,
        max_creation_history_entries: usize,
        max_transaction_bytes: usize,
        intents: Arc<dyn IntentBuilder>,
        clock: Arc<dyn DeadlineClock>,
    ) -> Self {
        Self {
            sessions,
            locks,
            markers,
            marker_priority,
            local_receiver_path,
            credentials,
            bitcoin_network,
            bitcoin_creation_enabled,
            offer_availability: Arc::new(AlwaysAvailableOffer),
            store,
            electrum,
            max_creation_history_entries,
            max_transaction_bytes,
            electrum_limiter: RequestLimiter::new(u64::MAX, u64::MAX),
            creation_snapshot_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            intents,
            clock,
            stack_id: UNSPECIFIED_STACK_ID.to_owned(),
            prepare_ttl: DEFAULT_PREPARE_TTL,
            max_request_expiry: DEFAULT_MAX_REQUEST_EXPIRY,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_delivery_intents(
        sessions: Arc<dyn SessionValidator>,
        locks: Arc<dyn LockFetcher>,
        markers: Arc<dyn MarkerDiscovery>,
        marker_priority: Vec<ReceiverPathPriority>,
        local_receiver_path: PaykitReceiverPath,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        bitcoin_creation_enabled: bool,
        store: Arc<dyn InvoicePersistence>,
        electrum: Arc<dyn ElectrumPort>,
        max_creation_history_entries: usize,
        max_transaction_bytes: usize,
        intents: Arc<dyn IntentBuilder>,
    ) -> Self {
        Self::new(
            sessions,
            locks,
            markers,
            marker_priority,
            local_receiver_path,
            credentials,
            bitcoin_network,
            bitcoin_creation_enabled,
            store,
            electrum,
            max_creation_history_entries,
            max_transaction_bytes,
            intents,
        )
    }

    pub fn with_electrum_controls(
        mut self,
        limiter: RequestLimiter,
        creation_snapshot_slots: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        self.electrum_limiter = limiter;
        self.creation_snapshot_slots = creation_snapshot_slots;
        self
    }

    /// Installs the runtime's live offer-availability verdict as the
    /// first-time-bind gate. Installed once at startup; the verdict itself
    /// is read per request.
    pub fn with_offer_availability(mut self, availability: Arc<dyn OfferAvailability>) -> Self {
        self.offer_availability = availability;
        self
    }

    /// Installs this stack's minted identity (`{stack_role}:{instance_uuid}`)
    /// for the phase-1 response body. The marketplace persists it at bind
    /// time and echoes it on `activate`/`void` (§B.11.3).
    pub fn with_stack_identity(mut self, stack_id: String) -> Self {
        self.stack_id = stack_id;
        self
    }

    /// Installs the configured `bitcoin.prepare_ttl` stamped into
    /// `prepare_expires_at` at creation commit (§B.11.1).
    pub fn with_prepare_ttl(mut self, prepare_ttl: Duration) -> Self {
        self.prepare_ttl = prepare_ttl;
        self
    }

    /// Installs the configured `bitcoin.max_request_expiry` bounding how
    /// far out a prepare's `expires_at` may lie (§B.9, fail closed).
    pub fn with_max_request_expiry(mut self, max_request_expiry: Duration) -> Self {
        self.max_request_expiry = max_request_expiry;
        self
    }

    pub async fn create(
        &self,
        request: CreateInvoiceRequest,
    ) -> Result<crate::application::two_phase::PrepareBody, CreateInvoiceError> {
        let started = self.clock.now();
        let creator = request.lock_resource.creator().clone();
        let bundle_binding = request.bundle_id.to_string().into_bytes();
        let payment_request_binding = request_binding(&request)?;
        // §B.11.6: an exact replay whose invoice is still
        // `awaiting_baseline` WAITS for the in-flight baseline to resolve —
        // bounded by the request deadline, never a second snapshot, never a
        // second index. The helper returns only a resolved preflight.
        let preflight = preflight_after_baseline_resolution(
            self.store.as_ref(),
            self.clock.as_ref(),
            started,
            &creator,
            &bundle_binding,
            &payment_request_binding,
        )
        .await?;
        match preflight {
            InvoicePreflight::ExactReplay => {
                return self
                    .exact_replay_outcome(
                        started,
                        &creator,
                        &request.reader,
                        &bundle_binding,
                        &payment_request_binding,
                    )
                    .await;
            }
            InvoicePreflight::Conflict => return Err(CreateInvoiceError::Conflict),
            // §B.11.6: a phase-1 replay against a void state is the named
            // refusal, never replay success and never a fresh allocation.
            InvoicePreflight::InvoiceFinalized => {
                return Err(CreateInvoiceError::InvoiceFinalized);
            }
            InvoicePreflight::PrepareExpired => {
                return Err(CreateInvoiceError::PrepareExpired);
            }
            // An exact replay above binds nothing new; only first-time binds
            // are gated — by the creation kill switch first, then by the
            // runtime's live offer availability.
            InvoicePreflight::New if !self.bitcoin_creation_enabled => {
                return Err(CreateInvoiceError::BitcoinCreationDisabled);
            }
            InvoicePreflight::New => {}
            // The wait helper above returns only resolved rows.
            InvoicePreflight::BaselineInProgress => {
                return Err(CreateInvoiceError::Unavailable);
            }
        }
        // §B.9: `expires_at` is refused when past or beyond the configured
        // maximum (missing is rejected by the route's schema). The check
        // runs only for a New bind: an exact replay must return the stored
        // body even after the deadline has passed (§B.11.6 — `observing`
        // and `expired_tail` replay 200).
        validate_expires_at(request.expires_at, self.max_request_expiry)?;
        // Runtime creation gate (ordering: static creation flag above →
        // live availability here → limiter charging in the baseline
        // sequence below). Refusing here consumes no address, advances no
        // cursor, and charges no Electrum request; a verdict that cannot
        // be read in time fails closed. Observation of existing invoices
        // is never gated on this verdict.
        let offer_available = tokio::time::timeout(
            OFFER_AVAILABILITY_TIMEOUT,
            self.offer_availability.bitcoin_offer_available(),
        )
        .await
        .map_err(|_| CreateInvoiceError::BitcoinOfferUnavailable)?;
        if !offer_available {
            return Err(CreateInvoiceError::BitcoinOfferUnavailable);
        }
        let session_remaining = remaining(started, self.clock.now())?;
        tokio::time::timeout(session_remaining, self.sessions.validate(&creator))
            .await
            .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
            .map_err(|error| match error {
                SessionValidationError::Invalid => CreateInvoiceError::CreatorSessionInvalid,
                SessionValidationError::Unavailable => {
                    CreateInvoiceError::CreatorSessionUnavailable
                }
            })?;
        let lock_remaining = remaining(started, self.clock.now())?;
        let lock = tokio::time::timeout(lock_remaining, self.locks.fetch(&request.lock_resource))
            .await
            .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
            .map_err(|error| match error {
                LockFetchError::NotFound => CreateInvoiceError::LockNotFound,
                LockFetchError::Unavailable => CreateInvoiceError::LockUnavailable,
                LockFetchError::Invalid => CreateInvoiceError::InvalidRequest,
            })?;
        validate_lock(&request, &lock)?;
        let marker_remaining = remaining(started, self.clock.now())?;
        let discovered =
            tokio::time::timeout(marker_remaining, self.markers.discover(&request.reader))
                .await
                .map_err(|_| CreateInvoiceError::DeadlineExceeded)??;
        let selected = select_reader_marker(discovered, &self.marker_priority)
            .ok_or(CreateInvoiceError::Unavailable)?;
        let credentials_remaining = remaining(started, self.clock.now())?;
        let (xpub, account_index) =
            tokio::time::timeout(credentials_remaining, self.credentials.xpub(&creator))
                .await
                .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
                .map_err(map_store)?;
        let nonce_sats = draw_nonce_sats();
        let price_sats = extract_terms(&lock)?.as_sats();
        let total_sats = price_sats
            .checked_add(nonce_sats)
            .ok_or(CreateInvoiceError::InvalidRequest)?;
        let terms =
            self.intents
                .payment_request_terms(&request, &lock, nonce_sats, request.expires_at)?;
        let payment_request_intent = DeliveryIntentV1::payment_request(
            request.reader.to_string(),
            &selected.marker,
            self.local_receiver_path.clone(),
            &terms,
        )
        .map_err(|_| CreateInvoiceError::InvalidRequest)?;
        let new_reader_payloads = DerivedNewReaderPayloads {
            intents: self.intents.clone(),
            xpub,
            account_index,
            network: self.bitcoin_network.clone(),
            reader: request.reader.to_string(),
            marker: selected.marker,
            local_receiver_path: self.local_receiver_path.clone(),
        };
        remaining(started, self.clock.now())?;
        // Once PostgreSQL mutation starts it must be awaited to a factual
        // commit/rollback result. Canceling this future at the HTTP deadline
        // could otherwise return failure while COMMIT succeeds concurrently.
        let created = match self
            .store
            .create_atomic(AtomicInvoiceInput {
                creator: &creator,
                reader: &request.reader,
                bundle_binding: &bundle_binding,
                payment_request_binding: &payment_request_binding,
                new_reader_payloads: &new_reader_payloads,
                payment_request_intent,
                required_sats: total_sats,
                nonce_sats,
                prepare_ttl: self.prepare_ttl,
                expires_at: request.expires_at,
            })
            .await
        {
            Ok(created) => created,
            // §B.11.4 failure-matrix row 8 / §B.11.6: the `FOR UPDATE`
            // loser found the winner's committed `awaiting_baseline` row
            // under the row lock. It waits for the winner's baseline
            // exactly like a preflight-visible replay — never a second
            // snapshot, never a second index — then answers from the
            // stored row.
            Err(PersistenceError::BaselineInProgress) => {
                return match preflight_after_baseline_resolution(
                    self.store.as_ref(),
                    self.clock.as_ref(),
                    started,
                    &creator,
                    &bundle_binding,
                    &payment_request_binding,
                )
                .await?
                {
                    InvoicePreflight::ExactReplay => {
                        self.exact_replay_outcome(
                            started,
                            &creator,
                            &request.reader,
                            &bundle_binding,
                            &payment_request_binding,
                        )
                        .await
                    }
                    InvoicePreflight::Conflict => Err(CreateInvoiceError::Conflict),
                    InvoicePreflight::InvoiceFinalized => Err(CreateInvoiceError::InvoiceFinalized),
                    InvoicePreflight::PrepareExpired => Err(CreateInvoiceError::PrepareExpired),
                    // The winner's row is committed, so `New` cannot
                    // occur, and the wait helper never returns an
                    // unresolved row.
                    _ => Err(CreateInvoiceError::Unavailable),
                };
            }
            Err(error) => return Err(map_store(error)),
        };
        // A replayed row won a creation race (both preflights read `New`
        // before the winner committed). Its baseline belongs to the
        // winner: running the sequence here would double-charge the
        // shared limiter for one invoice and end in a Conflict. The
        // winner's still-unresolved `awaiting_baseline` row is handled
        // above (the wait arm), so a replay that returns here is the
        // stored invoice, served with its existing terms.
        if created.replayed() {
            return self.phase_one_outcome(created.invoice_id()).await;
        }
        let address = new_reader_payloads
            .for_child_index(created.reader_child_index())
            .map_err(map_store)?
            .bitcoin_address;
        complete_creation_baseline_within_deadline(
            self.store.as_ref(),
            self.electrum.as_ref(),
            &self.electrum_limiter,
            &self.creation_snapshot_slots,
            self.max_creation_history_entries,
            self.max_transaction_bytes,
            self.clock.as_ref(),
            started,
            created.invoice_id(),
            &address,
        )
        .await?;
        self.phase_one_outcome(created.invoice_id()).await
    }

    /// The §B.11.6 exact-replay path: load the stored row (re-verifying
    /// the binding and the state under the row lock) and build the
    /// phase-1 body from the stored view.
    async fn exact_replay_outcome(
        &self,
        started: Instant,
        creator: &CreatorPubky,
        reader: &ReaderPubky,
        bundle_binding: &[u8],
        payment_request_binding: &[u8],
    ) -> Result<crate::application::two_phase::PrepareBody, CreateInvoiceError> {
        let replay_remaining = remaining(started, self.clock.now())?;
        let replayed = tokio::time::timeout(
            replay_remaining,
            self.store
                .exact_replay(creator, reader, bundle_binding, payment_request_binding),
        )
        .await
        .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
        .map_err(map_store)?;
        self.phase_one_outcome(replayed.invoice_id()).await
    }

    /// Builds the §B.11.3 phase-1 body from the stored view — never from
    /// request-side state — so a fresh prepare and every replay report
    /// exactly what the database holds, and a replay landing on a void
    /// state yields the §B.11.6 named refusal instead of a stale success.
    async fn phase_one_outcome(
        &self,
        invoice_id: uuid::Uuid,
    ) -> Result<crate::application::two_phase::PrepareBody, CreateInvoiceError> {
        let view = self
            .store
            .prepare_view(invoice_id)
            .await
            .map_err(map_store)?
            .ok_or(CreateInvoiceError::Unavailable)?;
        crate::application::two_phase::prepare_outcome(&view, &self.stack_id)
    }
}

/// Poll cadence of the §B.11.6 replay wait: an exact replay whose invoice
/// is still `awaiting_baseline` re-reads the side-effect-free preflight at
/// this interval until the in-flight baseline resolves.
const BASELINE_REPLAY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// §B.11.6: an exact replay whose invoice is `awaiting_baseline` **waits**
/// for the in-flight baseline to reach `prepared` or
/// `void_baseline_failed` (or any later state), bounded by the request
/// deadline — never a second snapshot, never a second index, nonce or
/// outbox row. The budget check runs on the injected [`DeadlineClock`]
/// (never `Instant::now()`), so an exhausted request budget answers
/// `DeadlineExceeded` (503 `dependency_timeout`) rather than the
/// in-progress refusal, and tests drive the deadline through the clock
/// seam. Returns only a resolved preflight.
pub(crate) async fn preflight_after_baseline_resolution(
    store: &dyn InvoicePersistence,
    clock: &dyn DeadlineClock,
    started: Instant,
    creator: &CreatorPubky,
    bundle_binding: &[u8],
    payment_request_binding: &[u8],
) -> Result<InvoicePreflight, CreateInvoiceError> {
    loop {
        let preflight_remaining = remaining(started, clock.now())?;
        let preflight = tokio::time::timeout(
            preflight_remaining,
            store.preflight(creator, bundle_binding, payment_request_binding),
        )
        .await
        .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
        .map_err(map_store)?;
        if preflight != InvoicePreflight::BaselineInProgress {
            return Ok(preflight);
        }
        let wait_remaining = remaining(started, clock.now())?;
        tokio::time::sleep(BASELINE_REPLAY_POLL_INTERVAL.min(wait_remaining)).await;
    }
}

/// Post-`create_atomic` baseline sequence shared by both creation paths.
/// Every step — the shared-limiter reservations, the snapshot-slot
/// acquisition, the snapshot itself, and the probe — runs inside the
/// single [`REQUEST_DEADLINE`] budget that started with the request, so a
/// stalled slot or a slow snapshot can no longer hold the handler past its
/// deadline. On any timeout or unavailable outcome the baseline is failed
/// to completion first (a started DB mutation is never cancelled), so no
/// `observing` invoice and no `queued` outbox row can exist afterwards.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn complete_creation_baseline_within_deadline(
    store: &dyn InvoicePersistence,
    electrum: &dyn ElectrumPort,
    electrum_limiter: &RequestLimiter,
    creation_snapshot_slots: &Arc<tokio::sync::Semaphore>,
    max_creation_history_entries: usize,
    max_transaction_bytes: usize,
    clock: &dyn DeadlineClock,
    started: Instant,
    invoice_id: uuid::Uuid,
    address: &str,
) -> Result<(), CreateInvoiceError> {
    let baseline = async {
        let reservation_remaining = remaining(started, clock.now())?;
        electrum_limiter
            .reserve_or_wait(
                3,
                Instant::now() + reservation_remaining.min(Duration::from_secs(2)),
            )
            .await
            .map_err(|_| CreateInvoiceError::Unavailable)?;
        let slot_remaining = remaining(started, clock.now())?;
        let snapshot_slot = tokio::time::timeout(
            slot_remaining,
            creation_snapshot_slots.clone().acquire_owned(),
        )
        .await
        .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
        .map_err(|_| CreateInvoiceError::Unavailable)?;
        let snapshot_remaining = remaining(started, clock.now())?;
        let snapshot = match tokio::time::timeout(
            snapshot_remaining,
            electrum.creation_snapshot(
                address,
                max_creation_history_entries,
                max_transaction_bytes,
                electrum_limiter,
                snapshot_slot,
            ),
        )
        .await
        {
            Err(_) => return Err(CreateInvoiceError::DeadlineExceeded),
            Ok(Err(_)) => return Err(CreateInvoiceError::Unavailable),
            Ok(Ok(snapshot)) => snapshot,
        };
        let probe_remaining = remaining(started, clock.now())?;
        electrum_limiter
            .reserve_or_wait(
                PROBE_REQUESTS_PER_TICK,
                Instant::now() + probe_remaining.min(Duration::from_secs(2)),
            )
            .await
            .map_err(|_| CreateInvoiceError::Unavailable)?;
        let probe_remaining = remaining(started, clock.now())?;
        let probe = match tokio::time::timeout(probe_remaining, electrum.probe()).await {
            Err(_) => return Err(CreateInvoiceError::DeadlineExceeded),
            Ok(Err(_)) => return Err(CreateInvoiceError::Unavailable),
            Ok(Ok(probe)) => probe,
        };
        if probe.height.abs_diff(snapshot.tip_height) > 3 {
            return Err(CreateInvoiceError::Unavailable);
        }
        Ok(snapshot)
    };
    match baseline.await {
        Ok(snapshot) => store
            .complete_creation_baseline(invoice_id, &snapshot)
            .await
            .map_err(map_store),
        Err(error) => {
            store
                .fail_creation_baseline(invoice_id)
                .await
                .map_err(map_store)?;
            Err(error)
        }
    }
}

/// §B.9's fail-closed `expires_at` validation, shared by both prepare
/// entrypoints: past (server clock) or further out than
/// `max_request_expiry` is `invalid_request`; "missing" never reaches
/// here — the route schema rejects it with the same refusal class.
///
/// The maximum is bounded by `Duration`, not by the calendar: startup
/// validation accepts up to `i64::MAX` seconds, far outside the range
/// `OffsetDateTime` can represent, so the bound is evaluated with
/// checked conversion and addition. A maximum that cannot be
/// represented from `now` admits nothing — the bind is refused as
/// over-maximum rather than panic.
pub(crate) fn validate_expires_at(
    expires_at: time::OffsetDateTime,
    max_request_expiry: Duration,
) -> Result<(), CreateInvoiceError> {
    let now = time::OffsetDateTime::now_utc();
    if expires_at <= now {
        return Err(CreateInvoiceError::InvalidExpiry(ExpiryRefusal::Past));
    }
    let maximum = time::Duration::try_from(max_request_expiry)
        .ok()
        .and_then(|duration| now.checked_add(duration));
    match maximum {
        Some(maximum) if expires_at <= maximum => Ok(()),
        _ => Err(CreateInvoiceError::InvalidExpiry(
            ExpiryRefusal::OverMaximum,
        )),
    }
}

fn request_binding(request: &CreateInvoiceRequest) -> Result<Vec<u8>, CreateInvoiceError> {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": request.bundle_id.to_string(),
        "lock_resource": request.lock_resource.to_string(),
        "reader": request.reader.to_string(),
        "expires_at": request
            .expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| CreateInvoiceError::InvalidRequest)?,
    }))
    .map_err(|_| CreateInvoiceError::InvalidRequest)
}
pub(crate) fn remaining(start: Instant, now: Instant) -> Result<Duration, CreateInvoiceError> {
    let remaining = REQUEST_DEADLINE
        .checked_sub(now.saturating_duration_since(start))
        .ok_or(CreateInvoiceError::DeadlineExceeded)?;
    if remaining.is_zero() {
        return Err(CreateInvoiceError::DeadlineExceeded);
    }
    Ok(remaining)
}
pub(crate) fn map_store(error: PersistenceError) -> CreateInvoiceError {
    match error {
        PersistenceError::Conflict => CreateInvoiceError::Conflict,
        PersistenceError::BaselineInProgress => CreateInvoiceError::BaselineInProgress,
        PersistenceError::InvoiceFinalized => CreateInvoiceError::InvoiceFinalized,
        PersistenceError::PrepareExpired => CreateInvoiceError::PrepareExpired,
        PersistenceError::Unavailable => CreateInvoiceError::Unavailable,
        _ => CreateInvoiceError::Unavailable,
    }
}
fn validate_lock(
    request: &CreateInvoiceRequest,
    lock: &ContentLock,
) -> Result<(), CreateInvoiceError> {
    let raw_creator = RawCreatorPubky::from_str(&request.lock_resource.creator().to_string())
        .map_err(|_| CreateInvoiceError::InvalidRequest)?;
    if lock.creator != raw_creator {
        return Err(CreateInvoiceError::InvalidRequest);
    }
    lock.validate_paykit_payment_v1_policy()
        .map_err(|_| CreateInvoiceError::InvalidRequest)?;
    let criterion = lock
        .criteria
        .iter()
        .find(|criterion| criterion.verifier_type == VerifierType::PaykitPayment)
        .ok_or(CreateInvoiceError::InvalidRequest)?;
    CriterionAsset::parse(
        criterion
            .params
            .get("asset")
            .and_then(Value::as_str)
            .ok_or(CreateInvoiceError::InvalidRequest)?,
    )
    .map_err(|_| CreateInvoiceError::InvalidRequest)?;
    CriterionAmount::parse(
        criterion
            .params
            .get("amount")
            .and_then(Value::as_str)
            .ok_or(CreateInvoiceError::InvalidRequest)?,
    )
    .map_err(|_| CreateInvoiceError::InvalidRequest)?;
    Ok(())
}
fn extract_terms(lock: &ContentLock) -> Result<CriterionAmount, CreateInvoiceError> {
    let criterion = lock
        .criteria
        .iter()
        .find(|criterion| criterion.verifier_type == VerifierType::PaykitPayment)
        .ok_or(CreateInvoiceError::InvalidRequest)?;
    CriterionAsset::parse(
        criterion
            .params
            .get("asset")
            .and_then(Value::as_str)
            .ok_or(CreateInvoiceError::InvalidRequest)?,
    )
    .map_err(|_| CreateInvoiceError::InvalidRequest)?;
    CriterionAmount::parse(
        criterion
            .params
            .get("amount")
            .and_then(Value::as_str)
            .ok_or(CreateInvoiceError::InvalidRequest)?,
    )
    .map_err(|_| CreateInvoiceError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §B.9 regression: startup validation accepts a
    /// `bitcoin.max_request_expiry` of exactly `i64::MAX` seconds
    /// (humantime parses `"9223372036854775807s"`; the typed config test
    /// proves the acceptance), but that many seconds lands far outside
    /// the calendar range `OffsetDateTime` can represent from `now`.
    /// Evaluating `now + max_request_expiry` unchecked would panic on a
    /// valid configuration; the checked bound must fail closed as
    /// `OverMaximum` instead.
    #[test]
    fn unrepresentable_maximum_fails_closed_as_over_maximum_instead_of_panicking() {
        let max_request_expiry = Duration::from_secs(i64::MAX as u64);
        let expires_at = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        let result = validate_expires_at(expires_at, max_request_expiry);
        assert_eq!(
            result,
            Err(CreateInvoiceError::InvalidExpiry(
                ExpiryRefusal::OverMaximum
            )),
        );
    }

    /// The representable bound keeps its exact boundary semantics:
    /// `expires_at` at `now + max_request_expiry` is admitted, one
    /// second further out is refused.
    #[test]
    fn representable_maximum_keeps_its_boundary() {
        let max_request_expiry = Duration::from_secs(60);
        let boundary = time::OffsetDateTime::now_utc() + time::Duration::seconds(59);
        assert_eq!(validate_expires_at(boundary, max_request_expiry), Ok(()));
        let beyond = time::OffsetDateTime::now_utc() + time::Duration::seconds(61);
        assert_eq!(
            validate_expires_at(beyond, max_request_expiry),
            Err(CreateInvoiceError::InvalidExpiry(
                ExpiryRefusal::OverMaximum
            )),
        );
    }
}
