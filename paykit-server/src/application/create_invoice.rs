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
};

const REQUEST_DEADLINE: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
pub struct CreateInvoiceRequest {
    pub bundle_id: BundleId,
    pub lock_resource: PubkyLockResource,
    pub reader: ReaderPubky,
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
    DeadlineExceeded,
    Unavailable,
    /// New Bitcoin binds are administratively disabled on this stack.
    BitcoinCreationDisabled,
}

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
        InvoiceStore::create_atomic(self, input).await
    }
}

/// Builds canonical paykit-lib inputs without allocating SDK-owned wire IDs.
pub trait IntentBuilder: Send + Sync {
    fn payment_request_terms(
        &self,
        request: &CreateInvoiceRequest,
        lock: &ContentLock,
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
    ) -> Result<PaymentRequestTerms, CreateInvoiceError> {
        let amount = extract_terms(lock)?;
        let sats = amount.as_sats();
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
            proposal_expires_at: None,
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
    store: Arc<dyn InvoicePersistence>,
    intents: Arc<dyn IntentBuilder>,
    clock: Arc<dyn DeadlineClock>,
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
        store: Arc<dyn InvoicePersistence>,
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
            store,
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
        store: Arc<dyn InvoicePersistence>,
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
            store,
            intents,
            clock,
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
        store: Arc<dyn InvoicePersistence>,
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
            store,
            intents,
        )
    }

    pub async fn create(
        &self,
        request: CreateInvoiceRequest,
    ) -> Result<AtomicInvoiceResult, CreateInvoiceError> {
        let started = self.clock.now();
        let creator = request.lock_resource.creator().clone();
        let bundle_binding = request.bundle_id.to_string().into_bytes();
        let payment_request_binding = request_binding(&request)?;
        let preflight_remaining = remaining(started, self.clock.now())?;
        match tokio::time::timeout(
            preflight_remaining,
            self.store
                .preflight(&creator, &bundle_binding, &payment_request_binding),
        )
        .await
        .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
        .map_err(map_store)?
        {
            InvoicePreflight::ExactReplay => {
                let replay_remaining = remaining(started, self.clock.now())?;
                return tokio::time::timeout(
                    replay_remaining,
                    self.store.exact_replay(
                        &creator,
                        &request.reader,
                        &bundle_binding,
                        &payment_request_binding,
                    ),
                )
                .await
                .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
                .map_err(map_store);
            }
            InvoicePreflight::Conflict => return Err(CreateInvoiceError::Conflict),
            InvoicePreflight::New => {}
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
        let terms = self.intents.payment_request_terms(&request, &lock)?;
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
        self.store
            .create_atomic(AtomicInvoiceInput {
                creator: &creator,
                reader: &request.reader,
                bundle_binding: &bundle_binding,
                payment_request_binding: &payment_request_binding,
                new_reader_payloads: &new_reader_payloads,
                payment_request_intent,
                required_sats: extract_terms(&lock)?.as_sats(),
            })
            .await
            .map_err(map_store)
    }
}

fn request_binding(request: &CreateInvoiceRequest) -> Result<Vec<u8>, CreateInvoiceError> {
    serde_json_canonicalizer::to_vec(&serde_json::json!({"bundle_id":request.bundle_id.to_string(),"lock_resource":request.lock_resource.to_string(),"reader":request.reader.to_string()})).map_err(|_| CreateInvoiceError::InvalidRequest)
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
