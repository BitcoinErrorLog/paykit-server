//! Invoice application service: replay-first validation and atomic intent persistence.

use std::{
    collections::HashMap,
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
    PaykitAppId, PaykitAppRegistry, PaymentAmount, PaymentEndpointIdentifier,
    PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
};
use serde_json::{Map, Value};

use crate::{
    application::{reader_registry::reader_is_capable, semantic_intent::DeliveryIntentV1},
    domain::{
        invoice::{CriterionAmount, CriterionAsset, CriterionPaymentWindowHours},
        locks::{BundleId, CreatorPubky, PubkyLockResource, ReaderPubky},
    },
    persistence::{
        AtomicInvoiceInput, AtomicInvoiceResult, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoicePreflight, InvoiceStore, PersistenceError,
    },
};

const REQUEST_DEADLINE: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
pub struct CreateInvoiceRequest {
    pub bundle_id: BundleId,
    pub lock_resource: PubkyLockResource,
    pub reader: ReaderPubky,
    pub payment_in: CriterionPaymentWindowHours,
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
    /// The Reader's App Registry was read and cannot receive or pay this request.
    ReaderNotPayable,
    DeadlineExceeded,
    Unavailable,
}

#[async_trait]
pub trait SessionValidator: Send + Sync {
    async fn validate(&self, creator: &CreatorPubky) -> Result<(), SessionValidationError>;
}
#[async_trait]
pub trait LockFetcher: Send + Sync {
    async fn fetch(&self, resource: &PubkyLockResource) -> Result<ContentLock, LockFetchError>;
}
/// `Ok(None)` means the Reader's homeserver answered that no App Registry is
/// published. Storage, transport, and malformed-data failures must be errors.
#[async_trait]
pub trait AppRegistryDiscovery: Send + Sync {
    async fn discover(
        &self,
        reader: &ReaderPubky,
    ) -> Result<Option<PaykitAppRegistry>, CreateInvoiceError>;
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
        address: &str,
    ) -> Result<PaymentRequestTerms, CreateInvoiceError>;
}

pub struct PaykitIntentBuilder {
    bitcoin_network: crate::config::BitcoinNetwork,
}

impl PaykitIntentBuilder {
    pub fn new(bitcoin_network: crate::config::BitcoinNetwork) -> Self {
        Self { bitcoin_network }
    }

    fn p2wpkh_identifier(&self) -> &'static str {
        match self.bitcoin_network {
            crate::config::BitcoinNetwork::Mainnet => "btc-bitcoin-p2wpkh",
            crate::config::BitcoinNetwork::Testnet => "btc-testnet-p2wpkh",
            crate::config::BitcoinNetwork::Signet => "btc-signet-p2wpkh",
            crate::config::BitcoinNetwork::Regtest => "btc-regtest-p2wpkh",
        }
    }
}

impl IntentBuilder for PaykitIntentBuilder {
    fn payment_request_terms(
        &self,
        request: &CreateInvoiceRequest,
        lock: &ContentLock,
        address: &str,
    ) -> Result<PaymentRequestTerms, CreateInvoiceError> {
        if address.is_empty() {
            return Err(CreateInvoiceError::InvalidRequest);
        }
        let identifier = PaymentEndpointIdentifier::new(self.p2wpkh_identifier())
            .map_err(|_| CreateInvoiceError::InvalidRequest)?;
        let payload = serde_json::to_string(&serde_json::json!({ "value": address }))
            .map_err(|_| CreateInvoiceError::InvalidRequest)?;
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
        PaymentRequestTerms::builder(
            PaymentAmount::new(
                format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000),
                "btc",
            )
            .map_err(|_| CreateInvoiceError::InvalidRequest)?,
            PaymentReference::new(uuid::Uuid::new_v4().hyphenated().to_string())
                .map_err(|_| CreateInvoiceError::InvalidRequest)?,
            vec![identifier.clone()],
        )
        .required_app_id(Some(
            PaykitAppId::new(crate::config::PAYKIT_APP_ID).expect("static app id"),
        ))
        .payment_endpoints(Some(HashMap::from([(
            identifier,
            PaymentEndpointPayload::new(payload),
        )])))
        .metadata(metadata)
        .build()
        .map_err(|_| CreateInvoiceError::InvalidRequest)
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

struct DerivedInvoicePayloads<'a> {
    intents: Arc<dyn IntentBuilder>,
    xpub: String,
    account_index: u32,
    network: crate::config::BitcoinNetwork,
    request: &'a CreateInvoiceRequest,
    lock: &'a ContentLock,
    app_id: PaykitAppId,
}
impl InvoicePayloadFactory for DerivedInvoicePayloads<'_> {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let address =
            derive_bip84_p2wpkh_address(&self.xpub, self.account_index, &self.network, child_index)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let terms = self
            .intents
            .payment_request_terms(self.request, self.lock, &address)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment_request_intent = DeliveryIntentV1::payment_request(
            self.request.reader.to_string(),
            self.app_id.clone(),
            &terms,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        Ok(InvoicePayloads {
            payment_request_intent,
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
    registries: Arc<dyn AppRegistryDiscovery>,
    app_id: PaykitAppId,
    credentials: Arc<dyn CreatorXpubProvider>,
    bitcoin_network: crate::config::BitcoinNetwork,
    store: Arc<dyn InvoicePersistence>,
    intents: Arc<dyn IntentBuilder>,
    clock: Arc<dyn DeadlineClock>,
    proposal_acceptance_window: Duration,
    payment_window: Duration,
}
impl CreateInvoiceService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: Arc<dyn SessionValidator>,
        locks: Arc<dyn LockFetcher>,
        registries: Arc<dyn AppRegistryDiscovery>,
        app_id: PaykitAppId,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<dyn IntentBuilder>,
    ) -> Self {
        Self::with_clock(
            sessions,
            locks,
            registries,
            app_id,
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
        registries: Arc<dyn AppRegistryDiscovery>,
        app_id: PaykitAppId,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<dyn IntentBuilder>,
        clock: Arc<dyn DeadlineClock>,
    ) -> Self {
        Self::with_clock_and_windows(
            sessions,
            locks,
            registries,
            app_id,
            credentials,
            bitcoin_network,
            store,
            intents,
            clock,
            Duration::from_secs(60 * 60),
            Duration::from_secs(24 * 60 * 60),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_invoice_windows(
        sessions: Arc<dyn SessionValidator>,
        locks: Arc<dyn LockFetcher>,
        registries: Arc<dyn AppRegistryDiscovery>,
        app_id: PaykitAppId,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<dyn IntentBuilder>,
        proposal_acceptance_window: Duration,
        payment_window: Duration,
    ) -> Self {
        Self::with_clock_and_windows(
            sessions,
            locks,
            registries,
            app_id,
            credentials,
            bitcoin_network,
            store,
            intents,
            Arc::new(SystemDeadlineClock),
            proposal_acceptance_window,
            payment_window,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_clock_and_windows(
        sessions: Arc<dyn SessionValidator>,
        locks: Arc<dyn LockFetcher>,
        registries: Arc<dyn AppRegistryDiscovery>,
        app_id: PaykitAppId,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<dyn IntentBuilder>,
        clock: Arc<dyn DeadlineClock>,
        proposal_acceptance_window: Duration,
        payment_window: Duration,
    ) -> Self {
        Self {
            sessions,
            locks,
            registries,
            app_id,
            credentials,
            bitcoin_network,
            store,
            intents,
            clock,
            proposal_acceptance_window,
            payment_window,
        }
    }

    pub async fn create(
        &self,
        request: CreateInvoiceRequest,
    ) -> Result<AtomicInvoiceResult, CreateInvoiceError> {
        let started = self.clock.now();
        let creator = request.lock_resource.creator().clone();
        let bundle_binding = request.bundle_id.to_string().into_bytes();
        let lock_resource_binding = request.lock_resource.to_string().into_bytes();
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
        let registry_remaining = remaining(started, self.clock.now())?;
        let discovered = tokio::time::timeout(
            registry_remaining,
            self.registries.discover(&request.reader),
        )
        .await
        .map_err(|_| CreateInvoiceError::DeadlineExceeded)??;
        // Discovery succeeded, so a missing or incapable registry is a definite
        // answer about this Reader rather than a dependency outage. Retrying the
        // same request cannot succeed until the Reader publishes a capable app.
        if !discovered.as_ref().is_some_and(reader_is_capable) {
            return Err(CreateInvoiceError::ReaderNotPayable);
        }
        let credentials_remaining = remaining(started, self.clock.now())?;
        let (xpub, account_index) =
            tokio::time::timeout(credentials_remaining, self.credentials.xpub(&creator))
                .await
                .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
                .map_err(map_store)?;
        let invoice_payloads = DerivedInvoicePayloads {
            intents: self.intents.clone(),
            xpub,
            account_index,
            network: self.bitcoin_network.clone(),
            request: &request,
            lock: &lock,
            app_id: self.app_id.clone(),
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
                lock_resource_binding: &lock_resource_binding,
                payment_request_binding: &payment_request_binding,
                invoice_payloads: &invoice_payloads,
                required_sats: extract_terms(&lock)?.as_sats(),
                proposal_acceptance_seconds: self.proposal_acceptance_window.as_secs(),
                payment_window_seconds: self.payment_window.as_secs(),
            })
            .await
            .map_err(map_store)
    }
}

fn request_binding(request: &CreateInvoiceRequest) -> Result<Vec<u8>, CreateInvoiceError> {
    serde_json_canonicalizer::to_vec(&serde_json::json!({"bundle_id":request.bundle_id.to_string(),"lock_resource":request.lock_resource.to_string(),"reader":request.reader.to_string(),"payment_in":request.payment_in.get()})).map_err(|_| CreateInvoiceError::InvalidRequest)
}
fn remaining(start: Instant, now: Instant) -> Result<Duration, CreateInvoiceError> {
    let remaining = REQUEST_DEADLINE
        .checked_sub(now.saturating_duration_since(start))
        .ok_or(CreateInvoiceError::DeadlineExceeded)?;
    if remaining.is_zero() {
        return Err(CreateInvoiceError::DeadlineExceeded);
    }
    Ok(remaining)
}
fn map_store(error: PersistenceError) -> CreateInvoiceError {
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
