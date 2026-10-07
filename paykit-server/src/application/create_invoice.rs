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
const REGISTRY_READ_ATTEMPTS: usize = 3;
const REGISTRY_RETRY_DELAY_CAPS_MS: [u64; REGISTRY_READ_ATTEMPTS - 1] = [333, 667];

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
pub enum RegistryDiscoveryError {
    InvalidRequest,
    Unavailable,
    Malformed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateInvoiceError {
    InvalidRequest,
    CreatorSessionInvalid,
    CreatorSessionUnavailable,
    LockNotFound,
    LockUnavailable,
    Conflict,
    ReaderSetupPending,
    ReaderNotPayable,
    ReaderRegistryUnavailable,
    ReaderRegistryMalformed,
    DeadlineExceeded,
    Unavailable,
}

impl CreateInvoiceError {
    pub(crate) const fn diagnostic_label(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::CreatorSessionInvalid => "creator_session_invalid",
            Self::CreatorSessionUnavailable => "creator_session_unavailable",
            Self::LockNotFound => "lock_not_found",
            Self::LockUnavailable => "lock_unavailable",
            Self::Conflict => "conflict",
            Self::ReaderSetupPending => "reader_setup_pending",
            Self::ReaderNotPayable => "reader_not_payable",
            Self::ReaderRegistryUnavailable => "reader_registry_unavailable",
            Self::ReaderRegistryMalformed => "reader_registry_malformed",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Unavailable => "unavailable",
        }
    }
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
pub trait AppRegistryDiscovery: Send + Sync {
    /// `Ok(None)` is reserved for a clean homeserver not-found/gone response.
    /// Read/transport failures and fetched invalid data remain typed errors.
    async fn discover(
        &self,
        reader: &ReaderPubky,
    ) -> Result<Option<PaykitAppRegistry>, RegistryDiscoveryError>;

    /// Reads the Reader's identity-signed Paykit Noise Key Authorization.
    /// Admission only: link setup verifies it again before any delivery,
    /// because the record can change in between.
    async fn authorization(
        &self,
        reader: &ReaderPubky,
    ) -> Result<ReaderAuthorization, RegistryDiscoveryError>;
}

/// Admission-time state of a Reader's signed Noise Key Authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderAuthorization {
    /// Present, signed by the Reader's identity key and owned by the Reader.
    Verified,
    /// Cleanly not found: the Reader's wallet has not published one yet.
    Missing,
    /// Present but unreadable, wrongly signed, or owned by another identity.
    Invalid,
}

#[async_trait]
pub trait RegistryRetryDelay: Send + Sync {
    async fn wait(&self, retry_index: usize);
}

#[derive(Default)]
struct FullJitterRegistryRetryDelay;

#[async_trait]
impl RegistryRetryDelay for FullJitterRegistryRetryDelay {
    async fn wait(&self, retry_index: usize) {
        let cap_ms = REGISTRY_RETRY_DELAY_CAPS_MS[retry_index];
        tokio::time::sleep(Duration::from_millis(rand::random_range(0..=cap_ms))).await;
    }
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
                .map_err(|error| {
                    diagnose("address_derivation", error);
                    PersistenceError::CorruptOrMissing
                })?;
        let terms = self
            .intents
            .payment_request_terms(self.request, self.lock, &address)
            .map_err(|error| {
                diagnose("payment_terms_construction", error);
                PersistenceError::CorruptOrMissing
            })?;
        let payment_request_intent = DeliveryIntentV1::payment_request(
            self.request.reader.to_string(),
            self.app_id.clone(),
            &terms,
        )
        .map_err(|_| {
            crate::diagnostics::failure(
                "invoice_create",
                "delivery_intent_construction",
                "serialization_failed",
            );
            PersistenceError::CorruptOrMissing
        })?;
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
    registry_retry_delay: Arc<dyn RegistryRetryDelay>,
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
            Arc::new(FullJitterRegistryRetryDelay),
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
            Arc::new(FullJitterRegistryRetryDelay),
            proposal_acceptance_window,
            payment_window,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registry_retry(
        sessions: Arc<dyn SessionValidator>,
        locks: Arc<dyn LockFetcher>,
        registries: Arc<dyn AppRegistryDiscovery>,
        app_id: PaykitAppId,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<dyn IntentBuilder>,
        registry_retry_delay: Arc<dyn RegistryRetryDelay>,
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
            registry_retry_delay,
            Duration::from_secs(60 * 60),
            Duration::from_secs(24 * 60 * 60),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_clock_and_registry_retry(
        sessions: Arc<dyn SessionValidator>,
        locks: Arc<dyn LockFetcher>,
        registries: Arc<dyn AppRegistryDiscovery>,
        app_id: PaykitAppId,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<dyn IntentBuilder>,
        clock: Arc<dyn DeadlineClock>,
        registry_retry_delay: Arc<dyn RegistryRetryDelay>,
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
            registry_retry_delay,
            Duration::from_secs(60 * 60),
            Duration::from_secs(24 * 60 * 60),
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
        registry_retry_delay: Arc<dyn RegistryRetryDelay>,
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
            registry_retry_delay,
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
        let payment_request_binding = request_binding(&request).inspect_err(|&error| {
            diagnose("request_binding", error);
        })?;
        let preflight_remaining = remaining_at(started, self.clock.now(), "invoice_preflight")?;
        match tokio::time::timeout(
            preflight_remaining,
            self.store
                .preflight(&creator, &bundle_binding, &payment_request_binding),
        )
        .await
        .map_err(|_| deadline("invoice_preflight"))?
        .map_err(|error| store_failure("invoice_preflight", error))?
        {
            InvoicePreflight::ExactReplay => {
                let replay_remaining = remaining_at(started, self.clock.now(), "exact_replay")?;
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
                .map_err(|_| deadline("exact_replay"))?
                .map_err(|error| store_failure("exact_replay", error));
            }
            InvoicePreflight::Conflict => {
                diagnose("invoice_preflight", CreateInvoiceError::Conflict);
                return Err(CreateInvoiceError::Conflict);
            }
            InvoicePreflight::New => {}
        }
        let session_remaining = remaining_at(started, self.clock.now(), "creator_session")?;
        tokio::time::timeout(session_remaining, self.sessions.validate(&creator))
            .await
            .map_err(|_| deadline("creator_session"))?
            .map_err(|error| match error {
                SessionValidationError::Invalid => {
                    diagnose("creator_session", CreateInvoiceError::CreatorSessionInvalid);
                    CreateInvoiceError::CreatorSessionInvalid
                }
                SessionValidationError::Unavailable => {
                    diagnose(
                        "creator_session",
                        CreateInvoiceError::CreatorSessionUnavailable,
                    );
                    CreateInvoiceError::CreatorSessionUnavailable
                }
            })?;
        let lock_remaining = remaining_at(started, self.clock.now(), "lock_fetch")?;
        let lock = tokio::time::timeout(lock_remaining, self.locks.fetch(&request.lock_resource))
            .await
            .map_err(|_| deadline("lock_fetch"))?
            .map_err(|error| match error {
                LockFetchError::NotFound => {
                    diagnose("lock_fetch", CreateInvoiceError::LockNotFound);
                    CreateInvoiceError::LockNotFound
                }
                LockFetchError::Unavailable => {
                    diagnose("lock_fetch", CreateInvoiceError::LockUnavailable);
                    CreateInvoiceError::LockUnavailable
                }
                LockFetchError::Invalid => {
                    diagnose("lock_fetch", CreateInvoiceError::InvalidRequest);
                    CreateInvoiceError::InvalidRequest
                }
            })?;
        validate_lock(&request, &lock).inspect_err(|&error| {
            diagnose("lock_validation", error);
        })?;
        let mut registry_attempt = 1;
        let discovered = loop {
            let registry_remaining =
                remaining_at(started, self.clock.now(), "reader_app_registry")?;
            let result = tokio::time::timeout(
                registry_remaining,
                self.registries.discover(&request.reader),
            )
            .await
            .map_err(|_| deadline("reader_app_registry"))?;
            match result {
                Ok(Some(registry)) => break registry,
                Ok(None) if registry_attempt < REGISTRY_READ_ATTEMPTS => {
                    let delay_remaining =
                        remaining_at(started, self.clock.now(), "reader_app_registry_retry")?;
                    tokio::time::timeout(
                        delay_remaining,
                        self.registry_retry_delay.wait(registry_attempt - 1),
                    )
                    .await
                    .map_err(|_| deadline("reader_app_registry_retry"))?;
                    registry_attempt += 1;
                }
                Ok(None) => {
                    diagnose(
                        "reader_app_registry_check",
                        CreateInvoiceError::ReaderSetupPending,
                    );
                    return Err(CreateInvoiceError::ReaderSetupPending);
                }
                Err(RegistryDiscoveryError::InvalidRequest) => {
                    diagnose(
                        "reader_app_registry_identity",
                        CreateInvoiceError::InvalidRequest,
                    );
                    return Err(CreateInvoiceError::InvalidRequest);
                }
                Err(RegistryDiscoveryError::Unavailable) => {
                    diagnose(
                        "reader_app_registry_fetch",
                        CreateInvoiceError::ReaderRegistryUnavailable,
                    );
                    return Err(CreateInvoiceError::ReaderRegistryUnavailable);
                }
                Err(RegistryDiscoveryError::Malformed) => {
                    diagnose(
                        "reader_app_registry_parse",
                        CreateInvoiceError::ReaderRegistryMalformed,
                    );
                    return Err(CreateInvoiceError::ReaderRegistryMalformed);
                }
            }
        };
        if !reader_is_capable(&discovered) {
            diagnose(
                "reader_app_registry_check",
                CreateInvoiceError::ReaderNotPayable,
            );
            return Err(CreateInvoiceError::ReaderNotPayable);
        }
        let authorization_remaining =
            remaining_at(started, self.clock.now(), "reader_authorization")?;
        let authorization = tokio::time::timeout(
            authorization_remaining,
            self.registries.authorization(&request.reader),
        )
        .await
        .map_err(|_| deadline("reader_authorization"))?;
        match authorization {
            Ok(ReaderAuthorization::Verified) => {}
            Ok(ReaderAuthorization::Missing) => {
                diagnose(
                    "reader_authorization_check",
                    CreateInvoiceError::ReaderSetupPending,
                );
                return Err(CreateInvoiceError::ReaderSetupPending);
            }
            Ok(ReaderAuthorization::Invalid) => {
                diagnose(
                    "reader_authorization_check",
                    CreateInvoiceError::ReaderNotPayable,
                );
                return Err(CreateInvoiceError::ReaderNotPayable);
            }
            Err(RegistryDiscoveryError::InvalidRequest) => {
                diagnose(
                    "reader_authorization_identity",
                    CreateInvoiceError::InvalidRequest,
                );
                return Err(CreateInvoiceError::InvalidRequest);
            }
            Err(RegistryDiscoveryError::Unavailable) => {
                diagnose(
                    "reader_authorization_fetch",
                    CreateInvoiceError::ReaderRegistryUnavailable,
                );
                return Err(CreateInvoiceError::ReaderRegistryUnavailable);
            }
            Err(RegistryDiscoveryError::Malformed) => {
                diagnose(
                    "reader_authorization_parse",
                    CreateInvoiceError::ReaderRegistryMalformed,
                );
                return Err(CreateInvoiceError::ReaderRegistryMalformed);
            }
        }
        let credentials_remaining = remaining_at(started, self.clock.now(), "creator_xpub_load")?;
        let (xpub, account_index) =
            tokio::time::timeout(credentials_remaining, self.credentials.xpub(&creator))
                .await
                .map_err(|_| deadline("creator_xpub_load"))?
                .map_err(|error| store_failure("creator_xpub_load", error))?;
        let invoice_payloads = DerivedInvoicePayloads {
            intents: self.intents.clone(),
            xpub,
            account_index,
            network: self.bitcoin_network.clone(),
            request: &request,
            lock: &lock,
            app_id: self.app_id.clone(),
        };
        remaining_at(started, self.clock.now(), "create_atomic")?;
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
            .map_err(|error| store_failure("create_atomic", error))
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

fn remaining_at(
    start: Instant,
    now: Instant,
    stage: &'static str,
) -> Result<Duration, CreateInvoiceError> {
    remaining(start, now).inspect_err(|&error| {
        diagnose(stage, error);
    })
}

fn deadline(stage: &'static str) -> CreateInvoiceError {
    diagnose(stage, CreateInvoiceError::DeadlineExceeded);
    CreateInvoiceError::DeadlineExceeded
}

fn store_failure(stage: &'static str, error: PersistenceError) -> CreateInvoiceError {
    crate::diagnostics::failure("invoice_create", stage, error.diagnostic_label());
    map_store(error)
}

fn diagnose(stage: &'static str, error: CreateInvoiceError) {
    crate::diagnostics::failure("invoice_create", stage, error.diagnostic_label());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_retry_policy_is_three_reads_with_at_most_one_second_of_delay() {
        assert_eq!(REGISTRY_READ_ATTEMPTS, 3);
        assert_eq!(REGISTRY_RETRY_DELAY_CAPS_MS.len(), 2);
        assert_eq!(REGISTRY_RETRY_DELAY_CAPS_MS.iter().sum::<u64>(), 1_000);
    }
}
