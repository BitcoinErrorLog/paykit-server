//! Signed Marketplace preparation of durable unpublished invoices.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex, OnceLock, Weak},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use paykit_lib::{
    ConversionRate, PaykitAppId, PaymentAmount, PaymentConversion, PaymentEndpointIdentifier,
    PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
};
use time::OffsetDateTime;

use crate::{
    application::{
        create_invoice::{
            AppRegistryDiscovery, CreatorReceivingProvider, FullJitterRegistryRetryDelay,
            REGISTRY_READ_ATTEMPTS, REQUEST_DEADLINE, ReaderAuthorization, RegistryDiscoveryError,
            RegistryRetryDelay, SessionValidationError, SessionValidator,
            derive_bip84_p2wpkh_address,
        },
        invoice_pricing::{ExchangeRates, conversion_rates},
        marketplace_terms::MarketplaceTerms,
        reader_registry::reader_is_capable,
        semantic_intent::DeliveryIntentV1,
        setup_status::AcceptedAsset,
    },
    config::BitcoinNetwork,
    domain::{
        invoice::CriterionAsset,
        locks::{CreatorPubky, ReaderPubky},
        receiving::{BitcoinAccount, USDT_ENDPOINT, UsdtAddress},
    },
    persistence::{
        MarketplacePreparationInput, MarketplacePreparationPayloadFactory,
        MarketplacePreparationPayloads, MarketplacePreparationPreflight,
        MarketplacePreparationResult, MarketplacePreparationStore, PersistenceError,
    },
};

pub struct PrepareMarketplaceRequest {
    pub creator: CreatorPubky,
    pub reader: ReaderPubky,
    pub reference: String,
    /// Exact amount in `asset`'s base units: sats, cents or millionths.
    pub amount: u64,
    /// Denomination of `amount`.
    pub asset: CriterionAsset,
    /// Optional narrowing of the seller's enabled receiving options. When omitted,
    /// the request offers every asset the seller has set up. When present it is a
    /// non-empty, unique subset filter that never adds a rail.
    pub accepted_assets: Option<Vec<AcceptedAsset>>,
    pub operation_id: String,
    pub payment_window_seconds: u64,
    pub description: Option<String>,
}

/// Receiving rails a seller still has to set up for the accepted assets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingSellerRails {
    Bitcoin,
    Usdt,
    BitcoinAndUsdt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareMarketplaceError {
    InvalidRequest,
    Conflict,
    CreatorSessionInvalid,
    CreatorSessionUnavailable,
    ReaderSetupPending,
    ReaderNotPayable,
    ReaderRegistryUnavailable,
    ReaderRegistryMalformed,
    SellerSetupPending(MissingSellerRails),
    /// An accepted asset needs a rail this deployment is not configured for.
    AssetUnsupported,
    /// The payment window is over the cap that applies to this request's conversion.
    PaymentWindowExceedsCap,
    DeadlineExceeded,
    Unavailable,
}

impl PrepareMarketplaceError {
    pub(crate) const fn diagnostic_label(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Conflict => "operation_conflict",
            Self::CreatorSessionInvalid => "creator_session_invalid",
            Self::CreatorSessionUnavailable => "creator_session_unavailable",
            Self::ReaderSetupPending => "reader_setup_pending",
            Self::ReaderNotPayable => "reader_not_payable",
            Self::ReaderRegistryUnavailable => "reader_registry_unavailable",
            Self::ReaderRegistryMalformed => "reader_registry_malformed",
            Self::SellerSetupPending(_) => "seller_setup_pending",
            Self::AssetUnsupported => "asset_unsupported",
            Self::PaymentWindowExceedsCap => "payment_window_exceeds_cap",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Unavailable => "unavailable",
        }
    }
}

#[async_trait]
pub trait MarketplacePreparationPersistence: Send + Sync {
    async fn preflight(
        &self,
        creator: &CreatorPubky,
        operation_id: &str,
        request_binding: &[u8],
    ) -> Result<MarketplacePreparationPreflight, PersistenceError>;

    async fn prepare(
        &self,
        input: MarketplacePreparationInput<'_>,
    ) -> Result<MarketplacePreparationResult, PersistenceError>;

    /// The database clock, the one clock a preparation's expiry is fixed and judged on.
    async fn database_time(&self) -> Result<OffsetDateTime, PersistenceError>;
}

#[async_trait]
impl MarketplacePreparationPersistence for MarketplacePreparationStore {
    async fn preflight(
        &self,
        creator: &CreatorPubky,
        operation_id: &str,
        request_binding: &[u8],
    ) -> Result<MarketplacePreparationPreflight, PersistenceError> {
        MarketplacePreparationStore::preflight(self, creator, operation_id, request_binding).await
    }

    async fn prepare(
        &self,
        input: MarketplacePreparationInput<'_>,
    ) -> Result<MarketplacePreparationResult, PersistenceError> {
        MarketplacePreparationStore::prepare(self, input).await
    }

    async fn database_time(&self) -> Result<OffsetDateTime, PersistenceError> {
        MarketplacePreparationStore::database_time(self).await
    }
}

pub struct PrepareMarketplaceService {
    sessions: Arc<dyn SessionValidator>,
    registries: Arc<dyn AppRegistryDiscovery>,
    credentials: Arc<dyn CreatorReceivingProvider>,
    store: Arc<dyn MarketplacePreparationPersistence>,
    app_id: PaykitAppId,
    bitcoin_network: BitcoinNetwork,
    payment_window_cap: Duration,
    conversion_payment_window: Duration,
    prepare_ttl: Duration,
    usdt_enabled: bool,
    rates: Option<Arc<dyn ExchangeRates>>,
    registry_retry_delay: Arc<dyn RegistryRetryDelay>,
    request_deadline: Duration,
}

impl PrepareMarketplaceService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: Arc<dyn SessionValidator>,
        registries: Arc<dyn AppRegistryDiscovery>,
        credentials: Arc<dyn CreatorReceivingProvider>,
        store: Arc<dyn MarketplacePreparationPersistence>,
        app_id: PaykitAppId,
        bitcoin_network: BitcoinNetwork,
        payment_window_cap: Duration,
        prepare_ttl: Duration,
    ) -> Self {
        Self {
            sessions,
            registries,
            credentials,
            store,
            app_id,
            bitcoin_network,
            payment_window_cap,
            conversion_payment_window: Duration::from_secs(3600),
            prepare_ttl,
            usdt_enabled: false,
            rates: None,
            registry_retry_delay: Arc::new(FullJitterRegistryRetryDelay),
            request_deadline: REQUEST_DEADLINE,
        }
    }

    /// Enables USDT as an accepted payment asset on this deployment.
    pub fn with_usdt(mut self, enabled: bool) -> Self {
        self.usdt_enabled = enabled;
        self
    }

    /// Cap for requests whose conversion crosses Bitcoin; never clamped, only refused.
    pub fn with_conversion_payment_window(mut self, window: Duration) -> Self {
        self.conversion_payment_window = window;
        self
    }

    /// BTC/USD feed read once at prepare for requests that cross Bitcoin.
    pub fn with_exchange_rates(mut self, rates: Arc<dyn ExchangeRates>) -> Self {
        self.rates = Some(rates);
        self
    }

    pub fn with_registry_retry_delay(
        mut self,
        registry_retry_delay: Arc<dyn RegistryRetryDelay>,
    ) -> Self {
        self.registry_retry_delay = registry_retry_delay;
        self
    }

    pub fn with_request_deadline(mut self, request_deadline: Duration) -> Self {
        self.request_deadline = request_deadline;
        self
    }

    pub async fn prepare(
        &self,
        request: PrepareMarketplaceRequest,
    ) -> Result<MarketplacePreparationResult, PrepareMarketplaceError> {
        let started = Instant::now();
        let filter =
            normalized_filter(request.accepted_assets.as_deref()).inspect_err(|&error| {
                diagnose("request_terms", error);
            })?;
        if request.amount == 0 {
            diagnose("request_terms", PrepareMarketplaceError::InvalidRequest);
            return Err(PrepareMarketplaceError::InvalidRequest);
        }
        let request_binding =
            request_binding(&request, filter.as_deref()).inspect_err(|&error| {
                diagnose("request_binding", error);
            })?;
        // PostgreSQL creator-row locking serializes commits across processes. This
        // process-local lock only prevents duplicate mutable external reads here.
        let operation_lock = marketplace_operation_lock(&request.creator, &request.operation_id);
        let _operation_guard = tokio::time::timeout(
            remaining_at(started, self.request_deadline, "operation_lock")?,
            operation_lock.lock(),
        )
        .await
        .map_err(|_| deadline("operation_lock"))?;
        let preflight = tokio::time::timeout(
            remaining_at(started, self.request_deadline, "preflight")?,
            self.store
                .preflight(&request.creator, &request.operation_id, &request_binding),
        )
        .await
        .map_err(|_| deadline("preflight"))?
        .map_err(|error| store_failure("preflight", error))?;
        match preflight {
            MarketplacePreparationPreflight::ExactReplay => {
                return tokio::time::timeout(
                    remaining_at(started, self.request_deadline, "exact_replay")?,
                    self.store.prepare(MarketplacePreparationInput {
                        creator: &request.creator,
                        reader: &request.reader,
                        reference: &request.reference,
                        operation_id: &request.operation_id,
                        request_binding: &request_binding,
                        amount: request.amount,
                        asset: request.asset,
                        payment_window_seconds: request.payment_window_seconds,
                        prepare_ttl_seconds: self.prepare_ttl.as_secs(),
                        prepare_deadline: None,
                        payloads: &ReplayOnlyPayloads,
                    }),
                )
                .await
                .map_err(|_| deadline("exact_replay"))?
                .map_err(|error| store_failure("exact_replay", error));
            }
            MarketplacePreparationPreflight::Conflict => {
                diagnose("preflight", PrepareMarketplaceError::Conflict);
                return Err(PrepareMarketplaceError::Conflict);
            }
            MarketplacePreparationPreflight::New => {}
        }

        self.validate_request(&request).inspect_err(|&error| {
            diagnose("request_validation", error);
        })?;

        tokio::time::timeout(
            remaining_at(started, self.request_deadline, "creator_session")?,
            self.sessions.validate(&request.creator),
        )
        .await
        .map_err(|_| deadline("creator_session"))?
        .map_err(|error| match error {
            SessionValidationError::Invalid => {
                diagnose(
                    "creator_session",
                    PrepareMarketplaceError::CreatorSessionInvalid,
                );
                PrepareMarketplaceError::CreatorSessionInvalid
            }
            SessionValidationError::Unavailable => {
                diagnose(
                    "creator_session",
                    PrepareMarketplaceError::CreatorSessionUnavailable,
                );
                PrepareMarketplaceError::CreatorSessionUnavailable
            }
        })?;
        let mut registry_attempt = 1;
        let registry = loop {
            let result = tokio::time::timeout(
                remaining_at(started, self.request_deadline, "reader_app_registry")?,
                self.registries.discover(&request.reader),
            )
            .await
            .map_err(|_| deadline("reader_app_registry"))?;
            match result {
                Ok(Some(registry)) => break registry,
                Ok(None) if registry_attempt < REGISTRY_READ_ATTEMPTS => {
                    tokio::time::timeout(
                        remaining_at(started, self.request_deadline, "reader_app_registry_retry")?,
                        self.registry_retry_delay.wait(registry_attempt - 1),
                    )
                    .await
                    .map_err(|_| deadline("reader_app_registry_retry"))?;
                    registry_attempt += 1;
                }
                Ok(None) => {
                    diagnose(
                        "reader_app_registry_check",
                        PrepareMarketplaceError::ReaderSetupPending,
                    );
                    return Err(PrepareMarketplaceError::ReaderSetupPending);
                }
                Err(error) => return Err(registry_failure("reader_app_registry", error)),
            }
        };
        if !reader_is_capable(&registry) {
            diagnose(
                "reader_app_registry_check",
                PrepareMarketplaceError::ReaderNotPayable,
            );
            return Err(PrepareMarketplaceError::ReaderNotPayable);
        }
        let authorization = tokio::time::timeout(
            remaining_at(started, self.request_deadline, "reader_authorization")?,
            self.registries.authorization(&request.reader),
        )
        .await
        .map_err(|_| deadline("reader_authorization"))?
        .map_err(|error| registry_failure("reader_authorization", error))?;
        match authorization {
            ReaderAuthorization::Verified => {}
            ReaderAuthorization::Missing => {
                diagnose(
                    "reader_authorization_check",
                    PrepareMarketplaceError::ReaderSetupPending,
                );
                return Err(PrepareMarketplaceError::ReaderSetupPending);
            }
            ReaderAuthorization::Invalid => {
                diagnose(
                    "reader_authorization_check",
                    PrepareMarketplaceError::ReaderNotPayable,
                );
                return Err(PrepareMarketplaceError::ReaderNotPayable);
            }
        }
        let receiving = tokio::time::timeout(
            remaining_at(started, self.request_deadline, "seller_receiving_details")?,
            self.credentials.receiving(&request.creator),
        )
        .await
        .map_err(|_| deadline("seller_receiving_details"))?
        .map_err(|error| store_failure("seller_receiving_details", error))?;
        // The seller's setup decides what can be offered, exactly as for Locks
        // invoices; a filter only narrows that set and never adds a rail.
        let allowed = |asset: AcceptedAsset| filter.as_ref().is_none_or(|set| set.contains(&asset));
        let bitcoin = receiving.bitcoin.filter(|_| allowed(AcceptedAsset::Btc));
        let expected_bitcoin_account_generation = bitcoin
            .as_ref()
            .map(|_| receiving.bitcoin_account_generation);
        let usdt = receiving
            .usdt
            .filter(|_| self.usdt_enabled && allowed(AcceptedAsset::Usdt));
        let offered: Vec<_> = [
            bitcoin.as_ref().map(|_| AcceptedAsset::Btc),
            usdt.as_ref().map(|_| AcceptedAsset::Usdt),
        ]
        .into_iter()
        .flatten()
        .collect();
        let Ok(terms) = MarketplaceTerms::new(request.amount, request.asset, offered) else {
            let error = refusal_without_rails(filter.as_deref(), self.usdt_enabled);
            diagnose("seller_receiving_details_check", error);
            return Err(error);
        };
        let cap = if terms.crosses_bitcoin_rate() {
            self.payment_window_cap.min(self.conversion_payment_window)
        } else {
            self.payment_window_cap
        };
        if request.payment_window_seconds > cap.as_secs() {
            diagnose(
                "payment_window_cap",
                PrepareMarketplaceError::PaymentWindowExceedsCap,
            );
            return Err(PrepareMarketplaceError::PaymentWindowExceedsCap);
        }
        // One feed read, fixed here for the life of the preparation: activation never
        // refetches, so the buyer's quote cannot move after the order is shown.
        let price = if terms.crosses_bitcoin_rate() {
            let provider = self.rates.as_ref().ok_or_else(|| {
                diagnose("exchange_rate", PrepareMarketplaceError::Unavailable);
                PrepareMarketplaceError::Unavailable
            })?;
            Some(
                tokio::time::timeout(
                    remaining_at(started, self.request_deadline, "exchange_rate")?,
                    provider.usd_per_btc(),
                )
                .await
                .map_err(|_| deadline("exchange_rate"))?
                .map_err(|_| {
                    diagnose("exchange_rate", PrepareMarketplaceError::Unavailable);
                    PrepareMarketplaceError::Unavailable
                })?,
            )
        } else {
            None
        };
        let rates = conversion_rates(
            terms.asset(),
            terms.accepts(AcceptedAsset::Btc),
            terms.accepts(AcceptedAsset::Usdt),
            price.as_deref(),
        )
        .map_err(|_| {
            diagnose("exchange_rate", PrepareMarketplaceError::Unavailable);
            PrepareMarketplaceError::Unavailable
        })?;
        let payloads = MarketplacePayloads {
            reader: &request.reader,
            reference: &request.reference,
            terms: &terms,
            rates,
            description: request.description.as_deref(),
            app_id: &self.app_id,
            bitcoin_network: &self.bitcoin_network,
            bitcoin,
            bitcoin_account_generation: expected_bitcoin_account_generation,
            usdt,
        };
        // The preparation's whole life is fixed here, on the database clock, when the
        // quote is accepted. A wait for the Creator row can only use up that life: the
        // store refuses once the deadline has passed and never starts a new TTL.
        let accepted_at = tokio::time::timeout(
            remaining_at(started, self.request_deadline, "quote_clock")?,
            self.store.database_time(),
        )
        .await
        .map_err(|_| deadline("quote_clock"))?
        .map_err(|error| store_failure("quote_clock", error))?;
        let prepare_deadline = time::Duration::try_from(self.prepare_ttl)
            .ok()
            .and_then(|ttl| accepted_at.checked_add(ttl))
            .ok_or_else(|| {
                diagnose("quote_clock", PrepareMarketplaceError::Unavailable);
                PrepareMarketplaceError::Unavailable
            })?;
        remaining_at(started, self.request_deadline, "prepare_store")?;
        // Do not cancel a PostgreSQL mutation at the HTTP deadline: COMMIT may
        // otherwise win while this request reports timeout. Await one factual
        // commit/rollback result, then report a late successful commit as timeout;
        // its exact retry will replay the committed result.
        let result = self
            .store
            .prepare(MarketplacePreparationInput {
                creator: &request.creator,
                reader: &request.reader,
                reference: &request.reference,
                operation_id: &request.operation_id,
                request_binding: &request_binding,
                amount: request.amount,
                asset: request.asset,
                payment_window_seconds: request.payment_window_seconds,
                prepare_ttl_seconds: self.prepare_ttl.as_secs(),
                prepare_deadline: Some(prepare_deadline),
                payloads: &payloads,
            })
            .await
            .map_err(|error| store_failure("prepare_store", error))?;
        if started.elapsed() >= self.request_deadline {
            return Err(deadline("prepare_store"));
        }
        Ok(result)
    }
}

type MarketplaceOperationLock = tokio::sync::Mutex<()>;

const MAX_RFC3339_PROPOSAL_EXPIRES_AT: &str = "9999-12-31T23:59:59.999999998Z";
const MAX_RFC3339_PAYMENT_DEADLINE: &str = "9999-12-31T23:59:59.999999999Z";

fn marketplace_operation_lock(
    creator: &CreatorPubky,
    operation_id: &str,
) -> Arc<MarketplaceOperationLock> {
    type OperationKey = (String, String);
    static LOCKS: OnceLock<StdMutex<HashMap<OperationKey, Weak<MarketplaceOperationLock>>>> =
        OnceLock::new();
    let registry = LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let key = (creator.to_string(), operation_id.to_owned());
    let mut registry = registry
        .lock()
        .expect("Marketplace operation lock registry is not poisoned");
    registry.retain(|_, lock| lock.strong_count() != 0);
    if let Some(lock) = registry.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(MarketplaceOperationLock::new(()));
    registry.insert(key, Arc::downgrade(&lock));
    lock
}

struct ReplayOnlyPayloads;

impl MarketplacePreparationPayloadFactory for ReplayOnlyPayloads {
    fn for_child_index(
        &self,
        _child_index: i64,
    ) -> Result<MarketplacePreparationPayloads, PersistenceError> {
        Err(PersistenceError::CorruptOrMissing)
    }
}

struct MarketplacePayloads<'a> {
    reader: &'a ReaderPubky,
    reference: &'a str,
    terms: &'a MarketplaceTerms,
    rates: Vec<ConversionRate>,
    description: Option<&'a str>,
    app_id: &'a PaykitAppId,
    bitcoin_network: &'a BitcoinNetwork,
    bitcoin: Option<BitcoinAccount>,
    bitcoin_account_generation: Option<i64>,
    usdt: Option<UsdtAddress>,
}

impl MarketplacePreparationPayloadFactory for MarketplacePayloads<'_> {
    fn expected_bitcoin_account_generation(&self) -> Option<i64> {
        self.bitcoin_account_generation
    }

    fn for_child_index(
        &self,
        child_index: i64,
    ) -> Result<MarketplacePreparationPayloads, PersistenceError> {
        let mut endpoints = HashMap::new();
        if let Some(bitcoin) = &self.bitcoin {
            let address = derive_bip84_p2wpkh_address(
                &bitcoin.xpub,
                bitcoin.account_index,
                self.bitcoin_network,
                child_index,
            )
            .map_err(|_| PersistenceError::InvalidInput)?;
            endpoints.insert(
                PaymentEndpointIdentifier::new(endpoint_identifier(self.bitcoin_network))
                    .map_err(|_| PersistenceError::InvalidInput)?,
                PaymentEndpointPayload::new(serde_json::json!({"value": address}).to_string()),
            );
        }
        if let Some(address) = &self.usdt {
            endpoints.insert(
                PaymentEndpointIdentifier::new(USDT_ENDPOINT)
                    .map_err(|_| PersistenceError::InvalidInput)?,
                PaymentEndpointPayload::new(address.endpoint().to_string()),
            );
        }
        let mut identifiers: Vec<_> = endpoints.keys().cloned().collect();
        identifiers.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let asset = self.terms.asset();
        let mut terms = PaymentRequestTerms::builder(
            PaymentAmount::new(
                asset.decimal_amount(self.terms.amount()),
                asset.as_str().to_ascii_lowercase(),
            )
            .map_err(|_| PersistenceError::InvalidInput)?,
            PaymentReference::new(self.reference.to_owned())
                .map_err(|_| PersistenceError::InvalidInput)?,
            identifiers,
        )
        .required_app_id(Some(self.app_id.clone()))
        .payment_endpoints(Some(endpoints))
        .conversion((!self.rates.is_empty()).then(|| PaymentConversion::Fixed {
            rates: self.rates.clone(),
        }));
        if let Some(description) = self.description {
            terms = terms.metadata(serde_json::Map::from_iter([(
                "note".into(),
                serde_json::Value::String(description.to_owned()),
            )]));
        }
        let terms = terms.build().map_err(|_| PersistenceError::InvalidInput)?;
        let intent =
            DeliveryIntentV1::payment_request(self.reader.to_string(), self.app_id.clone(), &terms)
                .map_err(|_| PersistenceError::InvalidInput)?;
        // Activation owns real deadline selection. Check its largest possible RFC 3339
        // shape now so no prepared invoice can later fail only because deadlines grow
        // the outbound Payment Request past the Noise frame.
        let mut final_shape = intent.clone();
        final_shape
            .set_deadlines(
                MAX_RFC3339_PROPOSAL_EXPIRES_AT.into(),
                MAX_RFC3339_PAYMENT_DEADLINE.into(),
            )
            .map_err(|_| PersistenceError::InvalidInput)?;
        Ok(MarketplacePreparationPayloads {
            payment_request_intent: intent,
        })
    }
}

impl PrepareMarketplaceService {
    /// Pure checks that need no seller, reader or feed read.
    fn validate_request(
        &self,
        request: &PrepareMarketplaceRequest,
    ) -> Result<(), PrepareMarketplaceError> {
        let reference = uuid::Uuid::parse_str(&request.reference)
            .map_err(|_| PrepareMarketplaceError::InvalidRequest)?;
        if request.operation_id.is_empty()
            || request.payment_window_seconds == 0
            || reference.get_version_num() != 4
            || reference.get_variant() != uuid::Variant::RFC4122
            || reference.hyphenated().to_string() != request.reference
        {
            return Err(PrepareMarketplaceError::InvalidRequest);
        }
        if request.description.as_deref().is_some_and(|description| {
            description.trim().is_empty()
                || description.chars().count() > 140
                || description
                    .chars()
                    .any(|character| character.is_control() || is_direction_control(character))
        }) {
            return Err(PrepareMarketplaceError::InvalidRequest);
        }
        PaymentReference::new(request.reference.clone())
            .map_err(|_| PrepareMarketplaceError::InvalidRequest)?;
        if request.payment_window_seconds > self.payment_window_cap.as_secs() {
            return Err(PrepareMarketplaceError::PaymentWindowExceedsCap);
        }
        Ok(())
    }
}

/// A present filter must be non-empty and unique; it is kept in canonical order.
fn normalized_filter(
    filter: Option<&[AcceptedAsset]>,
) -> Result<Option<Vec<AcceptedAsset>>, PrepareMarketplaceError> {
    let Some(filter) = filter else {
        return Ok(None);
    };
    let mut set = filter.to_vec();
    set.sort();
    if set.is_empty() || set.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PrepareMarketplaceError::InvalidRequest);
    }
    Ok(Some(set))
}

/// Why nothing could be offered: the deployment cannot do the only asset asked for,
/// or the seller has not set up any asset the request allows. The refusal names only
/// rails this deployment could offer.
fn refusal_without_rails(
    filter: Option<&[AcceptedAsset]>,
    usdt_enabled: bool,
) -> PrepareMarketplaceError {
    use AcceptedAsset::{Btc, Usdt};
    match filter {
        None => PrepareMarketplaceError::SellerSetupPending(MissingSellerRails::Bitcoin),
        Some([Usdt]) if !usdt_enabled => PrepareMarketplaceError::AssetUnsupported,
        Some(set) => PrepareMarketplaceError::SellerSetupPending(
            match (set.contains(&Btc), set.contains(&Usdt) && usdt_enabled) {
                (true, true) => MissingSellerRails::BitcoinAndUsdt,
                (false, true) => MissingSellerRails::Usdt,
                _ => MissingSellerRails::Bitcoin,
            },
        ),
    }
}

fn request_binding(
    request: &PrepareMarketplaceRequest,
    filter: Option<&[AcceptedAsset]>,
) -> Result<Vec<u8>, PrepareMarketplaceError> {
    let mut binding = serde_json::json!({
        "amount": request.amount.to_string(),
        "asset": request.asset.as_str(),
        "creator": request.creator.to_string(),
        "operation_id": request.operation_id,
        "payment_window_seconds": request.payment_window_seconds,
        "reader": request.reader.to_string(),
        "reference": request.reference,
    });
    let fields = binding
        .as_object_mut()
        .expect("static request binding is an object");
    if let Some(filter) = filter {
        fields.insert(
            "accepted_assets".into(),
            filter.iter().map(|asset| asset.as_str()).collect(),
        );
    }
    if let Some(description) = &request.description {
        fields.insert(
            "description".into(),
            serde_json::Value::String(description.clone()),
        );
    }
    serde_json_canonicalizer::to_vec(&binding).map_err(|_| PrepareMarketplaceError::InvalidRequest)
}

fn is_direction_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn endpoint_identifier(network: &BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Mainnet => "btc-bitcoin-p2wpkh",
        BitcoinNetwork::Testnet => "btc-testnet-p2wpkh",
        BitcoinNetwork::Signet => "btc-signet-p2wpkh",
        BitcoinNetwork::Regtest => "btc-regtest-p2wpkh",
    }
}

fn registry_failure(stage: &'static str, error: RegistryDiscoveryError) -> PrepareMarketplaceError {
    let mapped = match error {
        RegistryDiscoveryError::InvalidRequest => PrepareMarketplaceError::InvalidRequest,
        RegistryDiscoveryError::Unavailable => PrepareMarketplaceError::ReaderRegistryUnavailable,
        RegistryDiscoveryError::Malformed => PrepareMarketplaceError::ReaderRegistryMalformed,
    };
    diagnose(stage, mapped);
    mapped
}

fn map_store(error: PersistenceError) -> PrepareMarketplaceError {
    match error {
        PersistenceError::Conflict => PrepareMarketplaceError::Conflict,
        PersistenceError::DeadlineElapsed => PrepareMarketplaceError::DeadlineExceeded,
        PersistenceError::InvalidInput => PrepareMarketplaceError::InvalidRequest,
        PersistenceError::DeploymentMismatch
        | PersistenceError::CorruptOrMissing
        | PersistenceError::ReauthenticationMismatch
        | PersistenceError::Unavailable => PrepareMarketplaceError::Unavailable,
    }
}

fn store_failure(stage: &'static str, error: PersistenceError) -> PrepareMarketplaceError {
    crate::diagnostics::failure("marketplace_prepare", stage, error.diagnostic_label());
    map_store(error)
}

fn remaining_at(
    started: Instant,
    request_deadline: Duration,
    stage: &'static str,
) -> Result<Duration, PrepareMarketplaceError> {
    let remaining = request_deadline
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| deadline(stage))?;
    Ok(remaining)
}

fn deadline(stage: &'static str) -> PrepareMarketplaceError {
    diagnose(stage, PrepareMarketplaceError::DeadlineExceeded);
    PrepareMarketplaceError::DeadlineExceeded
}

fn diagnose(stage: &'static str, error: PrepareMarketplaceError) {
    crate::diagnostics::failure("marketplace_prepare", stage, error.diagnostic_label());
}
