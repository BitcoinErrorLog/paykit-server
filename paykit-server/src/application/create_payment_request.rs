//! Marketplace payment requests: lock-free invoice creation for physical
//! orders.
//!
//! The marketplace transaction service is a signed trusted caller (its key is
//! configured next to the Lock Server's). Unlike the Locks path, the
//! settlement terms come from the signed request itself — the marketplace is
//! the pricing authority for its orders — so no ContentLock is fetched or
//! validated. Everything downstream (per-reader address derivation, atomic
//! persistence, outbox delivery to the reader's wallet, Electrum observation,
//! and the status lookup keyed by `(creator, reference)`) reuses the invoice
//! pipeline unchanged. The reader's receiving capability is checked against
//! their shared Paykit app registry — the identity-wide replacement for the
//! receiver markers this service used to discover.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestTerms,
};
use serde_json::{Map, Value};

use crate::{
    application::{
        create_invoice::{
            AppRegistryDiscovery, CreateInvoiceError, CreatorXpubProvider, DeadlineClock,
            InvoicePersistence, PaykitIntentBuilder, SessionValidationError, SessionValidator,
            SystemDeadlineClock, derive_bip84_p2wpkh_address, map_store, remaining,
        },
        reader_registry::reader_is_capable,
        semantic_intent::DeliveryIntentV1,
    },
    config::BitcoinNetwork,
    domain::locks::{BundleId, CreatorPubky, ReaderPubky},
    persistence::{
        AtomicInvoiceInput, AtomicInvoiceResult, InvoicePayloadFactory, InvoicePayloads,
        InvoicePreflight, PersistenceError,
    },
};

/// One marketplace order's payment request. `reference` is the marketplace's
/// creator-scoped idempotency key (Crockford base32 of the order UUID) and
/// doubles as the status-lookup bundle identifier.
#[derive(Clone, Debug)]
pub struct MarketplacePaymentRequest {
    pub creator: CreatorPubky,
    pub reader: ReaderPubky,
    pub reference: BundleId,
    pub amount_sats: u64,
}

pub struct MarketplacePaymentRequestService {
    sessions: Arc<dyn SessionValidator>,
    registries: Arc<dyn AppRegistryDiscovery>,
    credentials: Arc<dyn CreatorXpubProvider>,
    bitcoin_network: BitcoinNetwork,
    store: Arc<dyn InvoicePersistence>,
    intents: Arc<PaykitIntentBuilder>,
    clock: Arc<dyn DeadlineClock>,
}

impl MarketplacePaymentRequestService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: Arc<dyn SessionValidator>,
        registries: Arc<dyn AppRegistryDiscovery>,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<PaykitIntentBuilder>,
    ) -> Self {
        Self::with_clock(
            sessions,
            registries,
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
        registries: Arc<dyn AppRegistryDiscovery>,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<PaykitIntentBuilder>,
        clock: Arc<dyn DeadlineClock>,
    ) -> Self {
        Self {
            sessions,
            registries,
            credentials,
            bitcoin_network,
            store,
            intents,
            clock,
        }
    }

    pub async fn create(
        &self,
        request: MarketplacePaymentRequest,
    ) -> Result<AtomicInvoiceResult, CreateInvoiceError> {
        if request.amount_sats == 0 {
            return Err(CreateInvoiceError::InvalidRequest);
        }
        let started = self.clock.now();
        let bundle_binding = request.reference.to_string().into_bytes();
        let payment_request_binding = request_binding(&request)?;
        let preflight_remaining = elapsed_remaining(started, self.clock.now())?;
        match tokio::time::timeout(
            preflight_remaining,
            self.store
                .preflight(&request.creator, &bundle_binding, &payment_request_binding),
        )
        .await
        .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
        .map_err(map_store)?
        {
            InvoicePreflight::ExactReplay => {
                let replay_remaining = elapsed_remaining(started, self.clock.now())?;
                return tokio::time::timeout(
                    replay_remaining,
                    self.store.exact_replay(
                        &request.creator,
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
        let session_remaining = elapsed_remaining(started, self.clock.now())?;
        tokio::time::timeout(session_remaining, self.sessions.validate(&request.creator))
            .await
            .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
            .map_err(|error| match error {
                SessionValidationError::Invalid => CreateInvoiceError::CreatorSessionInvalid,
                SessionValidationError::Unavailable => {
                    CreateInvoiceError::CreatorSessionUnavailable
                }
            })?;
        // As in the invoice path: a reader without a capable shared Paykit
        // registry cannot receive the payment request, so the order must not
        // allocate an invoice for them.
        let registry_remaining = elapsed_remaining(started, self.clock.now())?;
        let discovered = tokio::time::timeout(
            registry_remaining,
            self.registries.discover(&request.reader),
        )
        .await
        .map_err(|_| CreateInvoiceError::DeadlineExceeded)??;
        if !discovered.as_ref().is_some_and(reader_is_capable) {
            return Err(CreateInvoiceError::Unavailable);
        }
        let credentials_remaining = elapsed_remaining(started, self.clock.now())?;
        let (xpub, account_index) = tokio::time::timeout(
            credentials_remaining,
            self.credentials.xpub(&request.creator),
        )
        .await
        .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
        .map_err(map_store)?;
        let payloads = MarketplaceInvoicePayloads {
            intents: self.intents.clone(),
            xpub,
            account_index,
            network: self.bitcoin_network.clone(),
            request: &request,
        };
        elapsed_remaining(started, self.clock.now())?;
        // As in the Locks invoice path: once PostgreSQL mutation starts it is
        // awaited to a factual commit/rollback result rather than cancelled at
        // the HTTP deadline.
        self.store
            .create_atomic(AtomicInvoiceInput {
                creator: &request.creator,
                reader: &request.reader,
                bundle_binding: &bundle_binding,
                payment_request_binding: &payment_request_binding,
                invoice_payloads: &payloads,
                required_sats: request.amount_sats,
            })
            .await
            .map_err(map_store)
    }
}

/// Builds the marketplace payment request only after the transaction has
/// selected the permanent child index, so the derived invoice address binds
/// into the payment endpoints before either row is persisted.
struct MarketplaceInvoicePayloads<'a> {
    intents: Arc<PaykitIntentBuilder>,
    xpub: String,
    account_index: u32,
    network: BitcoinNetwork,
    request: &'a MarketplacePaymentRequest,
}

impl InvoicePayloadFactory for MarketplaceInvoicePayloads<'_> {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let address =
            derive_bip84_p2wpkh_address(&self.xpub, self.account_index, &self.network, child_index)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let terms = payment_request_terms(
            self.request,
            self.intents.onchain_endpoint_identifier(),
            &address,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment_request_intent = DeliveryIntentV1::payment_request(
            self.request.reader.to_string(),
            PaykitAppId::new(crate::config::PAYKIT_APP_ID).expect("static app id"),
            &terms,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        Ok(InvoicePayloads {
            payment_request_intent,
            bitcoin_address: address,
        })
    }
}

fn payment_request_terms(
    request: &MarketplacePaymentRequest,
    onchain_endpoint_identifier: &str,
    address: &str,
) -> Result<PaymentRequestTerms, CreateInvoiceError> {
    if address.is_empty() {
        return Err(CreateInvoiceError::InvalidRequest);
    }
    let identifier = PaymentEndpointIdentifier::new(onchain_endpoint_identifier)
        .map_err(|_| CreateInvoiceError::InvalidRequest)?;
    // Payment-endpoint-identifier spec section 7: the interoperable payload
    // convention is a JSON object with the receiving handle under "value".
    let payload = serde_json::to_string(&serde_json::json!({ "value": address }))
        .map_err(|_| CreateInvoiceError::InvalidRequest)?;
    let sats = request.amount_sats;
    let mut metadata = Map::new();
    metadata.insert(
        "order_reference".into(),
        Value::String(request.reference.to_string()),
    );
    metadata.insert("reader".into(), Value::String(request.reader.to_string()));
    PaymentRequestTerms::builder(
        PaymentAmount::new(
            format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000),
            "btc",
        )
        .map_err(|_| CreateInvoiceError::InvalidRequest)?,
        // The delivery-intent contract requires a UUIDv4 payment reference. A
        // retry never mints a second one: preflight replays the stored intent
        // before terms are rebuilt. Order correlation rides in
        // `metadata.order_reference`.
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

fn elapsed_remaining(start: Instant, now: Instant) -> Result<Duration, CreateInvoiceError> {
    remaining(start, now)
}

fn request_binding(request: &MarketplacePaymentRequest) -> Result<Vec<u8>, CreateInvoiceError> {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "amount_sats": request.amount_sats,
        "creator": request.creator.to_string(),
        "reader": request.reader.to_string(),
        "reference": request.reference.to_string(),
    }))
    .map_err(|_| CreateInvoiceError::InvalidRequest)
}
