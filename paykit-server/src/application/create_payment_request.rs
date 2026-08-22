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
//! pipeline unchanged.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use paykit_lib::{PaymentAmount, PaymentEndpointIdentifier, PaymentReference, PaymentRequestTerms};
use serde_json::{Map, Value};

use crate::{
    application::{
        create_invoice::{
            CreateInvoiceError, CreatorXpubProvider, DeadlineClock, DerivedNewReaderPayloads,
            InvoicePersistence, MarkerDiscovery, PaykitIntentBuilder, SessionValidationError,
            SessionValidator, SystemDeadlineClock, map_store, remaining,
        },
        reader_marker::select_reader_marker,
        semantic_intent::DeliveryIntentV1,
    },
    config::ReceiverPathPriority,
    domain::locks::{BundleId, CreatorPubky, ReaderPubky},
    persistence::{AtomicInvoiceInput, AtomicInvoiceResult, InvoicePreflight},
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
    markers: Arc<dyn MarkerDiscovery>,
    marker_priority: Vec<ReceiverPathPriority>,
    local_receiver_path: paykit_lib::PaykitReceiverPath,
    credentials: Arc<dyn CreatorXpubProvider>,
    bitcoin_network: crate::config::BitcoinNetwork,
    store: Arc<dyn InvoicePersistence>,
    intents: Arc<PaykitIntentBuilder>,
    clock: Arc<dyn DeadlineClock>,
}

impl MarketplacePaymentRequestService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: Arc<dyn SessionValidator>,
        markers: Arc<dyn MarkerDiscovery>,
        marker_priority: Vec<ReceiverPathPriority>,
        local_receiver_path: paykit_lib::PaykitReceiverPath,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<PaykitIntentBuilder>,
    ) -> Self {
        Self::with_clock(
            sessions,
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
        markers: Arc<dyn MarkerDiscovery>,
        marker_priority: Vec<ReceiverPathPriority>,
        local_receiver_path: paykit_lib::PaykitReceiverPath,
        credentials: Arc<dyn CreatorXpubProvider>,
        bitcoin_network: crate::config::BitcoinNetwork,
        store: Arc<dyn InvoicePersistence>,
        intents: Arc<PaykitIntentBuilder>,
        clock: Arc<dyn DeadlineClock>,
    ) -> Self {
        Self {
            sessions,
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
        let marker_remaining = elapsed_remaining(started, self.clock.now())?;
        let discovered =
            tokio::time::timeout(marker_remaining, self.markers.discover(&request.reader))
                .await
                .map_err(|_| CreateInvoiceError::DeadlineExceeded)??;
        let selected = select_reader_marker(discovered, &self.marker_priority)
            .ok_or(CreateInvoiceError::Unavailable)?;
        let credentials_remaining = elapsed_remaining(started, self.clock.now())?;
        let (xpub, account_index) = tokio::time::timeout(
            credentials_remaining,
            self.credentials.xpub(&request.creator),
        )
        .await
        .map_err(|_| CreateInvoiceError::DeadlineExceeded)?
        .map_err(map_store)?;
        let terms = self.payment_request_terms(&request)?;
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
                new_reader_payloads: &new_reader_payloads,
                payment_request_intent,
                required_sats: request.amount_sats,
            })
            .await
            .map_err(map_store)
    }

    fn payment_request_terms(
        &self,
        request: &MarketplacePaymentRequest,
    ) -> Result<PaymentRequestTerms, CreateInvoiceError> {
        let sats = request.amount_sats;
        let mut metadata = Map::new();
        metadata.insert(
            "order_reference".into(),
            Value::String(request.reference.to_string()),
        );
        metadata.insert("reader".into(), Value::String(request.reader.to_string()));
        Ok(PaymentRequestTerms {
            amount: PaymentAmount::new(
                format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000),
                "btc",
            )
            .map_err(|_| CreateInvoiceError::InvalidRequest)?,
            // The delivery-intent contract requires a UUIDv4 payment
            // reference. A retry never mints a second one: preflight replays
            // the stored intent before terms are rebuilt. Order correlation
            // rides in `metadata.order_reference`.
            payment_reference: PaymentReference::new(uuid::Uuid::new_v4().hyphenated().to_string())
                .map_err(|_| CreateInvoiceError::InvalidRequest)?,
            proposal_expires_at: None,
            recurrence: None,
            accepted_payment_endpoint_identifiers: vec![
                PaymentEndpointIdentifier::new(self.intents.onchain_endpoint_identifier())
                    .map_err(|_| CreateInvoiceError::InvalidRequest)?,
            ],
            metadata,
        })
    }
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
