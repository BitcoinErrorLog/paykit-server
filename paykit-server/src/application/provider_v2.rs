//! Replay-first signed provider-v2 invoice and pure persisted status services.

use std::{collections::HashMap, sync::Arc, time::Duration};

use paykit_lib::{
    ConversionRate, PaykitAppId, PaymentAmount, PaymentConversion, PaymentEndpointIdentifier,
    PaymentEndpointPayload, PaymentReference as LibPaymentReference, PaymentRequestTerms,
};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::{
    application::{
        create_invoice::{
            AppRegistryDiscovery, CreatorReceivingProvider, ReaderAuthorization,
            RegistryDiscoveryError, SessionValidationError, SessionValidator,
            derive_bip84_p2wpkh_address,
        },
        reader_registry::reader_is_capable,
        semantic_intent::DeliveryIntentV1,
    },
    config::BitcoinNetwork,
    domain::{
        locks::{BundleId, CreatorPubky, PubkyLockResource, ReaderPubky},
        provider_v2::{ProviderV2Asset, ProviderV2Payment},
    },
    persistence::{
        InvoicePayloadFactory, InvoicePayloads, InvoicePreflight, InvoiceStore, PersistenceError,
        ProviderV2AtomicInvoiceInput, ProviderV2CreateResult, ProviderV2Status,
    },
};

#[derive(Clone, Debug)]
pub struct ProviderV2CreateRequest {
    pub bundle_id: BundleId,
    pub lock_resource: PubkyLockResource,
    pub reader: ReaderPubky,
    pub payment: ProviderV2Payment,
    pub deadline: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderV2Error {
    InvalidRequest,
    Conflict,
    DeadlineElapsed,
    CreatorSessionInvalid,
    CreatorSessionUnavailable,
    ReaderSetupPending,
    ReaderNotPayable,
    ReaderRegistryUnavailable,
    ReaderRegistryMalformed,
    Unavailable,
}

pub struct ProviderV2Service {
    sessions: Arc<dyn SessionValidator>,
    registries: Arc<dyn AppRegistryDiscovery>,
    receiving: Arc<dyn CreatorReceivingProvider>,
    store: InvoiceStore,
    app_id: PaykitAppId,
    network: BitcoinNetwork,
    proposal_acceptance_window: Duration,
    usdt_enabled: bool,
    rates: Option<Arc<dyn super::invoice_pricing::ExchangeRates>>,
    conversion_payment_window: Duration,
}

impl ProviderV2Service {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: Arc<dyn SessionValidator>,
        registries: Arc<dyn AppRegistryDiscovery>,
        receiving: Arc<dyn CreatorReceivingProvider>,
        store: InvoiceStore,
        app_id: PaykitAppId,
        network: BitcoinNetwork,
        proposal_acceptance_window: Duration,
    ) -> Self {
        Self {
            sessions,
            registries,
            receiving,
            store,
            app_id,
            network,
            proposal_acceptance_window,
            usdt_enabled: false,
            rates: None,
            conversion_payment_window: Duration::from_secs(3600),
        }
    }

    pub fn with_usdt(mut self, enabled: bool) -> Self {
        self.usdt_enabled = enabled;
        self
    }

    pub fn with_exchange_rates(
        mut self,
        rates: Arc<dyn super::invoice_pricing::ExchangeRates>,
    ) -> Self {
        self.rates = Some(rates);
        self
    }

    pub fn with_conversion_payment_window(mut self, window: Duration) -> Self {
        self.conversion_payment_window = window;
        self
    }

    pub async fn create(
        &self,
        request: ProviderV2CreateRequest,
    ) -> Result<ProviderV2CreateResult, ProviderV2Error> {
        let creator = request.lock_resource.creator().clone();
        let bundle_binding = request.bundle_id.to_string().into_bytes();
        let lock_binding = request.lock_resource.to_string().into_bytes();
        let binding = canonical_binding(&request)?;
        let request_hash = *blake3::hash(&binding).as_bytes();
        match self
            .store
            .provider_v2_preflight(&creator, &bundle_binding, &request_hash)
            .await
            .map_err(map_store)?
        {
            InvoicePreflight::ExactReplay => {
                return self
                    .store
                    .provider_v2_exact_replay(&creator, &bundle_binding, &request_hash)
                    .await
                    .map_err(map_store);
            }
            InvoicePreflight::Conflict => return Err(ProviderV2Error::Conflict),
            InvoicePreflight::New => {}
        }

        self.gate(&creator, request.deadline).await?;
        self.sessions
            .validate(&creator)
            .await
            .map_err(|error| match error {
                SessionValidationError::Invalid => ProviderV2Error::CreatorSessionInvalid,
                SessionValidationError::Unavailable => ProviderV2Error::CreatorSessionUnavailable,
            })?;

        self.gate(&creator, request.deadline).await?;
        let registry = self
            .registries
            .discover(&request.reader)
            .await
            .map_err(map_registry)?
            .ok_or(ProviderV2Error::ReaderSetupPending)?;
        if !reader_is_capable(&registry) {
            return Err(ProviderV2Error::ReaderNotPayable);
        }

        self.gate(&creator, request.deadline).await?;
        match self
            .registries
            .authorization(&request.reader)
            .await
            .map_err(map_registry)?
        {
            ReaderAuthorization::Verified => {}
            ReaderAuthorization::Missing => return Err(ProviderV2Error::ReaderSetupPending),
            ReaderAuthorization::Invalid => return Err(ProviderV2Error::ReaderNotPayable),
        }

        self.gate(&creator, request.deadline).await?;
        let receiving = self
            .receiving
            .receiving(&creator)
            .await
            .map_err(map_store)?;
        let (bitcoin, usdt, rates, maximum_payment_seconds) = match request.payment.asset() {
            ProviderV2Asset::Btc => (
                Some(receiving.bitcoin.ok_or(ProviderV2Error::Unavailable)?),
                None,
                Vec::new(),
                None,
            ),
            ProviderV2Asset::Usdt => {
                if !self.usdt_enabled {
                    return Err(ProviderV2Error::InvalidRequest);
                }
                let usdt = receiving.usdt.ok_or(ProviderV2Error::Unavailable)?;
                let bitcoin = receiving.bitcoin;
                let crosses_bitcoin = bitcoin.is_some();
                let rates = if bitcoin.is_some() {
                    let price = self
                        .rates
                        .as_ref()
                        .ok_or(ProviderV2Error::Unavailable)?
                        .usd_per_btc()
                        .await
                        .map_err(|_| ProviderV2Error::Unavailable)?;
                    super::invoice_pricing::conversion_rates(
                        request.payment.asset().criterion_asset(),
                        true,
                        true,
                        Some(&price),
                    )
                    .map_err(|_| ProviderV2Error::InvalidRequest)?
                } else {
                    Vec::new()
                };
                (
                    bitcoin,
                    Some(usdt),
                    rates,
                    crosses_bitcoin.then_some(self.conversion_payment_window.as_secs()),
                )
            }
        };
        let payloads = ProviderPayloadFactory {
            reader: &request.reader,
            bundle_id: &request.bundle_id,
            payment: &request.payment,
            bitcoin,
            usdt,
            rates,
            maximum_payment_seconds,
            generation: receiving.bitcoin_account_generation,
            app_id: self.app_id.clone(),
            network: self.network.clone(),
        };
        self.store
            .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
                creator: &creator,
                reader: &request.reader,
                bundle_binding: &bundle_binding,
                lock_resource_binding: &lock_binding,
                request_hash,
                deadline: request.deadline,
                minimum_confirmations: request.payment.minimum_confirmations(),
                invoice_payloads: &payloads,
                proposal_acceptance_seconds: self.proposal_acceptance_window.as_secs(),
            })
            .await
            .map_err(map_store)
    }

    pub async fn status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<ProviderV2Status>, ProviderV2Error> {
        self.store
            .provider_v2_status(creator, bundle_id)
            .await
            .map_err(map_store)
    }

    async fn gate(
        &self,
        creator: &CreatorPubky,
        deadline: OffsetDateTime,
    ) -> Result<(), ProviderV2Error> {
        if self
            .store
            .provider_v2_deadline_gate(creator, deadline)
            .await
            .map_err(map_store)?
        {
            Ok(())
        } else {
            Err(ProviderV2Error::DeadlineElapsed)
        }
    }
}

struct ProviderPayloadFactory<'a> {
    reader: &'a ReaderPubky,
    bundle_id: &'a BundleId,
    payment: &'a ProviderV2Payment,
    bitcoin: Option<crate::domain::receiving::BitcoinAccount>,
    usdt: Option<crate::domain::receiving::UsdtAddress>,
    rates: Vec<ConversionRate>,
    maximum_payment_seconds: Option<u64>,
    generation: i64,
    app_id: PaykitAppId,
    network: BitcoinNetwork,
}

impl InvoicePayloadFactory for ProviderPayloadFactory<'_> {
    fn expected_bitcoin_account_generation(&self) -> Option<i64> {
        self.bitcoin.as_ref().map(|_| self.generation)
    }

    fn maximum_payment_seconds(&self) -> Option<u64> {
        self.maximum_payment_seconds
    }

    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let mut endpoints = HashMap::new();
        if let Some(account) = &self.bitcoin {
            let address = derive_bip84_p2wpkh_address(
                &account.xpub,
                account.account_index,
                &self.network,
                child_index,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
            endpoints.insert(
                PaymentEndpointIdentifier::new(match self.network {
                    BitcoinNetwork::Mainnet => "btc-bitcoin-p2wpkh",
                    BitcoinNetwork::Testnet => "btc-testnet-p2wpkh",
                    BitcoinNetwork::Signet => "btc-signet-p2wpkh",
                    BitcoinNetwork::Regtest => "btc-regtest-p2wpkh",
                })
                .map_err(|_| PersistenceError::InvalidInput)?,
                PaymentEndpointPayload::new(serde_json::json!({"value":address}).to_string()),
            );
        }
        if let Some(address) = &self.usdt {
            endpoints.insert(
                PaymentEndpointIdentifier::new(crate::domain::receiving::USDT_ENDPOINT)
                    .map_err(|_| PersistenceError::InvalidInput)?,
                PaymentEndpointPayload::new(address.endpoint().to_string()),
            );
        }
        let mut endpoint_identifiers: Vec<_> = endpoints.keys().cloned().collect();
        endpoint_identifiers.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let mut metadata = Map::new();
        metadata.insert(
            "bundle_id".into(),
            Value::String(self.bundle_id.to_string()),
        );
        let terms = PaymentRequestTerms::builder(
            paykit_amount(self.payment)?,
            LibPaymentReference::new(uuid::Uuid::new_v4().hyphenated().to_string())
                .map_err(|_| PersistenceError::InvalidInput)?,
            endpoint_identifiers,
        )
        .required_app_id(Some(self.app_id.clone()))
        .payment_endpoints(Some(endpoints))
        .conversion((!self.rates.is_empty()).then(|| PaymentConversion::Fixed {
            rates: self.rates.clone(),
        }))
        .metadata(metadata)
        .build()
        .map_err(|_| PersistenceError::InvalidInput)?;
        let intent =
            DeliveryIntentV1::payment_request(self.reader.to_string(), self.app_id.clone(), &terms)
                .map_err(|_| PersistenceError::InvalidInput)?;
        Ok(InvoicePayloads {
            payment_request_intent: intent,
        })
    }
}

fn paykit_amount(payment: &ProviderV2Payment) -> Result<PaymentAmount, PersistenceError> {
    PaymentAmount::new(
        payment
            .asset()
            .criterion_asset()
            .decimal_amount(payment.amount_units()),
        payment.asset().as_str().to_ascii_lowercase(),
    )
    .map_err(|_| PersistenceError::InvalidInput)
}

fn canonical_binding(request: &ProviderV2CreateRequest) -> Result<Vec<u8>, ProviderV2Error> {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": request.bundle_id.to_string(),
        "lock_resource": request.lock_resource.to_string(),
        "reader": request.reader.to_string(),
        "payment": {
            "recipient_pubky": request.lock_resource.creator().to_string(),
            "amount": request.payment.amount_lexeme(),
            "asset": request.payment.asset().as_str(),
            "minimum_confirmations": request.payment.minimum_confirmations(),
        },
        "deadline": request.deadline.format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| ProviderV2Error::InvalidRequest)?,
    }))
    .map_err(|_| ProviderV2Error::InvalidRequest)
}

#[cfg(feature = "test-utils")]
pub fn provider_v2_request_hash(
    request: &ProviderV2CreateRequest,
) -> Result<[u8; 32], ProviderV2Error> {
    Ok(*blake3::hash(&canonical_binding(request)?).as_bytes())
}

fn map_registry(error: RegistryDiscoveryError) -> ProviderV2Error {
    match error {
        RegistryDiscoveryError::InvalidRequest => ProviderV2Error::InvalidRequest,
        RegistryDiscoveryError::Unavailable => ProviderV2Error::ReaderRegistryUnavailable,
        RegistryDiscoveryError::Malformed => ProviderV2Error::ReaderRegistryMalformed,
    }
}

fn map_store(error: PersistenceError) -> ProviderV2Error {
    match error {
        PersistenceError::Conflict => ProviderV2Error::Conflict,
        PersistenceError::DeadlineElapsed => ProviderV2Error::DeadlineElapsed,
        PersistenceError::InvalidInput => ProviderV2Error::InvalidRequest,
        _ => ProviderV2Error::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        locks::{parse_bundle_id, parse_creator, parse_reader},
        receiving::UsdtAddress,
    };

    #[test]
    fn integer_base_unit_wire_amount_becomes_exact_payment_terms_amount() {
        let creator =
            parse_creator("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap();
        let btc = ProviderV2Payment::parse(&creator.to_string(), "000000001", "BTC", 0, &creator)
            .unwrap();
        assert_eq!(
            paykit_amount(&btc).unwrap(),
            PaymentAmount::new("0.00000001", "btc").unwrap()
        );

        let usdt =
            ProviderV2Payment::parse(&creator.to_string(), "5000001", "USDT", 0, &creator).unwrap();
        assert_eq!(
            paykit_amount(&usdt).unwrap(),
            PaymentAmount::new("5.000001", "usdt").unwrap()
        );
    }

    #[test]
    fn usdt_terms_use_canonical_direct_endpoint_without_inventing_bitcoin() {
        let creator =
            parse_creator("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap();
        let payment =
            ProviderV2Payment::parse(&creator.to_string(), "5000001", "USDT", 1, &creator).unwrap();
        let reader = parse_reader(&creator.to_string()).unwrap();
        let bundle_id = parse_bundle_id("000G40R40M30E209185GR38E1W").unwrap();
        let factory = ProviderPayloadFactory {
            reader: &reader,
            bundle_id: &bundle_id,
            payment: &payment,
            bitcoin: None,
            usdt: Some(
                UsdtAddress::try_from("0x1111111111111111111111111111111111111111".to_owned())
                    .unwrap(),
            ),
            rates: Vec::new(),
            maximum_payment_seconds: None,
            generation: 0,
            app_id: PaykitAppId::new("paykit-server").unwrap(),
            network: BitcoinNetwork::Regtest,
        };

        let payload = factory.for_child_index(0).unwrap();
        let terms = payload.payment_request_intent.terms().unwrap();
        assert_eq!(terms.amount, "5.000001");
        assert_eq!(terms.asset, "usdt");
        let encoded = serde_json::to_string(&terms).unwrap();
        assert!(encoded.contains(crate::domain::receiving::USDT_ENDPOINT));
        assert!(encoded.contains("0x1111111111111111111111111111111111111111"));
        assert!(!encoded.contains("btc-bitcoin-p2wpkh"));
        assert!(terms.rates.is_empty());
    }

    #[test]
    fn usdt_terms_can_offer_independent_bitcoin_settlement_with_fixed_rate() {
        let creator =
            parse_creator("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap();
        let payment =
            ProviderV2Payment::parse(&creator.to_string(), "5000001", "USDT", 1, &creator).unwrap();
        let reader = parse_reader(&creator.to_string()).unwrap();
        let bundle_id = parse_bundle_id("000G40R40M30E209185GR38E1W").unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let master =
            bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &[42; 32]).unwrap();
        let path: bitcoin::bip32::DerivationPath = "m/84'/1'/0'".parse().unwrap();
        let account = master.derive_priv(&secp, &path).unwrap();
        let xpub = bitcoin::bip32::Xpub::from_priv(&secp, &account).to_string();
        let factory = ProviderPayloadFactory {
            reader: &reader,
            bundle_id: &bundle_id,
            payment: &payment,
            bitcoin: Some(crate::domain::receiving::BitcoinAccount {
                xpub: xpub.into(),
                account_index: 0,
            }),
            usdt: Some(
                UsdtAddress::try_from("0x1111111111111111111111111111111111111111".to_owned())
                    .unwrap(),
            ),
            rates: vec![ConversionRate {
                asset: "btc".into(),
                value: "0.00001234".into(),
            }],
            maximum_payment_seconds: Some(3600),
            generation: 0,
            app_id: PaykitAppId::new("paykit-server").unwrap(),
            network: BitcoinNetwork::Regtest,
        };

        let payload = factory.for_child_index(7).unwrap();
        let terms = payload.payment_request_intent.terms().unwrap();
        assert_eq!(terms.amount, "5.000001");
        assert_eq!(terms.asset, "usdt");
        assert_eq!(terms.rates.len(), 1);
        assert_eq!(factory.maximum_payment_seconds(), Some(3600));
        let encoded = serde_json::to_string(&terms).unwrap();
        assert!(encoded.contains(crate::domain::receiving::USDT_ENDPOINT));
        assert!(encoded.contains("btc-regtest-p2wpkh"));
    }
}
