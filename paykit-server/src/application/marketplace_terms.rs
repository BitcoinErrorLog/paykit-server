//! Marketplace payment terms shared by prepare, activate and status.
//!
//! One request carries a denomination (`BTC`, `USD` or `USDT`), an exact amount in
//! that denomination's base units and the set of assets the buyer may pay with.
//! Amount, asset and rate formats are the ones Locks invoices already use.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    application::{semantic_intent::DeliveryIntentV1, setup_status::AcceptedAsset},
    domain::invoice::{CriterionAmount, CriterionAsset},
    persistence::{InvoicePaymentRecordV1, PersistenceError},
};

/// Closed failure for malformed Marketplace terms.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("marketplace payment terms are invalid")]
pub struct MarketplaceTermsError;

/// Denomination, exact amount and accepted payment assets of one Marketplace request.
///
/// Accepted assets are a non-empty, unique set kept in canonical order so the same
/// set always produces the same request binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplaceTerms {
    amount: u64,
    asset: CriterionAsset,
    accepted_assets: Vec<AcceptedAsset>,
}

impl MarketplaceTerms {
    pub fn new(
        amount: u64,
        asset: CriterionAsset,
        accepted_assets: impl IntoIterator<Item = AcceptedAsset>,
    ) -> Result<Self, MarketplaceTermsError> {
        let mut accepted_assets: Vec<_> = accepted_assets.into_iter().collect();
        accepted_assets.sort();
        if amount == 0
            || accepted_assets.is_empty()
            || accepted_assets.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(MarketplaceTermsError);
        }
        Ok(Self {
            amount,
            asset,
            accepted_assets,
        })
    }

    /// The terms a stored intent actually offers: the accepted assets are exactly the
    /// rails it carries endpoints for.
    pub fn from_intent(
        intent: &DeliveryIntentV1,
        amount: u64,
        asset: CriterionAsset,
    ) -> Result<Self, PersistenceError> {
        let record = InvoicePaymentRecordV1::from_intent(0, intent)?;
        let accepted = [
            record.has_bitcoin().then_some(AcceptedAsset::Btc),
            record.has_usdt().then_some(AcceptedAsset::Usdt),
        ]
        .into_iter()
        .flatten();
        Self::new(amount, asset, accepted).map_err(|_| PersistenceError::InvalidInput)
    }

    /// Parses a Locks-style base-unit integer amount string.
    pub fn parse_amount(value: &str) -> Result<u64, MarketplaceTermsError> {
        CriterionAmount::parse(value)
            .map(|amount| amount.units())
            .map_err(|_| MarketplaceTermsError)
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub fn asset(&self) -> CriterionAsset {
        self.asset
    }

    pub fn accepted_assets(&self) -> &[AcceptedAsset] {
        &self.accepted_assets
    }

    pub fn accepts(&self, asset: AcceptedAsset) -> bool {
        self.accepted_assets.contains(&asset)
    }

    /// True when an accepted asset needs the BTC/USD feed: any pairing that crosses
    /// BTC and a dollar-denominated asset. USD and USDT are fixed parity.
    pub fn crosses_bitcoin_rate(&self) -> bool {
        (self.asset == CriterionAsset::Btc && self.accepts(AcceptedAsset::Usdt))
            || (self.asset != CriterionAsset::Btc && self.accepts(AcceptedAsset::Btc))
    }
}

/// Exact payable amount per accepted asset and the rates they were quoted at.
///
/// Amounts are in each payment asset's base units, already rounded up to that
/// asset's unit. Rates are payment-asset units per one requested-asset unit, as
/// published to the payer in the Payment Request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketplaceQuote {
    payment_amounts: Vec<(AcceptedAsset, u64)>,
    rates: Vec<(AcceptedAsset, String)>,
}

impl MarketplaceQuote {
    pub fn new(
        payment_amounts: Vec<(AcceptedAsset, u64)>,
        rates: Vec<(AcceptedAsset, String)>,
    ) -> Self {
        Self {
            payment_amounts,
            rates,
        }
    }

    /// Derives and validates the quote from a stored Payment Request intent.
    ///
    /// The intent must name exactly the accepted assets' endpoints and carry exactly
    /// the fixed rates those assets need; nothing the request did not ask for.
    pub fn from_intent(
        intent: &DeliveryIntentV1,
        terms: &MarketplaceTerms,
    ) -> Result<Self, PersistenceError> {
        let intent_terms = intent.terms().map_err(|_| PersistenceError::InvalidInput)?;
        if intent_terms.asset != terms.asset().as_str().to_ascii_lowercase()
            || intent_terms.amount != terms.asset().decimal_amount(terms.amount())
        {
            return Err(PersistenceError::InvalidInput);
        }
        let record = InvoicePaymentRecordV1::from_intent(0, intent)?;
        if record.has_bitcoin() != terms.accepts(AcceptedAsset::Btc)
            || record.has_usdt() != terms.accepts(AcceptedAsset::Usdt)
        {
            return Err(PersistenceError::InvalidInput);
        }
        let mut payment_amounts = Vec::new();
        let mut rates = Vec::new();
        for &asset in terms.accepted_assets() {
            payment_amounts.push((
                asset,
                match asset {
                    AcceptedAsset::Btc => record.bitcoin_required_amount()?,
                    AcceptedAsset::Usdt => record.usdt_required_amount()?,
                },
            ));
            let name = asset.criterion_asset().as_str().to_ascii_lowercase();
            let mut matching = intent_terms.rates.iter().filter(|rate| rate.asset == name);
            let rate = matching.next();
            if matching.next().is_some()
                || rate.is_some() != (asset.criterion_asset() != terms.asset())
            {
                return Err(PersistenceError::InvalidInput);
            }
            if let Some(rate) = rate {
                rates.push((asset, rate.value.clone()));
            }
        }
        if intent_terms.rates.len() != rates.len() {
            return Err(PersistenceError::InvalidInput);
        }
        Ok(Self {
            payment_amounts,
            rates,
        })
    }

    pub fn payment_amounts(&self) -> &[(AcceptedAsset, u64)] {
        &self.payment_amounts
    }

    pub fn rates(&self) -> &[(AcceptedAsset, String)] {
        &self.rates
    }

    pub fn payment_amount(&self, asset: AcceptedAsset) -> Option<u64> {
        self.payment_amounts
            .iter()
            .find(|(candidate, _)| *candidate == asset)
            .map(|(_, amount)| *amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_are_nonempty_unique_and_canonically_ordered() {
        let terms = MarketplaceTerms::new(
            500,
            CriterionAsset::Usd,
            [AcceptedAsset::Usdt, AcceptedAsset::Btc],
        )
        .unwrap();
        assert_eq!(
            terms.accepted_assets(),
            [AcceptedAsset::Btc, AcceptedAsset::Usdt]
        );
        assert!(MarketplaceTerms::new(500, CriterionAsset::Usd, []).is_err());
        assert!(
            MarketplaceTerms::new(
                500,
                CriterionAsset::Usd,
                [AcceptedAsset::Btc, AcceptedAsset::Btc]
            )
            .is_err()
        );
        assert!(MarketplaceTerms::new(0, CriterionAsset::Usd, [AcceptedAsset::Btc]).is_err());
    }

    #[test]
    fn bitcoin_feed_is_needed_only_when_a_conversion_crosses_bitcoin() {
        use AcceptedAsset::{Btc, Usdt};
        use CriterionAsset::{Btc as DenominatedBtc, Usd, Usdt as DenominatedUsdt};
        for (asset, accepted, crosses) in [
            (Usd, vec![Btc, Usdt], true),
            (Usd, vec![Btc], true),
            (Usd, vec![Usdt], false),
            (DenominatedBtc, vec![Btc], false),
            (DenominatedBtc, vec![Usdt], true),
            (DenominatedBtc, vec![Btc, Usdt], true),
            (DenominatedUsdt, vec![Usdt], false),
            (DenominatedUsdt, vec![Btc], true),
            (DenominatedUsdt, vec![Btc, Usdt], true),
        ] {
            assert_eq!(
                MarketplaceTerms::new(1, asset, accepted.clone())
                    .unwrap()
                    .crosses_bitcoin_rate(),
                crosses,
                "{asset:?} {accepted:?}"
            );
        }
    }

    #[test]
    fn amounts_parse_like_locks_criteria() {
        assert_eq!(MarketplaceTerms::parse_amount("2500"), Ok(2_500));
        for invalid in ["", "0", "-1", "1.5", "1e3", " 1", "18446744073709551616"] {
            assert!(
                MarketplaceTerms::parse_amount(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    use std::collections::HashMap;

    use paykit_lib::{
        ConversionRate, PaykitAppId, PaymentAmount, PaymentConversion, PaymentEndpointIdentifier,
        PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
    };

    const BTC_ADDRESS: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const USDT_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

    fn intent(
        amount: &str,
        asset: &str,
        endpoints: &[&str],
        rates: &[(&str, &str)],
    ) -> DeliveryIntentV1 {
        let app_id = PaykitAppId::new("paykit-server").unwrap();
        let payloads: HashMap<_, _> = endpoints
            .iter()
            .map(|name| {
                let payload = if *name == "usdt-arbitrum-address" {
                    crate::domain::receiving::UsdtAddress::try_from(USDT_ADDRESS.to_owned())
                        .unwrap()
                        .endpoint()
                        .to_string()
                } else {
                    serde_json::json!({"value": BTC_ADDRESS}).to_string()
                };
                (
                    PaymentEndpointIdentifier::new(*name).unwrap(),
                    PaymentEndpointPayload::new(payload),
                )
            })
            .collect();
        let mut identifiers: Vec<_> = payloads.keys().cloned().collect();
        identifiers.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let terms = PaymentRequestTerms::builder(
            PaymentAmount::new(amount, asset).unwrap(),
            PaymentReference::new("7cceb26d-9042-4ea6-bfcb-01bbd778d76e").unwrap(),
            identifiers,
        )
        .required_app_id(Some(app_id.clone()))
        .payment_endpoints(Some(payloads))
        .conversion((!rates.is_empty()).then(|| {
            PaymentConversion::Fixed {
                rates: rates
                    .iter()
                    .map(|(asset, value)| ConversionRate {
                        asset: (*asset).into(),
                        value: (*value).into(),
                    })
                    .collect(),
            }
        }))
        .build()
        .unwrap();
        DeliveryIntentV1::payment_request(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy".into(),
            app_id,
            &terms,
        )
        .unwrap()
    }

    #[test]
    fn quote_reads_exact_payable_amounts_and_rates_from_the_intent() {
        let terms = MarketplaceTerms::new(
            500,
            CriterionAsset::Usd,
            [AcceptedAsset::Btc, AcceptedAsset::Usdt],
        )
        .unwrap();
        let quote = MarketplaceQuote::from_intent(
            &intent(
                "5.00",
                "usd",
                &["btc-bitcoin-p2wpkh", "usdt-arbitrum-address"],
                &[("btc", "0.000012345679012346"), ("usdt", "1")],
            ),
            &terms,
        )
        .unwrap();
        assert_eq!(
            quote.payment_amounts(),
            [
                (AcceptedAsset::Btc, 6_173),
                (AcceptedAsset::Usdt, 5_000_000)
            ]
        );
        assert_eq!(quote.payment_amount(AcceptedAsset::Usdt), Some(5_000_000));
        assert_eq!(quote.rates().len(), 2);
    }

    #[test]
    fn quote_refuses_anything_the_request_did_not_ask_for_or_cannot_price() {
        let usd_btc =
            MarketplaceTerms::new(500, CriterionAsset::Usd, [AcceptedAsset::Btc]).unwrap();
        let btc_rate = ("btc", "0.000012345679012346");
        for (label, intent) in [
            (
                "extra USDT endpoint",
                intent(
                    "5.00",
                    "usd",
                    &["btc-bitcoin-p2wpkh", "usdt-arbitrum-address"],
                    &[btc_rate, ("usdt", "1")],
                ),
            ),
            (
                "missing rate",
                intent("5.00", "usd", &["btc-bitcoin-p2wpkh"], &[]),
            ),
            (
                "wrong amount",
                intent("5.01", "usd", &["btc-bitcoin-p2wpkh"], &[btc_rate]),
            ),
            (
                "wrong denomination",
                intent("0.00000500", "btc", &["btc-bitcoin-p2wpkh"], &[btc_rate]),
            ),
            (
                "missing endpoint",
                intent("5.00", "usd", &["usdt-arbitrum-address"], &[("usdt", "1")]),
            ),
        ] {
            assert_eq!(
                MarketplaceQuote::from_intent(&intent, &usd_btc),
                Err(PersistenceError::InvalidInput),
                "{label}"
            );
        }
        let btc_only =
            MarketplaceTerms::new(50_000, CriterionAsset::Btc, [AcceptedAsset::Btc]).unwrap();
        assert!(
            MarketplaceQuote::from_intent(
                &intent(
                    "0.00050000",
                    "btc",
                    &["btc-bitcoin-p2wpkh"],
                    &[("btc", "1")]
                ),
                &btc_only
            )
            .is_err(),
            "a rate for the requested asset itself"
        );
    }
}
