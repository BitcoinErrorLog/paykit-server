//! Wire forms of Marketplace amount, asset, accepted assets and quote.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    application::{
        marketplace_terms::{MarketplaceQuote, MarketplaceTerms},
        setup_status::AcceptedAsset,
    },
    domain::invoice::CriterionAsset,
    http::error::ApiError,
};

pub(super) fn parse_amount(value: &str) -> Result<u64, ApiError> {
    MarketplaceTerms::parse_amount(value).map_err(|_| ApiError::InvalidRequest)
}

pub(super) fn parse_asset(value: &str) -> Result<CriterionAsset, ApiError> {
    CriterionAsset::parse(value).map_err(|_| ApiError::InvalidRequest)
}

pub(super) fn parse_accepted_assets(values: &[String]) -> Result<Vec<AcceptedAsset>, ApiError> {
    values
        .iter()
        .map(|value| AcceptedAsset::parse(value).map_err(|_| ApiError::InvalidRequest))
        .collect()
}

/// Terms echoed on prepare and activate. Amounts are base-unit integer strings.
#[derive(Serialize)]
pub(super) struct TermsResponse {
    amount: String,
    asset: &'static str,
    accepted_assets: Vec<&'static str>,
    payment_amounts: BTreeMap<&'static str, String>,
}

impl TermsResponse {
    pub(super) fn new(terms: &MarketplaceTerms, quote: &MarketplaceQuote) -> Self {
        Self {
            amount: terms.amount().to_string(),
            asset: terms.asset().as_str(),
            accepted_assets: terms
                .accepted_assets()
                .iter()
                .map(|asset| asset.as_str())
                .collect(),
            payment_amounts: quote
                .payment_amounts()
                .iter()
                .map(|(asset, amount)| (asset.as_str(), amount.to_string()))
                .collect(),
        }
    }
}

/// Fixed rates, payment-asset units per one requested-asset unit.
pub(super) fn rates(quote: &MarketplaceQuote) -> BTreeMap<&'static str, String> {
    quote
        .rates()
        .iter()
        .map(|(asset, value)| (asset.as_str(), value.clone()))
        .collect()
}
