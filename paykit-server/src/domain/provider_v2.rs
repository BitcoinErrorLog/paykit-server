//! Closed provider-v2 payment and observation values.

use time::OffsetDateTime;

use crate::domain::{
    invoice::{CriterionAmount, CriterionAsset},
    locks::{CreatorPubky, parse_creator},
    payment::BitcoinOutpoint,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderV2ValueError {
    InvalidPayment,
    InvalidSample,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderV2Asset {
    Btc,
    Usdt,
}

impl ProviderV2Asset {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Btc => "BTC",
            Self::Usdt => "USDT",
        }
    }

    pub const fn criterion_asset(self) -> CriterionAsset {
        match self {
            Self::Btc => CriterionAsset::Btc,
            Self::Usdt => CriterionAsset::Usdt,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderV2Payment {
    amount_lexeme: String,
    amount_units: u64,
    asset: ProviderV2Asset,
    minimum_confirmations: u8,
}

impl ProviderV2Payment {
    pub fn parse(
        recipient_pubky: &str,
        amount: &str,
        asset: &str,
        minimum_confirmations: u8,
        creator: &CreatorPubky,
    ) -> Result<Self, ProviderV2ValueError> {
        let recipient =
            parse_creator(recipient_pubky).map_err(|_| ProviderV2ValueError::InvalidPayment)?;
        let asset = match asset {
            "BTC" => ProviderV2Asset::Btc,
            "USDT" => ProviderV2Asset::Usdt,
            _ => return Err(ProviderV2ValueError::InvalidPayment),
        };
        if &recipient != creator || minimum_confirmations > 6 {
            return Err(ProviderV2ValueError::InvalidPayment);
        }
        let amount_units = CriterionAmount::parse(amount)
            .map_err(|_| ProviderV2ValueError::InvalidPayment)?
            .units();
        Ok(Self {
            amount_lexeme: amount.to_owned(),
            amount_units,
            asset,
            minimum_confirmations,
        })
    }

    pub fn amount_lexeme(&self) -> &str {
        &self.amount_lexeme
    }

    pub fn amount_units(&self) -> u64 {
        self.amount_units
    }

    pub fn asset(&self) -> ProviderV2Asset {
        self.asset
    }

    pub fn minimum_confirmations(&self) -> u8 {
        self.minimum_confirmations
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderV2SampleStatus {
    Undetected,
    Detected,
    Confirmed,
}

impl ProviderV2SampleStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undetected => "undetected",
            Self::Detected => "detected",
            Self::Confirmed => "confirmed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderV2Sample {
    observed_at: OffsetDateTime,
    status: ProviderV2SampleStatus,
    outpoint: Option<BitcoinOutpoint>,
    confirmations: u8,
    amount_matched: bool,
}

impl ProviderV2Sample {
    pub fn new(
        observed_at: OffsetDateTime,
        status: ProviderV2SampleStatus,
        outpoint: Option<BitcoinOutpoint>,
        confirmations: u8,
        amount_matched: bool,
    ) -> Result<Self, ProviderV2ValueError> {
        let valid = confirmations <= 6
            && match status {
                ProviderV2SampleStatus::Undetected => {
                    outpoint.is_none() && confirmations == 0 && !amount_matched
                }
                ProviderV2SampleStatus::Detected => outpoint.is_some() && confirmations == 0,
                ProviderV2SampleStatus::Confirmed => outpoint.is_some() && confirmations > 0,
            };
        if !valid {
            return Err(ProviderV2ValueError::InvalidSample);
        }
        Ok(Self {
            observed_at,
            status,
            outpoint,
            confirmations,
            amount_matched,
        })
    }

    pub fn qualifies(&self, minimum_confirmations: u8, deadline: OffsetDateTime) -> bool {
        self.outpoint.is_some()
            && self.amount_matched
            && self.confirmations >= minimum_confirmations
            && self.observed_at <= deadline
    }

    pub fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    pub fn status(&self) -> ProviderV2SampleStatus {
        self.status
    }

    pub fn outpoint(&self) -> Option<&BitcoinOutpoint> {
        self.outpoint.as_ref()
    }

    pub fn confirmations(&self) -> u8 {
        self.confirmations
    }

    pub fn amount_matched(&self) -> bool {
        self.amount_matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::locks::parse_creator;

    const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

    #[test]
    fn payment_asset_is_closed_to_btc_and_usdt_with_exact_base_units() {
        let creator = parse_creator(CREATOR).unwrap();

        let btc = ProviderV2Payment::parse(CREATOR, "21", "BTC", 6, &creator).unwrap();
        assert_eq!(btc.asset(), ProviderV2Asset::Btc);
        assert_eq!(btc.amount_units(), 21);

        let usdt = ProviderV2Payment::parse(CREATOR, "5000001", "USDT", 0, &creator).unwrap();
        assert_eq!(usdt.asset(), ProviderV2Asset::Usdt);
        assert_eq!(usdt.amount_units(), 5_000_001);

        for unsupported in ["btc", "usdt", "USD", "ETH", ""] {
            assert_eq!(
                ProviderV2Payment::parse(CREATOR, "1", unsupported, 0, &creator),
                Err(ProviderV2ValueError::InvalidPayment)
            );
        }
    }
}
