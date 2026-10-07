//! Invoice identity and Locks payment-criterion values.

use std::fmt;

use serde_json::Value;
use thiserror::Error;

use super::locks::{BundleId, CreatorPubky, PubkyLockResource};

/// Compatibility payment window used by current Locks callers and locks.
pub const DEFAULT_PAYMENT_WINDOW_HOURS: u64 = 24;

/// A creator-scoped Locks invoice identity.
///
/// The creator is always derived from the addressed canonical lock resource.
///
/// Raw `locks-core` identifiers cannot construct an invoice identity, even when
/// their parser normalizes the input. Callers must use the canonical domain
/// boundary parsers instead.
///
/// ```compile_fail
/// use std::str::FromStr;
///
/// use locks_core::ids::{BundleId, PubkyLockResource};
/// use paykit_server::domain::invoice::InvoiceIdentity;
///
/// let bundle = BundleId::from_str("000g40r40m30e209185gr38e1w").unwrap();
/// let resource = PubkyLockResource::from_str(
///     "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/app.locks/000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfg.json",
/// )
/// .unwrap();
///
/// let _ = InvoiceIdentity::new(resource, bundle);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InvoiceIdentity {
    creator: CreatorPubky,
    bundle_id: BundleId,
}

impl InvoiceIdentity {
    /// Creates an identity from an addressed lock resource and bundle identifier.
    pub fn new(lock_resource: PubkyLockResource, bundle_id: BundleId) -> Self {
        Self {
            creator: lock_resource.creator().clone(),
            bundle_id,
        }
    }

    /// Returns the creator derived from the canonical lock resource.
    pub fn creator(&self) -> &CreatorPubky {
        &self.creator
    }

    /// Returns the canonical bundle identifier scoped by this identity.
    pub fn bundle_id(&self) -> &BundleId {
        &self.bundle_id
    }
}

/// Denominations accepted in a Locks payment criterion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum CriterionAsset {
    Btc,
    Usd,
    Usdt,
}

impl CriterionAsset {
    pub fn parse(value: &str) -> Result<Self, CriterionAssetError> {
        match value {
            "BTC" => Ok(Self::Btc),
            "USD" => Ok(Self::Usd),
            "USDT" => Ok(Self::Usdt),
            _ => Err(CriterionAssetError::UnsupportedAsset),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Btc => "BTC",
            Self::Usd => "USD",
            Self::Usdt => "USDT",
        }
    }

    pub fn decimals(self) -> u32 {
        match self {
            Self::Btc => 8,
            Self::Usd => 2,
            Self::Usdt => 6,
        }
    }

    pub fn decimal_amount(self, units: u64) -> String {
        match self {
            Self::Usd => format!("{}.{:02}", units / 100, units % 100),
            Self::Btc => format!("{}.{:08}", units / 100_000_000, units % 100_000_000),
            Self::Usdt => format!("{}.{:06}", units / 1_000_000, units % 1_000_000),
        }
    }
}

/// Error returned when an unsupported criterion asset is supplied.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CriterionAssetError {
    /// The asset is not supported.
    #[error("criterion asset must be BTC, USD or USDT")]
    UnsupportedAsset,
}

/// A positive Locks criterion amount expressed in integer asset base units.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CriterionAmount(u64);

impl CriterionAmount {
    /// Parses a positive, unsigned, decimal integer representable as `u64`.
    ///
    /// This intentionally preserves the accepted lexical form rather than
    /// applying a leading-zero normalization policy.
    pub fn parse(value: &str) -> Result<Self, CriterionAmountError> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CriterionAmountError::NotUnsignedDecimalInteger);
        }

        let units = value
            .parse::<u64>()
            .map_err(|_| CriterionAmountError::OutOfRange)?;
        if units == 0 {
            return Err(CriterionAmountError::Zero);
        }

        Ok(Self(units))
    }

    /// Returns the settlement-authoritative integer base-unit amount.
    pub fn units(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for CriterionAmount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Error returned while parsing a criterion amount.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CriterionAmountError {
    /// The value was empty or included something other than ASCII decimal digits.
    #[error("criterion amount must be an unsigned decimal integer")]
    NotUnsignedDecimalInteger,
    /// The value was zero.
    #[error("criterion amount must be positive")]
    Zero,
    /// The value did not fit in `u64`.
    #[error("criterion amount exceeds u64")]
    OutOfRange,
}

/// A positive Locks payment window expressed as whole JSON hours.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CriterionPaymentWindowHours(u64);

impl CriterionPaymentWindowHours {
    /// Validates an already-decoded whole-hour value.
    pub fn new(hours: u64) -> Result<Self, CriterionPaymentWindowHoursError> {
        if hours == 0 {
            Err(CriterionPaymentWindowHoursError::Invalid)
        } else {
            Ok(Self(hours))
        }
    }

    /// Parses a required positive JSON `u64`.
    pub fn parse(value: &Value) -> Result<Self, CriterionPaymentWindowHoursError> {
        let hours = value
            .as_u64()
            .ok_or(CriterionPaymentWindowHoursError::Invalid)?;
        Self::new(hours)
    }

    /// Parses an optional JSON field while preserving missing-field diagnostics.
    pub fn parse_optional(value: Option<&Value>) -> Result<Self, CriterionPaymentWindowHoursError> {
        Self::parse(value.ok_or(CriterionPaymentWindowHoursError::Missing)?)
    }

    /// Returns the positive whole-hour value.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Error returned while parsing a Locks payment window.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CriterionPaymentWindowHoursError {
    /// The required `payment_in` field was absent.
    #[error("payment window hours are required")]
    Missing,
    /// The field was not a positive whole-hour JSON `u64`.
    #[error("payment window must be a positive whole-hour JSON u64")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{CriterionPaymentWindowHours, CriterionPaymentWindowHoursError};

    #[test]
    fn payment_window_hours_accepts_exact_positive_json_u64() {
        let hours = CriterionPaymentWindowHours::parse(&json!(24)).unwrap();
        assert_eq!(hours.get(), 24);
    }

    #[test]
    fn payment_window_hours_rejects_missing_zero_string_fraction_and_out_of_range() {
        for (value, expected) in [
            (None, CriterionPaymentWindowHoursError::Missing),
            (Some(json!(0)), CriterionPaymentWindowHoursError::Invalid),
            (Some(json!("24")), CriterionPaymentWindowHoursError::Invalid),
            (Some(json!(1.5)), CriterionPaymentWindowHoursError::Invalid),
            (
                Some(Value::Number(
                    serde_json::Number::from_f64(18_446_744_073_709_551_616.0).unwrap(),
                )),
                CriterionPaymentWindowHoursError::Invalid,
            ),
        ] {
            assert_eq!(
                CriterionPaymentWindowHours::parse_optional(value.as_ref()),
                Err(expected)
            );
        }
    }
}
