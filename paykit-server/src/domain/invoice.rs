//! Invoice identity and Locks payment-criterion values.

use std::fmt;

use thiserror::Error;

use super::locks::{BundleId, CreatorPubky, PubkyLockResource};

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
///     "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/locks.app/000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfg.json",
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

/// The only supported Locks payment-criterion asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CriterionAsset;

/// Inclusive bounds of the per-invoice CSPRNG amount nonce (design §B.8.2).
/// Every invoice created from W1.1b on draws `nonce_sats` inside this range
/// and binds at exactly `price + nonce_sats`; at most 999 satoshis keeps the
/// nonce far below a typical mainnet fee. Invoices created before W1.1b carry
/// no nonce and read as `nonce_sats = 0`.
pub const NONCE_SATS_MIN: u64 = 1;
/// Inclusive upper bound of the per-invoice amount nonce; see [`NONCE_SATS_MIN`].
pub const NONCE_SATS_MAX: u64 = 999;

impl CriterionAsset {
    /// Parses the exact accepted asset spelling, `BTC`.
    pub fn parse(value: &str) -> Result<Self, CriterionAssetError> {
        if value == "BTC" {
            Ok(Self)
        } else {
            Err(CriterionAssetError::UnsupportedAsset)
        }
    }

    /// Returns the exact supported asset spelling.
    pub fn as_str(&self) -> &'static str {
        "BTC"
    }
}

/// Error returned when an unsupported criterion asset is supplied.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CriterionAssetError {
    /// The asset was not the exact uppercase string `BTC`.
    #[error("criterion asset must be exact uppercase BTC")]
    UnsupportedAsset,
}

/// A positive Locks criterion amount expressed in integer satoshis.
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

        let sats = value
            .parse::<u64>()
            .map_err(|_| CriterionAmountError::OutOfRange)?;
        if sats == 0 {
            return Err(CriterionAmountError::Zero);
        }

        Ok(Self(sats))
    }

    /// Returns the settlement-authoritative integer satoshi amount.
    pub fn as_sats(&self) -> u64 {
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
