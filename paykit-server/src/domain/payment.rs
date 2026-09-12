//! Bitcoin outpoint and payment-observation domain values.

use std::fmt;

use bitcoin::OutPoint;
use thiserror::Error;
use uuid::Uuid;

use super::invoice::CriterionAmount;

/// A Bitcoin transaction output identity used by direct observation.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BitcoinOutpoint {
    txid: String,
    vout: u32,
}

impl fmt::Debug for BitcoinOutpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BitcoinOutpoint(<redacted>)")
    }
}

impl BitcoinOutpoint {
    /// Validates a lowercase 64-character ASCII-hex transaction ID and output index.
    pub fn new(txid: &str, vout: u32) -> Result<Self, BitcoinOutpointError> {
        if txid.len() != 64
            || !txid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(BitcoinOutpointError::InvalidTxid);
        }

        Ok(Self {
            txid: txid.to_owned(),
            vout,
        })
    }

    /// Returns the validated lowercase transaction ID.
    pub fn txid(&self) -> &str {
        &self.txid
    }

    /// Returns the transaction output index.
    pub fn vout(&self) -> u32 {
        self.vout
    }

    /// Canonicalizes an outpoint already parsed by the Bitcoin provider.
    pub fn from_bitcoin(outpoint: OutPoint) -> Self {
        Self {
            txid: outpoint.txid.to_string(),
            vout: outpoint.vout,
        }
    }

    pub(crate) fn canonical_text(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }
}

/// Error returned while parsing an observed-payment outpoint.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BitcoinOutpointError {
    /// The transaction ID was not exactly 64 lowercase ASCII-hex characters.
    #[error("txid must be 64 lowercase ASCII hex characters")]
    InvalidTxid,
}

/// A server-generated UUID v4 binding an invoice to a payment request.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PaymentReference {
    uuid: Uuid,
    text: String,
}

impl fmt::Debug for PaymentReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PaymentReference(<redacted>)")
    }
}

impl PaymentReference {
    /// Generates one UUID v4 payment reference.
    pub fn new() -> Self {
        let uuid = Uuid::new_v4();
        Self {
            text: uuid.hyphenated().to_string(),
            uuid,
        }
    }

    /// Returns the generated UUID value.
    pub fn as_uuid(&self) -> Uuid {
        self.uuid
    }

    /// Returns the stable canonical string for the generated UUID.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl Default for PaymentReference {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PaymentReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Public Locks-facing payment-detection status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentStatus {
    /// No valid referenced output is currently observed.
    Undetected,
    /// A valid referenced output is observed with zero confirmations.
    Detected,
    /// A valid referenced output is observed with one or more confirmations.
    Confirmed,
}

/// Factual payment-observation status for one invoice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentObservation {
    status: PaymentStatus,
    confirmations: u32,
    amount_matched: bool,
}

impl PaymentObservation {
    fn undetected() -> Self {
        Self {
            status: PaymentStatus::Undetected,
            confirmations: 0,
            amount_matched: false,
        }
    }

    fn observed(confirmations: u32, amount_matched: bool) -> Self {
        Self {
            status: if confirmations == 0 {
                PaymentStatus::Detected
            } else {
                PaymentStatus::Confirmed
            },
            confirmations,
            amount_matched,
        }
    }

    /// Returns whether no output, a zero-confirmation output, or a confirmed output is observed.
    pub fn status(&self) -> PaymentStatus {
        self.status
    }

    /// Returns the explicit observed confirmation count.
    pub fn confirmations(&self) -> u32 {
        self.confirmations
    }

    /// Returns whether one observed output pays exactly the invoice amount.
    pub fn amount_matched(&self) -> bool {
        self.amount_matched
    }
}

/// Pure state for an invoice's directly observed payment output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentBinding {
    invoice_sats: u64,
    observed_sats: Option<u64>,
    confirmations: u32,
}

impl PaymentBinding {
    /// Creates an unobserved payment binding for an invoice amount.
    pub fn undetected(invoice_amount: CriterionAmount) -> Self {
        Self {
            invoice_sats: invoice_amount.as_sats(),
            observed_sats: None,
            confirmations: 0,
        }
    }

    /// Creates a payment binding from a single observed output and confirmation count.
    ///
    /// An exact-amount output at six or more confirmations becomes final and
    /// records exactly six confirmations. Amount mismatches (under- or
    /// overpayment) retain their actual count.
    pub fn observed(
        invoice_amount: CriterionAmount,
        observed_sats: u64,
        confirmations: u32,
    ) -> Self {
        let amount_matched =
            crate::bitcoin::amount_matches(true, observed_sats, invoice_amount.as_sats());
        Self {
            invoice_sats: invoice_amount.as_sats(),
            observed_sats: Some(observed_sats),
            confirmations: if amount_matched {
                confirmations.min(6)
            } else {
                confirmations
            },
        }
    }

    /// Returns the current factual observation.
    pub fn observation(&self) -> PaymentObservation {
        match self.observed_sats {
            Some(observed_sats) => PaymentObservation::observed(
                self.confirmations,
                crate::bitcoin::amount_matches(true, observed_sats, self.invoice_sats),
            ),
            None => PaymentObservation::undetected(),
        }
    }

    /// Returns whether the binding is an exact-amount payment finalized at six confirmations.
    pub fn is_final(&self) -> bool {
        self.observed_sats
            .is_some_and(|sats| sats == self.invoice_sats)
            && self.confirmations == 6
    }

    /// Returns whether a newer direct observation may replace this binding.
    pub fn is_replaceable(&self) -> bool {
        match self.observed_sats {
            None => true,
            Some(observed_sats) if observed_sats != self.invoice_sats => true,
            Some(_) => !self.is_final() && self.confirmations < 1,
        }
    }

    /// Applies a pre-final reorg or unseen regression.
    ///
    /// A six-confirmation matching binding is permanent; every other binding
    /// becomes unobserved and is eligible for replacement.
    pub fn regress_to_unseen(&self) -> Self {
        if self.is_final() {
            self.clone()
        } else {
            Self {
                invoice_sats: self.invoice_sats,
                observed_sats: None,
                confirmations: 0,
            }
        }
    }
}
