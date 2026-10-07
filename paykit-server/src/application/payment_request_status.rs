use async_trait::async_trait;
use serde::Serialize;
use time::OffsetDateTime;

use crate::domain::{
    locks::{BundleId, CreatorPubky},
    payment_request_lifecycle::PaymentRequestLifecycleState,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentState {
    Undetected,
    Detected,
    Confirmed,
    Expired,
}

impl PaymentState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undetected => "undetected",
            Self::Detected => "detected",
            Self::Confirmed => "confirmed",
            Self::Expired => "expired",
        }
    }
}

/// Current Bitcoin output facts. Amount-matched confirmation counts are capped at six.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BitcoinPaymentStatus {
    pub confirmations: u32,
    pub amount_matched: bool,
    /// A full payment was verified within the inclusive invoice payment window.
    pub paid_on_time: bool,
}

/// Current verified USDT0 receipt facts on Arbitrum One (chain 42161).
/// L2 confirmation counts do not imply L1 finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct UsdtPaymentStatus {
    pub confirmations: u32,
    pub amount_matched: bool,
    /// A full payment was verified within the inclusive invoice payment window.
    pub paid_on_time: bool,
    pub finalized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentRequestStatusSummary {
    request_state: PaymentRequestLifecycleState,
    payment_state: PaymentState,
    invoice_created_at: OffsetDateTime,
    payment_deadline: OffsetDateTime,
    bitcoin: Option<BitcoinPaymentStatus>,
    usdt_arbitrum: Option<UsdtPaymentStatus>,
}

impl PaymentRequestStatusSummary {
    pub const fn new(
        request_state: PaymentRequestLifecycleState,
        payment_state: PaymentState,
        invoice_created_at: OffsetDateTime,
        payment_deadline: OffsetDateTime,
        bitcoin: Option<BitcoinPaymentStatus>,
        usdt_arbitrum: Option<UsdtPaymentStatus>,
    ) -> Self {
        Self {
            request_state,
            payment_state,
            invoice_created_at,
            payment_deadline,
            bitcoin,
            usdt_arbitrum,
        }
    }

    pub const fn request_state(&self) -> PaymentRequestLifecycleState {
        self.request_state
    }

    pub const fn payment_state(&self) -> PaymentState {
        self.payment_state
    }

    pub const fn invoice_created_at(&self) -> OffsetDateTime {
        self.invoice_created_at
    }

    pub const fn payment_deadline(&self) -> OffsetDateTime {
        self.payment_deadline
    }

    pub const fn bitcoin(&self) -> Option<BitcoinPaymentStatus> {
        self.bitcoin
    }

    pub const fn usdt_arbitrum(&self) -> Option<UsdtPaymentStatus> {
        self.usdt_arbitrum
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentRequestStatusError {
    Conflict,
    Unavailable,
}

impl PaymentRequestStatusError {
    pub(crate) const fn diagnostic_label(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
        }
    }
}

#[async_trait]
pub trait PaymentRequestStatusOperations: Send + Sync {
    async fn lookup(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<PaymentRequestStatusSummary>, PaymentRequestStatusError>;
}
