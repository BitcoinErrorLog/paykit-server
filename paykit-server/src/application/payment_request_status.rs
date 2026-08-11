use async_trait::async_trait;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentRequestStatusSummary {
    request_state: PaymentRequestLifecycleState,
    payment_state: PaymentState,
    invoice_created_at: OffsetDateTime,
    payment_deadline: OffsetDateTime,
    confirmations: u32,
    amount_matched: bool,
}

impl PaymentRequestStatusSummary {
    pub const fn new(
        request_state: PaymentRequestLifecycleState,
        payment_state: PaymentState,
        invoice_created_at: OffsetDateTime,
        payment_deadline: OffsetDateTime,
        confirmations: u32,
        amount_matched: bool,
    ) -> Self {
        Self {
            request_state,
            payment_state,
            invoice_created_at,
            payment_deadline,
            confirmations,
            amount_matched,
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

    pub const fn confirmations(&self) -> u32 {
        self.confirmations
    }

    pub const fn amount_matched(&self) -> bool {
        self.amount_matched
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentRequestStatusError {
    Unavailable,
}

#[async_trait]
pub trait PaymentRequestStatusOperations: Send + Sync {
    async fn lookup(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<PaymentRequestStatusSummary>, PaymentRequestStatusError>;
}
