//! Read-only payment status lookup backed only by durable invoice facts.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    domain::locks::{BundleId, CreatorPubky},
    persistence::{InvoiceStore, PersistenceError},
};

/// Validated payment facts read from one persisted invoice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistedPaymentStatus {
    Undetected {
        late_settlement: bool,
    },
    Detected {
        confirmations: u32,
        amount_matched: bool,
        late_settlement: bool,
    },
    Confirmed {
        confirmations: u32,
        amount_matched: bool,
        late_settlement: bool,
    },
}

/// Narrow read-only durable status boundary.
#[async_trait]
pub trait StatusRepository: Send + Sync {
    async fn status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<PersistedPaymentStatus>, PersistenceError>;
}

#[async_trait]
impl StatusRepository for InvoiceStore {
    async fn status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<PersistedPaymentStatus>, PersistenceError> {
        InvoiceStore::payment_status(self, creator, bundle_id).await
    }
}

/// The exact, secret-free Locks-facing status response. `late_settlement`
/// marks an observation recorded in the §B.9 expiry tail: it is a factual
/// observation, never a settlement — the marketplace routes it to
/// `manual_review` and it can never drive `paid`, even when it reports
/// `confirmed` with an exact amount (§B.9, §B.8.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentStatusResponse {
    status: &'static str,
    confirmations: u32,
    amount_matched: bool,
    late_settlement: bool,
}

impl PaymentStatusResponse {
    fn new(
        status: &'static str,
        confirmations: u32,
        amount_matched: bool,
        late_settlement: bool,
    ) -> Self {
        Self {
            status,
            confirmations,
            amount_matched,
            late_settlement,
        }
    }

    pub fn status(&self) -> &'static str {
        self.status
    }

    pub fn confirmations(&self) -> u32 {
        self.confirmations
    }

    pub fn amount_matched(&self) -> bool {
        self.amount_matched
    }

    pub fn late_settlement(&self) -> bool {
        self.late_settlement
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentStatusError {
    NotFound,
    Unavailable,
}

/// Looks up factual payment status without session validation, lock fetching,
/// invoice decryption, observer access, or other external I/O.
pub struct PaymentStatusService {
    repository: Arc<dyn StatusRepository>,
}

impl PaymentStatusService {
    pub fn new(repository: Arc<dyn StatusRepository>) -> Self {
        Self { repository }
    }

    pub async fn status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<PaymentStatusResponse, PaymentStatusError> {
        let persisted = self
            .repository
            .status(creator, bundle_id)
            .await
            .map_err(|_| PaymentStatusError::Unavailable)?
            .ok_or(PaymentStatusError::NotFound)?;
        Ok(match persisted {
            PersistedPaymentStatus::Undetected { late_settlement } => {
                PaymentStatusResponse::new("undetected", 0, false, late_settlement)
            }
            PersistedPaymentStatus::Detected {
                confirmations,
                amount_matched,
                late_settlement,
            } => PaymentStatusResponse::new(
                "detected",
                confirmations,
                amount_matched,
                late_settlement,
            ),
            PersistedPaymentStatus::Confirmed {
                confirmations,
                amount_matched,
                late_settlement,
            } => PaymentStatusResponse::new(
                "confirmed",
                confirmations,
                amount_matched,
                late_settlement,
            ),
        })
    }
}
