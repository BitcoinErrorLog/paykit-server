//! Read-only Bitcoin status lookup backed only by durable invoice facts.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    domain::locks::{BundleId, CreatorPubky},
    persistence::{InvoiceStore, PersistenceError},
};

/// Validated payment facts read from one persisted invoice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistedPaymentStatus {
    Undetected,
    Detected {
        confirmations: u32,
        amount_matched: bool,
    },
    Confirmed {
        confirmations: u32,
        amount_matched: bool,
    },
}

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

/// The secret-free Bitcoin observation response. Request settlement uses the per-rail status API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentStatusResponse {
    status: &'static str,
    confirmations: u32,
    amount_matched: bool,
}

impl PaymentStatusResponse {
    fn undetected() -> Self {
        Self {
            status: "undetected",
            confirmations: 0,
            amount_matched: false,
        }
    }

    fn factual(status: &'static str, confirmations: u32, amount_matched: bool) -> Self {
        Self {
            status,
            confirmations,
            amount_matched,
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
            PersistedPaymentStatus::Undetected => PaymentStatusResponse::undetected(),
            PersistedPaymentStatus::Detected {
                confirmations,
                amount_matched,
            } => PaymentStatusResponse::factual("detected", confirmations, amount_matched),
            PersistedPaymentStatus::Confirmed {
                confirmations,
                amount_matched,
            } => PaymentStatusResponse::factual("confirmed", confirmations, amount_matched),
        })
    }
}
