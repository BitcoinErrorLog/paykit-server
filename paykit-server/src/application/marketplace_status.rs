//! Read-only Marketplace invoice status projection.

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::locks::CreatorPubky;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketplaceBitcoinStatus {
    pub(crate) txid: String,
    pub(crate) vout: u32,
    pub(crate) observed_sats: u64,
    pub(crate) first_observed_at: OffsetDateTime,
    pub(crate) confirmations: u32,
    pub(crate) present: bool,
    pub(crate) amount_matched: bool,
    pub(crate) paid_on_time: bool,
}

impl MarketplaceBitcoinStatus {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        txid: String,
        vout: u32,
        observed_sats: u64,
        first_observed_at: OffsetDateTime,
        confirmations: u32,
        present: bool,
        amount_matched: bool,
        paid_on_time: bool,
    ) -> Self {
        Self {
            txid,
            vout,
            observed_sats,
            first_observed_at,
            confirmations,
            present,
            amount_matched,
            paid_on_time,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketplaceInvoiceStatus {
    pub(crate) invoice_id: Uuid,
    pub(crate) state: &'static str,
    pub(crate) proposal_delivery_state: &'static str,
    pub(crate) request_state: Option<&'static str>,
    pub(crate) payment_state: Option<&'static str>,
    pub(crate) activated_at: Option<OffsetDateTime>,
    pub(crate) payment_deadline: Option<OffsetDateTime>,
    pub(crate) bitcoin: Option<MarketplaceBitcoinStatus>,
    pub(crate) outcome: Option<&'static str>,
    pub(crate) resolved_at: Option<OffsetDateTime>,
}

impl MarketplaceInvoiceStatus {
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        invoice_id: Uuid,
        proposal_delivery_state: &'static str,
        request_state: Option<&'static str>,
        payment_state: &'static str,
        activated_at: OffsetDateTime,
        payment_deadline: OffsetDateTime,
        bitcoin: Option<MarketplaceBitcoinStatus>,
        outcome: Option<&'static str>,
        resolved_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            invoice_id,
            state: "active",
            proposal_delivery_state,
            request_state,
            payment_state: Some(payment_state),
            activated_at: Some(activated_at),
            payment_deadline: Some(payment_deadline),
            bitcoin,
            outcome,
            resolved_at,
        }
    }

    pub fn inactive(
        invoice_id: Uuid,
        state: &'static str,
        outcome: Option<&'static str>,
        resolved_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            invoice_id,
            state,
            proposal_delivery_state: "unpublished",
            request_state: None,
            payment_state: None,
            activated_at: None,
            payment_deadline: None,
            bitcoin: None,
            outcome,
            resolved_at,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarketplaceStatusError {
    Conflict,
    Unavailable,
    RecoveryRequired,
    InvalidConflict,
}

#[async_trait]
pub trait MarketplaceStatusPersistence: Send + Sync {
    async fn status(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<MarketplaceInvoiceStatus>, MarketplaceStatusError>;
}

pub struct MarketplaceStatusService {
    store: Arc<dyn MarketplaceStatusPersistence>,
}

impl MarketplaceStatusService {
    pub fn new(store: Arc<dyn MarketplaceStatusPersistence>) -> Self {
        Self { store }
    }

    pub async fn status(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<MarketplaceInvoiceStatus>, MarketplaceStatusError> {
        let status = self.store.status(creator, invoice_id).await?;
        match status.as_ref().and_then(|status| status.request_state) {
            Some("recovery_required") => Err(MarketplaceStatusError::RecoveryRequired),
            Some("invalid_conflict") => Err(MarketplaceStatusError::InvalidConflict),
            _ => Ok(status),
        }
    }
}
