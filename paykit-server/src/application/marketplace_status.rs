//! Read-only Marketplace invoice status projection.

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{application::setup_status::AcceptedAsset, domain::locks::CreatorPubky};

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
    /// A full payment was observed within the inclusive payment window.
    pub fn paid_on_time(&self) -> bool {
        self.paid_on_time
    }

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

/// The verified USDT0 receipt on Arbitrum One that best settles the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketplaceUsdtStatus {
    pub(crate) tx_hash: String,
    pub(crate) observed_amount: u64,
    pub(crate) observed_at: OffsetDateTime,
    pub(crate) confirmations: u32,
    pub(crate) amount_matched: bool,
    pub(crate) paid_on_time: bool,
    pub(crate) finalized: bool,
}

impl MarketplaceUsdtStatus {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_hash: String,
        observed_amount: u64,
        observed_at: OffsetDateTime,
        confirmations: u32,
        amount_matched: bool,
        paid_on_time: bool,
        finalized: bool,
    ) -> Self {
        Self {
            tx_hash,
            observed_amount,
            observed_at,
            confirmations,
            amount_matched,
            paid_on_time,
            finalized,
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
    pub(crate) accepted_assets: Vec<AcceptedAsset>,
    pub(crate) payment_amounts: Vec<(AcceptedAsset, u64)>,
    pub(crate) bitcoin: Option<MarketplaceBitcoinStatus>,
    pub(crate) usdt_arbitrum: Option<MarketplaceUsdtStatus>,
    pub(crate) paid_asset: Option<AcceptedAsset>,
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
            accepted_assets: Vec::new(),
            payment_amounts: Vec::new(),
            bitcoin,
            usdt_arbitrum: None,
            paid_asset: None,
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
            accepted_assets: Vec::new(),
            payment_amounts: Vec::new(),
            bitcoin: None,
            usdt_arbitrum: None,
            paid_asset: None,
            outcome,
            resolved_at,
        }
    }

    /// The assets the request offers and the exact payable amount of each.
    pub fn with_offer(
        mut self,
        accepted_assets: Vec<AcceptedAsset>,
        payment_amounts: Vec<(AcceptedAsset, u64)>,
    ) -> Self {
        self.accepted_assets = accepted_assets;
        self.payment_amounts = payment_amounts;
        self
    }

    /// The USDT receipt and the rail that settled the request, if any.
    pub fn with_usdt(
        mut self,
        usdt_arbitrum: Option<MarketplaceUsdtStatus>,
        paid_asset: Option<AcceptedAsset>,
    ) -> Self {
        self.usdt_arbitrum = usdt_arbitrum;
        self.paid_asset = paid_asset;
        self
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
