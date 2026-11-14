//! Read-only projection of the Receipt the seller's wallet issued for a
//! Marketplace request.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::locks::CreatorPubky;

/// The Payment Amount a Receipt states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SellerReceiptAmount {
    pub value: String,
    pub currency: String,
}

/// What a seller-issued Receipt says, as read from the Creator's shared SDK
/// state. The server reports it; it never checks the amount against the
/// request's terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SellerReceipt {
    pub receipt_id: String,
    /// The App on the Creator's identity that issued the Receipt.
    pub app_id: String,
    pub payment_request_id: String,
    pub payment_reference: String,
    pub payment_endpoint_identifier: Option<String>,
    pub amount: Option<SellerReceiptAmount>,
    /// Receipt Metadata, such as `{"txid": ...}` or `{"payment_hash": ...}`.
    pub metadata: Map<String, Value>,
    /// When the issuing App recorded the Receipt.
    pub issued_at: OffsetDateTime,
}

/// A seller Receipt and when this server stored it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSellerReceipt {
    pub receipt: SellerReceipt,
    pub stored_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarketplaceReceiptError {
    Unavailable,
}

#[async_trait]
pub trait MarketplaceReceiptPersistence: Send + Sync {
    /// `None` for an unknown invoice or another Creator's; `Some(None)` while
    /// no seller Receipt is stored for it.
    async fn seller_receipt(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<Option<StoredSellerReceipt>>, MarketplaceReceiptError>;
}

pub struct MarketplaceReceiptService {
    store: Arc<dyn MarketplaceReceiptPersistence>,
}

impl MarketplaceReceiptService {
    pub fn new(store: Arc<dyn MarketplaceReceiptPersistence>) -> Self {
        Self { store }
    }

    /// Reads only persisted state: no Pubky or SDK call.
    pub async fn seller_receipt(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<Option<StoredSellerReceipt>>, MarketplaceReceiptError> {
        self.store.seller_receipt(creator, invoice_id).await
    }
}
