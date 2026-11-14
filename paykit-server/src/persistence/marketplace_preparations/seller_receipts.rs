//! The Receipt the seller's wallet issued for a Marketplace request.

use serde_json::{Map, Value};

use super::*;
use crate::application::marketplace_receipt::{
    MarketplaceReceiptError, MarketplaceReceiptPersistence, SellerReceipt, SellerReceiptAmount,
    StoredSellerReceipt,
};

/// Stored seller Receipt facts. postcard cannot carry a JSON value, so the
/// Receipt Metadata is kept as its JSON text.
#[derive(Serialize, Deserialize)]
struct SellerReceiptEnvelopeV1 {
    version: u8,
    receipt_id: String,
    app_id: String,
    payment_request_id: String,
    payment_reference: String,
    payment_endpoint_identifier: Option<String>,
    amount: Option<(String, String)>,
    metadata: String,
    issued_at: OffsetDateTime,
}

/// An open Marketplace request with no seller Receipt stored yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSellerReceiptRequest {
    pub invoice_id: Uuid,
    /// The Payment Request ID the request was proposed under: its proposal
    /// outbox row ID, hyphenated.
    pub payment_request_id: String,
    /// The keyed lookup hash of the request's reader (the buyer).
    pub reader_lookup_hash: LookupHash,
}

/// What storing a seller Receipt did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SellerReceiptStored {
    Stored,
    /// The same Receipt was already stored.
    Unchanged,
    /// Another Receipt was already stored for the invoice; it is kept.
    KeptFirst,
}

#[derive(sqlx::FromRow)]
struct OpenRequestRow {
    invoice_id: Uuid,
    payment_request_id: Uuid,
    reader_lookup_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct SellerReceiptRow {
    creator_lookup_hash: Vec<u8>,
    receipt_envelope: Option<Vec<u8>>,
    receipt_lookup_hash: Option<Vec<u8>>,
    stored_at: Option<OffsetDateTime>,
}

/// Open requests: activated, not resolved, proposed, and with no seller
/// Receipt stored.
const OPEN_REQUESTS: &str = "FROM marketplace_payment_preparations preparation
     JOIN outbox ON outbox.marketplace_preparation_id = preparation.id
      AND outbox.intent_kind = 'payment_request_proposal'
     LEFT JOIN marketplace_seller_receipts receipt
       ON receipt.preparation_id = preparation.id
     WHERE preparation.state = 'active'
       AND preparation.business_outcome IS NULL
       AND receipt.preparation_id IS NULL";

impl MarketplacePreparationStore {
    /// Creators with at least one open Marketplace request that has no seller
    /// Receipt stored.
    pub async fn creators_awaiting_seller_receipts(&self) -> Result<Vec<Uuid>, PersistenceError> {
        sqlx::query_scalar(&format!(
            "SELECT DISTINCT preparation.creator_id {OPEN_REQUESTS} ORDER BY 1"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// One Creator's open Marketplace requests with no seller Receipt stored.
    pub async fn open_seller_receipt_requests(
        &self,
        creator_id: Uuid,
    ) -> Result<Vec<OpenSellerReceiptRequest>, PersistenceError> {
        sqlx::query_as::<_, OpenRequestRow>(&format!(
            "SELECT preparation.id AS invoice_id, outbox.id AS payment_request_id,
                    preparation.reader_lookup_hash
             {OPEN_REQUESTS} AND preparation.creator_id = $1
             ORDER BY preparation.id, outbox.id"
        ))
        .bind(creator_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .into_iter()
        .map(|row| {
            Ok(OpenSellerReceiptRequest {
                invoice_id: row.invoice_id,
                payment_request_id: row.payment_request_id.hyphenated().to_string(),
                reader_lookup_hash: stored_hash(&row.reader_lookup_hash)?,
            })
        })
        .collect()
    }

    /// The keyed lookup hash invoices store for `reader`.
    pub fn reader_lookup_hash(&self, reader: &ReaderPubky) -> LookupHash {
        self.crypto.lookup_hash(reader.to_string().as_bytes())
    }

    /// Stores the first seller Receipt accepted for an invoice. The same
    /// Receipt again is a no-op; a different one leaves the first in place.
    pub async fn store_seller_receipt(
        &self,
        creator_id: Uuid,
        invoice_id: Uuid,
        receipt: &SellerReceipt,
    ) -> Result<SellerReceiptStored, PersistenceError> {
        let creator_hash: Vec<u8> =
            sqlx::query_scalar("SELECT creator_lookup_hash FROM creators WHERE id = $1")
                .bind(creator_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| PersistenceError::Unavailable)?
                .ok_or(PersistenceError::CorruptOrMissing)?;
        let creator_hash = stored_hash(&creator_hash)?;
        let receipt_hash = self
            .crypto
            .seller_receipt_lookup_hash(receipt.receipt_id.as_bytes());
        let plaintext = postcard::to_allocvec(&SellerReceiptEnvelopeV1 {
            version: 1,
            receipt_id: receipt.receipt_id.clone(),
            app_id: receipt.app_id.clone(),
            payment_request_id: receipt.payment_request_id.clone(),
            payment_reference: receipt.payment_reference.clone(),
            payment_endpoint_identifier: receipt.payment_endpoint_identifier.clone(),
            amount: receipt
                .amount
                .as_ref()
                .map(|amount| (amount.value.clone(), amount.currency.clone())),
            metadata: serde_json::to_string(&receipt.metadata)
                .map_err(|_| PersistenceError::InvalidInput)?,
            issued_at: receipt.issued_at,
        })
        .map_err(|_| PersistenceError::InvalidInput)?;
        let envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::marketplace_seller_receipt(creator_hash, invoice_id),
                &plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let inserted = sqlx::query(
            "INSERT INTO marketplace_seller_receipts
             (preparation_id, creator_id, receipt_lookup_hash, receipt_envelope)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (preparation_id) DO NOTHING",
        )
        .bind(invoice_id)
        .bind(creator_id)
        .bind(receipt_hash.as_bytes().as_slice())
        .bind(envelope.as_bytes())
        .execute(&self.pool)
        .await
        .map_err(|error| match error {
            sqlx::Error::Database(_) => PersistenceError::CorruptOrMissing,
            _ => PersistenceError::Unavailable,
        })?;
        if inserted.rows_affected() == 1 {
            return Ok(SellerReceiptStored::Stored);
        }
        let stored: Vec<u8> = sqlx::query_scalar(
            "SELECT receipt_lookup_hash FROM marketplace_seller_receipts
             WHERE preparation_id = $1 AND creator_id = $2",
        )
        .bind(invoice_id)
        .bind(creator_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if stored_hash(&stored)? == receipt_hash {
            Ok(SellerReceiptStored::Unchanged)
        } else {
            Ok(SellerReceiptStored::KeptFirst)
        }
    }

    async fn seller_receipt_snapshot(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<Option<StoredSellerReceipt>>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let Some(row) = sqlx::query_as::<_, SellerReceiptRow>(
            "SELECT creators.creator_lookup_hash, receipt.receipt_envelope,
                    receipt.receipt_lookup_hash, receipt.stored_at
             FROM marketplace_payment_preparations preparation
             JOIN creators ON creators.id = preparation.creator_id
             LEFT JOIN marketplace_seller_receipts receipt
               ON receipt.preparation_id = preparation.id
              AND receipt.creator_id = preparation.creator_id
             WHERE preparation.id = $1 AND creators.creator_lookup_hash = $2",
        )
        .bind(invoice_id)
        .bind(creator_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        else {
            return Ok(None);
        };
        if stored_hash(&row.creator_lookup_hash)? != creator_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let (Some(envelope), Some(receipt_hash), Some(stored_at)) =
            (row.receipt_envelope, row.receipt_lookup_hash, row.stored_at)
        else {
            return Ok(Some(None));
        };
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::marketplace_seller_receipt(creator_hash, invoice_id),
                &EncryptedEnvelope::from_bytes(envelope),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let stored: SellerReceiptEnvelopeV1 =
            postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
        if stored.version != 1
            || self
                .crypto
                .seller_receipt_lookup_hash(stored.receipt_id.as_bytes())
                != stored_hash(&receipt_hash)?
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let metadata: Map<String, Value> = serde_json::from_str(&stored.metadata)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        Ok(Some(Some(StoredSellerReceipt {
            receipt: SellerReceipt {
                receipt_id: stored.receipt_id,
                app_id: stored.app_id,
                payment_request_id: stored.payment_request_id,
                payment_reference: stored.payment_reference,
                payment_endpoint_identifier: stored.payment_endpoint_identifier,
                amount: stored
                    .amount
                    .map(|(value, currency)| SellerReceiptAmount { value, currency }),
                metadata,
                issued_at: stored.issued_at,
            },
            stored_at,
        })))
    }
}

#[async_trait::async_trait]
impl MarketplaceReceiptPersistence for MarketplacePreparationStore {
    async fn seller_receipt(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<Option<StoredSellerReceipt>>, MarketplaceReceiptError> {
        self.seller_receipt_snapshot(creator, invoice_id)
            .await
            .map_err(|_| MarketplaceReceiptError::Unavailable)
    }
}
