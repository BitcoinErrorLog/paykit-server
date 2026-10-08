//! Contact work is committed with verified payment facts, not with buyer-supplied proofs.

use super::*;

/// A verified buyer awaiting private contact resolution. Identifiers must not be logged.
pub struct PendingBuyerContact {
    pub invoice_id: Uuid,
    pub creator_id: Uuid,
    pub reader: ReaderPubky,
}

#[derive(sqlx::FromRow)]
struct BuyerContactRow {
    invoice_id: Uuid,
    creator_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    reader_lookup_hash: Vec<u8>,
    invoice_envelope: Vec<u8>,
}

impl InvoiceStore {
    /// Claims one due contact attempt. Failed or interrupted attempts become due after a minute.
    /// This schedules work only; completion must be rechecked under the shared-state lock.
    pub async fn claim_buyer_contact(
        &self,
    ) -> Result<Option<PendingBuyerContact>, PersistenceError> {
        let row = sqlx::query_as::<_, BuyerContactRow>(
            "WITH candidate AS (
                 SELECT invoice_id FROM buyer_contacts
                 WHERE completed_at IS NULL AND next_attempt_at <= NOW()
                 ORDER BY next_attempt_at, invoice_id
                 FOR UPDATE SKIP LOCKED LIMIT 1
             ), claimed AS (
                 UPDATE buyer_contacts AS contact SET next_attempt_at = NOW() + INTERVAL '1 minute'
                 FROM candidate WHERE contact.invoice_id = candidate.invoice_id
                 RETURNING contact.invoice_id, contact.creator_id, contact.reader_lookup_hash
             )
             SELECT claimed.*, creators.creator_lookup_hash, invoices.invoice_envelope
             FROM claimed
             JOIN creators ON creators.id = claimed.creator_id
             JOIN invoices ON invoices.id = claimed.invoice_id AND invoices.creator_id = claimed.creator_id
                 AND invoices.reader_lookup_hash = claimed.reader_lookup_hash",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        row.map(|row| {
            let creator_hash = lookup_hash(&row.creator_lookup_hash)?;
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::invoice(creator_hash, row.invoice_id),
                    &EncryptedEnvelope::from_bytes(row.invoice_envelope),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let intent = DeliveryIntentV1::decode(&plaintext)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let reader = parse_reader(intent.reader_pubky())
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            if self
                .crypto
                .lookup_hash(reader.to_string().as_bytes())
                .as_bytes()
                .as_slice()
                != row.reader_lookup_hash
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
            Ok(PendingBuyerContact {
                invoice_id: row.invoice_id,
                creator_id: row.creator_id,
                reader,
            })
        })
        .transpose()
    }

    /// Checks that a claimed attempt still needs saving. Call under the Creator's
    /// shared-state lock and retain that lock through saving and completion.
    pub async fn buyer_contact_is_pending(
        &self,
        pending: &PendingBuyerContact,
    ) -> Result<bool, PersistenceError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM buyer_contacts
             WHERE invoice_id = $1 AND creator_id = $2 AND reader_lookup_hash = $3
                 AND completed_at IS NULL)",
        )
        .bind(pending.invoice_id)
        .bind(pending.creator_id)
        .bind(
            self.crypto
                .lookup_hash(pending.reader.to_string().as_bytes())
                .as_bytes()
                .as_slice(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// Retains a terminal record while the caller still holds the shared-state lock.
    pub async fn complete_buyer_contact(
        &self,
        pending: &PendingBuyerContact,
    ) -> Result<(), PersistenceError> {
        sqlx::query("UPDATE buyer_contacts SET completed_at = COALESCE(completed_at, NOW()) WHERE invoice_id = $1 AND creator_id = $2 AND reader_lookup_hash = $3")
            .bind(pending.invoice_id).bind(pending.creator_id)
            .bind(self.crypto.lookup_hash(pending.reader.to_string().as_bytes()).as_bytes().as_slice())
            .execute(&self.pool).await.map_err(|_| PersistenceError::Unavailable)?;
        Ok(())
    }
}
