//! Contact work is committed with verified payment facts, not with buyer-supplied proofs.

use super::*;

/// A verified buyer awaiting private contact resolution. Identifiers must not be logged.
pub struct PendingBuyerContact {
    pub invoice_id: Uuid,
    pub creator_id: Uuid,
    pub reader: ReaderPubky,
    pub(crate) claimed_next_attempt_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct BuyerContactRow {
    invoice_id: Uuid,
    creator_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    reader_lookup_hash: Vec<u8>,
    invoice_envelope: Vec<u8>,
    next_attempt_at: OffsetDateTime,
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
                 WHERE completed_at IS NULL AND next_attempt_at <= clock_timestamp()
                 ORDER BY next_attempt_at, invoice_id
                 FOR UPDATE SKIP LOCKED LIMIT 1
             ), claimed AS (
                 UPDATE buyer_contacts AS contact
                 SET next_attempt_at = clock_timestamp() + INTERVAL '1 minute'
                 FROM candidate WHERE contact.invoice_id = candidate.invoice_id
                 RETURNING contact.invoice_id, contact.creator_id,
                           contact.reader_lookup_hash, contact.next_attempt_at
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
                claimed_next_attempt_at: row.next_attempt_at,
            })
        })
        .transpose()
    }

    /// Restores an unstarted buyer-contact schedule when admission closes during the
    /// awaited claim, guarded by the exact claimed `next_attempt_at` timestamp and
    /// `completed_at IS NULL` so a concurrent replacement update is never overwritten.
    pub async fn release_unstarted_buyer_contact(
        &self,
        pending: &PendingBuyerContact,
    ) -> Result<bool, PersistenceError> {
        let updated = sqlx::query(
            "UPDATE buyer_contacts
             SET next_attempt_at = clock_timestamp()
             WHERE invoice_id = $1
               AND creator_id = $2
               AND completed_at IS NULL
               AND next_attempt_at = $3",
        )
        .bind(pending.invoice_id)
        .bind(pending.creator_id)
        .bind(pending.claimed_next_attempt_at)
        .execute(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(updated.rows_affected() == 1)
    }

    /// Checks that a claimed attempt still needs saving. Call under the Creator's
    /// shared-state lock and retain that lock through saving and completion.
    ///
    /// A contact backed by a timely Bitcoin payment is always due. One created
    /// from USDT alone is due only while that payment still qualifies under the
    /// current window, so a contact queued before the proposal-time bound
    /// existed waits until its proposal time is recorded, and stays held if its
    /// transfer predates the bound. It is held, not deleted.
    pub async fn buyer_contact_is_pending(
        &self,
        pending: &PendingBuyerContact,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let open: bool = sqlx::query_scalar(
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
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(open
            && self
                .contact_payment_qualifies(&mut tx, pending.invoice_id)
                .await?)
    }

    /// Whether `invoice`'s payment backs a buyer contact now: a timely Bitcoin
    /// payment always does, and a USDT one only while it qualifies under the
    /// current window.
    pub(super) async fn contact_payment_qualifies(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        invoice: Uuid,
    ) -> Result<bool, PersistenceError> {
        let bitcoin_backed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM invoice_timely_amount_matched_outpoints
             WHERE invoice_id = $1)",
        )
        .bind(invoice)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if bitcoin_backed {
            return Ok(true);
        }
        Ok(self
            .usdt_payment_status(tx, invoice)
            .await?
            .is_some_and(|usdt| usdt.paid_on_time))
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
