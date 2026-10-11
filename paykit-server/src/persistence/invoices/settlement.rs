//! One invoice may settle through either of its quoted payment options.

use super::*;

pub(super) struct ObservedPayment {
    pub present: bool,
    pub matched: bool,
    pub timely: bool,
    pub confirmations: i32,
    pub finalized: bool,
    pub received_at: Option<OffsetDateTime>,
}

impl ObservedPayment {
    pub(super) fn eligible(&self) -> bool {
        self.present && self.matched && self.timely
    }
}

impl InvoiceStore {
    /// Call with the invoice row locked. Rebuild from both chains so one observer cannot erase the other.
    pub(super) async fn project_payments(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        invoice: Uuid,
        creator_hash: LookupHash,
        payment: &InvoicePaymentRecordV1,
        now: OffsetDateTime,
    ) -> Result<(), PersistenceError> {
        let row: super::usdt::UsdtInvoiceRow = sqlx::query_as(
            "SELECT i.id, c.creator_lookup_hash, i.payment_record_envelope, i.invoice_envelope,
                i.invoice_created_at, i.payment_deadline FROM invoices i JOIN creators c ON c.id = i.creator_id WHERE i.id = $1")
            .bind(invoice).fetch_one(&mut **tx).await.map_err(|_| PersistenceError::Unavailable)?;
        let mut bitcoin = ObservedPayment {
            present: false,
            matched: false,
            timely: false,
            confirmations: 0,
            finalized: false,
            received_at: None,
        };
        if let Some(destination) = &payment.bitcoin {
            let observation: Option<BitcoinObservationRow> = sqlx::query_as(
                "SELECT id, invoice_id, marketplace_preparation_id,
                        observation_envelope, outpoint_lookup_hash, confirmations, present
                 FROM bitcoin_observations WHERE invoice_id = $1 AND active",
            )
            .bind(invoice)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            if let Some(observation) = observation {
                let facts = self.decrypt_observation(creator_hash, &observation)?;
                let matched =
                    observation.present && facts.observed_sats >= destination.required_amount;
                let timely: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM invoice_timely_amount_matched_outpoints WHERE invoice_id = $1 AND outpoint_lookup_hash = $2)")
                    .bind(invoice).bind(&observation.outpoint_lookup_hash).fetch_one(&mut **tx).await.map_err(|_| PersistenceError::Unavailable)?;
                bitcoin = ObservedPayment {
                    present: observation.present,
                    matched,
                    timely,
                    confirmations: if !observation.present {
                        0
                    } else if matched {
                        observation.confirmations.min(6)
                    } else {
                        observation.confirmations
                    },
                    finalized: false,
                    received_at: None,
                };
            }
        }
        let usdt = if let Some(destination) = &payment.usdt {
            self.usdt_payment(tx, &row, creator_hash, destination.required_amount)
                .await?
        } else {
            None
        };
        let eligible = bitcoin.eligible() || usdt.as_ref().is_some_and(ObservedPayment::eligible);
        let received_at = usdt
            .as_ref()
            .filter(|payment| payment.eligible())
            .and_then(|payment| payment.received_at);
        // Keep the Bitcoin projection chain-specific. USDT facts stay in its receipt observations.
        let status = if !bitcoin.present {
            "undetected"
        } else if bitcoin.confirmations == 0 {
            "detected"
        } else {
            "confirmed"
        };
        sqlx::query("UPDATE invoices SET payment_status = $2, confirmation_count = $3, amount_matched = $4,
            first_amount_matched_observed_at = LEAST(first_amount_matched_observed_at, $5),
            payment_expired_at = CASE WHEN $6 THEN NULL WHEN payment_deadline < $7 THEN COALESCE(payment_expired_at, $7) ELSE payment_expired_at END,
            updated_at = NOW() WHERE id = $1")
            .bind(invoice).bind(status).bind(bitcoin.confirmations).bind(bitcoin.matched)
            .bind(received_at).bind(eligible).bind(now)
            .execute(&mut **tx).await.map_err(|_| PersistenceError::Unavailable)?;
        if eligible {
            sqlx::query(
                "INSERT INTO buyer_contacts (invoice_id, creator_id, reader_lookup_hash)
                 SELECT id, creator_id, reader_lookup_hash FROM invoices WHERE id = $1
                 ON CONFLICT (creator_id, reader_lookup_hash) DO NOTHING",
            )
            .bind(invoice)
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        Ok(())
    }
}
