//! Invoice attribution for authenticated Paykit USDT evidence.

use super::*;
use crate::usdt::{
    ArbitrumVerifier, MAX_SCAN_CANDIDATES, PaymentCandidate, PaymentContext, VerificationError,
    VerifiedTransfer,
};
use paykit_sdk::{PaymentProofRecord, PaymentRequestLocalRole, PaymentRequestRecord};

#[derive(Serialize, Deserialize)]
struct TransferFacts {
    identity: String,
    amount: u64,
    timestamp: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct UsdtObservationRow {
    id: Uuid,
    observation_envelope: Vec<u8>,
    transfer_lookup_hash: Vec<u8>,
    confirmations: i32,
    finalized: bool,
}

#[derive(sqlx::FromRow)]
pub(super) struct UsdtInvoiceRow {
    pub(super) id: Uuid,
    pub(super) creator_lookup_hash: Vec<u8>,
    pub(super) payment_record_envelope: Vec<u8>,
    pub(super) invoice_envelope: Vec<u8>,
    pub(super) invoice_created_at: OffsetDateTime,
    pub(super) payment_deadline: OffsetDateTime,
}

impl InvoiceStore {
    pub(super) async fn scan_usdt_observation_integrity(&self) -> Result<(), PersistenceError> {
        let rows = sqlx::query_as::<_, (Uuid, Uuid, Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT o.id, o.invoice_id, c.creator_lookup_hash, o.observation_envelope, o.transfer_lookup_hash
             FROM usdt_observations o JOIN invoices i ON i.id=o.invoice_id JOIN creators c ON c.id=i.creator_id")
            .fetch_all(&self.pool).await.map_err(|_| PersistenceError::Unavailable)?;
        for (id, invoice, creator_hash, envelope, identity_hash) in rows {
            let creator_hash = lookup_hash(&creator_hash)?;
            self.transfer_facts(id, invoice, creator_hash, envelope, identity_hash)?;
        }
        Ok(())
    }

    fn transfer_facts(
        &self,
        id: Uuid,
        invoice: Uuid,
        creator_hash: LookupHash,
        envelope: Vec<u8>,
        identity_hash: Vec<u8>,
    ) -> Result<(TransferFacts, Option<[u8; 20]>), PersistenceError> {
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::usdt_observation(creator_hash, id, invoice),
                &EncryptedEnvelope::from_bytes(envelope),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let (facts, suffix): (TransferFacts, _) = postcard::take_from_bytes(&plaintext)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        // Existing envelopes contain only facts; verified refreshes append the attested sender.
        let sender = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .try_into()
                    .map_err(|_| PersistenceError::CorruptOrMissing)?,
            )
        };
        if identity_hash
            != self
                .crypto
                .usdt_transfer_lookup_hash(facts.identity.as_bytes())
                .as_bytes()
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok((facts, sender))
    }

    /// Resolves invoices only through their already-attributed SDK lifecycle record.
    /// Background scans defer present observations for a minute; bundle status reads are fresh.
    pub async fn observe_usdt_request(
        &self,
        creator_id: Uuid,
        creator: &CreatorPubky,
        record: &PaymentRequestRecord,
        verifier: &ArbitrumVerifier,
        bundle: Option<&BundleId>,
    ) -> Result<(), PersistenceError> {
        if record.local_role != Some(PaymentRequestLocalRole::Payee) {
            return Ok(());
        }
        let row: Option<UsdtInvoiceRow> = sqlx::query_as(
            "SELECT i.id, c.creator_lookup_hash, i.payment_record_envelope, i.invoice_envelope,
                    i.invoice_created_at, i.payment_deadline
             FROM invoices i JOIN creators c ON c.id = i.creator_id
             JOIN payment_request_lifecycles l ON l.invoice_id = i.id
             WHERE i.creator_id = $1 AND l.sdk_payment_request_id = $2 AND ($3::BYTEA IS NULL OR i.bundle_lookup_hash = $3)")
            .bind(creator_id).bind(&record.payment_request_id)
            .bind(bundle.map(|id| self.crypto.lookup_hash(id.to_string().as_bytes()).as_bytes().to_vec())).fetch_optional(&self.pool).await
            .map_err(|_| PersistenceError::Unavailable)?;
        let Some(row) = row else {
            return Ok(());
        };
        let creator_hash = lookup_hash(&row.creator_lookup_hash)?;
        if creator_hash != self.crypto.lookup_hash(creator.to_string().as_bytes()) {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let payment: InvoicePaymentRecordV1 = postcard::from_bytes(
            &self
                .crypto
                .decrypt(
                    &EnvelopeContext::invoice_payment_record(creator_hash, row.id),
                    &EncryptedEnvelope::from_bytes(row.payment_record_envelope.clone()),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let Some(destination) = &payment.usdt else {
            return Ok(());
        };
        let intent: DeliveryIntentV1 = postcard::from_bytes(
            &self
                .crypto
                .decrypt(
                    &EnvelopeContext::invoice(creator_hash, row.id),
                    &EncryptedEnvelope::from_bytes(row.invoice_envelope.clone()),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let terms = intent
            .terms()
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payer = record.counterparty.to_string();
        if intent.reader_pubky() != format!("pubky{payer}") {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let payee = creator.to_string();
        let payee = payee
            .strip_prefix("pubky")
            .ok_or(PersistenceError::CorruptOrMissing)?;
        let recipient = UsdtAddress::try_from(destination.address.clone())
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let context = PaymentContext {
            payer: &payer,
            payee,
            request_id: &record.payment_request_id,
            reference: &terms.payment_reference,
            recipient: &recipient,
        };
        let scan = verifier
            .payment_scan(&context, &record.payment_proofs)
            .await;
        let mut candidates = if bundle.is_some() || scan.is_none() {
            self.owned_usdt_candidates(
                &row,
                creator_hash,
                &payment,
                bundle.is_some(),
                &context,
                &record.payment_proofs,
            )
            .await?
        } else {
            Vec::new()
        };
        if let Some(scan) = &scan {
            for candidate in &scan.candidates {
                if candidates.len() == MAX_SCAN_CANDIDATES {
                    break;
                }
                if !candidates
                    .iter()
                    .any(|owned| owned.identity == candidate.identity)
                {
                    candidates.push(candidate.clone());
                }
            }
        }
        let mut observed = std::collections::HashSet::new();
        for candidate in &candidates {
            let identity = &candidate.identity;
            let identity_hash = self.crypto.usdt_transfer_lookup_hash(identity.as_bytes());
            let existing: Option<(bool, bool, bool)> = sqlx::query_as(
                "SELECT COALESCE(finalized OR ($2 AND invoice_id = $3 AND present
                    AND checked_at <= NOW() AND checked_at > NOW() - INTERVAL '1 minute'), FALSE),
                    present, COALESCE(invoice_id = $3, FALSE)
                 FROM usdt_observations WHERE transfer_lookup_hash = $1",
            )
            .bind(identity_hash.as_bytes().as_slice())
            .bind(bundle.is_none() && scan.is_some())
            .bind(row.id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            if existing.is_some_and(|(_, _, owned)| !owned) {
                continue;
            }
            if existing.is_some_and(|(skip, _, _)| skip) {
                observed.insert(identity.as_str());
                continue;
            }
            if existing.is_some() {
                // Reserve before RPC so failures and restarts retain the refresh interval.
                let reserved = sqlx::query(
                    "UPDATE usdt_observations SET checked_at = NOW()
                     WHERE invoice_id = $1 AND transfer_lookup_hash = $2 AND NOT finalized
                       AND ($3 OR checked_at > NOW() OR checked_at <= NOW() -
                         CASE WHEN present THEN INTERVAL '1 minute' ELSE INTERVAL '15 seconds' END)")
                    .bind(row.id).bind(identity_hash.as_bytes().as_slice()).bind(bundle.is_some())
                    .execute(&self.pool).await.map_err(|_| PersistenceError::Unavailable)?;
                if reserved.rows_affected() == 0 {
                    continue;
                }
            }
            let verified = match verifier.verify_candidate(&context, candidate).await {
                Ok(value) => value,
                Err(VerificationError::InvalidProof) => None,
                Err(VerificationError::Unavailable) => return Err(PersistenceError::Unavailable),
            };
            match verified {
                Some(transfer) => {
                    if self
                        .apply_usdt_transfer(&row, creator_hash, &payment, transfer)
                        .await?
                    {
                        observed.insert(identity.as_str());
                    }
                }
                None => {
                    if !existing.is_some_and(|(_, present, owned)| present && owned) {
                        continue;
                    }
                    self.clear_usdt_transfer(&row, creator_hash, &payment, &identity_hash)
                        .await?;
                }
            }
        }
        if let Some(scan) = &scan {
            verifier
                .finish_payment_scan(
                    scan,
                    scan.candidates
                        .iter()
                        .all(|candidate| observed.contains(candidate.identity.as_str())),
                )
                .await;
        }
        if bundle.is_some() {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            let selected = self
                .usdt_payment(&mut tx, &row, creator_hash, destination.required_amount)
                .await?;
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            // A bounded pass must not report an unrefreshed receipt as fresh payment status.
            if selected.is_some_and(|(identity, payment)| {
                !payment.finalized && !observed.contains(identity.as_str())
            }) {
                return Err(PersistenceError::Unavailable);
            }
        }
        Ok(())
    }

    async fn owned_usdt_candidates(
        &self,
        row: &UsdtInvoiceRow,
        creator_hash: LookupHash,
        payment: &InvoicePaymentRecordV1,
        force: bool,
        context: &PaymentContext<'_>,
        proofs: &[PaymentProofRecord],
    ) -> Result<Vec<PaymentCandidate>, PersistenceError> {
        let preferred = if force {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            let selected = self
                .usdt_payment(
                    &mut tx,
                    row,
                    creator_hash,
                    payment
                        .usdt
                        .as_ref()
                        .ok_or(PersistenceError::CorruptOrMissing)?
                        .required_amount,
                )
                .await?;
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            selected.map(|(identity, _)| {
                self.crypto
                    .usdt_transfer_lookup_hash(identity.as_bytes())
                    .as_bytes()
                    .to_vec()
            })
        } else {
            None
        };
        let observations: Vec<UsdtObservationRow> = sqlx::query_as(
            "SELECT id, observation_envelope, transfer_lookup_hash, confirmations, finalized
             FROM usdt_observations WHERE invoice_id = $1 AND NOT finalized
               AND ($2 OR checked_at > NOW() OR checked_at <= NOW() -
                 CASE WHEN present THEN INTERVAL '1 minute' ELSE INTERVAL '15 seconds' END)
             ORDER BY COALESCE(transfer_lookup_hash = $4, FALSE) DESC, present DESC, checked_at, id LIMIT $3",
        )
        .bind(row.id)
        .bind(force)
        .bind(MAX_SCAN_CANDIDATES as i64)
        .bind(preferred)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let mut candidates = Vec::new();
        let mut legacy_candidates = None;
        for observation in observations {
            let (facts, sender) = self.transfer_facts(
                observation.id,
                row.id,
                creator_hash,
                observation.observation_envelope,
                observation.transfer_lookup_hash,
            )?;
            let candidate = if let Some(sender) = sender {
                Some(
                    PaymentCandidate::from_observation(&facts.identity, sender)
                        .map_err(|_| PersistenceError::CorruptOrMissing)?,
                )
            } else {
                if legacy_candidates.is_none() {
                    legacy_candidates = PaymentCandidate::from_proofs(context, proofs);
                }
                legacy_candidates
                    .as_ref()
                    .and_then(|candidates| candidates.get(&facts.identity))
                    .cloned()
            };
            if let Some(candidate) = candidate {
                candidates.push(candidate);
            } else {
                // Unsupported histories cannot sustain nonfinal credit without an attestation anchor.
                let identity_hash = self
                    .crypto
                    .usdt_transfer_lookup_hash(facts.identity.as_bytes());
                self.clear_usdt_transfer(row, creator_hash, payment, &identity_hash)
                    .await?;
            }
        }
        Ok(candidates)
    }

    async fn clear_usdt_transfer(
        &self,
        row: &UsdtInvoiceRow,
        creator_hash: LookupHash,
        payment: &InvoicePaymentRecordV1,
        identity_hash: &LookupHash,
    ) -> Result<(), PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("SELECT id FROM invoices WHERE id = $1 FOR UPDATE")
            .bind(row.id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("UPDATE usdt_observations SET present = FALSE, confirmations = 0, checked_at = NOW() WHERE invoice_id = $1 AND transfer_lookup_hash = $2 AND NOT finalized")
            .bind(row.id).bind(identity_hash.as_bytes().as_slice()).execute(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?;
        self.project_payments(
            &mut tx,
            row.id,
            creator_hash,
            payment,
            OffsetDateTime::now_utc(),
        )
        .await?;
        tx.commit().await.map_err(|_| PersistenceError::Unavailable)
    }

    async fn apply_usdt_transfer(
        &self,
        row: &UsdtInvoiceRow,
        creator_hash: LookupHash,
        payment: &InvoicePaymentRecordV1,
        transfer: VerifiedTransfer,
    ) -> Result<bool, PersistenceError> {
        let transfer_hash = self
            .crypto
            .usdt_transfer_lookup_hash(transfer.identity.as_bytes());
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("SELECT id FROM invoices WHERE id = $1 FOR UPDATE")
            .bind(row.id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let existing: Option<(Uuid, Option<Uuid>, bool)> = sqlx::query_as(
            "SELECT id, invoice_id, finalized FROM usdt_observations WHERE transfer_lookup_hash = $1 FOR UPDATE")
            .bind(transfer_hash.as_bytes().as_slice()).fetch_optional(&mut *tx).await
            .map_err(|_| PersistenceError::Unavailable)?;
        if let Some((_, invoice_id, finalized)) = existing {
            if invoice_id != Some(row.id) {
                return Ok(false);
            }
            if finalized {
                return Ok(true);
            }
        }
        let id = existing.map(|(id, _, _)| id).unwrap_or_else(Uuid::new_v4);
        let facts = TransferFacts {
            identity: transfer.identity,
            amount: transfer.amount,
            timestamp: transfer.timestamp,
        };
        let envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::usdt_observation(creator_hash, id, row.id),
                &postcard::to_allocvec(&(facts, transfer.sender))
                    .map_err(|_| PersistenceError::CorruptOrMissing)?,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let confirmations =
            i32::try_from(transfer.confirmations).map_err(|_| PersistenceError::InvalidInput)?;
        // The unique transfer identity also fences simultaneous proofs for different invoices.
        let owner: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO usdt_observations (id, invoice_id, transfer_lookup_hash, observation_envelope, confirmations, present, finalized)
             VALUES ($1,$2,$3,$4,$5,TRUE,$6)
             ON CONFLICT (transfer_lookup_hash) DO UPDATE SET
                observation_envelope = CASE WHEN usdt_observations.invoice_id = EXCLUDED.invoice_id THEN EXCLUDED.observation_envelope ELSE usdt_observations.observation_envelope END,
                confirmations = CASE WHEN usdt_observations.invoice_id = EXCLUDED.invoice_id THEN EXCLUDED.confirmations ELSE usdt_observations.confirmations END,
                present = CASE WHEN usdt_observations.invoice_id = EXCLUDED.invoice_id THEN TRUE ELSE usdt_observations.present END,
                checked_at = CASE WHEN usdt_observations.invoice_id = EXCLUDED.invoice_id THEN NOW() ELSE usdt_observations.checked_at END,
                finalized = CASE WHEN usdt_observations.invoice_id = EXCLUDED.invoice_id THEN EXCLUDED.finalized ELSE usdt_observations.finalized END
             RETURNING invoice_id")
            .bind(id).bind(row.id).bind(transfer_hash.as_bytes().as_slice()).bind(envelope.as_bytes())
            .bind(confirmations).bind(transfer.finalized).fetch_one(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?;
        if owner != Some(row.id) {
            return Ok(false);
        }
        self.project_payments(
            &mut tx,
            row.id,
            creator_hash,
            payment,
            OffsetDateTime::now_utc(),
        )
        .await?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(true)
    }

    pub(super) async fn usdt_payment(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        row: &UsdtInvoiceRow,
        creator_hash: LookupHash,
        required: u64,
    ) -> Result<Option<(String, super::settlement::ObservedPayment)>, PersistenceError> {
        let observations: Vec<UsdtObservationRow> = sqlx::query_as(
            "SELECT id, observation_envelope, transfer_lookup_hash, confirmations, finalized FROM usdt_observations WHERE invoice_id = $1 AND present")
            .bind(row.id).fetch_all(&mut **tx).await.map_err(|_| PersistenceError::Unavailable)?;
        let mut selected: Option<(String, super::settlement::ObservedPayment)> = None;
        for observation in observations {
            let (facts, _) = self.transfer_facts(
                observation.id,
                row.id,
                creator_hash,
                observation.observation_envelope,
                observation.transfer_lookup_hash,
            )?;
            let timely = facts.timestamp
                >= row
                    .invoice_created_at
                    .replace_nanosecond(0)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?
                && facts.timestamp <= row.payment_deadline;
            let candidate = super::settlement::ObservedPayment {
                present: true,
                matched: facts.amount >= required,
                timely,
                confirmations: observation.confirmations,
                finalized: observation.finalized,
                received_at: Some(facts.timestamp.max(row.invoice_created_at)),
            };
            // Choose one receipt, never combine partial transfers. A final qualifying
            // receipt must not be hidden by a newer unfinalized receipt.
            let rank = |payment: &super::settlement::ObservedPayment| {
                (
                    payment.eligible(),
                    payment.finalized,
                    payment.matched,
                    payment.confirmations,
                )
            };
            if selected.as_ref().is_none_or(|(identity, current)| {
                (rank(&candidate), &facts.identity) > (rank(current), identity)
            }) {
                selected = Some((facts.identity, candidate));
            }
        }
        Ok(selected)
    }

    pub(super) async fn usdt_payment_status(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        invoice: Uuid,
    ) -> Result<Option<UsdtPaymentStatus>, PersistenceError> {
        let row: Option<UsdtInvoiceRow> = sqlx::query_as(
            "SELECT i.id, c.creator_lookup_hash, i.payment_record_envelope, i.invoice_envelope,
                    i.invoice_created_at, i.payment_deadline
             FROM invoices i JOIN creators c ON c.id = i.creator_id
             WHERE i.id = $1 AND EXISTS (SELECT 1 FROM usdt_observations WHERE invoice_id = i.id AND present)")
            .bind(invoice).fetch_optional(&mut **tx).await.map_err(|_| PersistenceError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let creator_hash = lookup_hash(&row.creator_lookup_hash)?;
        let payment: InvoicePaymentRecordV1 = postcard::from_bytes(
            &self
                .crypto
                .decrypt(
                    &EnvelopeContext::invoice_payment_record(creator_hash, row.id),
                    &EncryptedEnvelope::from_bytes(row.payment_record_envelope.clone()),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let destination = payment
            .usdt
            .as_ref()
            .ok_or(PersistenceError::CorruptOrMissing)?;
        self.usdt_payment(tx, &row, creator_hash, destination.required_amount)
            .await?
            .map(|(_, payment)| {
                Ok(UsdtPaymentStatus {
                    confirmations: u32::try_from(payment.confirmations)
                        .map_err(|_| PersistenceError::CorruptOrMissing)?,
                    amount_matched: payment.matched,
                    paid_on_time: payment.eligible(),
                    finalized: payment.finalized,
                })
            })
            .transpose()
    }
}
