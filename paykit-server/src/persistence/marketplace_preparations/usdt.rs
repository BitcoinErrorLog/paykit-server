//! Marketplace attribution of authenticated Paykit USDT evidence.

use paykit_sdk::{PaymentRequestLocalRole, PaymentRequestRecord};

use super::*;
use crate::{
    application::marketplace_status::MarketplaceUsdtStatus,
    domain::receiving::USDT_CHAIN_ID,
    usdt::{
        ArbitrumVerifier, MAX_SCAN_CANDIDATES, PaymentCandidate, PaymentContext, VerificationError,
        VerifiedTransfer,
    },
};

/// Facts of one verified ERC-20 receipt. The identity is `chain:transaction:log_index`.
#[derive(Serialize, Deserialize)]
struct MarketplaceUsdtFacts {
    identity: String,
    amount: u64,
    timestamp: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct UsdtTarget {
    preparation_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    payment_record_envelope: Vec<u8>,
    preparation_envelope: Vec<u8>,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
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
struct ScannedReceipt {
    preparation_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    id: Uuid,
    observation_envelope: Vec<u8>,
    transfer_lookup_hash: Vec<u8>,
    confirmations: i32,
    finalized: bool,
}

impl MarketplacePreparationStore {
    /// Attributes verified USDT evidence to an active Marketplace settlement only through
    /// its already-attributed SDK lifecycle record, never by a caller-nominated owner.
    pub async fn observe_usdt_request(
        &self,
        creator_id: Uuid,
        creator: &CreatorPubky,
        record: &PaymentRequestRecord,
        verifier: &ArbitrumVerifier,
    ) -> Result<(), PersistenceError> {
        if record.local_role != Some(PaymentRequestLocalRole::Payee) {
            return Ok(());
        }
        let target: Option<UsdtTarget> = sqlx::query_as(
            "SELECT settlement.preparation_id, creators.creator_lookup_hash,
                    settlement.payment_record_envelope,
                    preparation.preparation_envelope,
                    preparation.prepared_at, preparation.prepare_expires_at
             FROM payment_request_lifecycles lifecycle
             JOIN marketplace_settlements settlement
               ON settlement.preparation_id = lifecycle.marketplace_preparation_id
             JOIN marketplace_payment_preparations preparation
               ON preparation.id = settlement.preparation_id
              AND preparation.creator_id = settlement.creator_id
             JOIN creators ON creators.id = settlement.creator_id
             WHERE settlement.creator_id = $1
               AND lifecycle.sdk_payment_request_id = $2
               AND preparation.state = 'active'",
        )
        .bind(creator_id)
        .bind(&record.payment_request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(target) = target else {
            return Ok(());
        };
        let creator_hash = stored_hash(&target.creator_lookup_hash)?;
        if creator_hash != self.crypto.lookup_hash(creator.to_string().as_bytes()) {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let payment = self.decrypt_settlement_payment_record(
            creator_hash,
            target.preparation_id,
            target.payment_record_envelope.clone(),
        )?;
        let Some(recipient) = payment.usdt_address()? else {
            return Ok(());
        };
        let envelope = self.decode_preparation_envelope(creator_hash, &target)?;
        let terms = envelope
            .payment_request_intent
            .terms()
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payer = record.counterparty.to_string();
        if envelope.payment_request_intent.reader_pubky() != format!("pubky{payer}") {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let payee = creator.to_string();
        let payee = payee
            .strip_prefix("pubky")
            .ok_or(PersistenceError::CorruptOrMissing)?;
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
        let owned_candidates;
        let candidates = match &scan {
            Some(scan) => &scan.candidates,
            None => {
                owned_candidates = self.owned_usdt_candidates(&target, creator_hash).await?;
                &owned_candidates
            }
        };
        let mut observed = 0;
        for candidate in candidates {
            let identity = &candidate.identity;
            let identity_hash = self.crypto.usdt_transfer_lookup_hash(identity.as_bytes());
            let existing: Option<(bool, bool, bool)> = sqlx::query_as(
                "SELECT COALESCE(finalized OR ($3 AND marketplace_preparation_id = $2 AND present
                    AND checked_at <= NOW() AND checked_at > NOW() - INTERVAL '1 minute'), FALSE),
                    present, COALESCE(marketplace_preparation_id = $2, FALSE)
                 FROM usdt_observations WHERE transfer_lookup_hash = $1",
            )
            .bind(identity_hash.as_bytes().as_slice())
            .bind(target.preparation_id)
            .bind(scan.is_some())
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            if existing.is_some_and(|(_, _, owned)| !owned) {
                continue;
            }
            if existing.is_some_and(|(skip, _, _)| skip) {
                observed += 1;
                continue;
            }
            if existing.is_some() {
                // Reserve before RPC so failures and restarts retain the refresh interval.
                let reserved = sqlx::query(
                    "UPDATE usdt_observations SET checked_at = NOW()
                     WHERE marketplace_preparation_id = $1 AND transfer_lookup_hash = $2 AND NOT finalized
                       AND (checked_at > NOW() OR checked_at <= NOW() -
                         CASE WHEN present THEN INTERVAL '1 minute' ELSE INTERVAL '15 seconds' END)")
                    .bind(target.preparation_id).bind(identity_hash.as_bytes().as_slice())
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
                    observed += usize::from(
                        self.apply_usdt_transfer(&target, creator_hash, transfer)
                            .await?,
                    );
                }
                None => {
                    if !existing.is_some_and(|(_, present, owned)| present && owned) {
                        continue;
                    }
                    self.clear_usdt_transfer(target.preparation_id, &identity_hash)
                        .await?;
                }
            }
        }
        if let Some(scan) = &scan {
            verifier
                .finish_payment_scan(scan, observed == candidates.len())
                .await;
        }
        Ok(())
    }

    async fn owned_usdt_candidates(
        &self,
        target: &UsdtTarget,
        creator_hash: LookupHash,
    ) -> Result<Vec<PaymentCandidate>, PersistenceError> {
        let observations: Vec<UsdtObservationRow> = sqlx::query_as(
            "SELECT id, observation_envelope, transfer_lookup_hash, confirmations, finalized
             FROM usdt_observations WHERE marketplace_preparation_id = $1 AND NOT finalized
               AND (checked_at > NOW() OR checked_at <= NOW() -
                 CASE WHEN present THEN INTERVAL '1 minute' ELSE INTERVAL '15 seconds' END)
             ORDER BY checked_at, id LIMIT $2",
        )
        .bind(target.preparation_id)
        .bind(MAX_SCAN_CANDIDATES as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let mut candidates = Vec::new();
        for observation in observations {
            let (facts, sender) =
                self.usdt_facts(creator_hash, target.preparation_id, &observation)?;
            if let Some(sender) = sender {
                candidates.push(
                    PaymentCandidate::from_observation(&facts.identity, sender)
                        .map_err(|_| PersistenceError::CorruptOrMissing)?,
                );
            } else {
                // Unsupported histories cannot sustain nonfinal credit without an attestation anchor.
                let identity_hash = self
                    .crypto
                    .usdt_transfer_lookup_hash(facts.identity.as_bytes());
                self.clear_usdt_transfer(target.preparation_id, &identity_hash)
                    .await?;
            }
        }
        Ok(candidates)
    }

    async fn clear_usdt_transfer(
        &self,
        preparation_id: Uuid,
        identity_hash: &LookupHash,
    ) -> Result<(), PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        lock_active_settlement(&mut tx, preparation_id).await?;
        sqlx::query("UPDATE usdt_observations SET present = FALSE, confirmations = 0, checked_at = NOW() WHERE marketplace_preparation_id = $1 AND transfer_lookup_hash = $2 AND NOT finalized")
            .bind(preparation_id).bind(identity_hash.as_bytes().as_slice()).execute(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?;
        tx.commit().await.map_err(|_| PersistenceError::Unavailable)
    }

    async fn apply_usdt_transfer(
        &self,
        target: &UsdtTarget,
        creator_hash: LookupHash,
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
        lock_active_settlement(&mut tx, target.preparation_id).await?;
        let existing: Option<(Uuid, Option<Uuid>, bool)> = sqlx::query_as(
            "SELECT id, marketplace_preparation_id, finalized FROM usdt_observations
             WHERE transfer_lookup_hash = $1 FOR UPDATE",
        )
        .bind(transfer_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if let Some((_, owner, finalized)) = existing {
            // The unique transfer identity fences a receipt owned elsewhere, and a
            // finalized receipt is never rewritten.
            if owner != Some(target.preparation_id) || finalized {
                return Ok(owner == Some(target.preparation_id));
            }
        }
        let id = existing.map_or_else(Uuid::new_v4, |(id, _, _)| id);
        let facts = MarketplaceUsdtFacts {
            identity: transfer.identity,
            amount: transfer.amount,
            timestamp: transfer.timestamp,
        };
        let envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::usdt_observation_for_marketplace(
                    creator_hash,
                    id,
                    target.preparation_id,
                ),
                &postcard::to_allocvec(&(facts, transfer.sender))
                    .map_err(|_| PersistenceError::CorruptOrMissing)?,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let confirmations =
            i32::try_from(transfer.confirmations).map_err(|_| PersistenceError::InvalidInput)?;
        let owner: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO usdt_observations
                 (id, marketplace_preparation_id, transfer_lookup_hash, observation_envelope,
                  confirmations, present, finalized)
             VALUES ($1, $2, $3, $4, $5, TRUE, $6)
             ON CONFLICT (transfer_lookup_hash) DO UPDATE SET
                observation_envelope = CASE WHEN usdt_observations.marketplace_preparation_id = EXCLUDED.marketplace_preparation_id THEN EXCLUDED.observation_envelope ELSE usdt_observations.observation_envelope END,
                confirmations = CASE WHEN usdt_observations.marketplace_preparation_id = EXCLUDED.marketplace_preparation_id THEN EXCLUDED.confirmations ELSE usdt_observations.confirmations END,
                present = CASE WHEN usdt_observations.marketplace_preparation_id = EXCLUDED.marketplace_preparation_id THEN TRUE ELSE usdt_observations.present END,
                checked_at = CASE WHEN usdt_observations.marketplace_preparation_id = EXCLUDED.marketplace_preparation_id THEN NOW() ELSE usdt_observations.checked_at END,
                finalized = CASE WHEN usdt_observations.marketplace_preparation_id = EXCLUDED.marketplace_preparation_id THEN EXCLUDED.finalized ELSE usdt_observations.finalized END
             RETURNING marketplace_preparation_id",
        )
        .bind(id)
        .bind(target.preparation_id)
        .bind(transfer_hash.as_bytes().as_slice())
        .bind(envelope.as_bytes())
        .bind(confirmations)
        .bind(transfer.finalized)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if owner != Some(target.preparation_id) {
            return Ok(false);
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(true)
    }

    fn decode_preparation_envelope(
        &self,
        creator_hash: LookupHash,
        target: &UsdtTarget,
    ) -> Result<PreparationEnvelope, PersistenceError> {
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::marketplace_preparation(creator_hash, target.preparation_id),
                &EncryptedEnvelope::from_bytes(target.preparation_envelope.clone()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let envelope = PreparationEnvelope::decode(&plaintext)?;
        if envelope.prepared_at != target.prepared_at
            || envelope.prepare_expires_at != target.prepare_expires_at
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok(envelope)
    }

    fn usdt_facts(
        &self,
        creator_hash: LookupHash,
        preparation_id: Uuid,
        row: &UsdtObservationRow,
    ) -> Result<(MarketplaceUsdtFacts, Option<[u8; 20]>), PersistenceError> {
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::usdt_observation_for_marketplace(
                    creator_hash,
                    row.id,
                    preparation_id,
                ),
                &EncryptedEnvelope::from_bytes(row.observation_envelope.clone()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let (facts, suffix): (MarketplaceUsdtFacts, _) = postcard::take_from_bytes(&plaintext)
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
        if row.transfer_lookup_hash
            != self
                .crypto
                .usdt_transfer_lookup_hash(facts.identity.as_bytes())
                .as_bytes()
            || row.confirmations < 0
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok((facts, sender))
    }

    /// Authenticates every Marketplace USDT receipt against its keyed identity hash.
    pub(super) async fn scan_usdt_observation_integrity(&self) -> Result<(), PersistenceError> {
        let rows: Vec<ScannedReceipt> = sqlx::query_as(
            "SELECT observation.marketplace_preparation_id AS preparation_id,
                    creators.creator_lookup_hash,
                    observation.id, observation.observation_envelope,
                    observation.transfer_lookup_hash, observation.confirmations,
                    observation.finalized
             FROM usdt_observations observation
             JOIN marketplace_settlements settlement
               ON settlement.preparation_id = observation.marketplace_preparation_id
             JOIN creators ON creators.id = settlement.creator_id
             ORDER BY observation.id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for row in rows {
            self.usdt_facts(
                stored_hash(&row.creator_lookup_hash)?,
                row.preparation_id,
                &UsdtObservationRow {
                    id: row.id,
                    observation_envelope: row.observation_envelope,
                    transfer_lookup_hash: row.transfer_lookup_hash,
                    confirmations: row.confirmations,
                    finalized: row.finalized,
                },
            )?;
        }
        Ok(())
    }

    /// The one present receipt to display, never a sum of partial transfers (a final
    /// qualifying receipt is not hidden by a newer unfinalized one), and separately the
    /// block time of the earliest present receipt that qualifies. Which rail was paid
    /// first must not depend on which receipt ranks highest for display.
    pub(super) async fn status_usdt(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        creator_hash: LookupHash,
        preparation_id: Uuid,
        payment: &InvoicePaymentRecordV1,
        activated_at: OffsetDateTime,
        payment_deadline: OffsetDateTime,
    ) -> Result<Option<(MarketplaceUsdtStatus, Option<OffsetDateTime>)>, PersistenceError> {
        let rows: Vec<UsdtObservationRow> = sqlx::query_as(
            "SELECT id, observation_envelope, transfer_lookup_hash, confirmations, finalized
             FROM usdt_observations
             WHERE marketplace_preparation_id = $1 AND present
             ORDER BY id",
        )
        .bind(preparation_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if !payment.has_usdt() {
            return if rows.is_empty() {
                Ok(None)
            } else {
                Err(PersistenceError::CorruptOrMissing)
            };
        }
        let required = payment.usdt_required_amount()?;
        // Chain time has one-second resolution; the window opens at the whole second
        // of activation, as for Locks invoices.
        let window_start = activated_at
            .replace_nanosecond(0)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let mut selected: Option<((bool, bool, bool, u32), MarketplaceUsdtStatus)> = None;
        let mut first_qualifying_at: Option<OffsetDateTime> = None;
        for row in rows {
            let (facts, _) = self.usdt_facts(creator_hash, preparation_id, &row)?;
            let confirmations =
                u32::try_from(row.confirmations).map_err(|_| PersistenceError::CorruptOrMissing)?;
            let amount_matched = facts.amount >= required;
            let paid_on_time = amount_matched
                && facts.timestamp >= window_start
                && facts.timestamp <= payment_deadline;
            if paid_on_time {
                first_qualifying_at = Some(
                    first_qualifying_at.map_or(facts.timestamp, |first| first.min(facts.timestamp)),
                );
            }
            let tx_hash = transaction_hash(&facts.identity)?;
            let rank = (paid_on_time, row.finalized, amount_matched, confirmations);
            let candidate = MarketplaceUsdtStatus::new(
                tx_hash,
                facts.amount,
                facts.timestamp,
                confirmations,
                amount_matched,
                paid_on_time,
                row.finalized,
            );
            if selected.as_ref().is_none_or(|(current, _)| rank > *current) {
                selected = Some((rank, candidate));
            }
        }
        Ok(selected.map(|(_, status)| (status, first_qualifying_at)))
    }
}

async fn lock_active_settlement(
    tx: &mut Transaction<'_, Postgres>,
    preparation_id: Uuid,
) -> Result<(), PersistenceError> {
    let locked: Option<Uuid> = sqlx::query_scalar(
        "SELECT settlement.preparation_id
         FROM marketplace_settlements settlement
         JOIN marketplace_payment_preparations preparation
           ON preparation.id = settlement.preparation_id
          AND preparation.creator_id = settlement.creator_id
         WHERE settlement.preparation_id = $1 AND preparation.state = 'active'
         FOR UPDATE OF settlement",
    )
    .bind(preparation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| PersistenceError::Unavailable)?;
    locked.map(|_| ()).ok_or(PersistenceError::CorruptOrMissing)
}

/// `chain:0xtransaction:log_index` to the canonical lowercase transaction hash.
fn transaction_hash(identity: &str) -> Result<String, PersistenceError> {
    let mut parts = identity.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(chain), Some(hash), Some(_), None)
            if chain == USDT_CHAIN_ID
                && hash.len() == 66
                && hash.starts_with("0x")
                && hash[2..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            Ok(hash.to_owned())
        }
        _ => Err(PersistenceError::CorruptOrMissing),
    }
}
