use super::*;

use crate::application::payment_request_status::{BitcoinPaymentStatus, UsdtPaymentStatus};
use crate::domain::{
    payment_request_lifecycle::PaymentRequestLifecycleState,
    provider_v2::{ProviderV2Asset, ProviderV2Sample, ProviderV2SampleStatus},
};

/// Inputs for one atomic provider-v2 invoice and proposal admission.
pub struct ProviderV2AtomicInvoiceInput<'a> {
    pub creator: &'a CreatorPubky,
    pub reader: &'a ReaderPubky,
    pub bundle_binding: &'a [u8],
    pub lock_resource_binding: &'a [u8],
    pub request_hash: [u8; 32],
    pub deadline: OffsetDateTime,
    pub minimum_confirmations: u8,
    pub invoice_payloads: &'a dyn InvoicePayloadFactory,
    pub proposal_acceptance_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderV2CreateResult {
    invoice_id: Uuid,
    invoice_created_at: OffsetDateTime,
    proposal_expires_at: OffsetDateTime,
    deadline: OffsetDateTime,
    replayed: bool,
}

impl ProviderV2CreateResult {
    pub fn invoice_id(&self) -> Uuid {
        self.invoice_id
    }
    pub fn invoice_created_at(&self) -> OffsetDateTime {
        self.invoice_created_at
    }
    pub fn proposal_expires_at(&self) -> OffsetDateTime {
        self.proposal_expires_at
    }
    pub fn deadline(&self) -> OffsetDateTime {
        self.deadline
    }
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderV2Status {
    pub creator: String,
    pub bundle_id: String,
    pub request_state: PaymentRequestLifecycleState,
    pub payment_state: &'static str,
    pub invoice_created_at: OffsetDateTime,
    pub proposal_expires_at: OffsetDateTime,
    pub deadline: OffsetDateTime,
    pub asset: ProviderV2Asset,
    pub minimum_confirmations: u8,
    pub current_sample: Option<ProviderV2Sample>,
    pub first_threshold_satisfied: Option<ProviderV2Sample>,
    pub bitcoin: Option<BitcoinPaymentStatus>,
    pub usdt_arbitrum: Option<UsdtPaymentStatus>,
}

#[derive(sqlx::FromRow)]
struct ProviderReplayRow {
    invoice_id: Uuid,
    request_hash: Vec<u8>,
    invoice_created_at: OffsetDateTime,
    proposal_expires_at: OffsetDateTime,
    deadline: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct ProviderExistingRow {
    invoice_id: Uuid,
    request_hash: Option<Vec<u8>>,
    invoice_created_at: OffsetDateTime,
    proposal_expires_at: Option<OffsetDateTime>,
    deadline: Option<OffsetDateTime>,
}

#[derive(sqlx::FromRow)]
struct ProviderStatusRow {
    invoice_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    invoice_created_at: OffsetDateTime,
    proposal_expires_at: OffsetDateTime,
    deadline: OffsetDateTime,
    asset: String,
    minimum_confirmations: i16,
    payment_expired_at: Option<OffsetDateTime>,
    request_state: Option<String>,
    current_observed_at: Option<OffsetDateTime>,
    current_status: Option<String>,
    current_observation_id: Option<Uuid>,
    current_confirmations: Option<i16>,
    current_amount_matched: Option<bool>,
    first_observed_at: Option<OffsetDateTime>,
    first_status: Option<String>,
    first_observation_id: Option<Uuid>,
    first_confirmations: Option<i16>,
    first_amount_matched: Option<bool>,
}

impl InvoiceStore {
    /// Replay-first, cross-version-aware provider-v2 lookup.
    pub async fn provider_v2_preflight(
        &self,
        creator: &CreatorPubky,
        bundle_binding: &[u8],
        request_hash: &[u8; 32],
    ) -> Result<InvoicePreflight, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_binding);
        let existing: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "SELECT provider.request_hash
             FROM invoices
             JOIN creators ON creators.id = invoices.creator_id
             LEFT JOIN invoice_provider_v2 provider ON provider.invoice_id = invoices.id
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(match existing {
            None => InvoicePreflight::New,
            Some(Some(hash)) if hash.as_slice() == request_hash => InvoicePreflight::ExactReplay,
            Some(_) => InvoicePreflight::Conflict,
        })
    }

    pub async fn provider_v2_exact_replay(
        &self,
        creator: &CreatorPubky,
        bundle_binding: &[u8],
        request_hash: &[u8; 32],
    ) -> Result<ProviderV2CreateResult, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_binding);
        let row = sqlx::query_as::<_, ProviderReplayRow>(
            "SELECT invoices.id AS invoice_id, provider.request_hash,
                    invoices.invoice_created_at, provider.proposal_expires_at, provider.deadline
             FROM invoices
             JOIN creators ON creators.id = invoices.creator_id
             JOIN invoice_provider_v2 provider ON provider.invoice_id = invoices.id
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::Conflict)?;
        if row.request_hash.as_slice() != request_hash {
            return Err(PersistenceError::Conflict);
        }
        Ok(ProviderV2CreateResult {
            invoice_id: row.invoice_id,
            invoice_created_at: row.invoice_created_at,
            proposal_expires_at: row.proposal_expires_at,
            deadline: row.deadline,
            replayed: true,
        })
    }

    /// Samples PostgreSQL time while serializing against this Creator. New
    /// external work may start only after this returns `true`.
    pub async fn provider_v2_deadline_gate(
        &self,
        creator: &CreatorPubky,
        deadline: OffsetDateTime,
    ) -> Result<bool, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let found: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE")
                .bind(creator_hash.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
        if found.is_none() {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let allowed: bool = sqlx::query_scalar("SELECT clock_timestamp() < $1")
            .bind(deadline)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(allowed)
    }

    /// Atomically allocates the address, invoice, v2 binding, encrypted intent,
    /// and exactly one proposal outbox row.
    pub async fn create_provider_v2_atomic(
        &self,
        input: ProviderV2AtomicInvoiceInput<'_>,
    ) -> Result<ProviderV2CreateResult, PersistenceError> {
        if input.minimum_confirmations > 6
            || input.proposal_acceptance_seconds == 0
            || input.invoice_payloads.maximum_payment_seconds() == Some(0)
            || !input.deadline.nanosecond().is_multiple_of(1_000)
        {
            return Err(PersistenceError::InvalidInput);
        }
        let creator_hash = self
            .crypto
            .lookup_hash(input.creator.to_string().as_bytes());
        let reader_hash = self.crypto.lookup_hash(input.reader.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(input.bundle_binding);
        let lock_resource_hash = self.crypto.lookup_hash(input.lock_resource_binding);
        let proposal_seconds = i64::try_from(input.proposal_acceptance_seconds)
            .map_err(|_| PersistenceError::InvalidInput)?;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let creator = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, next_child_index, bitcoin_account_generation
             FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if lookup_hash(&creator.creator_lookup_hash)? != creator_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;

        let existing = sqlx::query_as::<_, ProviderExistingRow>(
            "SELECT invoices.id AS invoice_id, provider.request_hash,
                    invoices.invoice_created_at, provider.proposal_expires_at, provider.deadline
             FROM invoices
             LEFT JOIN invoice_provider_v2 provider ON provider.invoice_id = invoices.id
             WHERE invoices.creator_id = $1 AND invoices.bundle_lookup_hash = $2 FOR UPDATE OF invoices",
        )
        .bind(creator.id)
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx).await;
        match existing {
            Ok(Some(row))
                if row.request_hash.as_deref() == Some(input.request_hash.as_slice())
                    && row.proposal_expires_at.is_some()
                    && row.deadline.is_some() =>
            {
                tx.commit()
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                return Ok(ProviderV2CreateResult {
                    invoice_id: row.invoice_id,
                    invoice_created_at: row.invoice_created_at,
                    proposal_expires_at: row.proposal_expires_at.expect("checked above"),
                    deadline: row.deadline.expect("checked above"),
                    replayed: true,
                });
            }
            Ok(Some(_)) => return Err(PersistenceError::Conflict),
            Ok(None) => {}
            Err(_) => return Err(PersistenceError::Unavailable),
        }
        if now >= input.deadline {
            return Err(PersistenceError::DeadlineElapsed);
        }
        if let Some(maximum_payment_seconds) = input.invoice_payloads.maximum_payment_seconds() {
            let maximum_payment_seconds = i64::try_from(maximum_payment_seconds)
                .map_err(|_| PersistenceError::InvalidInput)?;
            if input.deadline
                > now
                    .checked_add(Duration::seconds(maximum_payment_seconds))
                    .ok_or(PersistenceError::InvalidInput)?
            {
                return Err(PersistenceError::InvalidInput);
            }
        }
        let max_proposal = input
            .deadline
            .checked_sub(Duration::microseconds(1))
            .ok_or(PersistenceError::InvalidInput)?;
        let configured_proposal = now
            .checked_add(Duration::seconds(proposal_seconds))
            .ok_or(PersistenceError::InvalidInput)?;
        let proposal_expires_at = configured_proposal.min(max_proposal);
        if proposal_expires_at < now {
            return Err(PersistenceError::DeadlineElapsed);
        }
        if input
            .invoice_payloads
            .expected_bitcoin_account_generation()
            .is_some_and(|expected| expected != creator.bitcoin_account_generation)
        {
            return Err(PersistenceError::Conflict);
        }

        sqlx::query(
            "INSERT INTO lock_payment_generations (creator_id, lock_resource_lookup_hash)
             VALUES ($1, $2) ON CONFLICT (creator_id, lock_resource_lookup_hash) DO NOTHING",
        )
        .bind(creator.id)
        .bind(lock_resource_hash.as_bytes().as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let (generation, active_drain, drain_fenced): (i64, Option<Uuid>, bool) = sqlx::query_as(
            "SELECT current_generation, active_drain_id, provider_v2_drain_fenced
             FROM lock_payment_generations
             WHERE creator_id = $1 AND lock_resource_lookup_hash = $2 FOR UPDATE",
        )
        .bind(creator.id)
        .bind(lock_resource_hash.as_bytes().as_slice())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if generation < 0 || active_drain.is_some() || drain_fenced {
            return Err(PersistenceError::Conflict);
        }

        if self
            .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
            .await?
            .is_some()
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let mut payloads = input
            .invoice_payloads
            .for_child_index(creator.next_child_index)?;
        payloads
            .payment_request_intent
            .set_deadlines(
                proposal_expires_at
                    .format(&Rfc3339)
                    .map_err(|_| PersistenceError::InvalidInput)?,
                input
                    .deadline
                    .format(&Rfc3339)
                    .map_err(|_| PersistenceError::InvalidInput)?,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        validate_intent(&payloads.payment_request_intent, input.reader)?;
        let payment_record = InvoicePaymentRecordV1::from_intent(
            creator.next_child_index,
            &payloads.payment_request_intent,
        )?;
        let terms = payloads
            .payment_request_intent
            .terms()
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let asset = match terms.asset.as_str() {
            "btc" => ProviderV2Asset::Btc,
            "usdt" => ProviderV2Asset::Usdt,
            _ => return Err(PersistenceError::InvalidInput),
        };
        if match asset {
            ProviderV2Asset::Btc => {
                !payment_record.has_bitcoin()
                    || payment_record.has_usdt()
                    || payment_record.bitcoin_required_amount()? == 0
            }
            ProviderV2Asset::Usdt => {
                !payment_record.has_usdt() || payment_record.usdt_required_amount()? == 0
            }
        } {
            return Err(PersistenceError::InvalidInput);
        }

        let assignment_id = Uuid::new_v4();
        let assignment_envelope = encrypt_assignment(
            &self.crypto,
            creator_hash,
            assignment_id,
            creator.next_child_index,
        )?;
        sqlx::query(
            "INSERT INTO reader_assignments
             (id, creator_id, reader_lookup_hash, bundle_lookup_hash, assignment_envelope)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(assignment_id)
        .bind(creator.id)
        .bind(reader_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .bind(assignment_envelope.as_bytes())
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Conflict)?;
        sqlx::query("UPDATE creators SET next_child_index = next_child_index + 1, updated_at = NOW() WHERE id = $1")
            .bind(creator.id).execute(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?;

        let intent_plaintext = postcard::to_allocvec(&payloads.payment_request_intent)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let invoice_id = Uuid::new_v4();
        let payment_record_plaintext = postcard::to_allocvec(&payment_record)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment_record_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::invoice_payment_record(creator_hash, invoice_id),
                &payment_record_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let invoice_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::invoice(creator_hash, invoice_id),
                &intent_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let bitcoin_address_hash = payment_record.bitcoin.as_ref().map(|destination| {
            self.crypto
                .bitcoin_address_lookup_hash(destination.address.as_bytes())
        });
        let derivation_hash = self
            .crypto
            .bitcoin_derivation_index_lookup_hash(creator_hash, creator.next_child_index);
        let proposal_hash = self.crypto.payment_request_proposal_lookup_hash(
            payloads
                .payment_request_intent
                .proposal_payment_reference()
                .map_err(|_| PersistenceError::CorruptOrMissing)?
                .as_bytes(),
        );

        sqlx::query(
            "INSERT INTO invoices
             (id, creator_id, reader_lookup_hash, bundle_lookup_hash, lock_resource_lookup_hash,
              lock_resource_generation, payment_request_lookup_hash, invoice_envelope,
              payment_record_envelope, bitcoin_address_lookup_hash, derivation_index_lookup_hash,
              payment_status, invoice_created_at, proposal_expires_at, payment_deadline,
              proposal_acceptance_seconds, payment_window_seconds, bitcoin_account_generation)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'undetected',$12,$13,$14,1,2,$15)",
        )
        .bind(invoice_id)
        .bind(creator.id)
        .bind(reader_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .bind(lock_resource_hash.as_bytes().as_slice())
        .bind(generation)
        .bind(input.request_hash.as_slice())
        .bind(invoice_envelope.as_bytes())
        .bind(payment_record_envelope.as_bytes())
        .bind(
            bitcoin_address_hash
                .as_ref()
                .map(|hash| hash.as_bytes().as_slice()),
        )
        .bind(derivation_hash.as_bytes().as_slice())
        .bind(now)
        .bind(proposal_expires_at)
        .bind(input.deadline)
        .bind(creator.bitcoin_account_generation)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Conflict)?;

        sqlx::query(
            "INSERT INTO invoice_provider_v2
             (invoice_id, request_hash, deadline, asset, minimum_confirmations, proposal_expires_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(invoice_id)
        .bind(input.request_hash.as_slice())
        .bind(input.deadline)
        .bind(asset.as_str())
        .bind(i16::from(input.minimum_confirmations))
        .bind(proposal_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Conflict)?;

        let outbox_id = Uuid::new_v4();
        let outbox_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::outbox_semantic_intent(creator_hash, outbox_id),
                &intent_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        insert_outbox(
            &mut tx,
            OutboxInsert {
                id: outbox_id,
                creator_id: creator.id,
                invoice_id,
                intent_envelope: outbox_envelope.as_bytes(),
                intent_kind: "payment_request_proposal",
                proposal_lookup_hash: Some(proposal_hash.as_bytes()),
            },
        )
        .await?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        self.admitted.notify_one();
        Ok(ProviderV2CreateResult {
            invoice_id,
            invoice_created_at: now,
            proposal_expires_at,
            deadline: input.deadline,
            replayed: false,
        })
    }

    /// Pure persisted provider-v2 status projection.
    pub async fn provider_v2_status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<ProviderV2Status>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_id.to_string().as_bytes());
        let row = sqlx::query_as::<_, ProviderStatusRow>(
            "SELECT invoices.id AS invoice_id, creators.creator_lookup_hash,
                    invoices.invoice_created_at, provider.proposal_expires_at, provider.deadline,
                    provider.asset, provider.minimum_confirmations, invoices.payment_expired_at,
                    (SELECT request_state FROM payment_request_lifecycles lifecycle
                     WHERE lifecycle.invoice_id = invoices.id
                     ORDER BY CASE request_state
                         WHEN 'invalid_conflict' THEN 9
                         WHEN 'recovery_required' THEN 8
                         WHEN 'proof_submitted' THEN 7
                         WHEN 'active_recurring' THEN 6
                         WHEN 'accepted' THEN 5
                         WHEN 'proposed' THEN 4
                         ELSE 0 END DESC,
                         lifecycle.last_event_at DESC,
                         lifecycle.request_state DESC,
                         lifecycle.sdk_payment_request_id DESC
                     LIMIT 1) AS request_state,
                    current.observed_at AS current_observed_at, current.status AS current_status,
                    current.observation_id AS current_observation_id,
                    current.confirmations AS current_confirmations,
                    current.amount_matched AS current_amount_matched,
                    first_evidence.observed_at AS first_observed_at,
                    first_evidence.status AS first_status,
                    first_evidence.observation_id AS first_observation_id,
                    first_evidence.confirmations AS first_confirmations,
                    first_evidence.amount_matched AS first_amount_matched
             FROM invoices
             JOIN creators ON creators.id = invoices.creator_id
             JOIN invoice_provider_v2 provider ON provider.invoice_id = invoices.id
             LEFT JOIN invoice_provider_v2_current_sample current ON current.invoice_id = invoices.id
             LEFT JOIN invoice_provider_v2_first_threshold_evidence first_evidence ON first_evidence.invoice_id = invoices.id
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        ).bind(creator_hash.as_bytes().as_slice()).bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool).await.map_err(|_| PersistenceError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if lookup_hash(&row.creator_lookup_hash)? != creator_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let current = self
            .decode_provider_sample(
                row.invoice_id,
                creator_hash,
                row.current_observed_at,
                row.current_status,
                row.current_observation_id,
                row.current_confirmations,
                row.current_amount_matched,
            )
            .await?;
        let first = self
            .decode_provider_sample(
                row.invoice_id,
                creator_hash,
                row.first_observed_at,
                row.first_status,
                row.first_observation_id,
                row.first_confirmations,
                row.first_amount_matched,
            )
            .await?;
        let request_state = row.request_state.as_deref().unwrap_or("proposed");
        let request_state = PaymentRequestLifecycleState::parse(request_state)
            .filter(|state| {
                !matches!(
                    state,
                    PaymentRequestLifecycleState::RecoveryRequired
                        | PaymentRequestLifecycleState::InvalidConflict
                )
            })
            .ok_or(PersistenceError::CorruptOrMissing)?;
        let asset = match row.asset.as_str() {
            "BTC" => ProviderV2Asset::Btc,
            "USDT" => ProviderV2Asset::Usdt,
            _ => return Err(PersistenceError::CorruptOrMissing),
        };
        let rail_status = if asset == ProviderV2Asset::Usdt {
            let mut status_tx = self
                .pool
                .begin()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            let rail_status = self
                .payment_request_status_by_invoice_with_fallback(
                    &mut status_tx,
                    row.invoice_id,
                    Some(request_state),
                )
                .await?;
            status_tx
                .commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            rail_status
        } else {
            None
        };
        let payment_state = if row.payment_expired_at.is_some() {
            "expired"
        } else {
            match asset {
                ProviderV2Asset::Btc => current
                    .as_ref()
                    .map_or("undetected", |sample| sample.status().as_str()),
                ProviderV2Asset::Usdt => rail_status
                    .as_ref()
                    .map_or("undetected", |status| status.payment_state().as_str()),
            }
        };
        Ok(Some(ProviderV2Status {
            creator: creator.to_string(),
            bundle_id: bundle_id.to_string(),
            request_state,
            payment_state,
            invoice_created_at: row.invoice_created_at,
            proposal_expires_at: row.proposal_expires_at,
            deadline: row.deadline,
            asset,
            minimum_confirmations: u8::try_from(row.minimum_confirmations)
                .map_err(|_| PersistenceError::CorruptOrMissing)?,
            current_sample: current,
            first_threshold_satisfied: first,
            bitcoin: rail_status.as_ref().and_then(|status| status.bitcoin()),
            usdt_arbitrum: rail_status.and_then(|status| status.usdt_arbitrum()),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn decode_provider_sample(
        &self,
        invoice_id: Uuid,
        creator_hash: LookupHash,
        observed_at: Option<OffsetDateTime>,
        status: Option<String>,
        observation_id: Option<Uuid>,
        confirmations: Option<i16>,
        amount_matched: Option<bool>,
    ) -> Result<Option<ProviderV2Sample>, PersistenceError> {
        if observed_at.is_none()
            && status.is_none()
            && observation_id.is_none()
            && confirmations.is_none()
            && amount_matched.is_none()
        {
            return Ok(None);
        }
        let (Some(observed_at), Some(status), Some(confirmations), Some(amount_matched)) =
            (observed_at, status, confirmations, amount_matched)
        else {
            return Err(PersistenceError::CorruptOrMissing);
        };
        let status = match status.as_str() {
            "undetected" => ProviderV2SampleStatus::Undetected,
            "detected" => ProviderV2SampleStatus::Detected,
            "confirmed" => ProviderV2SampleStatus::Confirmed,
            _ => return Err(PersistenceError::CorruptOrMissing),
        };
        let outpoint = match observation_id {
            None => None,
            Some(id) => {
                let row = sqlx::query_as::<_, BitcoinObservationRow>(
                    "SELECT id, invoice_id, marketplace_preparation_id, observation_envelope,
                            outpoint_lookup_hash, confirmations, present
                     FROM bitcoin_observations WHERE id = $1 AND invoice_id = $2",
                )
                .bind(id)
                .bind(invoice_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| PersistenceError::Unavailable)?
                .ok_or(PersistenceError::CorruptOrMissing)?;
                let record = self.decrypt_observation(creator_hash, &row)?;
                Some(parse_canonical_bitcoin_outpoint(&record.outpoint)?)
            }
        };
        ProviderV2Sample::new(
            observed_at,
            status,
            outpoint,
            u8::try_from(confirmations).map_err(|_| PersistenceError::CorruptOrMissing)?,
            amount_matched,
        )
        .map(Some)
        .map_err(|_| PersistenceError::CorruptOrMissing)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn project_provider_v2_sample(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        invoice_id: Uuid,
        observation_id: Uuid,
        observed_at: OffsetDateTime,
        present: bool,
        confirmations: i32,
        amount_matched: bool,
    ) -> Result<(), PersistenceError> {
        let binding: Option<(i16, OffsetDateTime)> = sqlx::query_as(
            "SELECT minimum_confirmations, deadline FROM invoice_provider_v2 WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some((minimum, deadline)) = binding else {
            return Ok(());
        };
        let bounded = confirmations.clamp(0, 6) as i16;
        let (status, sample_observation): (&str, Option<Uuid>) = if !present {
            ("undetected", None)
        } else if bounded == 0 {
            ("detected", Some(observation_id))
        } else {
            ("confirmed", Some(observation_id))
        };
        sqlx::query(
            "INSERT INTO invoice_provider_v2_current_sample
             (invoice_id, observation_id, observed_at, status, confirmations, amount_matched)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (invoice_id) DO UPDATE SET observation_id = EXCLUDED.observation_id,
                 observed_at = EXCLUDED.observed_at, status = EXCLUDED.status,
                 confirmations = EXCLUDED.confirmations, amount_matched = EXCLUDED.amount_matched,
                 updated_at = NOW()",
        )
        .bind(invoice_id)
        .bind(sample_observation)
        .bind(observed_at)
        .bind(status)
        .bind(if present { bounded } else { 0 })
        .bind(if present { amount_matched } else { false })
        .execute(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if present && amount_matched && bounded >= minimum && observed_at <= deadline {
            sqlx::query(
                "INSERT INTO invoice_provider_v2_first_threshold_evidence
                 (invoice_id, observation_id, observed_at, status, confirmations, amount_matched)
                 VALUES ($1,$2,$3,$4,$5,TRUE) ON CONFLICT (invoice_id) DO NOTHING",
            )
            .bind(invoice_id)
            .bind(observation_id)
            .bind(observed_at)
            .bind(status)
            .bind(bounded)
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        Ok(())
    }
}
