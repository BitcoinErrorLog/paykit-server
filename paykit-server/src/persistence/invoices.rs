//! Atomic encrypted reader allocation, invoice, and delivery-intent persistence.
//!
//! The caller supplies closed, versioned semantic delivery intents. This
//! repository persists those complete SDK inputs inside Creator-bound AEAD
//! envelopes before reporting invoice success.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    application::payment_status::PersistedPaymentStatus,
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    bitcoin::{
        DirectBinding, ObservationAction, ObservationTarget, PlannedObservation, TrackedOutput,
    },
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::locks::{CreatorPubky, ReaderPubky},
    domain::payment::BitcoinOutpoint,
    persistence::PersistenceError,
};

/// Baseline-set recomputation must order rows byte-exactly the way the
/// creation path hashed them. The text columns' collation is pinned to
/// "C" so a database created with a non-C default collation cannot
/// reorder the recomputation away from the hashed order.
const BASELINE_ENTRIES_SQL: &str = "SELECT kind, txid, vout FROM invoice_baseline_outpoints
     WHERE invoice_id = $1 AND kind IN ('output', 'replaced_input')
     ORDER BY kind COLLATE \"C\", txid COLLATE \"C\", vout";

/// Opaque inputs for one transactional invoice-allocation operation.
///
/// `endpoint_publication_payload` is persisted only when the reader has no
/// assignment yet. In that case the payment-request intent depends on its
/// outbox row. For an existing reader, no new endpoint publication is invented:
/// the application must have established that the existing reader endpoint is
/// ready before it asks this store to enqueue a payment request.
pub struct AtomicInvoiceInput<'a> {
    pub creator: &'a CreatorPubky,
    pub reader: &'a ReaderPubky,
    /// Creator-scoped idempotency key for the Locks bundle.
    pub bundle_binding: &'a [u8],
    /// Exact payment-request binding for idempotent replay detection.
    pub payment_request_binding: &'a [u8],
    /// Derives the encrypted assignment and endpoint payloads only after this
    /// transaction has selected the permanent child index.
    pub new_reader_payloads: &'a dyn NewReaderPayloadFactory,
    /// Complete Payment Request proposal intent. Exact replay does not rebuild it.
    pub payment_request_intent: DeliveryIntentV1,
    /// Settlement-authoritative integer satoshi amount the invoice binds at:
    /// the lock or marketplace price plus `nonce_sats` (design §B.8.2).
    pub required_sats: u64,
    /// CSPRNG-drawn amount nonce in [1, 999], persisted inside the sealed
    /// payment record so the exact-amount predicate and the phase-1 prepare
    /// response can report it. Never derived from the order id, the price, a
    /// counter, or time.
    pub nonce_sats: u64,
}

/// Private payloads for a newly allocated `(creator, reader)` assignment.
pub struct NewReaderPayloads {
    pub endpoint_intent: DeliveryIntentV1,
    /// Invoice-specific BIP84 P2WPKH address derived at the allocated index.
    pub bitcoin_address: String,
}

#[derive(Serialize, Deserialize)]
struct InvoicePaymentRecordV2 {
    version: u8,
    derivation_index: i64,
    bitcoin_address: String,
    required_sats: u64,
    creation_chain_height: u32,
    baseline_set_hash: [u8; 32],
}

/// Version 3 adds the CSPRNG-drawn amount nonce (design §B.8.2). For records
/// written from W1.1b on, `required_sats` is the nonce'd total the buyer was
/// told: the lock or marketplace price plus `nonce_sats`. The nonce is an
/// amount fact, so it lives only inside this AEAD-sealed record, never in a
/// plaintext column (amounts are sealed at rest under PAYKIT_MASTER_KEY).
#[derive(Serialize, Deserialize)]
struct InvoicePaymentRecordV3 {
    version: u8,
    derivation_index: i64,
    bitcoin_address: String,
    required_sats: u64,
    nonce_sats: u64,
    creation_chain_height: u32,
    baseline_set_hash: [u8; 32],
}

/// One decrypted invoice payment record at whichever version it was sealed.
/// Version-2 records predate the amount nonce and read as `nonce_sats = 0`,
/// so their exact-amount predicate runs against their stored required
/// amount. That is a behaviour change for exactly one in-flight case: a
/// version-2 overpayment at fewer than six confirmations, which had
/// `amount_matched = true` under the old `>=` predicate, flips to false and
/// takes the `manual_review` path — seller-recoverable, not stranded.
/// Finalized version-2 rows are frozen by the finalization guard (six
/// confirmations and `amount_matched` short-circuit before the predicate is
/// re-evaluated) and never flip.
enum InvoicePaymentRecord {
    V2(InvoicePaymentRecordV2),
    V3(InvoicePaymentRecordV3),
}

impl InvoicePaymentRecord {
    fn parse(plaintext: &[u8]) -> Result<Self, PersistenceError> {
        match plaintext.first() {
            Some(2) => {
                let record: InvoicePaymentRecordV2 = postcard::from_bytes(plaintext)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                if record.version != 2 {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                Ok(Self::V2(record))
            }
            Some(3) => {
                let record: InvoicePaymentRecordV3 = postcard::from_bytes(plaintext)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                if record.version != 3 {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                Ok(Self::V3(record))
            }
            _ => Err(PersistenceError::CorruptOrMissing),
        }
    }

    fn seal(&self) -> Result<Vec<u8>, PersistenceError> {
        match self {
            Self::V2(record) => {
                postcard::to_allocvec(record).map_err(|_| PersistenceError::CorruptOrMissing)
            }
            Self::V3(record) => {
                postcard::to_allocvec(record).map_err(|_| PersistenceError::CorruptOrMissing)
            }
        }
    }

    fn derivation_index(&self) -> i64 {
        match self {
            Self::V2(record) => record.derivation_index,
            Self::V3(record) => record.derivation_index,
        }
    }

    fn bitcoin_address(&self) -> &str {
        match self {
            Self::V2(record) => &record.bitcoin_address,
            Self::V3(record) => &record.bitcoin_address,
        }
    }

    fn required_sats(&self) -> u64 {
        match self {
            Self::V2(record) => record.required_sats,
            Self::V3(record) => record.required_sats,
        }
    }

    fn creation_chain_height(&self) -> u32 {
        match self {
            Self::V2(record) => record.creation_chain_height,
            Self::V3(record) => record.creation_chain_height,
        }
    }

    fn baseline_set_hash(&self) -> &[u8; 32] {
        match self {
            Self::V2(record) => &record.baseline_set_hash,
            Self::V3(record) => &record.baseline_set_hash,
        }
    }

    fn complete_baseline(&mut self, creation_chain_height: u32, baseline_set_hash: [u8; 32]) {
        match self {
            Self::V2(record) => {
                record.creation_chain_height = creation_chain_height;
                record.baseline_set_hash = baseline_set_hash;
            }
            Self::V3(record) => {
                record.creation_chain_height = creation_chain_height;
                record.baseline_set_hash = baseline_set_hash;
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct BitcoinObservationV1 {
    version: u8,
    outpoint: String,
    observed_sats: u64,
}

pub(crate) struct BitcoinObservationInput {
    pub address: String,
    pub outpoint: BitcoinOutpoint,
    pub observed_sats: u64,
    pub confirmations: u32,
    pub confirmed_height: Option<u32>,
    pub present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCandidate {
    pub invoice_id: Uuid,
    pub outpoint: bitcoin::OutPoint,
}

/// Produces payloads after the creator-row lock determines the child index.
pub trait NewReaderPayloadFactory: Send + Sync {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError>;
}

/// Secret-free identifiers returned by an atomic allocation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicInvoiceResult {
    invoice_id: Uuid,
    payment_request_outbox_id: Uuid,
    endpoint_publication_outbox_id: Option<Uuid>,
    reader_assignment_id: Uuid,
    reader_child_index: i64,
    replayed: bool,
}

/// Result of a side-effect-free invoice replay lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvoicePreflight {
    New,
    ExactReplay,
    Conflict,
    /// The idempotent payload matches an invoice whose creation baseline
    /// is still unresolved (`awaiting_baseline`): an earlier attempt
    /// committed the invoice row but its outcome — published or voided —
    /// is not yet known, either because it is still running or because it
    /// was orphaned by a dropped request and awaits the sweeper. The
    /// design forbids reporting success for an invoice that has not
    /// published, so this row is NEVER an [`InvoicePreflight::ExactReplay`]:
    /// the caller answers with a machine-readable in-progress outcome and
    /// the client retries until the row resolves (a completed baseline
    /// replays exactly; the sweeper's void is the terminal fallback).
    BaselineInProgress,
}

impl AtomicInvoiceResult {
    /// Builds the secret-free result returned by an invoice persistence adapter.
    ///
    /// This is public because [`crate::application::create_invoice::InvoicePersistence`]
    /// is an injected port; alternate adapters must be able to report a completed
    /// allocation without depending on this module's private fields.
    pub fn new(
        invoice_id: Uuid,
        payment_request_outbox_id: Uuid,
        endpoint_publication_outbox_id: Option<Uuid>,
        reader_assignment_id: Uuid,
        reader_child_index: i64,
        replayed: bool,
    ) -> Self {
        Self {
            invoice_id,
            payment_request_outbox_id,
            endpoint_publication_outbox_id,
            reader_assignment_id,
            reader_child_index,
            replayed,
        }
    }

    pub fn invoice_id(&self) -> Uuid {
        self.invoice_id
    }

    pub fn payment_request_outbox_id(&self) -> Uuid {
        self.payment_request_outbox_id
    }

    /// Returns the endpoint-publication intent that gates this payment request,
    /// when this invoice required one.
    pub fn endpoint_publication_outbox_id(&self) -> Option<Uuid> {
        self.endpoint_publication_outbox_id
    }

    pub fn reader_assignment_id(&self) -> Uuid {
        self.reader_assignment_id
    }

    pub fn reader_child_index(&self) -> i64 {
        self.reader_child_index
    }

    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

/// PostgreSQL advisory-lock key for cluster-single observer leadership.
/// Fixed and documented: every replica of one deployment tries the same key,
/// so exactly one observer is active cluster-wide. (Advisory locks are
/// per-DATABASE in PostgreSQL — the lock tag is scoped by the database OID —
/// so two deployments that share one PostgreSQL cluster contend on this key
/// only when they share one database; in that case the second stack's
/// observer simply idles, which is the designed fail-closed behaviour.)
pub const OBSERVER_LEADERSHIP_LOCK_KEY: i64 = 7_216_043_388_155_778_021;

/// Cluster-single observer leadership backed by a session-scoped
/// PostgreSQL advisory lock. The lock is held on a dedicated detached
/// connection for as long as this replica leads; the connection is never
/// held across per-row database locks, and no row lock is ever held across
/// network I/O. `is_leader` re-asserts the lock on every call, so takeover
/// is fail-closed: while another replica's session holds the lock this
/// replica idles, and when the leader's session dies PostgreSQL releases
/// the lock and the next call here acquires it.
pub struct PgObserverLeadership {
    pool: PgPool,
    connection: tokio::sync::Mutex<Option<PgConnection>>,
}

impl PgObserverLeadership {
    pub fn new(pool: &PgPool) -> Self {
        Self {
            pool: pool.clone(),
            connection: tokio::sync::Mutex::new(None),
        }
    }

    /// Re-asserts the leadership advisory lock on this replica's dedicated
    /// session. Returns `true` while this replica leads, `false` while a
    /// live peer leads, and `Err` when the check itself cannot complete
    /// (the caller treats that as "not leader" and idles fail-closed). A
    /// dead session is replaced once before giving up.
    pub async fn is_leader(&self) -> Result<bool, PersistenceError> {
        let mut guard = self.connection.lock().await;
        for attempt in 0..2 {
            if guard.is_none() {
                let connection = self
                    .pool
                    .acquire()
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?
                    .detach();
                *guard = Some(connection);
            }
            let connection = guard.as_mut().expect("leadership connection present");
            match sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
                .bind(OBSERVER_LEADERSHIP_LOCK_KEY)
                .fetch_one(&mut *connection)
                .await
            {
                // Re-entrant on the holding session, so a leader stays
                // leader; a non-leader holds no lock and drops its session.
                Ok(acquired) => {
                    if !acquired {
                        guard.take();
                    }
                    return Ok(acquired);
                }
                Err(_) => {
                    // The session is dead: PostgreSQL has already released
                    // any lock it held, so dropping it and retrying once on
                    // a fresh session is safe and never double-leads.
                    guard.take();
                    if attempt == 1 {
                        return Err(PersistenceError::Unavailable);
                    }
                }
            }
        }
        Err(PersistenceError::Unavailable)
    }
}

/// Encrypted invoice persistence with creator-row serialization.
#[derive(Clone, Debug)]
pub struct InvoiceStore {
    pool: PgPool,
    crypto: Arc<Crypto>,
}

impl InvoiceStore {
    pub fn new(pool: &PgPool, crypto: Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    /// Authenticates all final encrypted Bitcoin values and their keyed lookup hashes.
    pub async fn scan_payment_record_integrity(&self) -> Result<(), PersistenceError> {
        let invoices = sqlx::query_as::<_, (Uuid, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT invoices.id, creators.creator_lookup_hash,
                    invoices.payment_record_envelope, invoices.bitcoin_address_lookup_hash,
                    invoices.derivation_index_lookup_hash
             FROM invoices JOIN creators ON creators.id = invoices.creator_id
             WHERE invoices.baseline_state <> 'legacy_unbaselined'",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for (id, creator_hash, envelope, address_hash, index_hash) in invoices {
            let creator_hash = lookup_hash_from_storage(&creator_hash)?;
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::invoice_payment_record(creator_hash, id),
                    &EncryptedEnvelope::from_bytes(envelope),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let record = InvoicePaymentRecord::parse(&plaintext)?;
            // A version-3 record always carries a nonce drawn at creation;
            // one outside [1, 999] was never written by this code.
            if let InvoicePaymentRecord::V3(record) = &record
                && !(crate::domain::invoice::NONCE_SATS_MIN
                    ..=crate::domain::invoice::NONCE_SATS_MAX)
                    .contains(&record.nonce_sats)
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
            if address_hash
                != self
                    .crypto
                    .bitcoin_address_lookup_hash(record.bitcoin_address().as_bytes())
                    .as_bytes()
                || index_hash
                    != self
                        .crypto
                        .bitcoin_derivation_index_lookup_hash(
                            creator_hash,
                            record.derivation_index(),
                        )
                        .as_bytes()
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
        }

        let observations = sqlx::query_as::<_, (Uuid, Uuid, Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT observations.id, observations.invoice_id, creators.creator_lookup_hash,
                    observations.observation_envelope, observations.outpoint_lookup_hash
             FROM bitcoin_observations AS observations
             JOIN invoices ON invoices.id = observations.invoice_id
             JOIN creators ON creators.id = invoices.creator_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for (id, invoice_id, creator_hash, envelope, outpoint_hash) in observations {
            let creator_hash = lookup_hash_from_storage(&creator_hash)?;
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::bitcoin_observation_for_invoice(creator_hash, id, invoice_id),
                    &EncryptedEnvelope::from_bytes(envelope),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let record: BitcoinObservationV1 =
                postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
            if record.version != 1
                || outpoint_hash
                    != self
                        .crypto
                        .bitcoin_outpoint_lookup_hash(record.outpoint.as_bytes())
                        .as_bytes()
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
        }
        Ok(())
    }

    /// Loads every non-final invoice as an authenticated observation plan
    /// entry, ordered oldest ATTEMPT first (`last_attempted_at`, falling
    /// back to `last_observed_at` and then `created_at` for rows that
    /// predate attempt stamping) so budget exhaustion defers the most
    /// recently attempted targets and a permanently failing target
    /// rotates behind the rest of the plan exactly like a success.
    /// `staleness_secs` deliberately still derives from the last
    /// SUCCESSFUL observation (`last_observed_at`): a failing target
    /// keeps its staleness for backlog alerting even as it rotates.
    pub async fn observation_plan(&self) -> Result<Vec<PlannedObservation>, PersistenceError> {
        let rows = sqlx::query_as::<_, ObservationPlanRow>(
            "SELECT invoices.id AS invoice_id, creators.creator_lookup_hash, \
                    invoices.payment_record_envelope, invoices.bitcoin_address_lookup_hash, \
                    invoices.derivation_index_lookup_hash, observations.id AS observation_id, \
                    observations.observation_envelope, observations.outpoint_lookup_hash, \
                    GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (NOW() - \
                        COALESCE(invoices.last_observed_at, invoices.created_at)))))::BIGINT \
                        AS staleness_secs \
             FROM invoices JOIN creators ON creators.id = invoices.creator_id \
             LEFT JOIN bitcoin_observations AS observations \
               ON observations.invoice_id = invoices.id AND observations.active \
             WHERE invoices.baseline_state = 'observing' AND NOT invoices.integrity_failed
               AND NOT (invoices.payment_status = 'confirmed' \
                        AND invoices.confirmation_count = 6 AND invoices.amount_matched) \
              ORDER BY COALESCE(invoices.last_attempted_at, invoices.last_observed_at, \
                                invoices.created_at), invoices.id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        rows.into_iter()
            .map(|row| {
                let staleness_secs = u64::try_from(row.staleness_secs)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                let target = self.decrypt_target(row.target)?;
                Ok(PlannedObservation::new(
                    target,
                    std::time::Duration::from_secs(staleness_secs),
                ))
            })
            .collect()
    }

    /// Stamps one tick's ATTEMPTED target addresses, rotating each behind
    /// the rest of the oldest-first plan. Observed targets are stamped
    /// with both `last_observed_at` (success; drives staleness and
    /// backlog alerting) and `last_attempted_at` (drives scheduling);
    /// failed targets are stamped with `last_attempted_at` only, so they
    /// rotate to the tail exactly like successes while keeping their
    /// staleness. Without the failure stamp a permanently failing target
    /// would keep the head of the plan and, at enough failing targets,
    /// starve every honest seller of attempts.
    ///
    /// Every record's UPDATE must match exactly one invoice row: a zero-row
    /// stamp means the lookup hash derived from the observer's canonical
    /// address string no longer matches any stored hash, so the invoice
    /// would never rotate behind the plan and would be re-observed at the
    /// head of every tick. Misses are reported at WARN (with the truncated
    /// lookup hash; no invoice id exists for an unmatched hash) and counted
    /// in the return value, but never abort the remaining records.
    pub async fn record_observation_tick(
        &self,
        observed: &[String],
        failed: &[String],
    ) -> Result<u64, PersistenceError> {
        if observed.is_empty() && failed.is_empty() {
            return Ok(0);
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let mut misses = 0_u64;
        for (address, succeeded) in observed
            .iter()
            .map(|address| (address, true))
            .chain(failed.iter().map(|address| (address, false)))
        {
            let address_lookup_hash = self.crypto.bitcoin_address_lookup_hash(address.as_bytes());
            let stamped = if succeeded {
                sqlx::query(
                    "UPDATE invoices \
                     SET last_observed_at = NOW(), last_attempted_at = NOW(), updated_at = NOW() \
                     WHERE bitcoin_address_lookup_hash = $1 AND baseline_state = 'observing'",
                )
            } else {
                sqlx::query(
                    "UPDATE invoices \
                     SET last_attempted_at = NOW(), updated_at = NOW() \
                     WHERE bitcoin_address_lookup_hash = $1 AND baseline_state = 'observing'",
                )
            }
            .bind(address_lookup_hash.as_bytes().as_slice())
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            if stamped.rows_affected() == 0 {
                misses += 1;
                let hash_prefix = address_lookup_hash.as_bytes()[..8]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                tracing::warn!(
                    address_lookup_hash_prefix = %hash_prefix,
                    "observation tick stamp matched no invoice row"
                );
            }
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(misses)
    }

    fn decrypt_target(
        &self,
        row: ObservationTargetRow,
    ) -> Result<ObservationTarget, PersistenceError> {
        let creator_hash = lookup_hash_from_storage(&row.creator_lookup_hash)?;
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::invoice_payment_record(creator_hash, row.invoice_id),
                &EncryptedEnvelope::from_bytes(row.payment_record_envelope),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment = InvoicePaymentRecord::parse(&plaintext)?;
        if row.bitcoin_address_lookup_hash
            != self
                .crypto
                .bitcoin_address_lookup_hash(payment.bitcoin_address().as_bytes())
                .as_bytes()
            || row.derivation_index_lookup_hash
                != self
                    .crypto
                    .bitcoin_derivation_index_lookup_hash(creator_hash, payment.derivation_index())
                    .as_bytes()
        {
            return Err(PersistenceError::CorruptOrMissing);
        }

        let current = match (
            row.observation_id,
            row.observation_envelope,
            row.outpoint_lookup_hash,
        ) {
            (None, None, None) => None,
            (Some(id), Some(envelope), Some(outpoint_hash)) => {
                let plaintext = self
                    .crypto
                    .decrypt(
                        &EnvelopeContext::bitcoin_observation_for_invoice(
                            creator_hash,
                            id,
                            row.invoice_id,
                        ),
                        &EncryptedEnvelope::from_bytes(envelope),
                    )
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                let observation: BitcoinObservationV1 = postcard::from_bytes(&plaintext)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                if observation.version != 1
                    || outpoint_hash
                        != self
                            .crypto
                            .bitcoin_outpoint_lookup_hash(observation.outpoint.as_bytes())
                            .as_bytes()
                {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                let outpoint = observation
                    .outpoint
                    .parse::<bitcoin::OutPoint>()
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                if outpoint.to_string() != observation.outpoint {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                Some(TrackedOutput::new(outpoint, observation.observed_sats))
            }
            _ => return Err(PersistenceError::CorruptOrMissing),
        };
        Ok(ObservationTarget::new(
            payment.bitcoin_address().to_owned(),
            current,
        ))
    }

    /// Checks durable invoice idempotency before mutable external validation.
    pub async fn preflight(
        &self,
        creator: &CreatorPubky,
        bundle_binding: &[u8],
        payment_request_binding: &[u8],
    ) -> Result<InvoicePreflight, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_binding);
        let payment_hash = self.crypto.lookup_hash(payment_request_binding);
        let existing = sqlx::query_as::<_, (Vec<u8>, String)>(
            "SELECT invoices.payment_request_lookup_hash, invoices.baseline_state \
             FROM invoices \
             JOIN creators ON creators.id = invoices.creator_id \
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(match existing {
            None => InvoicePreflight::New,
            Some((request_hash, _)) if request_hash != payment_hash.as_bytes() => {
                InvoicePreflight::Conflict
            }
            // An unresolved or terminally voided baseline never published:
            // neither may report replay success (design r13). The voided
            // binding is spent — it maps to Conflict so the client mints a
            // fresh payment request instead of retrying a dead invoice.
            Some((_, baseline_state)) if baseline_state == "awaiting_baseline" => {
                InvoicePreflight::BaselineInProgress
            }
            Some((_, baseline_state)) if baseline_state == "void_baseline_failed" => {
                InvoicePreflight::Conflict
            }
            Some(_) => InvoicePreflight::ExactReplay,
        })
    }

    /// Loads an exact replay without rebuilding delivery intent or repeating
    /// external validation and discovery work.
    pub async fn exact_replay(
        &self,
        creator: &CreatorPubky,
        reader: &ReaderPubky,
        bundle_binding: &[u8],
        payment_binding: &[u8],
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let reader_hash = self.crypto.lookup_hash(reader.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_binding);
        let payment_hash = self.crypto.lookup_hash(payment_binding);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let creator = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, next_child_index FROM creators \
             WHERE creator_lookup_hash = $1 FOR UPDATE",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if lookup_hash(&creator.creator_lookup_hash)? != creator_hash {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let existing = sqlx::query_as::<_, ExistingInvoice>(
            "SELECT id, payment_request_lookup_hash FROM invoices \
             WHERE creator_id = $1 AND bundle_lookup_hash = $2 FOR UPDATE",
        )
        .bind(creator.id)
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if existing.payment_request_lookup_hash != payment_hash.as_bytes() {
            return Err(PersistenceError::Conflict);
        }
        let assignment = self
            .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
            .await?
            .ok_or(PersistenceError::CorruptOrMissing)?;
        let payment_outbox = sqlx::query_as::<_, ExistingPaymentOutbox>(
            "SELECT id, depends_on_id FROM outbox WHERE invoice_id = $1 \
             AND depends_on_id IS NOT NULL ORDER BY created_at, id LIMIT 1",
        )
        .bind(existing.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(AtomicInvoiceResult {
            invoice_id: existing.id,
            payment_request_outbox_id: payment_outbox.id,
            endpoint_publication_outbox_id: payment_outbox.depends_on_id,
            reader_assignment_id: assignment.id,
            reader_child_index: assignment.child_index,
            replayed: true,
        })
    }

    /// Reads only the durable payment facts for one creator-scoped bundle.
    ///
    /// Invoice envelopes are deliberately not selected or decrypted. A row with
    /// an unknown status or invalid confirmation count is a safe persistence
    /// failure rather than a value exposed to the caller.
    pub async fn payment_status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &crate::domain::locks::BundleId,
    ) -> Result<Option<PersistedPaymentStatus>, PersistenceError> {
        let creator_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(bundle_id.to_string().as_bytes());
        let row = sqlx::query_as::<_, PaymentStatusRow>(
            "SELECT invoices.payment_status, invoices.confirmation_count, invoices.amount_matched \
             FROM invoices JOIN creators ON creators.id = invoices.creator_id \
             WHERE creators.creator_lookup_hash = $1 AND invoices.bundle_lookup_hash = $2",
        )
        .bind(creator_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        row.map(PersistedPaymentStatus::try_from).transpose()
    }

    pub async fn complete_creation_baseline(
        &self,
        invoice_id: Uuid,
        creation_chain_height: u32,
        baseline_outputs: &[bitcoin::OutPoint],
        unconfirmed_inputs: &[bitcoin::OutPoint],
    ) -> Result<(), PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, String)>(
            "SELECT creators.creator_lookup_hash, invoices.payment_record_envelope,
                    invoices.baseline_state
             FROM invoices JOIN creators ON creators.id = invoices.creator_id
             WHERE invoices.id = $1 FOR UPDATE OF invoices",
        )
        .bind(invoice_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if row.2 != "awaiting_baseline" {
            return Err(PersistenceError::Conflict);
        }
        let creator_hash = lookup_hash_from_storage(&row.0)?;
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::invoice_payment_record(creator_hash, invoice_id),
                &EncryptedEnvelope::from_bytes(row.1),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let mut record = InvoicePaymentRecord::parse(&plaintext)?;
        let mut entries = baseline_outputs
            .iter()
            .map(|outpoint| {
                Ok((
                    "output",
                    outpoint.txid.to_string(),
                    i32::try_from(outpoint.vout).map_err(|_| PersistenceError::CorruptOrMissing)?,
                ))
            })
            .chain(unconfirmed_inputs.iter().map(|outpoint| {
                Ok((
                    "replaced_input",
                    outpoint.txid.to_string(),
                    i32::try_from(outpoint.vout).map_err(|_| PersistenceError::CorruptOrMissing)?,
                ))
            }))
            .collect::<Result<Vec<_>, PersistenceError>>()?;
        entries.sort_unstable_by(|left, right| {
            left.0
                .cmp(right.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        entries.dedup();
        let mut hasher = Sha256::new();
        for (kind, txid, vout) in &entries {
            hasher.update(kind.as_bytes());
            hasher.update(b":");
            hasher.update(format!("{txid}:{vout}").as_bytes());
            hasher.update(b"\n");
            sqlx::query(
                "INSERT INTO invoice_baseline_outpoints (invoice_id, txid, vout, kind)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(invoice_id)
            .bind(txid)
            .bind(vout)
            .bind(kind)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Conflict)?;
        }
        record.complete_baseline(creation_chain_height, hasher.finalize().into());
        let record_plaintext = record.seal()?;
        let envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::invoice_payment_record(creator_hash, invoice_id),
                &record_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        sqlx::query(
            "UPDATE invoices SET payment_record_envelope = $1,
                    creation_chain_height = $2, baseline_state = 'observing', updated_at = NOW()
             WHERE id = $3",
        )
        .bind(envelope.as_bytes())
        .bind(i32::try_from(creation_chain_height).map_err(|_| PersistenceError::CorruptOrMissing)?)
        .bind(invoice_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query(
            "UPDATE outbox SET status = 'queued', updated_at = NOW()
             WHERE invoice_id = $1 AND status = 'prepared'",
        )
        .bind(invoice_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit().await.map_err(|_| PersistenceError::Unavailable)
    }

    pub async fn fail_creation_baseline(&self, invoice_id: Uuid) -> Result<(), PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query(
            "UPDATE invoices SET baseline_state = 'void_baseline_failed', updated_at = NOW()
             WHERE id = $1 AND baseline_state = 'awaiting_baseline'",
        )
        .bind(invoice_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(())
    }

    pub async fn sweep_stale_creation_baselines(
        &self,
        timeout: std::time::Duration,
    ) -> Result<u64, PersistenceError> {
        let timeout_seconds =
            i64::try_from(timeout.as_secs()).map_err(|_| PersistenceError::CorruptOrMissing)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let rows = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM invoices
             WHERE baseline_state = 'awaiting_baseline'
               AND created_at <= NOW() - make_interval(secs => $1)
             FOR UPDATE",
        )
        .bind(timeout_seconds)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if !rows.is_empty() {
            sqlx::query(
                "UPDATE invoices SET baseline_state = 'void_baseline_failed', updated_at = NOW()
                 WHERE id = ANY($1) AND baseline_state = 'awaiting_baseline'",
            )
            .bind(&rows)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(u64::try_from(rows.len()).unwrap_or(u64::MAX))
    }

    pub async fn pending_candidates(&self) -> Result<Vec<PendingCandidate>, PersistenceError> {
        let rows = sqlx::query_as::<_, (Uuid, String, i32)>(
            "SELECT candidates.invoice_id, candidates.txid, candidates.vout
             FROM bitcoin_observation_candidates AS candidates
             JOIN invoices ON invoices.id = candidates.invoice_id
             WHERE NOT candidates.approved
               AND candidates.state = 'pending'
               AND candidates.next_attempt_at <= NOW()
               AND invoices.baseline_state = 'observing'
               AND NOT invoices.integrity_failed
               AND NOT (invoices.payment_status = 'confirmed'
                        AND invoices.confirmation_count = 6 AND invoices.amount_matched)
             ORDER BY candidates.next_attempt_at, candidates.confirmed_height,
                      candidates.created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        rows.into_iter()
            .map(|(invoice_id, txid, vout)| {
                let outpoint = format!("{txid}:{vout}")
                    .parse()
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                Ok(PendingCandidate {
                    invoice_id,
                    outpoint,
                })
            })
            .collect()
    }

    pub async fn record_candidate_failure(
        &self,
        candidate: &PendingCandidate,
        error_kind: &str,
        max_attempts: u32,
    ) -> Result<(), PersistenceError> {
        let vout = i32::try_from(candidate.outpoint.vout)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let txid = candidate.outpoint.txid.to_string();
        if error_kind == "persistence" {
            // A persistence failure is not a fetch attempt: it never
            // increments `attempt_count`, never transitions the candidate
            // to `unfetchable`, and never moves the invoice to
            // `manual_review`; only diagnostic state is recorded.
            sqlx::query(
                "UPDATE bitcoin_observation_candidates
                 SET last_attempt_at = NOW(), last_error_kind = $4, updated_at = NOW()
                 WHERE invoice_id = $1 AND txid = $2 AND vout = $3 AND state = 'pending'",
            )
            .bind(candidate.invoice_id)
            .bind(&txid)
            .bind(vout)
            .bind(error_kind)
            .execute(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(());
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let row = if error_kind == "transaction_too_large" {
            // A response over `electrum.max_transaction_bytes` is
            // deterministically unresolvable: one attempt ends the
            // candidate instead of burning the bounded fetch retries.
            sqlx::query_as::<_, (Uuid, i32, String)>(
                "UPDATE bitcoin_observation_candidates
                 SET attempt_count = attempt_count + 1,
                     last_attempt_at = NOW(),
                     last_error_kind = $4,
                     state = 'unfetchable',
                     updated_at = NOW()
                 WHERE invoice_id = $1 AND txid = $2 AND vout = $3 AND state = 'pending'
                 RETURNING invoice_id, attempt_count, state",
            )
            .bind(candidate.invoice_id)
            .bind(&txid)
            .bind(vout)
            .bind(error_kind)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?
        } else {
            let max_attempts =
                i32::try_from(max_attempts).map_err(|_| PersistenceError::CorruptOrMissing)?;
            sqlx::query_as::<_, (Uuid, i32, String)>(
                "UPDATE bitcoin_observation_candidates
                 SET attempt_count = attempt_count + 1,
                     last_attempt_at = NOW(),
                     last_error_kind = $4,
                     state = CASE WHEN attempt_count + 1 >= $5
                                   THEN 'unfetchable' ELSE 'pending' END,
                     next_attempt_at = NOW() + make_interval(
                         secs => LEAST(3600, 30 * power(2, LEAST(attempt_count, 7)))::INTEGER
                     ),
                     updated_at = NOW()
                 WHERE invoice_id = $1 AND txid = $2 AND vout = $3 AND state = 'pending'
                 RETURNING invoice_id, attempt_count, state",
            )
            .bind(candidate.invoice_id)
            .bind(&txid)
            .bind(vout)
            .bind(error_kind)
            .bind(max_attempts)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?
        };
        if let Some((invoice_id, attempts, state)) = row
            && state == "unfetchable"
        {
            sqlx::query(
                "UPDATE invoices SET baseline_state = 'manual_review', updated_at = NOW()
                 WHERE id = $1 AND baseline_state = 'observing'",
            )
            .bind(invoice_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            tracing::error!(
                invoice_id = %invoice_id,
                attempts,
                error_kind,
                "candidate transaction is unresolvable; invoice requires manual review"
            );
        }
        tx.commit().await.map_err(|_| PersistenceError::Unavailable)
    }

    pub async fn resolve_candidate(
        &self,
        candidate: &PendingCandidate,
        inputs: &[bitcoin::OutPoint],
    ) -> Result<(), PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let replaces_baseline: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM invoice_baseline_outpoints
                WHERE invoice_id = $1 AND kind = 'replaced_input'
                  AND (txid, vout) IN (
                    SELECT * FROM UNNEST($2::TEXT[], $3::INTEGER[])
                  )
             )",
        )
        .bind(candidate.invoice_id)
        .bind(
            inputs
                .iter()
                .map(|input| input.txid.to_string())
                .collect::<Vec<_>>(),
        )
        .bind(
            inputs
                .iter()
                .map(|input| i32::try_from(input.vout).unwrap_or(i32::MAX))
                .collect::<Vec<_>>(),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let mut approved_binding = None;
        if replaces_baseline {
            sqlx::query(
                "INSERT INTO invoice_baseline_outpoints (invoice_id, txid, vout, kind)
                 VALUES ($1, $2, $3, 'ineligible')
                 ON CONFLICT DO NOTHING",
            )
            .bind(candidate.invoice_id)
            .bind(candidate.outpoint.txid.to_string())
            .bind(
                i32::try_from(candidate.outpoint.vout)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?,
            )
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            sqlx::query("DELETE FROM bitcoin_observation_candidates WHERE invoice_id = $1")
                .bind(candidate.invoice_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            sqlx::query(
                "UPDATE invoices SET baseline_state = 'manual_review', updated_at = NOW()
                 WHERE id = $1 AND baseline_state = 'observing'",
            )
            .bind(candidate.invoice_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        } else {
            let row = sqlx::query_as::<_, (i32, i32, Vec<u8>, Vec<u8>)>(
                "SELECT candidates.confirmations, candidates.confirmed_height,
                        creators.creator_lookup_hash, invoices.payment_record_envelope
                 FROM bitcoin_observation_candidates AS candidates
                 JOIN invoices ON invoices.id = candidates.invoice_id
                 JOIN creators ON creators.id = invoices.creator_id
                 WHERE candidates.invoice_id = $1 AND candidates.txid = $2
                   AND candidates.vout = $3 FOR UPDATE OF candidates, invoices",
            )
            .bind(candidate.invoice_id)
            .bind(candidate.outpoint.txid.to_string())
            .bind(
                i32::try_from(candidate.outpoint.vout)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?,
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?
            .ok_or(PersistenceError::CorruptOrMissing)?;
            let creator_hash = lookup_hash_from_storage(&row.2)?;
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::invoice_payment_record(creator_hash, candidate.invoice_id),
                    &EncryptedEnvelope::from_bytes(row.3),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let record = InvoicePaymentRecord::parse(&plaintext)?;
            sqlx::query(
                "UPDATE bitcoin_observation_candidates
                 SET approved = TRUE, state = 'approved', updated_at = NOW()
                 WHERE invoice_id = $1 AND txid = $2 AND vout = $3",
            )
            .bind(candidate.invoice_id)
            .bind(candidate.outpoint.txid.to_string())
            .bind(
                i32::try_from(candidate.outpoint.vout)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?,
            )
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            approved_binding = Some((
                record.bitcoin_address().to_owned(),
                record.required_sats(),
                u32::try_from(row.0).map_err(|_| PersistenceError::CorruptOrMissing)?,
                u32::try_from(row.1).map_err(|_| PersistenceError::CorruptOrMissing)?,
            ));
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        if let Some((address, sats, confirmations, height)) = approved_binding {
            self.apply_bitcoin_observation_at_height(
                &address,
                &BitcoinOutpoint::from_bitcoin(candidate.outpoint),
                sats,
                confirmations,
                Some(height),
                true,
            )
            .await?;
        }
        Ok(())
    }

    /// Records one direct, invoice-address-specific output observation. The
    /// database resolves the address; callers cannot nominate an invoice.
    pub async fn apply_bitcoin_observation(
        &self,
        address: &str,
        outpoint: &BitcoinOutpoint,
        observed_sats: u64,
        confirmations: u32,
        confirmed_height: Option<u32>,
        present: bool,
    ) -> Result<bool, PersistenceError> {
        self.apply_bitcoin_observation_with_gate(
            address,
            outpoint,
            observed_sats,
            confirmations,
            confirmed_height,
            present,
            false,
        )
        .await
    }

    pub async fn apply_bitcoin_observation_at_height(
        &self,
        address: &str,
        outpoint: &BitcoinOutpoint,
        observed_sats: u64,
        confirmations: u32,
        confirmed_height: Option<u32>,
        present: bool,
    ) -> Result<bool, PersistenceError> {
        self.apply_bitcoin_observation_with_gate(
            address,
            outpoint,
            observed_sats,
            confirmations,
            confirmed_height,
            present,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_bitcoin_observation_with_gate(
        &self,
        address: &str,
        outpoint: &BitcoinOutpoint,
        observed_sats: u64,
        confirmations: u32,
        confirmed_height: Option<u32>,
        present: bool,
        require_candidate: bool,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let applied = self
            .apply_bitcoin_observation_in_tx(
                &mut tx,
                address,
                outpoint,
                observed_sats,
                confirmations,
                confirmed_height,
                present,
                require_candidate,
            )
            .await?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(applied)
    }

    pub(crate) async fn apply_bitcoin_observation_batch(
        &self,
        observations: &[BitcoinObservationInput],
    ) -> Result<usize, PersistenceError> {
        let mut applied = 0;
        for observation in observations {
            match self
                .apply_bitcoin_observation_with_gate(
                    &observation.address,
                    &observation.outpoint,
                    observation.observed_sats,
                    observation.confirmations,
                    observation.confirmed_height,
                    observation.present,
                    true,
                )
                .await
            {
                Ok(true) => applied += 1,
                Ok(false) => {}
                Err(PersistenceError::CorruptOrMissing) => {
                    self.mark_invoice_integrity_failed(&observation.address)
                        .await?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(applied)
    }

    async fn mark_invoice_integrity_failed(&self, address: &str) -> Result<(), PersistenceError> {
        let address_lookup_hash = self.crypto.bitcoin_address_lookup_hash(address.as_bytes());
        let result = sqlx::query_as::<_, (Uuid, bool, i32)>(
            "WITH current AS (
                 SELECT id,
                        integrity_last_logged_at IS NULL
                        OR integrity_last_logged_at <= NOW() - INTERVAL '5 minutes' AS should_log
                 FROM invoices
                 WHERE bitcoin_address_lookup_hash = $1
                 FOR UPDATE
             )
             UPDATE invoices
             SET integrity_failed = TRUE,
                 integrity_failure_count = integrity_failure_count + 1,
                 integrity_failed_at = COALESCE(integrity_failed_at, NOW()),
                 integrity_last_logged_at = CASE WHEN current.should_log
                                                THEN NOW()
                                                ELSE invoices.integrity_last_logged_at END,
                 updated_at = NOW()
             FROM current
             WHERE invoices.id = current.id
             RETURNING invoices.id, current.should_log, invoices.integrity_failure_count",
        )
        .bind(address_lookup_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if let Some((invoice_id, true, failure_count)) = result {
            tracing::error!(
                invoice_id = %invoice_id,
                failure_count,
                "invoice observation integrity validation failed; invoice excluded from future batches"
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_bitcoin_observation_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        address: &str,
        outpoint: &BitcoinOutpoint,
        observed_sats: u64,
        confirmations: u32,
        confirmed_height: Option<u32>,
        present: bool,
        require_candidate: bool,
    ) -> Result<bool, PersistenceError> {
        let incoming_confirmations = confirmations;
        let confirmations = i32::try_from(incoming_confirmations)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let txid = outpoint.txid().to_owned();
        let vout =
            i32::try_from(outpoint.vout()).map_err(|_| PersistenceError::CorruptOrMissing)?;
        let outpoint = outpoint.canonical_text();
        let address_lookup_hash = self.crypto.bitcoin_address_lookup_hash(address.as_bytes());
        let invoice = sqlx::query_as::<_, BitcoinInvoiceRow>(
            "SELECT invoices.id, invoices.payment_record_envelope,
                    invoices.bitcoin_address_lookup_hash, invoices.payment_status,
                    invoices.confirmation_count, invoices.amount_matched,
                    invoices.baseline_state, invoices.creation_chain_height,
                    creators.creator_lookup_hash
             FROM invoices JOIN creators ON creators.id = invoices.creator_id
             WHERE invoices.bitcoin_address_lookup_hash = $1 FOR UPDATE OF invoices",
        )
        .bind(address_lookup_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(invoice) = invoice else {
            return Ok(false);
        };
        if invoice.baseline_state != "observing" {
            return Ok(true);
        }
        let creator_hash = lookup_hash_from_storage(&invoice.creator_lookup_hash)?;
        let payment_record_plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::invoice_payment_record(creator_hash, invoice.id),
                &EncryptedEnvelope::from_bytes(invoice.payment_record_envelope),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment_record = InvoicePaymentRecord::parse(&payment_record_plaintext)?;
        if payment_record.bitcoin_address() != address
            || payment_record.creation_chain_height()
                != u32::try_from(invoice.creation_chain_height)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?
            || invoice.bitcoin_address_lookup_hash != address_lookup_hash.as_bytes()
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let required = payment_record.required_sats();
        // Final matching outputs are no longer monitored. Keep their persisted
        // six-confirmation fact immutable even if a stale observer reports later.
        if invoice.payment_status == "confirmed"
            && invoice.confirmation_count == 6
            && invoice.amount_matched
        {
            return Ok(true);
        }

        let approved_candidate: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM bitcoin_observation_candidates
                WHERE invoice_id = $1 AND txid = $2 AND vout = $3 AND approved
             )",
        )
        .bind(invoice.id)
        .bind(&txid)
        .bind(vout)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let baseline_entries = sqlx::query_as::<_, (String, String, i32)>(BASELINE_ENTRIES_SQL)
            .bind(invoice.id)
            .fetch_all(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let mut hasher = Sha256::new();
        for (kind, entry_txid, entry_vout) in &baseline_entries {
            hasher.update(kind.as_bytes());
            hasher.update(b":");
            hasher.update(format!("{entry_txid}:{entry_vout}").as_bytes());
            hasher.update(b"\n");
        }
        if payment_record.baseline_set_hash() != &<[u8; 32]>::from(hasher.finalize()) {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let baseline_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM invoice_baseline_outpoints
                WHERE invoice_id = $1 AND txid = $2 AND vout = $3
             )",
        )
        .bind(invoice.id)
        .bind(&txid)
        .bind(vout)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if baseline_member {
            return Ok(true);
        }
        if let Some(height) = confirmed_height
            && height
                <= u32::try_from(invoice.creation_chain_height)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?
        {
            return Ok(true);
        }
        if crate::bitcoin::amount_matches(present, observed_sats, required)
            && confirmations > 0
            && !approved_candidate
            && require_candidate
        {
            let height = confirmed_height.ok_or(PersistenceError::CorruptOrMissing)?;
            sqlx::query(
                "INSERT INTO bitcoin_observation_candidates
                    (invoice_id, txid, vout, confirmations, confirmed_height)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (invoice_id) DO UPDATE SET
                    txid = EXCLUDED.txid, vout = EXCLUDED.vout,
                    confirmations = EXCLUDED.confirmations,
                    confirmed_height = EXCLUDED.confirmed_height,
                    approved = FALSE, attempt_count = 0, last_attempt_at = NULL,
                    next_attempt_at = NOW(), last_error_kind = NULL,
                    state = 'pending', updated_at = NOW()
                 WHERE EXCLUDED.confirmed_height
                    < bitcoin_observation_candidates.confirmed_height",
            )
            .bind(invoice.id)
            .bind(&txid)
            .bind(vout)
            .bind(confirmations)
            .bind(i32::try_from(height).map_err(|_| PersistenceError::CorruptOrMissing)?)
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(true);
        }

        let outpoint_lookup_hash = self
            .crypto
            .bitcoin_outpoint_lookup_hash(outpoint.as_bytes());
        let existing_outpoint = sqlx::query_as::<_, BitcoinObservationRow>(
            "SELECT id, invoice_id, observation_envelope, outpoint_lookup_hash,
                    confirmations, present
             FROM bitcoin_observations WHERE outpoint_lookup_hash = $1 FOR UPDATE",
        )
        .bind(outpoint_lookup_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if existing_outpoint
            .as_ref()
            .is_some_and(|row| row.invoice_id != invoice.id)
        {
            return Err(PersistenceError::Conflict);
        }
        if let Some(row) = existing_outpoint.as_ref() {
            let record = self.decrypt_observation(creator_hash, row)?;
            if record.outpoint != outpoint
                || row.outpoint_lookup_hash != outpoint_lookup_hash.as_bytes()
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
        }
        let active = sqlx::query_as::<_, BitcoinObservationRow>(
            "SELECT id, invoice_id, observation_envelope, outpoint_lookup_hash,
                    confirmations, present
             FROM bitcoin_observations WHERE invoice_id = $1 AND active FOR UPDATE",
        )
        .bind(invoice.id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let active_record = active
            .as_ref()
            .map(|row| self.decrypt_observation(creator_hash, row))
            .transpose()?;

        let action = active
            .as_ref()
            .zip(active_record.as_ref())
            .map(|(row, record)| {
                DirectBinding::new(
                    &record.outpoint,
                    record.observed_sats,
                    u32::try_from(row.confirmations).unwrap_or_default(),
                    row.present,
                )
                .action_for_values(
                    &outpoint,
                    observed_sats,
                    incoming_confirmations,
                    present,
                    required,
                )
            });
        if action == Some(ObservationAction::Ignore) {
            return Ok(true);
        }
        // An unseen output with no existing binding is not an observation and
        // must not manufacture a binding for an otherwise undetected invoice.
        if active.is_none() && !present {
            return Ok(true);
        }
        if action == Some(ObservationAction::Replace) {
            sqlx::query(
                "UPDATE bitcoin_observations SET active = FALSE, updated_at = NOW() \
                 WHERE invoice_id = $1 AND active",
            )
            .bind(invoice.id)
            .execute(&mut **tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        let observation_id = existing_outpoint
            .as_ref()
            .map_or_else(Uuid::new_v4, |row| row.id);
        let observation_plaintext = postcard::to_allocvec(&BitcoinObservationV1 {
            version: 1,
            outpoint: outpoint.to_owned(),
            observed_sats,
        })
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let observation_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::bitcoin_observation_for_invoice(
                    creator_hash,
                    observation_id,
                    invoice.id,
                ),
                &observation_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let observation_write = sqlx::query(
            "INSERT INTO bitcoin_observations \
            (id, invoice_id, observation_envelope, outpoint_lookup_hash,
            confirmations, present, active) \
            VALUES ($1, $2, $3, $4, $5, $6, TRUE) \
            ON CONFLICT (outpoint_lookup_hash) DO UPDATE SET
            observation_envelope = EXCLUDED.observation_envelope,
            confirmations = EXCLUDED.confirmations, present = EXCLUDED.present, active = TRUE, \
            updated_at = NOW() WHERE bitcoin_observations.invoice_id = EXCLUDED.invoice_id",
        )
        .bind(observation_id)
        .bind(invoice.id)
        .bind(observation_envelope.as_bytes())
        .bind(outpoint_lookup_hash.as_bytes().as_slice())
        .bind(confirmations)
        .bind(present)
        .execute(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Conflict)?;
        if observation_write.rows_affected() != 1 {
            return Err(PersistenceError::Conflict);
        }
        // §B.8.2: the match is exact. An overpayment reports confirmed with
        // amount_matched = false and takes the same manual-review path as an
        // underpayment; the nonce is absorbed in the price, never refunded.
        let amount_matched = crate::bitcoin::amount_matches(present, observed_sats, required);
        let reported_confirmations = if amount_matched {
            incoming_confirmations.min(6)
        } else if present {
            incoming_confirmations
        } else {
            0
        };
        let status = if !present {
            "undetected"
        } else if reported_confirmations == 0 {
            "detected"
        } else {
            "confirmed"
        };
        sqlx::query("UPDATE invoices SET payment_status = $1, confirmation_count = $2, amount_matched = $3, updated_at = NOW() WHERE id = $4")
            .bind(status).bind(i32::try_from(reported_confirmations).map_err(|_| PersistenceError::CorruptOrMissing)?).bind(amount_matched).bind(invoice.id)
            .execute(&mut **tx).await.map_err(|_| PersistenceError::Unavailable)?;
        Ok(true)
    }

    /// Atomically resolves the creator, checks replay, allocates/reuses a
    /// reader, persists an invoice, and inserts ordered encrypted outbox work.
    pub async fn create_atomic(
        &self,
        input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        self.create_atomic_with_state(input, "observing", "queued")
            .await
    }

    pub async fn create_awaiting_baseline(
        &self,
        input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        self.create_atomic_with_state(input, "awaiting_baseline", "prepared")
            .await
    }

    async fn create_atomic_with_state(
        &self,
        input: AtomicInvoiceInput<'_>,
        baseline_state: &'static str,
        outbox_status: &'static str,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        let creator_hash = self
            .crypto
            .lookup_hash(input.creator.to_string().as_bytes());
        let reader_hash = self.crypto.lookup_hash(input.reader.to_string().as_bytes());
        let bundle_hash = self.crypto.lookup_hash(input.bundle_binding);
        let payment_request_hash = self.crypto.lookup_hash(input.payment_request_binding);

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let creator = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, next_child_index \
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

        if let Some(existing) = sqlx::query_as::<_, ExistingInvoice>(
            "SELECT id, payment_request_lookup_hash FROM invoices \
             WHERE creator_id = $1 AND bundle_lookup_hash = $2 FOR UPDATE",
        )
        .bind(creator.id)
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        {
            if existing.payment_request_lookup_hash != payment_request_hash.as_bytes() {
                return Err(PersistenceError::Conflict);
            }
            let assignment = self
                .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
                .await?
                .ok_or(PersistenceError::CorruptOrMissing)?;
            let payment_request_outbox = sqlx::query_as::<_, ExistingPaymentOutbox>(
                "SELECT id, depends_on_id FROM outbox \
                 WHERE invoice_id = $1 AND depends_on_id IS NOT NULL \
                 ORDER BY created_at, id LIMIT 1",
            )
            .bind(existing.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?
            .ok_or(PersistenceError::CorruptOrMissing)?;
            tx.commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            return Ok(AtomicInvoiceResult {
                invoice_id: existing.id,
                payment_request_outbox_id: payment_request_outbox.id,
                endpoint_publication_outbox_id: payment_request_outbox.depends_on_id,
                reader_assignment_id: assignment.id,
                reader_child_index: assignment.child_index,
                replayed: true,
            });
        }

        validate_intent(&input.payment_request_intent, input.reader, false)?;
        let (assignment, endpoint_publication_outbox_id, bitcoin_address) = match self
            .load_assignment(&mut tx, creator.id, reader_hash, bundle_hash, creator_hash)
            .await?
        {
            // A row for this triple must have been returned by the replay lookup
            // above. Anything else is legacy/corrupt state, never a reusable address.
            Some(_) => return Err(PersistenceError::CorruptOrMissing),
            None => {
                let payloads = input
                    .new_reader_payloads
                    .for_child_index(creator.next_child_index)?;
                validate_intent(&payloads.endpoint_intent, input.reader, true)?;
                let assignment_id = Uuid::new_v4();
                let endpoint_plaintext = postcard::to_allocvec(&payloads.endpoint_intent)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                let envelope = encrypt_assignment(
                    &self.crypto,
                    creator_hash,
                    assignment_id,
                    creator.next_child_index,
                    &endpoint_plaintext,
                )?;
                sqlx::query(
                    "INSERT INTO reader_assignments \
                     (id, creator_id, reader_lookup_hash, bundle_lookup_hash, assignment_envelope) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(assignment_id)
                .bind(creator.id)
                .bind(reader_hash.as_bytes().as_slice())
                .bind(bundle_hash.as_bytes().as_slice())
                .bind(envelope.as_bytes())
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Conflict)?;
                sqlx::query(
                    "UPDATE creators SET next_child_index = next_child_index + 1, updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(creator.id)
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;

                let endpoint_id = Uuid::new_v4();
                let endpoint_envelope = self
                    .crypto
                    .encrypt(
                        &EnvelopeContext::outbox_semantic_intent(creator_hash, endpoint_id),
                        &endpoint_plaintext,
                    )
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;

                insert_outbox(
                    &mut tx,
                    OutboxInsert {
                        id: endpoint_id,
                        creator_id: creator.id,
                        invoice_id: None,
                        intent_envelope: endpoint_envelope.as_bytes(),
                        depends_on_id: None,
                        reader_assignment_id: Some(assignment_id),
                        status: outbox_status,
                    },
                )
                .await?;
                (
                    Assignment {
                        id: assignment_id,
                        child_index: creator.next_child_index,
                    },
                    Some(endpoint_id),
                    payloads.bitcoin_address,
                )
            }
        };

        if !(crate::domain::invoice::NONCE_SATS_MIN..=crate::domain::invoice::NONCE_SATS_MAX)
            .contains(&input.nonce_sats)
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let payment_request_plaintext = postcard::to_allocvec(&input.payment_request_intent)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let invoice_id = Uuid::new_v4();
        let payment_record_plaintext = postcard::to_allocvec(&InvoicePaymentRecordV3 {
            version: 3,
            derivation_index: assignment.child_index,
            bitcoin_address: bitcoin_address.clone(),
            required_sats: input.required_sats,
            nonce_sats: input.nonce_sats,
            creation_chain_height: 0,
            baseline_set_hash: Sha256::digest([]).into(),
        })
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let payment_record_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::invoice_payment_record(creator_hash, invoice_id),
                &payment_record_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let bitcoin_address_lookup_hash = self
            .crypto
            .bitcoin_address_lookup_hash(bitcoin_address.as_bytes());
        let derivation_index_lookup_hash = self
            .crypto
            .bitcoin_derivation_index_lookup_hash(creator_hash, assignment.child_index);
        let invoice_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::invoice(creator_hash, invoice_id),
                &payment_request_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        sqlx::query(
            "INSERT INTO invoices \
             (id, creator_id, reader_lookup_hash, bundle_lookup_hash, payment_request_lookup_hash, invoice_envelope, payment_record_envelope, bitcoin_address_lookup_hash, derivation_index_lookup_hash, payment_status, baseline_state) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'undetected', $10)",
        )
        .bind(invoice_id)
        .bind(creator.id)
        .bind(reader_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .bind(payment_request_hash.as_bytes().as_slice())
        .bind(invoice_envelope.as_bytes())
        .bind(payment_record_envelope.as_bytes())
        .bind(bitcoin_address_lookup_hash.as_bytes().as_slice())
        .bind(derivation_index_lookup_hash.as_bytes().as_slice())
        .bind(baseline_state)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Conflict)?;
        // Endpoint publication is invoice-scoped, not a reusable reader assignment.
        sqlx::query("UPDATE outbox SET invoice_id = $1 WHERE id = $2")
            .bind(invoice_id)
            .bind(endpoint_publication_outbox_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;

        let payment_request_outbox_id = Uuid::new_v4();
        let payment_request_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::outbox_semantic_intent(creator_hash, payment_request_outbox_id),
                &payment_request_plaintext,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;

        insert_outbox(
            &mut tx,
            OutboxInsert {
                id: payment_request_outbox_id,
                creator_id: creator.id,
                invoice_id: Some(invoice_id),
                intent_envelope: payment_request_envelope.as_bytes(),
                depends_on_id: endpoint_publication_outbox_id,
                reader_assignment_id: None,
                status: outbox_status,
            },
        )
        .await?;

        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(AtomicInvoiceResult {
            invoice_id,
            payment_request_outbox_id,
            endpoint_publication_outbox_id,
            reader_assignment_id: assignment.id,
            reader_child_index: assignment.child_index,
            replayed: false,
        })
    }

    fn decrypt_observation(
        &self,
        creator_hash: LookupHash,
        row: &BitcoinObservationRow,
    ) -> Result<BitcoinObservationV1, PersistenceError> {
        let plaintext = self
            .crypto
            .decrypt(
                &EnvelopeContext::bitcoin_observation_for_invoice(
                    creator_hash,
                    row.id,
                    row.invoice_id,
                ),
                &EncryptedEnvelope::from_bytes(row.observation_envelope.clone()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let record: BitcoinObservationV1 =
            postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
        if record.version != 1
            || parse_canonical_bitcoin_outpoint(&record.outpoint).is_err()
            || row.outpoint_lookup_hash
                != self
                    .crypto
                    .bitcoin_outpoint_lookup_hash(record.outpoint.as_bytes())
                    .as_bytes()
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok(record)
    }

    async fn load_assignment(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        creator_id: Uuid,
        reader_hash: LookupHash,
        bundle_hash: LookupHash,
        creator_hash: LookupHash,
    ) -> Result<Option<Assignment>, PersistenceError> {
        let row = sqlx::query_as::<_, AssignmentRow>(
            "SELECT id, assignment_envelope FROM reader_assignments \
             WHERE creator_id = $1 AND reader_lookup_hash = $2 AND bundle_lookup_hash = $3 FOR UPDATE",
        )
        .bind(creator_id)
        .bind(reader_hash.as_bytes().as_slice())
        .bind(bundle_hash.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        row.map(|row| {
            decrypt_assignment(&self.crypto, creator_hash, row.id, &row.assignment_envelope).map(
                |child_index| Assignment {
                    id: row.id,
                    child_index,
                },
            )
        })
        .transpose()
    }
}

struct OutboxInsert<'a> {
    id: Uuid,
    creator_id: Uuid,
    invoice_id: Option<Uuid>,
    intent_envelope: &'a [u8],
    depends_on_id: Option<Uuid>,
    reader_assignment_id: Option<Uuid>,
    status: &'static str,
}

async fn insert_outbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: OutboxInsert<'_>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        "INSERT INTO outbox \
         (id, creator_id, invoice_id, intent_envelope, status, depends_on_id, reader_assignment_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(row.id)
    .bind(row.creator_id)
    .bind(row.invoice_id)
    .bind(row.intent_envelope)
    .bind(row.status)
    .bind(row.depends_on_id)
    .bind(row.reader_assignment_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| PersistenceError::Unavailable)?;
    Ok(())
}

fn validate_intent(
    intent: &DeliveryIntentV1,
    reader: &ReaderPubky,
    endpoint: bool,
) -> Result<(), PersistenceError> {
    intent
        .validate()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    if intent.reader_pubky() != reader.to_string() {
        return Err(PersistenceError::CorruptOrMissing);
    }
    match (endpoint, intent.operation()) {
        (true, DeliveryOperationV1::EndpointPublication { .. })
        | (false, DeliveryOperationV1::PaymentRequestProposal { .. }) => Ok(()),
        _ => Err(PersistenceError::CorruptOrMissing),
    }
}

fn lookup_hash_from_storage(bytes: &[u8]) -> Result<LookupHash, PersistenceError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    Ok(LookupHash::from_bytes(bytes))
}

fn lookup_hash(bytes: &[u8]) -> Result<LookupHash, PersistenceError> {
    lookup_hash_from_storage(bytes)
}

#[derive(sqlx::FromRow)]
struct CreatorRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    next_child_index: i64,
}

fn parse_canonical_bitcoin_outpoint(value: &str) -> Result<BitcoinOutpoint, PersistenceError> {
    let outpoint = value
        .parse::<bitcoin::OutPoint>()
        .map(BitcoinOutpoint::from_bitcoin)
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    if outpoint.canonical_text() != value {
        return Err(PersistenceError::CorruptOrMissing);
    }
    Ok(outpoint)
}

#[derive(sqlx::FromRow)]
struct BitcoinInvoiceRow {
    id: Uuid,
    payment_record_envelope: Vec<u8>,
    bitcoin_address_lookup_hash: Vec<u8>,
    payment_status: String,
    confirmation_count: i32,
    amount_matched: bool,
    baseline_state: String,
    creation_chain_height: i32,
    creator_lookup_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct BitcoinObservationRow {
    id: Uuid,
    invoice_id: Uuid,
    observation_envelope: Vec<u8>,
    outpoint_lookup_hash: Vec<u8>,
    confirmations: i32,
    present: bool,
}

#[derive(sqlx::FromRow)]
struct ObservationTargetRow {
    invoice_id: Uuid,
    creator_lookup_hash: Vec<u8>,
    payment_record_envelope: Vec<u8>,
    bitcoin_address_lookup_hash: Vec<u8>,
    derivation_index_lookup_hash: Vec<u8>,
    observation_id: Option<Uuid>,
    observation_envelope: Option<Vec<u8>>,
    outpoint_lookup_hash: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct ObservationPlanRow {
    #[sqlx(flatten)]
    target: ObservationTargetRow,
    staleness_secs: i64,
}

#[derive(sqlx::FromRow)]
struct ExistingInvoice {
    id: Uuid,
    payment_request_lookup_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct ExistingPaymentOutbox {
    id: Uuid,
    depends_on_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct PaymentStatusRow {
    payment_status: String,
    confirmation_count: i32,
    amount_matched: bool,
}

impl TryFrom<PaymentStatusRow> for PersistedPaymentStatus {
    type Error = PersistenceError;

    fn try_from(row: PaymentStatusRow) -> Result<Self, Self::Error> {
        let confirmations = u32::try_from(row.confirmation_count)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        match row.payment_status.as_str() {
            "undetected" => Ok(Self::Undetected),
            "detected" => Ok(Self::Detected {
                confirmations,
                amount_matched: row.amount_matched,
            }),
            "confirmed" => Ok(Self::Confirmed {
                confirmations,
                amount_matched: row.amount_matched,
            }),
            _ => Err(PersistenceError::CorruptOrMissing),
        }
    }
}

#[derive(sqlx::FromRow)]
struct AssignmentRow {
    id: Uuid,
    assignment_envelope: Vec<u8>,
}

struct Assignment {
    id: Uuid,
    child_index: i64,
}

#[derive(Serialize)]
struct ReaderAssignmentV1Ref<'a> {
    version: u8,
    child_index: i64,
    opaque_payload: &'a [u8],
}

#[derive(Deserialize)]
struct ReaderAssignmentV1 {
    version: u8,
    child_index: i64,
    opaque_payload: Vec<u8>,
}

fn encrypt_assignment(
    crypto: &Crypto,
    creator_hash: LookupHash,
    id: Uuid,
    child_index: i64,
    opaque_payload: &[u8],
) -> Result<EncryptedEnvelope, PersistenceError> {
    let bytes = Zeroizing::new(
        postcard::to_allocvec(&ReaderAssignmentV1Ref {
            version: 1,
            child_index,
            opaque_payload,
        })
        .map_err(|_| PersistenceError::CorruptOrMissing)?,
    );
    crypto
        .encrypt(
            &EnvelopeContext::reader_assignment(creator_hash, id),
            &bytes,
        )
        .map_err(|_| PersistenceError::CorruptOrMissing)
}

fn decrypt_assignment(
    crypto: &Crypto,
    creator_hash: LookupHash,
    id: Uuid,
    envelope: &[u8],
) -> Result<i64, PersistenceError> {
    let bytes = Zeroizing::new(
        crypto
            .decrypt(
                &EnvelopeContext::reader_assignment(creator_hash, id),
                &EncryptedEnvelope::from_bytes(envelope.to_vec()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?,
    );
    let assignment: ReaderAssignmentV1 =
        postcard::from_bytes(&bytes).map_err(|_| PersistenceError::CorruptOrMissing)?;
    if assignment.version != 1 || assignment.child_index < 0 {
        return Err(PersistenceError::CorruptOrMissing);
    }
    // The opaque payload is intentionally never inspected or returned here.
    let _ = assignment.opaque_payload;
    Ok(assignment.child_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_hash_recomputation_orders_with_explicit_c_collation() {
        assert!(
            BASELINE_ENTRIES_SQL.contains("ORDER BY kind COLLATE \"C\", txid COLLATE \"C\", vout"),
            "baseline-hash recomputation ordering must pin byte-exact C collation, got: {BASELINE_ENTRIES_SQL}"
        );
    }

    #[test]
    fn read_status_rejects_unknown_text_and_invalid_confirmation_counts() {
        for row in [
            PaymentStatusRow {
                payment_status: "unexpected".into(),
                confirmation_count: 0,
                amount_matched: false,
            },
            PaymentStatusRow {
                payment_status: "confirmed".into(),
                confirmation_count: -1,
                amount_matched: true,
            },
        ] {
            assert_eq!(
                PersistedPaymentStatus::try_from(row),
                Err(PersistenceError::CorruptOrMissing)
            );
        }
    }

    #[test]
    fn persisted_observations_accept_only_exact_canonical_outpoints() {
        let txid = "ab".repeat(32);
        assert!(parse_canonical_bitcoin_outpoint(&format!("{txid}:0")).is_ok());
        for malformed in [
            "legacy-outpoint:0".to_owned(),
            format!("{}:0", txid.to_ascii_uppercase()),
            format!("{txid}:00"),
            format!("{txid}:0:1"),
        ] {
            assert_eq!(
                parse_canonical_bitcoin_outpoint(&malformed),
                Err(PersistenceError::CorruptOrMissing)
            );
        }
    }
}
