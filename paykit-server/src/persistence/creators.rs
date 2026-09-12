//! Encrypted creator authority persistence.

use std::{collections::HashMap, fmt, time::Duration};

use paykit_sdk::{ReceiverNoiseSecretKey, storage::StorageState};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    allocation::{AllocationMode, ClaimAllocation, DowngradeReason},
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::locks::{CreatorPubky, parse_creator},
    persistence::PersistenceError,
    sentinel::{
        SentinelClassification, SentinelEvidenceRecord, SentinelFinding, SentinelScanOutcome,
        SentinelScanTarget, SentinelThresholds, downgrade_predicate,
    },
};

/// Secret-bearing creator authority accepted by the persistence boundary.
pub struct CreatorCredentials {
    creator: CreatorPubky,
    session_secret: Zeroizing<String>,
    receiver_noise_secret: ReceiverNoiseSecretKey,
    xpub: Zeroizing<String>,
    account_index: u32,
}

impl fmt::Debug for CreatorCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CreatorCredentials(<redacted>)")
    }
}

impl CreatorCredentials {
    /// Constructs creator authority from canonical identity and SDK secret wrappers.
    pub fn new(
        creator: CreatorPubky,
        session_secret: String,
        receiver_noise_secret: ReceiverNoiseSecretKey,
        xpub: String,
        account_index: u32,
    ) -> Self {
        Self::from_secret_parts(
            creator,
            Zeroizing::new(session_secret),
            receiver_noise_secret,
            Zeroizing::new(xpub),
            account_index,
        )
    }

    fn from_secret_parts(
        creator: CreatorPubky,
        session_secret: Zeroizing<String>,
        receiver_noise_secret: ReceiverNoiseSecretKey,
        xpub: Zeroizing<String>,
        account_index: u32,
    ) -> Self {
        Self {
            creator,
            session_secret,
            receiver_noise_secret,
            xpub,
            account_index,
        }
    }

    /// Returns the canonical creator identity.
    pub fn creator(&self) -> &CreatorPubky {
        &self.creator
    }
    /// Borrows the current Pubky session bearer secret.
    pub fn session_secret(&self) -> &str {
        self.session_secret.as_str()
    }
    /// Borrows the receiver-scoped Noise secret.
    pub fn receiver_noise_secret(&self) -> &ReceiverNoiseSecretKey {
        &self.receiver_noise_secret
    }
    /// Borrows the exact persisted account xpub.
    pub fn xpub(&self) -> &str {
        self.xpub.as_str()
    }
    /// Returns the immutable account index.
    pub fn account_index(&self) -> u32 {
        self.account_index
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PersistenceError> {
        let creator = self.creator.to_string();
        let wire = CreatorCredentialsV1Ref {
            version: 1,
            creator: &creator,
            session_secret: self.session_secret.as_str(),
            receiver_noise_secret: self.receiver_noise_secret.as_bytes(),
            xpub: self.xpub.as_str(),
            account_index: self.account_index,
        };
        postcard::to_allocvec(&wire)
            .map(Zeroizing::new)
            .map_err(|_| PersistenceError::CorruptOrMissing)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PersistenceError> {
        let wire: CreatorCredentialsV1 =
            postcard::from_bytes(bytes).map_err(|_| PersistenceError::CorruptOrMissing)?;
        if wire.version != 1 {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let creator =
            parse_creator(&wire.creator).map_err(|_| PersistenceError::CorruptOrMissing)?;
        Ok(Self::from_secret_parts(
            creator,
            wire.session_secret,
            ReceiverNoiseSecretKey::new(*wire.receiver_noise_secret),
            wire.xpub,
            wire.account_index,
        ))
    }
}

#[derive(Serialize)]
struct CreatorCredentialsV1Ref<'a> {
    version: u8,
    creator: &'a str,
    session_secret: &'a str,
    receiver_noise_secret: &'a [u8; 32],
    xpub: &'a str,
    account_index: u32,
}

#[derive(Deserialize)]
struct CreatorCredentialsV1 {
    version: u8,
    creator: String,
    session_secret: Zeroizing<String>,
    receiver_noise_secret: Zeroizing<[u8; 32]>,
    xpub: Zeroizing<String>,
    account_index: u32,
}

/// Immutable identity assigned to a persisted creator row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedCreator {
    id: Uuid,
    lookup_hash: LookupHash,
}
impl PersistedCreator {
    /// Returns the internal row UUID used in envelope AAD.
    pub fn id(&self) -> Uuid {
        self.id
    }
}

/// Encrypted creator and initial SDK-state repository.
#[derive(Clone, Debug)]
pub struct CreatorStore {
    pool: PgPool,
    crypto: std::sync::Arc<Crypto>,
}

/// A creator-scoped PostgreSQL session advisory lock used to serialize setup
/// publication and persistence across all server processes sharing the database.
/// Its dedicated connection is detached from the pool, so cancellation drops
/// the connection and releases PostgreSQL's session lock instead of returning a
/// locked session to the pool.
pub struct CreatorSetupLock {
    connection: PgConnection,
    key: i64,
}

impl CreatorSetupLock {
    /// Releases the advisory lock before closing its dedicated connection.
    pub async fn release(mut self) -> Result<(), PersistenceError> {
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(self.key)
            .execute(&mut self.connection)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(())
    }
}

impl CreatorStore {
    /// Creates a creator repository using a deployment-scoped crypto context.
    pub fn new(pool: &PgPool, crypto: std::sync::Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    /// Serializes the full setup critical section for one creator. Callers must
    /// hold this lock before loading credentials, publishing a marker, and
    /// committing credentials, then call [`CreatorSetupLock::release`].
    pub async fn acquire_setup_lock(
        &self,
        creator: &CreatorPubky,
    ) -> Result<CreatorSetupLock, PersistenceError> {
        let lookup_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let key = i64::from_be_bytes(
            lookup_hash.as_bytes()[..8]
                .try_into()
                .expect("lookup hashes are 32 bytes"),
        );
        // A session advisory lock survives returning a connection to the pool.
        // Detach before acquiring it so cancellation closes the connection and
        // PostgreSQL releases the lock.
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| PersistenceError::Unavailable)?
            .detach();
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(&mut connection)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(CreatorSetupLock { connection, key })
    }

    /// Inserts a creator and its initial full SDK state atomically, binding
    /// the claim's canonical key tail to this creator in the same
    /// transaction (design B.8.5). The claim's allocation decision (design
    /// B.8.6) is written in that same transaction: the INSERT is the ONLY
    /// statement in the system that can persist the `exclusive` mode, and
    /// only when the claim-channel checks computed it — creation is the
    /// sole `— → exclusive` transition in the design's table.
    ///
    /// `first_child_index` is the claim-time child index (W1.13 r3): the
    /// derivation cursor value the claim response's `first_derived_address`
    /// was derived at. It is written here, at row creation, and no statement
    /// ever updates it, so the seller status surface can re-derive that exact
    /// address forever while `next_child_index` moves with invoice
    /// allocation.
    pub async fn create(
        &self,
        credentials: &CreatorCredentials,
        state: &StorageState,
        key_tail: &[u8; 65],
        allocation: &ClaimAllocation,
        first_child_index: i64,
    ) -> Result<PersistedCreator, PersistenceError> {
        let lookup_hash = self
            .crypto
            .lookup_hash(credentials.creator().to_string().as_bytes());
        let id = Uuid::new_v4();
        let credentials_bytes = credentials.encode()?;
        let credential_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::creator_credentials(lookup_hash, id),
                &credentials_bytes,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let state_envelope =
            crate::persistence::sdk_state::encrypt_state(&self.crypto, lookup_hash, id, state)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        self.bind_key_tail(&mut tx, key_tail, &lookup_hash).await?;
        sqlx::query("INSERT INTO creators (id, creator_lookup_hash, credential_envelope, allocation_mode, claim_channel, downgrade_reason, first_child_index) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(id).bind(lookup_hash.as_bytes().as_slice()).bind(credential_envelope.as_bytes())
            .bind(allocation.mode.as_str())
            .bind(allocation.channel.as_deref())
            .bind(allocation.downgrade_reason.map(|reason| reason.as_str()))
            .bind(first_child_index)
            .execute(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("INSERT INTO sdk_states (creator_id, state_envelope) VALUES ($1, $2)")
            .bind(id)
            .bind(state_envelope.as_bytes())
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(PersistedCreator { id, lookup_hash })
    }

    /// Whether the canonical key tail was ever claimed by a creator other
    /// than `creator` on this stack. This is the claim handler's read-only
    /// pre-check so a refused claim never reaches Electrum; the authoritative
    /// check is the binding write inside the claim-commit transaction, which
    /// the primary key serializes under concurrency.
    pub async fn key_tail_claimed_by_other(
        &self,
        key_tail: &[u8; 65],
        creator: &CreatorPubky,
    ) -> Result<bool, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let claimed_by: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT creator_lookup_hash FROM claimed_key_fingerprints WHERE key_tail = $1",
        )
        .bind(key_tail.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(claimed_by.is_some_and(|claimed| claimed != hash.as_bytes()))
    }

    /// Writes the never-expiring fingerprint-to-seller binding inside the
    /// caller's claim-commit transaction. `ON CONFLICT DO NOTHING` blocks on
    /// a concurrent uncommitted claim of the same tail until it commits, so
    /// exactly one of two racing first claims wins; the loser (and any later
    /// claim by a different creator, active or not) is refused with
    /// [`PersistenceError::KeyClaimedByOtherSeller`], rolling the whole claim
    /// commit back. A re-claim by the same creator is unaffected.
    async fn bind_key_tail(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        key_tail: &[u8; 65],
        lookup_hash: &LookupHash,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "INSERT INTO claimed_key_fingerprints (key_tail, creator_lookup_hash) \
             VALUES ($1, $2) ON CONFLICT (key_tail) DO NOTHING",
        )
        .bind(key_tail.as_slice())
        .bind(lookup_hash.as_bytes().as_slice())
        .execute(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let claimed_by: Vec<u8> = sqlx::query_scalar(
            "SELECT creator_lookup_hash FROM claimed_key_fingerprints WHERE key_tail = $1",
        )
        .bind(key_tail.as_slice())
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if claimed_by != lookup_hash.as_bytes() {
            return Err(PersistenceError::KeyClaimedByOtherSeller);
        }
        Ok(())
    }

    /// Loads and authenticates a creator credential envelope by canonical creator identity.
    pub async fn load(
        &self,
        creator: &CreatorPubky,
    ) -> Result<CreatorCredentials, PersistenceError> {
        let row = self.lookup_row(creator).await?;
        self.decrypt_credentials(&row)
    }

    /// Loads and authenticates one exact internal Creator row for worker composition.
    pub async fn load_by_id(
        &self,
        creator_id: Uuid,
    ) -> Result<CreatorCredentials, PersistenceError> {
        let row = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE id = $1",
        )
        .bind(creator_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        self.decrypt_credentials(&row)
    }

    /// The creator's allocation status for the authenticated seller status
    /// surface (design §B.8.6): the mode, the claim channel recorded at claim
    /// time, the downgrade reason if any, and the persisted account key data
    /// (`xpub`, `account_index`, derivation cursor) the status endpoint
    /// derives the client's required evidence fields from — the same
    /// derivations the claim response performs (`key_identity.rs`,
    /// `derive_bip84_p2wpkh_address`). One row read; no key material leaves
    /// the server (the fingerprint is a hash, the first address is what
    /// invoices reveal anyway). `None` when the creator never claimed.
    /// Detection evidence metadata (§B.8.7, W1.14) is served separately by
    /// [`CreatorStore::sentinel_evidence`].
    pub async fn allocation_status(
        &self,
        creator: &CreatorPubky,
    ) -> Result<Option<CreatorStatusRecord>, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let row = sqlx::query_as::<_, CreatorStatusRow>(
            "SELECT id, creator_lookup_hash, credential_envelope, next_child_index, first_child_index, allocation_mode, claim_channel, downgrade_reason FROM creators WHERE creator_lookup_hash = $1",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let credentials = self.decrypt_credentials(&CreatorRow {
            id: row.id,
            creator_lookup_hash: row.creator_lookup_hash,
            credential_envelope: row.credential_envelope,
        })?;
        Ok(Some(CreatorStatusRecord {
            allocation: CreatorAllocationStatus {
                allocation_mode: row.allocation_mode,
                claim_channel: row.claim_channel,
                downgrade_reason: row.downgrade_reason,
            },
            xpub: credentials.xpub().to_owned(),
            account_index: credentials.account_index(),
            next_child_index: row.next_child_index,
            first_child_index: row.first_child_index,
        }))
    }

    /// Loads an existing creator when present. A present but unauthenticatable
    /// row is an error rather than an invitation to overwrite it during setup.
    pub async fn load_optional(
        &self,
        creator: &CreatorPubky,
    ) -> Result<Option<CreatorCredentials>, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let row = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE creator_lookup_hash = $1",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        row.map(|row| self.decrypt_credentials(&row)).transpose()
    }

    /// Replaces only the Pubky session secret after proving immutable account identity matches.
    /// The claim's canonical key tail is bound to this creator in the same
    /// transaction: a re-claim by the same creator is unaffected, and a tail
    /// ever claimed by a different creator is refused (design B.8.5).
    ///
    /// Allocation on re-claim (design B.8.6): a re-authentication may only
    /// KEEP or DOWNGRADE the creator's mode — there is no edit that moves a
    /// creator into `exclusive`. An `exclusive` creator whose re-claim passes
    /// every corroborating check keeps its mode (the UPDATE then touches no
    /// allocation columns); every other re-claim lands on the one UPDATE
    /// below, whose `allocation_mode` literal is `shared_manual` — no
    /// re-claim path contains a statement that can write `exclusive`. A
    /// re-claim that computed no new downgrade reason keeps the reason
    /// already recorded (`COALESCE`), so a passing re-claim never erases why
    /// the seller is manual. Returns the persisted allocation status so the
    /// claim response reports the row, not the request.
    pub async fn reauthenticate(
        &self,
        replacement: &CreatorCredentials,
        key_tail: &[u8; 65],
        allocation: &ClaimAllocation,
    ) -> Result<CreatorAllocationStatus, PersistenceError> {
        let hash = self
            .crypto
            .lookup_hash(replacement.creator().to_string().as_bytes());
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let row = sqlx::query_as::<_, CreatorRow>("SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE")
            .bind(hash.as_bytes().as_slice()).fetch_optional(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?.ok_or(PersistenceError::CorruptOrMissing)?;
        let existing = self.decrypt_credentials(&row)?;
        if existing.xpub != replacement.xpub || existing.account_index != replacement.account_index
        {
            return Err(PersistenceError::ReauthenticationMismatch);
        }
        let existing_mode: String =
            sqlx::query_scalar("SELECT allocation_mode FROM creators WHERE id = $1")
                .bind(row.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
        self.bind_key_tail(&mut tx, key_tail, &hash).await?;
        let updated = CreatorCredentials::from_secret_parts(
            existing.creator,
            replacement.session_secret.clone(),
            existing.receiver_noise_secret,
            existing.xpub,
            existing.account_index,
        );
        let bytes = updated.encode()?;
        let envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::creator_credentials(row.lookup_hash()?, row.id),
                &bytes,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        if existing_mode == AllocationMode::Exclusive.as_str()
            && allocation.mode == AllocationMode::Exclusive
        {
            // Keep: the re-claim re-proved every corroborating check on the
            // same immutable account. Only the session secret and the
            // verbatim channel of the latest claim move.
            sqlx::query(
                "UPDATE creators SET credential_envelope = $1, claim_channel = $2, updated_at = NOW() WHERE id = $3",
            )
            .bind(envelope.as_bytes())
            .bind(allocation.channel.as_deref())
            .bind(row.id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        } else {
            // Downgrade (or stay shared): the re-claim's own decision is
            // recorded verbatim. The literal below is the ONLY mode this
            // statement can write, and a re-claim with no new reason keeps
            // the recorded one.
            sqlx::query(
                "UPDATE creators SET credential_envelope = $1, claim_channel = $2, allocation_mode = 'shared_manual', downgrade_reason = COALESCE($3, downgrade_reason), updated_at = NOW() WHERE id = $4",
            )
            .bind(envelope.as_bytes())
            .bind(allocation.channel.as_deref())
            .bind(allocation.downgrade_reason.map(|reason| reason.as_str()))
            .bind(row.id)
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        }
        let status = sqlx::query_as::<_, CreatorAllocationStatus>(
            "SELECT allocation_mode, claim_channel, downgrade_reason FROM creators WHERE id = $1",
        )
        .bind(row.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(status)
    }

    /// Advances the creator's derivation cursor to at least `floor` and
    /// returns the resulting cursor pair. The update is monotonic
    /// (`GREATEST`), so a re-claim can never move the cursor backwards over
    /// an already allocated child index, and it never touches
    /// `first_child_index` — the claim-time index is written once at row
    /// creation. Callers hold the creator's setup lock, so this runs inside
    /// the same critical section as the claim commit.
    pub async fn advance_next_child_index(
        &self,
        creator: &CreatorPubky,
        floor: i64,
    ) -> Result<ChildIndexCursor, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        sqlx::query_as::<_, ChildIndexCursor>(
            "UPDATE creators SET next_child_index = GREATEST(next_child_index, $2), updated_at = NOW() \
             WHERE creator_lookup_hash = $1 RETURNING next_child_index, first_child_index",
        )
        .bind(hash.as_bytes().as_slice())
        .bind(floor)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)
    }

    /// The W1.14 sentinel admission plan (design §B.8.7): creators whose
    /// CURRENT database mode is `exclusive` and whose last completed scan is
    /// older than `rescan_interval` (never-scanned first, then
    /// stalest-first). `shared_manual` creators are never admitted and
    /// consume no sentinel budget; `pasted_auto` has no enabling path. Each
    /// target carries the decrypted account key data the tick needs to
    /// derive the never-assigned window — never logged.
    pub async fn sentinel_plan(
        &self,
        rescan_interval: Duration,
        limit: i64,
    ) -> Result<Vec<SentinelScanTarget>, PersistenceError> {
        let seconds =
            i64::try_from(rescan_interval.as_secs()).map_err(|_| PersistenceError::Unavailable)?;
        let rows = sqlx::query_as::<_, SentinelPlanRow>(
            "SELECT id, creator_lookup_hash, credential_envelope, next_child_index \
             FROM creators \
             WHERE allocation_mode = $3 \
               AND (sentinel_last_scanned_at IS NULL \
                    OR sentinel_last_scanned_at <= NOW() - make_interval(secs => $1)) \
             ORDER BY sentinel_last_scanned_at ASC NULLS FIRST, created_at ASC \
             LIMIT $2",
        )
        .bind(seconds)
        .bind(limit)
        .bind(AllocationMode::Exclusive.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        rows.iter()
            .map(|row| {
                let credentials = self.decrypt_credentials(&CreatorRow {
                    id: row.id,
                    creator_lookup_hash: row.creator_lookup_hash.clone(),
                    credential_envelope: row.credential_envelope.clone(),
                })?;
                Ok(SentinelScanTarget::new(
                    row.id,
                    Zeroizing::new(credentials.xpub().to_owned()),
                    credentials.account_index(),
                    row.next_child_index,
                ))
            })
            .collect()
    }

    /// The sentinel's atomic apply (design §B.8.7, F11): one transaction
    /// that re-checks "still never assigned" under the SAME creators row
    /// lock invoice assignment takes (`create_atomic` / `exact_replay` FOR
    /// UPDATE), persists durable candidate/evidence rows, performs the
    /// one-way `exclusive → shared_manual` downgrade with the fixed
    /// `unassigned_sentinel_evidence` reason, creates exactly one seller
    /// event on the transition, and stamps the scan cadence cursor. An
    /// exclusive creator's cursor starts at 0 and advances by exactly one
    /// per assignment, and the only other cursor write (the re-claim floor
    /// advance) cannot skip unassigned indices for an exclusive creator —
    /// a clean §B.5 claim scan is an exclusivity precondition, so the floor
    /// equals the cursor — hence `derivation_index < next_child_index`
    /// under the lock is the exact assigned re-check, and an index burned
    /// by a failed-baseline invoice is still "assigned to an invoice" for
    /// this predicate (the safe direction: never account-wide evidence).
    /// If assignment wins the lock first the finding is recorded
    /// `superseded_by_assignment` and never downgrades. Replayed outpoints
    /// are absorbed by the `UNIQUE (creator_id, outpoint_lookup_hash)` key
    /// and can never double-count a distinct hit; the conditional downgrade
    /// UPDATE plus the event table's own UNIQUE key guarantee one alert
    /// forever, and a crash mid-transaction rolls everything back so a
    /// restart/retry cannot diverge mode from evidence.
    ///
    /// A creator whose CURRENT mode is not `exclusive` at lock time is not
    /// admitted — with ONE exception (§B.8.7: post-downgrade hits record
    /// evidence, shown on the seller's status surface, raising no further
    /// alert): a scan result that was ADMITTED while the creator was still
    /// exclusive may land after another scan already downgraded it. For a
    /// creator whose recorded downgrade reason is exactly
    /// `unassigned_sentinel_evidence`, that in-flight result still commits
    /// its valid new evidence/candidate rows — without a second mode
    /// transition, event or alert, without stamping the scan cadence (no
    /// continuing periodic scans after the downgrade; the planner never
    /// re-admits `shared_manual`), and without reopening general admission:
    /// every other `shared_manual` creator remains a complete no-op.
    pub async fn apply_sentinel_scan(
        &self,
        creator_id: Uuid,
        findings: &[SentinelFinding],
        thresholds: &SentinelThresholds,
    ) -> Result<SentinelScanOutcome, PersistenceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let row = sqlx::query_as::<_, (Vec<u8>, String, Option<String>, i64)>(
            "SELECT creator_lookup_hash, allocation_mode, downgrade_reason, next_child_index \
             FROM creators WHERE id = $1 FOR UPDATE",
        )
        .bind(creator_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        let (creator_lookup_hash, mode, downgrade_reason, next_child_index) = row;
        let exclusive = mode == AllocationMode::Exclusive.as_str();
        // The in-flight commit window: already `shared_manual` BY the
        // sentinel's own downgrade — an already-admitted scan result may
        // still land its evidence. Any other mode/reason is a no-op.
        let post_downgrade_commit = !exclusive
            && mode == AllocationMode::SharedManual.as_str()
            && downgrade_reason.as_deref()
                == Some(DowngradeReason::UnassignedSentinelEvidence.as_str());
        if !exclusive && !post_downgrade_commit {
            // Not admitted: shared_manual creators consume no sentinel
            // budget. Nothing was written; the rollback is a no-op.
            return Ok(SentinelScanOutcome::default());
        }
        let creator_hash: LookupHash = creator_lookup_hash
            .as_slice()
            .try_into()
            .map(LookupHash::from_bytes)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let outpoint_hashes: Vec<Vec<u8>> = findings
            .iter()
            .map(|finding| {
                self.crypto
                    .bitcoin_outpoint_lookup_hash(finding.outpoint_text().as_bytes())
                    .as_bytes()
                    .to_vec()
            })
            .collect();
        let existing: Vec<(Vec<u8>, String)> = if outpoint_hashes.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as(
                "SELECT outpoint_lookup_hash, classification FROM sentinel_outpoints \
                 WHERE creator_id = $1 AND outpoint_lookup_hash = ANY($2)",
            )
            .bind(creator_id)
            .bind(&outpoint_hashes)
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?
        };
        let mut prior_by_hash: HashMap<Vec<u8>, String> = existing.into_iter().collect();
        let prior_hits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sentinel_outpoints \
             WHERE creator_id = $1 AND classification = 'evidence'",
        )
        .bind(creator_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let mut hits = u64::try_from(prior_hits).map_err(|_| PersistenceError::CorruptOrMissing)?;
        let mut outcome = SentinelScanOutcome {
            admitted: exclusive,
            ..SentinelScanOutcome::default()
        };
        // The downgrade predicate is evaluated only for a creator that is
        // still exclusive at lock time; a post-downgrade in-flight commit
        // can never trigger a second transition, event or alert.
        let mut downgrade_due = false;
        for (finding, outpoint_hash) in findings.iter().zip(&outpoint_hashes) {
            let assigned = finding.derivation_index() < next_child_index;
            // The value is bounded to BIGINT range exactly once, here inside
            // the transaction: an out-of-range value aborts the apply and
            // the rollback erases every earlier finding of this scan.
            let value = i64::try_from(finding.value_sats())
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let confirmations = i32::try_from(finding.confirmations())
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            // The per-output half of the predicate decides the row's
            // classification; the distinct-hit half is evaluated below with
            // the running hit count.
            let classification = if assigned {
                Some(SentinelClassification::SupersededByAssignment)
            } else if finding.value_sats() < thresholds.min_value_sats {
                // Below the relay-dust minimum: never a candidate, never
                // persisted.
                None
            } else if !finding.confirmed() {
                Some(SentinelClassification::Candidate)
            } else {
                Some(SentinelClassification::Evidence)
            };
            let Some(classification) = classification else {
                continue;
            };
            match prior_by_hash.get(outpoint_hash) {
                None => {
                    let id = Uuid::new_v4();
                    let envelope = self.seal_sentinel_evidence(creator_hash, id, finding, value)?;
                    let address_hash = self
                        .crypto
                        .bitcoin_address_lookup_hash(finding.address().as_bytes());
                    let index_hash = self.crypto.bitcoin_derivation_index_lookup_hash(
                        creator_hash,
                        finding.derivation_index(),
                    );
                    sqlx::query(
                        "INSERT INTO sentinel_outpoints \
                         (id, creator_id, sentinel_envelope, outpoint_lookup_hash, \
                          address_lookup_hash, derivation_index_lookup_hash, \
                          confirmations, classification) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    )
                    .bind(id)
                    .bind(creator_id)
                    .bind(envelope.as_bytes())
                    .bind(outpoint_hash)
                    .bind(address_hash.as_bytes().as_slice())
                    .bind(index_hash.as_bytes().as_slice())
                    .bind(confirmations)
                    .bind(classification.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                    prior_by_hash.insert(outpoint_hash.clone(), classification.as_str().to_owned());
                    match classification {
                        SentinelClassification::Evidence => {
                            hits += 1;
                            outcome.evidence += 1;
                            if exclusive
                                && downgrade_predicate(
                                    finding.confirmed(),
                                    finding.value_sats(),
                                    hits,
                                    thresholds,
                                )
                            {
                                downgrade_due = true;
                            }
                        }
                        SentinelClassification::Candidate => outcome.candidates += 1,
                        SentinelClassification::SupersededByAssignment => outcome.superseded += 1,
                    }
                }
                Some(prior) => {
                    // Terminal classifications are sticky: evidence stays
                    // evidence, superseded stays superseded; a candidate
                    // promotes to evidence on confirmation and to superseded
                    // on assignment.
                    let final_classification = match prior.as_str() {
                        "evidence" => SentinelClassification::Evidence,
                        "superseded_by_assignment" => {
                            SentinelClassification::SupersededByAssignment
                        }
                        _ => classification,
                    };
                    sqlx::query(
                        "UPDATE sentinel_outpoints \
                         SET classification = $3, confirmations = $4, last_observed_at = NOW() \
                         WHERE creator_id = $1 AND outpoint_lookup_hash = $2",
                    )
                    .bind(creator_id)
                    .bind(outpoint_hash)
                    .bind(final_classification.as_str())
                    .bind(confirmations)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                    if prior.as_str() == "candidate" {
                        match final_classification {
                            SentinelClassification::Evidence => {
                                hits += 1;
                                outcome.evidence += 1;
                                if exclusive
                                    && downgrade_predicate(
                                        finding.confirmed(),
                                        finding.value_sats(),
                                        hits,
                                        thresholds,
                                    )
                                {
                                    downgrade_due = true;
                                }
                            }
                            SentinelClassification::Candidate => outcome.candidates += 1,
                            SentinelClassification::SupersededByAssignment => {
                                outcome.superseded += 1;
                            }
                        }
                    }
                }
            }
        }
        if downgrade_due {
            // The conditional UPDATE is the exactly-once gate: it can only
            // fire on the exclusive -> shared_manual transition, and the
            // event table's UNIQUE (creator_id, event_kind) key is the
            // second line. Repeat hits after the downgrade add evidence
            // (above) but never reach here with a live `exclusive` row.
            let transitioned: Option<Uuid> = sqlx::query_scalar(
                "UPDATE creators \
                 SET allocation_mode = 'shared_manual', \
                     downgrade_reason = $2, updated_at = NOW() \
                 WHERE id = $1 AND allocation_mode = $3 \
                 RETURNING id",
            )
            .bind(creator_id)
            .bind(DowngradeReason::UnassignedSentinelEvidence.as_str())
            .bind(AllocationMode::Exclusive.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            if transitioned.is_some() {
                sqlx::query(
                    "INSERT INTO sentinel_events (creator_id, event_kind, reason) \
                     VALUES ($1, 'sentinel_downgrade', $2) \
                     ON CONFLICT (creator_id, event_kind) DO NOTHING",
                )
                .bind(creator_id)
                .bind(DowngradeReason::UnassignedSentinelEvidence.as_str())
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
                outcome.downgraded = true;
            }
        }
        // Stamp the completed scan for the re-scan cadence, in the same
        // transaction, so a failed apply never consumes the cadence. A
        // post-downgrade in-flight commit is NOT stamped: no continuing
        // periodic scans exist after the downgrade (the planner never
        // re-admits shared_manual, so the cursor is meaningless there).
        if exclusive {
            sqlx::query("UPDATE creators SET sentinel_last_scanned_at = NOW() WHERE id = $1")
                .bind(creator_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
        }
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(outcome)
    }

    /// The §B.8.7 detection evidence metadata for the authenticated seller
    /// status surface: every durable candidate/evidence row, oldest first,
    /// with the sealed derivation index, address, outpoint and value
    /// decrypted for the owner. None of it is ever logged.
    pub async fn sentinel_evidence(
        &self,
        creator: &CreatorPubky,
    ) -> Result<Vec<SentinelEvidenceRecord>, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let rows = sqlx::query_as::<_, SentinelEvidenceRow>(
            "SELECT sentinel_outpoints.id, sentinel_envelope, confirmations, classification, \
                    first_observed_at, last_observed_at \
             FROM sentinel_outpoints \
             JOIN creators ON creators.id = sentinel_outpoints.creator_id \
             WHERE creators.creator_lookup_hash = $1 \
             ORDER BY first_observed_at, sentinel_outpoints.id",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        rows.iter()
            .map(|row| {
                let plaintext = Zeroizing::new(
                    self.crypto
                        .decrypt(
                            &EnvelopeContext::sentinel_evidence(hash, row.id),
                            &EncryptedEnvelope::from_bytes(row.sentinel_envelope.clone()),
                        )
                        .map_err(|_| PersistenceError::CorruptOrMissing)?,
                );
                let wire: SentinelEvidenceV1 = postcard::from_bytes(&plaintext)
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                if wire.version != 1 {
                    return Err(PersistenceError::CorruptOrMissing);
                }
                Ok(SentinelEvidenceRecord {
                    classification: row.classification.clone(),
                    derivation_index: wire.derivation_index,
                    address: wire.address.clone(),
                    outpoint: wire.outpoint.clone(),
                    value_sats: u64::try_from(wire.value_sats)
                        .map_err(|_| PersistenceError::CorruptOrMissing)?,
                    confirmations: row.confirmations,
                    first_observed_at: row.first_observed_at,
                    last_observed_at: row.last_observed_at,
                })
            })
            .collect()
    }

    /// The durable, owner-visible §B.8.7 alerts for the authenticated
    /// seller status surface: at most one `sentinel_downgrade` row (the
    /// table's UNIQUE (creator_id, event_kind) key guarantees it), with the
    /// fixed event kind, the fixed reason identifier, the transition time
    /// and the seller's acknowledgement. No push channel exists; polling
    /// this surface IS the delivery mechanism (W1.16 renders it).
    pub async fn sentinel_alerts(
        &self,
        creator: &CreatorPubky,
    ) -> Result<Vec<crate::sentinel::SentinelAlertRecord>, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let rows = sqlx::query_as::<_, SentinelAlertRow>(
            "SELECT sentinel_events.event_kind, sentinel_events.reason, \
                    sentinel_events.created_at, sentinel_events.acknowledged_at \
             FROM sentinel_events \
             JOIN creators ON creators.id = sentinel_events.creator_id \
             WHERE creators.creator_lookup_hash = $1 \
             ORDER BY sentinel_events.created_at, sentinel_events.id",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(rows
            .into_iter()
            .map(|row| crate::sentinel::SentinelAlertRecord {
                event_kind: row.event_kind,
                reason: row.reason,
                created_at: row.created_at,
                acknowledged_at: row.acknowledged_at,
            })
            .collect())
    }

    /// The seller's durable read receipt for one sentinel alert: sets
    /// `acknowledged_at` exactly once (idempotent — an existing receipt is
    /// kept, never moved or cleared). Only the fixed event-kind vocabulary
    /// is accepted; anything else fails closed as `CorruptOrMissing` (the
    /// caller maps it to a request error). Returns whether a matching alert
    /// row existed.
    pub async fn acknowledge_sentinel_alert(
        &self,
        creator: &CreatorPubky,
        event_kind: &str,
    ) -> Result<bool, PersistenceError> {
        if event_kind != crate::sentinel::SENTINEL_EVENT_KIND_DOWNGRADE {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let updated: Option<Uuid> = sqlx::query_scalar(
            "UPDATE sentinel_events SET acknowledged_at = COALESCE(acknowledged_at, NOW()) \
             WHERE event_kind = $2 \
               AND creator_id = (SELECT id FROM creators WHERE creator_lookup_hash = $1) \
             RETURNING id",
        )
        .bind(hash.as_bytes().as_slice())
        .bind(event_kind)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(updated.is_some())
    }

    /// The age of the oldest admitted exclusive creator's last completed
    /// scan (creation time when never scanned): the freshness SLO input the
    /// sentinel age alert reports. `None` when no exclusive creator exists.
    pub async fn oldest_exclusive_sentinel_age(
        &self,
    ) -> Result<Option<Duration>, PersistenceError> {
        let age_seconds: Option<f64> = sqlx::query_scalar(
            "SELECT EXTRACT(EPOCH FROM \
                 (NOW() - MIN(COALESCE(sentinel_last_scanned_at, created_at))))::float8 \
             FROM creators WHERE allocation_mode = $1",
        )
        .bind(AllocationMode::Exclusive.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        Ok(age_seconds.map(|seconds| Duration::from_secs_f64(seconds.max(0.0))))
    }

    fn seal_sentinel_evidence(
        &self,
        creator_hash: LookupHash,
        row_id: Uuid,
        finding: &SentinelFinding,
        value_sats: i64,
    ) -> Result<EncryptedEnvelope, PersistenceError> {
        let wire = SentinelEvidenceV1Ref {
            version: 1,
            derivation_index: finding.derivation_index(),
            address: finding.address(),
            outpoint: &finding.outpoint_text(),
            value_sats,
        };
        let bytes = Zeroizing::new(
            postcard::to_allocvec(&wire).map_err(|_| PersistenceError::CorruptOrMissing)?,
        );
        self.crypto
            .encrypt(
                &EnvelopeContext::sentinel_evidence(creator_hash, row_id),
                &bytes,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)
    }

    /// Authenticates every creator authority, SDK-state and W1.14 sentinel
    /// evidence envelope required at boot. A corrupt or tampered row fails
    /// startup BEFORE the server serves: each sentinel row's envelope must
    /// authenticate under its own domain-separated context
    /// (`EnvelopeContext::sentinel_evidence` bound to the creator lookup
    /// hash and the row id), decode at version 1, and match every plaintext
    /// lookup-hash column recomputed from the sealed identity (outpoint,
    /// address, derivation index) — a bit flip in the ciphertext or any
    /// lookup-hash mismatch is `CorruptOrMissing`.
    pub async fn scan_integrity(&self) -> Result<(), PersistenceError> {
        let rows = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, credential_envelope FROM creators ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for row in rows {
            self.decrypt_credentials(&row)?;
            crate::persistence::sdk_state::load_state_by_row(&self.pool, &self.crypto, &row)
                .await?;
        }
        self.scan_sentinel_integrity().await
    }

    /// Boot-time authentication of every durable sentinel evidence row;
    /// see [`CreatorStore::scan_integrity`].
    async fn scan_sentinel_integrity(&self) -> Result<(), PersistenceError> {
        let rows = sqlx::query_as::<_, SentinelIntegrityRow>(
            "SELECT sentinel_outpoints.id, creators.creator_lookup_hash, sentinel_envelope, \
                    outpoint_lookup_hash, address_lookup_hash, derivation_index_lookup_hash \
             FROM sentinel_outpoints \
             JOIN creators ON creators.id = sentinel_outpoints.creator_id \
             ORDER BY sentinel_outpoints.id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for row in rows {
            let creator_hash: LookupHash = row
                .creator_lookup_hash
                .as_slice()
                .try_into()
                .map(LookupHash::from_bytes)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let plaintext = Zeroizing::new(
                self.crypto
                    .decrypt(
                        &EnvelopeContext::sentinel_evidence(creator_hash, row.id),
                        &EncryptedEnvelope::from_bytes(row.sentinel_envelope.clone()),
                    )
                    .map_err(|_| PersistenceError::CorruptOrMissing)?,
            );
            let wire: SentinelEvidenceV1 =
                postcard::from_bytes(&plaintext).map_err(|_| PersistenceError::CorruptOrMissing)?;
            if wire.version != 1 {
                return Err(PersistenceError::CorruptOrMissing);
            }
            // Every plaintext lookup-hash column must equal the hash
            // recomputed from the sealed identity: a mismatch means the
            // lookup columns were tampered or the envelope was swapped.
            if self
                .crypto
                .bitcoin_outpoint_lookup_hash(wire.outpoint.as_bytes())
                .as_bytes()
                .as_slice()
                != row.outpoint_lookup_hash.as_slice()
                || self
                    .crypto
                    .bitcoin_address_lookup_hash(wire.address.as_bytes())
                    .as_bytes()
                    .as_slice()
                    != row.address_lookup_hash.as_slice()
                || self
                    .crypto
                    .bitcoin_derivation_index_lookup_hash(creator_hash, wire.derivation_index)
                    .as_bytes()
                    .as_slice()
                    != row.derivation_index_lookup_hash.as_slice()
            {
                return Err(PersistenceError::CorruptOrMissing);
            }
        }
        Ok(())
    }

    async fn lookup_row(&self, creator: &CreatorPubky) -> Result<CreatorRow, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        sqlx::query_as("SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE creator_lookup_hash = $1")
            .bind(hash.as_bytes().as_slice()).fetch_optional(&self.pool).await.map_err(|_| PersistenceError::Unavailable)?.ok_or(PersistenceError::CorruptOrMissing)
    }

    fn decrypt_credentials(
        &self,
        row: &CreatorRow,
    ) -> Result<CreatorCredentials, PersistenceError> {
        let hash = row.lookup_hash()?;
        let plaintext = Zeroizing::new(
            self.crypto
                .decrypt(
                    &EnvelopeContext::creator_credentials(hash, row.id),
                    &EncryptedEnvelope::from_bytes(row.credential_envelope.clone()),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?,
        );
        let credentials = CreatorCredentials::decode(&plaintext)?;
        if self
            .crypto
            .lookup_hash(credentials.creator().to_string().as_bytes())
            != hash
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok(credentials)
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct CreatorRow {
    pub(crate) id: Uuid,
    pub(crate) creator_lookup_hash: Vec<u8>,
    pub(crate) credential_envelope: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct SentinelPlanRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    credential_envelope: Vec<u8>,
    next_child_index: i64,
}

#[derive(sqlx::FromRow)]
struct SentinelEvidenceRow {
    id: Uuid,
    sentinel_envelope: Vec<u8>,
    confirmations: i32,
    classification: String,
    first_observed_at: time::OffsetDateTime,
    last_observed_at: time::OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct SentinelAlertRow {
    event_kind: String,
    reason: String,
    created_at: time::OffsetDateTime,
    acknowledged_at: Option<time::OffsetDateTime>,
}

#[derive(sqlx::FromRow)]
struct SentinelIntegrityRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    sentinel_envelope: Vec<u8>,
    outpoint_lookup_hash: Vec<u8>,
    address_lookup_hash: Vec<u8>,
    derivation_index_lookup_hash: Vec<u8>,
}

/// The sealed §B.8.7 evidence identity: derivation index, address,
/// canonical `txid:vout`, and value. Only keyed lookup hashes and the
/// confirmation count are plaintext columns (migration 0016).
#[derive(Serialize)]
struct SentinelEvidenceV1Ref<'a> {
    version: u8,
    derivation_index: i64,
    address: &'a str,
    outpoint: &'a str,
    value_sats: i64,
}

#[derive(Deserialize)]
struct SentinelEvidenceV1 {
    version: u8,
    derivation_index: i64,
    address: String,
    outpoint: String,
    value_sats: i64,
}

/// The seller-visible allocation status row (design §B.8.6).
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct CreatorAllocationStatus {
    pub allocation_mode: String,
    pub claim_channel: Option<String>,
    pub downgrade_reason: Option<String>,
}

/// The derivation cursor pair after a claim-floor advance: the mutable
/// cursor the next invoice address derives from, and the immutable
/// claim-time index (W1.13 r3) the status's stable `first_derived_address`
/// derives at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct ChildIndexCursor {
    pub next_child_index: i64,
    pub first_child_index: i64,
}

/// Everything the authenticated seller status surface serves (design §B.8.6):
/// the allocation columns plus the persisted account key data the client's
/// evidence fields (`key_fingerprint`, `first_derived_address`) derive from.
/// Neither derived field is key material: the fingerprint is a hash and the
/// first address is what invoices reveal anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatorStatusRecord {
    pub allocation: CreatorAllocationStatus,
    /// The exact persisted account xpub (canonical base58 form).
    pub xpub: String,
    pub account_index: u32,
    /// The creator's mutable derivation cursor; invoice allocation advances
    /// it. Informational in the status body — never a derivation input.
    pub next_child_index: i64,
    /// The immutable claim-time child index (W1.13 r3): the status's
    /// `first_derived_address` derives at THIS index, exactly as the claim
    /// response did — never at `next_child_index`, which moves.
    pub first_child_index: i64,
}

#[derive(sqlx::FromRow)]
struct CreatorStatusRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    credential_envelope: Vec<u8>,
    next_child_index: i64,
    first_child_index: i64,
    allocation_mode: String,
    claim_channel: Option<String>,
    downgrade_reason: Option<String>,
}
impl CreatorRow {
    pub(crate) fn lookup_hash(&self) -> Result<LookupHash, PersistenceError> {
        self.creator_lookup_hash
            .as_slice()
            .try_into()
            .map(LookupHash::from_bytes)
            .map_err(|_| PersistenceError::CorruptOrMissing)
    }
}
