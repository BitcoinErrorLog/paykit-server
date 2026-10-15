//! Encrypted creator authority persistence.

use std::fmt;

use paykit_sdk::PaykitIdentitySecretKey;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::domain::receiving::{BitcoinAccount, UsdtAddress};

use crate::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::{
        locks::{CreatorPubky, parse_creator},
        payment_request_lifecycle::PaymentRequestLifecycleState,
    },
    persistence::{PaymentRequestLifecycleStore, PersistenceError, RequiredReceiveTarget},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinAccountRotation {
    pub generation: i64,
    pub cancellation_pending_count: u64,
    pub voided_preparation_count: u64,
}

#[derive(Clone, Copy)]
enum RotationOwner {
    Invoice(Uuid),
    Marketplace(Uuid),
}

/// Secret-bearing creator authority accepted by the persistence boundary.
pub struct CreatorCredentials {
    creator: CreatorPubky,
    session_secret: Zeroizing<String>,
    paykit_identity_secret: PaykitIdentitySecretKey,
    bitcoin_account: Option<BitcoinAccount>,
    usdt_address: Option<UsdtAddress>,
}

impl fmt::Debug for CreatorCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CreatorCredentials(<redacted>)")
    }
}

impl CreatorCredentials {
    /// Constructs creator authority with explicitly approved receiving details.
    pub fn new(
        creator: CreatorPubky,
        session_secret: String,
        paykit_identity_secret: PaykitIdentitySecretKey,
        bitcoin_account: Option<BitcoinAccount>,
        usdt_address: Option<UsdtAddress>,
    ) -> Self {
        Self {
            creator,
            session_secret: Zeroizing::new(session_secret),
            paykit_identity_secret,
            bitcoin_account,
            usdt_address,
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
    /// Borrows the delegated identity-wide Paykit secret.
    pub fn paykit_identity_secret(&self) -> &PaykitIdentitySecretKey {
        &self.paykit_identity_secret
    }
    pub fn bitcoin_account(&self) -> Option<&BitcoinAccount> {
        self.bitcoin_account.as_ref()
    }

    pub fn usdt_address(&self) -> Option<&UsdtAddress> {
        self.usdt_address.as_ref()
    }

    /// Rejects account removal, key rollback, and key substitution within a generation.
    /// A changed non-empty Bitcoin account is handled only by the atomic rotation path.
    pub fn validate_reauthentication(&self, replacement: &Self) -> Result<(), PersistenceError> {
        let current = &self.paykit_identity_secret;
        let next = &replacement.paykit_identity_secret;
        if self.creator != replacement.creator
            || (self.bitcoin_account.is_some() && replacement.bitcoin_account.is_none())
            || (self.usdt_address.is_some() && self.usdt_address != replacement.usdt_address)
            || next.key_generation() < current.key_generation()
            || (next.key_generation() == current.key_generation() && next != current)
        {
            return Err(PersistenceError::ReauthenticationMismatch);
        }
        Ok(())
    }

    pub fn bitcoin_account_changed(&self, replacement: &Self) -> bool {
        self.bitcoin_account != replacement.bitcoin_account
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PersistenceError> {
        let creator = self.creator.to_string();
        let wire = CreatorCredentialsV1Ref {
            version: 1,
            creator: &creator,
            session_secret: self.session_secret.as_str(),
            paykit_identity_secret: self.paykit_identity_secret.as_bytes(),
            key_generation: self.paykit_identity_secret.key_generation(),
            bitcoin_account: self.bitcoin_account.as_ref(),
            usdt_address: self.usdt_address.as_ref(),
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
        Ok(Self {
            creator,
            session_secret: wire.session_secret,
            paykit_identity_secret: PaykitIdentitySecretKey::new(
                *wire.paykit_identity_secret,
                wire.key_generation,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?,
            bitcoin_account: wire.bitcoin_account,
            usdt_address: wire.usdt_address,
        })
    }
}

#[derive(Serialize)]
struct CreatorCredentialsV1Ref<'a> {
    version: u8,
    creator: &'a str,
    session_secret: &'a str,
    paykit_identity_secret: &'a [u8; 32],
    key_generation: u64,
    bitcoin_account: Option<&'a BitcoinAccount>,
    usdt_address: Option<&'a UsdtAddress>,
}

#[derive(Deserialize)]
struct CreatorCredentialsV1 {
    version: u8,
    creator: String,
    session_secret: Zeroizing<String>,
    paykit_identity_secret: Zeroizing<[u8; 32]>,
    key_generation: u64,
    bitcoin_account: Option<BitcoinAccount>,
    usdt_address: Option<UsdtAddress>,
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

/// Encrypted creator authority repository.
#[derive(Clone, Debug)]
pub struct CreatorStore {
    pool: PgPool,
    crypto: std::sync::Arc<Crypto>,
}

/// A creator-scoped PostgreSQL session advisory lock used to serialize setup,
/// SDK outbox mutation, and rotation across all processes sharing the database.
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

fn creator_lock_key(lookup_hash: &[u8]) -> Result<i64, PersistenceError> {
    if lookup_hash.len() != 32 {
        return Err(PersistenceError::CorruptOrMissing);
    }
    let bytes: [u8; 8] = lookup_hash
        .get(..8)
        .ok_or(PersistenceError::CorruptOrMissing)?
        .try_into()
        .map_err(|_| PersistenceError::CorruptOrMissing)?;
    Ok(i64::from_be_bytes(bytes))
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
    /// hold this lock before loading credentials, publishing the Paykit App, and
    /// committing credentials, then call [`CreatorSetupLock::release`].
    pub async fn acquire_setup_lock(
        &self,
        creator: &CreatorPubky,
    ) -> Result<CreatorSetupLock, PersistenceError> {
        let lookup_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        self.acquire_creator_lock(creator_lock_key(lookup_hash.as_bytes())?)
            .await
    }

    /// Acquires the same cross-process Creator mutation fence from an internal
    /// row identity. Workers take this before the process-local SDK mutex and
    /// before claiming work, matching setup's advisory-lock-first ordering.
    pub async fn acquire_setup_lock_for_creator_id(
        &self,
        creator_id: Uuid,
    ) -> Result<CreatorSetupLock, PersistenceError> {
        let lookup_hash: Vec<u8> =
            sqlx::query_scalar("SELECT creator_lookup_hash FROM creators WHERE id = $1")
                .bind(creator_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| PersistenceError::Unavailable)?
                .ok_or(PersistenceError::CorruptOrMissing)?;
        self.acquire_creator_lock(creator_lock_key(&lookup_hash)?)
            .await
    }

    async fn acquire_creator_lock(&self, key: i64) -> Result<CreatorSetupLock, PersistenceError> {
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

    /// Inserts encrypted creator credentials before app publication.
    pub async fn create(
        &self,
        credentials: &CreatorCredentials,
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
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("INSERT INTO creators (id, creator_lookup_hash, credential_envelope) VALUES ($1, $2, $3)")
            .bind(id).bind(lookup_hash.as_bytes().as_slice()).bind(credential_envelope.as_bytes()).execute(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(PersistedCreator { id, lookup_hash })
    }

    /// Lists configured creators for durable SDK transport maintenance after restart.
    pub async fn ready_ids(&self) -> Result<Vec<Uuid>, PersistenceError> {
        sqlx::query_scalar("SELECT id FROM creators WHERE setup_complete ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)
    }

    /// Marks setup ready only after credentials and shared app publication succeed.
    pub async fn mark_setup_complete(
        &self,
        creator: &CreatorPubky,
    ) -> Result<(), PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        sqlx::query("UPDATE creators SET setup_complete = TRUE WHERE creator_lookup_hash = $1")
            .bind(hash.as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(())
    }

    /// Reports whether setup finished app publication.
    pub async fn setup_complete(&self, creator: &CreatorPubky) -> Result<bool, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        sqlx::query_scalar("SELECT setup_complete FROM creators WHERE creator_lookup_hash = $1")
            .bind(hash.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)
            .map(|value| value.unwrap_or(false))
    }

    /// Loads and authenticates a creator credential envelope by canonical creator identity.
    pub async fn load(
        &self,
        creator: &CreatorPubky,
    ) -> Result<CreatorCredentials, PersistenceError> {
        let row = self.lookup_row(creator).await?;
        self.decrypt_credentials(&row)
    }

    /// Loads authenticated Creator authority together with its opaque internal
    /// row identity for production SDK adapter composition.
    pub(crate) async fn load_with_id(
        &self,
        creator: &CreatorPubky,
    ) -> Result<(Uuid, CreatorCredentials), PersistenceError> {
        let row = self.lookup_row(creator).await?;
        let id = row.id;
        self.decrypt_credentials(&row)
            .map(|credentials| (id, credentials))
    }

    /// Loads credentials with the durable Bitcoin generation used to fence
    /// address derivation after account rotation.
    pub async fn load_with_bitcoin_account_generation(
        &self,
        creator: &CreatorPubky,
    ) -> Result<(CreatorCredentials, i64), PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let row = sqlx::query_as::<_, CreatorGenerationRow>(
            "SELECT id, creator_lookup_hash, credential_envelope, bitcoin_account_generation
             FROM creators WHERE creator_lookup_hash = $1",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        if row.bitcoin_account_generation < 0 {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let generation = row.bitcoin_account_generation;
        let credentials = self.decrypt_credentials(&CreatorRow {
            id: row.id,
            creator_lookup_hash: row.creator_lookup_hash,
            credential_envelope: row.credential_envelope,
        })?;
        Ok((credentials, generation))
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

    /// Replaces credentials after validating immutable account identity and key monotonicity.
    pub async fn reauthenticate(
        &self,
        replacement: &CreatorCredentials,
    ) -> Result<(), PersistenceError> {
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
        existing.validate_reauthentication(replacement)?;
        if existing.bitcoin_account_changed(replacement) {
            return Err(PersistenceError::ReauthenticationMismatch);
        }
        let bytes = replacement.encode()?;
        let envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::creator_credentials(row.lookup_hash()?, row.id),
                &bytes,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        sqlx::query(
            "UPDATE creators SET credential_envelope = $1, setup_complete = FALSE, updated_at = NOW() WHERE id = $2",
        )
        .bind(envelope.as_bytes())
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit().await.map_err(|_| PersistenceError::Unavailable)
    }

    /// Atomically installs a changed Bitcoin account, advances its issuance
    /// generation, voids unpublished Bitcoin Marketplace preparations, suppresses
    /// never-handed-off old proposals, and enqueues cancellation of every
    /// canonically proposed old-account request. Accepted requests remain intact.
    pub async fn rotate_bitcoin_account_after_receive(
        &self,
        lifecycles: &PaymentRequestLifecycleStore,
        replacement: &CreatorCredentials,
        receive_evidence: &[RequiredReceiveTarget],
    ) -> Result<BitcoinAccountRotation, PersistenceError> {
        let hash = self
            .crypto
            .lookup_hash(replacement.creator().to_string().as_bytes());
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let row = sqlx::query_as::<_, CreatorGenerationRow>(
            "SELECT id, creator_lookup_hash, credential_envelope, bitcoin_account_generation
             FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        let existing = self.decrypt_credentials(&CreatorRow {
            id: row.id,
            creator_lookup_hash: row.creator_lookup_hash.clone(),
            credential_envelope: row.credential_envelope,
        })?;
        existing.validate_reauthentication(replacement)?;
        if !existing.bitcoin_account_changed(replacement)
            || existing.bitcoin_account().is_none()
            || replacement.bitcoin_account().is_none()
        {
            return Err(PersistenceError::ReauthenticationMismatch);
        }
        let current_generation = row.bitcoin_account_generation;
        let next_generation = current_generation
            .checked_add(1)
            .ok_or(PersistenceError::CorruptOrMissing)?;

        let current_targets = lifecycles
            .required_receive_targets_for_creator_rotation_in_transaction(&mut tx, row.id)
            .await?;
        if !PaymentRequestLifecycleStore::receive_evidence_covers(
            &current_targets,
            receive_evidence,
        ) {
            return Err(PersistenceError::Unavailable);
        }

        let invoice_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM invoices
             WHERE creator_id = $1 AND bitcoin_address_lookup_hash IS NOT NULL
               AND bitcoin_account_generation = $2
             ORDER BY id FOR UPDATE",
        )
        .bind(row.id)
        .bind(current_generation)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        // Legacy preparations predate the generation column. Authenticate their
        // encrypted terms before backfilling only Bitcoin-bearing rows.
        let legacy_preparations: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT id, preparation_envelope FROM marketplace_payment_preparations
             WHERE creator_id = $1 AND bitcoin_account_generation IS NULL
             ORDER BY id FOR UPDATE",
        )
        .bind(row.id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for (preparation_id, envelope) in legacy_preparations {
            let plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::marketplace_preparation(hash, preparation_id),
                    &EncryptedEnvelope::from_bytes(envelope),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            if super::marketplace_preparations::PreparationEnvelope::decode(&plaintext)?
                .has_bitcoin()
            {
                sqlx::query(
                    "UPDATE marketplace_payment_preparations
                     SET bitcoin_account_generation = $2
                     WHERE id = $1 AND bitcoin_account_generation IS NULL",
                )
                .bind(preparation_id)
                .bind(current_generation)
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
            }
        }

        let marketplace_rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, state FROM marketplace_payment_preparations
             WHERE creator_id = $1 AND bitcoin_account_generation = $2
             ORDER BY id FOR UPDATE",
        )
        .bind(row.id)
        .bind(current_generation)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        let rotation_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO creator_bitcoin_account_rotations
             (id, creator_id, from_generation, to_generation)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(rotation_id)
        .bind(row.id)
        .bind(current_generation)
        .bind(next_generation)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        let mut owners = invoice_ids
            .into_iter()
            .map(RotationOwner::Invoice)
            .collect::<Vec<_>>();
        let mut voided_preparation_count = 0_u64;
        for (preparation_id, state) in marketplace_rows {
            match state.as_str() {
                "prepared" => {
                    let voided = sqlx::query(
                        "UPDATE marketplace_payment_preparations
                         SET state = 'voided', voided_at = clock_timestamp(),
                             updated_at = clock_timestamp()
                         WHERE id = $1 AND state = 'prepared'",
                    )
                    .bind(preparation_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                    if voided.rows_affected() != 1 {
                        return Err(PersistenceError::Conflict);
                    }
                    sqlx::query(
                        "INSERT INTO creator_bitcoin_account_rotation_items
                         (rotation_id, marketplace_preparation_id, classification)
                         VALUES ($1, $2, 'preparation_voided')",
                    )
                    .bind(rotation_id)
                    .bind(preparation_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                    voided_preparation_count += 1;
                }
                "active" => owners.push(RotationOwner::Marketplace(preparation_id)),
                "voided" => {}
                _ => return Err(PersistenceError::CorruptOrMissing),
            }
        }

        let mut cancellation_pending_count = 0_u64;
        for owner in owners {
            let (invoice_id, marketplace_preparation_id) = match owner {
                RotationOwner::Invoice(id) => (Some(id), None),
                RotationOwner::Marketplace(id) => (None, Some(id)),
            };
            let proposal: (Uuid, Vec<u8>, String, Option<String>) = sqlx::query_as(
                "SELECT id, intent_envelope, status, sdk_payment_request_id
                 FROM outbox
                 WHERE creator_id = $1
                   AND invoice_id IS NOT DISTINCT FROM $2
                   AND marketplace_preparation_id IS NOT DISTINCT FROM $3
                   AND intent_kind = 'payment_request_proposal'
                 ORDER BY created_at, id",
            )
            .bind(row.id)
            .bind(invoice_id)
            .bind(marketplace_preparation_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            let proposal_plaintext = self
                .crypto
                .decrypt(
                    &EnvelopeContext::outbox_semantic_intent(hash, proposal.0),
                    &EncryptedEnvelope::from_bytes(proposal.1),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            let proposal_intent = DeliveryIntentV1::decode(&proposal_plaintext)
                .map_err(|_| PersistenceError::CorruptOrMissing)?;
            if !matches!(
                proposal_intent.operation(),
                crate::application::semantic_intent::DeliveryOperationV1::PaymentRequestProposal { .. }
            ) {
                return Err(PersistenceError::CorruptOrMissing);
            }

            let lifecycle_rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT sdk_payment_request_id, request_state
                 FROM payment_request_lifecycles
                 WHERE invoice_id IS NOT DISTINCT FROM $1
                   AND marketplace_preparation_id IS NOT DISTINCT FROM $2
                 ORDER BY sdk_payment_request_id FOR UPDATE",
            )
            .bind(invoice_id)
            .bind(marketplace_preparation_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
            let parsed = lifecycle_rows
                .iter()
                .map(|(id, state)| {
                    PaymentRequestLifecycleState::parse(state)
                        .map(|state| (id, state))
                        .ok_or(PersistenceError::CorruptOrMissing)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if parsed
                .iter()
                .any(|(_, state)| *state == PaymentRequestLifecycleState::InvalidConflict)
            {
                return Err(PersistenceError::Conflict);
            }
            if parsed
                .iter()
                .any(|(_, state)| *state == PaymentRequestLifecycleState::RecoveryRequired)
            {
                return Err(PersistenceError::Unavailable);
            }
            let accepted = parsed.iter().any(|(_, state)| {
                matches!(
                    state,
                    PaymentRequestLifecycleState::Accepted
                        | PaymentRequestLifecycleState::ProofSubmitted
                        | PaymentRequestLifecycleState::ActiveRecurring
                )
            });
            let proposed = parsed
                .iter()
                .filter(|(_, state)| *state == PaymentRequestLifecycleState::Proposed)
                .map(|(id, _)| (*id).clone())
                .collect::<Vec<_>>();

            if accepted {
                sqlx::query(
                    "INSERT INTO creator_bitcoin_account_rotation_items
                     (rotation_id, invoice_id, marketplace_preparation_id, classification)
                     VALUES ($1, $2, $3, 'accepted')",
                )
                .bind(rotation_id)
                .bind(invoice_id)
                .bind(marketplace_preparation_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
                continue;
            }

            if proposed.is_empty() {
                if parsed.is_empty()
                    && (proposal.3.is_some()
                        || matches!(proposal.2.as_str(), "handed_off" | "delivered"))
                {
                    return Err(PersistenceError::Unavailable);
                }
                let classification = if parsed.is_empty()
                    && matches!(proposal.2.as_str(), "queued" | "retryable" | "leased")
                {
                    let suppressed = sqlx::query(
                        "UPDATE outbox
                         SET status = 'permanently_failed', error_class = 'bitcoin_account_rotated',
                             lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL,
                             updated_at = clock_timestamp()
                         WHERE id = $1 AND status IN ('queued', 'retryable', 'leased')",
                    )
                    .bind(proposal.0)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                    if suppressed.rows_affected() != 1 {
                        return Err(PersistenceError::Conflict);
                    }
                    "proposal_suppressed"
                } else {
                    "terminal"
                };
                sqlx::query(
                    "INSERT INTO creator_bitcoin_account_rotation_items
                     (rotation_id, invoice_id, marketplace_preparation_id, classification)
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(rotation_id)
                .bind(invoice_id)
                .bind(marketplace_preparation_id)
                .bind(classification)
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
                continue;
            }

            for payment_request_id in proposed {
                let existing_cancellation: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM outbox
                     WHERE creator_id = $1
                       AND invoice_id IS NOT DISTINCT FROM $2
                       AND marketplace_preparation_id IS NOT DISTINCT FROM $3
                       AND intent_kind = 'payment_request_cancellation'
                       AND cancellation_target_payment_request_id = $4",
                )
                .bind(row.id)
                .bind(invoice_id)
                .bind(marketplace_preparation_id)
                .bind(&payment_request_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
                let cancellation_outbox_id = if let Some(id) = existing_cancellation {
                    id
                } else {
                    let cancellation = DeliveryIntentV1::payment_request_cancellation(
                        &proposal_intent,
                        payment_request_id.clone(),
                    )
                    .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    let outbox_id = Uuid::new_v4();
                    let plaintext = postcard::to_allocvec(&cancellation)
                        .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    let envelope = self
                        .crypto
                        .encrypt(
                            &EnvelopeContext::outbox_semantic_intent(hash, outbox_id),
                            &plaintext,
                        )
                        .map_err(|_| PersistenceError::CorruptOrMissing)?;
                    sqlx::query(
                        "INSERT INTO outbox
                         (id, creator_id, invoice_id, marketplace_preparation_id,
                          intent_envelope, intent_kind,
                          cancellation_target_payment_request_id, status)
                         VALUES ($1, $2, $3, $4, $5,
                                 'payment_request_cancellation', $6, 'queued')",
                    )
                    .bind(outbox_id)
                    .bind(row.id)
                    .bind(invoice_id)
                    .bind(marketplace_preparation_id)
                    .bind(envelope.as_bytes())
                    .bind(&payment_request_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| PersistenceError::Unavailable)?;
                    outbox_id
                };
                sqlx::query(
                    "INSERT INTO creator_bitcoin_account_rotation_items
                     (rotation_id, invoice_id, marketplace_preparation_id,
                      sdk_payment_request_id, classification, cancellation_outbox_id)
                     VALUES ($1, $2, $3, $4, 'cancellation_pending', $5)",
                )
                .bind(rotation_id)
                .bind(invoice_id)
                .bind(marketplace_preparation_id)
                .bind(&payment_request_id)
                .bind(cancellation_outbox_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
                cancellation_pending_count += 1;
            }
        }

        let bytes = replacement.encode()?;
        let envelope = self
            .crypto
            .encrypt(&EnvelopeContext::creator_credentials(hash, row.id), &bytes)
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let updated = sqlx::query(
            "UPDATE creators
             SET credential_envelope = $1, bitcoin_account_generation = $2,
                 setup_complete = FALSE, updated_at = clock_timestamp()
             WHERE id = $3 AND bitcoin_account_generation = $4",
        )
        .bind(envelope.as_bytes())
        .bind(next_generation)
        .bind(row.id)
        .bind(current_generation)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        if updated.rows_affected() != 1 {
            return Err(PersistenceError::Conflict);
        }
        sqlx::query(
            "UPDATE creator_bitcoin_account_rotations
             SET cancellation_count = $2, voided_preparation_count = $3
             WHERE id = $1",
        )
        .bind(rotation_id)
        .bind(
            i64::try_from(cancellation_pending_count)
                .map_err(|_| PersistenceError::InvalidInput)?,
        )
        .bind(i64::try_from(voided_preparation_count).map_err(|_| PersistenceError::InvalidInput)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(BitcoinAccountRotation {
            generation: next_generation,
            cancellation_pending_count,
            voided_preparation_count,
        })
    }

    /// Authenticates every creator authority envelope required at boot.
    pub async fn scan_integrity(&self) -> Result<(), PersistenceError> {
        let rows = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, credential_envelope FROM creators ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for row in rows {
            self.decrypt_credentials(&row)?;
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
struct CreatorGenerationRow {
    id: Uuid,
    creator_lookup_hash: Vec<u8>,
    credential_envelope: Vec<u8>,
    bitcoin_account_generation: i64,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(secret: u8, generation: u64) -> CreatorCredentials {
        CreatorCredentials::new(
            parse_creator("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap(),
            "session".into(),
            PaykitIdentitySecretKey::new([secret; 32], generation).unwrap(),
            Some(crate::domain::receiving::BitcoinAccount {
                xpub: zeroize::Zeroizing::new("account".into()),
                account_index: 7,
            }),
            None,
        )
    }

    #[test]
    fn encrypted_credentials_plaintext_round_trips_key_and_generation() {
        let expected = credentials(9, 3);
        let decoded = CreatorCredentials::decode(&expected.encode().unwrap()).unwrap();
        assert_eq!(
            decoded.paykit_identity_secret(),
            expected.paykit_identity_secret()
        );
        assert_eq!(decoded.bitcoin_account().unwrap().account_index, 7);
        assert_eq!(decoded.bitcoin_account().unwrap().xpub.as_str(), "account");
        assert_eq!(format!("{decoded:?}"), "CreatorCredentials(<redacted>)");
    }

    #[test]
    fn reauthentication_validation_routes_changed_accounts_to_rotation() {
        let current = credentials(9, 3);
        assert!(
            current
                .validate_reauthentication(&credentials(9, 3))
                .is_ok()
        );
        assert!(
            current
                .validate_reauthentication(&credentials(8, 5))
                .is_ok()
        );
        for replacement in [credentials(9, 2), credentials(8, 3)] {
            assert_eq!(
                current.validate_reauthentication(&replacement),
                Err(PersistenceError::ReauthenticationMismatch)
            );
        }
        let mut replacement = credentials(8, 4);
        replacement.bitcoin_account.as_mut().unwrap().account_index = 8;
        assert!(current.validate_reauthentication(&replacement).is_ok());
        assert!(current.bitcoin_account_changed(&replacement));
        replacement.bitcoin_account.as_mut().unwrap().account_index = 7;
        replacement.bitcoin_account.as_mut().unwrap().xpub = Zeroizing::new("different".into());
        assert!(current.validate_reauthentication(&replacement).is_ok());
        assert!(current.bitcoin_account_changed(&replacement));
        replacement.bitcoin_account = None;
        assert!(current.validate_reauthentication(&replacement).is_err());
    }
}
