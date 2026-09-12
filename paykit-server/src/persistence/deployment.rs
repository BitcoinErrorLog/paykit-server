//! Immutable deployment configuration persisted on first startup.

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::config::{DeploymentInvariants, StackRole};

/// This stack's identity, `stack_id = {stack_role}:{instance_uuid}`. The
/// instance UUID is minted once per database into the single-row
/// `stack_identity` table inside the same boot transaction that adopts the
/// deployment role, and is never rewritten; the role alone is deliberately
/// not the identity, because a replacement production stack carries the same
/// role (the same-role/wrong-instance mixup the pin exists to catch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackIdentity {
    role: StackRole,
    instance_uuid: Uuid,
}

impl StackIdentity {
    /// Constructs an identity from its two halves. Production identities are
    /// minted by [`DeploymentStore`]; this constructor serves test
    /// compositions that never touch a database.
    pub fn new(role: StackRole, instance_uuid: Uuid) -> Self {
        Self {
            role,
            instance_uuid,
        }
    }
    /// The configured deployment role half of the identity.
    pub fn role(&self) -> StackRole {
        self.role
    }
    /// The per-database instance UUID half of the identity.
    pub fn instance_uuid(&self) -> Uuid {
        self.instance_uuid
    }
    /// The canonical `{stack_role}:{instance_uuid}` form carried on the claim
    /// response, `/health/ready`, and every stack-pinned message.
    pub fn stack_id(&self) -> String {
        format!("{}:{}", self.role.as_str(), self.instance_uuid)
    }
}

/// Postgres repository for the singleton deployment invariant record.
#[derive(Clone, Debug)]
pub struct DeploymentStore {
    pool: PgPool,
}

impl DeploymentStore {
    /// Creates a deployment metadata repository over the supplied pool.
    pub fn new(pool: &PgPool) -> Self {
        Self { pool: pool.clone() }
    }

    /// Persists the first deployment configuration, or validates it on restart.
    ///
    /// The stack role follows an adopt-once rule: a stored NULL means the role
    /// is unset (a database created before roles existed), so the configured
    /// role is written exactly once; from then on every boot compares the
    /// stored role with the configured one and refuses to start on mismatch.
    ///
    /// The stack identity is minted in the same transaction: a boot that
    /// finds no `stack_identity` row inserts a fresh v4 UUID (`ON CONFLICT DO
    /// NOTHING`), and every boot reads the row back, so the returned identity
    /// is byte-identical across restarts and distinct across databases.
    pub async fn initialize(
        &self,
        invariants: &DeploymentInvariants,
    ) -> Result<StackIdentity, PersistenceError> {
        self.initialize_inner(invariants, None).await
    }

    /// Test hook: like [`Self::initialize`], but signals once the deployment
    /// row lock is held and waits for `release` before attempting role
    /// adoption, so a concurrent adopter can be proven blocked on the row
    /// lock. Only compiled under the `test-utils` feature.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn initialize_holding_lock_for_test(
        &self,
        invariants: &DeploymentInvariants,
        lock_held: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<StackIdentity, PersistenceError> {
        self.initialize_inner(invariants, Some((lock_held, release)))
            .await
    }

    /// Reads the minted stack identity, minting it first when none exists.
    /// Boot compositions that do not run the full startup path (E2E fixtures)
    /// use this; the production boot mints inside [`Self::initialize`]'s
    /// deployment-adoption transaction instead.
    pub async fn stack_identity(&self, role: StackRole) -> Result<StackIdentity, PersistenceError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let identity = mint_or_read_stack_identity(&mut transaction, role).await?;
        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(identity)
    }

    async fn initialize_inner(
        &self,
        invariants: &DeploymentInvariants,
        #[cfg_attr(not(feature = "test-utils"), allow(unused_variables))] barrier: Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    ) -> Result<StackIdentity, PersistenceError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query(
            "INSERT INTO deployment_metadata \
             (id, bitcoin_network, receiver_path, locks_key_fingerprint) \
             VALUES (1, $1, $2, $3) ON CONFLICT (id) DO NOTHING",
        )
        .bind(invariants.bitcoin_network.as_str())
        .bind(invariants.receiver_path.as_str())
        .bind(
            invariants
                .trusted_locks_key_fingerprint
                .as_bytes()
                .as_slice(),
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        let existing = sqlx::query_as::<_, DeploymentMetadataRow>(
            "SELECT bitcoin_network, receiver_path, locks_key_fingerprint, stack_role \
             FROM deployment_metadata WHERE id = 1 FOR UPDATE",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        #[cfg(feature = "test-utils")]
        if let Some((lock_held, release)) = barrier {
            // Reached only through the test hook: the row lock is now held,
            // so prove it and wait for the test to release the barrier.
            let _ = lock_held.send(());
            let _ = release.await;
        }

        if existing.bitcoin_network != invariants.bitcoin_network.as_str()
            || existing.receiver_path != invariants.receiver_path.as_str()
            || existing.locks_key_fingerprint != invariants.trusted_locks_key_fingerprint.as_bytes()
        {
            return Err(PersistenceError::DeploymentMismatch);
        }
        match existing.stack_role.as_deref() {
            Some(role) if role != invariants.stack_role.as_str() => {
                return Err(PersistenceError::DeploymentMismatch);
            }
            Some(_) => {}
            None => {
                let adopted = sqlx::query(
                    "UPDATE deployment_metadata SET stack_role = $1, updated_at = NOW() \
                     WHERE id = 1 AND stack_role IS NULL",
                )
                .bind(invariants.stack_role.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(|_| PersistenceError::Unavailable)?;
                // The row is held FOR UPDATE, so the adopt-once update must
                // apply to exactly one row; anything else means the adoption
                // did not happen and boot must refuse rather than continue
                // with an unset role.
                if adopted.rows_affected() != 1 {
                    return Err(PersistenceError::DeploymentRoleAdoption);
                }
            }
        }
        // Mint the stack identity once, in the same boot transaction that
        // adopts the role, and read the surviving row back: never rewritten.
        let identity = mint_or_read_stack_identity(&mut transaction, invariants.stack_role).await?;
        transaction
            .commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(identity)
    }
}

/// Mints the single-row `stack_identity` when absent (racing boots insert
/// different candidate UUIDs; `ON CONFLICT DO NOTHING` plus the singleton
/// primary key makes exactly one survive) and reads the surviving row back.
async fn mint_or_read_stack_identity(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role: StackRole,
) -> Result<StackIdentity, PersistenceError> {
    sqlx::query(
        "INSERT INTO stack_identity (singleton, instance_uuid) VALUES (TRUE, $1) \
         ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .execute(&mut **transaction)
    .await
    .map_err(|_| PersistenceError::Unavailable)?;
    let instance_uuid: Uuid =
        sqlx::query_scalar("SELECT instance_uuid FROM stack_identity WHERE singleton = TRUE")
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
    Ok(StackIdentity {
        role,
        instance_uuid,
    })
}

#[derive(sqlx::FromRow)]
struct DeploymentMetadataRow {
    bitcoin_network: String,
    receiver_path: String,
    locks_key_fingerprint: Vec<u8>,
    stack_role: Option<String>,
}

/// Secret-free persistence failures suitable for startup and API boundaries.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PersistenceError {
    /// Stored deployment metadata differs from typed startup configuration.
    #[error("deployment metadata does not match configuration")]
    DeploymentMismatch,
    /// The adopt-once stack role update did not apply to exactly one row.
    #[error("stack role adoption did not apply to exactly one deployment row")]
    DeploymentRoleAdoption,
    /// A persisted row is missing, malformed, or could not be authenticated.
    #[error("persisted state is missing or corrupt")]
    CorruptOrMissing,
    /// Existing credentials disagree with an attempted reauthentication.
    #[error("reauthentication credentials do not match the persisted account")]
    ReauthenticationMismatch,
    /// The canonical key tail was already claimed by a different creator on
    /// this stack (design B.8.5: the binding never expires).
    #[error("watch-only key material is claimed by a different creator")]
    KeyClaimedByOtherSeller,
    /// The persistence backend could not complete the operation.
    #[error("persistence operation failed")]
    Unavailable,
    /// A requested idempotent binding conflicts with a durable record.
    #[error("persisted state conflicts with the request")]
    Conflict,
    /// The idempotent payload matches an invoice whose creation baseline
    /// is still unresolved: the atomic allocation's replay branch found
    /// the winner's `awaiting_baseline` row, exactly what `preflight`
    /// reports as [`crate::persistence::InvoicePreflight::BaselineInProgress`].
    /// The caller must not run a second baseline for the same invoice.
    #[error("invoice creation baseline is still resolving")]
    BaselineInProgress,
    /// The invoice reached a final state that admits neither activation nor
    /// a replayed prepare: `void_baseline_failed`, `void_cancelled`, or
    /// `expired_final` (design §B.11.6 — reported as `invoice_finalized`).
    /// On `void`, a published invoice (`observing` / `expired_tail`) is the
    /// same refusal: a published request must expire through the tail rather
    /// than vanish.
    #[error("invoice is finalized")]
    InvoiceFinalized,
    /// The invoice was reaped at `prepare_expires_at` without activation
    /// (design §B.11.1) or a prepare replay arrived after that reap
    /// (§B.11.6 — reported as `prepare_expired`).
    #[error("invoice prepare window expired")]
    PrepareExpired,
    /// A `resolve` named a `prepared` invoice (design §B.9): nothing was
    /// ever published, so no buyer could have paid it — reported as
    /// `invoice_not_activated`.
    #[error("invoice was never activated")]
    InvoiceNotActivated,
    /// A `resolve` named an invoice already resolved with a DIFFERENT
    /// resolution (design §B.9): one-way, and the conflict is surfaced —
    /// reported as `invoice_already_resolved` naming the existing
    /// resolution. A replay of the SAME resolution is not an error.
    #[error("invoice is already resolved with a different resolution")]
    InvoiceAlreadyResolved,
}
