//! Immutable deployment configuration persisted on first startup.

use sqlx::PgPool;
use thiserror::Error;

use crate::config::DeploymentInvariants;

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
    pub async fn initialize(
        &self,
        invariants: &DeploymentInvariants,
    ) -> Result<(), PersistenceError> {
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
    ) -> Result<(), PersistenceError> {
        self.initialize_inner(invariants, Some((lock_held, release)))
            .await
    }

    async fn initialize_inner(
        &self,
        invariants: &DeploymentInvariants,
        #[cfg_attr(not(feature = "test-utils"), allow(unused_variables))] barrier: Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    ) -> Result<(), PersistenceError> {
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
                Err(PersistenceError::DeploymentMismatch)
            }
            Some(_) => transaction
                .commit()
                .await
                .map_err(|_| PersistenceError::Unavailable),
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
                transaction
                    .commit()
                    .await
                    .map_err(|_| PersistenceError::Unavailable)
            }
        }
    }
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
    /// The persistence backend could not complete the operation.
    #[error("persistence operation failed")]
    Unavailable,
    /// A requested idempotent binding conflicts with a durable record.
    #[error("persisted state conflicts with the request")]
    Conflict,
}
