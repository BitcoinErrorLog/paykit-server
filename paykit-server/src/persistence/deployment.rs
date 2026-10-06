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
    pub async fn initialize(
        &self,
        invariants: &DeploymentInvariants,
    ) -> Result<(), PersistenceError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query(
            "INSERT INTO deployment_metadata \
             (id, bitcoin_network, paykit_client_id, app_id, locks_key_fingerprint) \
             VALUES (1, $1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
        )
        .bind(invariants.bitcoin_network.as_str())
        .bind(invariants.paykit_client_id.as_str())
        .bind(invariants.app_id.as_str())
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
            "SELECT bitcoin_network, paykit_client_id, app_id, locks_key_fingerprint \
             FROM deployment_metadata WHERE id = 1 FOR UPDATE",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;

        if existing.bitcoin_network == invariants.bitcoin_network.as_str()
            && existing.paykit_client_id == invariants.paykit_client_id.as_str()
            && existing.app_id == invariants.app_id.as_str()
            && existing.locks_key_fingerprint == invariants.trusted_locks_key_fingerprint.as_bytes()
        {
            transaction
                .commit()
                .await
                .map_err(|_| PersistenceError::Unavailable)
        } else {
            Err(PersistenceError::DeploymentMismatch)
        }
    }
}

#[derive(sqlx::FromRow)]
struct DeploymentMetadataRow {
    bitcoin_network: String,
    paykit_client_id: String,
    app_id: String,
    locks_key_fingerprint: Vec<u8>,
}

/// Secret-free persistence failures suitable for startup and API boundaries.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PersistenceError {
    /// Stored deployment metadata differs from typed startup configuration.
    #[error("deployment metadata does not match configuration")]
    DeploymentMismatch,
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
    /// A typed caller value cannot be represented by the persistence contract.
    #[error("persistence input is invalid")]
    InvalidInput,
}

impl PersistenceError {
    pub(crate) const fn diagnostic_label(self) -> &'static str {
        match self {
            Self::DeploymentMismatch => "deployment_mismatch",
            Self::CorruptOrMissing => "corrupt_or_missing",
            Self::ReauthenticationMismatch => "reauthentication_mismatch",
            Self::Unavailable => "unavailable",
            Self::Conflict => "conflict",
            Self::InvalidInput => "invalid_input",
        }
    }
}
