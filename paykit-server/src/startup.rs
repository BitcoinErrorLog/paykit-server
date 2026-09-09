//! Fail-closed PostgreSQL startup composition completed before HTTP bind.

use std::sync::Arc;

use sqlx::{PgPool, postgres::PgPoolOptions};
use thiserror::Error;

use crate::{
    config::Config,
    crypto::Crypto,
    persistence::{CreatorStore, DeploymentStore, InvoiceStore, StackIdentity, run_migrations},
};

/// Secret-free failures from database initialization before the listener binds.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StartupError {
    /// PostgreSQL could not be reached.
    #[error("postgres connection failed")]
    Connection,
    /// Embedded migrations could not be applied.
    #[error("postgres migration failed")]
    Migration,
    /// Deployment invariants could not be recorded or validated.
    #[error("deployment initialization failed")]
    Deployment,
    /// Deployment cryptographic state could not be constructed.
    #[error("cryptographic initialization failed")]
    Crypto,
    /// At least one persisted Creator or SDK state could not be authenticated.
    #[error("creator integrity check failed")]
    CreatorIntegrity,
    /// At least one encrypted Bitcoin payment record failed authentication.
    #[error("payment record integrity check failed")]
    PaymentRecordIntegrity,
}

/// A database that completed fail-closed startup: the connection pool and the
/// stack identity minted (once) inside the deployment-adoption transaction.
pub struct InitializedDatabase {
    pub pool: PgPool,
    pub stack_identity: StackIdentity,
}

impl std::fmt::Debug for InitializedDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitializedDatabase")
            .field("pool", &"<redacted>")
            .field("stack_id", &self.stack_identity.stack_id())
            .finish()
    }
}

/// Connects, migrates, validates deployment invariants, mints or reads the
/// stack identity, and authenticates every persisted Creator credential and
/// SDK state before returning a ready database.
pub async fn initialize_database(config: &Config) -> Result<InitializedDatabase, StartupError> {
    let pool = PgPoolOptions::new()
        .connect(config.database_url())
        .await
        .map_err(|_| StartupError::Connection)?;
    run_migrations(&pool)
        .await
        .map_err(|_| StartupError::Migration)?;
    let stack_identity = DeploymentStore::new(&pool)
        .initialize(config.deployment_invariants())
        .await
        .map_err(|_| StartupError::Deployment)?;

    let crypto = Arc::new(
        Crypto::from_master_key(config.master_key().as_bytes())
            .map_err(|_| StartupError::Crypto)?,
    );
    CreatorStore::new(&pool, crypto.clone())
        .scan_integrity()
        .await
        .map_err(|_| StartupError::CreatorIntegrity)?;
    let invoices = InvoiceStore::new(&pool, crypto);
    invoices
        .scan_payment_record_integrity()
        .await
        .map_err(|_| StartupError::PaymentRecordIntegrity)?;
    Ok(InitializedDatabase {
        pool,
        stack_identity,
    })
}
