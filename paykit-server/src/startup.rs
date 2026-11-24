//! Fail-closed PostgreSQL startup composition completed before HTTP bind.

use std::{sync::Arc, time::Duration};

use sqlx::{PgPool, postgres::PgPoolOptions};
use thiserror::Error;

use crate::{
    config::Config,
    crypto::Crypto,
    persistence::{
        CreatorStore, DeploymentStore, InvoiceStore, MarketplacePreparationStore, ProcessLock,
        run_migrations,
    },
};

/// Secret-free failures from database initialization before the listener binds.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StartupError {
    /// PostgreSQL could not be reached.
    #[error("postgres connection failed")]
    Connection,
    /// Another Paykit Server process kept the database's process lock for the whole wait.
    #[error("another Paykit Server process is using this database")]
    ProcessLockHeld,
    /// Embedded migrations could not be applied.
    #[error("postgres migration failed")]
    Migration,
    /// Deployment invariants could not be recorded or validated.
    #[error("deployment initialization failed")]
    Deployment,
    /// Deployment cryptographic state could not be constructed.
    #[error("cryptographic initialization failed")]
    Crypto,
    /// At least one persisted Creator or payment record could not be authenticated.
    #[error("creator integrity check failed")]
    CreatorIntegrity,
    /// At least one encrypted Bitcoin payment record failed authentication.
    #[error("payment record integrity check failed")]
    PaymentRecordIntegrity,
    /// At least one Marketplace settlement or Bitcoin evidence row failed authentication.
    #[error("marketplace observation integrity check failed")]
    MarketplaceObservationIntegrity,
}

const PROCESS_LOCK_RETRY_INTERVAL: Duration = Duration::from_secs(1);
/// Bounds one attempt, so an unanswered connection counts as unreachable and is retried.
const PROCESS_LOCK_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Takes the database's process lock, waiting up to `wait` for a previous process
/// to exit, so only one Paykit Server process serves a database at a time.
///
/// An unreachable PostgreSQL is retried for the same `wait`, so a process started
/// during a database restart waits for it instead of exiting at once.
pub async fn acquire_process_lock(
    config: &Config,
    wait: Duration,
) -> Result<ProcessLock, StartupError> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let held_elsewhere = match tokio::time::timeout(
            PROCESS_LOCK_ATTEMPT_TIMEOUT,
            ProcessLock::try_acquire(config.database_options()),
        )
        .await
        {
            Ok(Ok(Some(lock))) => return Ok(lock),
            Ok(Ok(None)) => true,
            Ok(Err(_)) | Err(_) => false,
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(if held_elsewhere {
                StartupError::ProcessLockHeld
            } else {
                StartupError::Connection
            });
        }
        tokio::time::sleep(PROCESS_LOCK_RETRY_INTERVAL).await;
    }
}

/// Connects, migrates, validates deployment invariants, and authenticates every
/// persisted Creator credential and payment record before returning a ready database.
pub async fn initialize_database(config: &Config) -> Result<PgPool, StartupError> {
    let pool = PgPoolOptions::new()
        .connect_with(config.database_options().clone())
        .await
        .map_err(|_| StartupError::Connection)?;
    run_migrations(&pool)
        .await
        .map_err(|_| StartupError::Migration)?;
    DeploymentStore::new(&pool)
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
    let invoices = InvoiceStore::new(&pool, crypto.clone());
    invoices
        .attribute_legacy_usdt_receipts()
        .await
        .map_err(|_| StartupError::PaymentRecordIntegrity)?;
    invoices
        .scan_payment_record_integrity()
        .await
        .map_err(|_| StartupError::PaymentRecordIntegrity)?;
    MarketplacePreparationStore::new(&pool, crypto)
        .scan_observation_integrity()
        .await
        .map_err(|_| StartupError::MarketplaceObservationIntegrity)?;
    Ok(pool)
}
