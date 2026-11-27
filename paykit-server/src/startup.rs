//! Fail-closed PostgreSQL startup composition completed before HTTP bind.

use std::{future::Future, sync::Arc, time::Duration};

use sqlx::{PgPool, postgres::PgPoolOptions};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    config::Config,
    crypto::Crypto,
    persistence::{
        CreatorStore, DeploymentStore, InvoiceStore, MarketplacePreparationStore, ProcessLock,
        ProcessLockLoss, ProcessLockTiming, run_migrations,
    },
    server::LOST_PROCESS_LOCK_DRAIN_LIMIT,
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

/// Blocks in PostgreSQL until the database's process lock is granted.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub async fn acquire_process_lock_blocking(config: &Config) -> Result<ProcessLock, StartupError> {
    ProcessLock::acquire_blocking(config.database_options())
        .await
        .map_err(|_| StartupError::Connection)
}

fn map_process_lock_loss(loss: ProcessLockLoss) -> StartupError {
    match loss {
        ProcessLockLoss::HeldElsewhere => StartupError::ProcessLockHeld,
        ProcessLockLoss::Unreachable => StartupError::Connection,
    }
}

/// Fences any prior unclean holder, waits out takeover quarantine, and initializes
/// the database while continuously renewing and monitoring `lock`.
///
/// When `public.process_ownership` already exists, ownership is claimed and takeover
/// quarantine completes before migrations, `DeploymentStore::initialize`,
/// `attribute_legacy_usdt_receipts`, or integrity scans run. On a fresh or pre-0030
/// database where `process_ownership` does not yet exist, migrations run first to
/// create the table, then ownership is claimed immediately before deployment
/// initialization and legacy receipt attribution.
pub async fn initialize_database_holding_process_lock(
    config: &Config,
    lock: &mut ProcessLock,
    timing: ProcessLockTiming,
) -> Result<PgPool, StartupError> {
    initialize_database_holding_process_lock_with_owner(config, lock, Uuid::new_v4(), timing).await
}

/// Same as [`initialize_database_holding_process_lock`] with a caller-supplied
/// `owner_id`, allowing callers that race startup against shutdown to clear a
/// committed ownership row if cancelled mid-claim.
pub async fn initialize_database_holding_process_lock_with_owner(
    config: &Config,
    lock: &mut ProcessLock,
    owner_id: Uuid,
    timing: ProcessLockTiming,
) -> Result<PgPool, StartupError> {
    initialize_database_holding_process_lock_inner(config, lock, owner_id, timing, async {}).await
}

/// Runs [`initialize_database_holding_process_lock_with_owner`] with an injected
/// post-claim hook under the startup lease-renewal supervisor for E2E tests.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub async fn initialize_database_holding_process_lock_with_post_claim_hook<H>(
    config: &Config,
    lock: &mut ProcessLock,
    owner_id: Uuid,
    timing: ProcessLockTiming,
    post_claim_hook: H,
) -> Result<PgPool, StartupError>
where
    H: Future<Output = ()> + Send,
{
    initialize_database_holding_process_lock_inner(config, lock, owner_id, timing, post_claim_hook)
        .await
}

async fn initialize_database_holding_process_lock_inner<H>(
    config: &Config,
    lock: &mut ProcessLock,
    owner_id: Uuid,
    timing: ProcessLockTiming,
    post_claim_hook: H,
) -> Result<PgPool, StartupError>
where
    H: Future<Output = ()> + Send,
{
    let lock_loss_drain_limit = config
        .shutdown
        .drain_timeout
        .min(LOST_PROCESS_LOCK_DRAIN_LIMIT);
    let table_exists = lock
        .ownership_table_exists()
        .await
        .map_err(|_| StartupError::Connection)?;

    if table_exists {
        let ownership = lock
            .claim_ownership(owner_id, timing, lock_loss_drain_limit)
            .await
            .map_err(map_process_lock_loss)?;
        lock.set_claimed_ownership(ownership);
        let outcome = lock
            .run_while_renewing_claimed(timing, async {
                post_claim_hook.await;
                let pool = connect_and_migrate(config)
                    .await
                    .map_err(|error| (error, None))?;
                if let Err(error) = finalize_database_initialization(&pool, config).await {
                    return Err((error, Some(pool)));
                }
                Ok(pool)
            })
            .await;
        match outcome {
            Ok(Ok(pool)) => Ok(pool),
            Ok(Err((error, maybe_pool))) => {
                let _ = lock
                    .clear_owner_with_fallback(owner_id, maybe_pool.as_ref())
                    .await;
                Err(error)
            }
            Err(loss) => Err(map_process_lock_loss(loss)),
        }
    } else {
        let pool = connect_and_migrate(config).await?;
        let ownership = lock
            .claim_ownership(owner_id, timing, lock_loss_drain_limit)
            .await
            .map_err(map_process_lock_loss)?;
        lock.set_claimed_ownership(ownership);
        let outcome = lock
            .run_while_renewing_claimed(timing, async {
                post_claim_hook.await;
                finalize_database_initialization(&pool, config).await
            })
            .await;
        match outcome {
            Ok(Ok(())) => Ok(pool),
            Ok(Err(error)) => {
                let _ = lock.clear_owner_with_fallback(owner_id, Some(&pool)).await;
                Err(error)
            }
            Err(loss) => Err(map_process_lock_loss(loss)),
        }
    }
}

/// Connects, migrates, validates deployment invariants, and authenticates every
/// persisted Creator credential and payment record before returning a ready database.
pub async fn initialize_database(config: &Config) -> Result<PgPool, StartupError> {
    let pool = connect_and_migrate(config).await?;
    finalize_database_initialization(&pool, config).await?;
    Ok(pool)
}

async fn connect_and_migrate(config: &Config) -> Result<PgPool, StartupError> {
    let pool = PgPoolOptions::new()
        .connect_with(config.database_options().clone())
        .await
        .map_err(|_| StartupError::Connection)?;
    run_migrations(&pool)
        .await
        .map_err(|_| StartupError::Migration)?;
    Ok(pool)
}

async fn finalize_database_initialization(
    pool: &PgPool,
    config: &Config,
) -> Result<(), StartupError> {
    DeploymentStore::new(pool)
        .initialize(config.deployment_invariants())
        .await
        .map_err(|_| StartupError::Deployment)?;

    let crypto = Arc::new(
        Crypto::from_master_key(config.master_key().as_bytes())
            .map_err(|_| StartupError::Crypto)?,
    );
    CreatorStore::new(pool, crypto.clone())
        .scan_integrity()
        .await
        .map_err(|_| StartupError::CreatorIntegrity)?;
    let invoices = InvoiceStore::new(pool, crypto.clone());
    invoices
        .attribute_legacy_usdt_receipts()
        .await
        .map_err(|_| StartupError::PaymentRecordIntegrity)?;
    invoices
        .scan_payment_record_integrity()
        .await
        .map_err(|_| StartupError::PaymentRecordIntegrity)?;
    MarketplacePreparationStore::new(pool, crypto)
        .scan_observation_integrity()
        .await
        .map_err(|_| StartupError::MarketplaceObservationIntegrity)?;
    Ok(())
}
