use std::time::Duration;

use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};

/// PostgreSQL advisory-lock key held by the one Paykit Server process serving a database.
pub const PROCESS_ADVISORY_LOCK_KEY: i64 = 4_679_362_128_418_235_710;

/// `application_name` of the lock session, so `pg_stat_activity` shows which client holds it.
pub const PROCESS_LOCK_APPLICATION_NAME: &str = "paykit-server process lock";

/// How a held process lock is checked, and retaken after its session ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessLockTiming {
    /// Pause between liveness checks of the lock session. A check, or an attempt to
    /// retake the lock, that takes longer than this counts as failed.
    pub check_interval: Duration,
    /// How long to keep retaking the lock once its session ends, which covers a
    /// PostgreSQL restart or failover.
    pub reacquire_within: Duration,
    /// Pause between attempts to retake the lock.
    pub retry_interval: Duration,
}

/// Why a held process lock could not be kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessLockLoss {
    /// Another session took the lock while this one was gone.
    HeldElsewhere,
    /// PostgreSQL stayed unreachable for the whole reacquire window.
    Unreachable,
}

/// A detached PostgreSQL session holding the process advisory lock.
///
/// Every process restores Creator Pubky grants from the shared database, and each
/// restore replaces the bearer held by any other process. Holding this lock for the
/// process lifetime keeps a second process from serving the same database.
///
/// Dropping this value closes the session, so PostgreSQL releases the lock even when
/// the process exits without calling [`ProcessLock::release`]. The session needs a
/// direct PostgreSQL connection or a session-mode pooler; behind a transaction-mode
/// pooler two processes can share one server session, where the lock is re-entrant.
pub struct ProcessLock {
    connection: PgConnection,
    options: PgConnectOptions,
}

impl ProcessLock {
    /// Takes the lock without waiting, returning `None` while another session holds it.
    pub async fn try_acquire(options: &PgConnectOptions) -> Result<Option<Self>, sqlx::Error> {
        let mut connection = PgConnection::connect_with(
            &options
                .clone()
                .application_name(PROCESS_LOCK_APPLICATION_NAME),
        )
        .await?;
        // A holder whose host disappears sends no FIN; keepalives let PostgreSQL end
        // its idle session, and release the lock, within about a minute. Keepalives
        // stop while PostgreSQL still has unacknowledged data for the holder, so the
        // user timeout bounds that case to a minute as well.
        sqlx::query(
            "SELECT set_config('tcp_keepalives_idle', '20', false), \
                    set_config('tcp_keepalives_interval', '10', false), \
                    set_config('tcp_keepalives_count', '3', false), \
                    set_config('tcp_user_timeout', '60000', false)",
        )
        .execute(&mut connection)
        .await?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(PROCESS_ADVISORY_LOCK_KEY)
            .fetch_one(&mut connection)
            .await?;
        if acquired {
            Ok(Some(Self {
                connection,
                options: options.clone(),
            }))
        } else {
            connection.close().await?;
            Ok(None)
        }
    }

    /// Completes once the lock session stops answering, which means PostgreSQL may
    /// have released the lock to another process.
    pub async fn lost(&mut self, check_interval: Duration) {
        loop {
            tokio::time::sleep(check_interval).await;
            match tokio::time::timeout(check_interval, self.connection.ping()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return,
            }
        }
    }

    /// Keeps the lock until it is lost for good.
    ///
    /// When the lock session ends, for example because PostgreSQL restarted, this
    /// retakes the lock on a new session and keeps holding it. It completes only when
    /// another session took the lock meanwhile, or when PostgreSQL stays unreachable
    /// for `timing.reacquire_within`.
    pub async fn hold(&mut self, timing: ProcessLockTiming) -> ProcessLockLoss {
        loop {
            self.lost(timing.check_interval).await;
            tracing::warn!("database process lock session ended; retaking the lock");
            let deadline = tokio::time::Instant::now() + timing.reacquire_within;
            loop {
                match tokio::time::timeout(timing.check_interval, Self::try_acquire(&self.options))
                    .await
                {
                    Ok(Ok(Some(retaken))) => {
                        *self = retaken;
                        tracing::info!("database process lock retaken");
                        break;
                    }
                    Ok(Ok(None)) => return ProcessLockLoss::HeldElsewhere,
                    Ok(Err(_)) | Err(_) => {}
                }
                if tokio::time::Instant::now() >= deadline {
                    return ProcessLockLoss::Unreachable;
                }
                tokio::time::sleep(timing.retry_interval).await;
            }
        }
    }

    /// Releases the lock and closes its session.
    pub async fn release(mut self) -> Result<(), sqlx::Error> {
        let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
            .bind(PROCESS_ADVISORY_LOCK_KEY)
            .fetch_one(&mut self.connection)
            .await?;
        if !released {
            tracing::warn!(
                "database process lock was not held by its session at release; \
                 a transaction-mode pooler may sit between the server and PostgreSQL"
            );
        }
        self.connection.close().await
    }
}
