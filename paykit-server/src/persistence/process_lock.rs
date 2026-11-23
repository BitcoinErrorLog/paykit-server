use std::time::Duration;

use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};

/// PostgreSQL advisory-lock key held by the one Paykit Server process serving a database.
pub const PROCESS_ADVISORY_LOCK_KEY: i64 = 4_679_362_128_418_235_710;

/// A detached PostgreSQL session holding the process advisory lock.
///
/// Every process restores Creator Pubky grants from the shared database, and each
/// restore replaces the bearer held by any other process. Holding this lock for the
/// process lifetime keeps a second process from serving the same database.
///
/// Dropping this value closes the session, so PostgreSQL releases the lock even when
/// the process exits without calling [`ProcessLock::release`]. The session needs a
/// direct PostgreSQL connection; a transaction-pooling proxy cannot hold session locks.
pub struct ProcessLock {
    connection: PgConnection,
}

impl ProcessLock {
    /// Takes the lock without waiting, returning `None` while another session holds it.
    pub async fn try_acquire(options: &PgConnectOptions) -> Result<Option<Self>, sqlx::Error> {
        let mut connection = PgConnection::connect_with(options).await?;
        // A holder whose host disappears sends no FIN; keepalives let PostgreSQL end
        // its session, and release the lock, within about a minute.
        sqlx::query(
            "SELECT set_config('tcp_keepalives_idle', '20', false), \
                    set_config('tcp_keepalives_interval', '10', false), \
                    set_config('tcp_keepalives_count', '3', false)",
        )
        .execute(&mut connection)
        .await?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(PROCESS_ADVISORY_LOCK_KEY)
            .fetch_one(&mut connection)
            .await?;
        if acquired {
            Ok(Some(Self { connection }))
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

    /// Releases the lock and closes its session.
    pub async fn release(mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(PROCESS_ADVISORY_LOCK_KEY)
            .execute(&mut self.connection)
            .await?;
        self.connection.close().await
    }
}
