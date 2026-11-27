use std::time::Duration;

use sqlx::{Connection, PgConnection, PgPool, postgres::PgConnectOptions};
use uuid::Uuid;

/// PostgreSQL advisory-lock key held by the one Paykit Server process serving a database.
pub const PROCESS_ADVISORY_LOCK_KEY: i64 = 4_679_362_128_418_235_710;

/// `application_name` of the lock session, so `pg_stat_activity` shows which client holds it.
pub const PROCESS_LOCK_APPLICATION_NAME: &str = "paykit-server process lock";

/// Minimum clock-skew and scheduling margin between local lease expiry and PostgreSQL
/// quarantine expiry.
const MIN_LEASE_SAFETY_MARGIN: Duration = Duration::from_millis(250);

/// How a held process lock is checked, renewed, and retaken after its session ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessLockTiming {
    /// Pause between liveness renewals of the lock session. A renewal or attempt to
    /// retake the lock that takes longer than this counts as failed.
    pub check_interval: Duration,
    /// How long to keep retaking the lock once its session ends, which covers a
    /// PostgreSQL restart or failover. Business admission remains closed during this wait.
    pub reacquire_within: Duration,
    /// Pause between attempts to retake the lock or poll takeover quarantine.
    pub retry_interval: Duration,
}

impl ProcessLockTiming {
    /// How long after the start of a confirmed renewal this process may admit business
    /// work locally before requiring another renewal.
    pub fn local_admission_window(self) -> Duration {
        self.check_interval.saturating_mul(2)
    }

    /// Durable PostgreSQL lease duration ensuring that an unreachable or force-terminated
    /// holder finishes admission revocation, reacquisition, and bounded lock-loss
    /// termination before a replacement exits takeover quarantine.
    pub fn lease_ttl(self, lock_loss_drain_limit: Duration) -> Duration {
        let safety_margin = self.check_interval.max(MIN_LEASE_SAFETY_MARGIN);
        self.local_admission_window()
            .saturating_add(self.reacquire_within)
            .saturating_add(lock_loss_drain_limit)
            .saturating_add(safety_margin)
    }
}

/// Why a held process lock could not be kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessLockLoss {
    /// Another session took the lock or fenced this process's ownership generation.
    HeldElsewhere,
    /// PostgreSQL stayed unreachable for the whole reacquire window.
    Unreachable,
}

/// Ownership state reported to the server runtime while holding a process lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessLockState {
    /// Ownership is active and locally valid until `local_valid_until`.
    Active {
        local_valid_until: tokio::time::Instant,
    },
    /// The lock session failed or was fenced; business admission and worker claims
    /// must stop immediately.
    Suspended,
}

/// Durable ownership lease claimed in PostgreSQL for one serving process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessOwnership {
    owner_id: Uuid,
    generation: i64,
    last_renew_started: tokio::time::Instant,
    local_admission_window: Duration,
    lease_ttl: Duration,
}

impl ProcessOwnership {
    pub fn owner_id(&self) -> Uuid {
        self.owner_id
    }

    pub fn generation(&self) -> i64 {
        self.generation
    }

    pub fn local_valid_until(&self) -> tokio::time::Instant {
        self.last_renew_started + self.local_admission_window
    }
}

/// A detached PostgreSQL session holding the process advisory lock.
///
/// Every process restores Creator Pubky grants from the shared database, and each
/// restore replaces the bearer held by any other process. Holding this lock for the
/// process lifetime, paired with the durable `process_ownership` lease and generation
/// fence, keeps two processes from admitting business work or restoring Creator grants
/// concurrently.
///
/// Dropping this value closes the session, so PostgreSQL releases the lock even when
/// the process exits without calling [`ProcessLock::release`]. The session needs a
/// direct PostgreSQL connection or a session-mode pooler; behind a transaction-mode
/// pooler two processes can share one server session, where the lock is re-entrant.
pub struct ProcessLock {
    connection: Option<PgConnection>,
    options: PgConnectOptions,
    claimed: Option<ProcessOwnership>,
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
                connection: Some(connection),
                options: options.clone(),
                claimed: None,
            }))
        } else {
            connection.close().await?;
            Ok(None)
        }
    }

    /// Blocks in PostgreSQL until the process advisory lock is granted.
    /// Used by takeover E2E tests to queue a replacement directly behind the
    /// current lock session so takeover begins the instant that session ends.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn acquire_blocking(options: &PgConnectOptions) -> Result<Self, sqlx::Error> {
        let mut connection = PgConnection::connect_with(
            &options
                .clone()
                .application_name(PROCESS_LOCK_APPLICATION_NAME),
        )
        .await?;
        sqlx::query(
            "SELECT set_config('tcp_keepalives_idle', '20', false), \
                    set_config('tcp_keepalives_interval', '10', false), \
                    set_config('tcp_keepalives_count', '3', false), \
                    set_config('tcp_user_timeout', '60000', false)",
        )
        .execute(&mut connection)
        .await?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(PROCESS_ADVISORY_LOCK_KEY)
            .execute(&mut connection)
            .await?;
        Ok(Self {
            connection: Some(connection),
            options: options.clone(),
            claimed: None,
        })
    }

    /// Returns the durable ownership already claimed during startup, if any.
    pub fn claimed_ownership(&self) -> Option<ProcessOwnership> {
        self.claimed
    }

    pub(crate) fn set_claimed_ownership(&mut self, ownership: ProcessOwnership) {
        self.claimed = Some(ownership);
    }

    pub(crate) fn take_claimed_ownership(&mut self) -> Option<ProcessOwnership> {
        self.claimed.take()
    }

    /// Returns whether the durable `process_ownership` table already exists in this database.
    pub async fn ownership_table_exists(&mut self) -> Result<bool, sqlx::Error> {
        let Some(connection) = self.connection.as_mut() else {
            return Err(sqlx::Error::WorkerCrashed);
        };
        sqlx::query_scalar("SELECT to_regclass('public.process_ownership') IS NOT NULL")
            .fetch_one(connection)
            .await
    }

    /// Completes once the lock session stops answering, which means PostgreSQL may
    /// have released the lock to another process.
    pub async fn lost(&mut self, check_interval: Duration) {
        loop {
            tokio::time::sleep(check_interval).await;
            let Some(connection) = self.connection.as_mut() else {
                return;
            };
            match tokio::time::timeout(check_interval, connection.ping()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return,
            }
        }
    }

    /// Claims the durable `process_ownership` lease for `owner_id` before this process
    /// mutates database startup state, opens HTTP admission, spawns workers, or restores
    /// Creator grants.
    ///
    /// If the previous owner exited cleanly (`owner_id IS NULL`), ownership transfers
    /// immediately. If the previous lock session ended uncleanly, this fences that owner
    /// and quarantines takeover until the old owner finishes draining cleanly and clears
    /// its lease, or until its durable lease expires. Reconnecting after a lost claim
    /// response idempotently renews the same `owner_id` if unfenced.
    pub async fn claim_ownership(
        &mut self,
        owner_id: Uuid,
        timing: ProcessLockTiming,
        lock_loss_drain_limit: Duration,
    ) -> Result<ProcessOwnership, ProcessLockLoss> {
        let local_admission_window = timing.local_admission_window();
        let lease_ttl = timing.lease_ttl(lock_loss_drain_limit);

        loop {
            let claim_started = tokio::time::Instant::now();
            let step = match self.connection.as_mut() {
                Some(connection) => tokio::time::timeout(
                    timing.check_interval,
                    claim_or_fence_step(connection, owner_id, lease_ttl),
                )
                .await
                .ok(),
                None => None,
            };
            match step {
                Some(Ok(ClaimStep::Claimed(generation))) => {
                    return Ok(ProcessOwnership {
                        owner_id,
                        generation,
                        last_renew_started: claim_started,
                        local_admission_window,
                        lease_ttl,
                    });
                }
                Some(Ok(ClaimStep::Quarantined(remaining))) => {
                    let sleep_for = if remaining.is_zero() {
                        timing.retry_interval
                    } else {
                        timing.retry_interval.min(remaining)
                    };
                    tokio::time::sleep(sleep_for).await;
                    continue;
                }
                Some(Ok(ClaimStep::LockNotHeld)) => {
                    self.connection.take();
                    return Err(ProcessLockLoss::HeldElsewhere);
                }
                Some(Err(_)) | None => {
                    self.connection.take();
                    tracing::warn!(
                        "database process lock session ended during ownership claim; retaking the lock"
                    );
                    let deadline = tokio::time::Instant::now() + timing.reacquire_within;
                    loop {
                        let now = tokio::time::Instant::now();
                        if now >= deadline {
                            return Err(ProcessLockLoss::Unreachable);
                        }
                        let attempt_timeout = timing
                            .check_interval
                            .min(deadline.saturating_duration_since(now));
                        match tokio::time::timeout(
                            attempt_timeout,
                            Self::try_acquire(&self.options),
                        )
                        .await
                        {
                            Ok(Ok(Some(retaken))) => {
                                self.connection = retaken.connection;
                                break;
                            }
                            Ok(Ok(None)) => return Err(ProcessLockLoss::HeldElsewhere),
                            Ok(Err(_)) | Err(_) => {}
                        }
                        let now = tokio::time::Instant::now();
                        if now >= deadline {
                            return Err(ProcessLockLoss::Unreachable);
                        }
                        tokio::time::sleep(
                            timing
                                .retry_interval
                                .min(deadline.saturating_duration_since(now)),
                        )
                        .await;
                    }
                }
            }
        }
    }

    /// Confirms and refreshes an already-claimed ownership lease on the lock session
    /// before opening business admission.
    pub async fn renew_claimed_ownership(
        &mut self,
        ownership: &mut ProcessOwnership,
        timing: ProcessLockTiming,
    ) -> Result<(), ProcessLockLoss> {
        let renew_started = tokio::time::Instant::now();
        let renewed = match self.connection.as_mut() {
            Some(connection) => match tokio::time::timeout(
                timing.check_interval,
                renew_ownership_on(connection, ownership),
            )
            .await
            {
                Ok(Ok(true)) => Ok(true),
                Ok(Ok(false)) => Ok(false),
                Ok(Err(_)) | Err(_) => Err(()),
            },
            None => Err(()),
        };
        match renewed {
            Ok(true) => {
                ownership.last_renew_started = renew_started;
                return Ok(());
            }
            Ok(false) => {
                self.connection.take();
                return Err(ProcessLockLoss::HeldElsewhere);
            }
            Err(()) => {
                self.connection.take();
            }
        }

        let hard_deadline = ownership.last_renew_started
            + ownership.local_admission_window
            + timing.reacquire_within;
        let deadline = (tokio::time::Instant::now() + timing.reacquire_within).min(hard_deadline);
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(ProcessLockLoss::Unreachable);
            }
            let attempt_started = now;
            let attempt_timeout = timing
                .check_interval
                .min(deadline.saturating_duration_since(now));
            match tokio::time::timeout(
                attempt_timeout,
                Self::try_reacquire_owned(&self.options, ownership),
            )
            .await
            {
                Ok(Ok(Some(retaken))) => {
                    self.connection = retaken.connection;
                    ownership.last_renew_started = attempt_started;
                    return Ok(());
                }
                Ok(Ok(None)) => return Err(ProcessLockLoss::HeldElsewhere),
                Ok(Err(_)) | Err(_) => {}
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(ProcessLockLoss::Unreachable);
            }
            tokio::time::sleep(
                timing
                    .retry_interval
                    .min(deadline.saturating_duration_since(now)),
            )
            .await;
        }
    }

    /// Clears `process_ownership` if this process's `owner_id` was committed and not fenced.
    /// Returns an error when the dedicated lock connection is absent so callers
    /// fall back to clearing through a pooled or fresh connection.
    pub async fn clear_owner_if_claimed(&mut self, owner_id: Uuid) -> Result<(), sqlx::Error> {
        if self.claimed.is_some_and(|owned| owned.owner_id == owner_id) {
            self.claimed = None;
        }
        let Some(connection) = self.connection.as_mut() else {
            return Err(sqlx::Error::WorkerCrashed);
        };
        sqlx::query(
            "UPDATE process_ownership \
             SET owner_id = NULL, \
                 fenced = FALSE, \
                 lease_expires_at = NULL, \
                 updated_at = clock_timestamp() \
             WHERE id = 1 AND owner_id = $1 AND NOT fenced",
        )
        .bind(owner_id)
        .execute(connection)
        .await?;
        Ok(())
    }

    /// Clears `process_ownership` for `owner_id` on the lock session, falling back to
    /// `pool` or a bounded short-lived connection if the lock session is absent or failed.
    pub async fn clear_owner_with_fallback(
        &mut self,
        owner_id: Uuid,
        pool: Option<&PgPool>,
    ) -> Result<(), sqlx::Error> {
        if tokio::time::timeout(
            Duration::from_secs(2),
            self.clear_owner_if_claimed(owner_id),
        )
        .await
        .is_ok_and(|result| result.is_ok())
        {
            return Ok(());
        }
        if let Some(pool) = pool {
            return tokio::time::timeout(
                Duration::from_secs(2),
                clear_process_owner_if_claimed(pool, owner_id),
            )
            .await
            .map_err(|_| sqlx::Error::PoolTimedOut)?;
        }
        let options = self.options.clone();
        tokio::time::timeout(Duration::from_secs(2), async move {
            let mut connection = PgConnection::connect_with(&options).await?;
            let result = sqlx::query(
                "UPDATE process_ownership \
                 SET owner_id = NULL, \
                     fenced = FALSE, \
                     lease_expires_at = NULL, \
                     updated_at = clock_timestamp() \
                 WHERE id = 1 AND owner_id = $1 AND NOT fenced",
            )
            .bind(owner_id)
            .execute(&mut connection)
            .await;
            let _ = connection.close().await;
            result?;
            Ok(())
        })
        .await
        .map_err(|_| sqlx::Error::PoolTimedOut)?
    }

    /// Continuously renews `ownership` every `timing.check_interval` during post-claim
    /// startup work, completing immediately if the lock session drops or is fenced.
    pub async fn supervise_claimed_ownership(
        &mut self,
        ownership: &mut ProcessOwnership,
        timing: ProcessLockTiming,
    ) -> ProcessLockLoss {
        loop {
            tokio::time::sleep(timing.check_interval).await;
            let renew_started = tokio::time::Instant::now();
            let renewed = match self.connection.as_mut() {
                Some(connection) => match tokio::time::timeout(
                    timing.check_interval,
                    renew_ownership_on(connection, ownership),
                )
                .await
                {
                    Ok(Ok(true)) => Ok(true),
                    Ok(Ok(false)) => Ok(false),
                    Ok(Err(_)) | Err(_) => Err(()),
                },
                None => Err(()),
            };
            match renewed {
                Ok(true) => {
                    ownership.last_renew_started = renew_started;
                }
                Ok(false) => {
                    self.connection.take();
                    return ProcessLockLoss::HeldElsewhere;
                }
                Err(()) => {
                    self.connection.take();
                    return ProcessLockLoss::Unreachable;
                }
            }
        }
    }

    /// Runs `work` concurrently with continuous periodic renewal of the claimed
    /// ownership lease, cancelling `work` immediately if ownership is lost or fenced.
    pub async fn run_while_renewing_claimed<F, T>(
        &mut self,
        timing: ProcessLockTiming,
        work: F,
    ) -> Result<T, ProcessLockLoss>
    where
        F: std::future::Future<Output = T>,
    {
        let mut ownership = self
            .claimed
            .take()
            .expect("ProcessLock must hold claimed ownership before supervised startup");
        let outcome = {
            let supervisor = self.supervise_claimed_ownership(&mut ownership, timing);
            tokio::pin!(supervisor);
            tokio::pin!(work);
            tokio::select! {
                biased;
                loss = &mut supervisor => Err(loss),
                result = &mut work => Ok(result),
            }
        };
        if outcome.is_ok() {
            self.claimed = Some(ownership);
        }
        outcome
    }

    /// Simulates a dropped dedicated lock connection after a committed claim.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn drop_connection_for_test(&mut self) {
        self.connection.take();
    }

    /// Renews the held advisory lock and durable ownership lease until ownership is lost.
    ///
    /// Immediately invokes `on_state_change(ProcessLockState::Suspended)` on the first
    /// session failure or fence before any reacquisition attempt. Admission is resumed
    /// only if this process retakes the advisory lock and PostgreSQL confirms the same
    /// unfenced ownership generation.
    pub async fn hold_owned(
        &mut self,
        ownership: &mut ProcessOwnership,
        timing: ProcessLockTiming,
        mut on_state_change: impl FnMut(ProcessLockState),
    ) -> ProcessLockLoss {
        loop {
            tokio::time::sleep(timing.check_interval).await;
            let renew_started = tokio::time::Instant::now();
            let hard_deadline = ownership.last_renew_started
                + ownership.local_admission_window
                + timing.reacquire_within;
            let local_remaining = ownership
                .local_valid_until()
                .saturating_duration_since(renew_started);
            if local_remaining.is_zero() {
                on_state_change(ProcessLockState::Suspended);
            }
            let renew_timeout = if local_remaining.is_zero() {
                timing
                    .check_interval
                    .min(hard_deadline.saturating_duration_since(renew_started))
            } else {
                timing.check_interval.min(local_remaining)
            };
            let renewed = match (self.connection.as_mut(), renew_timeout.is_zero()) {
                (Some(connection), false) => {
                    match tokio::time::timeout(
                        renew_timeout,
                        renew_ownership_on(connection, ownership),
                    )
                    .await
                    {
                        Ok(Ok(true)) => Ok(true),
                        Ok(Ok(false)) => Ok(false),
                        Ok(Err(_)) | Err(_) => Err(()),
                    }
                }
                _ => Err(()),
            };
            match renewed {
                Ok(true) => {
                    ownership.last_renew_started = renew_started;
                    on_state_change(ProcessLockState::Active {
                        local_valid_until: ownership.local_valid_until(),
                    });
                    continue;
                }
                Ok(false) => {
                    on_state_change(ProcessLockState::Suspended);
                    self.connection.take();
                    tracing::warn!("database process ownership was fenced or superseded");
                    return ProcessLockLoss::HeldElsewhere;
                }
                Err(()) => {
                    on_state_change(ProcessLockState::Suspended);
                    self.connection.take();
                    tracing::warn!(
                        "database process lock session ended; suspending admission and retaking the lock"
                    );
                }
            }

            let deadline =
                (tokio::time::Instant::now() + timing.reacquire_within).min(hard_deadline);
            loop {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return ProcessLockLoss::Unreachable;
                }
                let attempt_started = now;
                let attempt_timeout = timing
                    .check_interval
                    .min(deadline.saturating_duration_since(now));
                match tokio::time::timeout(
                    attempt_timeout,
                    Self::try_reacquire_owned(&self.options, ownership),
                )
                .await
                {
                    Ok(Ok(Some(retaken))) => {
                        self.connection = retaken.connection;
                        ownership.last_renew_started = attempt_started;
                        on_state_change(ProcessLockState::Active {
                            local_valid_until: ownership.local_valid_until(),
                        });
                        tracing::info!("database process lock retaken; resuming admission");
                        break;
                    }
                    Ok(Ok(None)) => {
                        return ProcessLockLoss::HeldElsewhere;
                    }
                    Ok(Err(_)) | Err(_) => {}
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return ProcessLockLoss::Unreachable;
                }
                tokio::time::sleep(
                    timing
                        .retry_interval
                        .min(deadline.saturating_duration_since(now)),
                )
                .await;
            }
        }
    }

    async fn try_reacquire_owned(
        options: &PgConnectOptions,
        ownership: &ProcessOwnership,
    ) -> Result<Option<ProcessLock>, sqlx::Error> {
        let Some(mut retaken) = Self::try_acquire(options).await? else {
            return Ok(None);
        };
        let Some(connection) = retaken.connection.as_mut() else {
            return Ok(None);
        };
        if renew_ownership_on(connection, ownership).await? {
            Ok(Some(retaken))
        } else {
            let _ = retaken.release().await;
            Ok(None)
        }
    }

    /// Clears any startup-claimed durable ownership row, then releases the advisory lock.
    pub async fn release_claimed(mut self) -> Result<(), sqlx::Error> {
        if let Some(ownership) = self.claimed.take() {
            return self.release_owned(&ownership).await;
        }
        self.release().await
    }

    /// Clears durable ownership on the lock session, then releases the advisory lock.
    pub async fn release_owned(mut self, ownership: &ProcessOwnership) -> Result<(), sqlx::Error> {
        self.claimed = None;
        if let Some(connection) = self.connection.as_mut() {
            release_ownership_on(connection, ownership).await?;
        }
        self.release().await
    }

    /// Releases the advisory lock and closes its session without clearing `process_ownership`.
    pub async fn release(mut self) -> Result<(), sqlx::Error> {
        let Some(mut connection) = self.connection.take() else {
            return Ok(());
        };
        let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
            .bind(PROCESS_ADVISORY_LOCK_KEY)
            .fetch_one(&mut connection)
            .await?;
        if !released {
            tracing::warn!(
                "database process lock was not held by its session at release; \
                 a transaction-mode pooler may sit between the server and PostgreSQL"
            );
        }
        connection.close().await
    }
}

/// Clears this process's durable ownership row through a pooled connection after a
/// clean lock-loss drain, letting a quarantined replacement take over immediately.
pub async fn release_process_ownership(
    pool: &PgPool,
    ownership: &ProcessOwnership,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE process_ownership \
         SET owner_id = NULL, \
             fenced = FALSE, \
             lease_expires_at = NULL, \
             updated_at = clock_timestamp() \
         WHERE id = 1 AND owner_id = $1 AND generation = $2",
    )
    .bind(ownership.owner_id)
    .bind(ownership.generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// Clears `process_ownership` for `owner_id` through a pooled connection when a
/// pre-serving shutdown raced with a committed unfenced claim whose lock connection closed.
pub async fn clear_process_owner_if_claimed(
    pool: &PgPool,
    owner_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE process_ownership \
         SET owner_id = NULL, \
             fenced = FALSE, \
             lease_expires_at = NULL, \
             updated_at = clock_timestamp() \
         WHERE id = 1 AND owner_id = $1 AND NOT fenced",
    )
    .bind(owner_id)
    .execute(pool)
    .await?;
    Ok(())
}

enum ClaimStep {
    Claimed(i64),
    Quarantined(Duration),
    LockNotHeld,
}

async fn claim_or_fence_step(
    connection: &mut PgConnection,
    owner_id: Uuid,
    lease_ttl: Duration,
) -> Result<ClaimStep, sqlx::Error> {
    let generation: Option<i64> = sqlx::query_scalar(
        "INSERT INTO process_ownership \
             (id, generation, owner_id, fenced, lease_expires_at, updated_at) \
         SELECT 1, 1, $1, FALSE, clock_timestamp() + make_interval(secs => $2), clock_timestamp() \
         WHERE EXISTS ( \
             SELECT 1 \
             FROM pg_locks \
             WHERE pid = pg_backend_pid() \
               AND locktype = 'advisory' \
               AND objsubid = 1 \
               AND granted \
               AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
               AND ((classid::bigint << 32) | objid::bigint) = $3 \
         ) \
         ON CONFLICT (id) DO UPDATE \
         SET generation = process_ownership.generation + 1, \
             owner_id = EXCLUDED.owner_id, \
             fenced = FALSE, \
             lease_expires_at = clock_timestamp() + make_interval(secs => $2), \
             updated_at = clock_timestamp() \
         WHERE process_ownership.owner_id IS NULL \
            OR process_ownership.lease_expires_at <= clock_timestamp() \
         RETURNING generation",
    )
    .bind(owner_id)
    .bind(lease_ttl.as_secs_f64())
    .bind(PROCESS_ADVISORY_LOCK_KEY)
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(generation) = generation {
        return Ok(ClaimStep::Claimed(generation));
    }

    // Handle a lost response after our own initial claim committed: renew
    // idempotently when unfenced, or fail closed if fenced meanwhile.
    let reclaimed_own: Option<i64> = sqlx::query_scalar(
        "UPDATE process_ownership \
         SET lease_expires_at = clock_timestamp() + make_interval(secs => $2), \
             updated_at = clock_timestamp() \
         WHERE id = 1 \
           AND owner_id = $1 \
           AND NOT fenced \
           AND EXISTS ( \
               SELECT 1 \
               FROM pg_locks \
               WHERE pid = pg_backend_pid() \
                 AND locktype = 'advisory' \
                 AND objsubid = 1 \
                 AND granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
                 AND ((classid::bigint << 32) | objid::bigint) = $3 \
           ) \
         RETURNING generation",
    )
    .bind(owner_id)
    .bind(lease_ttl.as_secs_f64())
    .bind(PROCESS_ADVISORY_LOCK_KEY)
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(generation) = reclaimed_own {
        return Ok(ClaimStep::Claimed(generation));
    }

    let own_fenced: Option<bool> =
        sqlx::query_scalar("SELECT fenced FROM process_ownership WHERE id = 1 AND owner_id = $1")
            .bind(owner_id)
            .fetch_optional(&mut *connection)
            .await?;
    if own_fenced == Some(true) {
        return Ok(ClaimStep::LockNotHeld);
    }

    let remaining_secs: Option<f64> = sqlx::query_scalar(
        "UPDATE process_ownership \
         SET fenced = TRUE, \
             updated_at = clock_timestamp() \
         WHERE id = 1 \
           AND owner_id IS NOT NULL \
           AND owner_id <> $1 \
           AND EXISTS ( \
               SELECT 1 \
               FROM pg_locks \
               WHERE pid = pg_backend_pid() \
                 AND locktype = 'advisory' \
                 AND objsubid = 1 \
                 AND granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
                 AND ((classid::bigint << 32) | objid::bigint) = $2 \
           ) \
         RETURNING EXTRACT(EPOCH FROM (lease_expires_at - clock_timestamp()))::double precision",
    )
    .bind(owner_id)
    .bind(PROCESS_ADVISORY_LOCK_KEY)
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(remaining_secs) = remaining_secs {
        let remaining = if remaining_secs > 0.0 && remaining_secs.is_finite() {
            Duration::from_secs_f64(remaining_secs)
        } else {
            Duration::ZERO
        };
        return Ok(ClaimStep::Quarantined(remaining));
    }

    if holds_advisory_lock(connection).await? {
        Ok(ClaimStep::Quarantined(Duration::ZERO))
    } else {
        Ok(ClaimStep::LockNotHeld)
    }
}

async fn holds_advisory_lock(connection: &mut PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 \
             FROM pg_locks \
             WHERE pid = pg_backend_pid() \
               AND locktype = 'advisory' \
               AND objsubid = 1 \
               AND granted \
               AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
               AND ((classid::bigint << 32) | objid::bigint) = $1 \
         )",
    )
    .bind(PROCESS_ADVISORY_LOCK_KEY)
    .fetch_one(connection)
    .await
}

async fn renew_ownership_on(
    connection: &mut PgConnection,
    ownership: &ProcessOwnership,
) -> Result<bool, sqlx::Error> {
    let renewed: Option<i64> = sqlx::query_scalar(
        "UPDATE process_ownership \
         SET lease_expires_at = clock_timestamp() + make_interval(secs => $3), \
             updated_at = clock_timestamp() \
         WHERE id = 1 \
           AND owner_id = $1 \
           AND generation = $2 \
           AND NOT fenced \
           AND EXISTS ( \
               SELECT 1 \
               FROM pg_locks \
               WHERE pid = pg_backend_pid() \
                 AND locktype = 'advisory' \
                 AND objsubid = 1 \
                 AND granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
                 AND ((classid::bigint << 32) | objid::bigint) = $4 \
           ) \
         RETURNING generation",
    )
    .bind(ownership.owner_id)
    .bind(ownership.generation)
    .bind(ownership.lease_ttl.as_secs_f64())
    .bind(PROCESS_ADVISORY_LOCK_KEY)
    .fetch_optional(connection)
    .await?;
    Ok(renewed.is_some())
}

async fn release_ownership_on(
    connection: &mut PgConnection,
    ownership: &ProcessOwnership,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE process_ownership \
         SET owner_id = NULL, \
             fenced = FALSE, \
             lease_expires_at = NULL, \
             updated_at = clock_timestamp() \
         WHERE id = 1 AND owner_id = $1 AND generation = $2",
    )
    .bind(ownership.owner_id)
    .bind(ownership.generation)
    .execute(connection)
    .await?;
    Ok(())
}
