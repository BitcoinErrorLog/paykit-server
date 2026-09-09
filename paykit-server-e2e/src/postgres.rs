//! Isolated PostgreSQL databases for E2E tests.

use std::{str::FromStr, thread, time::Duration};

use sqlx::{
    Connection, PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use url::Url;
use uuid::Uuid;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

fn isolated_database_url(database_url: &str, database_name: &str) -> String {
    let mut isolated_database_url =
        Url::parse(database_url).expect("TEST_DATABASE_URL must be a valid PostgreSQL URL");
    isolated_database_url.set_path(&format!("/{database_name}"));
    isolated_database_url.to_string()
}

/// A unique temporary PostgreSQL database created from `TEST_DATABASE_URL`.
pub struct TestDatabase {
    cleanup: Option<CleanupState>,
}

struct CleanupState {
    database_name: String,
    database_url: String,
    pool: PgPool,
    admin_options: PgConnectOptions,
}

impl TestDatabase {
    /// Creates a unique database under the PostgreSQL server named by `TEST_DATABASE_URL`.
    ///
    /// This reads the environment only; it never changes process environment state.
    pub async fn create() -> Self {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must name the PostgreSQL server for E2E tests");
        let admin_options = PgConnectOptions::from_str(&database_url)
            .expect("TEST_DATABASE_URL must be a valid PostgreSQL URL");
        let database_name = format!("paykit_e2e_{}", Uuid::new_v4().simple());

        let mut admin_connection = PgConnection::connect_with(&admin_options)
            .await
            .expect("connect to TEST_DATABASE_URL database to create isolated E2E database");
        sqlx::query(&format!("CREATE DATABASE {database_name}"))
            .execute(&mut admin_connection)
            .await
            .expect("create isolated E2E database");
        admin_connection
            .close()
            .await
            .expect("close E2E database administration connection");

        Self::connect_created(database_name, &database_url, admin_options).await
    }

    /// Creates a unique database whose DEFAULT collation is a non-C libc
    /// collation offered by this server, or `None` when the server offers
    /// none — callers then skip the collation-variant proof. Collation
    /// names come from the server's own `pg_collation` catalog; any name
    /// that cannot be safely interpolated is skipped.
    pub async fn create_with_non_c_collation() -> Option<Self> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must name the PostgreSQL server for E2E tests");
        let admin_options = PgConnectOptions::from_str(&database_url)
            .expect("TEST_DATABASE_URL must be a valid PostgreSQL URL");

        let mut admin_connection = PgConnection::connect_with(&admin_options)
            .await
            .expect("connect to TEST_DATABASE_URL database to create isolated E2E database");
        let collations: Vec<String> = sqlx::query_scalar(
            "SELECT collname FROM pg_collation
             WHERE collprovider = 'c' AND collname NOT IN ('C', 'POSIX')
             ORDER BY collname",
        )
        .fetch_all(&mut admin_connection)
        .await
        .ok()?;
        let database_name = format!("paykit_e2e_{}", Uuid::new_v4().simple());
        let mut created = false;
        for collation in collations.iter().filter(|name| !name.contains('\'')) {
            if sqlx::query(&format!(
                "CREATE DATABASE {database_name} TEMPLATE template0 LC_COLLATE '{collation}'"
            ))
            .execute(&mut admin_connection)
            .await
            .is_ok()
            {
                created = true;
                break;
            }
        }
        admin_connection.close().await.ok()?;
        if !created {
            return None;
        }
        Some(Self::connect_created(database_name, &database_url, admin_options).await)
    }

    async fn connect_created(
        database_name: String,
        database_url: &str,
        admin_options: PgConnectOptions,
    ) -> Self {
        let isolated_database_url = isolated_database_url(database_url, &database_name);
        let database_options = admin_options.clone().database(&database_name);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(database_options)
            .await
            .expect("connect to isolated E2E database");

        Self {
            cleanup: Some(CleanupState {
                database_name,
                database_url: isolated_database_url,
                pool,
                admin_options,
            }),
        }
    }

    /// Returns the isolated database name for administration assertions in E2E tests.
    pub fn database_name(&self) -> &str {
        &self.cleanup_state().database_name
    }

    /// Returns the isolated URL for startup composition tests.
    ///
    /// Callers must not format or log this secret-bearing value.
    pub fn database_url(&self) -> &str {
        &self.cleanup_state().database_url
    }

    /// Returns the isolated database pool.
    pub fn pool(&self) -> &PgPool {
        &self.cleanup_state().pool
    }

    /// Acquires a dedicated connection, useful for holding an advisory lock in a test.
    pub async fn acquire_connection(&self) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
        self.pool()
            .acquire()
            .await
            .expect("acquire isolated E2E database connection")
    }

    /// Closes pool connections and drops this temporary database.
    pub async fn cleanup(mut self) {
        self.take_cleanup_state()
            .cleanup()
            .await
            .expect("clean up isolated E2E database");
    }

    fn cleanup_state(&self) -> &CleanupState {
        self.cleanup
            .as_ref()
            .expect("TestDatabase has already been cleaned up")
    }

    fn take_cleanup_state(&mut self) -> CleanupState {
        self.cleanup
            .take()
            .expect("TestDatabase has already been cleaned up")
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let Some(cleanup) = self.cleanup.take() else {
            return;
        };

        let cleanup_thread = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("could not build TestDatabase cleanup runtime: {error}");
                    return;
                }
            };

            match runtime.block_on(async {
                tokio::time::timeout(CLEANUP_TIMEOUT, cleanup.cleanup_after_drop()).await
            }) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("could not clean up dropped TestDatabase: {error}"),
                Err(_) => eprintln!("timed out cleaning up dropped TestDatabase"),
            }
        });
        if cleanup_thread.join().is_err() {
            eprintln!("TestDatabase cleanup thread panicked");
        }
    }
}

impl CleanupState {
    async fn cleanup(self) -> Result<(), sqlx::Error> {
        let Self {
            database_name,
            database_url: _,
            pool,
            admin_options,
        } = self;
        pool.close().await;

        Self::drop_database(database_name, admin_options).await
    }

    /// Drop cleanup cannot await [`PgPool::close`]. `Drop` executes on the original
    /// Tokio runtime thread; waiting for a spawned cleanup thread while that thread
    /// waits for pool connection tasks deadlocks both runtimes. Releasing the pool
    /// handle and terminating its sessions from the admin connection is sufficient
    /// before the database is dropped.
    async fn cleanup_after_drop(self) -> Result<(), sqlx::Error> {
        let Self {
            database_name,
            database_url: _,
            pool,
            admin_options,
        } = self;
        drop(pool);
        Self::drop_database(database_name, admin_options).await
    }

    async fn drop_database(
        database_name: String,
        admin_options: PgConnectOptions,
    ) -> Result<(), sqlx::Error> {
        let mut admin_connection = PgConnection::connect_with(&admin_options).await?;
        sqlx::query(
            "SELECT pg_terminate_backend(pid) \
             FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(&database_name)
        .execute(&mut admin_connection)
        .await?;
        sqlx::query(&format!("DROP DATABASE {database_name}"))
            .execute(&mut admin_connection)
            .await?;
        admin_connection.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::isolated_database_url;
    use url::Url;

    #[test]
    fn isolated_url_preserves_authentication_and_options_while_replacing_database() {
        let isolated = isolated_database_url(
            "postgres://paykit:s3cr3t@localhost/original?sslmode=require",
            "paykit_e2e_test",
        );
        let parsed = Url::parse(&isolated).unwrap();

        assert_eq!(parsed.username(), "paykit");
        assert_eq!(parsed.password(), Some("s3cr3t"));
        assert_eq!(parsed.path(), "/paykit_e2e_test");
        assert_eq!(parsed.query(), Some("sslmode=require"));
        assert!(!isolated.contains("***"));
    }
}
