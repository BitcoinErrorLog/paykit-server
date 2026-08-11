use std::{str::FromStr, sync::OnceLock, time::Duration};

use paykit_server::persistence::{MIGRATION_ADVISORY_LOCK_KEY, run_migrations};
use paykit_server_e2e::postgres::TestDatabase;
use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgConnectOptions};
use uuid::Uuid;

const REQUIRED_TABLES: [&str; 7] = [
    "deployment_metadata",
    "creators",
    "sdk_states",
    "reader_assignments",
    "invoices",
    "outbox",
    "bitcoin_observations",
];

/// PostgreSQL advisory locks are server-wide, not database-scoped. These
/// migration tests deliberately use the production migration lock key, so
/// they must not contend with one another when the test harness runs them in
/// parallel against independently-created databases.
fn migration_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[tokio::test]
async fn migrations_create_the_required_schema_and_are_restart_safe() {
    let _migration_test_guard = migration_test_lock().lock().await;
    let database = TestDatabase::create().await;
    let pool = database.pool();

    run_migrations(pool).await.unwrap();
    run_migrations(pool).await.unwrap();

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    )
    .fetch_all(pool)
    .await
    .unwrap();

    for table in REQUIRED_TABLES {
        assert!(tables.iter().any(|name| name == table), "missing {table}");
    }
    for retired_table in ["inbox_events", "peer_work_leases"] {
        assert!(
            !tables.iter().any(|name| name == retired_table),
            "retired table remains: {retired_table}"
        );
    }

    let applied_versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(applied_versions, vec![1, 2, 3]);

    let observation_lifecycle_columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT column_name, is_nullable
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'invoices'
           AND column_name IN ('first_amount_matched_observed_at', 'payment_expired_at')
         ORDER BY column_name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        observation_lifecycle_columns,
        vec![
            ("first_amount_matched_observed_at".into(), "YES".into()),
            ("payment_expired_at".into(), "YES".into()),
        ]
    );
    let lifecycle_constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname FROM pg_constraint
         WHERE conrelid = 'invoices'::regclass
           AND conname IN (
               'invoices_first_amount_matched_window_check',
               'invoices_payment_expired_deadline_check',
               'invoices_payment_lifecycle_terminal_check'
           )
         ORDER BY conname",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        lifecycle_constraints,
        vec![
            "invoices_first_amount_matched_window_check",
            "invoices_payment_expired_deadline_check",
            "invoices_payment_lifecycle_terminal_check",
        ]
    );

    let plaintext_creator_pubky_columns: Vec<String> = sqlx::query_scalar(
        "SELECT table_name \
         FROM information_schema.columns \
         WHERE table_schema = 'public' AND column_name = 'creator_pubky' \
         ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        plaintext_creator_pubky_columns.is_empty(),
        "raw creator Pubky columns must not be persisted: {plaintext_creator_pubky_columns:?}"
    );
    let forbidden_bitcoin_columns: Vec<String> = sqlx::query_scalar(
        "SELECT table_name || '.' || column_name
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND column_name IN
               ('derivation_index', 'bitcoin_address', 'required_sats', 'outpoint',
                'observed_sats', 'bound_outpoint_lookup_hash')
         ORDER BY table_name, column_name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        forbidden_bitcoin_columns.is_empty(),
        "plaintext Bitcoin columns remain: {forbidden_bitcoin_columns:?}"
    );
    let nullable_current_columns: Vec<String> = sqlx::query_scalar(
        "SELECT table_name || '.' || column_name
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND column_name IN
               ('payment_record_envelope', 'bitcoin_address_lookup_hash',
                'derivation_index_lookup_hash',
                'observation_envelope', 'outpoint_lookup_hash',
                'reader_lookup_hash', 'bundle_lookup_hash',
                'invoice_created_at', 'payment_deadline', 'payment_in_hours')
           AND is_nullable <> 'NO'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(nullable_current_columns.is_empty());

    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope) VALUES ($1, $2) RETURNING id",
    )
    .bind(b"creator-lookup".as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_ne!(creator_id, Uuid::nil());

    database.cleanup().await;
}

#[tokio::test]
async fn migrations_wait_for_the_postgresql_advisory_lock_without_cancelling_the_waiter() {
    let _migration_test_guard = migration_test_lock().lock().await;
    tokio::task::LocalSet::new()
        .run_until(async {
            let database = TestDatabase::create().await;
            let pool = database.pool().clone();
            let mut lock_connection = database.acquire_connection().await;

            sqlx::query("SELECT pg_advisory_lock($1)")
                .bind(MIGRATION_ADVISORY_LOCK_KEY)
                .execute(&mut *lock_connection)
                .await
                .unwrap();

            let migration_pool = pool.clone();
            let blocked_migration =
                tokio::task::spawn_local(async move { run_migrations(&migration_pool).await });
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                !blocked_migration.is_finished(),
                "migration unexpectedly completed while its advisory lock was held"
            );

            sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(MIGRATION_ADVISORY_LOCK_KEY)
                .execute(&mut *lock_connection)
                .await
                .unwrap();

            blocked_migration.await.unwrap().unwrap();
            run_migrations(&pool).await.unwrap();
            drop(lock_connection);
            database.cleanup().await;
        })
        .await;
}

#[tokio::test]
async fn cancelling_a_migration_after_it_acquires_the_advisory_lock_releases_the_session_lock() {
    let _migration_test_guard = migration_test_lock().lock().await;
    tokio::task::LocalSet::new()
        .run_until(async {
            let database = TestDatabase::create().await;
            let pool = database.pool().clone();
            let independent_options = PgConnectOptions::from_str(
                &std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set"),
            )
            .unwrap()
            .database(database.database_name());
            let mut independent_connection = PgConnection::connect_with(&independent_options)
                .await
                .unwrap();

            run_migrations(&pool).await.unwrap();
            sqlx::query("BEGIN")
                .execute(&mut independent_connection)
                .await
                .unwrap();
            sqlx::query("LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE")
                .execute(&mut independent_connection)
                .await
                .unwrap();

            let migration_pool = pool.clone();
            let migration =
                tokio::task::spawn_local(async move { run_migrations(&migration_pool).await });

            wait_until_advisory_lock_is_held(&mut independent_connection).await;
            migration.abort();
            assert!(migration.await.unwrap_err().is_cancelled());

            sqlx::query("ROLLBACK")
                .execute(&mut independent_connection)
                .await
                .unwrap();
            acquire_and_release_advisory_lock(&mut independent_connection).await;
            run_migrations(&pool).await.unwrap();

            independent_connection.close().await.unwrap();
            database.cleanup().await;
        })
        .await;
}

#[tokio::test]
async fn dropping_test_database_without_cleanup_drops_its_temporary_database() {
    let _migration_test_guard = migration_test_lock().lock().await;
    let database = TestDatabase::create().await;
    let database_name = database.database_name().to_owned();
    drop(database);

    let admin_options = PgConnectOptions::from_str(
        &std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set"),
    )
    .unwrap();
    let mut admin_connection = PgConnection::connect_with(&admin_options).await.unwrap();
    let database_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(&database_name)
            .fetch_one(&mut admin_connection)
            .await
            .unwrap();

    if database_exists {
        sqlx::query(&format!("DROP DATABASE {database_name}"))
            .execute(&mut admin_connection)
            .await
            .unwrap();
    }
    admin_connection.close().await.unwrap();
    assert!(
        !database_exists,
        "dropping TestDatabase without cleanup leaked {database_name}"
    );
}

#[tokio::test]
async fn failed_migrations_release_the_postgresql_advisory_lock() {
    let _migration_test_guard = migration_test_lock().lock().await;
    let database = TestDatabase::create().await;
    let pool = database.pool();
    run_migrations(pool).await.unwrap();

    let mut lock_connection = database.acquire_connection().await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 1")
        .bind(vec![0_u8; 32])
        .execute(pool)
        .await
        .unwrap();

    assert!(
        run_migrations(pool).await.is_err(),
        "corrupted migration unexpectedly succeeded"
    );

    let acquired_after_failure: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(MIGRATION_ADVISORY_LOCK_KEY)
        .fetch_one(&mut *lock_connection)
        .await
        .unwrap();
    assert!(
        acquired_after_failure,
        "failed migrations must release their advisory lock"
    );
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATION_ADVISORY_LOCK_KEY)
        .execute(&mut *lock_connection)
        .await
        .unwrap();

    drop(lock_connection);
    database.cleanup().await;
}

#[tokio::test]
async fn schema_uniqueness_constraints_reject_duplicate_lookup_keys() {
    let _migration_test_guard = migration_test_lock().lock().await;
    let database = TestDatabase::create().await;
    let pool = database.pool();
    run_migrations(pool).await.unwrap();
    let creator_id = insert_creator(pool).await;

    sqlx::query(
        "INSERT INTO reader_assignments \
         (creator_id, reader_lookup_hash, bundle_lookup_hash, assignment_envelope) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(creator_id)
    .bind(b"reader".as_slice())
    .bind(b"bundle".as_slice())
    .bind(b"encrypted-assignment".as_slice())
    .execute(pool)
    .await
    .unwrap();
    assert_unique_violation(
        sqlx::query(
            "INSERT INTO reader_assignments \
             (creator_id, reader_lookup_hash, bundle_lookup_hash, assignment_envelope) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(creator_id)
        .bind(b"reader".as_slice())
        .bind(b"bundle".as_slice())
        .bind(b"another-encrypted-assignment".as_slice())
        .execute(pool)
        .await,
    );

    insert_invoice(pool, creator_id, b"bundle-a", b"request-a").await;
    assert_unique_violation(
        insert_invoice_result(pool, creator_id, b"bundle-a", b"request-b").await,
    );
    assert_unique_violation(
        insert_invoice_result(pool, creator_id, b"bundle-b", b"request-a").await,
    );
    insert_invoice(pool, creator_id, b"bundle-identity", b"request-identity-a").await;
    assert_unique_violation(
        insert_invoice_result_with_reader(
            pool,
            creator_id,
            b"different-reader",
            b"bundle-identity",
            b"request-identity-b",
        )
        .await,
    );

    let first_derivation_hash: Vec<u8> = sqlx::query_scalar(
        "SELECT derivation_index_lookup_hash
         FROM invoices WHERE payment_request_lookup_hash = $1",
    )
    .bind(b"request-a".as_slice())
    .fetch_one(pool)
    .await
    .unwrap();
    insert_invoice(pool, creator_id, b"bundle-index", b"request-index").await;
    assert_unique_violation(
        sqlx::query(
            "UPDATE invoices SET derivation_index_lookup_hash = $1
             WHERE payment_request_lookup_hash = $2",
        )
        .bind(first_derivation_hash)
        .bind(b"request-index".as_slice())
        .execute(pool)
        .await,
    );

    insert_invoice(pool, creator_id, b"bundle-c", b"request-c").await;
    insert_invoice(pool, creator_id, b"bundle-d", b"request-d").await;
    let first_invoice: Uuid =
        sqlx::query_scalar("SELECT id FROM invoices WHERE payment_request_lookup_hash = $1")
            .bind(b"request-c".as_slice())
            .fetch_one(pool)
            .await
            .unwrap();
    let second_invoice: Uuid =
        sqlx::query_scalar("SELECT id FROM invoices WHERE payment_request_lookup_hash = $1")
            .bind(b"request-d".as_slice())
            .fetch_one(pool)
            .await
            .unwrap();
    let outpoint_hash = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO bitcoin_observations
         (invoice_id, observation_envelope, outpoint_lookup_hash, active,
          confirmations, present)
         VALUES ($1, $2, $3, TRUE, 0, TRUE)",
    )
    .bind(first_invoice)
    .bind(b"encrypted-observation-a".as_slice())
    .bind(outpoint_hash.as_bytes().as_slice())
    .execute(pool)
    .await
    .unwrap();
    assert_unique_violation(
        sqlx::query(
            "INSERT INTO bitcoin_observations
             (invoice_id, observation_envelope, outpoint_lookup_hash, active,
              confirmations, present)
             VALUES ($1, $2, $3, TRUE, 0, TRUE)",
        )
        .bind(second_invoice)
        .bind(b"encrypted-observation-b".as_slice())
        .bind(outpoint_hash.as_bytes().as_slice())
        .execute(pool)
        .await,
    );

    database.cleanup().await;
}

#[tokio::test]
async fn outbox_sdk_identifier_constraints_reject_unattributable_terminal_rows() {
    let _migration_test_guard = migration_test_lock().lock().await;
    let database = TestDatabase::create().await;
    let pool = database.pool();
    run_migrations(pool).await.unwrap();
    let creator_id = insert_creator(pool).await;

    assert_check_violation(
        sqlx::query(
            "INSERT INTO outbox (creator_id, intent_envelope, status)
             VALUES ($1, $2, 'handed_off')",
        )
        .bind(creator_id)
        .bind(b"encrypted-intent".as_slice())
        .execute(pool)
        .await,
    );
    assert_check_violation(
        sqlx::query(
            "INSERT INTO outbox
             (creator_id, intent_envelope, status, sdk_outbound_message_id)
             VALUES ($1, $2, 'delivered', '01')",
        )
        .bind(creator_id)
        .bind(b"encrypted-intent".as_slice())
        .execute(pool)
        .await,
    );
    assert_check_violation(
        sqlx::query(
            "INSERT INTO outbox
             (creator_id, intent_envelope, status, sdk_event_id)
             VALUES ($1, $2, 'queued', 'event-id')",
        )
        .bind(creator_id)
        .bind(b"encrypted-intent".as_slice())
        .execute(pool)
        .await,
    );

    database.cleanup().await;
}

#[tokio::test]
async fn enum_like_status_columns_allow_unexpected_text_for_read_time_validation() {
    let _migration_test_guard = migration_test_lock().lock().await;
    let database = TestDatabase::create().await;
    let pool = database.pool();
    run_migrations(pool).await.unwrap();
    let creator_id = insert_creator(pool).await;
    insert_invoice(pool, creator_id, b"bundle-a", b"request-a").await;

    sqlx::query("UPDATE invoices SET payment_status = $1 WHERE creator_id = $2")
        .bind("unexpected_corrupt_status")
        .bind(creator_id)
        .execute(pool)
        .await
        .unwrap();

    let status: String = sqlx::query("SELECT payment_status FROM invoices WHERE creator_id = $1")
        .bind(creator_id)
        .fetch_one(pool)
        .await
        .unwrap()
        .get("payment_status");
    assert_eq!(status, "unexpected_corrupt_status");

    database.cleanup().await;
}

async fn insert_creator(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope) VALUES ($1, $2) RETURNING id",
    )
    .bind(b"creator-a".as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn insert_invoice(pool: &PgPool, creator_id: Uuid, bundle_hash: &[u8], request_hash: &[u8]) {
    insert_invoice_result(pool, creator_id, bundle_hash, request_hash)
        .await
        .unwrap();
}

async fn insert_invoice_result(
    pool: &PgPool,
    creator_id: Uuid,
    bundle_hash: &[u8],
    request_hash: &[u8],
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    insert_invoice_result_with_reader(pool, creator_id, b"reader", bundle_hash, request_hash).await
}

async fn insert_invoice_result_with_reader(
    pool: &PgPool,
    creator_id: Uuid,
    reader_hash: &[u8],
    bundle_hash: &[u8],
    request_hash: &[u8],
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let address_hash = Uuid::new_v4();
    let derivation_index_hash = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices \
         (creator_id, reader_lookup_hash, bundle_lookup_hash, payment_request_lookup_hash, \
          invoice_envelope, payment_record_envelope, bitcoin_address_lookup_hash,
          derivation_index_lookup_hash, payment_status, invoice_created_at,
          payment_deadline, payment_in_hours) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 NOW(), NOW() + INTERVAL '1 hour', 1)",
    )
    .bind(creator_id)
    .bind(reader_hash)
    .bind(bundle_hash)
    .bind(request_hash)
    .bind(b"encrypted-invoice".as_slice())
    .bind(b"encrypted-payment-record".as_slice())
    .bind(address_hash.as_bytes().as_slice())
    .bind(derivation_index_hash.as_bytes().as_slice())
    .bind("undetected")
    .execute(pool)
    .await
}

fn assert_unique_violation(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>) {
    let error = result.expect_err("duplicate row unexpectedly succeeded");
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23505")
    );
}

fn assert_check_violation(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>) {
    let error = result.expect_err("expected a check-constraint violation");
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
}

async fn wait_until_advisory_lock_is_held(connection: &mut PgConnection) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(MIGRATION_ADVISORY_LOCK_KEY)
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            if !acquired {
                return;
            }
            sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(MIGRATION_ADVISORY_LOCK_KEY)
                .execute(&mut *connection)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("migration never acquired its advisory lock");
}

async fn acquire_and_release_advisory_lock(connection: &mut PgConnection) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(MIGRATION_ADVISORY_LOCK_KEY)
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            if acquired {
                sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(MIGRATION_ADVISORY_LOCK_KEY)
                    .execute(&mut *connection)
                    .await
                    .unwrap();
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("cancelled migration left the advisory lock held");
}
