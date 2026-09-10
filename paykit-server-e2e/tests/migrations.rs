use std::{
    str::FromStr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use paykit_server::{
    crypto::Crypto,
    persistence::{InvoiceStore, MIGRATION_ADVISORY_LOCK_KEY, run_migrations},
};
use paykit_server_e2e::postgres::TestDatabase;
use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgConnectOptions};
use uuid::Uuid;

const REQUIRED_TABLES: [&str; 11] = [
    "deployment_metadata",
    "creators",
    "sdk_states",
    "reader_assignments",
    "invoices",
    "outbox",
    "bitcoin_observations",
    "invoice_baseline_outpoints",
    "bitcoin_observation_candidates",
    "stack_identity",
    "claimed_key_fingerprints",
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
    assert_eq!(
        applied_versions,
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );

    let retired_observation_budget_columns: Vec<String> = sqlx::query_scalar(
        "SELECT table_name || '.' || column_name
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND column_name IN
               ('observation_history_tx_count', 'observation_request_count',
                'observation_overrun')
         ORDER BY table_name, column_name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        retired_observation_budget_columns.is_empty(),
        "retired observation budget columns remain: {retired_observation_budget_columns:?}"
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
                'reader_lookup_hash', 'bundle_lookup_hash')
           AND is_nullable <> 'NO'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(nullable_current_columns.is_empty());

    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope, first_child_index) VALUES ($1, $2, 0) RETURNING id",
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
async fn legacy_invoice_is_never_defaulted_into_observation() {
    let _migration_test_guard = migration_test_lock().lock().await;
    let database = TestDatabase::create().await;
    let pool = database.pool();
    for migration in [
        include_str!("../../paykit-server/migrations/0001_initial.sql"),
        include_str!("../../paykit-server/migrations/0002_deployment_stack_role.sql"),
        include_str!("../../paykit-server/migrations/0003_invoice_observation_budget.sql"),
        include_str!("../../paykit-server/migrations/0004_observation_request_count.sql"),
        include_str!("../../paykit-server/migrations/0005_observation_overrun.sql"),
        include_str!("../../paykit-server/migrations/0006_drop_observation_budget_columns.sql"),
    ] {
        sqlx::raw_sql(migration).execute(pool).await.unwrap();
    }
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(b"legacy-creator".as_slice())
    .bind(b"legacy-credential".as_slice())
    .fetch_one(pool)
    .await
    .unwrap();
    let invoice_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices
         (id, creator_id, reader_lookup_hash, bundle_lookup_hash,
          payment_request_lookup_hash, invoice_envelope, payment_record_envelope,
          bitcoin_address_lookup_hash, derivation_index_lookup_hash, payment_status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'undetected')",
    )
    .bind(invoice_id)
    .bind(creator_id)
    .bind(b"legacy-reader".as_slice())
    .bind(b"legacy-bundle".as_slice())
    .bind(b"legacy-payment".as_slice())
    .bind(b"legacy-invoice-envelope".as_slice())
    .bind(b"legacy-v1-payment-record".as_slice())
    .bind(b"legacy-address".as_slice())
    .bind(b"legacy-index".as_slice())
    .execute(pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../paykit-server/migrations/0007_invoice_observation_attempts.sql"
    ))
    .execute(pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../paykit-server/migrations/0008_invoice_creation_baseline.sql"
    ))
    .execute(pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../../paykit-server/migrations/0009_observation_failure_isolation.sql"
    ))
    .execute(pool)
    .await
    .unwrap();

    let state: String = sqlx::query_scalar("SELECT baseline_state FROM invoices WHERE id = $1")
        .bind(invoice_id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(state, "legacy_unbaselined");
    let store = InvoiceStore::new(pool, Arc::new(Crypto::from_master_key(&[7; 32]).unwrap()));
    assert!(store.observation_plan().await.unwrap().is_empty());
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

/// Migration 0014 (two-phase activation, §B.11): the `baseline_state` CHECK
/// is total over the §B.11.1 table, the new columns exist, the outbox status
/// CHECK admits `prepared`, and the baseline-outpoint kind CHECK admits
/// `pre_existing` — each verified by acceptance AND by rejection of an
/// unknown value.
#[tokio::test]
async fn two_phase_activation_migration_applies_and_constrains_states() {
    let _migration_test_guard = migration_test_lock().lock().await;
    let database = TestDatabase::create().await;
    let pool = database.pool();
    run_migrations(pool).await.unwrap();
    let creator_id = insert_creator(pool).await;
    insert_invoice(pool, creator_id, b"bundle-2p", b"request-2p").await;

    // Every state in the §B.11.1 table (plus the two pre-existing live
    // values) is admitted; an unknown state is rejected. The 0015
    // resolution CHECKs tie the resolved states to their resolution
    // columns, so those two rows set the pair and every other state
    // clears it.
    for state in [
        "legacy_unbaselined",
        "awaiting_baseline",
        "prepared",
        "observing",
        "expired_tail",
        "expired_final",
        "void_baseline_failed",
        "void_prepare_expired",
        "void_cancelled",
        "resolved_paid_manually",
        "resolved_closed",
        "manual_review",
    ] {
        match state {
            "resolved_paid_manually" => sqlx::query(
                "UPDATE invoices SET baseline_state = $1, resolution = 'paid_manually',
                 resolved_at = NOW() WHERE creator_id = $2",
            ),
            "resolved_closed" => sqlx::query(
                "UPDATE invoices SET baseline_state = $1, resolution = 'refunded',
                 resolved_at = NOW() WHERE creator_id = $2",
            ),
            _ => sqlx::query(
                "UPDATE invoices SET baseline_state = $1, resolution = NULL,
                 resolved_at = NULL WHERE creator_id = $2",
            ),
        }
        .bind(state)
        .bind(creator_id)
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("baseline_state {state} rejected: {error}"));
    }
    assert_check_violation(
        sqlx::query("UPDATE invoices SET baseline_state = 'mystery' WHERE creator_id = $1")
            .bind(creator_id)
            .execute(pool)
            .await,
    );

    // The new columns exist and accept timestamps.
    sqlx::query(
        "UPDATE invoices SET expires_at = NOW(), prepare_expires_at = NOW(), activated_at = NOW()
         WHERE creator_id = $1",
    )
    .bind(creator_id)
    .execute(pool)
    .await
    .unwrap();

    // The outbox status CHECK admits the full closed set including
    // 'prepared', and rejects anything else.
    for status in [
        "prepared",
        "queued",
        "leased",
        "retryable",
        "handed_off",
        "delivered",
        "permanently_failed",
    ] {
        let mut insert = sqlx::query(
            "INSERT INTO outbox (creator_id, intent_envelope, status, sdk_outbound_message_id)
             VALUES ($1, $2, $3, $4)",
        );
        insert = insert
            .bind(creator_id)
            .bind(b"encrypted-intent".as_slice())
            .bind(status);
        // Terminal attributable states require an outbound id (0001's
        // attributable-terminal CHECK); non-terminal states forbid nothing.
        let result = if matches!(status, "handed_off" | "delivered") {
            insert.bind(Some("7")).execute(pool).await
        } else {
            insert.bind(None::<&str>).execute(pool).await
        };
        result.unwrap_or_else(|error| panic!("outbox status {status} rejected: {error}"));
    }
    assert_check_violation(
        sqlx::query(
            "INSERT INTO outbox (creator_id, intent_envelope, status)
             VALUES ($1, $2, 'mystery')",
        )
        .bind(creator_id)
        .bind(b"encrypted-intent".as_slice())
        .execute(pool)
        .await,
    );

    // The baseline-outpoint kind CHECK admits 'pre_existing' (§B.4.6) and
    // rejects an unknown kind.
    let invoice_id: Uuid =
        sqlx::query_scalar("SELECT id FROM invoices WHERE creator_id = $1 LIMIT 1")
            .bind(creator_id)
            .fetch_one(pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO invoice_baseline_outpoints (invoice_id, txid, vout, kind)
         VALUES ($1, $2, 0, 'pre_existing')",
    )
    .bind(invoice_id)
    .bind("ab".repeat(32))
    .execute(pool)
    .await
    .unwrap();
    assert_check_violation(
        sqlx::query(
            "INSERT INTO invoice_baseline_outpoints (invoice_id, txid, vout, kind)
             VALUES ($1, $2, 1, 'mystery')",
        )
        .bind(invoice_id)
        .bind("ab".repeat(32))
        .execute(pool)
        .await,
    );

    database.cleanup().await;
}

/// Migration 0015 (§B.9 expiry/resolve): legacy NULL `expires_at` rows are
/// backfilled to `created_at + 24 hours` and the column closes to NOT NULL;
/// the resolution CHECKs reject every invalid combination (23514);
/// `bitcoin_observations.late_settlement` defaults false.
#[tokio::test]
async fn payment_request_expiry_migration_backfills_and_constrains() {
    let _migration_test_guard = migration_test_lock().lock().await;
    let database = TestDatabase::create().await;
    let pool = database.pool();
    for migration in [
        include_str!("../../paykit-server/migrations/0001_initial.sql"),
        include_str!("../../paykit-server/migrations/0002_deployment_stack_role.sql"),
        include_str!("../../paykit-server/migrations/0003_invoice_observation_budget.sql"),
        include_str!("../../paykit-server/migrations/0004_observation_request_count.sql"),
        include_str!("../../paykit-server/migrations/0005_observation_overrun.sql"),
        include_str!("../../paykit-server/migrations/0006_drop_observation_budget_columns.sql"),
        include_str!("../../paykit-server/migrations/0007_invoice_observation_attempts.sql"),
        include_str!("../../paykit-server/migrations/0008_invoice_creation_baseline.sql"),
        include_str!("../../paykit-server/migrations/0009_observation_failure_isolation.sql"),
        include_str!("../../paykit-server/migrations/0010_invoice_amount_nonce.sql"),
        include_str!("../../paykit-server/migrations/0011_stack_identity.sql"),
        include_str!("../../paykit-server/migrations/0012_claimed_key_fingerprints.sql"),
        include_str!("../../paykit-server/migrations/0013_creator_allocation_mode.sql"),
        include_str!("../../paykit-server/migrations/0014_two_phase_activation.sql"),
    ] {
        sqlx::raw_sql(migration).execute(pool).await.unwrap();
    }
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope, first_child_index)
         VALUES ($1, $2, 0) RETURNING id",
    )
    .bind(b"expiry-legacy-creator".as_slice())
    .bind(b"expiry-legacy-credential".as_slice())
    .fetch_one(pool)
    .await
    .unwrap();
    // Legacy rows as the Locks /invoices path wrote them between 0014 and
    // 0015: `expires_at` NULL. One `observing`, one `prepared`, plus one
    // row that already carries an expiry and must be left untouched.
    let insert_legacy = |state: &str, expires: bool| {
        let pool = pool.clone();
        let state = state.to_owned();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO invoices
                 (creator_id, reader_lookup_hash, bundle_lookup_hash,
                  payment_request_lookup_hash, invoice_envelope, payment_record_envelope,
                  bitcoin_address_lookup_hash, derivation_index_lookup_hash, payment_status,
                  baseline_state, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'undetected', $9,
                         CASE WHEN $10 THEN NOW() + INTERVAL '3 hours' ELSE NULL END)
                 RETURNING id",
            )
            .bind(creator_id)
            .bind(format!("legacy-reader-{state}").into_bytes())
            .bind(format!("legacy-bundle-{state}-{expires}").into_bytes())
            .bind(format!("legacy-request-{state}-{expires}").into_bytes())
            .bind(b"legacy-invoice".as_slice())
            .bind(b"legacy-payment-record".as_slice())
            .bind(Uuid::new_v4().as_bytes().as_slice())
            .bind(Uuid::new_v4().as_bytes().as_slice())
            .bind(state)
            .bind(expires)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let observing = insert_legacy("observing", false).await;
    let prepared = insert_legacy("prepared", false).await;
    let already_set = insert_legacy("observing", true).await;
    let nilled: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE expires_at IS NULL")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(nilled, 2, "two legacy NULL-expiry rows staged");

    sqlx::raw_sql(include_str!(
        "../../paykit-server/migrations/0015_payment_request_expiry.sql"
    ))
    .execute(pool)
    .await
    .unwrap();

    // The backfill count this migration saw: exactly the two staged NULL
    // rows, each now `created_at + 24 hours`; the pre-set row is untouched.
    let backfilled: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invoices
         WHERE expires_at = created_at + INTERVAL '24 hours'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(backfilled, 2, "legacy backfill count seen by 0015");
    let untouched: bool = sqlx::query_scalar(
        "SELECT expires_at <> created_at + INTERVAL '24 hours' FROM invoices WHERE id = $1",
    )
    .bind(already_set)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(untouched, "a pre-set expires_at must survive the backfill");
    for id in [observing, prepared] {
        let state: String = sqlx::query_scalar(
            "SELECT baseline_state FROM invoices WHERE id = $1 AND expires_at IS NOT NULL",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(!state.is_empty());
    }
    // NOT NULL is closed.
    let not_null_error = sqlx::query(
        "INSERT INTO invoices
         (creator_id, reader_lookup_hash, bundle_lookup_hash,
          payment_request_lookup_hash, invoice_envelope, payment_record_envelope,
          bitcoin_address_lookup_hash, derivation_index_lookup_hash, payment_status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'undetected')",
    )
    .bind(creator_id)
    .bind(b"null-expiry-reader".as_slice())
    .bind(b"null-expiry-bundle".as_slice())
    .bind(b"null-expiry-request".as_slice())
    .bind(b"legacy-invoice".as_slice())
    .bind(b"legacy-payment-record".as_slice())
    .bind(Uuid::new_v4().as_bytes().as_slice())
    .bind(Uuid::new_v4().as_bytes().as_slice())
    .execute(pool)
    .await
    .expect_err("an INSERT without expires_at must violate NOT NULL");
    assert_eq!(
        not_null_error
            .as_database_error()
            .unwrap()
            .code()
            .as_deref(),
        Some("23502")
    );

    // Every invalid resolution combination is a CHECK violation (23514).
    for (resolution, resolved_at, state) in [
        // Unknown resolution text.
        (Some("'bogus'"), Some("NOW()"), "observing"),
        // The pair must be both-NULL or both-set.
        (Some("'paid_manually'"), None, "observing"),
        (None, Some("NOW()"), "observing"),
        // The resolved states require their matching resolution.
        (Some("'refunded'"), Some("NOW()"), "resolved_paid_manually"),
        (Some("'paid_manually'"), Some("NOW()"), "resolved_closed"),
        (None, None, "resolved_paid_manually"),
        (None, None, "resolved_closed"),
    ] {
        let statement = format!(
            "UPDATE invoices SET baseline_state = '{state}',
             resolution = {}, resolved_at = {} WHERE id = $1",
            resolution.unwrap_or("NULL"),
            resolved_at.unwrap_or("NULL"),
        );
        assert_check_violation(sqlx::query(&statement).bind(observing).execute(pool).await);
    }
    // The valid combinations are admitted: metadata-only on expired_final
    // and the two resolved states with their matching resolutions.
    for (resolution, state) in [
        ("'paid_manually'", "expired_final"),
        ("'paid_manually'", "resolved_paid_manually"),
        ("'refunded'", "resolved_closed"),
        ("'abandoned'", "resolved_closed"),
    ] {
        sqlx::query(&format!(
            "UPDATE invoices SET baseline_state = '{state}',
             resolution = {resolution}, resolved_at = NOW() WHERE id = $1"
        ))
        .bind(observing)
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("{state}/{resolution} rejected: {error}"));
        sqlx::query(
            "UPDATE invoices SET baseline_state = 'observing',
             resolution = NULL, resolved_at = NULL WHERE id = $1",
        )
        .bind(observing)
        .execute(pool)
        .await
        .unwrap();
    }

    // `late_settlement` defaults false on observation rows.
    sqlx::query(
        "INSERT INTO bitcoin_observations
         (invoice_id, observation_envelope, outpoint_lookup_hash, active,
          confirmations, present)
         VALUES ($1, $2, $3, TRUE, 0, TRUE)",
    )
    .bind(observing)
    .bind(b"legacy-observation".as_slice())
    .bind(Uuid::new_v4().as_bytes().as_slice())
    .execute(pool)
    .await
    .unwrap();
    let late: bool = sqlx::query_scalar(
        "SELECT late_settlement FROM bitcoin_observations WHERE invoice_id = $1",
    )
    .bind(observing)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(!late, "late_settlement must default false");

    database.cleanup().await;
}

async fn insert_creator(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope, first_child_index) VALUES ($1, $2, 0) RETURNING id",
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
          derivation_index_lookup_hash, payment_status, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW() + INTERVAL '1 hour')",
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
