use std::time::Duration;

use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment, StackRole},
    persistence::{DeploymentStore, PersistenceError, run_migrations},
    startup::{StartupError, initialize_database},
};
use paykit_server_e2e::postgres::TestDatabase;
use sqlx::postgres::PgPoolOptions;
use url::Url;

const KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn config(database_url: &str, network: &str, stack_role: &str) -> Config {
    config_with_principals(database_url, database_url, network, stack_role)
}

fn config_with_principals(
    runtime_database_url: &str,
    migrator_database_url: &str,
    network: &str,
    stack_role: &str,
) -> Config {
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:0"
[locks]
trusted_public_key = "{KEY}"
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "paykit-server"
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
network = "{network}"
[deployment]
stack_role = "{stack_role}"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "5s"
"#
        ),
        ConfigEnvironment {
            database_url: Some(runtime_database_url.to_owned()),
            migrator_database_url: Some(migrator_database_url.to_owned()),
            master_key: Some(MASTER_KEY.to_owned()),
            ..Default::default()
        },
    )
    .expect("valid config fixture")
}

fn database_url_for_role(database_url: &str, role: &str, password: &str) -> String {
    let mut url = Url::parse(database_url).expect("isolated database URL parses");
    url.set_username(role).expect("generated role is URL-safe");
    url.set_password(Some(password))
        .expect("generated role password is URL-safe");
    url.to_string()
}

fn login_role_password() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

#[tokio::test]
async fn booting_with_a_mismatched_network_or_role_fails_before_binding() {
    let database = TestDatabase::create().await;
    paykit_server::persistence::run_migrations(database.pool())
        .await
        .unwrap();
    initialize_database(&config(database.database_url(), "mainnet", "proof"))
        .await
        .unwrap();

    // Same role, different network: refused on the network invariant.
    let error = initialize_database(&config(database.database_url(), "regtest", "proof"))
        .await
        .unwrap_err();
    assert_eq!(error, StartupError::Deployment);
    // Same network, different role: refused on the stack_role invariant.
    let error = initialize_database(&config(database.database_url(), "mainnet", "production"))
        .await
        .unwrap_err();
    assert_eq!(error, StartupError::Deployment);

    database.cleanup().await;
}

#[tokio::test]
async fn booting_a_production_role_against_a_proof_database_fails_before_binding() {
    let database = TestDatabase::create().await;
    paykit_server::persistence::run_migrations(database.pool())
        .await
        .unwrap();
    initialize_database(&config(database.database_url(), "mainnet", "proof"))
        .await
        .unwrap();

    let error = initialize_database(&config(database.database_url(), "mainnet", "production"))
        .await
        .unwrap_err();
    assert_eq!(error, StartupError::Deployment);

    database.cleanup().await;
}

#[tokio::test]
async fn an_unset_stored_role_is_adopted_once_and_then_enforced() {
    let database = TestDatabase::create().await;
    let configured = config(database.database_url(), "mainnet", "proof");
    // Simulate a deployment row written before the stack-role migration: the
    // invariants are present but stack_role is still NULL.
    paykit_server::persistence::run_migrations(database.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO deployment_metadata \
         (id, bitcoin_network, receiver_path, locks_key_fingerprint) \
         VALUES (1, $1, $2, $3)",
    )
    .bind(configured.deployment_invariants().bitcoin_network.as_str())
    .bind(configured.deployment_invariants().receiver_path.as_str())
    .bind(
        configured
            .deployment_invariants()
            .trusted_locks_key_fingerprint
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();

    initialize_database(&configured).await.unwrap();
    let adopted: Option<String> =
        sqlx::query_scalar("SELECT stack_role FROM deployment_metadata WHERE id = 1")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(adopted.as_deref(), Some("proof"));

    let error = initialize_database(&config(database.database_url(), "mainnet", "production"))
        .await
        .unwrap_err();
    assert_eq!(error, StartupError::Deployment);
    initialize_database(&configured).await.unwrap();

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_first_boots_on_an_unset_role_adopt_exactly_once() {
    let database = TestDatabase::create().await;
    // A pre-role deployment row: invariants present, stack_role still NULL.
    let configured = config(database.database_url(), "mainnet", "proof");
    paykit_server::persistence::run_migrations(database.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO deployment_metadata \
         (id, bitcoin_network, receiver_path, locks_key_fingerprint) \
         VALUES (1, $1, $2, $3)",
    )
    .bind(configured.deployment_invariants().bitcoin_network.as_str())
    .bind(configured.deployment_invariants().receiver_path.as_str())
    .bind(
        configured
            .deployment_invariants()
            .trusted_locks_key_fingerprint
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();

    // Two first boots race to adopt the NULL row with different roles. The
    // winner holds the deployment row lock through the test hook while the
    // loser attempts adoption: the loser must block on the row lock until
    // the winner commits, then observe the adopted role and refuse.
    let proof_invariants = config(database.database_url(), "mainnet", "proof")
        .deployment_invariants()
        .clone();
    let production_invariants = config(database.database_url(), "mainnet", "production")
        .deployment_invariants()
        .clone();
    let (lock_held, held) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let winner_store = DeploymentStore::new(database.pool());
    let winner = tokio::spawn(async move {
        winner_store
            .initialize_holding_lock_for_test(&proof_invariants, lock_held, released)
            .await
    });
    held.await.expect("the winner signals its held row lock");

    let loser_store = DeploymentStore::new(database.pool());
    let mut loser =
        tokio::spawn(async move { loser_store.initialize(&production_invariants).await });

    // The loser must reach the row lock and stay blocked on it: it cannot
    // complete while the winner holds FOR UPDATE.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let lock_waits: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity \
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(database.pool())
            .await
            .unwrap();
            if lock_waits > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the losing adopter must block on the deployment row lock");
    tokio::select! {
        result = &mut loser => {
            panic!("loser completed while the winner held the deployment row lock: {result:?}")
        }
        _ = tokio::time::sleep(Duration::from_millis(200)) => {}
    }

    release.send(()).expect("release the winner's lock barrier");
    winner
        .await
        .expect("winner task joins")
        .expect("the winner adopts the role");
    assert_eq!(
        loser.await.expect("loser task joins"),
        Err(PersistenceError::DeploymentMismatch),
        "the loser must observe the winner's committed role and refuse"
    );
    let adopted: String =
        sqlx::query_scalar("SELECT stack_role FROM deployment_metadata WHERE id = 1")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(adopted, "proof", "exactly one concurrent boot adopts");

    // Two boots that agree with the adopted role both succeed.
    let first_config = config(database.database_url(), "mainnet", &adopted);
    let second_config = config(database.database_url(), "mainnet", &adopted);
    let first = initialize_database(&first_config);
    let second = initialize_database(&second_config);
    let (first, second) = tokio::join!(first, second);
    first.unwrap();
    second.unwrap();

    database.cleanup().await;
}

#[tokio::test]
async fn stack_identity_is_minted_once_and_byte_identical_across_reboots() {
    let database = TestDatabase::create().await;
    paykit_server::persistence::run_migrations(database.pool())
        .await
        .unwrap();
    let configured = config(database.database_url(), "testnet", "proof");

    // The first boot mints the single-row identity inside the
    // deployment-adoption transaction.
    let first = initialize_database(&configured).await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stack_identity")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1, "exactly one identity row exists after first boot");
    let stored: uuid::Uuid =
        sqlx::query_scalar("SELECT instance_uuid FROM stack_identity WHERE singleton = TRUE")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(stored, first.stack_identity.instance_uuid());

    // A second boot against the same database reads the same row back: the
    // stack_id is byte-identical across restarts and never rewritten.
    let second = initialize_database(&configured).await.unwrap();
    assert_eq!(first.stack_identity, second.stack_identity);
    assert_eq!(
        first.stack_identity.stack_id(),
        second.stack_identity.stack_id()
    );
    let rows_after_reboot: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stack_identity")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        rows_after_reboot, 1,
        "the identity row was never rewritten or duplicated"
    );

    // The role component equals the configured stack_role.
    assert_eq!(first.stack_identity.role(), StackRole::Proof);
    assert!(
        first.stack_identity.stack_id().starts_with("proof:"),
        "stack_id is {{stack_role}}:{{instance_uuid}}: {}",
        first.stack_identity.stack_id()
    );

    database.cleanup().await;
}

#[tokio::test]
async fn two_databases_migrated_from_the_same_binary_get_different_stack_ids() {
    let first_database = TestDatabase::create().await;
    let second_database = TestDatabase::create().await;
    paykit_server::persistence::run_migrations(first_database.pool())
        .await
        .unwrap();
    paykit_server::persistence::run_migrations(second_database.pool())
        .await
        .unwrap();

    let first = initialize_database(&config(first_database.database_url(), "testnet", "proof"))
        .await
        .unwrap();
    let second = initialize_database(&config(second_database.database_url(), "testnet", "proof"))
        .await
        .unwrap();

    // The same-role/wrong-instance case: two proof stacks share a role but
    // never a stack_id, because each database mints its own instance UUID.
    assert_eq!(first.stack_identity.role(), second.stack_identity.role());
    assert_ne!(
        first.stack_identity.instance_uuid(),
        second.stack_identity.instance_uuid()
    );
    assert_ne!(
        first.stack_identity.stack_id(),
        second.stack_identity.stack_id()
    );

    first_database.cleanup().await;
    second_database.cleanup().await;
}

#[tokio::test]
async fn startup_applies_as_migrator_then_boots_with_a_restricted_runtime_principal() {
    let admin_url =
        std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL names the test server");
    let admin_pool = PgPoolOptions::new().connect(&admin_url).await.unwrap();
    let database = TestDatabase::create().await;
    let migrator_role = format!("paykit_migrator_{}", uuid::Uuid::new_v4().simple());
    let runtime_role = format!("paykit_runtime_{}", uuid::Uuid::new_v4().simple());
    let migrator_password = login_role_password();
    let runtime_password = login_role_password();

    // CI Postgres uses scram-sha-256 over TCP. LOGIN roles with no password
    // cannot authenticate there, so initialize_database reported Connection
    // instead of the missing-grant Deployment failure this test asserts.
    sqlx::query(&format!(
        "CREATE ROLE {migrator_role} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE \
         NOREPLICATION NOBYPASSRLS PASSWORD '{migrator_password}'"
    ))
    .execute(&admin_pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE ROLE {runtime_role} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE \
         NOREPLICATION NOBYPASSRLS PASSWORD '{runtime_password}'"
    ))
    .execute(&admin_pool)
    .await
    .unwrap();
    sqlx::query(&format!("GRANT paykit TO {runtime_role}"))
        .execute(&admin_pool)
        .await
        .unwrap();
    sqlx::query(&format!(
        "GRANT CONNECT, TEMPORARY, CREATE ON DATABASE {} TO {migrator_role}",
        database.database_name()
    ))
    .execute(&admin_pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "GRANT CONNECT ON DATABASE {} TO {runtime_role}",
        database.database_name()
    ))
    .execute(&admin_pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "GRANT USAGE, CREATE ON SCHEMA public TO {migrator_role}"
    ))
    .execute(database.pool())
    .await
    .unwrap();

    let migrator_url =
        database_url_for_role(database.database_url(), &migrator_role, &migrator_password);
    let runtime_url =
        database_url_for_role(database.database_url(), &runtime_role, &runtime_password);
    let configured = config_with_principals(&runtime_url, &migrator_url, "testnet", "proof");

    // Exercise the real startup path against the fresh database. All embedded
    // migrations run as the owner before runtime verification; startup then
    // fails closed because the provisioner has not installed the baseline
    // runtime table grants yet.
    let error = initialize_database(&configured).await.unwrap_err();
    assert_eq!(error, StartupError::Deployment);

    let migrator_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&migrator_url)
        .await
        .unwrap();
    let applied: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&migrator_pool)
            .await
            .unwrap();
    assert_eq!(applied, (1..=26).collect::<Vec<_>>());
    let owned_objects: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner \
         WHERE c.relnamespace = 'public'::regnamespace AND r.rolname = current_user",
    )
    .fetch_one(&migrator_pool)
    .await
    .unwrap();
    assert!(
        owned_objects > 0,
        "the migrator must own the schema objects it creates"
    );

    // The deployment provisioner owns baseline runtime grants. Migrations 0024
    // and 0025 add only their narrowly scoped runtime grants to stable roles.
    sqlx::query(&format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE \
         deployment_metadata, creators, sdk_states, reader_assignments, invoices, outbox, \
         bitcoin_observations, invoice_baseline_outpoints, bitcoin_observation_candidates, \
         stack_identity, claimed_key_fingerprints, sentinel_outpoints, sentinel_events, \
         outbox_terminal_events TO {runtime_role}"
    ))
    .execute(&migrator_pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {runtime_role}"
    ))
    .execute(&migrator_pool)
    .await
    .unwrap();
    migrator_pool.close().await;

    let initialized = initialize_database(&configured).await.unwrap();
    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&initialized.pool)
        .await
        .unwrap();
    assert_eq!(current_user, runtime_role);

    let runtime_owns_objects: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner \
         WHERE c.relnamespace = 'public'::regnamespace AND r.rolname = current_user)",
    )
    .fetch_one(&initialized.pool)
    .await
    .unwrap();
    assert!(
        !runtime_owns_objects,
        "runtime principal unexpectedly owns a schema object"
    );
    assert!(
        sqlx::query("CREATE TABLE runtime_must_not_own_schema (id INTEGER)")
            .execute(&initialized.pool)
            .await
            .is_err(),
        "runtime principal unexpectedly executed DDL"
    );
    assert!(
        run_migrations(&initialized.pool).await.is_err(),
        "runtime principal unexpectedly executed the migration runner"
    );
    assert!(
        sqlx::query("UPDATE _sqlx_migrations SET success = FALSE WHERE version = 24")
            .execute(&initialized.pool)
            .await
            .is_err(),
        "runtime principal unexpectedly wrote the migration ledger"
    );

    let server = Server::build(
        configured,
        initialized.pool.clone(),
        initialized.stack_identity,
    )
    .await
    .unwrap();
    drop(server);
    initialized.pool.close().await;
    database.cleanup().await;

    sqlx::query(&format!("DROP ROLE {runtime_role}"))
        .execute(&admin_pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP ROLE {migrator_role}"))
        .execute(&admin_pool)
        .await
        .unwrap();
    admin_pool.close().await;
}

#[test]
fn database_url_for_role_replaces_user_and_password() {
    let url = database_url_for_role(
        "postgres://postgres:admin-secret@localhost:5432/paykit_e2e_test?sslmode=require",
        "paykit_runtime_abc",
        "runtime-secret",
    );
    let parsed = Url::parse(&url).unwrap();

    assert_eq!(parsed.username(), "paykit_runtime_abc");
    assert_eq!(parsed.password(), Some("runtime-secret"));
    assert_eq!(parsed.path(), "/paykit_e2e_test");
    assert_eq!(parsed.query(), Some("sslmode=require"));
}
