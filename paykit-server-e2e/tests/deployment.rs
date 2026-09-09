use std::time::Duration;

use paykit_server::{
    config::{Config, ConfigEnvironment, StackRole},
    persistence::{DeploymentStore, PersistenceError},
    startup::{StartupError, initialize_database},
};
use paykit_server_e2e::postgres::TestDatabase;

const KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn config(database_url: &str, network: &str, stack_role: &str) -> Config {
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
            database_url: Some(database_url.to_owned()),
            master_key: Some(MASTER_KEY.to_owned()),
        },
    )
    .expect("valid config fixture")
}

#[tokio::test]
async fn booting_with_a_mismatched_network_or_role_fails_before_binding() {
    let database = TestDatabase::create().await;
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
