use paykit_server::{
    config::{Config, ConfigEnvironment},
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
    initialize_database(&config(database.database_url(), "regtest", "proof"))
        .await
        .unwrap();

    // Same role, different network: refused on the network invariant.
    let error = initialize_database(&config(database.database_url(), "mainnet", "proof"))
        .await
        .unwrap_err();
    assert_eq!(error, StartupError::Deployment);
    // Same network, different role: refused on the stack_role invariant.
    let error = initialize_database(&config(database.database_url(), "regtest", "production"))
        .await
        .unwrap_err();
    assert_eq!(error, StartupError::Deployment);

    database.cleanup().await;
}

#[tokio::test]
async fn booting_a_production_role_against_a_proof_database_fails_before_binding() {
    let database = TestDatabase::create().await;
    initialize_database(&config(database.database_url(), "testnet", "proof"))
        .await
        .unwrap();

    let error = initialize_database(&config(database.database_url(), "testnet", "production"))
        .await
        .unwrap_err();
    assert_eq!(error, StartupError::Deployment);

    database.cleanup().await;
}

#[tokio::test]
async fn an_unset_stored_role_is_adopted_once_and_then_enforced() {
    let database = TestDatabase::create().await;
    let configured = config(database.database_url(), "testnet", "proof");
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

    let error = initialize_database(&config(database.database_url(), "testnet", "production"))
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
    let configured = config(database.database_url(), "testnet", "proof");
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

    // Two first boots race to adopt the NULL row with different roles:
    // exactly one adopts, the other observes the adopted role and refuses.
    let proof_config = config(database.database_url(), "testnet", "proof");
    let production_config = config(database.database_url(), "testnet", "production");
    let proof = initialize_database(&proof_config);
    let production = initialize_database(&production_config);
    let (proof, production) = tokio::join!(proof, production);
    assert!(
        matches!(
            (&proof, &production),
            (Ok(_), Err(StartupError::Deployment)) | (Err(StartupError::Deployment), Ok(_))
        ),
        "exactly one concurrent first boot must adopt the role"
    );
    let adopted: String =
        sqlx::query_scalar("SELECT stack_role FROM deployment_metadata WHERE id = 1")
            .fetch_one(database.pool())
            .await
            .unwrap();

    // Two boots that agree with the adopted role both succeed.
    let first_config = config(database.database_url(), "testnet", &adopted);
    let second_config = config(database.database_url(), "testnet", &adopted);
    let first = initialize_database(&first_config);
    let second = initialize_database(&second_config);
    let (first, second) = tokio::join!(first, second);
    first.unwrap();
    second.unwrap();

    database.cleanup().await;
}
