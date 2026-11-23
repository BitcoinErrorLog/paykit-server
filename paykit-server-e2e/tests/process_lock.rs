//! Single-process ownership of a Paykit Server database.
use std::time::{Duration, Instant};

use paykit_server::{
    config::{Config, ConfigEnvironment},
    startup::{StartupError, acquire_process_lock},
};
use paykit_server_e2e::postgres::TestDatabase;

const TRUSTED_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn config_for(database: &TestDatabase) -> Config {
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:8080"
[signed_services]
trusted_public_keys = ["{TRUSTED_KEY}"]
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "testnet"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "5s"
[limits]
request_body_bytes = 16384
[rate_limits]
signed_requests_per_second = 100
signed_burst = 200
"#
        ),
        ConfigEnvironment {
            database_url: Some(database.database_url().to_owned()),
            master_key: Some(MASTER_KEY.to_owned()),
        },
    )
    .unwrap()
}

#[tokio::test]
async fn a_second_process_waits_then_fails_while_the_lock_is_held() {
    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let held = acquire_process_lock(&config, Duration::ZERO).await.unwrap();

    let started = Instant::now();
    let second = acquire_process_lock(&config, Duration::from_secs(2)).await;
    assert_eq!(second.err(), Some(StartupError::ProcessLockHeld));
    assert!(started.elapsed() >= Duration::from_secs(2));

    held.release().await.unwrap();
    let next = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    next.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn a_waiting_process_starts_once_the_holder_exits() {
    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let held = acquire_process_lock(&config, Duration::ZERO).await.unwrap();

    let waiting = tokio::spawn({
        let config = config_for(&database);
        async move { acquire_process_lock(&config, Duration::from_secs(10)).await }
    });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!waiting.is_finished());
    drop(held);

    let next = waiting.await.unwrap().unwrap();
    next.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn lost_stays_pending_while_the_session_is_healthy() {
    let database = TestDatabase::create().await;
    let mut held = acquire_process_lock(&config_for(&database), Duration::ZERO)
        .await
        .unwrap();

    let lost = tokio::time::timeout(
        Duration::from_millis(500),
        held.lost(Duration::from_millis(50)),
    )
    .await;
    assert!(lost.is_err());

    held.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn lost_completes_when_the_lock_session_ends() {
    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let mut held = acquire_process_lock(&config, Duration::ZERO).await.unwrap();

    let terminated: Vec<bool> = sqlx::query_scalar(
        "SELECT pg_terminate_backend(pid) FROM pg_locks \
         WHERE locktype = 'advisory' AND granted \
           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(terminated, vec![true]);

    tokio::time::timeout(Duration::from_secs(5), held.lost(Duration::from_millis(50)))
        .await
        .expect("lost() must complete after the lock session ends");
    drop(held);

    let next = acquire_process_lock(&config, Duration::from_secs(5))
        .await
        .unwrap();
    next.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn the_lock_is_scoped_to_one_database() {
    let first = TestDatabase::create().await;
    let second = TestDatabase::create().await;
    let first_lock = acquire_process_lock(&config_for(&first), Duration::ZERO)
        .await
        .unwrap();
    let second_lock = acquire_process_lock(&config_for(&second), Duration::ZERO)
        .await
        .unwrap();

    first_lock.release().await.unwrap();
    second_lock.release().await.unwrap();
    first.cleanup().await;
    second.cleanup().await;
}
