use std::time::Duration;

use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment},
    persistence::run_migrations,
    runtime::ComponentState,
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::EphemeralTestnet;

const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const TRUSTED_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn build_pubky_testnet() -> EphemeralTestnet {
    let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap();
    EphemeralTestnet::builder()
        .postgres(postgres)
        .build()
        .await
        .unwrap()
}

fn config(database_url: &str, electrum_endpoint: &str, drain_timeout: &str) -> Config {
    let source = format!(
        r#"
[http]
listen_addr = "127.0.0.1:0"

[locks]
trusted_public_key = "{TRUSTED_KEY}"

[setup]
allowed_origins = ["https://app.example"]

[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"

[bitcoin]
network = "testnet"

[electrum]
endpoint = "{electrum_endpoint}"
poll_interval = "1s"
request_timeout = "1s"
connect_retries = 0

[outbox]
poll_interval = "1s"
batch_size = 16
lease_duration = "5s"
retry_initial = "1s"
retry_max = "2s"

[shutdown]
drain_timeout = "{drain_timeout}"
"#
    );
    Config::from_toml_and_environment(
        &source,
        ConfigEnvironment {
            database_url: Some(database_url.to_owned()),
            master_key: Some(MASTER_KEY.to_owned()),
        },
    )
    .unwrap()
}

async fn unavailable_electrum_endpoint() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
    drop(listener);
    endpoint
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_workers_publish_startup_evidence_before_readiness() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let endpoint = unavailable_electrum_endpoint().await;
    let server = Server::build_with_pubky(
        config(database.database_url(), &endpoint, "1s"),
        database.pool().clone(),
        testnet.sdk().unwrap(),
    )
    .await
    .unwrap();
    let runtime = server.runtime();
    assert_eq!(runtime.readiness().await.status, ComponentState::NotReady);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(server.run_until(listener, async move {
        let _ = shutdown_rx.await;
    }));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let report = runtime.readiness().await;
            if report.status == ComponentState::Ready {
                assert_eq!(report.electrum, ComponentState::Ready);
                assert_eq!(report.paykit_delivery, ComponentState::Ready);
                assert_eq!(report.outbox, ComponentState::Ready);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all owned workers must publish startup evidence");

    let creator = paykit_server::domain::locks::parse_creator(TRUSTED_KEY).unwrap();
    let creators = paykit_server::persistence::CreatorStore::new(
        database.pool(),
        std::sync::Arc::new(paykit_server::crypto::Crypto::from_master_key(&[1; 32]).unwrap()),
    );
    creators
        .create(&paykit_server::persistence::CreatorCredentials::new(
            creator.clone(),
            "invalid-session".into(),
            paykit_sdk::PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            "unused-xpub".into(),
            0,
        ))
        .await
        .unwrap();
    creators.mark_setup_complete(&creator).await.unwrap();
    // An empty outbox must not hide a configured Creator's transport failure.
    for expected in [ComponentState::Degraded, ComponentState::Ready] {
        if expected == ComponentState::Ready {
            sqlx::query("UPDATE creators SET setup_complete = FALSE")
                .execute(database.pool())
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let report = runtime.readiness().await;
                if report.paykit_delivery == expected {
                    assert_eq!(report.status, expected);
                    assert_eq!(report.outbox, ComponentState::Ready);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("transport worker must report availability");
    }

    shutdown_tx.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(runtime.readiness().await.status, ComponentState::NotReady);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_deadline_aborts_a_database_blocked_owned_worker() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let endpoint = unavailable_electrum_endpoint().await;
    let server = Server::build_with_pubky(
        config(database.database_url(), &endpoint, "100ms"),
        database.pool().clone(),
        testnet.sdk().unwrap(),
    )
    .await
    .unwrap();
    let runtime = server.runtime();

    let mut lock = database.acquire_connection().await;
    sqlx::query("BEGIN").execute(&mut *lock).await.unwrap();
    sqlx::query("LOCK TABLE outbox IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(server.run_until(listener, async move {
        let _ = shutdown_rx.await;
    }));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let blocked: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity \
                 WHERE datname = current_database() \
                 AND wait_event_type = 'Lock' \
                 AND query LIKE '%FROM outbox%'",
            )
            .fetch_one(database.pool())
            .await
            .unwrap();
            if blocked > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("an owned outbox worker must block on the held table lock");

    let started = tokio::time::Instant::now();
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("complete server/worker join must be deadline-bounded")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(80));
    assert_eq!(runtime.readiness().await.status, ComponentState::NotReady);

    sqlx::query("ROLLBACK").execute(&mut *lock).await.unwrap();
    drop(lock);
    database.cleanup().await;
}
