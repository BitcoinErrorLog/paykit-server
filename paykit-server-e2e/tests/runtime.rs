use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

mod common;
use paykit_sdk::PubkyPublicKey;
use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment},
    crypto::Crypto,
    domain::{
        locks::{ReaderPubky, parse_creator, parse_reader},
        receiving::BitcoinAccount,
    },
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, PersistenceError, run_migrations,
    },
    runtime::ComponentState,
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};

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
    let logs = captured_worker_logs();
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
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "unused-xpub".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    let logged_from = logs.len();
    creators.mark_setup_complete(&creator).await.unwrap();
    // An empty outbox must not hide a configured Creator from transport
    // maintenance, and that one Creator's failure must not degrade every Creator.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !logs.contains_since(logged_from, "Paykit transport maintenance failed") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("transport worker must maintain the configured Creator");
    let observed_until = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < observed_until {
        let report = runtime.readiness().await;
        assert_eq!(report.status, ComponentState::Ready);
        assert_eq!(report.paykit_delivery, ComponentState::Ready);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    shutdown_tx.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(runtime.readiness().await.status, ComponentState::NotReady);
    database.cleanup().await;
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Workers run on spawned tasks, so only a process-wide subscriber sees their events.
fn captured_worker_logs() -> CapturedLogs {
    static LOGS: OnceLock<CapturedLogs> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = CapturedLogs::default();
        let writer = logs.clone();
        tracing_subscriber::fmt()
            .with_env_filter("paykit_server::server=warn")
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .try_init()
            .expect("the runtime suite installs the only global subscriber");
        logs
    })
    .clone()
}

impl CapturedLogs {
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    fn contains_since(&self, offset: usize, needle: &str) -> bool {
        String::from_utf8_lossy(&self.0.lock().unwrap()[offset..]).contains(needle)
    }
}

struct Payloads(ReaderPubky);

impl InvoicePayloadFactory for Payloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        Ok(InvoicePayloads {
            payment_request_intent: common::payment_intent(
                &self.0,
                format!("unreachable-creator-address-{child_index}"),
            ),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_creators_failed_lifecycle_reconciliation_keeps_delivery_ready() {
    let logs = captured_worker_logs();
    let logged_from = logs.len();
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let testnet = build_pubky_testnet().await;

    // A Creator with Payment Request history whose session can no longer be
    // restored, so every lifecycle receive for it fails. Its outbox work is
    // terminal, so no durable delivery failure is pending.
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creator = parse_creator(TRUSTED_KEY).unwrap();
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    creators
        .create(&CreatorCredentials::new(
            creator.clone(),
            "invalid-session".into(),
            paykit_sdk::PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            Some(BitcoinAccount {
                xpub: "unused-xpub".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    let reader_key = PubkyPublicKey::from_public_key(&Keypair::random().public_key());
    let reader = parse_reader(&format!("pubky{reader_key}")).unwrap();
    let invoice = InvoiceStore::new(database.pool(), crypto)
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"runtime-history-bundle",
            lock_resource_binding: b"runtime-history-lock",
            payment_request_binding: b"runtime-history-request",
            invoice_payloads: &Payloads(reader.clone()),
            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap();
    sqlx::query(
        "UPDATE outbox SET status = 'permanently_failed', error_class = 'permanent' \
         WHERE id = $1",
    )
    .bind(invoice.payment_request_outbox_id())
    .execute(database.pool())
    .await
    .unwrap();

    let endpoint = unavailable_electrum_endpoint().await;
    let server = Server::build_with_pubky(
        config(database.database_url(), &endpoint, "1s"),
        database.pool().clone(),
        testnet.sdk().unwrap(),
    )
    .await
    .unwrap();
    let runtime = server.runtime();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(server.run_until(listener, async move {
        let _ = shutdown_rx.await;
    }));

    tokio::time::timeout(Duration::from_secs(10), async {
        while !logs.contains_since(
            logged_from,
            "Creator payment request reconciliation deferred",
        ) || runtime.readiness().await.status == ComponentState::NotReady
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("lifecycle reconciliation must attempt and log the failing Creator");
    assert!(logs.contains_since(logged_from, "step=\"receive_and_project\""));

    // Several 1 s reconciliation passes, each failing for that Creator.
    let observed_until = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < observed_until {
        let report = runtime.readiness().await;
        assert_eq!(report.paykit_delivery, ComponentState::Ready);
        assert_eq!(report.outbox, ComponentState::Ready);
        // The history invoice is an observation target and Electrum never answers.
        assert_eq!(report.electrum, ComponentState::Degraded);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    shutdown_tx.send(()).unwrap();
    task.await.unwrap().unwrap();
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
