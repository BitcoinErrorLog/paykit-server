//! Single-process ownership of a Paykit Server database.
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

mod common;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::hashes::{Hash, sha256};
use ed25519_dalek::{Signer, SigningKey};
use paykit_sdk::{
    PAYKIT_AUTHORIZER_SESSION_CAPABILITIES, PAYKIT_SESSION_CAPABILITIES, PaykitIdentitySecretKey,
    PubkyLocalSecretKey, PubkyPublicKey, PubkySessionAccess, PubkySessionBootstrap,
    PubkySessionProvider,
};
use paykit_server::{
    Server,
    bitkit_claim::{ClaimError, SetupCompanionClaim, VerifiedCompanionClaim},
    bitkit_setup::BitkitAuthStarter,
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    crypto::Crypto,
    domain::{
        locks::{ReaderPubky, parse_creator, parse_reader},
        payment::BitcoinOutpoint,
        receiving::UsdtAddress,
    },
    http::auth::signature_preimage,
    paykit::CreatorSessions,
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, OutboxStore, PROCESS_ADVISORY_LOCK_KEY,
        PROCESS_LOCK_APPLICATION_NAME, PersistenceError, ProcessLockLoss, ProcessLockTiming,
    },
    real_setup::{AppPublisher, RealSetupCompleter},
    server::RunError,
    setup::{Completion, SetupAttempt, SetupCompleter, StartedSetup},
    setup_orchestration::PubkyCompanionRelay,
    startup::{
        StartupError, acquire_process_lock, acquire_process_lock_blocking, initialize_database,
        initialize_database_holding_process_lock,
        initialize_database_holding_process_lock_with_post_claim_hook,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use sqlx::{Connection, PgConnection};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const TRUSTED_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn config_for(database: &TestDatabase) -> Config {
    config_with_url(database.database_url())
}

fn config_with_url(database_url: &str) -> Config {
    config_with_options(database_url, TRUSTED_KEY, "10s")
}

fn config_with_options(database_url: &str, trusted_key: &str, drain_timeout: &str) -> Config {
    config_with_poll_and_drain(database_url, trusted_key, "5s", drain_timeout)
}

fn config_with_poll_and_drain(
    database_url: &str,
    trusted_key: &str,
    poll_interval: &str,
    drain_timeout: &str,
) -> Config {
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:8080"
[signed_services]
trusted_public_keys = ["{trusted_key}"]
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "testnet"
[electrum]
endpoint = "tcp://127.0.0.1:9"
poll_interval = "{poll_interval}"
connect_retries = 0
[outbox]
poll_interval = "{poll_interval}"
[limits]
request_body_bytes = 16384
[rate_limits]
signed_requests_per_second = 100
signed_burst = 200
[shutdown]
drain_timeout = "{drain_timeout}"
"#
        ),
        ConfigEnvironment {
            database_url: Some(database_url.to_owned()),
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
async fn pg_stat_activity_names_the_lock_session() {
    let database = TestDatabase::create().await;
    let held = acquire_process_lock(&config_for(&database), Duration::ZERO)
        .await
        .unwrap();

    let named: Vec<i32> = sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity \
         WHERE application_name = $1 AND datname = current_database()",
    )
    .bind(PROCESS_LOCK_APPLICATION_NAME)
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(named, lock_holder_pids(&database).await);

    held.release().await.unwrap();
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

const SERVER_LOCK_TIMING: ProcessLockTiming = ProcessLockTiming {
    check_interval: Duration::from_millis(100),
    reacquire_within: Duration::from_secs(5),
    retry_interval: Duration::from_millis(50),
};

struct RunningServer {
    address: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    run: tokio::task::JoinHandle<Result<(), RunError>>,
    runtime: Arc<paykit_server::runtime::Runtime>,
}

async fn start_server_holding_the_lock(config: Config) -> RunningServer {
    start_server_holding_the_lock_with_timing(config, SERVER_LOCK_TIMING).await
}

async fn start_server_holding_the_lock_with_timing(
    config: Config,
    timing: ProcessLockTiming,
) -> RunningServer {
    let lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database(&config).await.unwrap();
    let server = Server::build(config, pool).await.unwrap();
    spawn_running_server(server, lock, timing).await
}

async fn spawn_running_server(
    server: Server,
    lock: paykit_server::persistence::ProcessLock,
    timing: ProcessLockTiming,
) -> RunningServer {
    let runtime = server.runtime();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run =
        tokio::spawn(
            server.run_holding_process_lock_until(listener, lock, timing, async move {
                let _ = stopped.await;
            }),
        );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !runtime.admitting() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server must claim ownership and open admission");
    RunningServer {
        address,
        stop,
        run,
        runtime,
    }
}

async fn lock_holder_pids(database: &TestDatabase) -> Vec<i32> {
    sqlx::query_scalar(
        "SELECT pid FROM pg_locks \
         WHERE locktype = 'advisory' AND granted \
           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .fetch_all(database.pool())
    .await
    .unwrap()
}

async fn terminate(database: &TestDatabase, pid: i32) {
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert!(terminated);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_retakes_the_lock_after_its_session_ends() {
    let database = TestDatabase::create().await;
    let server = start_server_holding_the_lock(config_for(&database)).await;
    let [first_holder] = lock_holder_pids(&database).await[..] else {
        panic!("the server must hold the lock");
    };

    terminate(&database, first_holder).await;
    let retaken = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let [holder] = lock_holder_pids(&database).await[..]
                && holder != first_holder
            {
                return holder;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the server must retake the lock on a new session");
    assert_ne!(retaken, first_holder);
    tokio::time::sleep(SERVER_LOCK_TIMING.check_interval * 3).await;
    assert!(!server.run.is_finished());
    assert!(!server.runtime.stopping());
    assert_eq!(
        acquire_process_lock(&config_for(&database), Duration::ZERO)
            .await
            .err(),
        Some(StartupError::ProcessLockHeld)
    );

    server.stop.send(()).unwrap();
    server.run.await.unwrap().unwrap();
    let next = acquire_process_lock(&config_for(&database), Duration::ZERO)
        .await
        .expect("a clean shutdown releases the lock");
    next.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_stops_when_another_process_takes_the_lock() {
    let database = TestDatabase::create().await;
    let server = start_server_holding_the_lock(config_for(&database)).await;
    let [holder] = lock_holder_pids(&database).await[..] else {
        panic!("the server must hold the lock");
    };

    // Queued behind the server's session, this session is granted the lock the
    // moment that session ends, before the server can retake it.
    let mut other_process = PgConnection::connect(database.database_url())
        .await
        .unwrap();
    let other_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut other_process)
        .await
        .unwrap();
    let take_over = tokio::spawn(async move {
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(PROCESS_ADVISORY_LOCK_KEY)
            .execute(&mut other_process)
            .await
            .unwrap();
        other_process
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted)",
            )
            .bind(other_pid)
            .fetch_one(database.pool())
            .await
            .unwrap();
            if waiting {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the other session must queue for the lock");

    let lost_at = Instant::now();
    terminate(&database, holder).await;
    let other_process = take_over.await.unwrap();
    assert_eq!(lock_holder_pids(&database).await, vec![other_pid]);

    let stopped = tokio::time::timeout(
        SERVER_LOCK_TIMING.check_interval * 2
            + SERVER_LOCK_TIMING.check_interval
            + paykit_server::server::LOST_PROCESS_LOCK_DRAIN_LIMIT
            + Duration::from_secs(1),
        server.run,
    )
    .await
    .expect("losing the lock to another process must stop the server")
    .unwrap();
    assert!(matches!(
        stopped,
        Err(RunError::ProcessLockLost(ProcessLockLoss::HeldElsewhere))
    ));
    assert!(server.runtime.stopping());
    assert!(lost_at.elapsed() < Duration::from_secs(7));
    assert_eq!(lock_holder_pids(&database).await, vec![other_pid]);

    other_process.close().await.unwrap();
    drop(server.stop);
    database.cleanup().await;
}

#[tokio::test]
async fn startup_retries_an_unreachable_database_for_the_whole_wait() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let config = config_with_url(&format!("postgres://postgres:postgres@{address}/postgres"));

    let started = Instant::now();
    let result = acquire_process_lock(&config, Duration::from_secs(2)).await;
    assert_eq!(result.err(), Some(StartupError::Connection));
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(2), "elapsed={elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(2600),
        "unreachable wait must not overshoot budget: elapsed={elapsed:?}"
    );
}

#[tokio::test]
async fn startup_bounds_hanging_database_attempts_to_wait_budget() {
    // Accepts TCP connections and holds them open without responding, simulating a
    // blackholed or hanging PostgreSQL endpoint.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let sink = tokio::spawn(async move {
        let mut sockets = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            sockets.push(stream);
        }
    });
    let config = config_with_url(&format!("postgres://postgres:postgres@{address}/postgres"));

    let wait = Duration::from_millis(400);
    let started = Instant::now();
    let result = acquire_process_lock(&config, wait).await;
    let elapsed = started.elapsed();
    sink.abort();

    assert_eq!(result.err(), Some(StartupError::Connection));
    assert!(elapsed >= wait, "elapsed={elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(900),
        "hanging attempt timeout must be capped to remaining wait budget: elapsed={elapsed:?}"
    );
}

#[tokio::test]
async fn startup_takes_the_lock_once_the_database_accepts_connections() {
    let database = TestDatabase::create().await;
    let mut proxied = url::Url::parse(database.database_url()).unwrap();
    let upstream = format!(
        "{}:{}",
        proxied.host_str().unwrap(),
        proxied.port().unwrap_or(5432)
    );
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    proxied.set_host(Some("127.0.0.1")).unwrap();
    proxied.set_port(Some(address.port())).unwrap();
    let config = config_with_url(proxied.as_str());

    let starting =
        tokio::spawn(async move { acquire_process_lock(&config, Duration::from_secs(10)).await });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!starting.is_finished());
    let proxy = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                let mut server = tokio::net::TcpStream::connect(upstream).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
        }
    });

    let lock = tokio::time::timeout(Duration::from_secs(5), starting)
        .await
        .expect("startup must take the lock once PostgreSQL answers")
        .unwrap()
        .unwrap();
    lock.release().await.unwrap();
    proxy.abort();
    database.cleanup().await;
}

async fn try_http_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Option<(u16, Vec<u8>)> {
    let mut stream = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect(address),
    )
    .await
    .ok()?
    .ok()?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.ok()?;
    stream.write_all(body).await.ok()?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .ok()?
        .ok()?;
    let header_end = response.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers_text = std::str::from_utf8(&response[..header_end]).ok()?;
    let status = headers_text
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    Some((status, response[(header_end + 4)..].to_vec()))
}

async fn creator_held_status(address: SocketAddr, creator: &str) -> Option<(u16, String)> {
    let (status, body) = try_http_request(
        address,
        "GET",
        &format!("/setup/creator-held?creator={creator}"),
        &[],
        b"",
    )
    .await?;
    Some((status, String::from_utf8_lossy(&body).into_owned()))
}

async fn setup_page_status(address: SocketAddr, state: &str) -> Option<u16> {
    let (status, _) = try_http_request(
        address,
        "GET",
        &format!("/setup?return_to=https://app.example/callback&state={state}"),
        &[],
        b"",
    )
    .await?;
    Some(status)
}

async fn signed_transaction_status(
    address: SocketAddr,
    signing_key: &SigningKey,
    creator: &str,
) -> Option<u16> {
    let path = "/transactions/status";
    let body = format!(r#"{{"bundle_id":"000G40R40M30E209185GR38E1W","creator":"{creator}"}}"#);
    let preimage = signature_preimage("POST", path, body.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&preimage).to_bytes());
    let headers = [
        ("content-type", "application/json".to_owned()),
        ("x-paykit-signature", signature),
    ];
    let (status, _) = try_http_request(address, "POST", path, &headers, body.as_bytes()).await?;
    Some(status)
}

async fn readiness_response(address: SocketAddr) -> Option<(u16, serde_json::Value)> {
    let (status, body) = try_http_request(address, "GET", "/health/ready", &[], b"").await?;
    let json = serde_json::from_slice(&body).ok()?;
    Some((status, json))
}

async fn ownership_row(database: &TestDatabase) -> Option<(i64, Option<Uuid>, bool)> {
    sqlx::query_as("SELECT generation, owner_id, fenced FROM process_ownership WHERE id = 1")
        .fetch_optional(database.pool())
        .await
        .unwrap()
}

fn trusted_key_for(signing_key: &SigningKey) -> String {
    pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(signing_key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string()
}

struct ToggleProxy {
    database_url: String,
    open: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl ToggleProxy {
    async fn start(upstream_url: &str) -> Self {
        let mut proxied = url::Url::parse(upstream_url).unwrap();
        let upstream = format!(
            "{}:{}",
            proxied.host_str().unwrap(),
            proxied.port().unwrap_or(5432)
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        proxied.set_host(Some("127.0.0.1")).unwrap();
        proxied.set_port(Some(address.port())).unwrap();
        let open = Arc::new(AtomicBool::new(true));
        let connections = Arc::new(Mutex::new(Vec::<tokio::task::AbortHandle>::new()));
        let accept_task = tokio::spawn({
            let open = open.clone();
            let connections = connections.clone();
            async move {
                loop {
                    let Ok((mut client, _)) = listener.accept().await else {
                        break;
                    };
                    if !open.load(Ordering::SeqCst) {
                        drop(client);
                        continue;
                    }
                    let upstream = upstream.clone();
                    let handle = tokio::spawn(async move {
                        if let Ok(mut server) = tokio::net::TcpStream::connect(upstream).await {
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                        }
                    });
                    connections.lock().unwrap().push(handle.abort_handle());
                }
            }
        });
        Self {
            database_url: proxied.to_string(),
            open,
            connections,
            accept_task,
        }
    }

    fn cut(&self) {
        self.open.store(false, Ordering::SeqCst);
        let mut connections = self.connections.lock().unwrap();
        for handle in connections.drain(..) {
            handle.abort();
        }
    }

    fn resume(&self) {
        self.open.store(true, Ordering::SeqCst);
    }

    fn stop(self) {
        self.cut();
        self.accept_task.abort();
    }
}

struct QueuedReplacement {
    address: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    runtime_rx: tokio::sync::oneshot::Receiver<Arc<paykit_server::runtime::Runtime>>,
    run: tokio::task::JoinHandle<Result<(), RunError>>,
}

async fn wait_until_lock_waiter_is_queued(database: &TestDatabase) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS ( \
                     SELECT 1 FROM pg_locks \
                     WHERE locktype = 'advisory' AND NOT granted \
                       AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
                 )",
            )
            .fetch_one(database.pool())
            .await
            .unwrap();
            if waiting {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("replacement server must queue on the PostgreSQL advisory lock");
}

async fn start_queued_replacement_server(
    database: &TestDatabase,
    config: Config,
    timing: ProcessLockTiming,
) -> QueuedReplacement {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let (runtime_tx, runtime_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(async move {
        let lock = acquire_process_lock_blocking(&config)
            .await
            .expect("replacement server must acquire advisory lock");
        let pool = initialize_database(&config)
            .await
            .expect("replacement server must initialize database");
        let server = Server::build(config, pool)
            .await
            .expect("replacement server must build");
        let runtime = server.runtime();
        let run_future =
            server.run_holding_process_lock_until(listener, lock, timing, async move {
                let _ = stopped.await;
            });
        // Construct run_holding_process_lock_until first so admission is synchronously
        // suspended before exposing runtime to observers.
        let _ = runtime_tx.send(runtime);
        run_future.await
    });
    wait_until_lock_waiter_is_queued(database).await;
    QueuedReplacement {
        address,
        stop,
        runtime_rx,
        run,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_session_failure_revokes_http_admission_before_reacquisition() {
    let database = TestDatabase::create().await;
    let proxy = ToggleProxy::start(database.database_url()).await;
    let server = start_server_holding_the_lock(config_with_url(&proxy.database_url)).await;

    assert_eq!(
        creator_held_status(server.address, TRUSTED_KEY).await,
        Some((200, "{\"held\":false}".to_owned()))
    );
    assert_eq!(
        setup_page_status(server.address, "before-cut").await,
        Some(200)
    );
    let (gen_before, owner_before, fenced_before) = ownership_row(&database).await.unwrap();
    assert_eq!(gen_before, 1);
    assert!(owner_before.is_some());
    assert!(!fenced_before);

    // Sever PostgreSQL access: lock session ends while reacquisition retries for up to 5 s.
    // `/setup` does not query PostgreSQL, so 503 proves runtime HTTP admission revocation.
    proxy.cut();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if setup_page_status(server.address, "during-cut").await == Some(503) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("HTTP business admission must close immediately on first session failure");

    assert!(
        !server.runtime.admitting(),
        "runtime must revoke admission while reacquiring"
    );
    assert!(!server.runtime.may_start_worker_claim());
    assert!(
        !server.runtime.stopping(),
        "server should still be attempting reacquisition during the outage window"
    );
    assert!(!server.run.is_finished());
    let (ready_status, ready_body) = readiness_response(server.address).await.unwrap();
    assert_eq!(ready_status, 503);
    assert_eq!(ready_body["postgres"], "not_ready");

    // Restore PostgreSQL with no competing server: same generation resumes serving.
    proxy.resume();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if setup_page_status(server.address, "after-resume").await == Some(200)
                && creator_held_status(server.address, TRUSTED_KEY).await
                    == Some((200, "{\"held\":false}".to_owned()))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("HTTP admission must resume once the same ownership generation is retaken");

    assert!(server.runtime.admitting());
    assert_eq!(
        ownership_row(&database).await,
        Some((1, owner_before, false))
    );

    server.stop.send(()).unwrap();
    server.run.await.unwrap().unwrap();
    assert_eq!(ownership_row(&database).await, Some((1, None, false)));
    proxy.stop();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_serving_servers_never_admit_business_requests_concurrently_on_takeover() {
    let database = TestDatabase::create().await;
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let trusted_key = trusted_key_for(&signing_key);
    let config_a = config_with_options(database.database_url(), &trusted_key, "1s");
    let config_b = config_with_options(database.database_url(), &trusted_key, "1s");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(2),
        retry_interval: Duration::from_millis(25),
    };

    let server_a = start_server_holding_the_lock_with_timing(config_a, timing).await;
    let [holder_a] = lock_holder_pids(&database).await[..] else {
        panic!("server A must hold the advisory lock");
    };
    let (gen_a, owner_a, fenced_a) = ownership_row(&database).await.unwrap();
    assert_eq!(gen_a, 1);
    assert!(owner_a.is_some());
    assert!(!fenced_a);
    assert_eq!(
        creator_held_status(server_a.address, &trusted_key).await,
        Some((200, "{\"held\":false}".to_owned()))
    );
    assert_eq!(
        signed_transaction_status(server_a.address, &signing_key, &trusted_key).await,
        Some(404)
    );

    let replacement = start_queued_replacement_server(&database, config_b, timing).await;
    let addr_a = server_a.address;
    let addr_b = replacement.address;
    let runtime_a = server_a.runtime.clone();
    let runtime_b_slot: Arc<Mutex<Option<Arc<paykit_server::runtime::Runtime>>>> =
        Arc::new(Mutex::new(None));
    let runtime_b_waiter = tokio::spawn({
        let slot = runtime_b_slot.clone();
        let rx = replacement.runtime_rx;
        async move {
            if let Ok(rt) = rx.await {
                *slot.lock().unwrap() = Some(rt);
            }
        }
    });

    let stop_probing = Arc::new(AtomicBool::new(false));
    let both_admitting = Arc::new(AtomicBool::new(false));
    let a_admitted: Arc<Mutex<Vec<(Instant, Instant)>>> = Arc::new(Mutex::new(Vec::new()));
    let b_admitted: Arc<Mutex<Vec<(Instant, Instant)>>> = Arc::new(Mutex::new(Vec::new()));

    let state_sampler = tokio::spawn({
        let stop = stop_probing.clone();
        let both = both_admitting.clone();
        let rt_a = runtime_a.clone();
        let rt_b_slot = runtime_b_slot.clone();
        async move {
            while !stop.load(Ordering::Relaxed) {
                let b_admit = rt_b_slot
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|rt| rt.admitting());
                if rt_a.admitting() && b_admit {
                    both.store(true, Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    });

    let probe_a = tokio::spawn({
        let stop = stop_probing.clone();
        let log = a_admitted.clone();
        let key = trusted_key.clone();
        let signing = signing_key.clone();
        async move {
            let mut turn = 0_usize;
            while !stop.load(Ordering::Relaxed) {
                let started = Instant::now();
                let status = if turn.is_multiple_of(2) {
                    creator_held_status(addr_a, &key).await.map(|(s, _)| s)
                } else {
                    signed_transaction_status(addr_a, &signing, &key).await
                };
                let completed = Instant::now();
                turn += 1;
                if let Some(status) = status
                    && status != 503
                {
                    log.lock().unwrap().push((started, completed));
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    });

    let probe_b = tokio::spawn({
        let stop = stop_probing.clone();
        let log = b_admitted.clone();
        let key = trusted_key.clone();
        let signing = signing_key.clone();
        async move {
            let mut turn = 0_usize;
            while !stop.load(Ordering::Relaxed) {
                let started = Instant::now();
                let status = if turn.is_multiple_of(2) {
                    creator_held_status(addr_b, &key).await.map(|(s, _)| s)
                } else {
                    signed_transaction_status(addr_b, &signing, &key).await
                };
                let completed = Instant::now();
                turn += 1;
                if let Some(status) = status
                    && status != 503
                {
                    log.lock().unwrap().push((started, completed));
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    });

    // Let probe_a record admitted business traffic on server A, then terminate A's lock session.
    tokio::time::sleep(Duration::from_millis(120)).await;
    terminate(&database, holder_a).await;

    let stopped_a = tokio::time::timeout(Duration::from_secs(5), server_a.run)
        .await
        .expect("server A must stop after losing the lock to server B")
        .unwrap();
    let a_exited_at = Instant::now();
    assert!(matches!(
        stopped_a,
        Err(RunError::ProcessLockLost(ProcessLockLoss::HeldElsewhere))
    ));
    assert!(!runtime_a.admitting());

    // Wait for server B to take over and serve real business requests.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if creator_held_status(addr_b, &trusted_key).await
                == Some((200, "{\"held\":false}".to_owned()))
                && signed_transaction_status(addr_b, &signing_key, &trusted_key).await == Some(404)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("server B must take over and serve business routes");

    tokio::time::sleep(Duration::from_millis(80)).await;
    stop_probing.store(true, Ordering::SeqCst);
    let _ = tokio::join!(state_sampler, probe_a, probe_b, runtime_b_waiter);

    assert!(
        !both_admitting.load(Ordering::SeqCst),
        "server A and server B must never have admitting() == true concurrently"
    );
    let a_hits = a_admitted.lock().unwrap().clone();
    let b_hits = b_admitted.lock().unwrap().clone();
    assert!(
        !a_hits.is_empty(),
        "server A should have admitted requests before loss"
    );
    assert!(
        !b_hits.is_empty(),
        "server B should have admitted requests after takeover"
    );
    let last_a_started = a_hits.iter().map(|(start, _)| *start).max().unwrap();
    let last_a_completed = a_hits.iter().map(|(_, end)| *end).max().unwrap();
    let first_b_started = b_hits.iter().map(|(start, _)| *start).min().unwrap();
    let first_b_completed = b_hits.iter().map(|(_, end)| *end).min().unwrap();
    assert!(
        last_a_started < a_exited_at,
        "server A admitted a request after exiting"
    );
    assert!(
        first_b_completed >= a_exited_at,
        "server B admitted a business response before server A finished lock-loss shutdown"
    );
    assert!(
        last_a_completed <= first_b_started,
        "server B started admitting business work before server A finished its last admitted request"
    );

    let (gen_b, owner_b, fenced_b) = ownership_row(&database).await.unwrap();
    assert_eq!(gen_b, 2);
    assert!(owner_b.is_some());
    assert_ne!(owner_b, owner_a);
    assert!(!fenced_b);

    replacement.stop.send(()).unwrap();
    replacement.run.await.unwrap().unwrap();
    assert_eq!(ownership_row(&database).await, Some((2, None, false)));
    drop(server_a.stop);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_settling_work_within_drain_limit_settles_cleanly_before_replacement_serves() {
    let database = TestDatabase::create().await;
    let config_a = config_with_options(database.database_url(), TRUSTED_KEY, "1s");
    let config_b = config_with_options(database.database_url(), TRUSTED_KEY, "1s");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_millis(500),
        retry_interval: Duration::from_millis(25),
    };

    let settling_entered = Arc::new(tokio::sync::Notify::new());
    let settled_cleanly = Arc::new(AtomicBool::new(false));
    let settled_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

    let lock_a = acquire_process_lock(&config_a, Duration::ZERO)
        .await
        .unwrap();
    let pool_a = initialize_database(&config_a).await.unwrap();
    let server_a_builder = Server::build(config_a, pool_a)
        .await
        .unwrap()
        .with_test_settling_pass({
            let entered = settling_entered.clone();
            let settled = settled_cleanly.clone();
            let settled_at = settled_at.clone();
            move || async move {
                entered.notify_one();
                tokio::time::sleep(Duration::from_millis(350)).await;
                *settled_at.lock().unwrap() = Some(Instant::now());
                settled.store(true, Ordering::SeqCst);
            }
        });
    let server_a = spawn_running_server(server_a_builder, lock_a, timing).await;
    settling_entered.notified().await;
    let [holder_a] = lock_holder_pids(&database).await[..] else {
        panic!("server A must hold the advisory lock");
    };

    let replacement = start_queued_replacement_server(&database, config_b, timing).await;
    let addr_b = replacement.address;
    let stop_probing = Arc::new(AtomicBool::new(false));
    let b_first_admitted_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let b_saw_quarantine_503 = Arc::new(AtomicBool::new(false));
    let probe_b = tokio::spawn({
        let stop = stop_probing.clone();
        let first = b_first_admitted_at.clone();
        let saw_503 = b_saw_quarantine_503.clone();
        async move {
            while !stop.load(Ordering::Relaxed) {
                if let Some((status, _)) = creator_held_status(addr_b, TRUSTED_KEY).await {
                    if status == 503 {
                        saw_503.store(true, Ordering::SeqCst);
                    } else {
                        let mut slot = first.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(Instant::now());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    });

    terminate(&database, holder_a).await;
    let stopped_a = tokio::time::timeout(Duration::from_secs(5), server_a.run)
        .await
        .expect("server A must stop cleanly after settling completes")
        .unwrap();
    assert!(matches!(
        stopped_a,
        Err(RunError::ProcessLockLost(ProcessLockLoss::HeldElsewhere))
    ));
    assert!(
        settled_cleanly.load(Ordering::SeqCst),
        "active settling work within the lock-loss drain limit must settle cleanly"
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if creator_held_status(addr_b, TRUSTED_KEY).await
                == Some((200, "{\"held\":false}".to_owned()))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("server B must take over once server A settles cleanly");

    stop_probing.store(true, Ordering::SeqCst);
    probe_b.await.unwrap();

    let settled_instant = settled_at.lock().unwrap().unwrap();
    let b_started = b_first_admitted_at.lock().unwrap().unwrap();
    assert!(
        b_started >= settled_instant,
        "server B must not admit business work before server A's active settling completes"
    );
    assert_eq!(ownership_row(&database).await.map(|(g, _, _)| g), Some(2));

    replacement.stop.send(()).unwrap();
    replacement.run.await.unwrap().unwrap();
    drop(server_a.stop);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_settling_work_beyond_drain_limit_terminates_in_bounded_time_without_dual_serving() {
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let database = TestDatabase::create().await;
    let drain_limit = Duration::from_millis(500);
    let config_a = config_with_options(database.database_url(), TRUSTED_KEY, "500ms");
    let config_b = config_with_options(database.database_url(), TRUSTED_KEY, "500ms");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_millis(500),
        retry_interval: Duration::from_millis(25),
    };

    let settling_entered = Arc::new(tokio::sync::Notify::new());
    let settling_unwound = Arc::new(AtomicBool::new(false));

    let lock_a = acquire_process_lock(&config_a, Duration::ZERO)
        .await
        .unwrap();
    let pool_a = initialize_database(&config_a).await.unwrap();
    let server_a_builder = Server::build(config_a, pool_a)
        .await
        .unwrap()
        .with_test_settling_pass({
            let entered = settling_entered.clone();
            let unwound = settling_unwound.clone();
            move || async move {
                let _guard = DropFlag(unwound);
                entered.notify_one();
                // Simulates a 30-second stalled Pubky homeserver request.
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    let server_a = spawn_running_server(server_a_builder, lock_a, timing).await;
    settling_entered.notified().await;
    let [holder_a] = lock_holder_pids(&database).await[..] else {
        panic!("server A must hold the advisory lock");
    };

    let replacement = start_queued_replacement_server(&database, config_b, timing).await;
    let addr_b = replacement.address;
    let runtime_a = server_a.runtime.clone();
    let runtime_b_slot: Arc<Mutex<Option<Arc<paykit_server::runtime::Runtime>>>> =
        Arc::new(Mutex::new(None));
    let runtime_b_waiter = tokio::spawn({
        let slot = runtime_b_slot.clone();
        let rx = replacement.runtime_rx;
        async move {
            if let Ok(rt) = rx.await {
                *slot.lock().unwrap() = Some(rt);
            }
        }
    });

    let stop_probing = Arc::new(AtomicBool::new(false));
    let both_admitting = Arc::new(AtomicBool::new(false));
    let b_admitted_while_settling_alive = Arc::new(AtomicBool::new(false));
    let b_saw_quarantine_503 = Arc::new(AtomicBool::new(false));

    let probe_b = tokio::spawn({
        let stop = stop_probing.clone();
        let both = both_admitting.clone();
        let b_early = b_admitted_while_settling_alive.clone();
        let saw_503 = b_saw_quarantine_503.clone();
        let unwound = settling_unwound.clone();
        let rt_a = runtime_a.clone();
        let rt_b_slot = runtime_b_slot.clone();
        async move {
            while !stop.load(Ordering::Relaxed) {
                let b_admit = rt_b_slot
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|rt| rt.admitting());
                if rt_a.admitting() && b_admit {
                    both.store(true, Ordering::SeqCst);
                }
                if let Some((status, _)) = creator_held_status(addr_b, TRUSTED_KEY).await {
                    if status == 503 {
                        saw_503.store(true, Ordering::SeqCst);
                    } else if !unwound.load(Ordering::SeqCst) {
                        b_early.store(true, Ordering::SeqCst);
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    });

    let lost_at = Instant::now();
    terminate(&database, holder_a).await;

    let stopped_a = tokio::time::timeout(Duration::from_secs(3), server_a.run)
        .await
        .expect("lock-loss termination must be bounded even when settling work stalls for 30 s")
        .unwrap();
    let elapsed_a = lost_at.elapsed();
    assert!(matches!(
        stopped_a,
        Err(RunError::ProcessLockLost(ProcessLockLoss::HeldElsewhere))
    ));
    assert!(
        elapsed_a >= drain_limit.saturating_sub(Duration::from_millis(120)),
        "settling work must be given the cooperative drain slice before forced termination: {elapsed_a:?}"
    );
    assert!(
        elapsed_a < Duration::from_secs(2),
        "lock-loss termination exceeded bounded drain window: {elapsed_a:?}"
    );
    assert!(
        settling_unwound.load(Ordering::SeqCst),
        "stuck settling child task must have completely unwound before server A returned"
    );

    // Because settling was force-terminated (unclean drain), server B remains
    // quarantined until lease_expires_at, then takes over cleanly.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if creator_held_status(addr_b, TRUSTED_KEY).await
                == Some((200, "{\"held\":false}".to_owned()))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("server B must take over once quarantine lease expires");

    stop_probing.store(true, Ordering::SeqCst);
    let _ = tokio::join!(probe_b, runtime_b_waiter);

    assert!(!both_admitting.load(Ordering::SeqCst));
    assert!(
        !b_admitted_while_settling_alive.load(Ordering::SeqCst),
        "server B must never admit business requests while server A's settling work is still running"
    );
    assert!(
        b_saw_quarantine_503.load(Ordering::SeqCst),
        "server B should reject business requests with 503 while in takeover quarantine"
    );
    assert_eq!(ownership_row(&database).await.map(|(g, _, _)| g), Some(2));

    replacement.stop.send(()).unwrap();
    replacement.run.await.unwrap().unwrap();
    drop(server_a.stop);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fenced_owner_cannot_resume_admission_even_if_advisory_lock_frees() {
    let database = TestDatabase::create().await;
    let proxy = ToggleProxy::start(database.database_url()).await;
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(5),
        retry_interval: Duration::from_millis(25),
    };
    let server_a =
        start_server_holding_the_lock_with_timing(config_with_url(&proxy.database_url), timing)
            .await;

    // Cut server A off from PostgreSQL so it suspends admission and waits to reacquire.
    proxy.cut();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !server_a.runtime.admitting() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("server A must revoke admission on first session failure");

    // Simulate a replacement acquiring the lock, fencing A, and then exiting cleanly
    // during quarantine so the advisory lock is free again when A reconnects.
    sqlx::query("UPDATE process_ownership SET fenced = TRUE WHERE id = 1")
        .execute(database.pool())
        .await
        .unwrap();

    proxy.resume();
    let stopped_a = tokio::time::timeout(Duration::from_secs(5), server_a.run)
        .await
        .expect("fenced server A must shut down instead of resuming admission")
        .unwrap();
    assert!(matches!(
        stopped_a,
        Err(RunError::ProcessLockLost(ProcessLockLoss::HeldElsewhere))
    ));
    assert!(!server_a.runtime.admitting());

    proxy.stop();
    drop(server_a.stop);
    database.cleanup().await;
}

#[tokio::test]
async fn suspended_runtime_blocks_creator_grant_restoration() {
    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let pool = initialize_database(&config).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(config.master_key().as_bytes()).unwrap());
    let creators = CreatorStore::new(&pool, crypto);

    let testnet = EphemeralTestnet::builder()
        .postgres(
            pubky_testnet::pubky_homeserver::ConnectionString::new(
                &std::env::var("TEST_DATABASE_URL").unwrap(),
            )
            .unwrap(),
        )
        .build()
        .await
        .unwrap();
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server").unwrap();
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let creator_keypair = Keypair::random();
    let signed_up = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(creator_keypair.secret_key()),
            &homeserver,
            None,
            PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", signed_up.public_key)).unwrap();
    let paykit_key = PaykitIdentitySecretKey::new([9_u8; 32], 1).unwrap();
    let mut cached_access = signed_up.access;
    cached_access.paykit_identity_secret_key = Some(paykit_key.clone());
    let session_secret = "unused-session-secret";
    let credentials = CreatorCredentials::new(
        creator.clone(),
        session_secret.to_owned(),
        paykit_key,
        None,
        None,
    );
    creators.create(&credentials).await.unwrap();

    let server = Server::build(config_for(&database), pool.clone())
        .await
        .unwrap();
    let runtime = server.runtime();
    let sessions = CreatorSessions::new(creators, pubky, config.paykit.clone())
        .with_runtime_for_test(runtime.clone());
    let provider = sessions.provider(&creator);
    let reconnect_provider = sessions.verified_reconnect_provider_for_test(
        &creator,
        session_secret,
        cached_access.clone(),
    );

    // Cold cache: suspended runtime and expired local lease both fail closed.
    runtime.suspend_admission();
    let error = provider
        .load_session_access()
        .await
        .expect_err("suspended runtime must refuse cold-cache Creator grant restoration");
    assert!(
        error
            .to_string()
            .contains("server process ownership is inactive"),
        "unexpected error: {error}"
    );
    runtime.grant_ownership_until(tokio::time::Instant::now());
    tokio::time::sleep(Duration::from_millis(5)).await;
    let error = provider
        .load_session_access()
        .await
        .expect_err("expired local ownership lease must refuse cold-cache restoration");
    assert!(
        error
            .to_string()
            .contains("server process ownership is inactive"),
        "unexpected error: {error}"
    );

    // Seed warm cache and verify healthy ownership serves both warm cache and verified_reconnect.
    provider
        .seed_cached_session_for_test(session_secret, cached_access)
        .await;
    runtime.grant_ownership_until(tokio::time::Instant::now() + Duration::from_secs(30));
    assert!(provider.load_session_access().await.unwrap().is_some());
    assert!(
        reconnect_provider
            .load_session_access()
            .await
            .unwrap()
            .is_some()
    );

    // Warm cache and verified_reconnect MUST be refused while suspended or lease-expired.
    runtime.suspend_admission();
    for (label, target) in [
        ("warm cache (suspended)", &provider),
        ("verified_reconnect (suspended)", &reconnect_provider),
    ] {
        let error = target.load_session_access().await.expect_err(label);
        assert!(
            error
                .to_string()
                .contains("server process ownership is inactive"),
            "{label}: unexpected error: {error}"
        );
    }

    runtime.grant_ownership_until(tokio::time::Instant::now());
    tokio::time::sleep(Duration::from_millis(5)).await;
    for (label, target) in [
        ("warm cache (expired lease)", &provider),
        ("verified_reconnect (expired lease)", &reconnect_provider),
    ] {
        let error = target.load_session_access().await.expect_err(label);
        assert!(
            error
                .to_string()
                .contains("server process ownership is inactive"),
            "{label}: unexpected error: {error}"
        );
    }

    // Clean shutdown while process still owns its lease keeps warm cache available
    // so active settling work can finish and unlock shared state before releasing.
    runtime.grant_ownership_until(tokio::time::Instant::now() + Duration::from_secs(30));
    runtime.begin_shutdown();
    assert!(runtime.owns_process_lock());
    assert!(!runtime.admitting());
    assert!(provider.load_session_access().await.unwrap().is_some());

    pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_poll_interval_workers_survive_temporary_outage_and_resume_same_generation() {
    let database = TestDatabase::create().await;
    let proxy = ToggleProxy::start(database.database_url()).await;
    let config = config_with_poll_and_drain(&proxy.database_url, TRUSTED_KEY, "50ms", "5s");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(5),
        retry_interval: Duration::from_millis(25),
    };
    let server = start_server_holding_the_lock_with_timing(config, timing).await;
    let (gen_before, owner_before, _) = ownership_row(&database).await.unwrap();
    assert_eq!(gen_before, 1);

    // Cut PostgreSQL for 300 ms (6x the 50 ms worker poll interval) so every permanent
    // worker loop ticks repeatedly while admission is suspended.
    proxy.cut();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !server.runtime.admitting() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server must suspend admission on session loss");

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !server.runtime.stopping(),
        "permanent workers must not exit on temporary admission suspension"
    );
    assert!(
        !server.run.is_finished(),
        "server must stay alive across a 300 ms outage with 50 ms worker polls"
    );
    assert_eq!(setup_page_status(server.address, "outage").await, Some(503));

    proxy.resume();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if setup_page_status(server.address, "recovered").await == Some(200)
                && creator_held_status(server.address, TRUSTED_KEY).await
                    == Some((200, "{\"held\":false}".to_owned()))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("server must resume same-generation serving after 300 ms outage");

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!server.run.is_finished());
    assert!(!server.runtime.stopping());
    assert_eq!(
        ownership_row(&database).await,
        Some((1, owner_before, false))
    );

    server.stop.send(()).unwrap();
    server.run.await.unwrap().unwrap();
    assert_eq!(ownership_row(&database).await, Some((1, None, false)));
    proxy.stop();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacement_fences_and_waits_out_quarantine_before_initialize_database() {
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let database = TestDatabase::create().await;
    let config_a = config_with_options(database.database_url(), TRUSTED_KEY, "400ms");
    let config_b = config_with_options(database.database_url(), TRUSTED_KEY, "400ms");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_millis(400),
        retry_interval: Duration::from_millis(25),
    };

    // Start Server A using the production startup sequence on a fresh database
    // (where process_ownership does not yet exist before migrations).
    let settling_entered = Arc::new(tokio::sync::Notify::new());
    let settling_unwound = Arc::new(AtomicBool::new(false));
    let mut lock_a = acquire_process_lock(&config_a, Duration::ZERO)
        .await
        .unwrap();
    let pool_a = initialize_database_holding_process_lock(&config_a, &mut lock_a, timing)
        .await
        .unwrap();
    assert!(lock_a.claimed_ownership().is_some());
    let server_a_builder = Server::build(config_a, pool_a)
        .await
        .unwrap()
        .with_test_settling_pass({
            let entered = settling_entered.clone();
            let unwound = settling_unwound.clone();
            move || async move {
                let _guard = DropFlag(unwound);
                entered.notify_one();
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    let server_a = spawn_running_server(server_a_builder, lock_a, timing).await;
    settling_entered.notified().await;
    let [holder_a] = lock_holder_pids(&database).await[..] else {
        panic!("server A must hold the advisory lock");
    };

    // Queue replacement B using the production startup path: acquire_process_lock
    // followed immediately by initialize_database_holding_process_lock.
    let init_finished_at = Arc::new(Mutex::new(None::<Instant>));
    let (stop_b, stopped_b) = tokio::sync::oneshot::channel::<()>();
    let replacement_run = tokio::spawn({
        let init_finished_at = init_finished_at.clone();
        async move {
            let mut lock_b = acquire_process_lock_blocking(&config_b).await.unwrap();
            let pool_b = initialize_database_holding_process_lock(&config_b, &mut lock_b, timing)
                .await
                .unwrap();
            *init_finished_at.lock().unwrap() = Some(Instant::now());
            let server_b = Server::build(config_b, pool_b).await.unwrap();
            let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            server_b
                .run_holding_process_lock_until(listener_b, lock_b, timing, async move {
                    let _ = stopped_b.await;
                })
                .await
        }
    });
    wait_until_lock_waiter_is_queued(&database).await;

    terminate(&database, holder_a).await;

    // Replacement B must fence A immediately while still waiting inside
    // initialize_database_holding_process_lock (before finishing initialization).
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if matches!(ownership_row(&database).await, Some((1, Some(_), true))) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("replacement must fence prior owner during startup quarantine");
    assert!(
        init_finished_at.lock().unwrap().is_none(),
        "initialize_database must not complete while server A is still draining/quarantined"
    );

    let stopped_a = tokio::time::timeout(Duration::from_secs(3), server_a.run)
        .await
        .expect("server A must terminate within bounded lock-loss limit")
        .unwrap();
    let a_finished_at = Instant::now();
    assert!(matches!(
        stopped_a,
        Err(RunError::ProcessLockLost(ProcessLockLoss::HeldElsewhere))
    ));
    assert!(settling_unwound.load(Ordering::SeqCst));

    // Wait for replacement B's quarantine to expire and initialize_database to finish.
    let b_init_done = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(at) = *init_finished_at.lock().unwrap() {
                return at;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("replacement must finish initialize_database once quarantine expires");

    assert!(
        b_init_done >= a_finished_at,
        "replacement finished initialize_database before server A completed lock-loss shutdown"
    );
    assert_eq!(ownership_row(&database).await.map(|(g, _, _)| g), Some(2));

    stop_b.send(()).unwrap();
    replacement_run.await.unwrap().unwrap();
    assert_eq!(ownership_row(&database).await, Some((2, None, false)));
    drop(server_a.stop);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_setup_completion_in_flight_retains_quarantine_on_lock_loss() {
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    struct DummyAttempt;
    impl SetupAttempt for DummyAttempt {
        fn into_any(self: Box<Self>) -> Box<dyn std::any::Any + Send> {
            self
        }
    }
    struct BlockingSetupCompleter {
        entered: Arc<tokio::sync::Notify>,
        unwound: Arc<AtomicBool>,
    }
    #[async_trait]
    impl SetupCompleter for BlockingSetupCompleter {
        async fn start(&self) -> Result<StartedSetup, Completion> {
            Ok(StartedSetup::new(
                "pubkyauth://test-disconnected-setup".to_owned(),
                Box::new(DummyAttempt),
            ))
        }
        async fn complete(&self, _attempt: Box<dyn SetupAttempt>) -> Completion {
            let _guard = DropFlag(self.unwound.clone());
            self.entered.notify_one();
            std::future::pending::<()>().await;
            Completion::DefinitiveFailure
        }
    }

    let database = TestDatabase::create().await;
    let config_a = config_with_options(database.database_url(), TRUSTED_KEY, "400ms");
    let config_b = config_with_options(database.database_url(), TRUSTED_KEY, "400ms");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_millis(400),
        retry_interval: Duration::from_millis(25),
    };

    let entered = Arc::new(tokio::sync::Notify::new());
    let unwound = Arc::new(AtomicBool::new(false));
    let completer = Arc::new(BlockingSetupCompleter {
        entered: entered.clone(),
        unwound: unwound.clone(),
    });

    let lock_a = acquire_process_lock(&config_a, Duration::ZERO)
        .await
        .unwrap();
    let pool_a = initialize_database(&config_a).await.unwrap();
    let server_a = spawn_running_server(
        Server::build_with_setup_completer(config_a, pool_a, completer)
            .await
            .unwrap(),
        lock_a,
        timing,
    )
    .await;

    // Start a setup flow via GET /setup and extract its flow_id.
    let (status, html_bytes) = try_http_request(
        server_a.address,
        "GET",
        "/setup?return_to=https://app.example/callback&state=disconnected",
        &[],
        b"",
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    let html = String::from_utf8(html_bytes).unwrap();
    let after_prefix = html
        .split("const flowId=\"")
        .nth(1)
        .expect("setup HTML must embed flowId");
    let flow_id = after_prefix
        .split('"')
        .next()
        .expect("flowId literal must terminate")
        .to_owned();

    // Trigger POST /setup/{flow_id}/complete and disconnect the HTTP client
    // immediately after the detached background completion task enters complete().
    let mut stream = tokio::net::TcpStream::connect(server_a.address)
        .await
        .unwrap();
    let request = format!(
        "POST /setup/{flow_id}/complete HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        server_a.address
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .expect("detached setup completion task must start");
    drop(stream);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        server_a.runtime.in_flight() >= 1,
        "disconnected setup completion must remain tracked by Runtime::in_flight"
    );

    let [holder_a] = lock_holder_pids(&database).await[..] else {
        panic!("server A must hold the advisory lock");
    };
    let replacement = start_queued_replacement_server(&database, config_b, timing).await;
    let addr_b = replacement.address;
    let stop_probing = Arc::new(AtomicBool::new(false));
    let b_saw_quarantine_503 = Arc::new(AtomicBool::new(false));
    let b_admitted_while_setup_alive = Arc::new(AtomicBool::new(false));
    let probe_b = tokio::spawn({
        let stop = stop_probing.clone();
        let saw_503 = b_saw_quarantine_503.clone();
        let early = b_admitted_while_setup_alive.clone();
        let unwound = unwound.clone();
        async move {
            while !stop.load(Ordering::Relaxed) {
                if let Some((status, _)) = creator_held_status(addr_b, TRUSTED_KEY).await {
                    if status == 503 {
                        saw_503.store(true, Ordering::SeqCst);
                    } else if !unwound.load(Ordering::SeqCst) {
                        early.store(true, Ordering::SeqCst);
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    });

    terminate(&database, holder_a).await;
    let stopped_a = tokio::time::timeout(Duration::from_secs(3), server_a.run)
        .await
        .expect("server A must stop within bounded lock-loss deadline")
        .unwrap();
    assert!(matches!(
        stopped_a,
        Err(RunError::ProcessLockLost(ProcessLockLoss::HeldElsewhere))
    ));
    assert!(
        unwound.load(Ordering::SeqCst),
        "detached setup completion task must be aborted and unwound on lock loss"
    );
    assert_eq!(server_a.runtime.in_flight(), 0);

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if creator_held_status(addr_b, TRUSTED_KEY).await
                == Some((200, "{\"held\":false}".to_owned()))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("server B must take over once quarantine lease expires");

    stop_probing.store(true, Ordering::SeqCst);
    probe_b.await.unwrap();
    assert!(!b_admitted_while_setup_alive.load(Ordering::SeqCst));
    assert!(
        b_saw_quarantine_503.load(Ordering::SeqCst),
        "quarantine must stay active rather than clearing ownership early"
    );
    assert_eq!(ownership_row(&database).await.map(|(g, _, _)| g), Some(2));

    replacement.stop.send(()).unwrap();
    replacement.run.await.unwrap().unwrap();
    drop(server_a.stop);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn barrier_held_http_request_on_old_server_blocks_replacement_admission() {
    struct DummyAttempt;
    impl SetupAttempt for DummyAttempt {
        fn into_any(self: Box<Self>) -> Box<dyn std::any::Any + Send> {
            self
        }
    }
    struct BarrierCompleter {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }
    #[async_trait]
    impl SetupCompleter for BarrierCompleter {
        async fn start(&self) -> Result<StartedSetup, Completion> {
            Ok(StartedSetup::new(
                "pubkyauth://test-barrier-request".to_owned(),
                Box::new(DummyAttempt),
            ))
        }
        async fn complete(&self, _attempt: Box<dyn SetupAttempt>) -> Completion {
            self.entered.notify_one();
            self.release.notified().await;
            Completion::DurableSuccess
        }
    }

    let database = TestDatabase::create().await;
    let config_a = config_with_options(database.database_url(), TRUSTED_KEY, "2s");
    let config_b = config_with_options(database.database_url(), TRUSTED_KEY, "2s");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(2),
        retry_interval: Duration::from_millis(25),
    };

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let completer = Arc::new(BarrierCompleter {
        entered: entered.clone(),
        release: release.clone(),
    });
    let lock_a = acquire_process_lock(&config_a, Duration::ZERO)
        .await
        .unwrap();
    let pool_a = initialize_database(&config_a).await.unwrap();
    let server_a = spawn_running_server(
        Server::build_with_setup_completer(config_a, pool_a, completer)
            .await
            .unwrap(),
        lock_a,
        timing,
    )
    .await;

    let (status, html_bytes) = try_http_request(
        server_a.address,
        "GET",
        "/setup?return_to=https://app.example/callback&state=barrier",
        &[],
        b"",
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    let html = String::from_utf8(html_bytes).unwrap();
    let flow_id = html
        .split("const flowId=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();

    // Hold a live connected HTTP request inside Server A at the barrier.
    let held_request = tokio::spawn({
        let addr_a = server_a.address;
        async move {
            let response = try_http_request(
                addr_a,
                "POST",
                &format!("/setup/{flow_id}/complete"),
                &[],
                b"",
            )
            .await
            .unwrap();
            (response.0, Instant::now())
        }
    });
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .expect("barrier-held HTTP request must enter handler");

    let [holder_a] = lock_holder_pids(&database).await[..] else {
        panic!("server A must hold the advisory lock");
    };
    let replacement = start_queued_replacement_server(&database, config_b, timing).await;
    let addr_b = replacement.address;

    terminate(&database, holder_a).await;

    // While Server A's HTTP request stays held at the barrier, Server B must
    // remain quarantined and reject business requests with 503.
    let mut b_saw_503 = false;
    for _ in 0..25 {
        if let Some((status, _)) = creator_held_status(addr_b, TRUSTED_KEY).await {
            assert_eq!(
                status, 503,
                "server B must not admit business requests while Server A's HTTP request is held"
            );
            b_saw_503 = true;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert!(
        b_saw_503,
        "server B must answer 503 while Server A's request is held at the barrier"
    );

    // Release Server A's barrier-held request so A finishes draining cleanly.
    release.notify_one();
    let (held_status, held_completed_at) =
        tokio::time::timeout(Duration::from_secs(3), held_request)
            .await
            .expect("held HTTP request on server A must complete once barrier releases")
            .unwrap();
    assert_eq!(held_status, 200);

    let stopped_a = tokio::time::timeout(Duration::from_secs(3), server_a.run)
        .await
        .expect("server A must exit cleanly after barrier-held request finishes")
        .unwrap();
    assert!(matches!(
        stopped_a,
        Err(RunError::ProcessLockLost(ProcessLockLoss::HeldElsewhere))
    ));

    // Server B must now take over cleanly and admit business traffic strictly after.
    let b_first_admitted_at = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let req_started = Instant::now();
            if creator_held_status(addr_b, TRUSTED_KEY).await
                == Some((200, "{\"held\":false}".to_owned()))
            {
                return req_started;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("server B must admit business requests after server A drains cleanly");
    assert!(
        b_first_admitted_at >= held_completed_at,
        "server B admitted before server A's barrier-held request finished"
    );
    assert_eq!(ownership_row(&database).await.map(|(g, _, _)| g), Some(2));

    replacement.stop.send(()).unwrap();
    replacement.run.await.unwrap().unwrap();
    drop(server_a.stop);
    database.cleanup().await;
}

#[tokio::test]
async fn lost_claim_response_reconnect_reclaims_same_owner_without_spinning() {
    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let pool = initialize_database(&config).await.unwrap();
    let owner_id = Uuid::new_v4();

    // Simulate a prior claim_ownership commit whose response dropped before reaching the client.
    sqlx::query(
        "INSERT INTO process_ownership (id, generation, owner_id, fenced, lease_expires_at)
         VALUES (1, 3, $1, FALSE, clock_timestamp() + INTERVAL '30 seconds')",
    )
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();

    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(2),
        retry_interval: Duration::from_millis(50),
    };
    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let started = Instant::now();
    let ownership = tokio::time::timeout(
        Duration::from_secs(2),
        lock.claim_ownership(owner_id, timing, Duration::from_secs(1)),
    )
    .await
    .expect("reclaiming own committed owner_id must not wait for 30 s lease expiry or spin")
    .unwrap();
    assert_eq!(ownership.owner_id(), owner_id);
    assert_eq!(ownership.generation(), 3);
    assert!(started.elapsed() < Duration::from_secs(1));

    // If that same owner_id was fenced meanwhile, reclaim must fail closed immediately.
    sqlx::query("UPDATE process_ownership SET fenced = TRUE WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap();
    let fenced = tokio::time::timeout(
        Duration::from_secs(2),
        lock.claim_ownership(owner_id, timing, Duration::from_secs(1)),
    )
    .await
    .expect("fenced owner_id must fail closed immediately");
    assert_eq!(fenced.err(), Some(ProcessLockLoss::HeldElsewhere));

    pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_during_claim_clears_committed_owner_row() {
    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(2),
        retry_interval: Duration::from_millis(25),
    };
    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database_holding_process_lock(&config, &mut lock, timing)
        .await
        .unwrap();
    assert!(matches!(
        ownership_row(&database).await,
        Some((1, Some(_), false))
    ));

    let server = Server::build(config_for(&database), pool).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Shutdown is already ready before the server opens admission.
    server
        .run_holding_process_lock_until(listener, lock, timing, async {})
        .await
        .unwrap();

    // The pre-serving shutdown must clear process_ownership so no 40 s quarantine remains.
    assert_eq!(ownership_row(&database).await, Some((1, None, false)));
    let next = acquire_process_lock(&config_for(&database), Duration::ZERO)
        .await
        .expect("advisory lock must also be released");
    next.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigterm_while_suspended_bounds_stalled_settling_and_retains_quarantine() {
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let database = TestDatabase::create().await;
    let proxy = ToggleProxy::start(database.database_url()).await;
    let config = config_with_options(&proxy.database_url, TRUSTED_KEY, "500ms");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(5),
        retry_interval: Duration::from_millis(25),
    };

    let settling_entered = Arc::new(tokio::sync::Notify::new());
    let settling_unwound = Arc::new(AtomicBool::new(false));
    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database_holding_process_lock(&config, &mut lock, timing)
        .await
        .unwrap();
    let server = Server::build(config, pool)
        .await
        .unwrap()
        .with_test_settling_pass({
            let entered = settling_entered.clone();
            let unwound = settling_unwound.clone();
            move || async move {
                let _guard = DropFlag(unwound);
                entered.notify_one();
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    let server = spawn_running_server(server, lock, timing).await;
    settling_entered.notified().await;

    // Sever PostgreSQL so hold_owned suspends admission and enters its 5 s reacquire loop.
    proxy.cut();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !server.runtime.owns_process_lock() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("server must suspend ownership on session loss");
    assert!(!server.runtime.stopping());

    // Deliver SIGTERM while suspended: must immediately enter bounded lock-loss
    // termination (500 ms), unwind the stalled 30 s settling pass, and keep quarantine.
    let stop_sent_at = Instant::now();
    server.stop.send(()).unwrap();
    let stopped = tokio::time::timeout(Duration::from_secs(2), server.run)
        .await
        .expect("SIGTERM while suspended must terminate within lock-loss drain limit")
        .unwrap();
    assert!(matches!(
        stopped,
        Err(RunError::ProcessLockLost(ProcessLockLoss::Unreachable))
    ));
    assert!(stop_sent_at.elapsed() < Duration::from_millis(1500));
    assert!(
        settling_unwound.load(Ordering::SeqCst),
        "stalled settling pass must be unwound before return"
    );
    assert!(
        matches!(ownership_row(&database).await, Some((1, Some(_), false))),
        "quarantine must be retained when SIGTERM arrives while suspended"
    );

    proxy.stop();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_drain_exceeding_lease_ttl_renews_while_healthy_and_escalates_on_lock_drop() {
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    // Part 1: Healthy graceful drain outliving 2x initial lease_ttl keeps renewing
    // ownership in PostgreSQL, completes settling cleanly, and clears ownership.
    let database = TestDatabase::create().await;
    let config = config_with_options(database.database_url(), TRUSTED_KEY, "400ms");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_millis(200),
        retry_interval: Duration::from_millis(25),
    };
    let initial_ttl = timing.lease_ttl(Duration::from_millis(400));
    let settling_duration = initial_ttl.saturating_mul(2) + Duration::from_millis(200);

    let settling_entered = Arc::new(tokio::sync::Notify::new());
    let settled_cleanly = Arc::new(AtomicBool::new(false));
    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database_holding_process_lock(&config, &mut lock, timing)
        .await
        .unwrap();
    let server = Server::build(config, pool)
        .await
        .unwrap()
        .with_test_settling_pass({
            let entered = settling_entered.clone();
            let settled = settled_cleanly.clone();
            move || async move {
                entered.notify_one();
                tokio::time::sleep(settling_duration).await;
                settled.store(true, Ordering::SeqCst);
            }
        });
    let server = spawn_running_server(server, lock, timing).await;
    settling_entered.notified().await;

    let initial_expiry: time::OffsetDateTime =
        sqlx::query_scalar("SELECT lease_expires_at FROM process_ownership WHERE id = 1")
            .fetch_one(database.pool())
            .await
            .unwrap();

    server.stop.send(()).unwrap();
    let mut observed_advances = 0_usize;
    let mut last_expiry = initial_expiry;
    let drain_watcher = async {
        loop {
            let row: Option<(Option<time::OffsetDateTime>, bool)> = sqlx::query_as(
                "SELECT lease_expires_at, \
                        COALESCE(lease_expires_at > clock_timestamp(), TRUE) \
                 FROM process_ownership WHERE id = 1",
            )
            .fetch_optional(database.pool())
            .await
            .unwrap();
            let Some((maybe_expiry, unexpired)) = row else {
                panic!("process_ownership row must exist");
            };
            let Some(expiry) = maybe_expiry else {
                break;
            };
            assert!(
                unexpired,
                "healthy graceful drain must keep renewing lease before expiry"
            );
            if expiry > last_expiry {
                observed_advances += 1;
                last_expiry = expiry;
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
    };
    let (run_res, ()) = tokio::time::timeout(settling_duration + Duration::from_secs(3), async {
        tokio::join!(server.run, drain_watcher)
    })
    .await
    .expect("healthy graceful drain must finish cleanly");
    run_res.unwrap().unwrap();
    assert!(settled_cleanly.load(Ordering::SeqCst));
    assert!(
        observed_advances >= 3,
        "graceful drain exceeding 2x lease_ttl must repeatedly renew ownership (advances={observed_advances})"
    );
    assert_eq!(ownership_row(&database).await, Some((1, None, false)));
    database.cleanup().await;

    // Part 2: When the lock session drops mid-graceful-drain, immediately escalate to bounded
    // lock-loss termination (aborting stalled 30 s settling pass) and retain quarantine.
    let database = TestDatabase::create().await;
    let config = config_with_options(database.database_url(), TRUSTED_KEY, "500ms");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(5),
        retry_interval: Duration::from_millis(25),
    };
    let settling_entered = Arc::new(tokio::sync::Notify::new());
    let settling_unwound = Arc::new(AtomicBool::new(false));
    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database_holding_process_lock(&config, &mut lock, timing)
        .await
        .unwrap();
    let server = Server::build(config, pool)
        .await
        .unwrap()
        .with_test_settling_pass({
            let entered = settling_entered.clone();
            let unwound = settling_unwound.clone();
            move || async move {
                let _guard = DropFlag(unwound);
                entered.notify_one();
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    let server = spawn_running_server(server, lock, timing).await;
    settling_entered.notified().await;
    let [holder] = lock_holder_pids(&database).await[..] else {
        panic!("server must hold the advisory lock");
    };

    // Start healthy graceful shutdown, wait briefly so graceful drain is active,
    // then kill the dedicated lock session mid-drain.
    server.stop.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!settling_unwound.load(Ordering::SeqCst));
    let killed_at = Instant::now();
    terminate(&database, holder).await;

    let stopped = tokio::time::timeout(Duration::from_secs(2), server.run)
        .await
        .expect("mid-drain lock loss must escalate out of graceful drain in bounded time")
        .unwrap();
    assert!(matches!(stopped, Err(RunError::ProcessLockLost(_))));
    assert!(killed_at.elapsed() < Duration::from_millis(1500));
    assert!(
        settling_unwound.load(Ordering::SeqCst),
        "escalated lock-loss shutdown must abort and unwind stalled settling pass"
    );
    assert!(
        matches!(ownership_row(&database).await, Some((1, Some(_), false))),
        "mid-drain lock loss must not call release_owned and must retain quarantine"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_claim_startup_exceeding_two_lease_ttls_renews_and_cancels_on_lock_drop() {
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    // Part 1: Slow post-claim startup exceeding 2x lease_ttl continuously renews
    // process_ownership without expiring.
    let database = TestDatabase::create().await;
    let config = config_with_options(database.database_url(), TRUSTED_KEY, "200ms");
    // Pre-migrate so public.process_ownership exists and claim runs before startup work.
    initialize_database(&config).await.unwrap().close().await;

    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_millis(200),
        retry_interval: Duration::from_millis(25),
    };
    let lease_ttl = timing.lease_ttl(Duration::from_millis(200));
    let slow_startup_duration = lease_ttl.saturating_mul(2) + Duration::from_millis(200);

    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let owner_id = Uuid::new_v4();
    let observe_pool = database.pool().clone();
    let observed_advances = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let advances_clone = observed_advances.clone();

    let pool = initialize_database_holding_process_lock_with_post_claim_hook(
        &config,
        &mut lock,
        owner_id,
        timing,
        async move {
            let started = Instant::now();
            let mut last_expiry: time::OffsetDateTime =
                sqlx::query_scalar("SELECT lease_expires_at FROM process_ownership WHERE id = 1")
                    .fetch_one(&observe_pool)
                    .await
                    .unwrap();
            while started.elapsed() < slow_startup_duration {
                tokio::time::sleep(Duration::from_millis(120)).await;
                let (expiry, unexpired): (time::OffsetDateTime, bool) = sqlx::query_as(
                    "SELECT lease_expires_at, lease_expires_at > clock_timestamp() \
                     FROM process_ownership WHERE id = 1",
                )
                .fetch_one(&observe_pool)
                .await
                .unwrap();
                assert!(
                    unexpired,
                    "startup supervisor must keep renewing lease before expiry"
                );
                if expiry > last_expiry {
                    advances_clone.fetch_add(1, Ordering::SeqCst);
                    last_expiry = expiry;
                }
            }
        },
    )
    .await
    .expect("slow post-claim startup exceeding 2x lease_ttl must succeed with continuous renewal");
    assert!(
        observed_advances.load(Ordering::SeqCst) >= 3,
        "expected repeated renewals during slow startup"
    );
    assert_eq!(
        ownership_row(&database).await,
        Some((1, Some(owner_id), false))
    );
    lock.release_claimed().await.unwrap();
    assert_eq!(ownership_row(&database).await, Some((1, None, false)));
    pool.close().await;

    // Part 2: Dropping the lock session mid-startup cancels post-claim work immediately
    // and retains quarantine rather than clearing ownership.
    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let owner_id = Uuid::new_v4();
    let hook_entered = Arc::new(tokio::sync::Notify::new());
    let hook_cancelled = Arc::new(AtomicBool::new(false));
    let startup_task = tokio::spawn({
        let config = config_with_options(database.database_url(), TRUSTED_KEY, "200ms");
        let entered = hook_entered.clone();
        let cancelled = hook_cancelled.clone();
        async move {
            initialize_database_holding_process_lock_with_post_claim_hook(
                &config,
                &mut lock,
                owner_id,
                timing,
                async move {
                    let _guard = DropFlag(cancelled);
                    entered.notify_one();
                    std::future::pending::<()>().await;
                },
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(3), hook_entered.notified())
        .await
        .expect("post-claim startup hook must start");
    let [holder] = lock_holder_pids(&database).await[..] else {
        panic!("startup lock session must hold advisory lock");
    };
    terminate(&database, holder).await;

    let result = tokio::time::timeout(Duration::from_secs(2), startup_task)
        .await
        .expect("startup must cancel promptly when lock session drops")
        .unwrap();
    assert_eq!(result.err(), Some(StartupError::Connection));
    assert!(
        hook_cancelled.load(Ordering::SeqCst),
        "post-claim startup future must be dropped immediately on lock loss"
    );
    assert_eq!(
        ownership_row(&database).await,
        Some((2, Some(owner_id), false)),
        "lock loss mid-startup must retain quarantine instead of clearing ownership"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_lock_connection_after_claim_uses_pooled_cleanup_fallback_on_shutdown() {
    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(2),
        retry_interval: Duration::from_millis(25),
    };

    // Part 1: Direct check that clear_owner_if_claimed returns Err when connection is absent.
    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database_holding_process_lock(&config, &mut lock, timing)
        .await
        .unwrap();
    let owner_id = lock.claimed_ownership().unwrap().owner_id();
    lock.drop_connection_for_test();
    assert!(
        lock.clear_owner_if_claimed(owner_id).await.is_err(),
        "clear_owner_if_claimed must return Err when dedicated connection is absent"
    );
    assert_eq!(
        ownership_row(&database).await,
        Some((1, Some(owner_id), false))
    );
    pool.close().await;

    // Reset row cleanly for Part 2.
    sqlx::query(
        "UPDATE process_ownership \
         SET owner_id = NULL, fenced = FALSE, lease_expires_at = NULL WHERE id = 1",
    )
    .execute(database.pool())
    .await
    .unwrap();

    // Part 2: Server::run_holding_process_lock_until with dropped dedicated connection
    // and pre-serving shutdown falls back to pooled clear_process_owner_if_claimed.
    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database_holding_process_lock(&config, &mut lock, timing)
        .await
        .unwrap();
    let owner_id = lock.claimed_ownership().unwrap().owner_id();
    assert_eq!(
        ownership_row(&database).await,
        Some((2, Some(owner_id), false))
    );
    lock.drop_connection_for_test();

    let server = Server::build(config_for(&database), pool).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    server
        .run_holding_process_lock_until(listener, lock, timing, async {})
        .await
        .unwrap();

    assert_eq!(
        ownership_row(&database).await,
        Some((2, None, false)),
        "shutdown with dropped lock connection must clear process_ownership via pooled fallback"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_owner_with_fallback_uses_direct_connection_when_pool_fails() {
    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(2),
        retry_interval: Duration::from_millis(25),
    };

    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database_holding_process_lock(&config, &mut lock, timing)
        .await
        .unwrap();
    let owner_id = lock.claimed_ownership().unwrap().owner_id();
    assert_eq!(
        ownership_row(&database).await,
        Some((1, Some(owner_id), false))
    );

    // Drop the dedicated lock connection AND close the supplied PgPool so both primary
    // and pooled paths fail; clear_owner_with_fallback must still clear via direct options.
    lock.drop_connection_for_test();
    pool.close().await;
    lock.clear_owner_with_fallback(owner_id, Some(&pool))
        .await
        .expect("direct connection fallback must clear unfenced owner when pool fails");

    assert_eq!(ownership_row(&database).await, Some((1, None, false)));
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suspended_ownership_during_cold_cache_import_rejects_and_does_not_cache() {
    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let pool = initialize_database(&config).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(config.master_key().as_bytes()).unwrap());
    let creators = CreatorStore::new(&pool, crypto);

    let testnet = EphemeralTestnet::builder()
        .postgres(
            pubky_testnet::pubky_homeserver::ConnectionString::new(
                &std::env::var("TEST_DATABASE_URL").unwrap(),
            )
            .unwrap(),
        )
        .with_http_relay()
        .build()
        .await
        .unwrap();
    let pubky = testnet.sdk().unwrap();
    let auth_relay = paykit_server_e2e::auth_relay_inbox(&testnet.http_relay().local_url());
    let root = PubkyLocalSecretKey::new(Keypair::random().secret_key());
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let signed_up = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.bitkit.wallet")
        .unwrap()
        .with_auth_relay(&auth_relay)
        .unwrap()
        .sign_up(
            &root,
            &homeserver,
            None,
            PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let grant = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server")
        .unwrap()
        .with_auth_relay(&auth_relay)
        .unwrap()
        .sign_in(&root, PAYKIT_SESSION_CAPABILITIES)
        .await
        .unwrap();
    let session_secret = grant
        .export_session_secret()
        .await
        .unwrap()
        .as_str()
        .to_owned();
    let creator = parse_creator(&signed_up.public_key.to_app_key()).unwrap();
    let paykit_key = root.derive_paykit_identity_secret_key(1).unwrap();
    creators
        .create(&CreatorCredentials::new(
            creator.clone(),
            session_secret,
            paykit_key,
            None,
            None,
        ))
        .await
        .unwrap();

    let server = Server::build(config_for(&database), pool.clone())
        .await
        .unwrap();
    let runtime = server.runtime();
    runtime.grant_ownership_until(tokio::time::Instant::now() + Duration::from_secs(30));

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let sessions = CreatorSessions::new(creators, pubky, config.paykit.clone())
        .with_runtime_for_test(runtime.clone());
    let provider = sessions
        .provider(&creator)
        .with_import_gate_for_test(entered.clone(), release.clone());

    let load = tokio::spawn({
        let provider = provider.clone();
        async move { provider.load_session_access().await }
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .expect("cold-cache import must reach import_session");
    assert!(
        runtime.in_flight() >= 1,
        "in-flight cold-cache import must be tracked by Runtime"
    );

    // Suspend ownership while import_session().await is still in flight.
    runtime.suspend_admission();
    release.notify_one();

    let error = tokio::time::timeout(Duration::from_secs(5), load)
        .await
        .expect("import must finish after gate release")
        .unwrap()
        .expect_err("post-await ownership revocation must reject imported access");
    assert!(
        error
            .to_string()
            .contains("server process ownership is inactive"),
        "unexpected error: {error}"
    );
    assert!(
        !provider.is_cached_for_test().await,
        "rejected import must not populate the session cache"
    );
    assert_eq!(runtime.in_flight(), 0);

    // Once ownership resumes cleanly, a subsequent cold-cache load succeeds and caches.
    runtime.grant_ownership_until(tokio::time::Instant::now() + Duration::from_secs(30));
    let load = tokio::spawn({
        let provider = provider.clone();
        async move { provider.load_session_access().await }
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .expect("second import must enter gate");
    release.notify_one();
    assert!(load.await.unwrap().unwrap().is_some());
    assert!(provider.is_cached_for_test().await);

    pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_setup_completion_is_aborted_and_joined_on_graceful_shutdown() {
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    struct DummyAttempt;
    impl SetupAttempt for DummyAttempt {
        fn into_any(self: Box<Self>) -> Box<dyn std::any::Any + Send> {
            self
        }
    }
    struct StalledSetupCompleter {
        entered: Arc<tokio::sync::Notify>,
        unwound: Arc<AtomicBool>,
    }
    #[async_trait]
    impl SetupCompleter for StalledSetupCompleter {
        async fn start(&self) -> Result<StartedSetup, Completion> {
            Ok(StartedSetup::new(
                "pubkyauth://test-graceful-stalled-setup".to_owned(),
                Box::new(DummyAttempt),
            ))
        }
        async fn complete(&self, _attempt: Box<dyn SetupAttempt>) -> Completion {
            let _guard = DropFlag(self.unwound.clone());
            self.entered.notify_one();
            std::future::pending::<()>().await;
            Completion::DefinitiveFailure
        }
    }

    let database = TestDatabase::create().await;
    let config = config_with_options(database.database_url(), TRUSTED_KEY, "400ms");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(2),
        retry_interval: Duration::from_millis(25),
    };
    let entered = Arc::new(tokio::sync::Notify::new());
    let unwound = Arc::new(AtomicBool::new(false));
    let completer = Arc::new(StalledSetupCompleter {
        entered: entered.clone(),
        unwound: unwound.clone(),
    });

    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database_holding_process_lock(&config, &mut lock, timing)
        .await
        .unwrap();
    let server = spawn_running_server(
        Server::build_with_setup_completer(config, pool, completer)
            .await
            .unwrap(),
        lock,
        timing,
    )
    .await;

    let (status, html_bytes) = try_http_request(
        server.address,
        "GET",
        "/setup?return_to=https://app.example/callback&state=graceful-stalled",
        &[],
        b"",
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    let html = String::from_utf8(html_bytes).unwrap();
    let flow_id = html
        .split("const flowId=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();

    let mut stream = tokio::net::TcpStream::connect(server.address)
        .await
        .unwrap();
    let request = format!(
        "POST /setup/{flow_id}/complete HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        server.address
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .expect("detached setup completion must start");
    drop(stream);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(server.runtime.in_flight() >= 1);

    // Trigger healthy graceful shutdown: stalled setup completion must be aborted
    // and joined under drain_timeout before run_holding unlocks and returns.
    let stop_at = Instant::now();
    server.stop.send(()).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(2), server.run)
        .await
        .expect("graceful shutdown must bound stalled setup completion")
        .unwrap();
    assert!(outcome.is_ok());
    assert!(
        stop_at.elapsed() <= Duration::from_millis(550),
        "graceful shutdown must complete within 400 ms drain_timeout plus minimal slack: {:?}",
        stop_at.elapsed()
    );
    assert!(
        unwound.load(Ordering::SeqCst),
        "stalled setup completion task must have been aborted and joined before unlock"
    );
    assert_eq!(server.runtime.in_flight(), 0);
    // Because graceful drain timed out and force-aborted in-flight setup work,
    // durable ownership stays quarantined instead of calling release_owned.
    assert!(matches!(
        ownership_row(&database).await,
        Some((1, Some(_), false))
    ));
    let next = acquire_process_lock(&config_for(&database), Duration::ZERO)
        .await
        .expect("advisory lock must be released after graceful shutdown");
    next.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setup_commit_checkpoint_drains_on_healthy_sigterm_and_fails_closed_on_suspension() {
    struct BarrierPublisher {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        publish_calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[async_trait]
    impl AppPublisher for BarrierPublisher {
        async fn verify_key(&self, _access: &PubkySessionAccess) -> Result<(), ClaimError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
        async fn publish(&self, _access: PubkySessionAccess) -> Result<(), ClaimError> {
            self.publish_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let database = TestDatabase::create().await;
    let config = config_for(&database);
    let pool = initialize_database(&config).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(config.master_key().as_bytes()).unwrap());
    let creators = CreatorStore::new(&pool, crypto);

    let testnet = EphemeralTestnet::builder()
        .postgres(
            pubky_testnet::pubky_homeserver::ConnectionString::new(
                &std::env::var("TEST_DATABASE_URL").unwrap(),
            )
            .unwrap(),
        )
        .with_http_relay()
        .build()
        .await
        .unwrap();
    let pubky = testnet.sdk().unwrap();
    let auth_relay = paykit_server_e2e::auth_relay_inbox(&testnet.http_relay().local_url());
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());

    async fn mint_creator(
        pubky: &pubky::Pubky,
        auth_relay: &str,
        homeserver: &PubkyPublicKey,
    ) -> (
        paykit_server::domain::locks::CreatorPubky,
        PubkySessionAccess,
        String,
        PaykitIdentitySecretKey,
    ) {
        let root = PubkyLocalSecretKey::new(Keypair::random().secret_key());
        let signed_up = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.bitkit.wallet")
            .unwrap()
            .with_auth_relay(auth_relay)
            .unwrap()
            .sign_up(
                &root,
                homeserver,
                None,
                PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
            )
            .await
            .unwrap();
        let grant = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server")
            .unwrap()
            .with_auth_relay(auth_relay)
            .unwrap()
            .sign_in(&root, PAYKIT_SESSION_CAPABILITIES)
            .await
            .unwrap();
        let secret = grant
            .export_session_secret()
            .await
            .unwrap()
            .as_str()
            .to_owned();
        let creator = parse_creator(&signed_up.public_key.to_app_key()).unwrap();
        let paykit_key = root.derive_paykit_identity_secret_key(1).unwrap();
        (creator, grant.access, secret, paykit_key)
    }

    // Part 1: Healthy SIGTERM paused across verify_key checkpoint drains cleanly through
    // persistence, session load, publication, and mark_setup_complete.
    let (creator_a, access_a, secret_a, key_a) =
        mint_creator(&pubky, &auth_relay, &homeserver).await;
    let server_a = Server::build(config_for(&database), pool.clone())
        .await
        .unwrap();
    let runtime_a = server_a.runtime();
    runtime_a.grant_ownership_until(tokio::time::Instant::now() + Duration::from_secs(30));

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let publish_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let publisher = Arc::new(BarrierPublisher {
        entered: entered.clone(),
        release: release.clone(),
        publish_calls: publish_calls.clone(),
    });
    let sessions_a = CreatorSessions::new(creators.clone(), pubky.clone(), config.paykit.clone())
        .with_runtime_for_test(runtime_a.clone());
    let bootstrap_a = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server")
        .unwrap()
        .with_auth_relay(&auth_relay)
        .unwrap();
    let completer_a = RealSetupCompleter::with_app_publisher(
        BitkitAuthStarter::new(bootstrap_a),
        Arc::new(PubkyCompanionRelay::new(pubky.client().clone())),
        publisher,
        creators.clone(),
        sessions_a,
        BitcoinNetwork::Testnet,
    )
    .with_runtime_for_test(runtime_a.clone());

    let claim_a = VerifiedCompanionClaim::Setup(SetupCompanionClaim {
        bitcoin_account: None,
        paykit_identity_secret_key: key_a,
        usdt_address: Some(
            UsdtAddress::try_from("0x1111111111111111111111111111111111111111".to_owned()).unwrap(),
        ),
    });
    let commit_a = tokio::spawn({
        let creator_a = creator_a.clone();
        async move {
            completer_a
                .commit_verified_claim_for_test(access_a, creator_a, secret_a, false, claim_a)
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .expect("setup commit must reach verify_key checkpoint");

    // Ordinary SIGTERM closes new admission while process-lock ownership stays healthy.
    runtime_a.begin_shutdown();
    assert!(!runtime_a.admitting());
    assert!(runtime_a.owns_process_lock());
    release.notify_one();

    tokio::time::timeout(Duration::from_secs(5), commit_a)
        .await
        .expect("admitted setup commit must finish during healthy SIGTERM")
        .unwrap()
        .expect("healthy SIGTERM must not abort already-admitted setup commit");
    assert_eq!(publish_calls.load(Ordering::SeqCst), 1);
    assert_eq!(creators.setup_complete(&creator_a).await, Ok(true));

    // Part 2: Ownership suspension across the exact same checkpoint fails closed before
    // persisting credentials or publishing.
    let (creator_b, access_b, secret_b, key_b) =
        mint_creator(&pubky, &auth_relay, &homeserver).await;
    let server_b = Server::build(config_for(&database), pool.clone())
        .await
        .unwrap();
    let runtime_b = server_b.runtime();
    runtime_b.grant_ownership_until(tokio::time::Instant::now() + Duration::from_secs(30));

    let entered_b = Arc::new(tokio::sync::Notify::new());
    let release_b = Arc::new(tokio::sync::Notify::new());
    let publish_calls_b = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let publisher_b = Arc::new(BarrierPublisher {
        entered: entered_b.clone(),
        release: release_b.clone(),
        publish_calls: publish_calls_b.clone(),
    });
    let sessions_b = CreatorSessions::new(creators.clone(), pubky.clone(), config.paykit.clone())
        .with_runtime_for_test(runtime_b.clone());
    let bootstrap_b = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server")
        .unwrap()
        .with_auth_relay(&auth_relay)
        .unwrap();
    let completer_b = RealSetupCompleter::with_app_publisher(
        BitkitAuthStarter::new(bootstrap_b),
        Arc::new(PubkyCompanionRelay::new(pubky.client().clone())),
        publisher_b,
        creators.clone(),
        sessions_b,
        BitcoinNetwork::Testnet,
    )
    .with_runtime_for_test(runtime_b.clone());

    let claim_b = VerifiedCompanionClaim::Setup(SetupCompanionClaim {
        bitcoin_account: None,
        paykit_identity_secret_key: key_b,
        usdt_address: Some(
            UsdtAddress::try_from("0x2222222222222222222222222222222222222222".to_owned()).unwrap(),
        ),
    });
    let commit_b = tokio::spawn({
        let creator_b = creator_b.clone();
        async move {
            completer_b
                .commit_verified_claim_for_test(access_b, creator_b, secret_b, false, claim_b)
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), entered_b.notified())
        .await
        .expect("second setup commit must reach verify_key checkpoint");

    runtime_b.suspend_admission();
    assert!(!runtime_b.owns_process_lock());
    release_b.notify_one();

    let result_b = tokio::time::timeout(Duration::from_secs(5), commit_b)
        .await
        .expect("suspended setup commit must return promptly")
        .unwrap();
    assert_eq!(result_b, Err(ClaimError::TransientUnavailable));
    assert_eq!(publish_calls_b.load(Ordering::SeqCst), 0);
    assert!(creators.load_optional(&creator_b).await.unwrap().is_none());

    pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn barrier_held_worker_claims_release_without_penalty_when_suspended_mid_claim() {
    struct TestPayloads {
        reader: ReaderPubky,
        address: String,
    }
    impl InvoicePayloadFactory for TestPayloads {
        fn for_child_index(&self, _child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
            Ok(InvoicePayloads {
                payment_request_intent: common::payment_intent(&self.reader, self.address.clone()),
            })
        }
    }

    async fn wait_for_xact_lock_waiter(pool: &sqlx::PgPool, lock_key: i64) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM pg_locks \
                         WHERE locktype = 'advisory' AND objsubid = 1 AND NOT granted \
                           AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
                           AND ((classid::bigint << 32) | objid::bigint) = $1 \
                     )",
                )
                .bind(lock_key)
                .fetch_one(pool)
                .await
                .unwrap();
                if waiting {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("worker claim must block on PostgreSQL barrier lock");
    }

    const OUTBOX_BARRIER_KEY: i64 = 7_111_222_333_444_001;
    const BUYER_CONTACT_BARRIER_KEY: i64 = 7_111_222_333_444_002;

    let database = TestDatabase::create().await;
    let config = config_with_poll_and_drain(database.database_url(), TRUSTED_KEY, "50ms", "5s");
    let timing = ProcessLockTiming {
        check_interval: Duration::from_secs(10),
        reacquire_within: Duration::from_secs(5),
        retry_interval: Duration::from_millis(50),
    };
    let mut lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database_holding_process_lock(&config, &mut lock, timing)
        .await
        .unwrap();

    let crypto = Arc::new(Crypto::from_master_key(config.master_key().as_bytes()).unwrap());
    let creators = CreatorStore::new(&pool, crypto.clone());
    let invoices = InvoiceStore::new(&pool, crypto.clone());
    let outbox = OutboxStore::new(&pool, crypto);

    let creator = parse_creator(TRUSTED_KEY).unwrap();
    let reader = parse_reader("pubky8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo").unwrap();
    creators
        .create(&CreatorCredentials::new(
            creator.clone(),
            "unused-secret".to_owned(),
            PaykitIdentitySecretKey::new([5_u8; 32], 1).unwrap(),
            None,
            None,
        ))
        .await
        .unwrap();
    let binding = Uuid::new_v4();
    let address = format!("tb1qbarrier{}", binding.simple());
    let payloads = TestPayloads {
        reader: reader.clone(),
        address: address.clone(),
    };
    invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: binding.as_bytes(),
            lock_resource_binding: b"barrier-lock-resource",
            payment_request_binding: binding.as_bytes(),
            invoice_payloads: &payloads,
            proposal_acceptance_seconds: 3600,
            payment_window_seconds: 86400,
        })
        .await
        .unwrap();

    // Install BEFORE UPDATE triggers on outbox and buyer_contacts that count every
    // committed UPDATE and wait on advisory locks while our test holds them.
    sqlx::raw_sql(&format!(
        "CREATE TABLE test_claim_trigger_hits (name TEXT PRIMARY KEY, hits INTEGER NOT NULL); \
         INSERT INTO test_claim_trigger_hits (name, hits) VALUES ('outbox', 0), ('buyer_contacts', 0); \
         CREATE FUNCTION delay_outbox_claim() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
             PERFORM pg_advisory_xact_lock({OUTBOX_BARRIER_KEY}); \
             UPDATE test_claim_trigger_hits SET hits = hits + 1 WHERE name = 'outbox'; \
             RETURN NEW; \
         END $$; \
         CREATE TRIGGER delay_outbox_claim BEFORE UPDATE ON outbox \
         FOR EACH ROW EXECUTE FUNCTION delay_outbox_claim(); \
         CREATE FUNCTION delay_buyer_contact_claim() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
             PERFORM pg_advisory_xact_lock({BUYER_CONTACT_BARRIER_KEY}); \
             UPDATE test_claim_trigger_hits SET hits = hits + 1 WHERE name = 'buyer_contacts'; \
             RETURN NEW; \
         END $$; \
         CREATE TRIGGER delay_buyer_contact_claim BEFORE UPDATE ON buyer_contacts \
         FOR EACH ROW EXECUTE FUNCTION delay_buyer_contact_claim();"
    ))
    .execute(&pool)
    .await
    .unwrap();

    async fn wait_for_trigger_hits(pool: &sqlx::PgPool, name: &str, expected: i32) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let hits: i32 =
                    sqlx::query_scalar("SELECT hits FROM test_claim_trigger_hits WHERE name = $1")
                        .bind(name)
                        .fetch_one(pool)
                        .await
                        .unwrap();
                if hits >= expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected {name} trigger hits >= {expected}"));
    }

    let mut barrier_conn = PgConnection::connect(database.database_url())
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(OUTBOX_BARRIER_KEY)
        .execute(&mut barrier_conn)
        .await
        .unwrap();

    // Start the real server with 50 ms worker polling.
    let server = spawn_running_server(
        Server::build(config, pool.clone()).await.unwrap(),
        lock,
        timing,
    )
    .await;

    // Class 1: Barrier-held outbox enqueue claim (process_creator_outbox).
    // Hit 1 = blocked claim commit; hit 2 = post-claim release_unstarted_claim commit.
    wait_for_xact_lock_waiter(&pool, OUTBOX_BARRIER_KEY).await;
    server.runtime.suspend_admission();
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(OUTBOX_BARRIER_KEY)
        .execute(&mut barrier_conn)
        .await
        .unwrap();
    wait_for_trigger_hits(&pool, "outbox", 2).await;
    let row: (String, i32, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT status, attempt_count, claim_token, lease_owner FROM outbox LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "queued");
    assert_eq!(row.1, 0, "enqueue release must not consume attempt budget");
    assert!(row.2.is_none());
    assert!(row.3.is_none());

    // Verify token-fenced safety: a stale enqueue claim cannot clobber a newer token.
    let claimed = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let replacement_token = Uuid::new_v4();
    sqlx::query("UPDATE outbox SET claim_token = $1 WHERE id = $2")
        .bind(replacement_token)
        .bind(claimed.id())
        .execute(&pool)
        .await
        .unwrap();
    assert!(!outbox.release_unstarted_claim(&claimed).await.unwrap());
    let token_after: Option<Uuid> =
        sqlx::query_scalar("SELECT claim_token FROM outbox WHERE id = $1")
            .bind(claimed.id())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(token_after, Some(replacement_token));

    // Class 2: Barrier-held outbox reconciliation claim (outbox_reconciliation_loop).
    sqlx::query(
        "UPDATE outbox \
         SET status = 'handed_off', \
             sdk_outbound_message_id = '42', \
             sdk_event_id = 'evt-42', \
             sdk_payment_request_id = 'req-42', \
             attempt_count = 1, \
             lease_owner = NULL, \
             claim_token = NULL, \
             lease_expires_at = NULL, \
             next_attempt_at = clock_timestamp() - INTERVAL '1 second' \
         WHERE id = $1",
    )
    .bind(claimed.id())
    .execute(&pool)
    .await
    .unwrap();
    let hits_before_rec: i32 =
        sqlx::query_scalar("SELECT hits FROM test_claim_trigger_hits WHERE name = 'outbox'")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(OUTBOX_BARRIER_KEY)
        .execute(&mut barrier_conn)
        .await
        .unwrap();
    server
        .runtime
        .grant_ownership_until(tokio::time::Instant::now() + Duration::from_secs(30));

    wait_for_xact_lock_waiter(&pool, OUTBOX_BARRIER_KEY).await;
    server.runtime.suspend_admission();
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(OUTBOX_BARRIER_KEY)
        .execute(&mut barrier_conn)
        .await
        .unwrap();
    wait_for_trigger_hits(&pool, "outbox", hits_before_rec + 2).await;
    let row: (String, i32, Option<Uuid>, bool) = sqlx::query_as(
        "SELECT status, attempt_count, claim_token, next_attempt_at <= clock_timestamp() \
         FROM outbox WHERE id = $1",
    )
    .bind(claimed.id())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "handed_off");
    assert_eq!(
        row.1, 1,
        "reconciliation release must not consume attempt budget"
    );
    assert!(row.2.is_none());
    assert!(row.3, "reconciliation row must stay immediately due");

    // Verify token-fenced safety for reconciliation release.
    let rec_claim = outbox
        .claim_reconciliation(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let replacement_rec_token = Uuid::new_v4();
    sqlx::query("UPDATE outbox SET claim_token = $1 WHERE id = $2")
        .bind(replacement_rec_token)
        .bind(rec_claim.id())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !outbox
            .release_unstarted_reconciliation_claim(&rec_claim)
            .await
            .unwrap()
    );
    // Keep outbox row delivered so Class 3 isolates buyer_contacts cleanly.
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL WHERE id = $1",
    )
    .bind(rec_claim.id())
    .execute(&pool)
    .await
    .unwrap();

    // Class 3: Barrier-held buyer_contacts claim (buyer_contacts_loop).
    let outpoint =
        BitcoinOutpoint::new(&sha256::Hash::hash(binding.as_bytes()).to_string(), 0).unwrap();
    invoices
        .apply_bitcoin_observation(&address, &outpoint, 100, 0, true)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(BUYER_CONTACT_BARRIER_KEY)
        .execute(&mut barrier_conn)
        .await
        .unwrap();
    server
        .runtime
        .grant_ownership_until(tokio::time::Instant::now() + Duration::from_secs(30));

    wait_for_xact_lock_waiter(&pool, BUYER_CONTACT_BARRIER_KEY).await;
    server.runtime.suspend_admission();
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(BUYER_CONTACT_BARRIER_KEY)
        .execute(&mut barrier_conn)
        .await
        .unwrap();
    wait_for_trigger_hits(&pool, "buyer_contacts", 2).await;
    let (is_due, completed): (bool, bool) = sqlx::query_as(
        "SELECT next_attempt_at <= clock_timestamp() + INTERVAL '5 seconds', \
                completed_at IS NOT NULL \
         FROM buyer_contacts LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        is_due,
        "suspended buyer_contact claim must restore next_attempt_at immediately"
    );
    assert!(!completed);

    // Verify CAS-fenced safety: a stale buyer_contact release never overwrites a replacement update.
    let bc_claim = invoices.claim_buyer_contact().await.unwrap().unwrap();
    sqlx::query("UPDATE buyer_contacts SET completed_at = clock_timestamp() WHERE invoice_id = $1")
        .bind(bc_claim.invoice_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !invoices
            .release_unstarted_buyer_contact(&bc_claim)
            .await
            .unwrap()
    );
    let completed_after: bool = sqlx::query_scalar(
        "SELECT completed_at IS NOT NULL FROM buyer_contacts WHERE invoice_id = $1",
    )
    .bind(bc_claim.invoice_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(completed_after);

    barrier_conn.close().await.unwrap();
    server.stop.send(()).unwrap();
    let _ = server.run.await.unwrap();
    pool.close().await;
    database.cleanup().await;
}

/// TCP proxy that forwards traffic normally until `stall_existing()` freezes all
/// already-established connections without closing their sockets (simulating a
/// TCP blackhole) while still allowing fresh connections to connect cleanly.
struct StallableProxy {
    database_url: String,
    existing_stalls: Arc<Mutex<Vec<Arc<AtomicBool>>>>,
    tasks: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl StallableProxy {
    async fn start(upstream_url: &str) -> Self {
        let mut proxied = url::Url::parse(upstream_url).unwrap();
        let upstream = format!(
            "{}:{}",
            proxied.host_str().unwrap(),
            proxied.port().unwrap_or(5432)
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        proxied.set_host(Some("127.0.0.1")).unwrap();
        proxied.set_port(Some(address.port())).unwrap();
        let existing_stalls = Arc::new(Mutex::new(Vec::<Arc<AtomicBool>>::new()));
        let tasks = Arc::new(Mutex::new(Vec::<tokio::task::AbortHandle>::new()));
        let accept_task = tokio::spawn({
            let existing_stalls = existing_stalls.clone();
            let tasks = tasks.clone();
            async move {
                loop {
                    let Ok((client, _)) = listener.accept().await else {
                        break;
                    };
                    let stalled = Arc::new(AtomicBool::new(false));
                    existing_stalls.lock().unwrap().push(stalled.clone());
                    let upstream = upstream.clone();
                    let handle = tokio::spawn(async move {
                        let Ok(server) = tokio::net::TcpStream::connect(upstream).await else {
                            return;
                        };
                        let (mut cr, mut cw) = client.into_split();
                        let (mut sr, mut sw) = server.into_split();
                        let c2s = {
                            let stalled = stalled.clone();
                            async move {
                                let mut buf = [0_u8; 4096];
                                loop {
                                    let Ok(n) = cr.read(&mut buf).await else {
                                        break;
                                    };
                                    if n == 0 {
                                        break;
                                    }
                                    if stalled.load(Ordering::SeqCst) {
                                        std::future::pending::<()>().await;
                                    }
                                    if sw.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        };
                        let s2c = {
                            let stalled = stalled.clone();
                            async move {
                                let mut buf = [0_u8; 4096];
                                loop {
                                    let Ok(n) = sr.read(&mut buf).await else {
                                        break;
                                    };
                                    if n == 0 {
                                        break;
                                    }
                                    if stalled.load(Ordering::SeqCst) {
                                        std::future::pending::<()>().await;
                                    }
                                    if cw.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        };
                        let _ = tokio::join!(c2s, s2c);
                    });
                    tasks.lock().unwrap().push(handle.abort_handle());
                }
            }
        });
        Self {
            database_url: proxied.to_string(),
            existing_stalls,
            tasks,
            accept_task,
        }
    }

    fn stall_existing(&self) {
        for flag in self.existing_stalls.lock().unwrap().iter() {
            flag.store(true, Ordering::SeqCst);
        }
    }

    fn drop_stalled(&self) {
        for handle in self.tasks.lock().unwrap().drain(..) {
            handle.abort();
        }
        self.existing_stalls.lock().unwrap().clear();
    }

    fn stop(self) {
        self.accept_task.abort();
        self.drop_stalled();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clear_owner_with_fallback_recovers_within_deadline_when_primary_connection_stalls() {
    let database = TestDatabase::create().await;
    let proxy = StallableProxy::start(database.database_url()).await;
    let proxy_config = config_with_url(&proxy.database_url);
    let direct_config = config_for(&database);
    let timing = ProcessLockTiming {
        check_interval: Duration::from_millis(100),
        reacquire_within: Duration::from_secs(2),
        retry_interval: Duration::from_millis(25),
    };

    // Part 1: Dedicated lock connection stalls past its stage cap; falls through to pool.
    let mut lock = acquire_process_lock(&proxy_config, Duration::ZERO)
        .await
        .unwrap();
    let _proxied_pool = initialize_database_holding_process_lock(&proxy_config, &mut lock, timing)
        .await
        .unwrap();
    let owner_a = lock.claimed_ownership().unwrap().owner_id();
    let direct_pool = initialize_database(&direct_config).await.unwrap();

    proxy.stall_existing();
    let started = Instant::now();
    lock.clear_owner_with_fallback(owner_a, Some(&direct_pool))
        .await
        .expect("pooled fallback must clear owner after stalled primary stage times out");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(500) && elapsed < Duration::from_secs(2),
        "primary stage must time out cleanly and fall through within shared 2 s deadline: {elapsed:?}"
    );
    assert_eq!(ownership_row(&database).await, Some((1, None, false)));
    let _ = lock.release().await;
    proxy.drop_stalled();

    // Part 2: Dedicated lock connection stalls AND supplied pool is closed; falls through
    // to short-lived direct connection within the same shared 2 s deadline.
    let mut lock = acquire_process_lock(&proxy_config, Duration::from_secs(2))
        .await
        .unwrap();
    let _proxied_pool2 = initialize_database_holding_process_lock(&proxy_config, &mut lock, timing)
        .await
        .unwrap();
    let owner_b = lock.claimed_ownership().unwrap().owner_id();
    assert_eq!(
        ownership_row(&database).await,
        Some((2, Some(owner_b), false))
    );

    proxy.stall_existing();
    direct_pool.close().await;
    let started = Instant::now();
    lock.clear_owner_with_fallback(owner_b, Some(&direct_pool))
        .await
        .expect("direct connection fallback must clear owner when primary stalls and pool fails");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(500) && elapsed < Duration::from_secs(2),
        "direct fallback must finish inside shared 2 s deadline: {elapsed:?}"
    );
    assert_eq!(ownership_row(&database).await, Some((2, None, false)));
    let _ = lock.release().await;

    proxy.stop();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_lock_connection_at_final_release_is_bounded() {
    let database = TestDatabase::create().await;
    let proxy = StallableProxy::start(database.database_url()).await;
    let proxy_config = config_with_url(&proxy.database_url);
    let direct_config = config_for(&database);
    let timing = ProcessLockTiming {
        check_interval: Duration::from_secs(10),
        reacquire_within: Duration::from_secs(2),
        retry_interval: Duration::from_millis(25),
    };

    // Part 1: Direct ProcessLock::release() on a blackholed socket times out within 1 s.
    let lock = acquire_process_lock(&proxy_config, Duration::ZERO)
        .await
        .unwrap();
    proxy.stall_existing();
    let started = Instant::now();
    let released = tokio::time::timeout(Duration::from_secs(3), lock.release())
        .await
        .expect("release() must not hang indefinitely on a stalled connection");
    assert!(released.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "release() exceeded bounded 1 s timeout: {:?}",
        started.elapsed()
    );
    proxy.drop_stalled();

    // Part 2: Full Server::run_holding_process_lock_until clean shutdown with a blackholed
    // dedicated lock connection clears ownership via fallback, bounds release(), and exits.
    let mut lock = acquire_process_lock(&proxy_config, Duration::from_secs(2))
        .await
        .unwrap();
    let _init_pool = initialize_database_holding_process_lock(&proxy_config, &mut lock, timing)
        .await
        .unwrap();
    let direct_pool = initialize_database(&direct_config).await.unwrap();
    let server = spawn_running_server(
        Server::build(direct_config, direct_pool).await.unwrap(),
        lock,
        timing,
    )
    .await;

    // Stall the dedicated lock connection right before triggering clean shutdown.
    proxy.stall_existing();
    let started = Instant::now();
    server.stop.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(4), server.run)
        .await
        .expect("run_holding must terminate in bounded time even when final release stalls")
        .unwrap();
    assert!(result.is_ok());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "bounded final release overshot expected budget: {:?}",
        started.elapsed()
    );
    assert_eq!(ownership_row(&database).await, Some((1, None, false)));

    proxy.stop();
    database.cleanup().await;
}
