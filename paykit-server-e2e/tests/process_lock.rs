//! Single-process ownership of a Paykit Server database.
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use paykit_sdk::{
    PAYKIT_AUTHORIZER_SESSION_CAPABILITIES, PaykitIdentitySecretKey, PubkyLocalSecretKey,
    PubkyPublicKey, PubkySessionBootstrap, PubkySessionProvider,
};
use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::parse_creator,
    http::auth::signature_preimage,
    paykit::CreatorSessions,
    persistence::{
        CreatorCredentials, CreatorStore, PROCESS_ADVISORY_LOCK_KEY, PROCESS_LOCK_APPLICATION_NAME,
        ProcessLockLoss, ProcessLockTiming,
    },
    server::RunError,
    setup::{Completion, SetupAttempt, SetupCompleter, StartedSetup},
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
    assert!(started.elapsed() >= Duration::from_secs(2));
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
