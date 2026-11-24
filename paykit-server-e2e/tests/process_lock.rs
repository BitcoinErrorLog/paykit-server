//! Single-process ownership of a Paykit Server database.
use std::time::{Duration, Instant};

use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment},
    persistence::{
        PROCESS_ADVISORY_LOCK_KEY, PROCESS_LOCK_APPLICATION_NAME, ProcessLockLoss,
        ProcessLockTiming,
    },
    server::RunError,
    startup::{StartupError, acquire_process_lock, initialize_database},
};
use paykit_server_e2e::postgres::TestDatabase;
use sqlx::{Connection, PgConnection};

const TRUSTED_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn config_for(database: &TestDatabase) -> Config {
    config_with_url(database.database_url())
}

fn config_with_url(database_url: &str) -> Config {
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
endpoint = "tcp://127.0.0.1:9"
connect_retries = 0
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
    stop: tokio::sync::oneshot::Sender<()>,
    run: tokio::task::JoinHandle<Result<(), RunError>>,
    runtime: std::sync::Arc<paykit_server::runtime::Runtime>,
}

async fn start_server_holding_the_lock(config: Config) -> RunningServer {
    let lock = acquire_process_lock(&config, Duration::ZERO).await.unwrap();
    let pool = initialize_database(&config).await.unwrap();
    let server = Server::build(config, pool).await.unwrap();
    let runtime = server.runtime();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(server.run_holding_process_lock_until(
        listener,
        lock,
        SERVER_LOCK_TIMING,
        async move {
            let _ = stopped.await;
        },
    ));
    RunningServer { stop, run, runtime }
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
