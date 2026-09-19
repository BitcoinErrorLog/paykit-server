use std::{
    any::Any,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use async_trait::async_trait;
use paykit_server::setup::{
    CancellationStore, Completion, ManualClock, PostgresCancellationStore, SetupAttempt,
    SetupCompleter, SetupLimits, SetupService, StartedSetup,
};
use paykit_server_e2e::postgres::TestDatabase;

const CREATOR: &str = "tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

struct Attempt;

impl SetupAttempt for Attempt {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

struct Completer;

#[async_trait]
impl SetupCompleter for Completer {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        Ok(StartedSetup::new(
            "https://bitkit.example/auth".into(),
            Box::new(Attempt),
        ))
    }

    async fn complete(
        &self,
        _attempt: Box<dyn SetupAttempt>,
        _expected_creator: &paykit_sdk::PubkyPublicKey,
    ) -> Completion {
        Completion::DurableSuccess
    }
}

fn service(store: Arc<dyn CancellationStore>) -> SetupService {
    SetupService::with_cancellation_store(
        vec!["https://app.example".into()],
        Arc::new(Completer),
        Arc::new(ManualClock::default()),
        SetupLimits {
            max_polls_per_flow: 2,
            max_polls: 2,
            setup_per_ip_per_minute: 10,
            max_pending_setup_flows: 2,
        },
        store,
    )
}

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[tokio::test]
async fn postgres_cancellation_is_durable_idempotent_and_preserves_completed_flow() {
    let database = TestDatabase::create().await;
    paykit_server::persistence::run_migrations(database.pool())
        .await
        .unwrap();
    let store: Arc<dyn CancellationStore> =
        Arc::new(PostgresCancellationStore::new(database.pool().clone()));
    let setup = service(store);
    let pending = setup
        .begin(peer(), "https://app.example", "pending", CREATOR)
        .await
        .unwrap();

    assert_eq!(
        setup.cancel(peer(), &pending.flow_id).await,
        paykit_server::setup::CancelResult::Cancelled
    );
    let tombstones: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM setup_flow_cancellations WHERE flow_id = $1")
            .bind(&pending.flow_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(tombstones, 1);
    assert_eq!(
        setup.cancel(peer(), &pending.flow_id).await,
        paykit_server::setup::CancelResult::Cancelled
    );

    let completed = setup
        .begin(peer(), "https://app.example", "completed", CREATOR)
        .await
        .unwrap();
    assert_eq!(
        setup.trigger_completion(&completed.flow_id).await,
        paykit_server::setup::PollResult::Complete
    );
    assert_eq!(
        setup.cancel(peer(), &completed.flow_id).await,
        paykit_server::setup::CancelResult::Complete
    );
    database.cleanup().await;
}
