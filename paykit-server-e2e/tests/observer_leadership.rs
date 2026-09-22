//! Cluster-single observer leadership over a Postgres TTL lease.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use paykit_server::{
    crypto::Crypto,
    persistence::{
        InvoiceStore, OBSERVER_LEADERSHIP_LEASE_NAME, PersistenceError, PgObserverLeadership,
        run_migrations,
    },
};
use paykit_server_e2e::postgres::TestDatabase;

const LEASE_TTL: Duration = Duration::from_secs(30);
const STAMP_ADDRESS: &str = "bcrt1qobserverleadershiptickstamp000000000000";

fn invoices(pool: &sqlx::PgPool) -> InvoiceStore {
    InvoiceStore::new(
        pool,
        Arc::new(Crypto::from_master_key(&[7; 32]).expect("test master key")),
    )
}

async fn stamp(
    invoices: &InvoiceStore,
    lease: paykit_server::persistence::ObserverLease,
) -> Result<u64, PersistenceError> {
    invoices
        .clone()
        .with_observer_lease(lease)
        .record_observation_tick(&[STAMP_ADDRESS.to_owned()], &[])
        .await
}

#[tokio::test]
async fn one_holder_acquires_and_renews_without_bumping_fence() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();

    let first = PgObserverLeadership::new(database.pool(), LEASE_TTL);
    let second = PgObserverLeadership::new(database.pool(), LEASE_TTL);

    let first_lease = first.acquire().await.unwrap().expect("first holder");
    assert_eq!(first_lease.fence, 1);
    assert_eq!(first_lease.holder, first.holder());
    assert!(
        second.acquire().await.unwrap().is_none(),
        "a live lease must keep the second replica on standby"
    );

    let renewed = first.acquire().await.unwrap().expect("renew");
    assert_eq!(renewed.fence, 1, "renew must not bump the fencing token");
    assert_eq!(renewed.holder, first.holder());
    assert!(second.acquire().await.unwrap().is_none());

    first.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn release_hands_over_and_bumps_fence() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();

    let first = PgObserverLeadership::new(database.pool(), LEASE_TTL);
    let second = PgObserverLeadership::new(database.pool(), LEASE_TTL);

    let first_lease = first.acquire().await.unwrap().expect("first holder");
    assert_eq!(first_lease.fence, 1);
    first.release().await.unwrap();

    let second_lease = second.acquire().await.unwrap().expect("handover");
    assert_eq!(second_lease.fence, 2);
    assert_eq!(second_lease.holder, second.holder());
    assert!(first.acquire().await.unwrap().is_none());

    let third = PgObserverLeadership::new(database.pool(), LEASE_TTL);
    assert!(third.acquire().await.unwrap().is_none());

    second.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn expired_lease_lets_a_peer_take_over() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();

    let first = PgObserverLeadership::new(database.pool(), Duration::from_secs(1));
    let second = PgObserverLeadership::new(database.pool(), Duration::from_secs(1));

    let first_lease = first.acquire().await.unwrap().expect("first holder");
    assert_eq!(first_lease.fence, 1);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let second_lease = loop {
        if let Some(lease) = second.acquire().await.unwrap() {
            break lease;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "TTL expiry must let the waiting replica lead"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(second_lease.fence, 2);
    assert!(first.acquire().await.unwrap().is_none());

    second.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn stale_fencing_token_aborts_observer_writes() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let invoices = invoices(database.pool());

    let first = PgObserverLeadership::new(database.pool(), LEASE_TTL);
    let second = PgObserverLeadership::new(database.pool(), LEASE_TTL);

    let first_lease = first.acquire().await.unwrap().expect("first holder");
    stamp(&invoices, first_lease)
        .await
        .expect("current leader may stamp");

    first.release().await.unwrap();
    let second_lease = second.acquire().await.unwrap().expect("handover");
    assert_eq!(second_lease.fence, 2);
    stamp(&invoices, second_lease)
        .await
        .expect("new leader may stamp");

    let stale = stamp(&invoices, first_lease).await.unwrap_err();
    assert_eq!(stale, PersistenceError::StaleObserverLease);

    second.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn two_instances_overlap_without_double_processing() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let invoices = invoices(database.pool());

    let first = Arc::new(PgObserverLeadership::new(database.pool(), LEASE_TTL));
    let second = Arc::new(PgObserverLeadership::new(database.pool(), LEASE_TTL));
    let concurrent = Arc::new(AtomicUsize::new(0));
    let max_concurrent = Arc::new(AtomicUsize::new(0));
    let first_writes = Arc::new(AtomicUsize::new(0));
    let second_writes = Arc::new(AtomicUsize::new(0));

    async fn tick(
        leadership: &PgObserverLeadership,
        invoices: &InvoiceStore,
        writes: &AtomicUsize,
        concurrent: &AtomicUsize,
        max_concurrent: &AtomicUsize,
    ) {
        let Some(lease) = leadership.acquire().await.unwrap() else {
            return;
        };
        let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
        max_concurrent.fetch_max(now, Ordering::SeqCst);
        stamp(invoices, lease).await.expect("leader stamp");
        writes.fetch_add(1, Ordering::SeqCst);
        concurrent.fetch_sub(1, Ordering::SeqCst);
    }

    for _ in 0..40 {
        tokio::join!(
            tick(
                &first,
                &invoices,
                &first_writes,
                &concurrent,
                &max_concurrent
            ),
            tick(
                &second,
                &invoices,
                &second_writes,
                &concurrent,
                &max_concurrent
            ),
        );
    }

    assert!(
        first_writes.load(Ordering::SeqCst) > 0,
        "the first replica must process while it holds the lease"
    );
    assert_eq!(
        second_writes.load(Ordering::SeqCst),
        0,
        "the overlapping replica must not process while the first lease is live"
    );
    assert_eq!(
        max_concurrent.load(Ordering::SeqCst),
        1,
        "two replicas must never process an observer write at the same time"
    );

    first.release().await.unwrap();
    for _ in 0..20 {
        tick(
            &second,
            &invoices,
            &second_writes,
            &concurrent,
            &max_concurrent,
        )
        .await;
    }
    assert!(
        second_writes.load(Ordering::SeqCst) > 0,
        "the standby must process after handover"
    );
    assert_eq!(max_concurrent.load(Ordering::SeqCst), 1);

    second.release().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn the_leadership_name_is_the_documented_fixed_constant() {
    assert_eq!(OBSERVER_LEADERSHIP_LEASE_NAME, "observer");
}
