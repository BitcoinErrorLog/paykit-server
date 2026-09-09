//! Cluster-single observer leadership over a real PostgreSQL advisory lock.

use paykit_server::persistence::{
    OBSERVER_LEADERSHIP_LOCK_KEY, PgObserverLeadership, run_migrations,
};
use paykit_server_e2e::postgres::TestDatabase;

#[tokio::test]
async fn one_leader_holds_the_lock_until_its_session_drops_then_a_peer_takes_over() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();

    let first = PgObserverLeadership::new(database.pool());
    let second = PgObserverLeadership::new(database.pool());

    // Exactly one replica leads; the peer idles fail-closed.
    assert!(first.is_leader().await.unwrap());
    assert!(
        !second.is_leader().await.unwrap(),
        "a live lease must keep the second replica idle"
    );
    // Leadership is re-asserted, not re-contended, on the holding session.
    assert!(first.is_leader().await.unwrap());

    // The leader's session ends (process crash, pod eviction): PostgreSQL
    // releases the advisory lock and the next peer check takes over.
    drop(first);
    assert!(
        second.is_leader().await.unwrap(),
        "an expired lease must let the waiting replica lead"
    );

    // A third replica still idles behind the new leader.
    let third = PgObserverLeadership::new(database.pool());
    assert!(!third.is_leader().await.unwrap());

    database.cleanup().await;
}

#[tokio::test]
async fn the_leadership_key_is_the_documented_fixed_constant() {
    // The key is the single cluster-wide rendezvous for observer
    // leadership; pinning it here keeps accidental key drift from
    // splitting the fleet into two active observers.
    assert_eq!(OBSERVER_LEADERSHIP_LOCK_KEY, 7_216_043_388_155_778_021);
}
