//! End-to-end fingerprint↔seller binding at the persistence boundary
//! (design §B.8.5): the binding row is written in the same transaction as the
//! claim commit, keyed on the canonical 65-byte key tail, and never expires.

use std::sync::Arc;

use paykit_sdk::{ReceiverNoiseSecretKey, storage::StorageState};
use paykit_server::{
    crypto::Crypto,
    domain::locks::{CreatorPubky, parse_creator},
    persistence::{CreatorCredentials, CreatorStore, PersistenceError, run_migrations},
};
use paykit_server_e2e::postgres::TestDatabase;

const CREATOR_A: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const CREATOR_B: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";

fn creator_a() -> CreatorPubky {
    parse_creator(CREATOR_A).unwrap()
}
fn creator_b() -> CreatorPubky {
    parse_creator(CREATOR_B).unwrap()
}

fn credentials(creator: CreatorPubky, session: &str) -> CreatorCredentials {
    CreatorCredentials::new(
        creator,
        session.to_owned(),
        ReceiverNoiseSecretKey::new([9; 32]),
        "xpub".to_owned(),
        0,
    )
}

fn key_tail(seed: u8) -> [u8; 65] {
    [seed; 65]
}

async fn store(database: &TestDatabase) -> CreatorStore {
    run_migrations(database.pool()).await.unwrap();
    CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key([1; 32].as_slice()).unwrap()),
    )
}

#[tokio::test]
async fn the_binding_is_written_with_the_claim_and_never_expires() {
    let database = TestDatabase::create().await;
    let creators = store(&database).await;
    let tail = key_tail(1);

    // The first claim binds the tail to seller A.
    creators
        .create(
            &credentials(creator_a(), "a-session"),
            &StorageState::default(),
            &tail,
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
        )
        .await
        .unwrap();
    let row: (Vec<u8>,) = sqlx::query_as(
        "SELECT creator_lookup_hash FROM claimed_key_fingerprints WHERE key_tail = $1",
    )
    .bind(tail.as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(row.0.len(), 32);
    assert!(
        creators
            .key_tail_claimed_by_other(&tail, &creator_b())
            .await
            .unwrap()
    );
    assert!(
        !creators
            .key_tail_claimed_by_other(&tail, &creator_a())
            .await
            .unwrap()
    );

    // A re-claim (reauthentication) by the same seller is unaffected.
    creators
        .reauthenticate(
            &credentials(creator_a(), "a-new-session"),
            &tail,
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
        )
        .await
        .unwrap();

    // Seller B can never claim the tail — even after A's claim record is
    // gone (HEAD has no deactivation; deleting the creator record is what
    // "inactive" means here). The binding row has no FK to creators and
    // never expires.
    sqlx::query("DELETE FROM sdk_states")
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM creators")
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        creators
            .create(
                &credentials(creator_b(), "b-session"),
                &StorageState::default(),
                &tail,
                &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            )
            .await,
        Err(PersistenceError::KeyClaimedByOtherSeller)
    );
    // B's refused claim committed nothing: no creator row, still one binding.
    let creator_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    let binding_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claimed_key_fingerprints")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!((creator_rows, binding_rows), (0, 1));

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_first_claims_of_one_tail_have_exactly_one_winner() {
    let database = TestDatabase::create().await;
    let creators = store(&database).await;
    let tail = key_tail(2);

    // A and B race a first claim of the same tail. The unique primary key
    // plus ON CONFLICT inside the claim transaction serializes them: exactly
    // one wins, and the loser gets the named refusal, not a 500-class error.
    let a_credentials = credentials(creator_a(), "a-session");
    let b_credentials = credentials(creator_b(), "b-session");
    let state = StorageState::default();
    let allocation = paykit_server::allocation::ClaimAllocation::shared_manual_default();
    let a = creators.create(&a_credentials, &state, &tail, &allocation);
    let b = creators.create(&b_credentials, &state, &tail, &allocation);
    let (a, b) = tokio::join!(a, b);
    let outcomes = [a, b];
    let winners = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    let losers = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Err(PersistenceError::KeyClaimedByOtherSeller)))
        .count();
    assert_eq!(
        (winners, losers),
        (1, 1),
        "exactly one concurrent first claim wins; the loser is refused by name: {outcomes:?}"
    );

    let creator_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    let binding_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claimed_key_fingerprints")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!((creator_rows, binding_rows), (1, 1));

    database.cleanup().await;
}
