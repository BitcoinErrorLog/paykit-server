use std::sync::Arc;

use paykit_server::{
    crypto::Crypto,
    domain::{
        locks::{CreatorPubky, parse_creator},
        payment_request_lifecycle::{
            PaymentRequestLifecycleProjection, PaymentRequestLifecycleState,
        },
    },
    persistence::{
        PaymentRequestLifecycleApply, PaymentRequestLifecycleStore, PersistenceError,
        run_migrations,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}

async fn setup() -> (
    TestDatabase,
    Arc<Crypto>,
    PaymentRequestLifecycleStore,
    Uuid,
) {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[41; 32]).unwrap());
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope) VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let store = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone());
    (database, crypto, store, creator_id)
}

async fn attributable_invoice(
    database: &TestDatabase,
    crypto: &Crypto,
    creator_id: Uuid,
    ordinal: u8,
) -> (Uuid, Uuid, String) {
    let bundle_id = Uuid::from_u128(u128::from(ordinal) + 1);
    let invoice_id = Uuid::new_v4();
    let payment_request_id = Uuid::new_v4().to_string();
    let created_at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let deadline = created_at + Duration::hours(24);
    let hash = |label: &str| {
        crypto
            .lookup_hash(format!("{label}-{ordinal}").as_bytes())
            .as_bytes()
            .to_vec()
    };

    sqlx::query(
        "INSERT INTO invoices (
             id, creator_id, reader_lookup_hash, bundle_lookup_hash,
             payment_request_lookup_hash, invoice_envelope, payment_record_envelope,
             bitcoin_address_lookup_hash, derivation_index_lookup_hash,
             payment_status, confirmation_count, amount_matched,
             invoice_created_at, payment_deadline, payment_in_hours
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', 0, FALSE,
                   $10, $11, 24)",
    )
    .bind(invoice_id)
    .bind(creator_id)
    .bind(hash("reader"))
    .bind(
        crypto
            .lookup_hash(bundle_id.as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .bind(hash("request"))
    .bind(b"encrypted-invoice".as_slice())
    .bind(b"encrypted-payment".as_slice())
    .bind(hash("address"))
    .bind(hash("index"))
    .bind(created_at)
    .bind(deadline)
    .execute(database.pool())
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO outbox (
             creator_id, invoice_id, intent_envelope, status,
             sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id
         ) VALUES ($1, $2, $3, 'delivered', '1', $4, $5)",
    )
    .bind(creator_id)
    .bind(invoice_id)
    .bind(b"encrypted-intent".as_slice())
    .bind(Uuid::new_v4().to_string())
    .bind(&payment_request_id)
    .execute(database.pool())
    .await
    .unwrap();

    (invoice_id, bundle_id, payment_request_id)
}

fn projection(
    payment_request_id: String,
    request_state: PaymentRequestLifecycleState,
    cursor: u64,
    recorded_at: OffsetDateTime,
) -> PaymentRequestLifecycleProjection {
    PaymentRequestLifecycleProjection {
        payment_request_id,
        request_state,
        state_event_id: Some(Uuid::new_v4().to_string()),
        last_stream_item_id: Some(cursor),
        last_outbound_message_id: Some(1),
        last_event_at: recorded_at,
    }
}

#[tokio::test]
async fn all_canonical_lifecycle_states_are_durable_and_queryable_after_restart() {
    let (database, crypto, store, creator_id) = setup().await;
    let states = [
        PaymentRequestLifecycleState::Proposed,
        PaymentRequestLifecycleState::ProposalExpired,
        PaymentRequestLifecycleState::Accepted,
        PaymentRequestLifecycleState::Rejected,
        PaymentRequestLifecycleState::Canceled,
        PaymentRequestLifecycleState::ProofSubmitted,
        PaymentRequestLifecycleState::ActiveRecurring,
        PaymentRequestLifecycleState::RecoveryRequired,
        PaymentRequestLifecycleState::InvalidConflict,
    ];
    let recorded_at = OffsetDateTime::from_unix_timestamp(1_800_000_100).unwrap();

    for (ordinal, state) in states.into_iter().enumerate() {
        let (_, bundle_id, payment_request_id) =
            attributable_invoice(&database, &crypto, creator_id, ordinal as u8).await;
        assert_eq!(
            store
                .apply(
                    creator_id,
                    &projection(payment_request_id, state, 1, recorded_at)
                )
                .await
                .unwrap(),
            PaymentRequestLifecycleApply::Applied
        );

        let restarted = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone());
        let persisted = restarted
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted.request_state, state);
        assert_eq!(persisted.last_event_at, recorded_at);
    }

    database.cleanup().await;
}

#[tokio::test]
async fn exact_replay_is_idempotent_but_stale_or_equal_cursor_divergence_conflicts() {
    let (database, crypto, store, creator_id) = setup().await;
    let (_, bundle_id, payment_request_id) =
        attributable_invoice(&database, &crypto, creator_id, 20).await;
    let recorded_at =
        OffsetDateTime::from_unix_timestamp(1_800_000_200).unwrap() + Duration::nanoseconds(600);
    let proposed = projection(
        payment_request_id.clone(),
        PaymentRequestLifecycleState::Proposed,
        2,
        recorded_at,
    );

    assert_eq!(
        store.apply(creator_id, &proposed).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );
    let restarted = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone());
    assert_eq!(
        restarted.apply(creator_id, &proposed).await.unwrap(),
        PaymentRequestLifecycleApply::ExactReplay
    );

    let stale = projection(
        payment_request_id.clone(),
        PaymentRequestLifecycleState::Accepted,
        1,
        recorded_at - Duration::seconds(1),
    );
    assert_eq!(
        store.apply(creator_id, &stale).await,
        Err(PersistenceError::Conflict)
    );

    let divergent = projection(
        payment_request_id.clone(),
        PaymentRequestLifecycleState::Accepted,
        2,
        recorded_at,
    );
    assert_eq!(
        store.apply(creator_id, &divergent).await,
        Err(PersistenceError::Conflict)
    );
    let divergent_with_later_timestamp = projection(
        payment_request_id,
        PaymentRequestLifecycleState::Accepted,
        2,
        recorded_at + Duration::seconds(1),
    );
    assert_eq!(
        store
            .apply(creator_id, &divergent_with_later_timestamp)
            .await,
        Err(PersistenceError::Conflict)
    );

    let persisted = store.load(&creator(), bundle_id).await.unwrap().unwrap();
    assert_eq!(
        persisted.request_state,
        PaymentRequestLifecycleState::Proposed
    );

    let mut timestamp_refreshed = proposed.clone();
    timestamp_refreshed.last_event_at = OffsetDateTime::from_unix_timestamp(1_800_000_201).unwrap();
    assert_eq!(
        store.apply(creator_id, &timestamp_refreshed).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );
    let timestamp_refreshed_persisted = store.load(&creator(), bundle_id).await.unwrap().unwrap();
    assert_eq!(
        timestamp_refreshed_persisted.request_state,
        PaymentRequestLifecycleState::Proposed
    );
    assert_eq!(
        timestamp_refreshed_persisted.last_event_at,
        timestamp_refreshed.last_event_at
    );

    let mut expired = timestamp_refreshed.clone();
    expired.request_state = PaymentRequestLifecycleState::ProposalExpired;
    assert_eq!(
        store.apply(creator_id, &expired).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );
    let mut reopened = timestamp_refreshed;
    reopened.last_stream_item_id = Some(3);
    reopened.last_event_at += Duration::seconds(1);
    assert_eq!(
        store.apply(creator_id, &reopened).await,
        Err(PersistenceError::Conflict)
    );
    assert_eq!(
        store
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::ProposalExpired
    );

    database.cleanup().await;
}

#[tokio::test]
async fn lifecycle_projection_skips_unattributable_and_rejects_multiple_attribution() {
    let (database, crypto, store, creator_id) = setup().await;
    let recorded_at = OffsetDateTime::from_unix_timestamp(1_800_000_250).unwrap();
    let unrelated = projection(
        Uuid::new_v4().to_string(),
        PaymentRequestLifecycleState::Proposed,
        1,
        recorded_at,
    );
    assert_eq!(
        store.apply(creator_id, &unrelated).await.unwrap(),
        PaymentRequestLifecycleApply::NotAttributable
    );
    let projected: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_request_lifecycles")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(projected, 0);

    let (_, _, payment_request_id) = attributable_invoice(&database, &crypto, creator_id, 21).await;
    let (_, _, other_payment_request_id) =
        attributable_invoice(&database, &crypto, creator_id, 22).await;
    sqlx::query(
        "UPDATE outbox
         SET sdk_payment_request_id = $1
         WHERE sdk_payment_request_id = $2",
    )
    .bind(&payment_request_id)
    .bind(other_payment_request_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        store
            .apply(
                creator_id,
                &projection(
                    payment_request_id,
                    PaymentRequestLifecycleState::Proposed,
                    1,
                    recorded_at,
                ),
            )
            .await,
        Err(PersistenceError::CorruptOrMissing)
    );
    let projected: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_request_lifecycles")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(projected, 0);

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_monotonic_updates_converge_and_delayed_acceptance_after_cancellation_is_invalid()
 {
    let (database, crypto, store, creator_id) = setup().await;
    let (_, bundle_id, payment_request_id) =
        attributable_invoice(&database, &crypto, creator_id, 30).await;
    let base = OffsetDateTime::from_unix_timestamp(1_800_000_300).unwrap();
    let proposed = projection(
        payment_request_id.clone(),
        PaymentRequestLifecycleState::Proposed,
        1,
        base,
    );
    let accepted = projection(
        payment_request_id.clone(),
        PaymentRequestLifecycleState::Accepted,
        2,
        base + Duration::seconds(1),
    );

    let first_store = store.clone();
    let second_store = store.clone();
    let (first, second) = tokio::join!(
        first_store.apply(creator_id, &proposed),
        second_store.apply(creator_id, &accepted),
    );
    assert!(first.is_ok() || first == Err(PersistenceError::Conflict));
    assert!(second.is_ok());
    assert_eq!(
        store
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::Accepted
    );

    let canceled = projection(
        payment_request_id.clone(),
        PaymentRequestLifecycleState::Canceled,
        3,
        base + Duration::seconds(2),
    );
    store.apply(creator_id, &canceled).await.unwrap();
    let invalid = projection(
        payment_request_id,
        PaymentRequestLifecycleState::InvalidConflict,
        4,
        base + Duration::seconds(3),
    );
    store.apply(creator_id, &invalid).await.unwrap();

    let restarted = PaymentRequestLifecycleStore::new(database.pool(), crypto);
    assert_eq!(
        restarted
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::InvalidConflict
    );

    database.cleanup().await;
}
