use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::{InMemoryStorage, PaykitSdk, PaykitSdkConfig, PaymentRequestRecord};
use paykit_server::{
    application::semantic_intent::{DeliveryIntentV1, PaymentTermsV1},
    crypto::{Crypto, EnvelopeContext},
    domain::{
        locks::{CreatorPubky, parse_creator},
        payment_request_lifecycle::{
            PaymentRequestLifecycleProjection, PaymentRequestLifecycleState, ProposalCorrelation,
        },
    },
    paykit::{ExplicitInputsPaymentAdapter, project_payment_request_record},
    persistence::{
        PaymentRequestLifecycleApply, PaymentRequestLifecycleStore, PersistenceError,
        run_migrations,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use std::collections::HashMap;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}

fn proposal_intent(payment_reference: &str) -> DeliveryIntentV1 {
    let app_id = PaykitAppId::new("paykit-server").unwrap();
    DeliveryIntentV1::payment_request(
        CREATOR.into(),
        app_id.clone(),
        &PaymentRequestTerms::builder(
            PaymentAmount::new("1", "btc").unwrap(),
            PaymentReference::new(payment_reference.to_owned()).unwrap(),
            vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
        )
        .required_app_id(Some(app_id))
        .payment_endpoints(Some(HashMap::from([(
            PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
            PaymentEndpointPayload::new("payload"),
        )])))
        .build()
        .unwrap(),
    )
    .unwrap()
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
    attributable_invoice_with(database, crypto, creator_id, ordinal, proposal_intent).await
}

async fn attributable_invoice_with(
    database: &TestDatabase,
    crypto: &Crypto,
    creator_id: Uuid,
    ordinal: u8,
    intent: fn(&str) -> DeliveryIntentV1,
) -> (Uuid, Uuid, String) {
    attributable_invoice_for_request(
        database,
        crypto,
        creator_id,
        ordinal,
        Uuid::new_v4().to_string(),
        intent,
    )
    .await
}

async fn attributable_invoice_for_request(
    database: &TestDatabase,
    crypto: &Crypto,
    creator_id: Uuid,
    ordinal: u8,
    payment_request_id: String,
    intent: fn(&str) -> DeliveryIntentV1,
) -> (Uuid, Uuid, String) {
    let bundle_id = Uuid::from_u128(u128::from(ordinal) + 1);
    let invoice_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    let intent_envelope = crypto
        .encrypt(
            &EnvelopeContext::outbox_semantic_intent(
                crypto.lookup_hash(CREATOR.as_bytes()),
                outbox_id,
            ),
            &postcard::to_allocvec(&intent(&payment_request_id)).unwrap(),
        )
        .unwrap();
    let created_at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let deadline = created_at + Duration::hours(24);
    let hash = |label: &str| {
        crypto
            .lookup_hash(format!("{label}-{ordinal}").as_bytes())
            .as_bytes()
            .to_vec()
    };
    let lock_resource_lookup_hash = hash("lock-resource");

    sqlx::query(
        "INSERT INTO invoices (
             id, creator_id, reader_lookup_hash, bundle_lookup_hash,
             lock_resource_lookup_hash, payment_request_lookup_hash,
             invoice_envelope, payment_record_envelope,
             bitcoin_address_lookup_hash, derivation_index_lookup_hash,
             payment_status, confirmation_count, amount_matched,
             invoice_created_at, proposal_expires_at, payment_deadline,
             proposal_acceptance_seconds, payment_window_seconds
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                   'pending', 0, FALSE, $11, $11 + INTERVAL '1 hour', $12,
                   3600, 86400)",
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
    .bind(&lock_resource_lookup_hash)
    .bind(
        crypto
            .lookup_hash(payment_request_id.as_bytes())
            .as_bytes()
            .as_slice(),
    )
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
        "INSERT INTO lock_payment_generations (creator_id, lock_resource_lookup_hash)
         VALUES ($1, $2)",
    )
    .bind(creator_id)
    .bind(&lock_resource_lookup_hash)
    .execute(database.pool())
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO outbox (
             id, creator_id, invoice_id, intent_envelope, intent_kind, status,
             sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id,
             proposal_lookup_hash
         ) VALUES (
             $1, $2, $3, $4, 'payment_request_proposal', 'delivered', '1', $5, $6, $7
         )",
    )
    .bind(outbox_id)
    .bind(creator_id)
    .bind(invoice_id)
    .bind(intent_envelope.as_bytes())
    .bind(Uuid::new_v4().to_string())
    .bind(&payment_request_id)
    .bind(
        crypto
            .payment_request_proposal_lookup_hash(payment_request_id.as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();

    (invoice_id, bundle_id, payment_request_id)
}

async fn attributable_marketplace(
    database: &TestDatabase,
    crypto: &Crypto,
    creator_id: Uuid,
    ordinal: u8,
) -> (Uuid, String) {
    let preparation_id = Uuid::new_v4();
    let payment_request_id = Uuid::new_v4().to_string();
    let outbox_id = Uuid::new_v4();
    let intent_envelope = crypto
        .encrypt(
            &EnvelopeContext::outbox_semantic_intent(
                crypto.lookup_hash(CREATOR.as_bytes()),
                outbox_id,
            ),
            &postcard::to_allocvec(&proposal_intent(&payment_request_id)).unwrap(),
        )
        .unwrap();
    let created_at = OffsetDateTime::from_unix_timestamp(1_800_001_000).unwrap();
    let hash = |label: u8| vec![ordinal.wrapping_add(label); 32];
    sqlx::query(
        "INSERT INTO marketplace_payment_preparations (
             id, creator_id, operation_lookup_hash, request_lookup_hash,
             reader_lookup_hash, preparation_envelope, state, prepared_at,
             prepare_expires_at, activated_at, payment_deadline
         ) VALUES ($1, $2, $3, $4, $5, $6, 'active', $7,
                   $7 + INTERVAL '1 hour', $7, $7 + INTERVAL '24 hours')",
    )
    .bind(preparation_id)
    .bind(creator_id)
    .bind(hash(1))
    .bind(hash(2))
    .bind(hash(3))
    .bind(b"encrypted-preparation".as_slice())
    .bind(created_at)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO marketplace_settlements (
             preparation_id, creator_id, payment_record_envelope,
             bitcoin_address_lookup_hash, derivation_index_lookup_hash
         ) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(preparation_id)
    .bind(creator_id)
    .bind(b"encrypted-payment".as_slice())
    .bind(hash(4))
    .bind(hash(5))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO outbox (
             id, creator_id, marketplace_preparation_id, intent_envelope,
             intent_kind, status, sdk_outbound_message_id, sdk_event_id,
             sdk_payment_request_id, proposal_lookup_hash
         ) VALUES ($1, $2, $3, $4, 'payment_request_proposal', 'delivered',
                   '1', $5, $6, $7)",
    )
    .bind(outbox_id)
    .bind(creator_id)
    .bind(preparation_id)
    .bind(intent_envelope.as_bytes())
    .bind(Uuid::new_v4().to_string())
    .bind(&payment_request_id)
    .bind(
        crypto
            .payment_request_proposal_lookup_hash(payment_request_id.as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();
    (preparation_id, payment_request_id)
}

fn projection(
    payment_request_id: String,
    request_state: PaymentRequestLifecycleState,
    cursor: u64,
    recorded_at: OffsetDateTime,
) -> PaymentRequestLifecycleProjection {
    PaymentRequestLifecycleProjection {
        proposal: ProposalCorrelation {
            reader_pubky: CREATOR.into(),
            proposal_app_id: "paykit-server".into(),
            terms: PaymentTermsV1 {
                amount: "1".into(),
                asset: "btc".into(),
                rates: Vec::new(),
                payment_reference: payment_request_id.clone(),
                proposal_expires_at: None,
                payment_deadline: None,
                accepted_endpoint_identifiers: vec!["btc-bitcoin-p2wpkh".into()],
                payment_endpoints: [("btc-bitcoin-p2wpkh".into(), "payload".into())]
                    .into_iter()
                    .collect(),
                metadata: serde_json::Map::new(),
            },
        },
        payment_request_id,
        request_state,
        state_event_id: Some(Uuid::new_v4().to_string()),
        last_stream_item_id: Some(cursor),
        last_outbound_message_id: Some(1),
        last_event_at: recorded_at,
        proposal_recorded_at: None,
        acceptance_recorded_at: None,
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
async fn marketplace_lifecycle_is_attributed_without_changing_locks_projection() {
    let (database, crypto, store, creator_id) = setup().await;
    let (_, bundle_id, locks_request_id) =
        attributable_invoice(&database, &crypto, creator_id, 70).await;
    let (preparation_id, marketplace_request_id) =
        attributable_marketplace(&database, &crypto, creator_id, 80).await;
    let recorded_at = OffsetDateTime::from_unix_timestamp(1_800_002_000).unwrap();

    assert_eq!(
        store
            .apply(
                creator_id,
                &projection(
                    marketplace_request_id,
                    PaymentRequestLifecycleState::Accepted,
                    1,
                    recorded_at,
                ),
            )
            .await
            .unwrap(),
        PaymentRequestLifecycleApply::Applied
    );
    assert_eq!(
        store
            .load_marketplace(&creator(), preparation_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::Accepted
    );
    assert!(store.load(&creator(), bundle_id).await.unwrap().is_none());

    assert_eq!(
        store
            .apply(
                creator_id,
                &projection(
                    locks_request_id,
                    PaymentRequestLifecycleState::Rejected,
                    1,
                    recorded_at,
                ),
            )
            .await
            .unwrap(),
        PaymentRequestLifecycleApply::Applied
    );
    assert_eq!(
        store
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::Rejected
    );

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
async fn recovery_overlay_is_reversible_at_equal_cursors_with_exact_event_identity() {
    let (database, crypto, store, creator_id) = setup().await;
    let (_, bundle_id, payment_request_id) =
        attributable_invoice(&database, &crypto, creator_id, 23).await;
    let base = OffsetDateTime::from_unix_timestamp(1_800_000_275).unwrap();
    let accepted = projection(
        payment_request_id,
        PaymentRequestLifecycleState::Accepted,
        2,
        base,
    );
    let event_id = accepted.state_event_id.clone();
    store.apply(creator_id, &accepted).await.unwrap();

    let mut recovery = accepted.clone();
    recovery.request_state = PaymentRequestLifecycleState::RecoveryRequired;
    recovery.last_event_at += Duration::seconds(1);
    assert_eq!(
        store.apply(creator_id, &recovery).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );
    assert_eq!(
        PaymentRequestLifecycleStore::new(database.pool(), crypto.clone())
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::RecoveryRequired
    );

    let mut recovered = recovery.clone();
    recovered.request_state = PaymentRequestLifecycleState::Accepted;
    recovered.last_event_at += Duration::seconds(1);
    assert_eq!(recovered.state_event_id, event_id);
    assert_eq!(
        store.apply(creator_id, &recovered).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );

    let mut different_event = recovered.clone();
    different_event.request_state = PaymentRequestLifecycleState::RecoveryRequired;
    different_event.state_event_id = Some(Uuid::new_v4().to_string());
    different_event.last_event_at += Duration::seconds(1);
    assert_eq!(
        store.apply(creator_id, &different_event).await,
        Err(PersistenceError::Conflict)
    );
    assert_eq!(
        store
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::Accepted
    );

    let mut invalid = recovered;
    invalid.request_state = PaymentRequestLifecycleState::InvalidConflict;
    invalid.last_event_at += Duration::seconds(1);
    assert_eq!(
        store.apply(creator_id, &invalid).await,
        Err(PersistenceError::Conflict)
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
async fn ambiguous_retry_attempt_is_attributed_by_stable_proposal_semantics() {
    let (database, crypto, store, creator_id) = setup().await;
    let (_, bundle_id, associated_request_id) =
        attributable_invoice(&database, &crypto, creator_id, 24).await;
    let recorded_at = OffsetDateTime::from_unix_timestamp(1_800_000_280).unwrap();

    let associated = projection(
        associated_request_id.clone(),
        PaymentRequestLifecycleState::Proposed,
        2,
        recorded_at,
    );
    store.apply(creator_id, &associated).await.unwrap();

    let mut ambiguous_attempt = projection(
        Uuid::new_v4().to_string(),
        PaymentRequestLifecycleState::Accepted,
        3,
        recorded_at + Duration::seconds(1),
    );
    ambiguous_attempt.proposal.terms.payment_reference = associated_request_id;
    assert_eq!(
        store.apply(creator_id, &ambiguous_attempt).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );

    let attempts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_request_lifecycles
         WHERE invoice_id = (SELECT id FROM invoices WHERE bundle_lookup_hash = $1)",
    )
    .bind(
        crypto
            .lookup_hash(bundle_id.as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(
        store
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::Accepted
    );

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

#[tokio::test]
async fn active_drain_rejects_new_attempts_but_allows_existing_attempt_progress() {
    let (database, crypto, store, creator_id) = setup().await;
    let (invoice_id, _, payment_request_id) =
        attributable_invoice(&database, &crypto, creator_id, 31).await;
    let recorded_at = OffsetDateTime::from_unix_timestamp(1_800_000_400).unwrap();
    let proposed = projection(
        payment_request_id,
        PaymentRequestLifecycleState::Proposed,
        1,
        recorded_at,
    );
    assert_eq!(
        store.apply(creator_id, &proposed).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );

    let (lock_hash, generation): (Vec<u8>, i64) = sqlx::query_as(
        "SELECT lock_resource_lookup_hash, lock_resource_generation FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let drain_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO payment_drains (
             id, creator_id, lock_resource_lookup_hash,
             lock_resource_generation, lock_resource_envelope, status,
             accepted_count, terminal_count, cancellation_enqueued_count,
             cancellation_set_hash, item_set_hash
         )
         SELECT $2, creator_id, lock_resource_lookup_hash,
                lock_resource_generation, $3, 'active',
                0, 0, 0, decode(repeat('00', 32), 'hex'),
                decode(repeat('00', 32), 'hex')
         FROM invoices
         WHERE id = $1",
    )
    .bind(invoice_id)
    .bind(drain_id)
    .bind(vec![0_u8])
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE lock_payment_generations
         SET current_generation = $3, active_drain_id = $4
         WHERE creator_id = $1 AND lock_resource_lookup_hash = $2",
    )
    .bind(creator_id)
    .bind(lock_hash)
    .bind(generation)
    .bind(drain_id)
    .execute(database.pool())
    .await
    .unwrap();

    let mut retry = proposed.clone();
    retry.payment_request_id = Uuid::new_v4().to_string();
    retry.state_event_id = Some(Uuid::new_v4().to_string());
    retry.last_stream_item_id = Some(2);
    assert_eq!(
        store.apply(creator_id, &retry).await,
        Err(PersistenceError::Conflict)
    );

    sqlx::query(
        "UPDATE lock_payment_generations
         SET current_generation = current_generation + 1, active_drain_id = NULL
         WHERE creator_id = $1 AND lock_resource_lookup_hash = (
             SELECT lock_resource_lookup_hash FROM invoices WHERE id = $2
         )",
    )
    .bind(creator_id)
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    let mut post_cleanup_retry = retry.clone();
    post_cleanup_retry.payment_request_id = Uuid::new_v4().to_string();
    post_cleanup_retry.state_event_id = Some(Uuid::new_v4().to_string());
    post_cleanup_retry.last_stream_item_id = Some(3);
    assert_eq!(
        store.apply(creator_id, &post_cleanup_retry).await,
        Err(PersistenceError::Conflict)
    );

    let mut accepted = proposed;
    accepted.request_state = PaymentRequestLifecycleState::Accepted;
    accepted.last_stream_item_id = Some(2);
    accepted.last_event_at = recorded_at + Duration::seconds(1);
    assert_eq!(
        store.apply(creator_id, &accepted).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );

    database.cleanup().await;
}

const PROPOSAL_EXPIRES_AT: &str = "2027-01-15T08:00:00Z";

fn expiring_proposal_intent(payment_reference: &str) -> DeliveryIntentV1 {
    let mut intent = proposal_intent(payment_reference);
    intent
        .set_deadlines(PROPOSAL_EXPIRES_AT.into(), "2027-01-16T08:00:00Z".into())
        .unwrap();
    intent
}

/// What Paykit before `v0.1.1-rc3` stored for an Acceptance the server fetched
/// at `fetched_at`, at or after the proposal expiry, and the state `rederived`
/// that Paykit now derives from the same stored events.
fn late_acceptance(
    payment_request_id: String,
    fetched_at: OffsetDateTime,
    rederived: PaymentRequestLifecycleState,
) -> (
    PaymentRequestLifecycleProjection,
    PaymentRequestLifecycleProjection,
) {
    let terms = expiring_proposal_intent(&payment_request_id)
        .terms()
        .unwrap()
        .clone();
    let mut invalid = projection(
        payment_request_id,
        PaymentRequestLifecycleState::InvalidConflict,
        3,
        fetched_at,
    );
    invalid.proposal.terms = terms;
    let mut current = invalid.clone();
    current.request_state = rederived;
    current.state_event_id = Some(Uuid::new_v4().to_string());
    current.acceptance_recorded_at = Some(fetched_at);
    (invalid, current)
}

fn proposal_expiry() -> OffsetDateTime {
    OffsetDateTime::parse(PROPOSAL_EXPIRES_AT, &Rfc3339).unwrap()
}

#[tokio::test]
async fn a_stored_invalid_request_takes_the_state_derived_for_a_late_fetched_acceptance() {
    let (database, crypto, store, creator_id) = setup().await;
    for (ordinal, rederived) in [
        (40, PaymentRequestLifecycleState::Accepted),
        (41, PaymentRequestLifecycleState::ProofSubmitted),
    ] {
        let (_, bundle_id, payment_request_id) = attributable_invoice_with(
            &database,
            &crypto,
            creator_id,
            ordinal,
            expiring_proposal_intent,
        )
        .await;
        let (invalid, current) = late_acceptance(
            payment_request_id,
            proposal_expiry() + Duration::minutes(5),
            rederived,
        );
        assert_eq!(
            store.apply(creator_id, &invalid).await.unwrap(),
            PaymentRequestLifecycleApply::Applied
        );

        // Same source cursors and event time, new state and state event.
        assert_eq!(
            store.apply(creator_id, &current).await.unwrap(),
            PaymentRequestLifecycleApply::Applied
        );
        let restarted = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone());
        assert_eq!(
            restarted
                .load(&creator(), bundle_id)
                .await
                .unwrap()
                .unwrap()
                .request_state,
            rederived
        );
        assert_eq!(
            restarted.apply(creator_id, &current).await.unwrap(),
            PaymentRequestLifecycleApply::ExactReplay
        );
    }

    database.cleanup().await;
}

struct NoSession;

#[async_trait::async_trait]
impl paykit_sdk::PubkySessionProvider for NoSession {
    async fn load_session_access(
        &self,
    ) -> paykit_sdk::Result<Option<paykit_sdk::PubkySessionAccess>> {
        Ok(None)
    }

    async fn load_public_storage(&self) -> paykit_sdk::Result<Option<pubky::PublicStorage>> {
        Ok(None)
    }

    async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
        Ok(())
    }
}

#[derive(serde::Deserialize)]
struct CanceledRequestHistory {
    state_blob_base64: String,
    old_record: PaymentRequestRecord,
}

#[tokio::test]
async fn a_canceled_request_replayed_from_legacy_sdk_state_recovers_after_restart() {
    let (database, crypto, store, creator_id) = setup().await;
    let history: CanceledRequestHistory = serde_json::from_str(include_str!(
        "fixtures/canceled-late-acceptance-sdk-0.1.0.json"
    ))
    .unwrap();
    let (_, bundle_id, _) = attributable_invoice_for_request(
        &database,
        &crypto,
        creator_id,
        43,
        history.old_record.payment_request_id.clone(),
        expiring_proposal_intent,
    )
    .await;
    let invalid = project_payment_request_record(&history.old_record).unwrap();
    assert_eq!(
        invalid.request_state,
        PaymentRequestLifecycleState::InvalidConflict
    );
    assert_eq!(invalid.acceptance_recorded_at, None);
    assert_eq!(
        store.apply(creator_id, &invalid).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );
    drop(store);

    let blob = STANDARD.decode(history.state_blob_base64).unwrap();
    let state = paykit_sdk::storage::decode_storage_state_blob(&blob).unwrap();
    let sdk = PaykitSdk::new(
        InMemoryStorage::from_state(state),
        NoSession,
        ExplicitInputsPaymentAdapter,
        PaykitSdkConfig::new("paykit-server").unwrap(),
    );
    let records = sdk.payment_requests().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payment_proofs.len(), 1);
    let current = project_payment_request_record(&records[0]).unwrap();
    assert_eq!(
        current.request_state,
        PaymentRequestLifecycleState::Canceled
    );
    assert_eq!(current.state_event_id, invalid.state_event_id);
    assert_eq!(
        current.state_event_id.as_deref(),
        Some("8a0d8b4c-913f-4e31-9f2c-2a6f5bb4d102")
    );
    assert_eq!(current.last_stream_item_id, invalid.last_stream_item_id);
    assert_eq!(
        current.last_outbound_message_id,
        invalid.last_outbound_message_id
    );
    assert_eq!(current.last_event_at, invalid.last_event_at);
    assert_eq!(
        current.acceptance_recorded_at,
        Some(proposal_expiry() + Duration::seconds(2))
    );

    let restarted = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone());
    assert_eq!(
        restarted
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::InvalidConflict
    );
    let mut regressed_stream = current.clone();
    regressed_stream.last_stream_item_id = current.last_stream_item_id.map(|id| id - 1);
    let mut regressed_outbound = current.clone();
    regressed_outbound.last_outbound_message_id = current.last_outbound_message_id.map(|id| id - 1);
    let mut regressed_time = current.clone();
    regressed_time.last_event_at -= Duration::seconds(1);
    for refused in [regressed_stream, regressed_outbound, regressed_time] {
        assert_eq!(
            restarted.apply(creator_id, &refused).await,
            Err(PersistenceError::Conflict)
        );
    }
    let mut misattributed = current.clone();
    misattributed.proposal.terms.amount = "2".into();
    assert_eq!(
        restarted.apply(creator_id, &misattributed).await,
        Err(PersistenceError::CorruptOrMissing)
    );
    assert_eq!(
        restarted.apply(creator_id, &current).await.unwrap(),
        PaymentRequestLifecycleApply::Applied
    );
    drop(restarted);

    let restarted = PaymentRequestLifecycleStore::new(database.pool(), crypto);
    let persisted = restarted
        .load(&creator(), bundle_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        persisted.request_state,
        PaymentRequestLifecycleState::Canceled
    );
    assert_eq!(persisted.last_event_at, current.last_event_at);
    assert_eq!(
        restarted.apply(creator_id, &current).await.unwrap(),
        PaymentRequestLifecycleApply::ExactReplay
    );
    database.cleanup().await;
}

#[tokio::test]
async fn a_stored_invalid_request_stays_invalid_without_a_late_fetched_acceptance() {
    let (database, crypto, store, creator_id) = setup().await;
    let (_, bundle_id, payment_request_id) =
        attributable_invoice_with(&database, &crypto, creator_id, 42, expiring_proposal_intent)
            .await;
    let (invalid, current) = late_acceptance(
        payment_request_id,
        proposal_expiry() + Duration::minutes(5),
        PaymentRequestLifecycleState::Canceled,
    );
    store.apply(creator_id, &invalid).await.unwrap();

    let mut in_time = current.clone();
    in_time.acceptance_recorded_at = Some(proposal_expiry() - Duration::seconds(1));
    let mut without_time = current.clone();
    without_time.acceptance_recorded_at = None;
    let mut reproposed = current;
    reproposed.request_state = PaymentRequestLifecycleState::Proposed;
    for refused in [in_time, without_time, reproposed] {
        assert_eq!(
            store.apply(creator_id, &refused).await,
            Err(PersistenceError::Conflict)
        );
    }
    assert_eq!(
        store
            .load(&creator(), bundle_id)
            .await
            .unwrap()
            .unwrap()
            .request_state,
        PaymentRequestLifecycleState::InvalidConflict
    );

    database.cleanup().await;
}
