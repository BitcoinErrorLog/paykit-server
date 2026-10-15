use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use paykit_sdk::PaykitIdentitySecretKey;
use paykit_server::{
    bitcoin::{ObservationTarget, ObservedOutput, TrackedOutput},
    config::BitcoinNetwork,
    crypto::Crypto,
    domain::{
        invoice::CriterionAsset,
        locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    },
    persistence::{
        CreatorCredentials, CreatorStore, MarketplaceActivationInput, MarketplacePreparationInput,
        MarketplacePreparationPayloadFactory, MarketplacePreparationPayloads,
        MarketplacePreparationStore, PersistenceError, run_migrations,
    },
    workers::observer::{
        ElectrumPort, ObserverError, observe_marketplace_once, observe_marketplace_once_at,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use time::OffsetDateTime;

mod common;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const REFERENCE: &str = "7cceb26d-9042-4ea6-bfcb-01bbd778d76e";

fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}

fn reader() -> ReaderPubky {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &replacement.to_string());
        if let Ok(reader) = parse_reader(&candidate) {
            return reader;
        }
    }
    panic!("valid reader fixture")
}

fn crypto() -> Arc<Crypto> {
    Arc::new(Crypto::from_master_key(&[7; 32]).unwrap())
}

struct Payloads;

impl MarketplacePreparationPayloadFactory for Payloads {
    fn for_child_index(
        &self,
        _child_index: i64,
    ) -> Result<MarketplacePreparationPayloads, PersistenceError> {
        Ok(MarketplacePreparationPayloads {
            payment_request_intent: common::payment_intent_with_reference(
                &reader(),
                ADDRESS.into(),
                REFERENCE.into(),
            ),
        })
    }
}

async fn store(database: &TestDatabase) -> MarketplacePreparationStore {
    run_migrations(database.pool()).await.unwrap();
    CreatorStore::new(database.pool(), crypto())
        .create(&CreatorCredentials::new(
            creator(),
            "session-secret".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "xpub-secret".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    MarketplacePreparationStore::new(database.pool(), crypto())
}

async fn prepare(
    store: &MarketplacePreparationStore,
    operation_id: &str,
    payment_window_seconds: u64,
) -> paykit_server::persistence::MarketplacePreparationResult {
    store
        .prepare(MarketplacePreparationInput {
            creator: &creator(),
            reader: &reader(),
            reference: REFERENCE,
            operation_id,
            request_binding: operation_id.as_bytes(),
            amount: 100,
            asset: CriterionAsset::Btc,
            payment_window_seconds,
            prepare_ttl_seconds: 15 * 60,
            prepare_deadline: common::deadline_after(15 * 60),
            payloads: &Payloads,
        })
        .await
        .unwrap()
}

async fn activate(
    store: &MarketplacePreparationStore,
    invoice_id: uuid::Uuid,
) -> paykit_server::persistence::MarketplaceActivationResult {
    store
        .activate(MarketplaceActivationInput {
            creator: &creator(),
            invoice_id,
            amount: 100,
            asset: CriterionAsset::Btc,
            proposal_acceptance_window: std::time::Duration::from_secs(1),
        })
        .await
        .unwrap()
        .unwrap()
}

struct FixedBatch(Vec<ObservedOutput>);

#[async_trait]
impl ElectrumPort for FixedBatch {
    async fn observations(
        &self,
        _targets: &[ObservationTarget],
    ) -> Result<Vec<ObservedOutput>, ObserverError> {
        Ok(self.0.clone())
    }
}

fn outpoint(byte: u8) -> OutPoint {
    OutPoint::new(
        Txid::from_str(&format!("{byte:02x}{}", "00".repeat(31))).unwrap(),
        u32::from(byte),
    )
}

fn output(outpoint: OutPoint, sats: u64, confirmations: u32, present: bool) -> ObservedOutput {
    ObservedOutput {
        network: BitcoinNetwork::Regtest,
        address: ADDRESS.into(),
        outpoint,
        sats,
        confirmations,
        present,
    }
}

async fn observe(
    store: &MarketplacePreparationStore,
    target: ObservationTarget,
    output: ObservedOutput,
    at: OffsetDateTime,
) -> Result<usize, ObserverError> {
    observe_marketplace_once_at(
        &FixedBatch(vec![output]),
        store,
        &BitcoinNetwork::Regtest,
        &[target],
        at,
    )
    .await
}

async fn assert_reorg_batch_preserves_replacement(original: OutPoint, replacement: OutPoint) {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store, "marketplace-payment:reorg-batch", 60).await;
    let activated = activate(&store, prepared.invoice_id()).await;
    let original_at = activated.activated_at() + time::Duration::seconds(1);
    let batch_at = original_at + time::Duration::seconds(1);

    let target = store.observation_targets().await.unwrap().remove(0);
    assert_eq!(
        observe(&store, target, output(original, 100, 1, true), original_at).await,
        Ok(1)
    );
    let target = store.observation_targets().await.unwrap().remove(0);
    assert_eq!(
        observe_marketplace_once_at(
            &FixedBatch(vec![
                output(replacement, 100, 0, true),
                output(original, 100, 0, false),
            ]),
            &store,
            &BitcoinNetwork::Regtest,
            &[target],
            batch_at,
        )
        .await,
        Ok(2)
    );

    let active: (i32, bool, OffsetDateTime) = sqlx::query_as(
        "SELECT confirmations, present, first_observed_at
         FROM bitcoin_observations
         WHERE marketplace_preparation_id = $1 AND active",
    )
    .bind(prepared.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(active, (0, true, batch_at));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM bitcoin_observations
             WHERE marketplace_preparation_id = $1",
        )
        .bind(prepared.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM marketplace_timely_amount_matched_outpoints
             WHERE preparation_id = $1",
        )
        .bind(prepared.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        2
    );

    database.cleanup().await;
}

#[tokio::test]
async fn prepared_and_voided_preparations_are_not_observation_targets() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store, "marketplace-payment:prepared", 60).await;
    assert!(store.observation_targets().await.unwrap().is_empty());

    store
        .void(&creator(), prepared.invoice_id())
        .await
        .unwrap()
        .unwrap();
    assert!(store.observation_targets().await.unwrap().is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM marketplace_settlements")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );
    database.cleanup().await;
}

#[tokio::test]
async fn replacement_keeps_per_outpoint_evidence_and_does_not_transfer_timeliness() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store, "marketplace-payment:replacement", 2).await;
    let activated = activate(&store, prepared.invoice_id()).await;
    let first = outpoint(1);
    let first_at = activated.activated_at() + time::Duration::seconds(1);
    let target = store.observation_targets().await.unwrap().remove(0);
    assert_eq!(
        observe(&store, target, output(first, 100, 0, true), first_at).await,
        Ok(1)
    );

    let evidence: (uuid::Uuid, Vec<u8>, OffsetDateTime) = sqlx::query_as(
        "SELECT id, observation_envelope, first_observed_at
         FROM bitcoin_observations WHERE marketplace_preparation_id = $1 AND active",
    )
    .bind(prepared.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert!(
        sqlx::query(
            "UPDATE bitcoin_observations SET first_observed_at = first_observed_at + INTERVAL '1 second'
             WHERE id = $1",
        )
        .bind(evidence.0)
        .execute(database.pool())
        .await
        .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM bitcoin_observations WHERE id = $1")
            .bind(evidence.0)
            .execute(database.pool())
            .await
            .is_err()
    );
    assert_eq!(
        observe(
            &store,
            ObservationTarget::new(ADDRESS, Some(TrackedOutput::new(first, 100))),
            output(first, 101, 0, true),
            first_at + time::Duration::milliseconds(100),
        )
        .await,
        Err(ObserverError::Persistence)
    );

    let replacement = outpoint(2);
    let replacement_at = activated.payment_deadline() + time::Duration::seconds(1);
    let target = store.observation_targets().await.unwrap().remove(0);
    assert_eq!(
        observe(
            &store,
            target,
            output(replacement, 100, 1, true),
            replacement_at,
        )
        .await,
        Ok(1)
    );
    let rows: Vec<(uuid::Uuid, bool, OffsetDateTime, Vec<u8>)> = sqlx::query_as(
        "SELECT id, active, first_observed_at, observation_envelope
         FROM bitcoin_observations WHERE marketplace_preparation_id = $1 ORDER BY first_observed_at",
    )
    .bind(prepared.invoice_id())
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].0, rows[0].1, rows[0].2, &rows[0].3),
        (evidence.0, false, evidence.2, &evidence.1)
    );
    assert!(rows[1].1);
    assert_eq!(rows[1].2, replacement_at);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM marketplace_timely_amount_matched_outpoints
             WHERE preparation_id = $1",
        )
        .bind(prepared.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        1,
        "late replacement must not inherit first outpoint timeliness"
    );
    let projection: (String, i32, bool, bool) = sqlx::query_as(
        "SELECT payment_status, confirmation_count, amount_matched,
                payment_expired_at IS NOT NULL
         FROM marketplace_settlements WHERE preparation_id = $1",
    )
    .bind(prepared.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(projection, ("confirmed".into(), 1, true, true));
    database.cleanup().await;
}

#[tokio::test]
async fn reorg_batch_preserves_replacement_first_seen_for_both_outpoint_orders() {
    assert_reorg_batch_preserves_replacement(outpoint(2), outpoint(1)).await;
    assert_reorg_batch_preserves_replacement(outpoint(1), outpoint(2)).await;
}

#[tokio::test]
async fn underpayment_reorg_and_six_confirmation_finality_match_locks_rules() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store, "marketplace-payment:finality", 60).await;
    let activated = activate(&store, prepared.invoice_id()).await;
    let underpaid = outpoint(3);
    let observed_at = activated.activated_at() + time::Duration::seconds(1);
    let target = store.observation_targets().await.unwrap().remove(0);
    observe(&store, target, output(underpaid, 99, 20, true), observed_at)
        .await
        .unwrap();

    let matched = outpoint(4);
    let target = store.observation_targets().await.unwrap().remove(0);
    observe(
        &store,
        target,
        output(matched, 100, 0, true),
        observed_at + time::Duration::seconds(1),
    )
    .await
    .unwrap();
    let target = store.observation_targets().await.unwrap().remove(0);
    observe(
        &store,
        target,
        output(matched, 100, 0, false),
        observed_at + time::Duration::seconds(2),
    )
    .await
    .unwrap();

    let after_reorg = outpoint(5);
    let target = store.observation_targets().await.unwrap().remove(0);
    observe(
        &store,
        target,
        output(after_reorg, 100, 6, true),
        observed_at + time::Duration::seconds(3),
    )
    .await
    .unwrap();
    assert!(store.observation_targets().await.unwrap().is_empty());

    observe(
        &store,
        ObservationTarget::new(ADDRESS, Some(TrackedOutput::new(after_reorg, 100))),
        output(after_reorg, 100, 0, false),
        observed_at + time::Duration::seconds(4),
    )
    .await
    .unwrap();
    let final_projection: (String, i32, bool, bool) = sqlx::query_as(
        "SELECT payment_status, confirmation_count, amount_matched,
                (SELECT present FROM bitcoin_observations
                 WHERE marketplace_preparation_id = $1 AND active)
         FROM marketplace_settlements WHERE preparation_id = $1",
    )
    .bind(prepared.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(final_projection, ("confirmed".into(), 6, true, true));
    database.cleanup().await;
}

#[tokio::test]
async fn overdue_never_paid_settlement_expires_but_remains_observable() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store, "marketplace-payment:unpaid-expiry", 60).await;
    let activated = activate(&store, prepared.invoice_id()).await;
    let after_deadline = activated.payment_deadline() + time::Duration::seconds(1);

    let targets = store.observation_targets_at(after_deadline).await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(
        sqlx::query_scalar::<_, Option<OffsetDateTime>>(
            "SELECT payment_expired_at FROM marketplace_settlements WHERE preparation_id = $1",
        )
        .bind(prepared.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        Some(after_deadline)
    );

    assert_eq!(
        observe(
            &store,
            targets.into_iter().next().unwrap(),
            output(outpoint(6), 100, 0, true),
            after_deadline + time::Duration::seconds(1),
        )
        .await,
        Ok(1)
    );
    assert_eq!(
        sqlx::query_as::<_, (String, bool, bool)>(
            "SELECT payment_status, amount_matched, payment_expired_at IS NOT NULL
             FROM marketplace_settlements WHERE preparation_id = $1",
        )
        .bind(prepared.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        ("detected".into(), true, true)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn currently_present_timely_match_prevents_target_discovery_expiry() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store, "marketplace-payment:timely-present", 60).await;
    let activated = activate(&store, prepared.invoice_id()).await;
    let matched = outpoint(7);
    let target = store.observation_targets().await.unwrap().remove(0);
    observe(
        &store,
        target,
        output(matched, 100, 0, true),
        activated.activated_at() + time::Duration::seconds(1),
    )
    .await
    .unwrap();

    assert_eq!(
        store
            .observation_targets_at(activated.payment_deadline() + time::Duration::seconds(1))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<OffsetDateTime>>(
            "SELECT payment_expired_at FROM marketplace_settlements WHERE preparation_id = $1",
        )
        .bind(prepared.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        None
    );
    database.cleanup().await;
}

#[tokio::test]
async fn production_target_discovery_samples_database_time_after_settlement_lock_wait() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store, "marketplace-payment:target-lock-wait", 60).await;
    activate(&store, prepared.invoice_id()).await;

    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(
        "SELECT preparation_id FROM marketplace_settlements WHERE preparation_id = $1 FOR UPDATE",
    )
    .bind(prepared.invoice_id())
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    let deadline: OffsetDateTime = sqlx::query_scalar(
        "UPDATE marketplace_payment_preparations
         SET payment_deadline = sampled.now + INTERVAL '300 milliseconds'
         FROM (SELECT clock_timestamp() AS now) AS sampled
         WHERE id = $1 RETURNING payment_deadline",
    )
    .bind(prepared.invoice_id())
    .fetch_one(&mut *blocker)
    .await
    .unwrap();

    let task = tokio::spawn(async move { store.observation_targets().await });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    blocker.commit().await.unwrap();
    assert_eq!(task.await.unwrap().unwrap().len(), 1);

    let expired_at: Option<OffsetDateTime> = sqlx::query_scalar(
        "SELECT payment_expired_at FROM marketplace_settlements WHERE preparation_id = $1",
    )
    .bind(prepared.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert!(expired_at.is_some_and(|expired_at| expired_at > deadline));
    database.cleanup().await;
}

#[tokio::test]
async fn production_observation_samples_database_time_after_settlement_lock_wait() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let prepared = prepare(&store, "marketplace-payment:lock-wait", 60).await;
    activate(&store, prepared.invoice_id()).await;
    let target = store.observation_targets().await.unwrap().remove(0);

    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query(
        "SELECT preparation_id FROM marketplace_settlements WHERE preparation_id = $1 FOR UPDATE",
    )
    .bind(prepared.invoice_id())
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    let deadline: OffsetDateTime = sqlx::query_scalar(
        "UPDATE marketplace_payment_preparations
         SET payment_deadline = sampled.now + INTERVAL '300 milliseconds'
         FROM (SELECT clock_timestamp() AS now) AS sampled
         WHERE id = $1 RETURNING payment_deadline",
    )
    .bind(prepared.invoice_id())
    .fetch_one(&mut *blocker)
    .await
    .unwrap();

    let task = tokio::spawn(async move {
        observe_marketplace_once(
            &FixedBatch(vec![output(outpoint(8), 100, 0, true)]),
            &store,
            &BitcoinNetwork::Regtest,
            &[target],
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    blocker.commit().await.unwrap();
    assert_eq!(task.await.unwrap(), Ok(1));

    let lifecycle: (Option<OffsetDateTime>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT first_amount_matched_observed_at, payment_expired_at
         FROM marketplace_settlements WHERE preparation_id = $1",
    )
    .bind(prepared.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert!(
        lifecycle
            .0
            .is_some_and(|first_observed_at| first_observed_at > deadline)
    );
    assert!(lifecycle.1.is_some_and(|expired_at| expired_at > deadline));
    database.cleanup().await;
}
