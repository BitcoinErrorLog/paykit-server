use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid, hashes::Hash};
use paykit_sdk::PaykitIdentitySecretKey;
use paykit_server::{
    bitcoin::{ObservationTarget, ObservedOutput, TrackedOutput},
    config::BitcoinNetwork,
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    domain::payment::BitcoinOutpoint,
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, PersistenceError, run_migrations,
    },
    workers::observer::{ElectrumPort, ObserverError, observe_once, observe_once_at},
};
use paykit_server_e2e::postgres::TestDatabase;
use sqlx::Row;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

mod common;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const REGTEST_ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

struct Payloads;
impl InvoicePayloadFactory for Payloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        Ok(InvoicePayloads {
            payment_request_intent: common::payment_intent(
                &reader(),
                format!("bitcoin-address-{child_index}"),
            ),
        })
    }
}
static PAYLOADS: Payloads = Payloads;

fn crypto() -> Arc<Crypto> {
    Arc::new(Crypto::from_master_key(&[7; 32]).unwrap())
}
fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}
fn other_creator() -> CreatorPubky {
    for character in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(6..7, &character.to_string());
        if let Ok(candidate) = parse_creator(&candidate)
            && candidate != creator()
        {
            return candidate;
        }
    }
    panic!("distinct valid Creator fixture")
}
fn reader() -> ReaderPubky {
    for character in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &character.to_string());
        if let Ok(reader) = parse_reader(&candidate) {
            return reader;
        }
    }
    panic!("valid reader fixture")
}
async fn store(database: &TestDatabase) -> InvoiceStore {
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator(),
            "session".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "xpub".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    InvoiceStore::new(database.pool(), crypto)
}
async fn invoice(store: &InvoiceStore) -> (uuid::Uuid, String) {
    invoice_for(store, b"bundle", b"request", "bitcoin-address-0").await
}

async fn invoice_for(
    store: &InvoiceStore,
    bundle: &[u8],
    request: &[u8],
    address: &str,
) -> (uuid::Uuid, String) {
    let created = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: bundle,
            lock_resource_binding: b"payment-observation-lock",
            payment_request_binding: request,
            invoice_payloads: &PAYLOADS,

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap();
    (created.invoice_id(), address.into())
}

struct FixedPayloads(&'static str);
impl InvoicePayloadFactory for FixedPayloads {
    fn for_child_index(&self, _child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        Ok(InvoicePayloads {
            payment_request_intent: common::payment_intent(&reader(), self.0.to_owned()),
        })
    }
}

async fn create_other_creator(database: &TestDatabase) {
    CreatorStore::new(database.pool(), crypto())
        .create(&CreatorCredentials::new(
            other_creator(),
            "other-session".into(),
            PaykitIdentitySecretKey::new([8; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "other-xpub".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
}

async fn other_creator_invoice(
    store: &InvoiceStore,
    bundle: &[u8],
    request: &[u8],
    address: &'static str,
) -> uuid::Uuid {
    store
        .create_atomic(AtomicInvoiceInput {
            creator: &other_creator(),
            reader: &reader(),
            bundle_binding: bundle,
            lock_resource_binding: b"payment-observation-lock",
            payment_request_binding: request,
            invoice_payloads: &FixedPayloads(address),

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap()
        .invoice_id()
}
async fn facts(database: &TestDatabase, invoice_id: uuid::Uuid) -> (String, i32, bool) {
    let row = sqlx::query(
        "SELECT payment_status, confirmation_count, amount_matched FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    (
        row.get("payment_status"),
        row.get("confirmation_count"),
        row.get("amount_matched"),
    )
}

fn provider_outpoint(label: u8) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([label; 32]), 0)
}

fn persisted_outpoint(label: &str) -> BitcoinOutpoint {
    use bitcoin::hashes::sha256;

    BitcoinOutpoint::new(&sha256::Hash::hash(label.as_bytes()).to_string(), 0).unwrap()
}

fn outpoint_text(outpoint: &BitcoinOutpoint) -> String {
    format!("{}:{}", outpoint.txid(), outpoint.vout())
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

async fn batch_invoice(database: &TestDatabase) -> (InvoiceStore, uuid::Uuid) {
    let store = store(database).await;
    let invoice_id = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: b"batch-bundle",
            lock_resource_binding: b"batch-lock",
            payment_request_binding: b"batch-request",
            invoice_payloads: &FixedPayloads(REGTEST_ADDRESS),

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap()
        .invoice_id();
    (store, invoice_id)
}

fn invoice_target() -> ObservationTarget {
    ObservationTarget::new(REGTEST_ADDRESS, None)
}

fn tracked_invoice_target(outpoint: OutPoint, sats: u64) -> ObservationTarget {
    ObservationTarget::new(REGTEST_ADDRESS, Some(TrackedOutput::new(outpoint, sats)))
}

async fn assert_invoice_has_no_observation_writes(database: &TestDatabase, invoice_id: uuid::Uuid) {
    assert_eq!(
        facts(database, invoice_id).await,
        ("undetected".into(), 0, false)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bitcoin_observations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );
}

fn timestamp(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).unwrap()
}

async fn set_invoice_deadline(
    database: &TestDatabase,
    invoice_id: uuid::Uuid,
    deadline: OffsetDateTime,
) {
    sqlx::query(
        "UPDATE invoices
         SET invoice_created_at = $1 - INTERVAL '24 hours',
             proposal_expires_at = $1 - INTERVAL '23 hours',
             payment_deadline = $1
         WHERE id = $2",
    )
    .bind(deadline)
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
}

async fn install_decision_clock_audit(database: &TestDatabase) {
    sqlx::query(
        "CREATE TABLE decision_clock_audit (
             decision_at TIMESTAMPTZ NOT NULL,
             database_at TIMESTAMPTZ NOT NULL
         )",
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE FUNCTION audit_invoice_decision_clock() RETURNS trigger AS $$
         BEGIN
             IF NEW.payment_expired_at IS DISTINCT FROM OLD.payment_expired_at THEN
                 INSERT INTO decision_clock_audit VALUES
                     (NEW.payment_expired_at, clock_timestamp());
             ELSIF NEW.first_amount_matched_observed_at IS DISTINCT FROM
                   OLD.first_amount_matched_observed_at THEN
                 INSERT INTO decision_clock_audit VALUES
                     (NEW.first_amount_matched_observed_at, clock_timestamp());
             END IF;
             RETURN NEW;
         END;
         $$ LANGUAGE plpgsql",
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER audit_invoice_decision_clock
         AFTER UPDATE ON invoices
         FOR EACH ROW EXECUTE FUNCTION audit_invoice_decision_clock()",
    )
    .execute(database.pool())
    .await
    .unwrap();
}

#[tokio::test]
async fn amount_match_at_deadline_persists_first_observation_and_continues_confirmations() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let deadline = timestamp("2030-01-02T00:00:00Z");
    set_invoice_deadline(&database, invoice_id, deadline).await;
    let initial_provider_outpoint = provider_outpoint(90);
    let outpoint = BitcoinOutpoint::from_bitcoin(initial_provider_outpoint);

    assert_eq!(
        observe_once_at(
            &FixedBatch(vec![ObservedOutput {
                network: BitcoinNetwork::Regtest,
                address: REGTEST_ADDRESS.into(),
                outpoint: initial_provider_outpoint,
                sats: 100,
                confirmations: 0,
                present: true,
            }]),
            &store,
            &BitcoinNetwork::Regtest,
            &[invoice_target()],
            deadline,
        )
        .await,
        Ok(1)
    );
    let lifecycle: (Option<OffsetDateTime>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT first_amount_matched_observed_at, payment_expired_at FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(lifecycle, (Some(deadline), None));
    assert_eq!(
        store
            .observation_targets_at(deadline + time::Duration::hours(1))
            .await
            .unwrap(),
        vec![tracked_invoice_target(initial_provider_outpoint, 100)]
    );

    assert!(
        store
            .apply_bitcoin_observation_at(
                REGTEST_ADDRESS,
                &outpoint,
                100,
                1,
                true,
                deadline + time::Duration::hours(1),
            )
            .await
            .unwrap()
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );

    assert!(
        store
            .apply_bitcoin_observation_at(
                REGTEST_ADDRESS,
                &outpoint,
                100,
                0,
                false,
                deadline + time::Duration::hours(2),
            )
            .await
            .unwrap()
    );
    let replacement = BitcoinOutpoint::from_bitcoin(provider_outpoint(94));
    assert!(
        store
            .apply_bitcoin_observation_at(
                REGTEST_ADDRESS,
                &replacement,
                100,
                0,
                true,
                deadline + time::Duration::hours(3),
            )
            .await
            .unwrap()
    );
    let lifecycle: (Option<OffsetDateTime>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT first_amount_matched_observed_at, payment_expired_at FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(lifecycle.0, Some(deadline));
    assert!(lifecycle.1.is_some());

    database.cleanup().await;
}

#[tokio::test]
async fn overdue_undetected_invoice_is_durably_expired_and_remains_observable_after_restart() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let deadline = timestamp("2030-01-02T00:00:00Z");
    let after_deadline = deadline + time::Duration::microseconds(1);
    set_invoice_deadline(&database, invoice_id, deadline).await;

    assert_eq!(
        store.observation_targets_at(after_deadline).await.unwrap(),
        vec![invoice_target()]
    );
    let expired_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT payment_expired_at FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(expired_at, Some(after_deadline));

    let restarted = InvoiceStore::new(database.pool(), crypto());
    assert_eq!(
        restarted
            .observation_targets_at(after_deadline)
            .await
            .unwrap(),
        vec![invoice_target()]
    );

    database.cleanup().await;
}

#[tokio::test]
async fn first_late_match_is_persisted_as_factual_evidence_but_remains_expired() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let deadline = timestamp("2030-01-02T00:00:00Z");
    let observed_at = deadline + time::Duration::microseconds(1);
    set_invoice_deadline(&database, invoice_id, deadline).await;
    let provider_outpoint = provider_outpoint(89);
    let outpoint = BitcoinOutpoint::from_bitcoin(provider_outpoint);

    assert!(
        store
            .apply_bitcoin_observation_at(REGTEST_ADDRESS, &outpoint, 100, 0, true, observed_at,)
            .await
            .unwrap()
    );

    assert_eq!(
        facts(&database, invoice_id).await,
        ("detected".into(), 0, true)
    );
    let lifecycle: (Option<OffsetDateTime>, Option<OffsetDateTime>, i64) = sqlx::query_as(
        "SELECT first_amount_matched_observed_at, payment_expired_at,
                (SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1)
         FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(lifecycle, (Some(observed_at), Some(observed_at), 1));
    assert_eq!(
        store
            .observation_targets_at(observed_at + time::Duration::hours(1))
            .await
            .unwrap(),
        vec![tracked_invoice_target(provider_outpoint, 100)]
    );

    database.cleanup().await;
}

#[tokio::test]
async fn production_target_expiry_uses_post_fence_postgres_time() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    sqlx::query(
        "UPDATE invoices
         SET invoice_created_at = transaction_timestamp() - INTERVAL '25 hours',
             proposal_expires_at = transaction_timestamp() - INTERVAL '24 hours',
             payment_deadline = transaction_timestamp() - INTERVAL '1 hour'
         WHERE id = $1",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    install_decision_clock_audit(&database).await;

    assert_eq!(
        store.observation_targets().await.unwrap(),
        vec![invoice_target()]
    );
    let audit: (OffsetDateTime, OffsetDateTime) =
        sqlx::query_as("SELECT decision_at, database_at FROM decision_clock_audit")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(audit.0 <= audit.1);
    assert!(audit.1 - audit.0 < time::Duration::seconds(1));

    database.cleanup().await;
}

#[tokio::test]
async fn production_bitcoin_observation_uses_post_fence_postgres_time() {
    let database = TestDatabase::create().await;
    let (store, _) = batch_invoice(&database).await;
    install_decision_clock_audit(&database).await;

    let outpoint = BitcoinOutpoint::from_bitcoin(provider_outpoint(97));
    assert!(
        store
            .apply_bitcoin_observation(REGTEST_ADDRESS, &outpoint, 100, 0, true)
            .await
            .unwrap()
    );
    let audit: (OffsetDateTime, OffsetDateTime) =
        sqlx::query_as("SELECT decision_at, database_at FROM decision_clock_audit")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(audit.0 <= audit.1);
    assert!(audit.1 - audit.0 < time::Duration::seconds(1));

    database.cleanup().await;
}

#[tokio::test]
async fn production_observation_samples_database_time_after_invoice_lock_wait() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query("SELECT id FROM invoices WHERE id = $1 FOR UPDATE")
        .bind(invoice_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let deadline: OffsetDateTime = sqlx::query_scalar(
        "UPDATE invoices
         SET invoice_created_at = sampled.now + INTERVAL '300 milliseconds' - INTERVAL '24 hours',
             proposal_expires_at = sampled.now + INTERVAL '300 milliseconds' - INTERVAL '23 hours',
             payment_deadline = sampled.now + INTERVAL '300 milliseconds'
         FROM (SELECT clock_timestamp() AS now) AS sampled
         WHERE id = $1 RETURNING payment_deadline",
    )
    .bind(invoice_id)
    .fetch_one(&mut *blocker)
    .await
    .unwrap();

    let task = tokio::spawn(async move {
        let outpoint = BitcoinOutpoint::from_bitcoin(provider_outpoint(98));
        store
            .apply_bitcoin_observation(REGTEST_ADDRESS, &outpoint, 100, 0, true)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    blocker.commit().await.unwrap();
    assert!(task.await.unwrap().unwrap());

    let lifecycle: (Option<OffsetDateTime>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT first_amount_matched_observed_at, payment_expired_at
         FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
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

#[tokio::test]
async fn late_qualifying_replacement_is_factual_without_upgrading_timeliness() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let deadline = timestamp("2030-01-02T00:00:00Z");
    set_invoice_deadline(&database, invoice_id, deadline).await;
    let underpayment = BitcoinOutpoint::from_bitcoin(provider_outpoint(91));
    let late_match = BitcoinOutpoint::from_bitcoin(provider_outpoint(92));

    assert!(
        store
            .apply_bitcoin_observation_at(
                REGTEST_ADDRESS,
                &underpayment,
                99,
                0,
                true,
                deadline - time::Duration::hours(1),
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .apply_bitcoin_observation_at(
                REGTEST_ADDRESS,
                &late_match,
                100,
                0,
                true,
                deadline + time::Duration::microseconds(1),
            )
            .await
            .unwrap()
    );

    assert_eq!(
        facts(&database, invoice_id).await,
        ("detected".into(), 0, true)
    );
    let lifecycle: (Option<OffsetDateTime>, Option<OffsetDateTime>, i64) = sqlx::query_as(
        "SELECT first_amount_matched_observed_at, payment_expired_at,
                (SELECT COUNT(*) FROM bitcoin_observations)
         FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        lifecycle,
        (
            Some(deadline + time::Duration::microseconds(1)),
            Some(deadline + time::Duration::microseconds(1)),
            2,
        )
    );

    database.cleanup().await;
}

#[tokio::test]
async fn expired_replacement_survives_stale_absence_applied_after_it() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let deadline = timestamp("2030-01-02T00:00:00Z");
    set_invoice_deadline(&database, invoice_id, deadline).await;
    let original_provider_outpoint = provider_outpoint(81);
    let original = BitcoinOutpoint::from_bitcoin(original_provider_outpoint);
    let replacement_provider_outpoint = provider_outpoint(82);
    let replacement = BitcoinOutpoint::from_bitcoin(replacement_provider_outpoint);

    assert!(
        store
            .apply_bitcoin_observation_at(REGTEST_ADDRESS, &original, 99, 0, true, deadline,)
            .await
            .unwrap()
    );
    assert!(
        store
            .apply_bitcoin_observation_at(
                REGTEST_ADDRESS,
                &replacement,
                100,
                0,
                true,
                deadline + time::Duration::microseconds(1),
            )
            .await
            .unwrap()
    );

    assert!(
        store
            .apply_bitcoin_observation_at(
                REGTEST_ADDRESS,
                &original,
                99,
                0,
                false,
                deadline + time::Duration::microseconds(1),
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .observation_targets_at(deadline + time::Duration::hours(1))
            .await
            .unwrap(),
        vec![tracked_invoice_target(replacement_provider_outpoint, 100)]
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("detected".into(), 0, true)
    );

    database.cleanup().await;
}

#[tokio::test]
async fn underpayment_at_deadline_is_persisted_and_terminally_expired() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let deadline = timestamp("2030-01-02T00:00:00Z");
    set_invoice_deadline(&database, invoice_id, deadline).await;
    let underpayment = BitcoinOutpoint::from_bitcoin(provider_outpoint(93));

    assert!(
        store
            .apply_bitcoin_observation_at(REGTEST_ADDRESS, &underpayment, 99, 0, true, deadline,)
            .await
            .unwrap()
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("detected".into(), 0, false)
    );
    let lifecycle: (Option<OffsetDateTime>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT first_amount_matched_observed_at, payment_expired_at FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(lifecycle, (None, Some(deadline)));
    assert_eq!(
        store.observation_targets_at(deadline).await.unwrap(),
        vec![tracked_invoice_target(provider_outpoint(93), 99)]
    );

    database.cleanup().await;
}

#[tokio::test]
async fn matching_output_later_in_exact_deadline_batch_wins_before_expiry() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let deadline = timestamp("2030-01-02T00:00:00Z");
    set_invoice_deadline(&database, invoice_id, deadline).await;

    assert_eq!(
        observe_once_at(
            &FixedBatch(vec![
                ObservedOutput {
                    network: BitcoinNetwork::Regtest,
                    address: REGTEST_ADDRESS.into(),
                    outpoint: provider_outpoint(95),
                    sats: 99,
                    confirmations: 0,
                    present: true,
                },
                ObservedOutput {
                    network: BitcoinNetwork::Regtest,
                    address: REGTEST_ADDRESS.into(),
                    outpoint: provider_outpoint(96),
                    sats: 100,
                    confirmations: 0,
                    present: true,
                },
            ]),
            &store,
            &BitcoinNetwork::Regtest,
            &[invoice_target()],
            deadline,
        )
        .await,
        Ok(2)
    );
    let lifecycle: (Option<OffsetDateTime>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT first_amount_matched_observed_at, payment_expired_at FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(lifecycle, (Some(deadline), None));
    assert_eq!(
        facts(&database, invoice_id).await,
        ("detected".into(), 0, true)
    );

    database.cleanup().await;
}

#[tokio::test]
async fn observation_targets_reconstruct_active_output_and_exclude_final_invoice() {
    let database = TestDatabase::create().await;
    let (store, _) = batch_invoice(&database).await;
    let targets = store.observation_targets().await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0], invoice_target());

    let provider_outpoint = provider_outpoint(42);
    let persisted = BitcoinOutpoint::from_bitcoin(provider_outpoint);
    assert!(
        store
            .apply_bitcoin_observation(REGTEST_ADDRESS, &persisted, 100, 2, true)
            .await
            .unwrap()
    );
    let targets = store.observation_targets().await.unwrap();
    assert_eq!(
        targets,
        vec![tracked_invoice_target(provider_outpoint, 100)]
    );

    assert!(
        store
            .apply_bitcoin_observation(REGTEST_ADDRESS, &persisted, 100, 6, true)
            .await
            .unwrap()
    );
    assert!(store.observation_targets().await.unwrap().is_empty());
    database.cleanup().await;
}

#[tokio::test]
async fn provider_output_for_an_unrequested_address_causes_no_database_write() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let batch = FixedBatch(vec![ObservedOutput {
        network: BitcoinNetwork::Regtest,
        address: REGTEST_ADDRESS.into(),
        outpoint: provider_outpoint(9),
        sats: 100,
        confirmations: 0,
        present: true,
    }]);

    assert_eq!(
        observe_once(&batch, &store, &BitcoinNetwork::Regtest, &[]).await,
        Err(ObserverError::InvalidObservation)
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("undetected".into(), 0, false)
    );

    database.cleanup().await;
}

#[tokio::test]
async fn invalid_output_late_in_provider_batch_causes_no_database_write() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let batch = FixedBatch(vec![
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(1),
            sats: 100,
            confirmations: 0,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Signet,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(2),
            sats: 100,
            confirmations: 0,
            present: true,
        },
    ]);

    assert_eq!(
        observe_once(
            &batch,
            &store,
            &BitcoinNetwork::Regtest,
            &[invoice_target()],
        )
        .await,
        Err(ObserverError::WrongNetwork)
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("undetected".into(), 0, false)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bitcoin_observations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );

    database.cleanup().await;
}

#[tokio::test]
async fn malformed_output_late_in_provider_batch_causes_no_database_write() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let batch = FixedBatch(vec![
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(3),
            sats: 100,
            confirmations: 0,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: "not-a-bitcoin-address".into(),
            outpoint: provider_outpoint(4),
            sats: 100,
            confirmations: 0,
            present: true,
        },
    ]);

    assert_eq!(
        observe_once(
            &batch,
            &store,
            &BitcoinNetwork::Regtest,
            &[invoice_target()],
        )
        .await,
        Err(ObserverError::InvalidObservation)
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("undetected".into(), 0, false)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bitcoin_observations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );

    database.cleanup().await;
}

#[tokio::test]
async fn noncanonical_address_late_in_provider_batch_causes_no_database_write() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let batch = FixedBatch(vec![
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(31),
            sats: 100,
            confirmations: 0,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.to_ascii_uppercase(),
            outpoint: provider_outpoint(32),
            sats: 100,
            confirmations: 0,
            present: true,
        },
    ]);

    assert_eq!(
        observe_once(
            &batch,
            &store,
            &BitcoinNetwork::Regtest,
            &[invoice_target()],
        )
        .await,
        Err(ObserverError::InvalidObservation)
    );
    assert_invoice_has_no_observation_writes(&database, invoice_id).await;

    database.cleanup().await;
}

#[tokio::test]
async fn inconsistent_absence_late_in_provider_batch_causes_no_database_write() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let tracked_outpoint = provider_outpoint(33);
    let batch = FixedBatch(vec![
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(34),
            sats: 100,
            confirmations: 0,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: tracked_outpoint,
            sats: 100,
            confirmations: 1,
            present: false,
        },
    ]);

    assert_eq!(
        observe_once(
            &batch,
            &store,
            &BitcoinNetwork::Regtest,
            &[tracked_invoice_target(tracked_outpoint, 100)],
        )
        .await,
        Err(ObserverError::InvalidObservation)
    );
    assert_invoice_has_no_observation_writes(&database, invoice_id).await;

    database.cleanup().await;
}

#[tokio::test]
async fn duplicate_outpoint_late_in_provider_batch_causes_no_database_write() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let duplicate = provider_outpoint(35);
    let batch = FixedBatch(vec![
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: duplicate,
            sats: 50,
            confirmations: 0,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: duplicate,
            sats: 100,
            confirmations: 0,
            present: true,
        },
    ]);

    assert_eq!(
        observe_once(
            &batch,
            &store,
            &BitcoinNetwork::Regtest,
            &[invoice_target()],
        )
        .await,
        Err(ObserverError::InvalidObservation)
    );
    assert_invoice_has_no_observation_writes(&database, invoice_id).await;

    database.cleanup().await;
}

#[tokio::test]
async fn unrepresentable_confirmation_late_in_batch_causes_no_database_write() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let batch = FixedBatch(vec![
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(7),
            sats: 100,
            confirmations: 0,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(8),
            sats: 100,
            confirmations: u32::MAX,
            present: true,
        },
    ]);

    assert_eq!(
        observe_once(
            &batch,
            &store,
            &BitcoinNetwork::Regtest,
            &[invoice_target()],
        )
        .await,
        Err(ObserverError::InvalidObservation)
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("undetected".into(), 0, false)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bitcoin_observations")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );

    database.cleanup().await;
}

#[tokio::test]
async fn persistence_conflict_late_in_batch_rolls_back_earlier_observations() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    create_other_creator(&database).await;
    let other_invoice_id = other_creator_invoice(
        &store,
        b"batch-conflict-bundle",
        b"batch-conflict-request",
        "other-bitcoin-address-0",
    )
    .await;
    let conflicting_provider_outpoint = provider_outpoint(11);
    let conflicting_outpoint = BitcoinOutpoint::from_bitcoin(conflicting_provider_outpoint);
    assert!(
        store
            .apply_bitcoin_observation(
                "other-bitcoin-address-0",
                &conflicting_outpoint,
                100,
                0,
                true,
            )
            .await
            .unwrap()
    );
    let batch = FixedBatch(vec![
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(10),
            sats: 100,
            confirmations: 0,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: conflicting_provider_outpoint,
            sats: 100,
            confirmations: 0,
            present: true,
        },
    ]);

    assert_eq!(
        observe_once(
            &batch,
            &store,
            &BitcoinNetwork::Regtest,
            &[invoice_target()],
        )
        .await,
        Err(ObserverError::Persistence)
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("undetected".into(), 0, false)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1",
        )
        .bind(other_invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap(),
        1
    );

    database.cleanup().await;
}

#[tokio::test]
async fn multiple_underpaying_outputs_remain_separate_and_are_not_accumulated() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    let batch = FixedBatch(vec![
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(5),
            sats: 50,
            confirmations: 1,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(6),
            sats: 50,
            confirmations: 1,
            present: true,
        },
    ]);

    assert_eq!(
        observe_once(
            &batch,
            &store,
            &BitcoinNetwork::Regtest,
            &[invoice_target()],
        )
        .await,
        Ok(2)
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, false)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1 AND active",
        )
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap(),
        1
    );

    database.cleanup().await;
}

#[tokio::test]
async fn direct_observation_persists_replacement_reorg_and_six_confirmation_finality() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let (invoice_id, address) = invoice(&store).await;

    assert!(
        !store
            .apply_bitcoin_observation("wrong-address", &persisted_outpoint("wrong"), 100, 0, true,)
            .await
            .unwrap()
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("undetected".into(), 0, false)
    );

    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("rbf-old"), 100, 0, true)
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("rbf-new"), 101, 0, true)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("detected".into(), 0, true)
    );
    let protected_observation = sqlx::query(
        "SELECT observation_envelope, outpoint_lookup_hash
         FROM bitcoin_observations WHERE invoice_id = $1 AND active",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let canonical_rbf_new = outpoint_text(&persisted_outpoint("rbf-new"));

    assert_eq!(
        protected_observation.get::<Vec<u8>, _>("outpoint_lookup_hash"),
        crypto()
            .bitcoin_outpoint_lookup_hash(canonical_rbf_new.as_bytes())
            .as_bytes()
            .as_slice()
    );
    let observation_envelope = protected_observation.get::<Vec<u8>, _>("observation_envelope");
    assert!(
        !observation_envelope
            .windows(canonical_rbf_new.len())
            .any(|window| window == canonical_rbf_new.as_bytes())
    );

    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("rbf-new"), 101, 1, true)
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("ignored-while-frozen"),
            100,
            0,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT outpoint_lookup_hash FROM bitcoin_observations WHERE invoice_id = $1 AND active"
        )
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap(),
        crypto()
            .bitcoin_outpoint_lookup_hash(canonical_rbf_new.as_bytes())
            .as_bytes()
            .as_slice()
    );

    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("rbf-new"), 101, 1, false)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("undetected".into(), 0, false)
    );
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("after-unseen"), 100, 1, true)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("after-unseen"), 100, 0, true)
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("rbf-new"), 101, 0, true)
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("after-reorg"), 100, 1, true)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );

    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("after-reorg"), 100, 9, true)
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("ignored-final"), 100, 0, true)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 6, true)
    );
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT outpoint_lookup_hash FROM bitcoin_observations WHERE invoice_id = $1 AND active"
        )
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap(),
        crypto()
            .bitcoin_outpoint_lookup_hash(
                outpoint_text(&persisted_outpoint("after-reorg")).as_bytes(),
            )
            .as_bytes()
            .as_slice()
    );

    database.cleanup().await;
}

#[tokio::test]
async fn underpayment_is_nonfinal_replaceable_and_outpoints_stay_globally_unique() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let (invoice_id, address) = invoice(&store).await;

    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("underpaid"), 99, 20, true)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 20, false)
    );
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("underpaid"), 100, 0, true)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap(),
        1
    );
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("replacement"), 100, 0, true)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("detected".into(), 0, true)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bitcoin_observations WHERE outpoint_lookup_hash = $1"
        )
        .bind(
            crypto()
                .bitcoin_outpoint_lookup_hash(
                    outpoint_text(&persisted_outpoint("underpaid")).as_bytes(),
                )
                .as_bytes()
                .as_slice(),
        )
        .fetch_one(database.pool())
        .await
        .unwrap(),
        1
    );

    create_other_creator(&database).await;
    let other_id = other_creator_invoice(
        &store,
        b"bundle-two",
        b"request-two",
        "other-bitcoin-address-0",
    )
    .await;
    let error = store
        .apply_bitcoin_observation(
            "other-bitcoin-address-0",
            &persisted_outpoint("replacement"),
            100,
            0,
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(error, PersistenceError::Conflict);
    assert_eq!(
        facts(&database, other_id).await,
        ("undetected".into(), 0, false)
    );

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_first_attribution_of_one_outpoint_has_exactly_one_invoice_owner() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let (first_id, first_address) = invoice_for(
        &store,
        b"race-bundle-1",
        b"race-request-1",
        "bitcoin-address-0",
    )
    .await;
    create_other_creator(&database).await;
    let second_address = "race-other-address-0";
    let second_id =
        other_creator_invoice(&store, b"race-bundle-2", b"race-request-2", second_address).await;
    sqlx::query(
        "CREATE FUNCTION delay_racing_observation() RETURNS trigger AS $$
         BEGIN
           PERFORM pg_sleep(0.2);
           RETURN NEW;
         END;
         $$ LANGUAGE plpgsql",
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER delay_racing_observation
         BEFORE INSERT ON bitcoin_observations
         FOR EACH ROW EXECUTE FUNCTION delay_racing_observation()",
    )
    .execute(database.pool())
    .await
    .unwrap();

    let race_outpoint = persisted_outpoint("race-outpoint");
    let first = store.apply_bitcoin_observation(&first_address, &race_outpoint, 100, 1, true);
    let second = store.apply_bitcoin_observation(second_address, &race_outpoint, 100, 1, true);
    let (first, second) = tokio::join!(first, second);
    assert!(matches!(
        (&first, &second),
        (Ok(true), Err(PersistenceError::Conflict)) | (Err(PersistenceError::Conflict), Ok(true))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bitcoin_observations WHERE outpoint_lookup_hash = $1",
        )
        .bind(
            crypto()
                .bitcoin_outpoint_lookup_hash(outpoint_text(&race_outpoint).as_bytes())
                .as_bytes()
                .as_slice(),
        )
        .fetch_one(database.pool())
        .await
        .unwrap(),
        1
    );
    let first_status: String =
        sqlx::query_scalar("SELECT payment_status FROM invoices WHERE id = $1")
            .bind(first_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let second_status: String =
        sqlx::query_scalar("SELECT payment_status FROM invoices WHERE id = $1")
            .bind(second_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(matches!(
        (first_status.as_str(), second_status.as_str()),
        ("confirmed", "undetected") | ("undetected", "confirmed")
    ));

    database.cleanup().await;
}

#[tokio::test]
async fn payment_record_integrity_rejects_row_and_type_envelope_swaps() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let (first_id, first_address) = invoice_for(
        &store,
        b"swap-bundle-1",
        b"swap-request-1",
        "bitcoin-address-0",
    )
    .await;
    let (second_id, second_address) = invoice_for(
        &store,
        b"swap-bundle-2",
        b"swap-request-2",
        "bitcoin-address-1",
    )
    .await;
    create_other_creator(&database).await;
    let other_invoice_id = other_creator_invoice(
        &store,
        b"swap-other-bundle",
        b"swap-other-request",
        "swap-other-address-0",
    )
    .await;
    let first_creator_id: uuid::Uuid =
        sqlx::query_scalar("SELECT creator_id FROM invoices WHERE id = $1")
            .bind(first_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let other_creator_id: uuid::Uuid =
        sqlx::query_scalar("SELECT creator_id FROM invoices WHERE id = $1")
            .bind(other_invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    sqlx::query("UPDATE invoices SET creator_id = $1 WHERE id = $2")
        .bind(other_creator_id)
        .bind(first_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store.scan_payment_record_integrity().await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query("UPDATE invoices SET creator_id = $1 WHERE id = $2")
        .bind(first_creator_id)
        .bind(first_id)
        .execute(database.pool())
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(
            &first_address,
            &persisted_outpoint("swap-first"),
            100,
            0,
            true,
        )
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(
            &second_address,
            &persisted_outpoint("swap-second"),
            100,
            0,
            true,
        )
        .await
        .unwrap();

    let first_invoice_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT payment_record_envelope FROM invoices WHERE id = $1")
            .bind(first_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let second_invoice_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT payment_record_envelope FROM invoices WHERE id = $1")
            .bind(second_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    sqlx::query("UPDATE invoices SET payment_record_envelope = $1 WHERE id = $2")
        .bind(&second_invoice_envelope)
        .bind(first_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store.scan_payment_record_integrity().await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query("UPDATE invoices SET payment_record_envelope = $1 WHERE id = $2")
        .bind(&first_invoice_envelope)
        .bind(first_id)
        .execute(database.pool())
        .await
        .unwrap();

    let first_observation: (uuid::Uuid, Vec<u8>) = sqlx::query_as(
        "SELECT id, observation_envelope FROM bitcoin_observations WHERE invoice_id = $1",
    )
    .bind(first_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let second_observation: (uuid::Uuid, Vec<u8>) = sqlx::query_as(
        "SELECT id, observation_envelope FROM bitcoin_observations WHERE invoice_id = $1",
    )
    .bind(second_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE bitcoin_observations SET invoice_id = $1 WHERE id = $2")
        .bind(other_invoice_id)
        .bind(first_observation.0)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store.scan_payment_record_integrity().await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query("UPDATE bitcoin_observations SET invoice_id = $1 WHERE id = $2")
        .bind(first_id)
        .bind(first_observation.0)
        .execute(database.pool())
        .await
        .unwrap();
    store.scan_payment_record_integrity().await.unwrap();

    let (same_creator_parent_id, _) = invoice_for(
        &store,
        b"swap-same-creator-parent-bundle",
        b"swap-same-creator-parent-request",
        "bitcoin-address-2",
    )
    .await;
    sqlx::query("UPDATE bitcoin_observations SET invoice_id = $1 WHERE id = $2")
        .bind(same_creator_parent_id)
        .bind(first_observation.0)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store.scan_payment_record_integrity().await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query("UPDATE bitcoin_observations SET invoice_id = $1 WHERE id = $2")
        .bind(first_id)
        .bind(first_observation.0)
        .execute(database.pool())
        .await
        .unwrap();
    store.scan_payment_record_integrity().await.unwrap();

    sqlx::query("UPDATE bitcoin_observations SET observation_envelope = $1 WHERE id = $2")
        .bind(&second_observation.1)
        .bind(first_observation.0)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store.scan_payment_record_integrity().await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query("UPDATE bitcoin_observations SET observation_envelope = $1 WHERE id = $2")
        .bind(&first_observation.1)
        .bind(first_observation.0)
        .execute(database.pool())
        .await
        .unwrap();

    sqlx::query("UPDATE invoices SET payment_record_envelope = $1 WHERE id = $2")
        .bind(&first_observation.1)
        .bind(first_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store.scan_payment_record_integrity().await,
        Err(PersistenceError::CorruptOrMissing)
    );

    database.cleanup().await;
}
