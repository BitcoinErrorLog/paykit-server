use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use bitcoin::{Address, CompressedPublicKey, Network, OutPoint, Txid, hashes::Hash};
use paykit_sdk::{ReceiverNoiseSecretKey, storage::StorageState};
use paykit_server::{
    bitcoin::{ObservationTarget, ObservedOutput, TrackedOutput},
    config::BitcoinNetwork,
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext},
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    domain::payment::BitcoinOutpoint,
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoiceStore,
        NewReaderPayloadFactory, NewReaderPayloads, PersistenceError, run_migrations,
    },
    workers::observer::{
        ElectrumPort, ObservationBackend, ObservationReport, ObserverError, TipProbe,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use serde::Serialize;
use sqlx::Row;

mod common;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const REGTEST_ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

struct Payloads;
impl NewReaderPayloadFactory for Payloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        Ok(NewReaderPayloads {
            endpoint_intent: common::endpoint_intent(
                &reader(),
                format!("bitcoin-address-{child_index}"),
            ),
            bitcoin_address: format!("bitcoin-address-{child_index}"),
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
        .create(
            &CreatorCredentials::new(
                creator(),
                "session".into(),
                ReceiverNoiseSecretKey::new([9; 32]),
                "xpub".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(18),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
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
            payment_request_binding: request,
            new_reader_payloads: &PAYLOADS,
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 100,
            nonce_sats: 1,
        })
        .await
        .unwrap();
    (created.invoice_id(), address.into())
}

struct FixedPayloads(&'static str);
impl NewReaderPayloadFactory for FixedPayloads {
    fn for_child_index(&self, _child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        Ok(NewReaderPayloads {
            endpoint_intent: common::endpoint_intent(&reader(), self.0.to_owned()),
            bitcoin_address: self.0.into(),
        })
    }
}

async fn create_other_creator(database: &TestDatabase) {
    CreatorStore::new(database.pool(), crypto())
        .create(
            &CreatorCredentials::new(
                other_creator(),
                "other-session".into(),
                ReceiverNoiseSecretKey::new([8; 32]),
                "other-xpub".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(19),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
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
            payment_request_binding: request,
            new_reader_payloads: &FixedPayloads(address),
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 100,
            nonce_sats: 1,
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

async fn awaiting_invoice(
    store: &InvoiceStore,
    bundle: &'static [u8],
    request: &'static [u8],
    address: &'static str,
) -> uuid::Uuid {
    store
        .create_awaiting_baseline(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: bundle,
            payment_request_binding: request,
            new_reader_payloads: &FixedPayloads(address),
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 100,
            nonce_sats: 1,
        })
        .await
        .unwrap()
        .invoice_id()
}

async fn awaiting_other_creator_invoice(
    store: &InvoiceStore,
    bundle: &'static [u8],
    request: &'static [u8],
    address: &'static str,
) -> uuid::Uuid {
    store
        .create_awaiting_baseline(AtomicInvoiceInput {
            creator: &other_creator(),
            reader: &reader(),
            bundle_binding: bundle,
            payment_request_binding: request,
            new_reader_payloads: &FixedPayloads(address),
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 100,
            nonce_sats: 1,
        })
        .await
        .unwrap()
        .invoice_id()
}

/// Distinct canonical key tails so the fingerprint-to-seller binding written
/// by every create/reauthenticate never collides within a test database.
fn key_tail(seed: u8) -> [u8; 65] {
    [seed; 65]
}

#[tokio::test]
async fn new_1_baseline_unconfirmed_later_confirmed_above_floor_never_binds() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id =
        awaiting_invoice(&store, b"new-1-bundle", b"new-1-request", REGTEST_ADDRESS).await;
    let baseline = provider_outpoint(201);
    store
        .complete_creation_baseline(invoice_id, 100, &[baseline], &[])
        .await
        .unwrap();

    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(baseline),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();

    assert_invoice_has_no_observation_writes(&database, invoice_id).await;
    assert!(store.pending_candidates().await.unwrap().is_empty());
    database.cleanup().await;
}

#[tokio::test]
async fn baseline_input_replacement_never_binds_but_unrelated_input_does() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let baseline_input = provider_outpoint(202);
    let blocked_id = awaiting_invoice(
        &store,
        b"rbf-blocked-bundle",
        b"rbf-blocked-request",
        REGTEST_ADDRESS,
    )
    .await;
    store
        .complete_creation_baseline(blocked_id, 100, &[], &[baseline_input])
        .await
        .unwrap();
    let blocked = provider_outpoint(203);
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(blocked),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    let candidate = store.pending_candidates().await.unwrap().remove(0);
    store
        .resolve_candidate(&candidate, &[baseline_input])
        .await
        .unwrap();
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(blocked),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    assert_invoice_has_no_observation_writes(&database, blocked_id).await;

    let allowed_address = "bcrt1q6rz28mcfaxtmdy5rme7l2ae6f4h0d2sgzvv5u0";
    let allowed_id = awaiting_invoice(
        &store,
        b"rbf-allowed-bundle",
        b"rbf-allowed-request",
        allowed_address,
    )
    .await;
    store
        .complete_creation_baseline(allowed_id, 100, &[], &[baseline_input])
        .await
        .unwrap();
    let allowed = provider_outpoint(204);
    store
        .apply_bitcoin_observation_at_height(
            allowed_address,
            &BitcoinOutpoint::from_bitcoin(allowed),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    let candidate = store.pending_candidates().await.unwrap().remove(0);
    store
        .resolve_candidate(&candidate, &[provider_outpoint(205)])
        .await
        .unwrap();
    store
        .apply_bitcoin_observation_at_height(
            allowed_address,
            &BitcoinOutpoint::from_bitcoin(allowed),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, allowed_id).await,
        ("confirmed".into(), 1, true)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn post_baseline_output_binds_after_one_candidate_fetch_decision() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id =
        awaiting_invoice(&store, b"post-bundle", b"post-request", REGTEST_ADDRESS).await;
    store
        .complete_creation_baseline(invoice_id, 100, &[], &[])
        .await
        .unwrap();
    let output = provider_outpoint(206);
    for _ in 0..2 {
        store
            .apply_bitcoin_observation_at_height(
                REGTEST_ADDRESS,
                &BitcoinOutpoint::from_bitcoin(output),
                100,
                1,
                Some(101),
                true,
            )
            .await
            .unwrap();
        if let Some(candidate) = store.pending_candidates().await.unwrap().first() {
            store.resolve_candidate(candidate, &[]).await.unwrap();
        }
    }
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn output_at_or_below_creation_floor_writes_no_observation() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id =
        awaiting_invoice(&store, b"floor-bundle", b"floor-request", REGTEST_ADDRESS).await;
    store
        .complete_creation_baseline(invoice_id, 100, &[], &[])
        .await
        .unwrap();
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(provider_outpoint(207)),
            100,
            2,
            Some(100),
            true,
        )
        .await
        .unwrap();
    assert_invoice_has_no_observation_writes(&database, invoice_id).await;
    assert!(store.pending_candidates().await.unwrap().is_empty());
    database.cleanup().await;
}

#[tokio::test]
async fn confirmed_height_uses_chain_height_instead_of_confirmation_count() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id =
        awaiting_invoice(&store, b"height-bundle", b"height-request", REGTEST_ADDRESS).await;
    store
        .complete_creation_baseline(invoice_id, 850_000, &[], &[])
        .await
        .unwrap();
    let below = provider_outpoint(208);
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(below),
            100,
            1,
            Some(850_000),
            true,
        )
        .await
        .unwrap();
    assert!(store.pending_candidates().await.unwrap().is_empty());

    let above = provider_outpoint(209);
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(above),
            100,
            1,
            Some(850_001),
            true,
        )
        .await
        .unwrap();
    let candidate = store.pending_candidates().await.unwrap().remove(0);
    store.resolve_candidate(&candidate, &[]).await.unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn overpaying_replacement_inherits_baseline_and_reports_mismatch() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id = awaiting_invoice(
        &store,
        b"overpay-bundle",
        b"overpay-request",
        REGTEST_ADDRESS,
    )
    .await;
    let baseline_input = provider_outpoint(210);
    store
        .complete_creation_baseline(invoice_id, 100, &[], &[baseline_input])
        .await
        .unwrap();
    let replacement = provider_outpoint(211);
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(replacement),
            101,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();

    // §B.8.2: an overpay is never a first-bind candidate (the candidate gate
    // matches the exact nonce'd total). It binds directly as a confirmed
    // amount mismatch — the marketplace manual-review path — and the
    // creation baseline is inherited untouched: no candidate rows, no
    // ineligible markings, baseline_state stays observing.
    assert!(store.pending_candidates().await.unwrap().is_empty());
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, false)
    );
    let state: String = sqlx::query_scalar("SELECT baseline_state FROM invoices WHERE id = $1")
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
    // Correct per §B.9: the invoice stays observing; the marketplace
    // routes the order to manual_review.
    assert_eq!(state, "observing");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM invoice_baseline_outpoints WHERE invoice_id = $1",
        )
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap(),
        1,
        "only the original replaced_input baseline row may exist"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn candidate_backoff_skips_a_then_exhaustion_routes_it_to_manual_review() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_a = awaiting_invoice(
        &store,
        b"candidate-a-bundle",
        b"candidate-a-request",
        REGTEST_ADDRESS,
    )
    .await;
    store
        .complete_creation_baseline(invoice_a, 100, &[], &[])
        .await
        .unwrap();
    let outpoint_a = provider_outpoint(212);
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(outpoint_a),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    let candidate_a = store.pending_candidates().await.unwrap().remove(0);
    store
        .record_candidate_failure(&candidate_a, "fetch", 12)
        .await
        .unwrap();
    assert!(store.pending_candidates().await.unwrap().is_empty());
    let attempt: (i32, bool, String) = sqlx::query_as(
        "SELECT attempt_count, next_attempt_at > last_attempt_at, last_error_kind
         FROM bitcoin_observation_candidates WHERE invoice_id = $1",
    )
    .bind(invoice_a)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(attempt, (1, true, "fetch".into()));

    let address_b = "bcrt1q6rz28mcfaxtmdy5rme7l2ae6f4h0d2sgzvv5u0";
    let invoice_b = awaiting_invoice(
        &store,
        b"candidate-b-bundle",
        b"candidate-b-request",
        address_b,
    )
    .await;
    store
        .complete_creation_baseline(invoice_b, 100, &[], &[])
        .await
        .unwrap();
    let outpoint_b = provider_outpoint(213);
    store
        .apply_bitcoin_observation_at_height(
            address_b,
            &BitcoinOutpoint::from_bitcoin(outpoint_b),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    let ready = store.pending_candidates().await.unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].invoice_id, invoice_b);

    for _ in 1..12 {
        sqlx::query(
            "UPDATE bitcoin_observation_candidates SET next_attempt_at = NOW()
             WHERE invoice_id = $1",
        )
        .bind(invoice_a)
        .execute(database.pool())
        .await
        .unwrap();
        store
            .record_candidate_failure(&candidate_a, "fetch", 12)
            .await
            .unwrap();
    }
    let exhausted: (i32, String, String) = sqlx::query_as(
        "SELECT candidates.attempt_count, candidates.state, invoices.baseline_state
         FROM bitcoin_observation_candidates candidates
         JOIN invoices ON invoices.id = candidates.invoice_id
         WHERE candidates.invoice_id = $1",
    )
    .bind(invoice_a)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        exhausted,
        (12, "unfetchable".into(), "manual_review".into())
    );
    assert!(
        store
            .pending_candidates()
            .await
            .unwrap()
            .iter()
            .all(|candidate| candidate.invoice_id != invoice_a)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn persistence_failures_never_consume_the_candidate_fetch_retry_budget() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id = awaiting_invoice(
        &store,
        b"persist-fail-bundle",
        b"persist-fail-request",
        REGTEST_ADDRESS,
    )
    .await;
    store
        .complete_creation_baseline(invoice_id, 100, &[], &[])
        .await
        .unwrap();
    let outpoint = provider_outpoint(216);
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(outpoint),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    let candidate = store.pending_candidates().await.unwrap().remove(0);
    for _ in 0..12 {
        store
            .record_candidate_failure(&candidate, "persistence", 12)
            .await
            .unwrap();
    }

    // Twelve persistence failures: zero strikes, still pending, still
    // observing — only diagnostic state was recorded.
    let row: (i32, String, String, String) = sqlx::query_as(
        "SELECT candidates.attempt_count, candidates.state, candidates.last_error_kind,
                invoices.baseline_state
         FROM bitcoin_observation_candidates candidates
         JOIN invoices ON invoices.id = candidates.invoice_id
         WHERE candidates.invoice_id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            0,
            "pending".into(),
            "persistence".into(),
            "observing".into()
        )
    );

    // The candidate resolves and binds normally afterwards.
    store.resolve_candidate(&candidate, &[]).await.unwrap();
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(outpoint),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn oversized_candidate_transaction_moves_to_manual_review_after_one_attempt() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id = awaiting_invoice(
        &store,
        b"oversized-bundle",
        b"oversized-request",
        REGTEST_ADDRESS,
    )
    .await;
    store
        .complete_creation_baseline(invoice_id, 100, &[], &[])
        .await
        .unwrap();
    let outpoint = provider_outpoint(217);
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(outpoint),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    let candidate = store.pending_candidates().await.unwrap().remove(0);

    // A response over electrum.max_transaction_bytes is deterministically
    // unresolvable: ONE attempt ends the candidate and routes the invoice
    // to manual review — never the twelve-strike fetch path.
    store
        .record_candidate_failure(&candidate, "transaction_too_large", 12)
        .await
        .unwrap();
    let row: (i32, String, String, String) = sqlx::query_as(
        "SELECT candidates.attempt_count, candidates.state, candidates.last_error_kind,
                invoices.baseline_state
         FROM bitcoin_observation_candidates candidates
         JOIN invoices ON invoices.id = candidates.invoice_id
         WHERE candidates.invoice_id = $1",
    )
    .bind(invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            1,
            "unfetchable".into(),
            "transaction_too_large".into(),
            "manual_review".into()
        )
    );
    assert!(
        store
            .pending_candidates()
            .await
            .unwrap()
            .iter()
            .all(|entry| entry.invoice_id != invoice_id)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn baseline_hash_recomputation_matches_under_a_non_c_database_collation() {
    let Some(database) = TestDatabase::create_with_non_c_collation().await else {
        eprintln!("no creatable non-C libc collation on this server; skipping collation proof");
        return;
    };
    let store = store(&database).await;
    let invoice_id = awaiting_invoice(
        &store,
        b"collate-bundle",
        b"collate-request",
        REGTEST_ADDRESS,
    )
    .await;
    store
        .complete_creation_baseline(
            invoice_id,
            100,
            &[provider_outpoint(231)],
            &[provider_outpoint(232)],
        )
        .await
        .unwrap();

    // Binding recomputes the baseline-set hash from SQL-ordered rows;
    // under this database's non-C default collation only the explicit
    // COLLATE "C" keeps the recomputation on the hashed byte order.
    let output = provider_outpoint(233);
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(output),
            100,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    let candidate = store.pending_candidates().await.unwrap().remove(0);
    store.resolve_candidate(&candidate, &[]).await.unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );
    let integrity_failed: bool =
        sqlx::query_scalar("SELECT integrity_failed FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(!integrity_failed);
    database.cleanup().await;
}

#[tokio::test]
async fn stale_awaiting_baseline_is_voided_and_prepared_outbox_is_terminal() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id = awaiting_invoice(
        &store,
        b"sweeper-bundle",
        b"sweeper-request",
        REGTEST_ADDRESS,
    )
    .await;
    sqlx::query("UPDATE invoices SET created_at = NOW() - INTERVAL '2 minutes' WHERE id = $1")
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();

    assert_eq!(
        store
            .sweep_stale_creation_baselines(std::time::Duration::from_secs(60))
            .await
            .unwrap(),
        1
    );
    let state: String = sqlx::query_scalar("SELECT baseline_state FROM invoices WHERE id = $1")
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(state, "void_baseline_failed");
    let statuses: Vec<String> =
        sqlx::query_scalar("SELECT status FROM outbox WHERE invoice_id = $1 ORDER BY id")
            .bind(invoice_id)
            .fetch_all(database.pool())
            .await
            .unwrap();
    assert!(!statuses.is_empty() && statuses.iter().all(|status| status == "prepared"));
    database.cleanup().await;
}

struct FixedBatch(Vec<ObservedOutput>);

#[async_trait]
impl ElectrumPort for FixedBatch {
    async fn observations(
        &self,
        _tip_height: u32,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        Ok(ObservationReport {
            outputs: self.0.clone(),
            observed: targets
                .iter()
                .map(|target| target.address().to_owned())
                .collect(),
            failed: Vec::new(),
        })
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 0,
            time_unix: 0,
        })
    }
}

/// Applies one fetched batch through the same validate-then-apply path the
/// observer tick uses, for one explicit target set.
async fn observe_once(
    port: &FixedBatch,
    store: &InvoiceStore,
    network: &BitcoinNetwork,
    targets: &[ObservationTarget],
) -> Result<usize, ObserverError> {
    let report = port.observations(0, targets).await?;
    ObservationBackend::apply_observations(store, network, targets, report.outputs).await
}

#[tokio::test]
async fn corrupt_invoice_is_isolated_while_other_observation_commits() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    create_other_creator(&database).await;
    let bad_address = REGTEST_ADDRESS;
    let good_address: &'static str = Box::leak(
        Address::p2wpkh(
            &CompressedPublicKey::from_str(
                "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .unwrap(),
            Network::Regtest,
        )
        .to_string()
        .into_boxed_str(),
    );
    let bad_id = awaiting_invoice(
        &store,
        b"bad-integrity-bundle",
        b"bad-integrity-request",
        bad_address,
    )
    .await;
    store
        .complete_creation_baseline(bad_id, 100, &[], &[])
        .await
        .unwrap();
    let good_id = awaiting_other_creator_invoice(
        &store,
        b"good-integrity-bundle",
        b"good-integrity-request",
        good_address,
    )
    .await;
    store
        .complete_creation_baseline(good_id, 100, &[], &[])
        .await
        .unwrap();
    let targets = observation_targets(&store).await;
    sqlx::query("UPDATE invoices SET payment_record_envelope = $1 WHERE id = $2")
        .bind(b"corrupt-v1".as_slice())
        .bind(bad_id)
        .execute(database.pool())
        .await
        .unwrap();
    let outputs = vec![
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: bad_address.into(),
            outpoint: provider_outpoint(214),
            sats: 100,
            confirmations: 0,
            confirmed_height: None,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: good_address.into(),
            outpoint: provider_outpoint(215),
            sats: 100,
            confirmations: 0,
            confirmed_height: None,
            present: true,
        },
    ];
    assert_eq!(
        observe_once(
            &FixedBatch(outputs),
            &store,
            &BitcoinNetwork::Regtest,
            &targets,
        )
        .await
        .unwrap(),
        1
    );
    let bad_integrity: (bool, i32) = sqlx::query_as(
        "SELECT integrity_failed, integrity_failure_count FROM invoices WHERE id = $1",
    )
    .bind(bad_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(bad_integrity, (true, 1));
    assert_eq!(
        facts(&database, good_id).await,
        ("detected".into(), 0, true)
    );
    assert!(
        observation_targets(&store)
            .await
            .iter()
            .all(|target| target.address() != bad_address)
    );
    database.cleanup().await;
}

/// Every non-final invoice as an observation target, via the durable plan.
async fn observation_targets(store: &InvoiceStore) -> Vec<ObservationTarget> {
    ObservationBackend::observation_plan(store)
        .await
        .unwrap()
        .into_iter()
        .map(|planned| planned.target().clone())
        .collect()
}

async fn batch_invoice(database: &TestDatabase) -> (InvoiceStore, uuid::Uuid) {
    let store = store(database).await;
    let invoice_id = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: b"batch-bundle",
            payment_request_binding: b"batch-request",
            new_reader_payloads: &FixedPayloads(REGTEST_ADDRESS),
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 100,
            nonce_sats: 1,
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

#[tokio::test]
async fn observation_targets_reconstruct_active_output_and_exclude_final_invoice() {
    let database = TestDatabase::create().await;
    let (store, _) = batch_invoice(&database).await;
    let targets = observation_targets(&store).await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0], invoice_target());

    let provider_outpoint = provider_outpoint(42);
    let persisted = BitcoinOutpoint::from_bitcoin(provider_outpoint);
    assert!(
        store
            .apply_bitcoin_observation(REGTEST_ADDRESS, &persisted, 100, 2, None, true)
            .await
            .unwrap()
    );
    let targets = observation_targets(&store).await;
    assert_eq!(
        targets,
        vec![tracked_invoice_target(provider_outpoint, 100)]
    );

    assert!(
        store
            .apply_bitcoin_observation(REGTEST_ADDRESS, &persisted, 100, 6, None, true)
            .await
            .unwrap()
    );
    assert!(observation_targets(&store).await.is_empty());
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
        confirmed_height: None,
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
            confirmed_height: None,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Signet,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(2),
            sats: 100,
            confirmations: 0,
            confirmed_height: None,
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
            confirmed_height: None,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: "not-a-bitcoin-address".into(),
            outpoint: provider_outpoint(4),
            sats: 100,
            confirmations: 0,
            confirmed_height: None,
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
            confirmed_height: None,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.to_ascii_uppercase(),
            outpoint: provider_outpoint(32),
            sats: 100,
            confirmations: 0,
            confirmed_height: None,
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
            confirmed_height: None,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: tracked_outpoint,
            sats: 100,
            confirmations: 1,
            confirmed_height: Some(1),
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
            confirmed_height: None,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: duplicate,
            sats: 100,
            confirmations: 0,
            confirmed_height: None,
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
            confirmed_height: None,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(8),
            sats: 100,
            confirmations: u32::MAX,
            confirmed_height: Some(u32::MAX),
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
async fn persistence_conflict_late_in_batch_keeps_earlier_invoice_commit() {
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
                None,
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
            confirmed_height: None,
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: conflicting_provider_outpoint,
            sats: 100,
            confirmations: 0,
            confirmed_height: None,
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
        ("detected".into(), 0, true)
    );
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
            confirmed_height: Some(1),
            present: true,
        },
        ObservedOutput {
            network: BitcoinNetwork::Regtest,
            address: REGTEST_ADDRESS.into(),
            outpoint: provider_outpoint(6),
            sats: 50,
            confirmations: 1,
            confirmed_height: Some(1),
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
            .apply_bitcoin_observation(
                "wrong-address",
                &persisted_outpoint("wrong"),
                100,
                0,
                None,
                true,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        facts(&database, invoice_id).await,
        ("undetected".into(), 0, false)
    );

    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("rbf-old"), 100, 0, None, true)
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("rbf-new"), 100, 0, None, true)
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
        .apply_bitcoin_observation(&address, &persisted_outpoint("rbf-new"), 100, 1, None, true)
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("ignored-while-frozen"),
            100,
            0,
            None,
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
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("rbf-new"),
            100,
            1,
            None,
            false,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("undetected".into(), 0, false)
    );
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("after-unseen"),
            100,
            1,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("after-unseen"),
            100,
            0,
            None,
            true,
        )
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("rbf-new"), 100, 0, None, true)
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("after-reorg"),
            100,
            1,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );

    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("after-reorg"),
            100,
            9,
            None,
            true,
        )
        .await
        .unwrap();
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("ignored-final"),
            100,
            0,
            None,
            true,
        )
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
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("underpaid"),
            99,
            20,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 20, false)
    );
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("underpaid"),
            100,
            0,
            None,
            true,
        )
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
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("replacement"),
            100,
            0,
            None,
            true,
        )
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
            None,
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
    let first = store.apply_bitcoin_observation(&first_address, &race_outpoint, 100, 1, None, true);
    let second =
        store.apply_bitcoin_observation(second_address, &race_outpoint, 100, 1, None, true);
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
            None,
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
            None,
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

#[tokio::test]
async fn v1_payment_record_is_a_hard_integrity_error() {
    #[derive(Serialize)]
    struct InvoicePaymentRecordV1<'a> {
        version: u8,
        derivation_index: i64,
        bitcoin_address: &'a str,
        required_sats: u64,
    }

    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let (invoice_id, address) = invoice(&store).await;
    let plaintext = postcard::to_allocvec(&InvoicePaymentRecordV1 {
        version: 1,
        derivation_index: 0,
        bitcoin_address: &address,
        required_sats: 100,
    })
    .unwrap();
    let crypto = crypto();
    let creator_hash = crypto.lookup_hash(creator().to_string().as_bytes());
    let envelope = crypto
        .encrypt(
            &EnvelopeContext::invoice_payment_record(creator_hash, invoice_id),
            &plaintext,
        )
        .unwrap();
    sqlx::query("UPDATE invoices SET payment_record_envelope = $1 WHERE id = $2")
        .bind(envelope.as_bytes())
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();

    assert_eq!(
        store.scan_payment_record_integrity().await,
        Err(PersistenceError::CorruptOrMissing)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn record_observation_tick_reports_stamp_misses_without_aborting_known_records() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;

    // A record whose address lookup hash matches no invoice row, followed
    // by a valid record: the miss is reported and the valid record stamps.
    let misses = store
        .record_observation_tick(
            &["address-never-bound".to_owned(), REGTEST_ADDRESS.to_owned()],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(misses, 1);
    let stamped: bool =
        sqlx::query_scalar("SELECT last_observed_at IS NOT NULL FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(stamped);
    database.cleanup().await;
}

#[tokio::test]
async fn observation_plan_orders_oldest_observed_first_and_stamp_rotates_the_plan() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: b"plan-bundle-b",
            payment_request_binding: b"plan-request-b",
            new_reader_payloads: &FixedPayloads("plan-address-b"),
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 100,
            nonce_sats: 1,
        })
        .await
        .unwrap();

    let plan = store.observation_plan().await.unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].target().address(), REGTEST_ADDRESS);
    assert_eq!(plan[1].target().address(), "plan-address-b");

    store
        .record_observation_tick(&[REGTEST_ADDRESS.to_owned()], &[])
        .await
        .unwrap();

    let plan = store.observation_plan().await.unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].target().address(), "plan-address-b");
    assert_eq!(plan[1].target().address(), REGTEST_ADDRESS);
    let stamped: bool =
        sqlx::query_scalar("SELECT last_observed_at IS NOT NULL FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(stamped);
    database.cleanup().await;
}

#[tokio::test]
async fn a_failed_observation_attempt_rotates_the_plan_without_marking_the_target_observed() {
    let database = TestDatabase::create().await;
    let (store, invoice_id) = batch_invoice(&database).await;
    store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: b"plan-bundle-c",
            payment_request_binding: b"plan-request-c",
            new_reader_payloads: &FixedPayloads("plan-address-c"),
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 100,
            nonce_sats: 1,
        })
        .await
        .unwrap();

    let plan = store.observation_plan().await.unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].target().address(), REGTEST_ADDRESS);
    assert_eq!(plan[1].target().address(), "plan-address-c");

    // A FAILED attempt stamps last_attempted_at only: the target rotates
    // behind the rest of the plan exactly like a success (so a
    // permanently failing target cannot hold the head and starve other
    // sellers), but last_observed_at stays NULL — staleness and backlog
    // alerting keep tracking the last SUCCESSFUL observation.
    store
        .record_observation_tick(&[], &[REGTEST_ADDRESS.to_owned()])
        .await
        .unwrap();

    let plan = store.observation_plan().await.unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].target().address(), "plan-address-c");
    assert_eq!(plan[1].target().address(), REGTEST_ADDRESS);
    let observed: bool =
        sqlx::query_scalar("SELECT last_observed_at IS NOT NULL FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(
        !observed,
        "a failed attempt must not mark the target observed"
    );
    let attempted: bool =
        sqlx::query_scalar("SELECT last_attempted_at IS NOT NULL FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(attempted, "a failed attempt carries the attempt stamp");
    database.cleanup().await;
}

#[tokio::test]
async fn overpayment_reports_confirmed_amount_mismatch_and_remains_replaceable() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let (invoice_id, address) = invoice(&store).await;

    // required + 1 reports confirmed with amount_matched = false: the exact
    // facts an underpayment produces, so the marketplace manual-review path
    // is the same existing one (§B.8.2). Nothing is refunded on chain.
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("overpaid"),
            101,
            20,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 20, false)
    );
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("overpaid"),
            101,
            42,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 42, false)
    );

    // The overpaid binding never finalizes and stays replaceable: an exact
    // payment afterwards binds and finalizes at six confirmations.
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("exact"), 100, 1, None, true)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("exact"), 100, 9, None, true)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 6, true)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn first_bind_candidate_gate_uses_the_exact_required_amount() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let invoice_id =
        awaiting_invoice(&store, b"gate-bundle", b"gate-request", REGTEST_ADDRESS).await;
    store
        .complete_creation_baseline(invoice_id, 100, &[], &[])
        .await
        .unwrap();

    // required - 1 is never a first-bind candidate (behaviour unchanged).
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(provider_outpoint(210)),
            99,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    assert!(store.pending_candidates().await.unwrap().is_empty());
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, false)
    );

    // The exact required amount is candidated and, once the candidate is
    // resolved, binds over the underpayment.
    let exact = provider_outpoint(211);
    store
        .apply_bitcoin_observation_at_height(
            REGTEST_ADDRESS,
            &BitcoinOutpoint::from_bitcoin(exact),
            100,
            1,
            Some(102),
            true,
        )
        .await
        .unwrap();
    let candidates = store.pending_candidates().await.unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].outpoint, exact);
    store.resolve_candidate(&candidates[0], &[]).await.unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );

    // required + 1 is never a candidate either: it binds directly as a
    // confirmed amount mismatch, taking the same path as an underpayment.
    let overpaid_id = awaiting_invoice(
        &store,
        b"gate-over-bundle",
        b"gate-over-request",
        "bcrt1q6rz28mcfaxtmdy5rme7l2ae6f4h0d2sgzvv5u0",
    )
    .await;
    store
        .complete_creation_baseline(overpaid_id, 100, &[], &[])
        .await
        .unwrap();
    store
        .apply_bitcoin_observation_at_height(
            "bcrt1q6rz28mcfaxtmdy5rme7l2ae6f4h0d2sgzvv5u0",
            &BitcoinOutpoint::from_bitcoin(provider_outpoint(212)),
            101,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    assert!(store.pending_candidates().await.unwrap().is_empty());
    assert_eq!(
        facts(&database, overpaid_id).await,
        ("confirmed".into(), 1, false)
    );
    database.cleanup().await;
}

/// Deserialization mirror of the sealed payment record written from W1.1b
/// on; field order must match the product struct exactly.
#[derive(serde::Deserialize)]
struct InvoicePaymentRecordV3 {
    version: u8,
    derivation_index: i64,
    bitcoin_address: String,
    required_sats: u64,
    nonce_sats: u64,
    creation_chain_height: u32,
    baseline_set_hash: [u8; 32],
}

fn decrypt_payment_record(
    crypto: &Crypto,
    pool_row: &(uuid::Uuid, Vec<u8>),
) -> InvoicePaymentRecordV3 {
    let creator_hash = crypto.lookup_hash(creator().to_string().as_bytes());
    let plaintext = crypto
        .decrypt(
            &EnvelopeContext::invoice_payment_record(creator_hash, pool_row.0),
            &EncryptedEnvelope::from_bytes(pool_row.1.clone()),
        )
        .unwrap();
    postcard::from_bytes(&plaintext).unwrap()
}

async fn payment_record_row(
    database: &TestDatabase,
    invoice_id: uuid::Uuid,
) -> (uuid::Uuid, Vec<u8>) {
    sqlx::query_as("SELECT id, payment_record_envelope FROM invoices WHERE id = $1")
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn invoice_payment_record_seals_nonce_and_nonce_d_total() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let price_sats = 93_u64;
    let nonce_sats = 7_u64;
    let invoice_id = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: b"seal-bundle",
            payment_request_binding: b"seal-request",
            new_reader_payloads: &PAYLOADS,
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: price_sats + nonce_sats,
            nonce_sats,
        })
        .await
        .unwrap()
        .invoice_id();

    // The persisted invoice record seals both the nonce and the total the
    // marketplace would record, and the total equals price + nonce (§B.8.2).
    let record =
        decrypt_payment_record(&crypto(), &payment_record_row(&database, invoice_id).await);
    assert_eq!(record.version, 3);
    assert_eq!(record.derivation_index, 0);
    assert_eq!(record.bitcoin_address, "bitcoin-address-0");
    assert_eq!(record.creation_chain_height, 0);
    assert_eq!(
        record.baseline_set_hash,
        bitcoin::hashes::sha256::Hash::hash(b"").to_byte_array()
    );
    assert_eq!(record.nonce_sats, nonce_sats);
    assert_eq!(record.required_sats, price_sats + nonce_sats);
    store.scan_payment_record_integrity().await.unwrap();

    // A nonce outside [1, 999] is never persisted.
    for bad_nonce in [0, 1_000] {
        let error = store
            .create_atomic(AtomicInvoiceInput {
                creator: &creator(),
                reader: &reader(),
                bundle_binding: format!("seal-bad-{bad_nonce}").into_bytes().leak(),
                payment_request_binding: format!("seal-bad-{bad_nonce}-request")
                    .into_bytes()
                    .leak(),
                new_reader_payloads: &PAYLOADS,
                payment_request_intent: common::payment_intent(&reader()),
                required_sats: 100,
                nonce_sats: bad_nonce,
            })
            .await
            .unwrap_err();
        assert_eq!(error, PersistenceError::CorruptOrMissing);
    }

    // The nonce arithmetic contract (§B.8.2): a payment of the bare price is
    // an underpayment against the nonce'd total and never matches; only the
    // full price + nonce binds.
    store
        .apply_bitcoin_observation(
            "bitcoin-address-0",
            &persisted_outpoint("bare-price"),
            price_sats,
            6,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 6, false)
    );
    store
        .apply_bitcoin_observation(
            "bitcoin-address-0",
            &persisted_outpoint("nonce-total"),
            price_sats + nonce_sats,
            6,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 6, true)
    );
    database.cleanup().await;
}

#[tokio::test]
async fn replay_by_state_returns_the_same_nonce_total_and_address() {
    let database = TestDatabase::create().await;
    let store = store(&database).await;

    let first = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: b"replay-bundle",
            payment_request_binding: b"replay-request",
            new_reader_payloads: &PAYLOADS,
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 108,
            nonce_sats: 8,
        })
        .await
        .unwrap();
    assert!(!first.replayed());

    // A replay by state serves the stored record: even if the retry carries
    // a different nonce and total, neither is re-drawn or re-persisted, and
    // the derived address (allocated by the per-creator child-index cursor,
    // never by the amount) is the creation one.
    let replay = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: b"replay-bundle",
            payment_request_binding: b"replay-request",
            new_reader_payloads: &PAYLOADS,
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 999_999,
            nonce_sats: 999,
        })
        .await
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.invoice_id(), first.invoice_id());
    assert_eq!(replay.reader_child_index(), first.reader_child_index());

    let record = decrypt_payment_record(
        &crypto(),
        &payment_record_row(&database, first.invoice_id()).await,
    );
    assert_eq!(record.nonce_sats, 8);
    assert_eq!(record.required_sats, 108);
    assert_eq!(record.bitcoin_address, "bitcoin-address-0");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM invoices")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    database.cleanup().await;
}

#[tokio::test]
async fn pre_nonce_v2_invoice_binds_exactly_at_its_stored_required_amount() {
    #[derive(Serialize)]
    struct InvoicePaymentRecordV2<'a> {
        version: u8,
        derivation_index: i64,
        bitcoin_address: &'a str,
        required_sats: u64,
        creation_chain_height: u32,
        baseline_set_hash: [u8; 32],
    }

    let database = TestDatabase::create().await;
    let store = store(&database).await;
    let (invoice_id, address) = invoice(&store).await;

    // Rewrite the freshly sealed record as a pre-W1.1b version-2 record:
    // nonce 0, required amount as stored at creation.
    let crypto = crypto();
    let creator_hash = crypto.lookup_hash(creator().to_string().as_bytes());
    let v2_plaintext = postcard::to_allocvec(&InvoicePaymentRecordV2 {
        version: 2,
        derivation_index: 0,
        bitcoin_address: &address,
        required_sats: 100,
        creation_chain_height: 0,
        baseline_set_hash: bitcoin::hashes::sha256::Hash::hash(b"").to_byte_array(),
    })
    .unwrap();
    let v2_envelope = crypto
        .encrypt(
            &EnvelopeContext::invoice_payment_record(creator_hash, invoice_id),
            &v2_plaintext,
        )
        .unwrap();
    sqlx::query("UPDATE invoices SET payment_record_envelope = $1 WHERE id = $2")
        .bind(v2_envelope.as_bytes())
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
    store.scan_payment_record_integrity().await.unwrap();

    // required - 1 stays a mismatch, exactly as for a nonce'd invoice.
    store
        .apply_bitcoin_observation(&address, &persisted_outpoint("v2-under"), 99, 1, None, true)
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, false)
    );
    // The stored required amount binds exactly (nonce 0 legacy behaviour).
    store
        .apply_bitcoin_observation(
            &address,
            &persisted_outpoint("v2-exact"),
            100,
            1,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        facts(&database, invoice_id).await,
        ("confirmed".into(), 1, true)
    );

    // A legacy record that completes its baseline afterwards stays version 2.
    // (This is the creator's second invoice, so its child index is 1.)
    let awaiting_id = awaiting_invoice(&store, b"v2-bundle", b"v2-request", REGTEST_ADDRESS).await;
    let v2_awaiting = postcard::to_allocvec(&InvoicePaymentRecordV2 {
        version: 2,
        derivation_index: 1,
        bitcoin_address: REGTEST_ADDRESS,
        required_sats: 100,
        creation_chain_height: 0,
        baseline_set_hash: bitcoin::hashes::sha256::Hash::hash(b"").to_byte_array(),
    })
    .unwrap();
    let v2_awaiting_envelope = crypto
        .encrypt(
            &EnvelopeContext::invoice_payment_record(creator_hash, awaiting_id),
            &v2_awaiting,
        )
        .unwrap();
    sqlx::query("UPDATE invoices SET payment_record_envelope = $1 WHERE id = $2")
        .bind(v2_awaiting_envelope.as_bytes())
        .bind(awaiting_id)
        .execute(database.pool())
        .await
        .unwrap();
    store
        .complete_creation_baseline(awaiting_id, 100, &[], &[])
        .await
        .unwrap();
    let row = payment_record_row(&database, awaiting_id).await;
    let plaintext = crypto
        .decrypt(
            &EnvelopeContext::invoice_payment_record(creator_hash, row.0),
            &EncryptedEnvelope::from_bytes(row.1),
        )
        .unwrap();
    // The record version is the first postcard byte.
    assert_eq!(plaintext[0], 2);
    store.scan_payment_record_integrity().await.unwrap();
    database.cleanup().await;
}
