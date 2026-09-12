//! W1.14 unassigned-sentinel detection over REAL Postgres seams (design
//! §B.8.7): the atomic evidence+downgrade transaction, its lock ordering
//! against invoice address assignment (F11), supersession, idempotent
//! replay, restart convergence, per-creator admission cadence, the distinct
//! sentinel token budget, and the current-mode payment gate.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use bitcoin::{
    Network, OutPoint, Txid,
    bip32::{DerivationPath, Xpriv, Xpub},
    hashes::Hash,
    secp256k1::Secp256k1,
};
use paykit_sdk::{ReceiverNoiseSecretKey, storage::StorageState};
use paykit_server::{
    allocation::{AllocationMode, CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1, ClaimAllocation},
    application::payment_status::PersistedPaymentStatus,
    bitcoin::ObservationTarget,
    config::BitcoinNetwork,
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_bundle_id, parse_creator, parse_reader},
    domain::payment::BitcoinOutpoint,
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoiceStore,
        NewReaderPayloadFactory, NewReaderPayloads, PersistenceError, run_migrations,
    },
    runtime::Runtime,
    sentinel::{
        SENTINEL_SCAN_WINDOW, SentinelFinding, SentinelPolicy, SentinelThresholds,
        scan_window_addresses,
    },
    workers::observer::{
        AddressFailureReason, ElectrumPort, FailedObservation, ObservationReport, ObserverError,
        ObserverPolicy, ObserverTickOutcome, ObserverTickState, TipProbe, observe_tick,
    },
};
use paykit_server_e2e::postgres::TestDatabase;

mod common;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
/// A canonical Locks bundle identifier (Crockford-uppercase, parser-stable).
const BUNDLE_A: &str = "000G40R40M30E209185GR38E1W";

fn crypto() -> Arc<Crypto> {
    Arc::new(Crypto::from_master_key(&[7; 32]).unwrap())
}
fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}
fn second_creator() -> CreatorPubky {
    for character in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(6..7, &character.to_string());
        if let Ok(candidate) = parse_creator(&candidate)
            && candidate != creator()
        {
            return candidate;
        }
    }
    panic!("distinct valid creator fixture");
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
fn key_tail(seed: u8) -> [u8; 65] {
    [seed; 65]
}
fn exclusive_allocation() -> ClaimAllocation {
    ClaimAllocation {
        channel: Some(CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1.to_owned()),
        mode: AllocationMode::Exclusive,
        downgrade_reason: None,
    }
}
fn thresholds() -> SentinelThresholds {
    SentinelPolicy::default().thresholds
}

/// A real BIP84 account xpub (test-network kind) at `m/84'/1'/3'`, so the
/// tick's window derivation matches the addresses the fake Electrum serves.
fn test_xpub(seed: u8) -> (String, u32) {
    let secp = Secp256k1::new();
    let xprv = Xpriv::new_master(Network::Testnet, &[seed; 32]).unwrap();
    let path = DerivationPath::from_str("m/84'/1'/3'").unwrap();
    let account = xprv.derive_priv(&secp, &path).unwrap();
    (Xpub::from_priv(&secp, &account).to_string(), 3)
}

struct Payloads;
impl NewReaderPayloadFactory for Payloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        Ok(NewReaderPayloads {
            endpoint_intent: common::endpoint_intent(
                &reader(),
                format!("assigned-address-{child_index}"),
            ),
            bitcoin_address: format!("assigned-address-{child_index}"),
        })
    }
}
static PAYLOADS: Payloads = Payloads;

struct FixedPayloads(&'static str);
impl NewReaderPayloadFactory for FixedPayloads {
    fn for_child_index(&self, _child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        Ok(NewReaderPayloads {
            endpoint_intent: common::endpoint_intent(&reader(), self.0.to_owned()),
            bitcoin_address: self.0.into(),
        })
    }
}

/// A canonical regtest P2WPKH address for live observation targets (the
/// tick's batch validation requires canonical addresses).
const LIVE_ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

struct Stores {
    creators: CreatorStore,
    invoices: InvoiceStore,
    creator_id: uuid::Uuid,
}

async fn exclusive_store(database: &TestDatabase, xpub: &str, account_index: u32) -> Stores {
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let persisted = creators
        .create(
            &CreatorCredentials::new(
                creator(),
                "session".into(),
                ReceiverNoiseSecretKey::new([9; 32]),
                xpub.into(),
                account_index,
            ),
            &StorageState::default(),
            &key_tail(18),
            &exclusive_allocation(),
            0,
        )
        .await
        .unwrap();
    Stores {
        creators: creators.clone(),
        invoices: InvoiceStore::new(database.pool(), crypto),
        creator_id: persisted.id(),
    }
}

async fn create_invoice_at(store: &InvoiceStore, bundle: &'static [u8]) -> uuid::Uuid {
    // The payment-request binding is globally unique; derive it from the
    // bundle so distinct invoices never collide.
    let request: Vec<u8> = bundle.iter().map(|byte| byte.wrapping_add(1)).collect();
    store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: bundle,
            payment_request_binding: &request,
            new_reader_payloads: &PAYLOADS,
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap()
        .invoice_id()
}

async fn creator_mode(pool: &sqlx::PgPool) -> String {
    sqlx::query_scalar("SELECT allocation_mode FROM creators LIMIT 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn classifications(pool: &sqlx::PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT classification FROM sentinel_outpoints ORDER BY first_observed_at, id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn event_count(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sentinel_events")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn outpoint(label: u8) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([label; 32]), 0)
}

fn finding(index: i64, label: u8, value_sats: u64, confirmations: u32) -> SentinelFinding {
    SentinelFinding::new(
        index,
        format!("sentinel-address-{index}"),
        outpoint(label),
        value_sats,
        confirmations,
    )
}

/// The qualifying case: one confirmed output at the dust minimum paying a
/// never-assigned derived address downgrades atomically — evidence row,
/// one-way mode transition with the fixed reason, exactly one seller event.
#[tokio::test]
async fn qualifying_never_assigned_confirmed_output_downgrades_atomically() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    let outcome = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(7, 1, 294, 2)], &thresholds())
        .await
        .unwrap();

    assert!(outcome.admitted);
    assert!(outcome.downgraded);
    assert_eq!(outcome.evidence, 1);
    assert_eq!(
        creator_mode(database.pool()).await,
        "shared_manual",
        "the one-way exclusive -> shared_manual transition"
    );
    let (reason,): (String,) = sqlx::query_as("SELECT downgrade_reason FROM creators LIMIT 1")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(reason, "unassigned_sentinel_evidence");
    assert_eq!(classifications(database.pool()).await, vec!["evidence"]);
    assert_eq!(event_count(database.pool()).await, 1);
    let evidence = stores.creators.sentinel_evidence(&creator()).await.unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].classification, "evidence");
    assert_eq!(evidence[0].derivation_index, 7);
    assert_eq!(evidence[0].outpoint, outpoint(1).to_string());
    assert_eq!(evidence[0].value_sats, 294);
    assert_eq!(evidence[0].confirmations, 2);
    database.cleanup().await;
}

/// Threshold direction one: a confirmed output BELOW the value minimum is
/// not even a candidate — nothing is persisted, nothing downgrades.
#[tokio::test]
async fn below_min_value_confirmed_output_never_downgrades() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    let outcome = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(3, 2, 293, 5)], &thresholds())
        .await
        .unwrap();

    assert!(outcome.admitted);
    assert!(!outcome.downgraded);
    assert_eq!(outcome.evidence, 0);
    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert!(classifications(database.pool()).await.is_empty());
    assert_eq!(event_count(database.pool()).await, 0);
    database.cleanup().await;
}

/// Threshold direction two: below the distinct-hit count records evidence
/// but does not downgrade; reaching the count does — exactly once.
#[tokio::test]
async fn below_distinct_hit_count_records_evidence_without_downgrading() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;
    let two_hits = SentinelThresholds {
        min_value_sats: 294,
        hit_count: 2,
    };

    let first = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(1, 3, 500, 1)], &two_hits)
        .await
        .unwrap();
    assert!(first.admitted);
    assert!(!first.downgraded, "one hit below the two-hit count");
    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert_eq!(classifications(database.pool()).await, vec!["evidence"]);
    assert_eq!(event_count(database.pool()).await, 0);

    let second = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(2, 4, 500, 1)], &two_hits)
        .await
        .unwrap();
    assert!(second.downgraded, "the second distinct hit satisfies it");
    assert_eq!(creator_mode(database.pool()).await, "shared_manual");
    assert_eq!(event_count(database.pool()).await, 1);
    database.cleanup().await;
}

/// Threshold direction three: a mempool-only qualifying output is a durable
/// CANDIDATE — never evidence, never a downgrade — and promotes to evidence
/// only when a later scan observes it confirmed.
#[tokio::test]
async fn mempool_only_output_is_a_candidate_until_it_confirms() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    let mempool = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(4, 5, 600, 0)], &thresholds())
        .await
        .unwrap();
    assert!(mempool.admitted);
    assert!(!mempool.downgraded, "mempool-only is never evidence");
    assert_eq!(mempool.candidates, 1);
    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert_eq!(classifications(database.pool()).await, vec!["candidate"]);
    assert_eq!(event_count(database.pool()).await, 0);

    let confirmed = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(4, 5, 600, 3)], &thresholds())
        .await
        .unwrap();
    assert!(
        confirmed.downgraded,
        "the confirmed candidate is now evidence"
    );
    assert_eq!(classifications(database.pool()).await, vec!["evidence"]);
    let rows: Vec<(i32,)> = sqlx::query_as("SELECT confirmations FROM sentinel_outpoints")
        .fetch_all(database.pool())
        .await
        .unwrap();
    assert_eq!(
        rows,
        vec![(3,)],
        "the durable row tracks confirmation status"
    );
    assert_eq!(event_count(database.pool()).await, 1);
    database.cleanup().await;
}

/// Under/over/late payments to ASSIGNED invoice addresses are
/// invoice-specific ambiguous evidence: the marketplace-facing routing
/// flags fire, the creator's mode NEVER changes, and the sentinel records
/// nothing. Presenting the same outpoints to the sentinel at their (now
/// assigned) derivation indices yields `superseded_by_assignment`, never
/// account-wide evidence.
#[tokio::test]
async fn assigned_address_payments_never_downgrade_the_creator() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    // Underpayment at the index-0 invoice address.
    let under_id = create_invoice_at(&stores.invoices, b"under-bundle").await;
    stores
        .invoices
        .apply_bitcoin_observation(
            "assigned-address-0",
            &BitcoinOutpoint::from_bitcoin(outpoint(11)),
            50,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    // Overpayment at the index-1 invoice address.
    create_invoice_at(&stores.invoices, b"over-bundle").await;
    stores
        .invoices
        .apply_bitcoin_observation(
            "assigned-address-1",
            &BitcoinOutpoint::from_bitcoin(outpoint(12)),
            150,
            1,
            Some(101),
            true,
        )
        .await
        .unwrap();
    // Late payment at the index-2 invoice address (expired tail).
    let late_id = create_invoice_at(&stores.invoices, b"late-bundle").await;
    sqlx::query("UPDATE invoices SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1")
        .bind(late_id)
        .execute(database.pool())
        .await
        .unwrap();
    stores
        .invoices
        .apply_expiry_transitions(Duration::from_secs(24 * 60 * 60))
        .await
        .unwrap();
    stores
        .invoices
        .apply_bitcoin_observation(
            "assigned-address-2",
            &BitcoinOutpoint::from_bitcoin(outpoint(13)),
            100,
            6,
            Some(301),
            true,
        )
        .await
        .unwrap();

    // Invoice-specific routing evidence fired.
    let mismatch: (bool,) = sqlx::query_as("SELECT amount_matched FROM invoices WHERE id = $1")
        .bind(under_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert!(
        !mismatch.0,
        "underpayment routes that invoice to manual_review"
    );
    let late: (bool,) = sqlx::query_as(
        "SELECT late_settlement FROM bitcoin_observations WHERE invoice_id = $1 AND active",
    )
    .bind(late_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert!(late.0, "late payment routes that invoice to manual_review");

    // The creator's mode is untouched and the sentinel recorded nothing.
    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert!(classifications(database.pool()).await.is_empty());
    assert_eq!(event_count(database.pool()).await, 0);

    // The same payments presented at their assigned derivation indices are
    // superseded, never account-wide evidence (indices 0, 1, 2 are all
    // assigned now; the cursor advanced to 3).
    let outcome = stores
        .creators
        .apply_sentinel_scan(
            stores.creator_id,
            &[
                SentinelFinding::new(0, "assigned-address-0".into(), outpoint(11), 294, 3),
                SentinelFinding::new(1, "assigned-address-1".into(), outpoint(12), 294, 3),
                SentinelFinding::new(2, "assigned-address-2".into(), outpoint(13), 294, 3),
            ],
            &thresholds(),
        )
        .await
        .unwrap();
    assert!(outcome.admitted);
    assert!(!outcome.downgraded);
    assert_eq!(outcome.superseded, 3);
    assert_eq!(outcome.evidence, 0);
    assert_eq!(
        classifications(database.pool()).await,
        vec!["superseded_by_assignment"; 3]
    );
    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert_eq!(event_count(database.pool()).await, 0);
    database.cleanup().await;
}

/// A candidate whose derivation index is assigned to an invoice BEFORE the
/// sentinel's atomic re-check commits is recorded
/// `superseded_by_assignment` and never downgrades.
#[tokio::test]
async fn assigned_before_commit_candidate_becomes_superseded_by_assignment() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    // The assignment wins: index 0 is bound to an invoice (cursor -> 1)
    // before the sentinel's finding at index 0 is applied.
    create_invoice_at(&stores.invoices, BUNDLE_A.as_bytes()).await;

    let outcome = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(0, 21, 1000, 4)], &thresholds())
        .await
        .unwrap();

    assert!(outcome.admitted);
    assert!(!outcome.downgraded);
    assert_eq!(outcome.superseded, 1);
    assert_eq!(
        classifications(database.pool()).await,
        vec!["superseded_by_assignment"]
    );
    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert_eq!(event_count(database.pool()).await, 0);
    database.cleanup().await;
}

/// F11: the sentinel's atomic apply and invoice assignment serialize on the
/// SAME creators row lock. While a third transaction holds that lock, BOTH
/// block; after it releases, both complete and the final state is exactly
/// one of the two lock orders — never a divergent mix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f11_assignment_and_scan_serialize_on_the_creator_row_lock() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    let mut holder = database.pool().begin().await.unwrap();
    let (cursor,): (i64,) =
        sqlx::query_as("SELECT next_child_index FROM creators WHERE id = $1 FOR UPDATE")
            .bind(stores.creator_id)
            .fetch_one(&mut *holder)
            .await
            .unwrap();
    assert_eq!(cursor, 0);

    let invoices = stores.invoices.clone();
    let assignment = tokio::spawn(async move {
        invoices
            .create_atomic(AtomicInvoiceInput {
                creator: &creator(),
                reader: &reader(),
                bundle_binding: BUNDLE_A.as_bytes(),
                payment_request_binding: b"request",
                new_reader_payloads: &PAYLOADS,
                payment_request_intent: common::payment_intent(&reader()),
                required_sats: 100,
                nonce_sats: 1,
                prepare_ttl: Duration::from_secs(900),
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !assignment.is_finished(),
        "assignment must block on the held creator row lock"
    );

    let creators = stores.creators.clone();
    let creator_id = stores.creator_id;
    let scan = tokio::spawn(async move {
        creators
            .apply_sentinel_scan(creator_id, &[finding(0, 31, 700, 2)], &thresholds())
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !scan.is_finished(),
        "the sentinel apply must block on the SAME creator row lock"
    );

    holder.commit().await.unwrap();
    assignment.await.unwrap();
    let outcome = scan.await.unwrap();

    // Exactly one lock order happened, proven by a consistent final state.
    let mode = creator_mode(database.pool()).await;
    let classes = classifications(database.pool()).await;
    let events = event_count(database.pool()).await;
    if outcome.superseded == 1 {
        assert_eq!(mode, "exclusive", "assignment won; no downgrade");
        assert_eq!(classes, vec!["superseded_by_assignment"]);
        assert_eq!(events, 0);
    } else {
        assert!(outcome.downgraded, "the scan won the lock first");
        assert_eq!(mode, "shared_manual");
        assert_eq!(classes, vec!["evidence"]);
        assert_eq!(events, 1);
    }
    database.cleanup().await;
}

/// A derivation index burned by a failed-baseline invoice is still
/// "assigned to an invoice" for the §B.8.7 predicate: the index was
/// allocated (advancing the cursor) and is never reused, so a sentinel
/// finding there is `superseded_by_assignment`, never account-wide
/// evidence, and never downgrades. This is the exact-assignment re-check,
/// not a conflation of "never paid" with "never assigned".
#[tokio::test]
async fn burned_baseline_index_is_assigned_not_sentinel_evidence() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    // Index 0 is assigned to an invoice that then expires all the way to
    // `expired_final`: the invoice is dead, the index is burned (never
    // reusable), and the cursor has advanced past it.
    let invoice_id = create_invoice_at(&stores.invoices, BUNDLE_A.as_bytes()).await;
    sqlx::query("UPDATE invoices SET expires_at = NOW() - INTERVAL '3 days' WHERE id = $1")
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
    // observing -> expired_tail -> expired_final.
    for _ in 0..2 {
        stores
            .invoices
            .apply_expiry_transitions(Duration::from_secs(24 * 60 * 60))
            .await
            .unwrap();
    }
    let (baseline, cursor): (String, i64) = sqlx::query_as(
        "SELECT baseline_state, (SELECT next_child_index FROM creators LIMIT 1) \
         FROM invoices LIMIT 1",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        baseline, "expired_final",
        "the dead invoice leaves its index burned"
    );
    assert_eq!(cursor, 1);

    let outcome = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(0, 24, 900, 3)], &thresholds())
        .await
        .unwrap();
    assert!(outcome.admitted);
    assert!(!outcome.downgraded);
    assert_eq!(
        outcome.superseded, 1,
        "a burned index counts as assigned: superseded, not evidence"
    );
    assert_eq!(outcome.evidence, 0);
    assert_eq!(
        classifications(database.pool()).await,
        vec!["superseded_by_assignment"]
    );
    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert_eq!(event_count(database.pool()).await, 0);
    database.cleanup().await;
}

/// F11 scan-wins over TWO OVERLAPPING REAL Postgres transactions: the
/// scanner holds the creator allocation row lock while the assignment is
/// attempted, the assignment provably BLOCKS behind it, and after the
/// scanner commits the assignment proceeds to the scan-won result — the
/// downgrade stands, the finding is evidence (never retroactively
/// superseded), and shared_manual sellers still sell. No sequential
/// substitute and no in-memory repository: a test connection locks
/// `sentinel_outpoints` against writers, which holds the scanner's real
/// transaction open (its evidence INSERT blocks) with the creator row
/// lock already taken, and `pg_stat_activity` proves the scanner reached
/// that blocked INSERT before the assignment is attempted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f11_scan_winning_the_lock_blocks_assignment_until_commit() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    // Hold the evidence table against writers: the scanner's real
    // transaction takes the creator row lock first, then blocks on its
    // evidence INSERT until this connection commits.
    let mut table_holder = database.pool().begin().await.unwrap();
    sqlx::query("LOCK TABLE sentinel_outpoints IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *table_holder)
        .await
        .unwrap();

    let creators = stores.creators.clone();
    let creator_id = stores.creator_id;
    let scan = tokio::spawn(async move {
        creators
            .apply_sentinel_scan(creator_id, &[finding(0, 32, 700, 2)], &thresholds())
            .await
            .unwrap()
    });

    // Wait until the scanner's transaction is provably blocked inside its
    // evidence INSERT — at which point it already holds the creator row
    // lock (the FOR UPDATE read precedes every write).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity \
             WHERE wait_event_type = 'Lock' AND query LIKE '%INSERT INTO sentinel_outpoints%'",
        )
        .fetch_one(database.pool())
        .await
        .unwrap();
        if blocked > 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the scanner never reached its blocked evidence INSERT"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The scanner now holds the creator allocation row lock. Attempt the
    // assignment: it must BLOCK behind the scanner — no interleaving in
    // which an assignment slips past the scanning transaction exists.
    let invoices = stores.invoices.clone();
    let assignment = tokio::spawn(async move {
        invoices
            .create_atomic(AtomicInvoiceInput {
                creator: &creator(),
                reader: &reader(),
                bundle_binding: BUNDLE_A.as_bytes(),
                payment_request_binding: b"request",
                new_reader_payloads: &PAYLOADS,
                payment_request_intent: common::payment_intent(&reader()),
                required_sats: 100,
                nonce_sats: 1,
                prepare_ttl: Duration::from_secs(900),
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !assignment.is_finished(),
        "the assignment must block behind the scanner's held creator row lock"
    );
    assert!(
        !scan.is_finished(),
        "the scanner is still blocked on its evidence insert"
    );

    // Release the table: the scanner commits first (downgrade), then the
    // blocked assignment proceeds against the scan-won state.
    table_holder.commit().await.unwrap();
    let outcome = scan.await.unwrap();
    assert!(outcome.downgraded, "the scan won the lock");
    assignment.await.unwrap();

    assert_eq!(creator_mode(database.pool()).await, "shared_manual");
    assert_eq!(
        classifications(database.pool()).await,
        vec!["evidence"],
        "scan-time evidence is never retroactively superseded"
    );
    assert_eq!(event_count(database.pool()).await, 1);
    let (cursor,): (i64,) = sqlx::query_as("SELECT next_child_index FROM creators LIMIT 1")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        cursor, 1,
        "the blocked assignment proceeded after the scanner committed"
    );
    database.cleanup().await;
}

/// Repeat hits inside and after the downgrading scan may add evidence but
/// must never create a second alert; a replayed outpoint can never
/// double-count a distinct hit.
#[tokio::test]
async fn repeat_hits_add_evidence_without_a_second_alert() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    // Two qualifying outpoints in ONE scan: both become evidence, the first
    // satisfies the predicate, and exactly one event exists forever.
    let outcome = stores
        .creators
        .apply_sentinel_scan(
            stores.creator_id,
            &[finding(5, 41, 400, 1), finding(6, 42, 400, 1)],
            &thresholds(),
        )
        .await
        .unwrap();
    assert!(outcome.downgraded);
    assert_eq!(outcome.evidence, 2);
    assert_eq!(event_count(database.pool()).await, 1);
    assert_eq!(
        classifications(database.pool()).await,
        vec!["evidence", "evidence"]
    );

    // After the downgrade the creator is not RE-admitted (`admitted` is
    // false — no new budget admission), but §B.8.7 records post-downgrade
    // hits: the replayed outpoint is absorbed idempotently and the NEW
    // distinct outpoint lands as a third evidence row. The single event
    // stands — no second transition, no second alert.
    let replay = stores
        .creators
        .apply_sentinel_scan(
            stores.creator_id,
            &[finding(5, 41, 400, 4), finding(8, 43, 400, 4)],
            &thresholds(),
        )
        .await
        .unwrap();
    assert!(
        !replay.admitted,
        "shared_manual consumes no sentinel budget"
    );
    assert!(!replay.downgraded);
    assert_eq!(
        replay.evidence, 1,
        "the new distinct outpoint commits as post-downgrade evidence"
    );
    assert_eq!(event_count(database.pool()).await, 1);
    assert_eq!(
        classifications(database.pool()).await,
        vec!["evidence", "evidence", "evidence"]
    );
    database.cleanup().await;
}

/// The §B.8.7 in-flight commit: a scan ADMITTED while the creator was
/// still exclusive whose result lands AFTER another scan already
/// downgraded it. Its valid new evidence and candidate rows still commit
/// and are visible on the seller's status surface — without a second mode
/// transition, event or alert, without stamping the scan cadence (no
/// continuing periodic scans after the downgrade), and without reopening
/// general admission (the planner still excludes shared_manual).
#[tokio::test]
async fn in_flight_scan_result_commits_evidence_after_the_downgrade() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    // Scan A (already applied): the qualifying hit downgrades atomically.
    let first = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(1, 55, 700, 2)], &thresholds())
        .await
        .unwrap();
    assert!(first.downgraded);
    assert_eq!(event_count(database.pool()).await, 1);
    let stamp_after_first: time::OffsetDateTime =
        sqlx::query_scalar("SELECT sentinel_last_scanned_at FROM creators LIMIT 1")
            .fetch_one(database.pool())
            .await
            .unwrap();

    // Scan B was admitted before A committed (the planner saw exclusive)
    // but its result lands now: a new confirmed qualifying outpoint and a
    // new mempool-only one at never-assigned indices.
    let second = stores
        .creators
        .apply_sentinel_scan(
            stores.creator_id,
            &[finding(2, 56, 700, 2), finding(3, 57, 700, 0)],
            &thresholds(),
        )
        .await
        .unwrap();
    assert!(
        !second.admitted,
        "the creator was not re-admitted: this is the in-flight commit"
    );
    assert!(!second.downgraded, "no second transition exists");
    assert_eq!(second.evidence, 1);
    assert_eq!(second.candidates, 1);

    // The new distinct evidence row is visible on the seller's status
    // surface; the event/alert count remains exactly one forever.
    let mut classes = classifications(database.pool()).await;
    classes.sort();
    assert_eq!(classes, vec!["candidate", "evidence", "evidence"]);
    assert_eq!(event_count(database.pool()).await, 1);
    let evidence = stores.creators.sentinel_evidence(&creator()).await.unwrap();
    assert_eq!(evidence.len(), 3);
    let outpoints: HashSet<String> = evidence.iter().map(|row| row.outpoint.clone()).collect();
    assert!(outpoints.contains(&outpoint(56).to_string()));
    let candidate = evidence
        .iter()
        .find(|row| row.classification == "candidate")
        .expect("the mempool-only row commits as a candidate");
    assert_eq!(candidate.outpoint, outpoint(57).to_string());

    // No continuing periodic scans after the downgrade: the cadence cursor
    // did not move, and the planner never re-admits shared_manual.
    let stamp_after_second: time::OffsetDateTime =
        sqlx::query_scalar("SELECT sentinel_last_scanned_at FROM creators LIMIT 1")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(stamp_after_first, stamp_after_second);
    assert!(
        stores
            .creators
            .sentinel_plan(Duration::ZERO, 10)
            .await
            .unwrap()
            .is_empty(),
        "shared_manual is never re-admitted to the sentinel plan"
    );
    assert_eq!(creator_mode(database.pool()).await, "shared_manual");
    let (reason,): (String,) = sqlx::query_as("SELECT downgrade_reason FROM creators LIMIT 1")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(reason, "unassigned_sentinel_evidence");
    database.cleanup().await;
}

/// General admission is NOT reopened: a shared_manual creator downgraded
/// for any reason OTHER than the sentinel's own
/// (`unassigned_sentinel_evidence`) is a complete no-op for
/// `apply_sentinel_scan` — no evidence, no events, no stamp.
#[tokio::test]
async fn other_shared_manual_creators_remain_a_complete_noop() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    let creators = CreatorStore::new(database.pool(), crypto);
    creators
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
            &ClaimAllocation {
                channel: None,
                mode: AllocationMode::SharedManual,
                downgrade_reason: Some(
                    paykit_server::allocation::DowngradeReason::AccountHasHistory,
                ),
            },
            0,
        )
        .await
        .unwrap();
    let (creator_id,): (uuid::Uuid,) = sqlx::query_as("SELECT id FROM creators LIMIT 1")
        .fetch_one(database.pool())
        .await
        .unwrap();

    let outcome = creators
        .apply_sentinel_scan(creator_id, &[finding(1, 58, 700, 2)], &thresholds())
        .await
        .unwrap();
    assert!(!outcome.admitted);
    assert_eq!(outcome, Default::default());
    assert!(classifications(database.pool()).await.is_empty());
    assert_eq!(event_count(database.pool()).await, 0);
    let (stamped,): (bool,) =
        sqlx::query_as("SELECT sentinel_last_scanned_at IS NOT NULL FROM creators LIMIT 1")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(!stamped);
    database.cleanup().await;
}

/// Idempotent replay while still admitted: the same outpoint presented
/// twice counts one distinct hit and cannot duplicate the transition.
#[tokio::test]
async fn replayed_outpoint_never_double_counts_distinct_hits() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;
    let two_hits = SentinelThresholds {
        min_value_sats: 294,
        hit_count: 2,
    };

    stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(1, 51, 500, 1)], &two_hits)
        .await
        .unwrap();
    let replay = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(1, 51, 500, 2)], &two_hits)
        .await
        .unwrap();
    assert!(!replay.downgraded, "a replay is not a second distinct hit");
    assert_eq!(event_count(database.pool()).await, 0);
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sentinel_outpoints")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "the UNIQUE (creator, outpoint) key absorbs replays"
    );

    let second = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(2, 52, 500, 1)], &two_hits)
        .await
        .unwrap();
    assert!(second.downgraded);
    assert_eq!(event_count(database.pool()).await, 1);
    database.cleanup().await;
}

/// A failed apply rolls back completely (no partial evidence, no mode
/// move), and a retry after the failure converges with no divergence.
#[tokio::test]
async fn failed_apply_rolls_back_and_retry_converges() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;

    // The second finding's value overflows BIGINT, failing the transaction
    // AFTER the first finding's insert — the rollback must erase it.
    let overflow = SentinelFinding::new(2, "sentinel-address-2".into(), outpoint(62), u64::MAX, 1);
    let failed = stores
        .creators
        .apply_sentinel_scan(
            stores.creator_id,
            &[finding(1, 61, 500, 1), overflow],
            &thresholds(),
        )
        .await;
    assert!(failed.is_err());
    assert!(classifications(database.pool()).await.is_empty());
    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert_eq!(event_count(database.pool()).await, 0);
    let (stamped,): (bool,) =
        sqlx::query_as("SELECT sentinel_last_scanned_at IS NOT NULL FROM creators LIMIT 1")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(!stamped, "a failed apply must not stamp the scan cursor");

    let retried = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(1, 61, 500, 1)], &thresholds())
        .await
        .unwrap();
    assert!(retried.downgraded);
    assert_eq!(classifications(database.pool()).await, vec!["evidence"]);
    assert_eq!(event_count(database.pool()).await, 1);
    database.cleanup().await;
}

/// The mode survives a restart (fresh stores over the same database), and
/// the payment-status transition surface reads the creator's CURRENT mode
/// from the database at read time — never a claim-time cached copy.
#[tokio::test]
async fn mode_survives_restart_and_transition_reads_current_db_value() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;
    create_invoice_at(&stores.invoices, BUNDLE_A.as_bytes()).await;
    let before = stores
        .invoices
        .payment_status(&creator(), &parse_bundle_id(BUNDLE_A).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.allocation_mode(), AllocationMode::Exclusive);

    stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(3, 71, 900, 1)], &thresholds())
        .await
        .unwrap();
    drop(stores);

    // "Restart": brand-new stores over the same pool; nothing is cached.
    let crypto = crypto();
    let restarted = InvoiceStore::new(database.pool(), crypto.clone());
    let restarted_creators = CreatorStore::new(database.pool(), crypto);
    assert_eq!(creator_mode(database.pool()).await, "shared_manual");
    let evidence = restarted_creators
        .sentinel_evidence(&creator())
        .await
        .unwrap();
    assert_eq!(evidence.len(), 1, "evidence is durable across the restart");

    let after = restarted
        .payment_status(&creator(), &parse_bundle_id(BUNDLE_A).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after.allocation_mode(),
        AllocationMode::SharedManual,
        "the transition surface serves the current DB mode"
    );
    database.cleanup().await;
}

/// A downgrade landing after invoice creation but before the payment commit
/// prevents the automatic paid path: the observation facts are still
/// recorded, but the status surface reports the creator's current
/// `shared_manual` mode, which routes the order to the existing
/// manual-review/seller-confirm path contract.
#[tokio::test]
async fn downgrade_racing_an_observing_invoice_prevents_automatic_paid() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;
    create_invoice_at(&stores.invoices, BUNDLE_A.as_bytes()).await;

    // The sentinel downgrade lands while the invoice is observing.
    let downgraded = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(9, 81, 800, 1)], &thresholds())
        .await
        .unwrap();
    assert!(downgraded.downgraded);

    // The exact payment commits afterwards.
    stores
        .invoices
        .apply_bitcoin_observation(
            "assigned-address-0",
            &BitcoinOutpoint::from_bitcoin(outpoint(82)),
            100,
            6,
            Some(301),
            true,
        )
        .await
        .unwrap();

    let status = stores
        .invoices
        .payment_status(&creator(), &parse_bundle_id(BUNDLE_A).unwrap())
        .await
        .unwrap()
        .unwrap();
    let PersistedPaymentStatus::Confirmed {
        confirmations,
        amount_matched,
        late_settlement,
        allocation_mode,
    } = status
    else {
        panic!("the exact confirmed payment is recorded: {status:?}");
    };
    assert_eq!(confirmations, 6);
    assert!(amount_matched);
    assert!(!late_settlement);
    assert_eq!(
        allocation_mode,
        AllocationMode::SharedManual,
        "current mode gates automatic paid: the marketplace routes manual_review"
    );
    database.cleanup().await;
}

/// shared_manual creators are never admitted to the sentinel plan and
/// consume no sentinel budget.
#[tokio::test]
async fn shared_manual_creators_are_never_admitted() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    let creators = CreatorStore::new(database.pool(), crypto);
    creators
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
            &ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();

    assert!(
        creators
            .sentinel_plan(Duration::ZERO, 10)
            .await
            .unwrap()
            .is_empty(),
        "pasted/manual creators consume no sentinel budget"
    );
    database.cleanup().await;
}

/// Per-creator admission cadence: a scanned creator is re-admitted only
/// after the re-scan interval, and the age alert reports the oldest
/// admitted exclusive creator's staleness without gating anything.
#[tokio::test]
async fn per_creator_rescan_interval_and_age_alert() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;
    let rescan = Duration::from_secs(10 * 60);

    let plan = stores.creators.sentinel_plan(rescan, 10).await.unwrap();
    assert_eq!(plan.len(), 1, "a never-scanned exclusive creator is due");
    assert_eq!(plan[0].creator_id(), stores.creator_id);
    assert_eq!(plan[0].window_start(), 0);

    // A successful (finding-free) scan stamps the cursor.
    let outcome = stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[], &thresholds())
        .await
        .unwrap();
    assert!(outcome.admitted);
    assert!(!outcome.downgraded);
    assert!(
        stores
            .creators
            .sentinel_plan(rescan, 10)
            .await
            .unwrap()
            .is_empty(),
        "inside the 10-minute re-scan interval the creator is not re-admitted"
    );
    assert_eq!(
        stores
            .creators
            .sentinel_plan(Duration::ZERO, 10)
            .await
            .unwrap()
            .len(),
        1,
        "a zero interval re-admits immediately"
    );

    // The age alert reads the oldest admitted exclusive creator's
    // staleness; it reports, never mutates the mode or gates creation.
    let age = stores
        .creators
        .oldest_exclusive_sentinel_age()
        .await
        .unwrap()
        .unwrap();
    assert!(age < Duration::from_secs(60));
    sqlx::query("UPDATE creators SET sentinel_last_scanned_at = NOW() - INTERVAL '2 hours'")
        .execute(database.pool())
        .await
        .unwrap();
    let age = stores
        .creators
        .oldest_exclusive_sentinel_age()
        .await
        .unwrap()
        .unwrap();
    assert!(
        age >= Duration::from_secs(2 * 60 * 60),
        "the oldest admitted exclusive creator past sentinel_max_age is reported"
    );
    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    create_invoice_at(&stores.invoices, BUNDLE_A.as_bytes()).await;
    database.cleanup().await;
}

/// Startup integrity (W1.14): valid sentinel evidence rows boot cleanly,
/// and the boot scan authenticates them again after a "restart" (fresh
/// stores over the same database — nothing is cached).
#[tokio::test]
async fn startup_integrity_scan_accepts_valid_sentinel_rows() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;
    // One evidence row and one durable candidate row.
    stores
        .creators
        .apply_sentinel_scan(
            stores.creator_id,
            &[finding(1, 71, 500, 0), finding(2, 72, 500, 3)],
            &thresholds(),
        )
        .await
        .unwrap();
    let mut classes = classifications(database.pool()).await;
    classes.sort();
    assert_eq!(classes, vec!["candidate", "evidence"]);

    stores.creators.scan_integrity().await.unwrap();

    // Restart: a fresh store over the same database authenticates the
    // same rows.
    let restarted = CreatorStore::new(database.pool(), crypto());
    restarted.scan_integrity().await.unwrap();
    database.cleanup().await;
}

/// Startup integrity fails CLOSED: a corrupted sentinel envelope (AEAD
/// authentication under the domain-separated context fails) or a
/// lookup-hash column that no longer matches the sealed identity aborts
/// the boot scan — the server must refuse to serve rather than start over
/// tampered evidence.
#[tokio::test]
async fn startup_integrity_scan_fails_closed_on_corrupt_or_tampered_rows() {
    let database = TestDatabase::create().await;
    let stores = exclusive_store(&database, "xpub", 0).await;
    stores
        .creators
        .apply_sentinel_scan(stores.creator_id, &[finding(1, 73, 500, 3)], &thresholds())
        .await
        .unwrap();
    stores.creators.scan_integrity().await.unwrap();

    // Corrupt ciphertext: the envelope no longer authenticates.
    sqlx::query("UPDATE sentinel_outpoints SET sentinel_envelope = $1")
        .bind(b"corrupt-sentinel-envelope".as_slice())
        .execute(database.pool())
        .await
        .unwrap();
    assert!(
        stores.creators.scan_integrity().await.is_err(),
        "a corrupt envelope must fail startup"
    );

    // Lookup mismatch: valid envelope, tampered outpoint lookup hash.
    let database2 = TestDatabase::create().await;
    let stores2 = exclusive_store(&database2, "xpub", 0).await;
    stores2
        .creators
        .apply_sentinel_scan(stores2.creator_id, &[finding(1, 74, 500, 3)], &thresholds())
        .await
        .unwrap();
    sqlx::query("UPDATE sentinel_outpoints SET outpoint_lookup_hash = $1")
        .bind([9_u8; 32].as_slice())
        .execute(database2.pool())
        .await
        .unwrap();
    assert!(
        stores2.creators.scan_integrity().await.is_err(),
        "a lookup-hash mismatch must fail startup"
    );
    database2.cleanup().await;

    // Tampered derivation-index lookup hash.
    let database3 = TestDatabase::create().await;
    let stores3 = exclusive_store(&database3, "xpub", 0).await;
    stores3
        .creators
        .apply_sentinel_scan(stores3.creator_id, &[finding(1, 75, 500, 3)], &thresholds())
        .await
        .unwrap();
    sqlx::query("UPDATE sentinel_outpoints SET derivation_index_lookup_hash = $1")
        .bind([8_u8; 32].as_slice())
        .execute(database3.pool())
        .await
        .unwrap();
    assert!(
        stores3.creators.scan_integrity().await.is_err(),
        "a derivation-index lookup mismatch must fail startup"
    );
    database3.cleanup().await;
    database.cleanup().await;
}

// ---------------------------------------------------------------------------
// Tick-level tests over the real InvoiceStore backend and a fake Electrum.
// ---------------------------------------------------------------------------

struct Ready;
#[async_trait]
impl paykit_server::runtime::DependencyCheck for Ready {
    async fn postgres_ready(&self) -> bool {
        true
    }
}

/// One canned unspent output: (outpoint, sats, confirmations).
type CannedOutput = (OutPoint, u64, u32);

/// Fake Electrum port: a fixed tip plus canned per-address unspent outputs
/// and per-address isolated failures.
#[derive(Default)]
struct FakeElectrum {
    outputs: Mutex<HashMap<String, Vec<CannedOutput>>>,
    failing: Mutex<HashSet<String>>,
}

impl FakeElectrum {
    fn pay(&self, address: &str, outpoint: OutPoint, sats: u64, confirmations: u32) {
        self.outputs
            .lock()
            .unwrap()
            .insert(address.to_owned(), vec![(outpoint, sats, confirmations)]);
    }
    fn fail(&self, address: &str) {
        self.failing.lock().unwrap().insert(address.to_owned());
    }
}

#[async_trait]
impl ElectrumPort for FakeElectrum {
    async fn observations(
        &self,
        tip_height: u32,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        let mut report = ObservationReport::default();
        for target in targets {
            let address = target.address().to_owned();
            if self.failing.lock().unwrap().contains(&address) {
                report.failed.push(FailedObservation {
                    address,
                    reason: AddressFailureReason::Error,
                });
                continue;
            }
            let outputs = self
                .outputs
                .lock()
                .unwrap()
                .get(&address)
                .cloned()
                .unwrap_or_default();
            for (outpoint, sats, confirmations) in outputs {
                report.outputs.push(paykit_server::bitcoin::ObservedOutput {
                    network: BitcoinNetwork::Regtest,
                    address: address.clone(),
                    outpoint,
                    sats,
                    confirmations,
                    confirmed_height: (confirmations > 0).then(|| tip_height + 1 - confirmations),
                    present: true,
                });
            }
            report.observed.push(address);
        }
        Ok(report)
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 800,
            time_unix: 1_700_000_000,
        })
    }
}

fn tick_state(sentinel_policy: SentinelPolicy) -> (ObserverTickState, Arc<Runtime>) {
    let policy = ObserverPolicy {
        poll_interval: Duration::from_secs(30),
        max_requests_per_tick: 1000,
        max_requests_per_second: 5,
        max_transaction_bytes: 400_000,
        baseline_completion_timeout: Duration::from_secs(60),
        expiry_tail: Duration::from_secs(24 * 60 * 60),
    };
    let mut state = ObserverTickState::new(&policy);
    state.enable_sentinel(sentinel_policy);
    let runtime = Arc::new(Runtime::new(Arc::new(Ready), 1));
    (state, runtime)
}

async fn stamped(pool: &sqlx::PgPool) -> bool {
    sqlx::query_scalar("SELECT sentinel_last_scanned_at IS NOT NULL FROM creators LIMIT 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// End-to-end through the real observer tick: a qualifying confirmed output
/// at a never-assigned window address downgrades the exclusive creator,
/// with durable evidence and exactly one event.
#[tokio::test]
async fn tick_downgrades_exclusive_creator_with_qualifying_output() {
    let database = TestDatabase::create().await;
    let (xpub, account_index) = test_xpub(42);
    let stores = exclusive_store(&database, &xpub, account_index).await;
    let addresses = scan_window_addresses(
        &xpub,
        account_index,
        &BitcoinNetwork::Regtest,
        0,
        SENTINEL_SCAN_WINDOW,
    )
    .unwrap();
    let port = FakeElectrum::default();
    port.pay(&addresses[5].1, outpoint(91), 500, 2);

    let (mut state, runtime) = tick_state(SentinelPolicy::default());
    let outcome = observe_tick(
        &port,
        &stores.invoices,
        &BitcoinNetwork::Regtest,
        &runtime,
        &mut state,
    )
    .await;

    assert_eq!(
        outcome,
        ObserverTickOutcome::Observed {
            processed: 0,
            deferred: 0,
            failed: 0,
        }
    );
    assert_eq!(creator_mode(database.pool()).await, "shared_manual");
    assert_eq!(classifications(database.pool()).await, vec!["evidence"]);
    assert_eq!(event_count(database.pool()).await, 1);
    assert!(stamped(database.pool()).await);
    let evidence = stores.creators.sentinel_evidence(&creator()).await.unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].derivation_index, 5);
    assert_eq!(evidence[0].outpoint, outpoint(91).to_string());
    assert_eq!(evidence[0].value_sats, 500);
    database.cleanup().await;
}

/// A mempool-only output at a window address is a candidate through the
/// tick: the creator keeps its mode and is stamped for the cadence.
#[tokio::test]
async fn tick_records_mempool_candidate_without_downgrading() {
    let database = TestDatabase::create().await;
    let (xpub, account_index) = test_xpub(43);
    let stores = exclusive_store(&database, &xpub, account_index).await;
    let addresses = scan_window_addresses(
        &xpub,
        account_index,
        &BitcoinNetwork::Regtest,
        0,
        SENTINEL_SCAN_WINDOW,
    )
    .unwrap();
    let port = FakeElectrum::default();
    port.pay(&addresses[0].1, outpoint(92), 500, 0);

    let (mut state, runtime) = tick_state(SentinelPolicy::default());
    observe_tick(
        &port,
        &stores.invoices,
        &BitcoinNetwork::Regtest,
        &runtime,
        &mut state,
    )
    .await;

    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert_eq!(classifications(database.pool()).await, vec!["candidate"]);
    assert_eq!(event_count(database.pool()).await, 0);
    assert!(stamped(database.pool()).await);
    database.cleanup().await;
}

/// An Electrum failure on the sentinel window downgrades nothing, records
/// nothing, and does not stamp the creator for the cadence.
#[tokio::test]
async fn electrum_failure_downgrades_nothing() {
    let database = TestDatabase::create().await;
    let (xpub, account_index) = test_xpub(44);
    let stores = exclusive_store(&database, &xpub, account_index).await;
    let addresses = scan_window_addresses(
        &xpub,
        account_index,
        &BitcoinNetwork::Regtest,
        0,
        SENTINEL_SCAN_WINDOW,
    )
    .unwrap();
    let port = FakeElectrum::default();
    port.pay(&addresses[3].1, outpoint(93), 500, 2);
    port.fail(&addresses[7].1);

    let (mut state, runtime) = tick_state(SentinelPolicy::default());
    observe_tick(
        &port,
        &stores.invoices,
        &BitcoinNetwork::Regtest,
        &runtime,
        &mut state,
    )
    .await;

    assert_eq!(creator_mode(database.pool()).await, "exclusive");
    assert!(classifications(database.pool()).await.is_empty());
    assert_eq!(event_count(database.pool()).await, 0);
    assert!(
        !stamped(database.pool()).await,
        "a partially failed window is retried next tick, not stamped"
    );
    database.cleanup().await;
}

/// The sentinel is subordinate to live invoice observation under ONE
/// shared endpoint quota: with the shared bucket sized to exactly cover
/// the probe plus one live target, the live target is processed and the
/// sentinel allowance is ZERO — the qualifying output is NOT scanned this
/// tick (a second, independent sentinel bucket would scan and downgrade
/// here, doubling the endpoint quota; this test fails against that).
#[tokio::test]
async fn sentinel_allowance_is_zero_when_live_consumes_the_shared_budget() {
    let database = TestDatabase::create().await;
    let (xpub, account_index) = test_xpub(45);
    let stores = exclusive_store(&database, &xpub, account_index).await;
    let addresses = scan_window_addresses(
        &xpub,
        account_index,
        &BitcoinNetwork::Regtest,
        0,
        SENTINEL_SCAN_WINDOW,
    )
    .unwrap();
    // The live invoice binds a canonical regtest address (the tick's batch
    // validation rejects anything else); it answers empty (still observing).
    stores
        .invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader(),
            bundle_binding: BUNDLE_A.as_bytes(),
            payment_request_binding: b"request",
            new_reader_payloads: &FixedPayloads(LIVE_ADDRESS),
            payment_request_intent: common::payment_intent(&reader()),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();

    let port = FakeElectrum::default();
    port.pay(&addresses[2].1, outpoint(94), 500, 2);

    let policy = ObserverPolicy {
        poll_interval: Duration::from_secs(30),
        // Exactly probe (2) + one live lookup: zero live headroom.
        max_requests_per_tick: 3,
        max_requests_per_second: 100,
        max_transaction_bytes: 400_000,
        baseline_completion_timeout: Duration::from_secs(60),
        expiry_tail: Duration::from_secs(24 * 60 * 60),
    };
    let mut state = ObserverTickState::new(&policy);
    state.enable_sentinel(SentinelPolicy::default());
    let runtime = Arc::new(Runtime::new(Arc::new(Ready), 1));

    let outcome = observe_tick(
        &port,
        &stores.invoices,
        &BitcoinNetwork::Regtest,
        &runtime,
        &mut state,
    )
    .await;

    assert_eq!(
        outcome,
        ObserverTickOutcome::Observed {
            processed: 1,
            deferred: 0,
            failed: 0,
        },
        "the live target is never deferred by sentinel work"
    );
    assert_eq!(
        creator_mode(database.pool()).await,
        "exclusive",
        "no leftover shared tokens: the sentinel does not scan this tick"
    );
    assert!(classifications(database.pool()).await.is_empty());
    assert!(
        !stamped(database.pool()).await,
        "an un-scanned creator is not stamped for the cadence"
    );
    assert!(
        state.limiter().available() < 20,
        "live work left far less than one sentinel window in the shared bucket"
    );
    database.cleanup().await;
}

/// The aggregate endpoint quota is ONE bucket: with the shared capacity
/// exhausted by the probe plus a budget-truncated live plan (live targets
/// deferred), the sentinel phase admits NOTHING — live priority is
/// absolute and live + sentinel + probe can never sum above the
/// configured per-tick quota. Against the r1 twin-bucket implementation
/// (independent live and sentinel 1,000-request buckets) the sentinel
/// scans here and this test fails.
#[tokio::test]
async fn aggregate_quota_deferred_live_targets_mean_zero_sentinel_work() {
    let database = TestDatabase::create().await;
    let (xpub, account_index) = test_xpub(48);
    let stores = exclusive_store(&database, &xpub, account_index).await;
    // 25 live invoices at 25 DISTINCT canonical regtest addresses (the
    // tick's batch validation rejects duplicate targets): the plan exceeds
    // the bucket, so live defers 5. The addresses derive from a separate
    // seed, disjoint from the creator's own sentinel window.
    let (live_xpub, live_account) = test_xpub(60);
    let live_addresses =
        scan_window_addresses(&live_xpub, live_account, &BitcoinNetwork::Regtest, 0, 25).unwrap();
    for (index, (_, address)) in live_addresses.iter().enumerate() {
        stores
            .invoices
            .create_atomic(AtomicInvoiceInput {
                creator: &creator(),
                reader: &reader(),
                bundle_binding: format!("live-bundle-{index}").into_bytes().leak(),
                payment_request_binding: format!("live-request-{index}").into_bytes().leak(),
                new_reader_payloads: &FixedPayloads(address.clone().leak()),
                payment_request_intent: common::payment_intent(&reader()),
                required_sats: 100,
                nonce_sats: 1,
                prepare_ttl: Duration::from_secs(900),
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();
    }

    let port = FakeElectrum::default();
    let policy = ObserverPolicy {
        poll_interval: Duration::from_secs(30),
        // Probe (2) + 20 live lookups = 22: the whole per-tick quota.
        max_requests_per_tick: 22,
        max_requests_per_second: 5,
        max_transaction_bytes: 400_000,
        baseline_completion_timeout: Duration::from_secs(60),
        expiry_tail: Duration::from_secs(24 * 60 * 60),
    };
    let mut state = ObserverTickState::new(&policy);
    state.enable_sentinel(SentinelPolicy::default());
    let runtime = Arc::new(Runtime::new(Arc::new(Ready), 1));

    let outcome = observe_tick(
        &port,
        &stores.invoices,
        &BitcoinNetwork::Regtest,
        &runtime,
        &mut state,
    )
    .await;

    assert_eq!(
        outcome,
        ObserverTickOutcome::Observed {
            processed: 20,
            deferred: 5,
            failed: 0,
        },
        "the budget admits a strict prefix of the live plan first"
    );
    assert_eq!(
        creator_mode(database.pool()).await,
        "exclusive",
        "live targets were deferred: the sentinel allowance is zero"
    );
    assert!(classifications(database.pool()).await.is_empty());
    assert!(!stamped(database.pool()).await);
    assert_eq!(
        state.limiter().available(),
        0,
        "aggregate traffic this tick is bounded by the one shared quota"
    );
    database.cleanup().await;
}

/// With live headroom the sentinel allowance defaults to 10% of the shared
/// bucket's post-live remainder, bounded by whole creator windows, and
/// every scanned request is charged against the SHARED bucket: after a
/// 20-request window scan the shared balance dropped by exactly the probe
/// plus the window.
#[tokio::test]
async fn sentinel_allowance_is_ten_percent_of_the_post_live_remainder() {
    let database = TestDatabase::create().await;
    let (xpub, account_index) = test_xpub(49);
    let stores = exclusive_store(&database, &xpub, account_index).await;

    let port = FakeElectrum::default();
    let (mut state, runtime) = tick_state(SentinelPolicy::default());
    let before = state.limiter().available();
    assert_eq!(before, 1000, "a fresh shared bucket is at capacity");

    let outcome = observe_tick(
        &port,
        &stores.invoices,
        &BitcoinNetwork::Regtest,
        &runtime,
        &mut state,
    )
    .await;
    assert_eq!(
        outcome,
        ObserverTickOutcome::Observed {
            processed: 0,
            deferred: 0,
            failed: 0,
        }
    );
    assert!(
        stamped(database.pool()).await,
        "allowance (1000-2)/10 = 99 admits the one 20-request window"
    );
    let after = state.limiter().available();
    assert!(
        (976..=978).contains(&after),
        "the shared bucket was charged probe (2) + one sentinel window (20): {after}"
    );
    database.cleanup().await;
}

/// One tick never scans more creators than the global sentinel budget
/// allows: with a 25-token tick, one 20-address window completes and the
/// second creator waits for a later tick.
#[tokio::test]
async fn sentinel_tick_never_exceeds_its_global_budget() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let (xpub_a, account_a) = test_xpub(46);
    creators
        .create(
            &CreatorCredentials::new(
                creator(),
                "session".into(),
                ReceiverNoiseSecretKey::new([9; 32]),
                xpub_a.clone(),
                account_a,
            ),
            &StorageState::default(),
            &key_tail(18),
            &exclusive_allocation(),
            0,
        )
        .await
        .unwrap();
    let (xpub_b, account_b) = test_xpub(47);
    creators
        .create(
            &CreatorCredentials::new(
                second_creator(),
                "session".into(),
                ReceiverNoiseSecretKey::new([8; 32]),
                xpub_b.clone(),
                account_b,
            ),
            &StorageState::default(),
            &key_tail(19),
            &exclusive_allocation(),
            0,
        )
        .await
        .unwrap();
    let invoices = InvoiceStore::new(database.pool(), crypto);

    let tight = SentinelPolicy {
        max_requests_per_tick: 25,
        max_requests_per_second: 25,
        ..SentinelPolicy::default()
    };
    let (mut state, runtime) = tick_state(tight);
    let port = FakeElectrum::default();
    observe_tick(
        &port,
        &invoices,
        &BitcoinNetwork::Regtest,
        &runtime,
        &mut state,
    )
    .await;

    let stamped_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM creators WHERE sentinel_last_scanned_at IS NOT NULL",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        stamped_count, 1,
        "one 20-request window fits a 25-token tick"
    );
    let remaining = state.sentinel_budget_available().unwrap();
    assert!(
        remaining <= 20,
        "the 25-token tick granted at most its capacity (plus sub-token refill): {remaining}"
    );
    assert_eq!(
        creators
            .sentinel_plan(Duration::from_secs(10 * 60), 10)
            .await
            .unwrap()
            .len(),
        1,
        "the un-scanned creator is still due next tick"
    );
    database.cleanup().await;
}
