//! Verified USDT0 proofs on active Marketplace requests, and the status route that
//! reports them next to Bitcoin. Real services and PostgreSQL; only the BTC/USD feed,
//! the Bitcoin chain and the Arbitrum RPC are doubles.

use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use paykit_server::{
    bitcoin::ObservedOutput, config::BitcoinNetwork, crypto::Crypto, usdt::ArbitrumVerifier,
    workers::observer::observe_marketplace_once_at,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

mod common;

use common::{
    arbitrum::{Rpc, fixture, record},
    marketplace_rig::*,
};

/// USD 0.05: payable as 50,000 millionths of USDT, which the fixture receipt carries,
/// and as 62 sats at the 81,000 USD feed.
const AMOUNT: &str = "5";
const REQUIRED_USDT: u64 = 50_000;
const REQUIRED_SATS: u64 = 62;

struct Offered {
    invoice: String,
    activated_at: OffsetDateTime,
    payment_deadline: OffsetDateTime,
}

impl Offered {
    fn at(&self, seconds: i64) -> i64 {
        self.activated_at.unix_timestamp() + seconds
    }
}

fn reference(index: usize) -> String {
    fixture(index)["binding"]["paymentReference"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Prepares and activates a request whose reference and request id match proof fixture
/// `index`, and records the SDK lifecycle attribution the background worker would.
async fn offered(rig: &Rig, index: usize, accepted: &[&str]) -> Offered {
    offered_with_window(rig, index, accepted, 1_800).await
}

async fn offered_with_window(rig: &Rig, index: usize, accepted: &[&str], window: u64) -> Offered {
    let (status, prepared) = rig
        .prepare_with_reference(
            &reference(index),
            &format!("usdt-{index}"),
            AMOUNT,
            "USD",
            accepted,
            window,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&prepared)
    );
    let invoice = invoice_id(&prepared);
    let (status, activated) = rig.activate(&invoice, AMOUNT, "USD").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&activated)
    );
    let parse = |field: &str| {
        OffsetDateTime::parse(
            json(&activated)[field].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    };
    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             marketplace_preparation_id, sdk_payment_request_id, request_state,
             state_event_id, last_stream_item_id, last_event_at
         ) VALUES ($1, $2, 'proof_submitted', $3, 1, clock_timestamp())",
    )
    .bind(Uuid::parse_str(&invoice).unwrap())
    .bind(
        fixture(index)["binding"]["paymentRequestId"]
            .as_str()
            .unwrap(),
    )
    .bind(Uuid::new_v4().to_string())
    .execute(rig.database.pool())
    .await
    .unwrap();
    Offered {
        invoice,
        activated_at: parse("activated_at"),
        payment_deadline: parse("payment_deadline"),
    }
}

async fn creator_row(rig: &Rig) -> Uuid {
    sqlx::query_scalar("SELECT id FROM creators")
        .fetch_one(rig.database.pool())
        .await
        .unwrap()
}

/// One background pass over the SDK's record for proof fixture `index`. A fresh
/// verifier per pass keeps the five-second chain-tip cache from hiding a chain change.
async fn submit(rig: &Rig, rpc: &Rpc, index: usize) {
    let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
    rig.store
        .observe_usdt_request(
            creator_row(rig).await,
            &creator(),
            &record(index),
            &verifier,
        )
        .await
        .unwrap();
}

/// The background pass defers a still-present receipt for a minute; age it to re-check now.
async fn age_receipts(rig: &Rig) {
    sqlx::query("UPDATE usdt_observations SET checked_at = NOW() - INTERVAL '2 minutes'")
        .execute(rig.database.pool())
        .await
        .unwrap();
}

fn chain(rpc: &Rpc, change: impl FnOnce(&mut common::arbitrum::Chain)) {
    change(&mut rpc.chain.lock().unwrap());
}

fn transfer(chain: &mut common::arbitrum::Chain, amount: u64) {
    chain.receipt["logs"][1]["data"] = json!(format!("0x{amount:064x}"));
}

async fn observe_bitcoin(rig: &Rig, sats: u64, confirmations: u32, byte: u8, at: OffsetDateTime) {
    let targets = rig.store.observation_targets_at(at).await.unwrap();
    assert_eq!(targets.len(), 1);
    let output = ObservedOutput {
        network: BitcoinNetwork::Mainnet,
        address: targets[0].address().to_owned(),
        outpoint: outpoint(byte),
        sats,
        confirmations,
        present: true,
    };
    observe_marketplace_once_at(
        &Batch(vec![output]),
        &rig.store,
        &BitcoinNetwork::Mainnet,
        &targets,
        at,
    )
    .await
    .unwrap();
}

const TX_HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

#[tokio::test]
async fn verified_usdt_proof_reaches_a_dual_asset_request_and_sets_the_paid_asset() {
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;

    let before = rig.status(&request.invoice).await;
    assert_eq!(before["accepted_assets"], json!(["BTC", "USDT"]));
    assert_eq!(
        before["payment_amounts"],
        json!({"BTC": REQUIRED_SATS.to_string(), "USDT": REQUIRED_USDT.to_string()})
    );
    assert!(before["usdt_arbitrum"].is_null());
    assert!(before["paid_asset"].is_null());
    assert_eq!(before["payment_state"], "undetected");
    assert_status_fixture(&rig, &request.invoice, "dual-asset").await;

    chain(&rpc, |chain| chain.timestamp = request.at(10));
    submit(&rig, &rpc, 0).await;
    let included = rig.status(&request.invoice).await;
    assert_eq!(
        included["usdt_arbitrum"],
        json!({
            "tx_hash": TX_HASH,
            "observed_amount": REQUIRED_USDT.to_string(),
            "confirmations": 2,
            "amount_matched": true,
            "paid_on_time": true,
            "finalized": false,
        })
    );
    assert_eq!(included["paid_asset"], "USDT");
    assert_eq!(included["payment_state"], "confirmed");
    assert!(included["bitcoin"].is_null());
    assert_status_fixture(&rig, &request.invoice, "usdt-included").await;

    chain(&rpc, |chain| chain.finalized = true);
    age_receipts(&rig).await;
    submit(&rig, &rpc, 0).await;
    let finalized = rig.status(&request.invoice).await;
    assert_eq!(finalized["usdt_arbitrum"]["finalized"], true);
    assert_eq!(finalized["paid_asset"], "USDT");
    assert_status_fixture(&rig, &request.invoice, "usdt-finalized").await;

    rig.store.scan_observation_integrity().await.unwrap();
    rig.cleanup().await;
}

async fn assert_status_fixture(rig: &Rig, invoice: &str, name: &str) {
    let (status, body) = rig
        .post(STATUS, json!({"creator": CREATOR, "invoice_id": invoice}))
        .await;
    assert_eq!(status, StatusCode::OK);
    common::assert_fixture(STATUS_FIXTURES, name, &body, &VOLATILE);
}

#[tokio::test]
async fn reorged_usdt_receipt_reports_null_and_returns_when_the_block_does() {
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;
    chain(&rpc, |chain| chain.timestamp = request.at(10));
    submit(&rig, &rpc, 0).await;
    assert_eq!(rig.status(&request.invoice).await["paid_asset"], "USDT");

    chain(&rpc, |chain| chain.reorg = true);
    age_receipts(&rig).await;
    submit(&rig, &rpc, 0).await;
    let reorged = rig.status(&request.invoice).await;
    assert!(reorged["usdt_arbitrum"].is_null());
    assert!(reorged["paid_asset"].is_null());
    assert_eq!(reorged["payment_state"], "undetected");
    assert_status_fixture(&rig, &request.invoice, "usdt-reorged").await;
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM usdt_observations")
        .fetch_one(rig.database.pool())
        .await
        .unwrap();
    assert_eq!(kept, 1, "the receipt row is kept as evidence");

    chain(&rpc, |chain| chain.reorg = false);
    age_receipts(&rig).await;
    submit(&rig, &rpc, 0).await;
    assert_eq!(rig.status(&request.invoice).await["paid_asset"], "USDT");
    rig.cleanup().await;
}

#[tokio::test]
async fn finalized_receipt_survives_a_reorg_signal() {
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;
    chain(&rpc, |chain| {
        chain.timestamp = request.at(10);
        chain.finalized = true;
    });
    submit(&rig, &rpc, 0).await;
    chain(&rpc, |chain| chain.reorg = true);
    age_receipts(&rig).await;
    submit(&rig, &rpc, 0).await;
    let status = rig.status(&request.invoice).await;
    assert_eq!(status["usdt_arbitrum"]["finalized"], true);
    assert_eq!(status["paid_asset"], "USDT");
    rig.cleanup().await;
}

#[tokio::test]
async fn underpaid_early_and_late_receipts_are_visible_but_never_the_paid_asset() {
    for (label, amount, offset, matched, on_time) in [
        ("underpaid", REQUIRED_USDT - 1, 10, false, false),
        ("before activation", REQUIRED_USDT, -120, true, false),
        ("after the deadline", REQUIRED_USDT, 1_801, true, false),
        ("exactly at the deadline", REQUIRED_USDT, 1_800, true, true),
        ("overpaid", REQUIRED_USDT + 1, 10, true, true),
    ] {
        let rig = rig(BOTH_RAILS, true).await;
        let rpc = Rpc::start().await;
        let request = offered(&rig, 0, &[]).await;
        chain(&rpc, |chain| {
            transfer(chain, amount);
            chain.timestamp = request.at(offset);
        });
        submit(&rig, &rpc, 0).await;
        let status = rig.status(&request.invoice).await;
        let usdt = &status["usdt_arbitrum"];
        assert_eq!(usdt["amount_matched"], matched, "{label}");
        assert_eq!(usdt["paid_on_time"], on_time, "{label}");
        assert_eq!(usdt["observed_amount"], amount.to_string(), "{label}");
        assert_eq!(
            status["paid_asset"],
            if on_time { json!("USDT") } else { Value::Null },
            "{label}"
        );
        if label == "underpaid" {
            assert_status_fixture(&rig, &request.invoice, "usdt-underpaid").await;
        }
        if label == "after the deadline" {
            assert_eq!(status["payment_state"], "expired", "{label}");
            assert_status_fixture(&rig, &request.invoice, "usdt-late").await;
        }
        assert!(
            request.payment_deadline > request.activated_at,
            "window sanity"
        );
        rig.cleanup().await;
    }
}

#[tokio::test]
async fn bitcoin_payment_on_a_dual_asset_request_leaves_usdt_null() {
    let rig = rig(BOTH_RAILS, true).await;
    let request = offered(&rig, 0, &[]).await;
    observe_bitcoin(
        &rig,
        REQUIRED_SATS,
        2,
        1,
        request.activated_at + time::Duration::seconds(5),
    )
    .await;
    let status = rig.status(&request.invoice).await;
    assert_eq!(status["bitcoin"]["amount_matched"], true);
    assert_eq!(status["bitcoin"]["paid_on_time"], true);
    assert!(status["usdt_arbitrum"].is_null());
    assert_eq!(status["paid_asset"], "BTC");
    assert_eq!(status["payment_state"], "confirmed");
    assert_status_fixture(&rig, &request.invoice, "btc-on-dual-request").await;
    rig.cleanup().await;
}

#[tokio::test]
async fn cross_rail_double_payment_keeps_both_observations_and_names_the_earlier_rail() {
    for (label, usdt_first, fixture_name) in [
        ("usdt first", true, "cross-rail-usdt-first"),
        ("bitcoin first", false, "cross-rail-bitcoin-first"),
    ] {
        let rig = rig(BOTH_RAILS, true).await;
        let rpc = Rpc::start().await;
        let request = offered(&rig, 0, &[]).await;
        let (usdt_offset, bitcoin_offset) = if usdt_first { (10, 60) } else { (60, 10) };
        chain(&rpc, |chain| chain.timestamp = request.at(usdt_offset));
        submit(&rig, &rpc, 0).await;
        observe_bitcoin(
            &rig,
            REQUIRED_SATS,
            1,
            1,
            request.activated_at + time::Duration::seconds(bitcoin_offset),
        )
        .await;
        let status = rig.status(&request.invoice).await;
        assert_eq!(status["bitcoin"]["paid_on_time"], true, "{label}");
        assert_eq!(status["usdt_arbitrum"]["paid_on_time"], true, "{label}");
        assert_eq!(
            status["paid_asset"],
            if usdt_first { "USDT" } else { "BTC" },
            "{label}"
        );
        assert_status_fixture(&rig, &request.invoice, fixture_name).await;
        let rows: (i64, i64) = (
            sqlx::query_scalar("SELECT count(*) FROM bitcoin_observations")
                .fetch_one(rig.database.pool())
                .await
                .unwrap(),
            sqlx::query_scalar("SELECT count(*) FROM usdt_observations")
                .fetch_one(rig.database.pool())
                .await
                .unwrap(),
        );
        assert_eq!(rows, (1, 1), "{label}");
        rig.cleanup().await;
    }
}

#[tokio::test]
async fn partial_payments_across_rails_are_never_combined() {
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;
    chain(&rpc, |chain| {
        transfer(chain, REQUIRED_USDT / 2);
        chain.timestamp = request.at(10);
    });
    submit(&rig, &rpc, 0).await;
    observe_bitcoin(
        &rig,
        REQUIRED_SATS / 2,
        1,
        1,
        request.activated_at + time::Duration::seconds(10),
    )
    .await;
    let status = rig.status(&request.invoice).await;
    assert_eq!(status["bitcoin"]["amount_matched"], false);
    assert_eq!(status["usdt_arbitrum"]["amount_matched"], false);
    assert!(status["paid_asset"].is_null());
    rig.cleanup().await;
}

#[tokio::test]
async fn one_transfer_belongs_to_one_request_for_good() {
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let first = offered(&rig, 0, &[]).await;
    let second = offered(&rig, 1, &[]).await;
    chain(&rpc, |chain| chain.timestamp = first.at(10));
    submit(&rig, &rpc, 0).await;
    submit(&rig, &rpc, 1).await;
    assert_eq!(rig.status(&first.invoice).await["paid_asset"], "USDT");
    let other = rig.status(&second.invoice).await;
    assert!(other["usdt_arbitrum"].is_null());
    assert!(other["paid_asset"].is_null());
    let owners: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT marketplace_preparation_id) FROM usdt_observations",
    )
    .fetch_one(rig.database.pool())
    .await
    .unwrap();
    assert_eq!(owners, 1);
    rig.cleanup().await;
}

#[tokio::test]
async fn a_request_that_did_not_offer_usdt_ignores_a_usdt_proof() {
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &["BTC"]).await;
    chain(&rpc, |chain| chain.timestamp = request.at(10));
    submit(&rig, &rpc, 0).await;
    let status = rig.status(&request.invoice).await;
    assert_eq!(status["accepted_assets"], json!(["BTC"]));
    assert!(status["usdt_arbitrum"].is_null());
    assert!(status["paid_asset"].is_null());
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM usdt_observations")
        .fetch_one(rig.database.pool())
        .await
        .unwrap();
    assert_eq!(rows, 0);
    rig.cleanup().await;
}

#[tokio::test]
async fn a_usdt_only_request_is_settled_by_its_proof_alone() {
    let rig = rig(
        Seller {
            bitcoin: false,
            usdt: true,
        },
        true,
    )
    .await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;
    assert!(rig.store.observation_targets().await.unwrap().is_empty());
    chain(&rpc, |chain| chain.timestamp = request.at(10));
    submit(&rig, &rpc, 0).await;
    let status = rig.status(&request.invoice).await;
    assert_eq!(status["accepted_assets"], json!(["USDT"]));
    assert!(status["bitcoin"].is_null());
    assert_eq!(status["paid_asset"], "USDT");
    assert_eq!(status["payment_state"], "confirmed");
    rig.cleanup().await;
}

#[tokio::test]
async fn proof_before_activation_attribution_is_ignored_and_prepared_requests_never_match() {
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let (status, prepared) = rig
        .prepare_with_reference(&reference(0), "prepared-only", AMOUNT, "USD", &[], 1_800)
        .await;
    assert_eq!(status, StatusCode::OK);
    let invoice = invoice_id(&prepared);
    submit(&rig, &rpc, 0).await;
    let status = rig.status(&invoice).await;
    assert_eq!(status["state"], "prepared");
    assert!(status["usdt_arbitrum"].is_null());
    assert_eq!(status["accepted_assets"], json!(["BTC", "USDT"]));
    rig.cleanup().await;
}

type Reads = Vec<Value>;

/// Waits until `ready` reports every reader's initial reads. A reader returns only after
/// the proof is submitted, so a reader that finishes first has failed: its panic is
/// reported at once, not discovered after a wait that can never end. `limit` is a
/// backstop for a reader that neither progresses nor fails.
async fn wait_for_readers_ready(
    readers: &mut tokio::task::JoinSet<Reads>,
    ready: impl Fn() -> bool,
    limit: std::time::Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + limit;
    while !ready() {
        tokio::select! {
            finished = readers.join_next() => {
                return Err(match finished {
                    Some(Err(error)) if error.is_panic() => {
                        let payload = error.into_panic();
                        let message = payload
                            .downcast_ref::<String>()
                            .cloned()
                            .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                            .unwrap_or_else(|| "non-string panic".to_owned());
                        format!("a status reader failed before the proof was submitted: {message}")
                    }
                    Some(Err(error)) => format!("a status reader was cancelled: {error}"),
                    Some(Ok(_)) => "a status reader stopped before the proof was submitted".to_owned(),
                    None => "no status readers are running".to_owned(),
                });
            }
            () = tokio::time::sleep(std::time::Duration::from_millis(1)) => {}
            () = tokio::time::sleep_until(deadline) => {
                return Err(format!("status readers were not ready within {limit:?}"));
            }
        }
    }
    Ok(())
}

/// A reader failing, or going quiet, before readiness fails the wait promptly instead of
/// hanging it.
#[tokio::test]
async fn reader_failure_before_readiness_fails_the_wait_promptly() {
    use std::{sync::atomic::AtomicUsize, time::Duration};
    let limit = Duration::from_secs(30);
    let promptly = Duration::from_secs(5);

    let mut failing = tokio::task::JoinSet::new();
    failing.spawn(async { panic!("status 429") });
    failing.spawn(async {
        std::future::pending::<()>().await;
        Vec::new()
    });
    let started = std::time::Instant::now();
    let error = wait_for_readers_ready(&mut failing, || false, limit)
        .await
        .unwrap_err();
    assert!(started.elapsed() < promptly, "took {:?}", started.elapsed());
    assert!(error.contains("status 429"), "{error}");

    let mut quiet_exit = tokio::task::JoinSet::new();
    quiet_exit.spawn(async { Vec::new() });
    let error = wait_for_readers_ready(&mut quiet_exit, || false, limit)
        .await
        .unwrap_err();
    assert!(error.contains("stopped before the proof"), "{error}");

    let mut stalled = tokio::task::JoinSet::new();
    stalled.spawn(async {
        std::future::pending::<()>().await;
        Vec::new()
    });
    let started = std::time::Instant::now();
    let error = wait_for_readers_ready(&mut stalled, || false, Duration::from_millis(200))
        .await
        .unwrap_err();
    assert!(started.elapsed() < promptly);
    assert!(error.contains("not ready within"), "{error}");

    let progress = std::sync::Arc::new(AtomicUsize::new(0));
    let mut healthy = tokio::task::JoinSet::new();
    let ticking = progress.clone();
    healthy.spawn(async move {
        for _ in 0..3 {
            ticking.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        std::future::pending::<()>().await;
        Vec::new()
    });
    wait_for_readers_ready(&mut healthy, || progress.load(Ordering::SeqCst) >= 3, limit)
        .await
        .unwrap();
}

/// A status read overlapping the commit that applies a proof sees the request either
/// entirely before it or entirely after it, never a half-applied mixture. The reads are
/// bounded and synchronised, not timed: every reader has read before the proof is
/// submitted and reads a fixed number of times after it. A reader that fails before
/// that point fails the test at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_reads_racing_a_proof_submission_never_see_a_half_applied_state() {
    const READERS: usize = 3;
    const READS_BEFORE_SUBMIT: usize = 3;
    const READS_AFTER_SUBMIT: usize = 6;
    /// Backstop on the reads before the submit, so a stalled test cannot flood the rig.
    const MAX_READS_BEFORE_SUBMIT: usize = 1_000;
    let rig = std::sync::Arc::new(rig(BOTH_RAILS, true).await);
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;
    chain(&rpc, |chain| chain.timestamp = request.at(10));

    let submitted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let early_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut readers = tokio::task::JoinSet::new();
    for _ in 0..READERS {
        let rig = rig.clone();
        let submitted = submitted.clone();
        let early_reads = early_reads.clone();
        let invoice = request.invoice.clone();
        readers.spawn(async move {
            let mut seen = Vec::new();
            let mut counted = 0;
            while !submitted.load(Ordering::SeqCst) {
                if seen.len() >= MAX_READS_BEFORE_SUBMIT {
                    return seen;
                }
                seen.push(rig.status(&invoice).await);
                if counted < READS_BEFORE_SUBMIT {
                    counted += 1;
                    early_reads.fetch_add(1, Ordering::SeqCst);
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            for _ in 0..READS_AFTER_SUBMIT {
                seen.push(rig.status(&invoice).await);
            }
            seen
        });
    }
    wait_for_readers_ready(
        &mut readers,
        || early_reads.load(Ordering::SeqCst) >= READERS * READS_BEFORE_SUBMIT,
        std::time::Duration::from_secs(30),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    submit(&rig, &rpc, 0).await;
    submitted.store(true, Ordering::SeqCst);

    let mut before = 0;
    let mut after = 0;
    while let Some(reader) = readers.join_next().await {
        let seen = reader.unwrap();
        let mut applied = false;
        for status in &seen {
            let has_usdt = !status["usdt_arbitrum"].is_null();
            assert!(!applied || has_usdt, "a read went back to before the proof");
            applied |= has_usdt;
            if has_usdt {
                after += 1;
                assert_eq!(status["paid_asset"], "USDT", "{status}");
                assert_eq!(status["payment_state"], "confirmed", "{status}");
                assert_eq!(status["usdt_arbitrum"]["amount_matched"], true);
                assert_eq!(status["usdt_arbitrum"]["paid_on_time"], true);
            } else {
                before += 1;
                assert!(status["paid_asset"].is_null(), "{status}");
                assert_eq!(status["payment_state"], "undetected", "{status}");
            }
        }
        assert!(
            applied,
            "every reader's reads after the submit see the proof"
        );
    }
    assert!(before >= READERS * READS_BEFORE_SUBMIT, "before={before}");
    assert!(after >= READERS * READS_AFTER_SUBMIT, "after={after}");
    std::sync::Arc::into_inner(rig).unwrap().cleanup().await;
}

/// Facts of one receipt as the store keeps them encrypted, for receipts the fixtures
/// cannot sign (the proof fixtures cover one transfer per request).
#[derive(serde::Serialize)]
struct ReceiptFacts {
    identity: String,
    amount: u64,
    timestamp: OffsetDateTime,
}

fn extra_tx_hash(byte: u8) -> String {
    format!("0x{}", format!("{byte:02x}").repeat(32))
}

/// Records a second, verified-looking receipt for the request straight through the
/// storage layer, so two distinct USDT transfers can settle one request.
async fn insert_receipt(
    rig: &Rig,
    request: &Offered,
    byte: u8,
    amount: u64,
    block_offset: i64,
    confirmations: i32,
    finalized: bool,
) -> String {
    use paykit_server::crypto::EnvelopeContext;
    let crypto = Crypto::from_master_key(&[7; 32]).unwrap();
    let preparation = Uuid::parse_str(&request.invoice).unwrap();
    let identity = format!("42161:{}:1", extra_tx_hash(byte));
    let id = Uuid::new_v4();
    let envelope = crypto
        .encrypt(
            &EnvelopeContext::usdt_observation_for_marketplace(
                crypto.lookup_hash(creator().to_string().as_bytes()),
                id,
                preparation,
            ),
            &postcard::to_allocvec(&ReceiptFacts {
                identity: identity.clone(),
                amount,
                timestamp: OffsetDateTime::from_unix_timestamp(request.at(block_offset)).unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
    sqlx::query(
        "INSERT INTO usdt_observations
         (id, marketplace_preparation_id, transfer_lookup_hash, observation_envelope,
          confirmations, present, finalized)
         VALUES ($1, $2, $3, $4, $5, TRUE, $6)",
    )
    .bind(id)
    .bind(preparation)
    .bind(
        crypto
            .usdt_transfer_lookup_hash(identity.as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .bind(envelope.as_bytes())
    .bind(confirmations)
    .bind(finalized)
    .execute(rig.database.pool())
    .await
    .unwrap();
    extra_tx_hash(byte)
}

/// Which rail was paid first is decided by the earliest qualifying receipt of each rail.
/// A later receipt that ranks higher for display (final, more confirmations) must not
/// move USDT behind Bitcoin.
#[tokio::test]
async fn earliest_qualifying_usdt_receipt_decides_the_paid_asset_not_the_displayed_one() {
    // USDT receipt A, then Bitcoin, then a final, higher-ranked USDT receipt B.
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;
    chain(&rpc, |chain| chain.timestamp = request.at(10));
    submit(&rig, &rpc, 0).await;
    observe_bitcoin(
        &rig,
        REQUIRED_SATS,
        1,
        1,
        request.activated_at + time::Duration::seconds(20),
    )
    .await;
    let b = insert_receipt(&rig, &request, 0xb1, REQUIRED_USDT, 30, 9, true).await;
    let status = rig.status(&request.invoice).await;
    assert_eq!(status["usdt_arbitrum"]["tx_hash"], b, "B is displayed");
    assert_eq!(status["usdt_arbitrum"]["finalized"], true);
    assert_eq!(status["bitcoin"]["paid_on_time"], true);
    assert_eq!(
        status["paid_asset"], "USDT",
        "A, the earliest qualifying receipt, preceded Bitcoin"
    );

    // A is reorged out: the earliest qualifying USDT receipt is now B, after Bitcoin.
    chain(&rpc, |chain| chain.reorg = true);
    age_receipts(&rig).await;
    submit(&rig, &rpc, 0).await;
    let status = rig.status(&request.invoice).await;
    assert_eq!(status["usdt_arbitrum"]["tx_hash"], b);
    assert_eq!(status["paid_asset"], "BTC");

    // A returns with its block.
    chain(&rpc, |chain| chain.reorg = false);
    age_receipts(&rig).await;
    submit(&rig, &rpc, 0).await;
    assert_eq!(rig.status(&request.invoice).await["paid_asset"], "USDT");
    rig.cleanup().await;

    // Bitcoin first: both USDT receipts come after it.
    let rig = fresh_dual_rig().await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;
    observe_bitcoin(
        &rig,
        REQUIRED_SATS,
        1,
        1,
        request.activated_at + time::Duration::seconds(5),
    )
    .await;
    chain(&rpc, |chain| chain.timestamp = request.at(10));
    submit(&rig, &rpc, 0).await;
    insert_receipt(&rig, &request, 0xb1, REQUIRED_USDT, 30, 9, true).await;
    let status = rig.status(&request.invoice).await;
    assert_eq!(status["paid_asset"], "BTC");
    assert_eq!(status["usdt_arbitrum"]["paid_on_time"], true);
    rig.cleanup().await;

    // An earlier receipt that does not qualify never counts as the first payment.
    let rig = fresh_dual_rig().await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;
    chain(&rpc, |chain| {
        transfer(chain, REQUIRED_USDT - 1);
        chain.timestamp = request.at(10);
    });
    submit(&rig, &rpc, 0).await;
    observe_bitcoin(
        &rig,
        REQUIRED_SATS,
        1,
        1,
        request.activated_at + time::Duration::seconds(20),
    )
    .await;
    insert_receipt(&rig, &request, 0xb1, REQUIRED_USDT, 30, 9, true).await;
    assert_eq!(rig.status(&request.invoice).await["paid_asset"], "BTC");
    rig.cleanup().await;
}

async fn fresh_dual_rig() -> Rig {
    rig(BOTH_RAILS, true).await
}

#[tokio::test]
async fn usdt_receipts_are_authenticated_by_the_integrity_scan() {
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let request = offered(&rig, 0, &[]).await;
    chain(&rpc, |chain| chain.timestamp = request.at(10));
    submit(&rig, &rpc, 0).await;
    rig.store.scan_observation_integrity().await.unwrap();
    sqlx::query("UPDATE usdt_observations SET transfer_lookup_hash = $1")
        .bind(
            Crypto::from_master_key(&[7; 32])
                .unwrap()
                .lookup_hash(b"other")
                .as_bytes()
                .as_slice(),
        )
        .execute(rig.database.pool())
        .await
        .expect_err("receipt identity cannot be rewritten");
    sqlx::query("UPDATE usdt_observations SET observation_envelope = $1")
        .bind(vec![0_u8; 32])
        .execute(rig.database.pool())
        .await
        .unwrap();
    assert!(rig.store.scan_observation_integrity().await.is_err());
    let (status, _) = rig
        .post(
            STATUS,
            json!({"creator": CREATOR, "invoice_id": request.invoice}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a tampered receipt fails closed"
    );
    rig.cleanup().await;
}

/// A pass that starts after the payment window has closed, and after Bitcoin target
/// discovery has stamped the settlement expired, is an ordinary pass: the receipt is
/// judged by its block time, not skipped and not an error.
#[tokio::test]
async fn proof_pass_after_the_settlement_expired_records_the_receipt_by_block_time() {
    for (label, block_offset, on_time) in [("on time by block time", 0, true), ("late", 5, false)] {
        let rig = rig(BOTH_RAILS, true).await;
        let rpc = Rpc::start().await;
        let request = offered_with_window(&rig, 0, &[], 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
        rig.store.observation_targets().await.unwrap();
        let expired: Option<OffsetDateTime> =
            sqlx::query_scalar("SELECT payment_expired_at FROM marketplace_settlements")
                .fetch_one(rig.database.pool())
                .await
                .unwrap();
        assert!(expired.is_some(), "{label}: discovery stamped the expiry");

        chain(&rpc, |chain| chain.timestamp = request.at(block_offset));
        submit(&rig, &rpc, 0).await;
        let status = rig.status(&request.invoice).await;
        assert_eq!(status["usdt_arbitrum"]["paid_on_time"], on_time, "{label}");
        assert_eq!(
            status["paid_asset"],
            if on_time { json!("USDT") } else { Value::Null },
            "{label}"
        );
        assert_eq!(
            status["payment_state"],
            if on_time { "confirmed" } else { "expired" },
            "{label}"
        );
        rig.cleanup().await;
    }
}

/// The settlement a proof pass locks cannot disappear or leave `active` underneath it:
/// the database refuses the state change, so a failed lock is a broken invariant.
#[tokio::test]
async fn an_active_settlement_cannot_leave_active_during_a_pass() {
    let rig = rig(BOTH_RAILS, true).await;
    let rpc = Rpc::start().await;
    let request = offered_with_window(&rig, 0, &[], 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
    rig.store.observation_targets().await.unwrap();
    for statement in [
        "UPDATE marketplace_payment_preparations SET state = 'voided', activated_at = NULL, payment_deadline = NULL, voided_at = NOW()",
        "UPDATE marketplace_payment_preparations SET state = 'prepared', activated_at = NULL, payment_deadline = NULL",
        "DELETE FROM marketplace_settlements",
    ] {
        sqlx::query(statement)
            .execute(rig.database.pool())
            .await
            .expect_err(statement);
    }
    chain(&rpc, |chain| chain.timestamp = request.at(0));
    submit(&rig, &rpc, 0).await;
    assert_eq!(rig.status(&request.invoice).await["paid_asset"], "USDT");
    rig.cleanup().await;
}
