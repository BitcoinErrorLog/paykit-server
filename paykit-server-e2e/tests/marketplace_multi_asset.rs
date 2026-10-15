//! Marketplace requests that carry every accepted asset, over the signed routes and
//! the real services on PostgreSQL. Only the BTC/USD feed and the chain are doubles.

use std::{sync::Arc, sync::atomic::Ordering, time::Duration};

use axum::http::StatusCode;
use paykit_server::{
    bitcoin::ObservedOutput,
    config::BitcoinNetwork,
    crypto::{EncryptedEnvelope, EnvelopeContext},
    persistence::OutboxStore,
    workers::observer::observe_marketplace_once_at,
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

mod common;

use common::marketplace_rig::*;

#[tokio::test]
async fn dual_asset_prepare_and_activate_round_trip_with_replay_and_binding() {
    let rig = rig(BOTH_RAILS, true).await;
    let (status, prepared) = rig
        .prepare("order-1:attempt-1", "500", "USD", &["USDT", "BTC"], 1_800)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&prepared)
    );
    common::assert_fixture(FIXTURES, "prepare-usd-btc-usdt", &prepared, &VOLATILE);
    let expected_terms = serde_json::json!({
        "amount": "500",
        "asset": "USD",
        "accepted_assets": ["BTC", "USDT"],
        "payment_amounts": {"BTC": "6173", "USDT": "5000000"},
        "rates": {"BTC": "0.000012345679012346", "USDT": "1"},
    });
    for key in expected_terms.as_object().unwrap().keys() {
        assert_eq!(json(&prepared)[key], expected_terms[key], "{key}");
    }
    let invoice = invoice_id(&prepared);
    assert_eq!(rig.feed.calls.load(Ordering::SeqCst), 1);

    // An exact retry replays the stored quote without reading the feed again, even
    // while it is down, and the set order does not matter.
    rig.feed.failing.store(true, Ordering::SeqCst);
    let (status, replay) = rig
        .prepare("order-1:attempt-1", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&replay), json(&prepared));
    assert_eq!(rig.feed.calls.load(Ordering::SeqCst), 1);

    // Any change under the same operation id is a binding conflict.
    for (label, amount, asset, accepted, window) in [
        ("amount", "501", "USD", vec!["BTC", "USDT"], 1_800),
        ("asset", "500", "USDT", vec!["BTC", "USDT"], 1_800),
        ("accepted set", "500", "USD", vec!["BTC"], 1_800),
        ("window", "500", "USD", vec!["BTC", "USDT"], 900),
    ] {
        let (status, body) = rig
            .prepare("order-1:attempt-1", amount, asset, &accepted, window)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{label}");
        assert_eq!(
            json(&body)["error"]["code"],
            "operation_conflict",
            "{label}"
        );
    }
    let (status, body) = rig
        .prepare("order-1:attempt-1", "501", "USD", &["BTC", "USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    common::assert_fixture(FIXTURES, "operation-conflict", &body, &VOLATILE);

    let (status, activated) = rig.activate(&invoice, "500", "USD").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&activated)
    );
    common::assert_fixture(FIXTURES, "activate-usd-btc-usdt", &activated, &VOLATILE);
    assert_eq!(
        json(&activated)["payment_amounts"],
        expected_terms["payment_amounts"]
    );
    assert_eq!(
        json(&activated)["accepted_assets"],
        expected_terms["accepted_assets"]
    );
    let (status, replay) = rig.activate(&invoice, "500", "USD").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&replay), json(&activated));

    for (label, amount, asset) in [
        ("amount", "501", "USD"),
        ("asset", "500", "USDT"),
        ("sats total", "6173", "BTC"),
    ] {
        let (status, body) = rig.activate(&invoice, amount, asset).await;
        assert_eq!(status, StatusCode::CONFLICT, "{label}");
        assert_eq!(json(&body)["error"]["code"], "total_mismatch", "{label}");
    }
    let (_, body) = rig.activate(&invoice, "501", "USD").await;
    common::assert_fixture(FIXTURES, "total-mismatch", &body, &VOLATILE);
    rig.cleanup().await;
}

#[tokio::test]
async fn every_denomination_and_accepted_set_prepares_over_the_signed_route() {
    let rig = rig(BOTH_RAILS, true).await;
    for (asset, amount, name) in [
        ("USD", "500", "usd"),
        ("BTC", "50000", "btc"),
        ("USDT", "5000000", "usdt"),
    ] {
        for (accepted, suffix) in [
            (vec!["BTC"], "btc"),
            (vec!["USDT"], "usdt"),
            (vec!["BTC", "USDT"], "btc-usdt"),
        ] {
            let (status, body) = rig
                .prepare(&format!("{name}-{suffix}"), amount, asset, &accepted, 1_800)
                .await;
            assert_eq!(status, StatusCode::OK, "{asset} {accepted:?}");
            let prepared = json(&body);
            assert_eq!(prepared["asset"], asset);
            assert_eq!(prepared["amount"], amount);
            assert_eq!(prepared["accepted_assets"], serde_json::json!(accepted));
            let payable = prepared["payment_amounts"].as_object().unwrap();
            assert_eq!(payable.len(), accepted.len());
            for rail in &accepted {
                assert!(payable[*rail].as_str().unwrap().parse::<u64>().unwrap() > 0);
            }
            common::assert_fixture(
                FIXTURES,
                &format!("prepare-{name}-{suffix}"),
                &body,
                &VOLATILE,
            );
        }
    }
    rig.cleanup().await;
}

#[tokio::test]
async fn omitted_filter_derives_the_sellers_rails_and_a_filter_only_narrows() {
    for (seller, usdt_enabled, name, rails) in [
        (BOTH_RAILS, true, "derived-btc-usdt", vec!["BTC", "USDT"]),
        (
            Seller {
                bitcoin: true,
                usdt: false,
            },
            true,
            "derived-btc",
            vec!["BTC"],
        ),
        (
            Seller {
                bitcoin: false,
                usdt: true,
            },
            true,
            "derived-usdt",
            vec!["USDT"],
        ),
        (
            BOTH_RAILS,
            false,
            "derived-btc-without-usdt-config",
            vec!["BTC"],
        ),
    ] {
        let rig = rig(seller, usdt_enabled).await;
        let (status, body) = rig.prepare(name, "500", "USD", &[], 1_800).await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert_eq!(
            json(&body)["accepted_assets"],
            serde_json::json!(rails),
            "{name}"
        );
        common::assert_fixture(FIXTURES, &format!("prepare-usd-{name}"), &body, &VOLATILE);
        rig.cleanup().await;
    }

    // Seller shares USDT but the Shop's toggle is off: the filter narrows to BTC and
    // the proposal carries no USDT endpoint.
    let rig = rig(BOTH_RAILS, true).await;
    let (status, body) = rig.prepare("narrowed", "500", "USD", &["BTC"], 1_800).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["accepted_assets"], serde_json::json!(["BTC"]));
    assert!(json(&body)["payment_amounts"]["USDT"].is_null());
    // A filter naming a rail the seller lacks is narrowed, not refused.
    rig.cleanup().await;
    let btc_only = rig_seller_btc().await;
    let (status, body) = btc_only
        .prepare("partial", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["accepted_assets"], serde_json::json!(["BTC"]));
    // Omitted and an explicit filter are different requests under one operation id.
    let (status, _) = btc_only.prepare("partial", "500", "USD", &[], 1_800).await;
    assert_eq!(status, StatusCode::CONFLICT);
    btc_only.cleanup().await;
}

async fn rig_seller_btc() -> Rig {
    rig(
        Seller {
            bitcoin: true,
            usdt: false,
        },
        true,
    )
    .await
}

#[tokio::test]
async fn proposal_carries_exactly_the_accepted_rails_and_the_fixed_rates() {
    let rig = rig(BOTH_RAILS, true).await;
    for (operation, asset, amount, accepted) in [
        ("dual", "USD", "500", vec!["BTC", "USDT"]),
        ("btc-only", "BTC", "50000", vec!["BTC"]),
        ("usdt-only", "USD", "500", vec!["USDT"]),
        ("derived", "USD", "500", vec![]),
    ] {
        let (status, prepared) = rig
            .prepare(operation, amount, asset, &accepted, 1_800)
            .await;
        assert_eq!(status, StatusCode::OK, "{operation}");
        let (status, _) = rig.activate(&invoice_id(&prepared), amount, asset).await;
        assert_eq!(status, StatusCode::OK, "{operation}");
    }
    let outbox = OutboxStore::new(rig.database.pool(), crypto());
    let claims = outbox
        .claim(uuid::Uuid::new_v4(), 4, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(claims.len(), 4);
    let mut seen = Vec::new();
    for claim in &claims {
        let intent = outbox.delivery_intent(claim).unwrap();
        let terms = intent.terms().unwrap();
        let mut endpoints: Vec<_> = terms.payment_endpoints.keys().cloned().collect();
        endpoints.sort();
        let mut rates: Vec<_> = terms.rates.iter().map(|rate| rate.asset.clone()).collect();
        rates.sort();
        seen.push((terms.asset.clone(), endpoints, rates));
    }
    seen.sort();
    assert_eq!(
        seen,
        vec![
            (
                "btc".to_owned(),
                vec!["btc-bitcoin-p2wpkh".to_owned()],
                Vec::<String>::new()
            ),
            (
                "usd".to_owned(),
                vec![
                    "btc-bitcoin-p2wpkh".to_owned(),
                    "usdt-arbitrum-address".to_owned()
                ],
                vec!["btc".to_owned(), "usdt".to_owned()]
            ),
            (
                "usd".to_owned(),
                vec![
                    "btc-bitcoin-p2wpkh".to_owned(),
                    "usdt-arbitrum-address".to_owned()
                ],
                vec!["btc".to_owned(), "usdt".to_owned()]
            ),
            (
                "usd".to_owned(),
                vec!["usdt-arbitrum-address".to_owned()],
                vec!["usdt".to_owned()]
            ),
        ]
    );
    rig.cleanup().await;
}

#[tokio::test]
async fn rate_is_fixed_at_prepare_and_activation_never_refetches_it() {
    let rig = rig(BOTH_RAILS, true).await;
    let (status, prepared) = rig
        .prepare("fixed-rate", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rig.feed.calls.load(Ordering::SeqCst), 1);

    rig.feed.failing.store(true, Ordering::SeqCst);
    let (status, activated) = rig.activate(&invoice_id(&prepared), "500", "USD").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&activated)
    );
    assert_eq!(
        json(&activated)["payment_amounts"],
        json(&prepared)["payment_amounts"]
    );
    assert_eq!(
        rig.feed.calls.load(Ordering::SeqCst),
        1,
        "activation must not read the feed"
    );

    let proposal = OutboxStore::new(rig.database.pool(), crypto());
    let claims = proposal
        .claim(uuid::Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap();
    let intent = proposal.delivery_intent(&claims[0]).unwrap();
    assert_eq!(
        intent
            .terms()
            .unwrap()
            .rates
            .iter()
            .map(|rate| (rate.asset.as_str(), rate.value.as_str()))
            .collect::<Vec<_>>(),
        vec![("btc", "0.000012345679012346"), ("usdt", "1")]
    );
    rig.cleanup().await;
}

#[tokio::test]
async fn unavailable_or_stale_rate_at_prepare_persists_nothing_and_keeps_the_address_index() {
    let rig = rig(BOTH_RAILS, true).await;
    rig.feed.failing.store(true, Ordering::SeqCst);
    let (status, body) = rig
        .prepare("stale", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(&body)["error"]["code"], "dependency_unavailable");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM marketplace_payment_preparations")
        .fetch_one(rig.database.pool())
        .await
        .unwrap();
    let next_index: i64 = sqlx::query_scalar("SELECT next_child_index FROM creators")
        .fetch_one(rig.database.pool())
        .await
        .unwrap();
    assert_eq!((rows, next_index), (0, 0));

    // Combinations that do not cross Bitcoin never need the feed.
    let (status, _) = rig.prepare("parity", "500", "USD", &["USDT"], 1_800).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rig.feed.calls.load(Ordering::SeqCst), 1);
    rig.cleanup().await;
}

#[tokio::test]
async fn typed_refusals_persist_nothing_and_have_stable_bodies() {
    let usdt_less = rig(
        Seller {
            bitcoin: true,
            usdt: false,
        },
        true,
    )
    .await;
    let (status, body) = usdt_less
        .prepare("no-usdt", "500", "USD", &["USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    common::assert_fixture(FIXTURES, "seller-setup-pending-usdt", &body, &VOLATILE);
    let (status, body) = usdt_less
        .prepare("window", "500", "USD", &["BTC", "USDT"], 3_601)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    common::assert_fixture(FIXTURES, "payment-window-exceeds-cap", &body, &VOLATILE);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM marketplace_payment_preparations")
        .fetch_one(usdt_less.database.pool())
        .await
        .unwrap();
    assert_eq!(rows, 0);
    usdt_less.cleanup().await;

    let unsupported = rig(BOTH_RAILS, false).await;
    let (status, body) = unsupported
        .prepare("unsupported", "500", "USD", &["USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    common::assert_fixture(FIXTURES, "asset-unsupported", &body, &VOLATILE);
    unsupported.cleanup().await;

    let bitcoin_less = rig(
        Seller {
            bitcoin: false,
            usdt: true,
        },
        true,
    )
    .await;
    let (status, body) = bitcoin_less
        .prepare("no-bitcoin", "500", "USD", &["BTC"], 1_800)
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json(&body)["error"]["message"],
        "seller Bitcoin receiving setup is needed"
    );
    common::assert_fixture(FIXTURES, "seller-setup-pending-bitcoin", &body, &VOLATILE);
    bitcoin_less.cleanup().await;

    let neither = rig(
        Seller {
            bitcoin: false,
            usdt: false,
        },
        true,
    )
    .await;
    let (status, body) = neither
        .prepare("no-rails", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    common::assert_fixture(FIXTURES, "seller-setup-pending-both", &body, &VOLATILE);
    neither.cleanup().await;
}

#[tokio::test]
async fn usdt_only_request_activates_without_a_bitcoin_address_and_is_never_watched() {
    let rig = rig(
        Seller {
            bitcoin: false,
            usdt: true,
        },
        true,
    )
    .await;
    let mut invoices = Vec::new();
    for operation in ["usdt-1", "usdt-2"] {
        let (status, prepared) = rig.prepare(operation, "500", "USD", &["USDT"], 1_800).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&prepared)
        );
        if operation == "usdt-1" {
            common::assert_fixture(FIXTURES, "prepare-usd-usdt", &prepared, &VOLATILE);
        }
        let invoice = invoice_id(&prepared);
        let (status, activated) = rig.activate(&invoice, "500", "USD").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&activated)
        );
        invoices.push(invoice);
    }
    let settlements: (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(bitcoin_address_lookup_hash) FROM marketplace_settlements",
    )
    .fetch_one(rig.database.pool())
    .await
    .unwrap();
    assert_eq!(settlements, (2, 0));
    let owners: i64 = sqlx::query_scalar("SELECT count(*) FROM bitcoin_address_owners")
        .fetch_one(rig.database.pool())
        .await
        .unwrap();
    assert_eq!(owners, 0);
    assert!(rig.store.observation_targets().await.unwrap().is_empty());
    rig.store.scan_observation_integrity().await.unwrap();
    for invoice in invoices {
        let status = rig.status(&invoice).await;
        assert_eq!(status["state"], "active");
        assert_eq!(status["payment_state"], "undetected");
        assert!(status["bitcoin"].is_null());
    }
    rig.cleanup().await;
}

#[tokio::test]
async fn one_thousand_eight_hundred_second_window_gives_fifteen_minute_accept_by_and_thirty_minute_deadline()
 {
    let rig = rig(BOTH_RAILS, true).await;
    let (_, prepared) = rig
        .prepare("window", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    let (status, activated) = rig.activate(&invoice_id(&prepared), "500", "USD").await;
    assert_eq!(status, StatusCode::OK);
    let activated_at =
        OffsetDateTime::parse(json(&activated)["activated_at"].as_str().unwrap(), &Rfc3339)
            .unwrap();
    let deadline = OffsetDateTime::parse(
        json(&activated)["payment_deadline"].as_str().unwrap(),
        &Rfc3339,
    )
    .unwrap();
    assert_eq!(deadline - activated_at, time::Duration::minutes(30));
    let outbox = OutboxStore::new(rig.database.pool(), crypto());
    let claims = outbox
        .claim(uuid::Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap();
    let terms = outbox
        .delivery_intent(&claims[0])
        .unwrap()
        .terms()
        .unwrap()
        .clone();
    let accept_by =
        OffsetDateTime::parse(terms.proposal_expires_at.as_deref().unwrap(), &Rfc3339).unwrap();
    assert_eq!(accept_by - activated_at, time::Duration::minutes(15));
    assert_eq!(
        OffsetDateTime::parse(terms.payment_deadline.as_deref().unwrap(), &Rfc3339).unwrap(),
        deadline
    );
    rig.cleanup().await;
}

#[tokio::test]
async fn bitcoin_payment_on_a_dual_asset_request_matches_the_converted_amount() {
    let rig = rig(BOTH_RAILS, true).await;
    let (_, prepared) = rig
        .prepare("btc-on-dual", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    let invoice = invoice_id(&prepared);
    rig.activate(&invoice, "500", "USD").await;
    let observe = |sats: u64, confirmations: u32, byte: u8| {
        let store = rig.store.clone();
        async move {
            let at = OffsetDateTime::now_utc();
            let targets = store.observation_targets_at(at).await.unwrap();
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
                &store,
                &BitcoinNetwork::Mainnet,
                &targets,
                at,
            )
            .await
            .unwrap();
        }
    };

    observe(6_172, 1, 1).await;
    let underpaid = rig.status(&invoice).await;
    assert_eq!(underpaid["bitcoin"]["observed_sats"], 6_172);
    assert_eq!(underpaid["bitcoin"]["amount_matched"], false);
    assert_eq!(underpaid["bitcoin"]["paid_on_time"], false);

    observe(6_173, 2, 2).await;
    let paid = rig.status(&invoice).await;
    assert_eq!(paid["bitcoin"]["observed_sats"], 6_173);
    assert_eq!(paid["bitcoin"]["confirmations"], 2);
    assert_eq!(paid["bitcoin"]["amount_matched"], true);
    assert_eq!(paid["bitcoin"]["paid_on_time"], true);
    assert_eq!(paid["payment_state"], "confirmed");
    rig.cleanup().await;
}

#[derive(Serialize, Deserialize)]
struct StoredLegacyEnvelope {
    version: u8,
    operation_id: String,
    request_binding: Vec<u8>,
    reader: String,
    reference: String,
    total_sats: u64,
    payment_window_seconds: u64,
    prepare_ttl_seconds: u64,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
    child_index: i64,
    payment_request_intent: paykit_server::application::semantic_intent::DeliveryIntentV1,
}

#[derive(Deserialize)]
struct StoredCurrentEnvelope {
    _version: u8,
    operation_id: String,
    request_binding: Vec<u8>,
    reader: String,
    reference: String,
    _terms: paykit_server::application::marketplace_terms::MarketplaceTerms,
    payment_window_seconds: u64,
    prepare_ttl_seconds: u64,
    prepared_at: OffsetDateTime,
    prepare_expires_at: OffsetDateTime,
    child_index: i64,
    payment_request_intent: paykit_server::application::semantic_intent::DeliveryIntentV1,
}

#[tokio::test]
async fn rc16_preparation_rows_still_activate_and_report_status_as_bitcoin() {
    let rig = rig(BOTH_RAILS, true).await;
    let (_, prepared) = rig.prepare("legacy", "50000", "BTC", &["BTC"], 3_600).await;
    let invoice = invoice_id(&prepared);
    let invoice_uuid = uuid::Uuid::parse_str(&invoice).unwrap();

    // Rewrite the stored envelope as rc11-rc16 wrote it: version 1, sats total.
    let creator_hash = crypto().lookup_hash(creator().to_string().as_bytes());
    let context = EnvelopeContext::marketplace_preparation(creator_hash, invoice_uuid);
    let encrypted: Vec<u8> = sqlx::query_scalar(
        "SELECT preparation_envelope FROM marketplace_payment_preparations WHERE id = $1",
    )
    .bind(invoice_uuid)
    .fetch_one(rig.database.pool())
    .await
    .unwrap();
    let current: StoredCurrentEnvelope = postcard::from_bytes(
        &crypto()
            .decrypt(&context, &EncryptedEnvelope::from_bytes(encrypted))
            .unwrap(),
    )
    .unwrap_or_else(|_| panic!("current envelope layout"));
    let legacy = StoredLegacyEnvelope {
        version: 1,
        operation_id: current.operation_id,
        request_binding: current.request_binding,
        reader: current.reader,
        reference: current.reference,
        total_sats: 50_000,
        payment_window_seconds: current.payment_window_seconds,
        prepare_ttl_seconds: current.prepare_ttl_seconds,
        prepared_at: current.prepared_at,
        prepare_expires_at: current.prepare_expires_at,
        child_index: current.child_index,
        payment_request_intent: current.payment_request_intent,
    };
    let rewritten = crypto()
        .encrypt(&context, &postcard::to_allocvec(&legacy).unwrap())
        .unwrap();
    let rc16_binding = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "amount_sats": 50_000,
        "creator": CREATOR,
        "operation_id": "legacy",
        "payment_window_seconds": 3_600,
        "reader": reader().to_string(),
        "reference": REFERENCE,
    }))
    .unwrap();
    sqlx::query(
        "UPDATE marketplace_payment_preparations
         SET preparation_envelope = $2, request_lookup_hash = $3 WHERE id = $1",
    )
    .bind(invoice_uuid)
    .bind(rewritten.as_bytes())
    .bind(crypto().lookup_hash(&rc16_binding).as_bytes().as_slice())
    .execute(rig.database.pool())
    .await
    .unwrap();

    assert_eq!(rig.status(&invoice).await["state"], "prepared");
    let (status, body) = rig.activate(&invoice, "500", "USD").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (status, activated) = rig.activate(&invoice, "50000", "BTC").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&activated)
    );
    let activated = json(&activated);
    assert_eq!(activated["amount"], "50000");
    assert_eq!(activated["asset"], "BTC");
    assert_eq!(activated["accepted_assets"], serde_json::json!(["BTC"]));
    assert_eq!(
        activated["payment_amounts"],
        serde_json::json!({"BTC": "50000"})
    );
    let (status, replay) = rig.activate(&invoice, "50000", "BTC").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&replay), activated);
    assert_eq!(rig.status(&invoice).await["state"], "active");
    assert_eq!(rig.store.observation_targets().await.unwrap().len(), 1);
    rig.store.scan_observation_integrity().await.unwrap();

    // The retired v1 prepare body is rejected, and the new body under the same
    // operation id is a binding conflict, not a silent replay of the rc16 row.
    let (status, body) = rig
        .post(
            PREPARE,
            serde_json::json!({
                "creator": CREATOR,
                "reader": reader().to_string(),
                "reference": REFERENCE,
                "operation_id": "legacy",
                "amount_sats": 50_000,
                "payment_window_seconds": 3_600,
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (status, body) = rig.prepare("legacy", "50000", "BTC", &["BTC"], 3_600).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json(&body)["error"]["code"], "operation_conflict");
    rig.cleanup().await;
}

#[tokio::test]
async fn usdt_only_request_expires_at_read_time_without_a_bitcoin_watcher() {
    let rig = rig(
        Seller {
            bitcoin: false,
            usdt: true,
        },
        true,
    )
    .await;
    // `payment_expired_at` only stops Electrum discovery of a Bitcoin address; the
    // status route derives `expired` from the deadline itself, so a request with no
    // Bitcoin rail needs no stored expiry.
    let (_, prepared) = rig.prepare("one-second", "500", "USD", &["USDT"], 1).await;
    let invoice = invoice_id(&prepared);
    rig.activate(&invoice, "500", "USD").await;
    assert_eq!(rig.status(&invoice).await["payment_state"], "undetected");
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    assert!(rig.store.observation_targets().await.unwrap().is_empty());
    let status = rig.status(&invoice).await;
    assert_eq!(status["payment_state"], "expired");
    assert!(status["paid_asset"].is_null());
    let stored: Option<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT payment_expired_at FROM marketplace_settlements")
            .fetch_one(rig.database.pool())
            .await
            .unwrap();
    assert_eq!(stored, None);
    rig.cleanup().await;
}

/// Holds the Creator row `FOR UPDATE`, as a concurrent preparation, activation or
/// observation of the same seller would.
async fn hold_creator_row(rig: &Rig) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut held = rig.database.pool().begin().await.unwrap();
    sqlx::query("SELECT id FROM creators FOR UPDATE")
        .execute(&mut *held)
        .await
        .unwrap();
    held
}

async fn database_now(rig: &Rig) -> OffsetDateTime {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(rig.database.pool())
        .await
        .unwrap()
}

fn spawn_prepare(
    rig: &Arc<Rig>,
    operation: &'static str,
) -> tokio::task::JoinHandle<(StatusCode, Vec<u8>)> {
    let rig = rig.clone();
    tokio::spawn(async move {
        rig.prepare(operation, "500", "USD", &["BTC", "USDT"], 1_800)
            .await
    })
}

async fn count_preparations(rig: &Rig) -> (i64, i64) {
    (
        sqlx::query_scalar("SELECT count(*) FROM marketplace_payment_preparations")
            .fetch_one(rig.database.pool())
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT next_child_index FROM creators")
            .fetch_one(rig.database.pool())
            .await
            .unwrap(),
    )
}

/// The quote's whole life is fixed when the rate is accepted. A wait for the Creator row
/// that outlasts it, even one that also crosses the request deadline (so the caller sees
/// a timeout), must not commit a preparation with a fresh TTL around the old rate.
#[tokio::test]
async fn creator_lock_wait_past_the_quote_deadline_commits_nothing_and_never_revives_the_rate() {
    let rig = Arc::new(
        rig_with(
            BOTH_RAILS,
            true,
            Duration::from_secs(2),
            Some(Duration::from_secs(1)),
        )
        .await,
    );
    let held = hold_creator_row(&rig).await;
    let waiting = spawn_prepare(&rig, "stale-quote");
    tokio::time::sleep(Duration::from_millis(3_000)).await;
    held.rollback().await.unwrap();

    let (status, body) = waiting.await.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(&body)["error"]["code"], "dependency_timeout");
    assert_eq!(
        count_preparations(&rig).await,
        (0, 0),
        "no preparation row and no address index"
    );
    assert_eq!(rig.feed.calls.load(Ordering::SeqCst), 1);

    // The exact retry is a new request: it reads the feed again, so the old rate is gone.
    *rig.feed.price.lock().unwrap() = "90000";
    let (status, retry) = rig
        .prepare("stale-quote", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&retry)
    );
    assert_eq!(json(&retry)["payment_amounts"]["BTC"], "5556");
    assert_eq!(json(&retry)["rates"]["BTC"], "0.000011111111111111");
    assert_eq!(rig.feed.calls.load(Ordering::SeqCst), 2);
    assert_eq!(count_preparations(&rig).await, (1, 1));
    Arc::into_inner(rig).unwrap().cleanup().await;
}

/// The same refusal without the request deadline getting involved.
#[tokio::test]
async fn creator_lock_wait_past_the_quote_deadline_is_refused_even_when_the_request_is_still_live()
{
    let rig = Arc::new(rig_with(BOTH_RAILS, true, Duration::from_secs(2), None).await);
    let held = hold_creator_row(&rig).await;
    let waiting = spawn_prepare(&rig, "slow-lock");
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    held.commit().await.unwrap();
    let (status, body) = waiting.await.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(&body)["error"]["code"], "dependency_timeout");
    assert_eq!(count_preparations(&rig).await, (0, 0));
    Arc::into_inner(rig).unwrap().cleanup().await;
}

/// A wait that ends inside the quote's life still commits, and the preparation ends
/// exactly where the quote's life was fixed, not a full TTL after the lock was won.
#[tokio::test]
async fn creator_lock_wait_inside_the_quote_deadline_keeps_the_fixed_expiry() {
    let ttl = 6;
    let rig = Arc::new(rig_with(BOTH_RAILS, true, Duration::from_secs(ttl), None).await);
    let started = database_now(&rig).await;
    let held = hold_creator_row(&rig).await;
    let waiting = spawn_prepare(&rig, "inside");
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let released = database_now(&rig).await;
    held.commit().await.unwrap();

    let (status, body) = waiting.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let expires = OffsetDateTime::parse(
        json(&body)["prepare_expires_at"].as_str().unwrap(),
        &Rfc3339,
    )
    .unwrap();
    let ttl = time::Duration::seconds(i64::try_from(ttl).unwrap());
    assert!(
        expires >= started + ttl && expires < started + ttl + time::Duration::seconds(1),
        "expiry {expires} is the acceptance time plus the TTL, started {started}"
    );
    assert!(
        expires < released + ttl - time::Duration::seconds(1),
        "expiry {expires} must not be lock time {released} plus the TTL"
    );
    let stored: (OffsetDateTime, OffsetDateTime) = sqlx::query_as(
        "SELECT prepared_at, prepare_expires_at FROM marketplace_payment_preparations",
    )
    .fetch_one(rig.database.pool())
    .await
    .unwrap();
    assert_eq!(stored.1 - stored.0, ttl);
    assert_eq!(stored.1, expires);
    let (status, _) = rig.activate(&invoice_id(&body), "500", "USD").await;
    assert_eq!(status, StatusCode::OK);
    Arc::into_inner(rig).unwrap().cleanup().await;
}

/// Replay returns the stored preparation, with its original rate and expiry, even after
/// the fixed deadline and while the feed is down; activation after it is `prepare_expired`.
#[tokio::test]
async fn exact_replay_after_the_fixed_deadline_returns_the_stored_preparation() {
    let rig = rig_with(BOTH_RAILS, true, Duration::from_secs(2), None).await;
    let (status, prepared) = rig
        .prepare("replay", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    rig.feed.failing.store(true, Ordering::SeqCst);
    let (status, replay) = rig
        .prepare("replay", "500", "USD", &["BTC", "USDT"], 1_800)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&replay), json(&prepared));
    assert_eq!(rig.feed.calls.load(Ordering::SeqCst), 1);
    let (status, body) = rig.activate(&invoice_id(&prepared), "500", "USD").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json(&body)["error"]["code"], "prepare_expired");
    rig.cleanup().await;
}
