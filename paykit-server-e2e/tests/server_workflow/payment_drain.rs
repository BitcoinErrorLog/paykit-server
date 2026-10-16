use super::*;
use paykit_server::{
    domain::locks::parse_addressed_lock_resource,
    persistence::{OutboxStore, PaymentRequestLifecycleStore},
};

fn payment_drain_request(signing_key: &SigningKey, fixture: &CreatorFixture) -> Request<Body> {
    signed_request(
        signing_key,
        Method::POST,
        "/payment-request-drains",
        format!(r#"{{"lock_resource":"{}"}}"#, fixture.lock_resource),
    )
}

async fn assert_drain_completes_with_terminal_item(
    server: &Server,
    pool: &PgPool,
    signing_key: &SigningKey,
    fixture: &CreatorFixture,
    creator_id: Uuid,
    lifecycles: &PaymentRequestLifecycleStore,
    expected_classification: &str,
) {
    let lock_resource = parse_addressed_lock_resource(&fixture.lock_resource).unwrap();
    assert!(
        lifecycles
            .required_receive_targets_for_lock(creator_id, &lock_resource)
            .await
            .unwrap()
            .is_empty(),
        "terminal pre-handoff proposal must not require an impossible receive"
    );

    let response = server
        .router()
        .oneshot(payment_drain_request(signing_key, fixture))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["status"], "completed");
    assert_eq!(body["accepted_count"], 0);
    assert_eq!(body["terminal_count"], 1);
    assert_eq!(body["cancellation_enqueued_count"], 0);

    let classification: String =
        sqlx::query_scalar("SELECT classification FROM payment_drain_items")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(classification, expected_classification);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn drain_completes_for_rotation_suppressed_proposal_to_never_linked_reader() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let config = config(database.database_url(), &signing_key, "1h");
    let pool = initialize_database(&config).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server").unwrap();
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(&pool, crypto.clone());
    let fixture = create_creator(
        &bootstrap,
        &homeserver,
        &creators,
        CreatorSpec {
            seed: 43,
            account_index: 0,
            amount_sats: 100,
            counter_seed: 100,
        },
    )
    .await;
    let (reader, _, _) = create_peer(&bootstrap, &homeserver).await;
    let server = Server::build_with_transports(
        config,
        pool.clone(),
        pubky,
        Arc::new(DeterministicElectrum::new(&[&fixture])),
    )
    .await
    .unwrap();
    let response = server
        .router()
        .oneshot(invoice_request(&signing_key, &fixture, &reader, BUNDLE_A))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let creator_id = creators.ready_ids().await.unwrap()[0];
    let lifecycles = PaymentRequestLifecycleStore::new(&pool, crypto);
    let evidence = lifecycles
        .required_receive_targets_for_creator_rotation(&fixture.creator)
        .await
        .unwrap();
    let current = creators.load(&fixture.creator).await.unwrap();
    let replacement = CreatorCredentials::new(
        fixture.creator.clone(),
        current.session_secret().to_owned(),
        current.paykit_identity_secret().clone(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: account_xpub(44, 1).into(),
            account_index: 1,
        }),
        None,
    );
    creators
        .rotate_bitcoin_account_after_receive(&lifecycles, &replacement, &evidence)
        .await
        .unwrap();

    assert_drain_completes_with_terminal_item(
        &server,
        &pool,
        &signing_key,
        &fixture,
        creator_id,
        &lifecycles,
        "canceled",
    )
    .await;

    drop(server);
    pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn drain_completes_for_expired_pre_handoff_proposal_to_never_linked_reader() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let config = config(database.database_url(), &signing_key, "1h");
    let pool = initialize_database(&config).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server").unwrap();
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(&pool, crypto.clone());
    let fixture = create_creator(
        &bootstrap,
        &homeserver,
        &creators,
        CreatorSpec {
            seed: 43,
            account_index: 0,
            amount_sats: 100,
            counter_seed: 100,
        },
    )
    .await;
    let (reader, _, _) = create_peer(&bootstrap, &homeserver).await;
    let server = Server::build_with_transports(
        config,
        pool.clone(),
        pubky,
        Arc::new(DeterministicElectrum::new(&[&fixture])),
    )
    .await
    .unwrap();
    let response = server
        .router()
        .oneshot(invoice_request(&signing_key, &fixture, &reader, BUNDLE_A))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let creator_id = creators.ready_ids().await.unwrap()[0];
    let outbox = OutboxStore::new(&pool, crypto.clone());
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(60))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(outbox.mark_proposal_expired(&claim).await.unwrap());
    let lifecycles = PaymentRequestLifecycleStore::new(&pool, crypto);

    assert_drain_completes_with_terminal_item(
        &server,
        &pool,
        &signing_key,
        &fixture,
        creator_id,
        &lifecycles,
        "proposal_expired",
    )
    .await;

    drop(server);
    pool.close().await;
    database.cleanup().await;
}
