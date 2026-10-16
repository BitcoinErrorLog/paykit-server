use super::*;
use paykit_lib::{PaymentAmount, PaymentEndpointIdentifier, PaymentReference, PaymentRequestTerms};
use paykit_server::{
    application::payment_request_status::PaymentRequestStatusError,
    paykit::{CreatorSessions, PaykitAdapter},
    persistence::{CreatorCredentials, InvoiceStore, OutboxStore, PaymentRequestLifecycleStore},
    workers::outbox::Adapter,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn status_receives_required_peer_without_consuming_unrelated_messages() {
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
    let creator_key = PubkyPublicKey::from_raw_or_app_key(fixture.creator.to_string()).unwrap();
    let (reader, peer_key, peer_sdk) = create_peer(&bootstrap, &homeserver).await;
    let (_, unrelated_key, unrelated_sdk) = create_peer(&bootstrap, &homeserver).await;
    for (key, sdk) in [(&peer_key, &peer_sdk), (&unrelated_key, &unrelated_sdk)] {
        link(&fixture.sdk, creator_key.clone(), sdk, key.clone()).await;
    }

    let paykit = config.paykit.clone();
    let server = Server::build_with_transports(
        config,
        pool.clone(),
        pubky.clone(),
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
    // The server is not running: no background worker can consume either inbox.
    let creator_id = creators.ready_ids().await.unwrap()[0];
    set_whole_second_invoice_deadlines(&pool, &crypto, creator_id, &fixture.creator).await;
    let sessions = CreatorSessions::new(creators, pubky, paykit.clone());
    let adapter =
        PaykitAdapter::new(creator_id, sessions.provider(&fixture.creator), &paykit).unwrap();
    let outbox = OutboxStore::new(&pool, crypto.clone());
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(60))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let intent = outbox.delivery_intent(&claim).unwrap();
    let handoff = adapter
        .execute_claimed_handoff(&outbox, &claim, &intent)
        .await
        .unwrap();
    assert!(outbox.mark_handed_off(&claim, &handoff).await.unwrap());
    adapter.send_handed_off(&outbox, &claim).await.unwrap();
    peer_sdk
        .receive_private_messages(creator_key.clone())
        .await
        .unwrap();

    unrelated_sdk
        .propose_payment_request(
            creator_key.clone(),
            PaymentRequestTerms::builder(
                PaymentAmount::new("0.00000100", "BTC").unwrap(),
                PaymentReference::new(Uuid::new_v4().to_string()).unwrap(),
                vec![PaymentEndpointIdentifier::new("btc-testnet-p2wpkh").unwrap()],
            )
            .build()
            .unwrap(),
        )
        .await
        .unwrap();
    unrelated_sdk
        .process_outbound_private_messages(creator_key)
        .await
        .unwrap();

    let lifecycles = PaymentRequestLifecycleStore::new(&pool, crypto.clone());
    let invoices = InvoiceStore::new(&pool, crypto);
    let bundle = parse_bundle_id(BUNDLE_A).unwrap();
    let required = lifecycles
        .required_receive_targets_for_bundle(creator_id, &bundle)
        .await
        .unwrap();
    assert_eq!(required.len(), 1);
    assert_eq!(required[0].counterparty(), reader.to_string());
    assert!(
        adapter
            .reconcile_and_lookup_payment_request_status(&lifecycles, &invoices, &bundle)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .sdk
            .received_payment_requests_from(&unrelated_key)
            .await
            .unwrap()
            .is_empty()
    );

    fixture.sdk.block_peer(peer_key).await.unwrap();
    assert_eq!(
        adapter
            .reconcile_and_lookup_payment_request_status(&lifecycles, &invoices, &bundle)
            .await,
        Err(PaymentRequestStatusError::Unavailable)
    );
    adapter
        .receive_and_project_payment_requests(&lifecycles)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .sdk
            .received_payment_requests_from(&unrelated_key)
            .await
            .unwrap()
            .len(),
        1
    );
    drop(server);
    pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn status_route_returns_canceled_for_rotation_suppressed_proposal() {
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
    assert!(evidence.is_empty());
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
    let rotation = creators
        .rotate_bitcoin_account_after_receive(&lifecycles, &replacement, &evidence)
        .await
        .unwrap();
    assert_eq!(rotation.cancellation_pending_count, 0);
    assert!(
        lifecycles
            .required_receive_targets_for_bundle(creator_id, &parse_bundle_id(BUNDLE_A).unwrap(),)
            .await
            .unwrap()
            .is_empty(),
        "suppressed pre-handoff proposal must not require an impossible receive"
    );

    let response = server
        .router()
        .oneshot(payment_request_status_request(
            &signing_key,
            &fixture,
            BUNDLE_A,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["request_state"], "canceled");
    assert_eq!(body["payment_state"], "undetected");

    drop(server);
    pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn status_route_returns_proposal_expired_for_expired_pre_handoff_proposal() {
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
    assert!(
        lifecycles
            .required_receive_targets_for_bundle(creator_id, &parse_bundle_id(BUNDLE_A).unwrap(),)
            .await
            .unwrap()
            .is_empty(),
        "expired pre-handoff proposal must not require an impossible receive"
    );

    let response = server
        .router()
        .oneshot(payment_request_status_request(
            &signing_key,
            &fixture,
            BUNDLE_A,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["request_state"], "proposal_expired");
    assert_eq!(body["payment_state"], "undetected");

    drop(server);
    pool.close().await;
    database.cleanup().await;
}

async fn set_whole_second_invoice_deadlines(
    pool: &PgPool,
    crypto: &Crypto,
    creator_id: Uuid,
    creator: &CreatorPubky,
) {
    // Keep this intake fixture independent of fractional timestamp formatting.
    // Both encrypted intent copies must agree before the outbox is claimed.
    let mut transaction = pool.begin().await.unwrap();
    let (outbox_id, invoice_id, envelope, created, proposal, payment): (
        Uuid,
        Uuid,
        Vec<u8>,
        OffsetDateTime,
        OffsetDateTime,
        OffsetDateTime,
    ) = sqlx::query_as(
        "SELECT outbox.id, invoices.id, outbox.intent_envelope,
                date_trunc('second', invoices.invoice_created_at),
                date_trunc('second', invoices.proposal_expires_at),
                date_trunc('second', invoices.payment_deadline)
         FROM outbox JOIN invoices ON invoices.id = outbox.invoice_id
         WHERE outbox.creator_id = $1 AND outbox.status = 'queued'",
    )
    .bind(creator_id)
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    let creator_hash = crypto.lookup_hash(creator.to_string().as_bytes());
    let outbox_context = EnvelopeContext::outbox_semantic_intent(creator_hash, outbox_id);
    let plaintext = crypto
        .decrypt(&outbox_context, &EncryptedEnvelope::from_bytes(envelope))
        .unwrap();
    let mut intent = DeliveryIntentV1::decode(&plaintext).unwrap();
    intent
        .set_deadlines(
            proposal.format(&Rfc3339).unwrap(),
            payment.format(&Rfc3339).unwrap(),
        )
        .unwrap();
    let sdk_terms = intent.terms().unwrap().to_sdk().unwrap();
    assert_eq!(
        intent.terms().unwrap().payment_deadline,
        Some(sdk_terms.payment_deadline().unwrap().at(None).unwrap())
    );
    let plaintext = postcard::to_allocvec(&intent).unwrap();
    let invoice_envelope = crypto
        .encrypt(
            &EnvelopeContext::invoice(creator_hash, invoice_id),
            &plaintext,
        )
        .unwrap();
    let outbox_envelope = crypto.encrypt(&outbox_context, &plaintext).unwrap();
    sqlx::query(
        "UPDATE invoices SET invoice_created_at = $1, proposal_expires_at = $2,
                payment_deadline = $3, invoice_envelope = $4 WHERE id = $5",
    )
    .bind(created)
    .bind(proposal)
    .bind(payment)
    .bind(invoice_envelope.as_bytes())
    .bind(invoice_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query("UPDATE outbox SET intent_envelope = $1 WHERE id = $2")
        .bind(outbox_envelope.as_bytes())
        .bind(outbox_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}
