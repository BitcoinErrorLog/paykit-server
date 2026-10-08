//! Real AUTH, companion relay, encrypted credentials, and hosted app publication.
use async_trait::async_trait;
use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use paykit_sdk::{
    ContactUpdate, PAYKIT_SESSION_CAPABILITIES, PaykitIdentitySecretKey, PubkyAuthCompanionClaim,
    PubkyLocalSecretKey, PubkyPublicKey, PubkySessionAccess, PubkySessionBootstrap,
    PubkySessionProvider, StorageAdapter,
};
use paykit_server::{
    application::create_invoice::derive_bip84_p2wpkh_address,
    bitkit_claim::{
        ClaimError, QUERY_PARAMETER, encode_unsigned_payload, parse_auth_request,
        parse_reconnect_auth_request,
    },
    bitkit_setup::BitkitAuthStarter,
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    paykit::{CreatorSessionProvider, CreatorSessions},
    persistence::{
        AtomicInvoiceInput, AtomicInvoiceResult, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, PersistenceError, run_migrations,
    },
    real_setup::{AppPublisher, RealSetupCompleter, SharedAppPublisher},
    setup::{PollResult, SetupLimits, SetupService, StartedFlow, SystemClock},
    setup_orchestration::PubkyCompanionRelay,
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::EphemeralTestnet;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

mod common;
#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

struct AccountPayloads<'a>(&'a ReaderPubky);

impl InvoicePayloadFactory for AccountPayloads<'_> {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let address = derive_bip84_p2wpkh_address(
            &account(0).to_string(),
            0,
            &BitcoinNetwork::Testnet,
            child_index,
        )
        .unwrap();
        Ok(InvoicePayloads {
            payment_request_intent: common::payment_intent(self.0, address.clone()),
        })
    }
}

async fn allocate_invoice(
    invoices: &InvoiceStore,
    creator: &CreatorPubky,
    reader: &ReaderPubky,
    binding: &[u8],
) -> AtomicInvoiceResult {
    invoices
        .create_atomic(AtomicInvoiceInput {
            creator,
            reader,
            bundle_binding: binding,
            lock_resource_binding: binding,
            payment_request_binding: binding,
            invoice_payloads: &AccountPayloads(reader),

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap()
}

async fn business_rows(database: &TestDatabase) -> Vec<String> {
    let mut rows = sqlx::query_scalar::<_, String>(
        "SELECT json_build_object('id', id, 'next_child_index', next_child_index)::text FROM creators ORDER BY id",
    ).fetch_all(database.pool()).await.unwrap();
    for table in [
        "invoices",
        "reader_assignments",
        "outbox",
        "bitcoin_observations",
    ] {
        rows.extend(
            sqlx::query_scalar::<_, String>(&format!(
                "SELECT row_to_json(r)::text FROM {table} r ORDER BY id"
            ))
            .fetch_all(database.pool())
            .await
            .unwrap(),
        );
    }
    rows
}

struct FailAfterPublication {
    creators: CreatorStore,
    sessions: CreatorSessions,
    creator: CreatorPubky,
    fail: AtomicBool,
    calls: AtomicUsize,
}

#[async_trait]
impl AppPublisher for FailAfterPublication {
    async fn verify_key(&self, access: &PubkySessionAccess) -> Result<(), ClaimError> {
        SharedAppPublisher.verify_key(access).await
    }
    async fn publish(&self, access: PubkySessionAccess) -> Result<(), ClaimError> {
        let persisted = self.creators.load(&self.creator).await.unwrap();
        assert_eq!(
            Some(persisted.paykit_identity_secret()),
            access.paykit_identity_secret_key.as_ref()
        );
        assert!(!self.creators.setup_complete(&self.creator).await.unwrap());
        // Workers can load persisted credentials before app publication completes.
        let provider = self.sessions.provider(&self.creator);
        let worker = provider.load_session_access().await.unwrap().unwrap();
        let refreshed = worker
            .session
            .as_grant()
            .unwrap()
            .force_refresh()
            .await
            .unwrap();
        assert_eq!(
            access.session.as_grant().unwrap().current_bearer().await,
            refreshed,
            "setup and workers must share one refreshed bearer"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        SharedAppPublisher.publish(access).await?;
        let registry = paykit_lib::get_paykit_app_registry(
            &worker.outbox_client.public_storage(),
            &worker.public_key().unwrap().to_public_key().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        let app_id = paykit_lib::PaykitAppId::new("paykit-server").unwrap();
        assert_eq!(
            registry.apps().get(&app_id),
            Some(&paykit_server::real_setup::server_app())
        );
        let snapshot = paykit_sdk::PubkySharedStateStorage::new(provider)
            .transaction(|tx| Ok(tx.export_storage_state()))
            .await
            .unwrap();
        assert!(snapshot.registered_paykit_apps.contains(&app_id));
        assert_eq!(snapshot.contact_records.len(), 1);
        if self.fail.swap(false, Ordering::SeqCst) {
            Err(ClaimError::InvalidEnvelope)
        } else {
            Ok(())
        }
    }
}

fn account(index: u32) -> Xpub {
    let secp = Secp256k1::new();
    let key = Xpriv::new_master(Network::Testnet, &[42; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[84, 1, index].map(|i| ChildNumber::from_hardened_idx(i).unwrap()),
        )
        .unwrap();
    Xpub::from_priv(&secp, &key)
}

async fn complete(
    service: &SetupService,
    bootstrap: &PubkySessionBootstrap,
    root: &PubkyLocalSecretKey,
    key: &PaykitIdentitySecretKey,
    index: u32,
) -> PollResult {
    let payload = encode_unsigned_payload(index, &account(index).encode(), key);
    complete_payload(service, bootstrap, root, payload.as_slice()).await
}

async fn complete_payload(
    service: &SetupService,
    bootstrap: &PubkySessionBootstrap,
    root: &PubkyLocalSecretKey,
    payload: &[u8],
) -> PollResult {
    let flow = service
        .begin("127.0.0.1".parse().unwrap(), "https://app.example", "state")
        .await
        .unwrap();
    assert!(
        flow.authorization_url
            .contains("x-bitkit-claim=paykit-access-v1.watch-only-account-v1")
    );
    approve_payload(service, bootstrap, root, flow, payload, false).await
}

async fn reconnect(
    service: &SetupService,
    bootstrap: &PubkySessionBootstrap,
    root: &PubkyLocalSecretKey,
    key: &PaykitIdentitySecretKey,
    creator: &CreatorPubky,
) -> PollResult {
    let mut payload = vec![1];
    payload.extend_from_slice(&key.key_generation().to_be_bytes());
    payload.extend_from_slice(key.as_bytes());
    reconnect_payload(service, bootstrap, root, creator, &payload).await
}

async fn reconnect_payload(
    service: &SetupService,
    bootstrap: &PubkySessionBootstrap,
    root: &PubkyLocalSecretKey,
    creator: &CreatorPubky,
    payload: &[u8],
) -> PollResult {
    let flow = service
        .begin_reconnect(
            "127.0.0.1".parse().unwrap(),
            "https://app.example",
            "reconnect",
            creator,
        )
        .await
        .unwrap();
    let request =
        parse_reconnect_auth_request(&flow.authorization_url, PAYKIT_SESSION_CAPABILITIES).unwrap();
    assert_eq!(request.claim_type(), "paykit-access-v1");
    assert!(!flow.authorization_url.contains("watch-only-account-v1"));
    approve_payload(service, bootstrap, root, flow, payload, true).await
}

async fn approve_payload(
    service: &SetupService,
    bootstrap: &PubkySessionBootstrap,
    root: &PubkyLocalSecretKey,
    flow: StartedFlow,
    payload: &[u8],
    reconnect: bool,
) -> PollResult {
    let request = if reconnect {
        parse_reconnect_auth_request(&flow.authorization_url, PAYKIT_SESSION_CAPABILITIES)
    } else {
        parse_auth_request(&flow.authorization_url, PAYKIT_SESSION_CAPABILITIES)
    }
    .unwrap();
    let claim =
        PubkyAuthCompanionClaim::new(QUERY_PARAMETER, request.claim_type(), payload.to_vec())
            .unwrap();
    bootstrap
        .approve_auth_with_companion_claim(
            &flow.authorization_url,
            PAYKIT_SESSION_CAPABILITIES,
            root,
            &claim,
        )
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        service.trigger_completion(&flow.flow_id),
    )
    .await
    .expect("setup deadline")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_setup_reconnect_preserves_pending_invoices_and_hosted_state() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
    let testnet = EphemeralTestnet::builder()
        .postgres(pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap())
        .build()
        .await
        .unwrap();
    let relay = http_relay::HttpRelay::builder()
        .http_port(0)
        .run()
        .await
        .unwrap();
    let client = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(client.clone(), "app.paykit.server")
        .unwrap()
        .with_auth_relay(relay.local_url().join("inbox").unwrap().as_str())
        .unwrap();
    let root_keypair = pubky::Keypair::random();
    let root = PubkyLocalSecretKey::new(root_keypair.secret_key());
    let home = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let wallet_auth = bootstrap
        .sign_up(
            &root,
            &home,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let owner = wallet_auth.public_key.clone();
    let creator = parse_creator(&owner.to_app_key()).unwrap();
    let wallet = sdk_fixtures::hosted_sdk(wallet_auth.access.clone(), "bitkit", 0).await;
    let contact = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    wallet
        .save_contact(ContactUpdate {
            public_key: contact.clone(),
            label: Some("Before setup".into()),
        })
        .await
        .unwrap();
    let before = wallet
        .paykit_app_registry(owner.clone())
        .await
        .unwrap()
        .unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let invoices = InvoiceStore::new(database.pool(), crypto);
    let sessions = CreatorSessions::new(
        creators.clone(),
        client.clone(),
        paykit_server::config::PaykitConfig {
            client_id: pubky::ClientId::new("app.paykit.server").unwrap(),
            app_id: paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
            network: paykit_server::config::PaykitNetwork::Testnet,
            proposal_acceptance_window: Duration::from_secs(60 * 60),
            payment_window: Duration::from_secs(24 * 60 * 60),
            conversion_payment_window: std::time::Duration::from_secs(3600),
        },
    );
    let publisher = Arc::new(FailAfterPublication {
        creators: creators.clone(),
        sessions: sessions.clone(),
        creator: creator.clone(),
        fail: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let completer = RealSetupCompleter::with_app_publisher(
        BitkitAuthStarter::new(bootstrap.clone()),
        Arc::new(PubkyCompanionRelay::new(
            pubky::PubkyHttpClient::new().unwrap(),
        )),
        publisher.clone(),
        creators.clone(),
        sessions,
        BitcoinNetwork::Testnet,
    );
    let service = SetupService::new(
        vec!["https://app.example".into()],
        Arc::new(completer),
        Arc::new(SystemClock::default()),
        SetupLimits {
            max_polls_per_flow: 2,
            max_polls: 10,
            setup_per_ip_per_minute: 20,
            max_pending_setup_flows: 10,
        },
    );
    let key = root.derive_paykit_identity_secret_key(1).unwrap();
    assert!(
        service
            .begin_reconnect(
                "127.0.0.1".parse().unwrap(),
                "https://app.example",
                "missing",
                &creator
            )
            .await
            .is_err()
    );
    let wrong = PaykitIdentitySecretKey::new([3; 32], 1).unwrap();
    let authorization = wallet
        .paykit_noise_key_authorization(owner.clone())
        .await
        .unwrap();
    let authorization_path = paykit_lib::PAYKIT_NOISE_KEY_AUTHORIZATION_PATH;
    let owner_storage = wallet_auth.access.session.storage();
    owner_storage.delete(authorization_path).await.unwrap();
    assert_eq!(
        complete(&service, &bootstrap, &root, &key, 0).await,
        PollResult::Failed
    );
    assert!(creators.load_optional(&creator).await.unwrap().is_none());
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 0);

    let mut tampered = serde_json::to_value(&authorization).unwrap();
    tampered["key_generation"] = serde_json::json!(2);
    let mismatched =
        paykit_lib::PaykitNoiseKeyAuthorization::sign(&root_keypair, &[9; 32], 1).unwrap();
    // Raw owner writes inject invalid remote records without weakening SDK publication.
    for invalid in [tampered, serde_json::to_value(mismatched).unwrap()] {
        owner_storage
            .put_json(authorization_path, &invalid)
            .await
            .unwrap();
        assert_eq!(
            complete(&service, &bootstrap, &root, &key, 0).await,
            PollResult::Failed
        );
        assert!(creators.load_optional(&creator).await.unwrap().is_none());
        assert_eq!(publisher.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            wallet.paykit_app_registry(owner.clone()).await.unwrap(),
            Some(before.clone())
        );
    }
    owner_storage
        .put_json(authorization_path, &authorization)
        .await
        .unwrap();
    assert_eq!(
        complete(&service, &bootstrap, &root, &wrong, 0).await,
        PollResult::Failed
    );
    assert!(creators.load_optional(&creator).await.unwrap().is_none());
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        complete(&service, &bootstrap, &root, &key, 0).await,
        PollResult::Failed
    );
    assert!(!creators.setup_complete(&creator).await.unwrap());
    let registry = wallet
        .paykit_app_registry(owner.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        registry
            .apps()
            .get(&paykit_lib::PaykitAppId::new("bitkit").unwrap()),
        before
            .apps()
            .get(&paykit_lib::PaykitAppId::new("bitkit").unwrap())
    );
    assert!(
        registry
            .apps()
            .contains_key(&paykit_lib::PaykitAppId::new("paykit-server").unwrap())
    );
    assert_eq!(wallet.contact_records().await.unwrap().len(), 1);
    assert_eq!(
        reconnect(&service, &bootstrap, &root, &key, &creator).await,
        PollResult::Complete
    );
    assert!(creators.setup_complete(&creator).await.unwrap());
    let reader = parse_reader(&contact.to_app_key()).unwrap();
    let pending = allocate_invoice(&invoices, &creator, &reader, b"pending-before-reconnect").await;
    assert_eq!(pending.reader_child_index(), 0);
    let second = allocate_invoice(&invoices, &creator, &reader, b"second-before-reconnect").await;
    assert_eq!(second.reader_child_index(), 1);
    let before_reconnect = business_rows(&database).await;
    let original = creators.load(&creator).await.unwrap();
    let publication_calls = publisher.calls.load(Ordering::SeqCst);
    // Even a correctly signed combined reply cannot smuggle account bytes into reconnect.
    let combined = encode_unsigned_payload(0, &account(0).encode(), &key);
    assert_eq!(
        reconnect_payload(&service, &bootstrap, &root, &creator, combined.as_slice()).await,
        PollResult::Failed
    );
    let other_root = PubkyLocalSecretKey::new(pubky::Keypair::random().secret_key());
    let other = bootstrap
        .sign_up(&other_root, &home, None, PAYKIT_SESSION_CAPABILITIES)
        .await
        .unwrap();
    assert_eq!(
        reconnect(&service, &bootstrap, &other_root, &key, &creator).await,
        PollResult::Failed
    );
    assert!(
        creators
            .load_optional(&parse_creator(&other.public_key.to_app_key()).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        complete(&service, &bootstrap, &root, &key, 1).await,
        PollResult::Failed
    );
    // A different valid xpub at the same account index must also be rejected.
    let mut different = account(0);
    different.chain_code = account(1).chain_code;
    let payload = encode_unsigned_payload(0, &different.encode(), &key);
    assert_eq!(
        complete_payload(&service, &bootstrap, &root, payload.as_slice()).await,
        PollResult::Failed
    );
    assert_eq!(
        reconnect(&service, &bootstrap, &root, &wrong, &creator).await,
        PollResult::Failed
    );
    let cancelled = service
        .begin_reconnect(
            "127.0.0.1".parse().unwrap(),
            "https://app.example",
            "cancelled-reconnect",
            &creator,
        )
        .await
        .unwrap();
    // No wallet approval: a dropped wait must not replace existing credentials.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            service.trigger_completion(&cancelled.flow_id),
        )
        .await
        .is_err()
    );
    // The dropped request leaves completion running in its own task.
    assert_eq!(
        service.trigger_completion(&cancelled.flow_id).await,
        PollResult::PendingTimeout
    );
    assert_eq!(publisher.calls.load(Ordering::SeqCst), publication_calls);
    let unchanged = creators.load(&creator).await.unwrap();
    assert!(unchanged.session_secret() == original.session_secret());
    assert_eq!(unchanged.paykit_identity_secret(), &key);
    assert_eq!(
        unchanged.bitcoin_account().unwrap().xpub.as_str(),
        original.bitcoin_account().unwrap().xpub.as_str()
    );
    assert_eq!(
        creators
            .load(&creator)
            .await
            .unwrap()
            .bitcoin_account()
            .unwrap()
            .account_index,
        0
    );
    assert!(creators.setup_complete(&creator).await.unwrap());
    assert_eq!(business_rows(&database).await, before_reconnect);
    assert_eq!(
        reconnect(&service, &bootstrap, &root, &key, &creator).await,
        PollResult::Complete
    );
    let refreshed_credentials = creators.load(&creator).await.unwrap();
    assert_eq!(
        refreshed_credentials
            .bitcoin_account()
            .unwrap()
            .xpub
            .as_str(),
        original.bitcoin_account().unwrap().xpub.as_str()
    );
    assert_eq!(
        refreshed_credentials
            .bitcoin_account()
            .unwrap()
            .account_index,
        original.bitcoin_account().unwrap().account_index
    );
    assert_eq!(refreshed_credentials.paykit_identity_secret(), &key);
    assert_eq!(business_rows(&database).await, before_reconnect);

    let config = Config::from_toml_and_environment(
        r#"
[http]
listen_addr = "127.0.0.1:0"
[signed_services]
trusted_public_keys = ["pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo"]
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "testnet"
[electrum]
endpoint = "tcp://127.0.0.1:1"
[outbox]
poll_interval = "1s"
"#,
        ConfigEnvironment {
            database_url: Some(database.database_url().into()),
            master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()),
        },
    )
    .unwrap();
    let provider = CreatorSessionProvider::with_pubky(
        creators.clone(),
        creator.clone(),
        client,
        &config.paykit,
    );
    let access = provider.load_session_access().await.unwrap().unwrap();
    assert!(access.local_secret_key.is_none());
    assert!(
        access
            .validate_for_capabilities(paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES)
            .is_err()
    );
    assert_eq!(access.public_key().unwrap(), owner);
    let refreshed = access
        .session
        .as_grant()
        .unwrap()
        .force_refresh()
        .await
        .unwrap();
    let cached = provider.load_session_access().await.unwrap().unwrap();
    assert!(cached.session.as_grant().unwrap().current_bearer().await == refreshed);

    let replacement = root.derive_paykit_identity_secret_key(2).unwrap();
    wallet
        .rotate_paykit_identity_key(replacement.clone())
        .await
        .unwrap();
    assert_eq!(
        reconnect(&service, &bootstrap, &root, &key, &creator).await,
        PollResult::Failed
    );
    let rejected = creators.load(&creator).await.unwrap();
    assert!(rejected.session_secret() == refreshed_credentials.session_secret());
    assert_eq!(rejected.paykit_identity_secret(), &key);
    assert!(creators.setup_complete(&creator).await.unwrap());
    assert_eq!(business_rows(&database).await, before_reconnect);
    assert_eq!(
        reconnect(&service, &bootstrap, &root, &replacement, &creator).await,
        PollResult::Complete
    );
    assert_eq!(
        reconnect(&service, &bootstrap, &root, &key, &creator).await,
        PollResult::Failed
    );
    let rotated = creators.load(&creator).await.unwrap();
    assert_eq!(
        rotated.bitcoin_account().unwrap().xpub.as_str(),
        original.bitcoin_account().unwrap().xpub.as_str()
    );
    assert_eq!(
        rotated.bitcoin_account().unwrap().account_index,
        original.bitcoin_account().unwrap().account_index
    );
    assert_eq!(rotated.paykit_identity_secret(), &replacement);
    assert!(creators.setup_complete(&creator).await.unwrap());
    assert_eq!(business_rows(&database).await, before_reconnect);
    let replay = invoices
        .exact_replay(
            &creator,
            &reader,
            b"pending-before-reconnect",
            b"pending-before-reconnect",
        )
        .await
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.invoice_id(), pending.invoice_id());
    assert_eq!(
        replay.reader_assignment_id(),
        pending.reader_assignment_id()
    );
    assert_eq!(
        replay.payment_request_outbox_id(),
        pending.payment_request_outbox_id()
    );
    assert_eq!(replay.reader_child_index(), 0);
    assert_eq!(business_rows(&database).await, before_reconnect);
    let next = allocate_invoice(&invoices, &creator, &reader, b"after-key-rotation").await;
    assert_eq!(next.reader_child_index(), 2);
    assert_ne!(next.invoice_id(), pending.invoice_id());
    let rotated_access = provider.load_session_access().await.unwrap().unwrap();
    assert_eq!(
        rotated_access.paykit_identity_secret_key.as_ref(),
        Some(&replacement)
    );
    let server = paykit_sdk::PaykitSdk::new(
        paykit_sdk::PubkySharedStateStorage::new(provider.clone()),
        provider,
        paykit_server::paykit::ExplicitInputsPaymentAdapter,
        paykit_sdk::PaykitSdkConfig::new("paykit-server").unwrap(),
    );
    server.initialize().await.unwrap();
    assert_eq!(server.contact_records().await.unwrap().len(), 1);
    assert_eq!(
        server.contact_records().await.unwrap()[0].public_key,
        contact
    );
    database.cleanup().await;
}
