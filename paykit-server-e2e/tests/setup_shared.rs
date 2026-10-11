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
            marketplace_prepare_ttl: Duration::from_secs(15 * 60),
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

/// `POST /setup/status` `accepted_asset` against sellers created by the real
/// setup and reconnect routes, with the Shop iframe's USDT claim selection.
mod setup_status_readiness {
    use super::*;
    use axum::{
        Extension,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use paykit_server::{
        application::create_invoice::{SessionValidationError, SessionValidator},
        application::setup_status::SetupStatusService,
        domain::receiving::USDT_TOKEN,
        http::{auth::SignedServiceAuth, setup_status::setup_status_router},
    };
    use tower::ServiceExt;

    const USDT_ADDRESS: &str = "0x2222222222222222222222222222222222222222";
    const READY: &str = r#"{"status":"ready"}"#;
    const SETUP_REQUIRED: &str = r#"{"status":"setup_required"}"#;

    struct StoredAuthority {
        creators: CreatorStore,
        sessions: CreatorSessions,
    }

    #[async_trait]
    impl SessionValidator for StoredAuthority {
        async fn validate(&self, creator: &CreatorPubky) -> Result<(), SessionValidationError> {
            if !self
                .creators
                .setup_complete(creator)
                .await
                .map_err(|_| SessionValidationError::Unavailable)?
            {
                return Err(SessionValidationError::Invalid);
            }
            let access = self
                .sessions
                .provider(creator)
                .load_session_access()
                .await
                .map_err(|_| SessionValidationError::Unavailable)?
                .ok_or(SessionValidationError::Invalid)?;
            access
                .session
                .revalidate()
                .await
                .map_err(|_| SessionValidationError::Unavailable)?
                .ok_or(SessionValidationError::Invalid)?;
            Ok(())
        }
    }

    struct Seller {
        root: PubkyLocalSecretKey,
        creator: CreatorPubky,
        key: PaykitIdentitySecretKey,
        _wallet: sdk_fixtures::HostedSdk,
    }

    async fn enroll(bootstrap: &PubkySessionBootstrap, home: &PubkyPublicKey) -> Seller {
        let root_keypair = pubky::Keypair::random();
        let root = PubkyLocalSecretKey::new(root_keypair.secret_key());
        let wallet_auth = bootstrap
            .sign_up(
                &root,
                home,
                None,
                paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
            )
            .await
            .unwrap();
        let creator = parse_creator(&wallet_auth.public_key.to_app_key()).unwrap();
        let wallet = sdk_fixtures::hosted_sdk(wallet_auth.access, "bitkit", 0).await;
        let key = root.derive_paykit_identity_secret_key(1).unwrap();
        Seller {
            root,
            creator,
            key,
            _wallet: wallet,
        }
    }

    fn payload(seller: &Seller, bitcoin: bool, usdt: Option<&str>) -> Vec<u8> {
        let mut value = serde_json::json!({
            "paykit_access": {
                "key_generation": seller.key.key_generation(),
                "secret": URL_SAFE_NO_PAD.encode(seller.key.as_bytes()),
            }
        });
        if bitcoin {
            value["bitcoin_account"] = serde_json::json!({
                "account_index": 0,
                "address_type": "nativeSegwit",
                "xpub": account(0).to_string(),
            });
        }
        if let Some(address) = usdt {
            value["usdt-arbitrum-address"] = serde_json::json!({
                "value": address,
                "chain_id": "42161",
                "token": USDT_TOKEN,
            });
        }
        serde_json::to_vec(&value).unwrap()
    }

    async fn setup(
        service: &SetupService,
        bootstrap: &PubkySessionBootstrap,
        seller: &Seller,
        usdt: Option<&str>,
    ) -> PollResult {
        let flow = service
            .begin("127.0.0.1".parse().unwrap(), "https://app.example", "setup")
            .await
            .unwrap();
        assert!(flow.authorization_url.contains("usdt-address-v1"));
        let payload = payload(seller, true, usdt);
        approve_payload(service, bootstrap, &seller.root, flow, &payload, false).await
    }

    async fn reconnect_with_usdt(
        service: &SetupService,
        bootstrap: &PubkySessionBootstrap,
        seller: &Seller,
        usdt: Option<&str>,
    ) -> PollResult {
        let flow = service
            .begin_reconnect(
                "127.0.0.1".parse().unwrap(),
                "https://app.example",
                "reconnect",
                &seller.creator,
            )
            .await
            .unwrap();
        assert!(flow.authorization_url.contains("usdt-address-v1"));
        let payload = payload(seller, false, usdt);
        approve_payload(service, bootstrap, &seller.root, flow, &payload, true).await
    }

    fn signing_config(key: &SigningKey) -> Config {
        let key = pubky::PublicKey::from(
            pubky::pkarr::PublicKey::try_from(key.verifying_key().as_bytes()).unwrap(),
        )
        .to_string();
        Config::from_toml_and_environment(
            &format!(
                r#"
[http]
listen_addr = "127.0.0.1:8080"
[signed_services]
trusted_public_keys = ["{key}"]
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "testnet"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "5s"
[limits]
request_body_bytes = 16384
[rate_limits]
signed_requests_per_second = 100
signed_burst = 200
"#
            ),
            ConfigEnvironment {
                database_url: Some("postgres://paykit:secret@localhost/paykit".to_owned()),
                master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned()),
            },
        )
        .unwrap()
    }

    struct StatusRoute {
        signer: SigningKey,
        creators: CreatorStore,
        sessions: CreatorSessions,
        usdt_enabled: bool,
    }

    impl StatusRoute {
        async fn ask(&self, body: String) -> (StatusCode, String) {
            let service = SetupStatusService::new(Arc::new(StoredAuthority {
                creators: self.creators.clone(),
                sessions: self.sessions.clone(),
            }))
            .with_receiving(Arc::new(self.creators.clone()), self.usdt_enabled);
            let router = setup_status_router(Arc::new(service)).layer(Extension(Arc::new(
                SignedServiceAuth::from_config(&signing_config(&self.signer)),
            )));
            let body = body.into_bytes();
            let preimage =
                paykit_server::http::auth::signature_preimage("POST", "/setup/status", &body);
            let request = Request::builder()
                .method(Method::POST)
                .uri("/setup/status")
                .header(
                    "X-Paykit-Signature",
                    URL_SAFE_NO_PAD.encode(self.signer.sign(&preimage).to_bytes()),
                )
                .body(Body::from(body))
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            let status = response.status();
            let body = String::from_utf8(
                to_bytes(response.into_body(), 32 * 1024)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            (status, body)
        }

        async fn accepted(&self, creator: &CreatorPubky, accepted: &str) -> String {
            let (status, body) = self
                .ask(format!(
                    r#"{{"accepted_asset":"{accepted}","creator":"{creator}"}}"#
                ))
                .await;
            assert_eq!(status, StatusCode::OK);
            body
        }

        async fn denomination(&self, creator: &CreatorPubky, asset: &str) -> String {
            let (status, body) = self
                .ask(format!(r#"{{"asset":"{asset}","creator":"{creator}"}}"#))
                .await;
            assert_eq!(status, StatusCode::OK);
            body
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accepted_asset_follows_real_setup_and_reconnect() {
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
        let home = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
        let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
        let creators = CreatorStore::new(database.pool(), crypto);
        let sessions = CreatorSessions::new(
            creators.clone(),
            client.clone(),
            paykit_server::config::PaykitConfig {
                client_id: pubky::ClientId::new("app.paykit.server").unwrap(),
                app_id: paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
                network: paykit_server::config::PaykitNetwork::Testnet,
                proposal_acceptance_window: Duration::from_secs(60 * 60),
                payment_window: Duration::from_secs(24 * 60 * 60),
                conversion_payment_window: Duration::from_secs(3600),
                marketplace_prepare_ttl: Duration::from_secs(15 * 60),
            },
        );
        let completer = RealSetupCompleter::new(
            BitkitAuthStarter::new(bootstrap.clone()).with_usdt(),
            Arc::new(PubkyCompanionRelay::new(
                pubky::PubkyHttpClient::new().unwrap(),
            )),
            creators.clone(),
            sessions.clone(),
            BitcoinNetwork::Testnet,
        );
        let service = SetupService::new(
            vec!["https://app.example".into()],
            Arc::new(completer),
            Arc::new(SystemClock::default()),
            SetupLimits {
                max_polls_per_flow: 2,
                max_polls: 20,
                setup_per_ip_per_minute: 20,
                max_pending_setup_flows: 10,
            },
        );
        let route = StatusRoute {
            signer: SigningKey::from_bytes(&[7; 32]),
            creators: creators.clone(),
            sessions: sessions.clone(),
            usdt_enabled: true,
        };
        let without_usdt_config = StatusRoute {
            signer: SigningKey::from_bytes(&[7; 32]),
            creators,
            sessions,
            usdt_enabled: false,
        };

        let never_set_up = enroll(&bootstrap, &home).await;
        // Seller A approved a Bitcoin account and a USDT address.
        let both = enroll(&bootstrap, &home).await;
        assert_eq!(
            setup(&service, &bootstrap, &both, Some(USDT_ADDRESS)).await,
            PollResult::Complete
        );
        // Seller B approved a Bitcoin account and declined the USDT address.
        let bitcoin_only = enroll(&bootstrap, &home).await;
        assert_eq!(
            setup(&service, &bootstrap, &bitcoin_only, None).await,
            PollResult::Complete
        );

        assert_eq!(route.accepted(&both.creator, "USDT").await, READY);
        assert_eq!(route.accepted(&both.creator, "BTC").await, READY);
        assert_eq!(
            route.accepted(&bitcoin_only.creator, "USDT").await,
            SETUP_REQUIRED
        );
        assert_eq!(route.accepted(&bitcoin_only.creator, "BTC").await, READY);
        assert_eq!(
            route.accepted(&never_set_up.creator, "USDT").await,
            SETUP_REQUIRED
        );
        assert_eq!(
            route.accepted(&never_set_up.creator, "BTC").await,
            SETUP_REQUIRED
        );
        // `[usdt]` not configured: even a seller with a USDT address is not ready.
        assert_eq!(
            without_usdt_config.accepted(&both.creator, "USDT").await,
            SETUP_REQUIRED
        );
        assert_eq!(
            without_usdt_config.accepted(&both.creator, "BTC").await,
            READY
        );

        // The denomination semantics are untouched: the same Bitcoin-only seller
        // is ready for every denomination, exactly as before `accepted_asset`.
        for asset in ["BTC", "USD", "USDT"] {
            assert_eq!(
                route.denomination(&bitcoin_only.creator, asset).await,
                READY
            );
            assert_eq!(route.denomination(&both.creator, asset).await, READY);
            assert_eq!(
                route.denomination(&never_set_up.creator, asset).await,
                SETUP_REQUIRED
            );
        }
        assert_eq!(
            without_usdt_config
                .denomination(&both.creator, "USDT")
                .await,
            SETUP_REQUIRED
        );
        assert_eq!(
            without_usdt_config.denomination(&both.creator, "USD").await,
            READY
        );

        // Both fields together.
        let (status, body) = route
            .ask(format!(
                r#"{{"accepted_asset":"USDT","asset":"USDT","creator":"{}"}}"#,
                bitcoin_only.creator
            ))
            .await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, SETUP_REQUIRED));
        let (status, body) = route
            .ask(format!(
                r#"{{"accepted_asset":"BTC","asset":"USDT","creator":"{}"}}"#,
                bitcoin_only.creator
            ))
            .await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, READY));
        let (status, body) = route
            .ask(format!(
                r#"{{"accepted_asset":"USDT","asset":"USD","creator":"{}"}}"#,
                both.creator
            ))
            .await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, READY));

        // A reconnect that does not add the address leaves USDT unavailable.
        assert_eq!(
            reconnect_with_usdt(&service, &bootstrap, &bitcoin_only, None).await,
            PollResult::Complete
        );
        assert_eq!(
            route.accepted(&bitcoin_only.creator, "USDT").await,
            SETUP_REQUIRED
        );
        // A reconnect that adds the address makes the seller USDT-ready.
        assert_eq!(
            reconnect_with_usdt(&service, &bootstrap, &bitcoin_only, Some(USDT_ADDRESS)).await,
            PollResult::Complete
        );
        assert_eq!(route.accepted(&bitcoin_only.creator, "USDT").await, READY);
        assert_eq!(route.accepted(&bitcoin_only.creator, "BTC").await, READY);
        assert_eq!(
            without_usdt_config
                .accepted(&bitcoin_only.creator, "USDT")
                .await,
            SETUP_REQUIRED
        );
        database.cleanup().await;
    }
}
