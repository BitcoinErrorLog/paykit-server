//! Isolated hosted-state verification for wallet and delegated server runtimes.
use async_trait::async_trait;
use paykit_lib::{PaykitApp, PaykitAppCapabilities, PaykitAppId};
use paykit_sdk::{
    ContactUpdate, PAYKIT_SESSION_CAPABILITIES, PaykitSdk, PaykitSdkConfig, PubkyLocalSecretKey,
    PubkyPublicKey, PubkySessionAccess, PubkySessionBootstrap, PubkySessionProvider,
    PubkySharedStateStorage,
};
use paykit_server::{
    bitkit_claim::{encode_unsigned_payload, parse_unsigned_payload},
    paykit::ExplicitInputsPaymentAdapter,
    real_setup::{AppPublisher, SharedAppPublisher},
};
use pubky_testnet::EphemeralTestnet;

#[derive(Clone)]
struct Provider(PubkySessionAccess);
#[async_trait]
impl PubkySessionProvider for Provider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        Ok(Some(self.0.clone()))
    }
    async fn load_public_storage(&self) -> paykit_sdk::Result<Option<pubky::PublicStorage>> {
        Ok(Some(self.0.outbox_client.public_storage()))
    }
    async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
        unreachable!("test does not sign out")
    }
}

fn sdk(
    access: PubkySessionAccess,
    app_id: &str,
) -> PaykitSdk<PubkySharedStateStorage, Provider, ExplicitInputsPaymentAdapter> {
    let provider = Provider(access);
    PaykitSdk::new(
        PubkySharedStateStorage::new(provider.clone()),
        provider,
        ExplicitInputsPaymentAdapter,
        PaykitSdkConfig::new(app_id).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegated_server_preserves_wallet_registry_and_contacts_across_restart() {
    let postgres = std::env::var("TEST_DATABASE_URL").expect("isolated PostgreSQL required");
    let testnet = EphemeralTestnet::builder()
        .postgres(pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap())
        .build()
        .await
        .unwrap();
    let client = testnet.sdk().unwrap();
    let home = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let root = PubkyLocalSecretKey::new(pubky::Keypair::random().secret_key());
    let wallet_bootstrap =
        PubkySessionBootstrap::with_pubky(client.clone(), "app.bitkit.wallet").unwrap();
    let wallet_auth = wallet_bootstrap
        .sign_up(
            &root,
            &home,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let owner = wallet_auth.public_key.clone();
    let wallet_access = wallet_auth.access;
    let wallet = sdk(wallet_access.clone(), "bitkit");
    wallet.initialize().await.unwrap();
    wallet
        .publish_paykit_noise_key_authorization()
        .await
        .unwrap();
    let wallet_app = PaykitApp::new(
        "Bitkit",
        PaykitAppCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: true,
            outgoing_payments: true,
        },
    )
    .unwrap();
    wallet.publish_paykit_app(wallet_app.clone()).await.unwrap();
    let bitkit = PaykitAppId::new("bitkit").unwrap();
    wallet
        .set_default_paykit_app(Some(bitkit.clone()))
        .await
        .unwrap();
    let contact_a = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    wallet
        .save_contact(ContactUpdate {
            public_key: contact_a.clone(),
            label: Some("Wallet contact".into()),
        })
        .await
        .unwrap();

    let server_bootstrap = PubkySessionBootstrap::with_pubky(client, "app.paykit.server").unwrap();
    let grant = server_bootstrap
        .sign_in(&root, PAYKIT_SESSION_CAPABILITIES)
        .await
        .unwrap();
    let exported = grant.export_session_secret().await.unwrap();
    let mut access = server_bootstrap
        .import_session(exported.as_str(), None, PAYKIT_SESSION_CAPABILITIES)
        .await
        .unwrap()
        .access;
    let delegated = root.derive_paykit_identity_secret_key(1).unwrap();
    let payload = encode_unsigned_payload(7, &[9; 78], &delegated);
    assert_eq!(payload.len(), 124);
    let claim = parse_unsigned_payload(payload.as_slice()).unwrap();
    access.paykit_identity_secret_key = Some(claim.paykit_identity_secret_key);
    assert!(access.local_secret_key.is_none());
    assert!(
        access
            .validate_for_capabilities(paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES)
            .is_err()
    );
    assert_eq!(access.public_key().unwrap(), owner);
    SharedAppPublisher.verify_key(&access).await.unwrap();
    SharedAppPublisher.publish(access.clone()).await.unwrap();
    let server = sdk(access.clone(), "paykit-server");
    server.initialize().await.unwrap();
    assert_eq!(server.contact_records().await.unwrap().len(), 1);
    let contact_b = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    server
        .save_contact(ContactUpdate {
            public_key: contact_b.clone(),
            label: Some("Server contact".into()),
        })
        .await
        .unwrap();
    wallet
        .save_contact(ContactUpdate {
            public_key: contact_a.clone(),
            label: Some("Updated wallet contact".into()),
        })
        .await
        .unwrap();
    assert_eq!(wallet.contact_records().await.unwrap().len(), 2);
    drop(server);
    let restarted = sdk(access.clone(), "paykit-server");
    restarted.initialize().await.unwrap();
    let contacts = restarted.contact_records().await.unwrap();
    assert_eq!(contacts.len(), 2);
    assert_eq!(
        contacts
            .iter()
            .find(|c| c.public_key == contact_a)
            .unwrap()
            .label
            .as_deref(),
        Some("Updated wallet contact")
    );
    assert!(contacts.iter().any(|c| c.public_key == contact_b));
    let registry = restarted
        .paykit_app_registry(owner.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(registry.apps().get(&bitkit), Some(&wallet_app));
    assert!(
        registry
            .apps()
            .contains_key(&PaykitAppId::new("paykit-server").unwrap())
    );
    assert_eq!(registry.default_app_id(), Some(&bitkit));

    let mut wrong = access;
    wrong.paykit_identity_secret_key =
        Some(paykit_sdk::PaykitIdentitySecretKey::new([8; 32], 1).unwrap());
    assert!(SharedAppPublisher.verify_key(&wrong).await.is_err());
    assert!(sdk(wrong, "paykit-server").initialize().await.is_err());
    assert_eq!(wallet.contact_records().await.unwrap().len(), 2);
    assert_eq!(
        wallet.paykit_app_registry(owner).await.unwrap(),
        Some(registry)
    );
}
