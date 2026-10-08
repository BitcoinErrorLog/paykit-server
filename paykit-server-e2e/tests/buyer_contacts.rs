use std::{sync::Arc, time::Duration};

use bitcoin::hashes::{Hash, sha256};
use paykit_sdk::{
    ContactUpdate, PaykitProfile, PubkyLocalSecretKey, PubkyPublicKey, PubkySessionBootstrap,
    PublicationStatus,
};
use paykit_server::{
    config::{PaykitConfig, PaykitNetwork},
    crypto::Crypto,
    domain::{
        locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
        payment::BitcoinOutpoint,
        receiving::BitcoinAccount,
    },
    paykit::{CreatorSessionProvider, PaykitAdapter},
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, PendingBuyerContact, PersistenceError, run_migrations,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::EphemeralTestnet;

mod common;
#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

struct Fixture {
    database: TestDatabase,
    testnet: EphemeralTestnet,
    creator: CreatorPubky,
    invoices: InvoiceStore,
    wallet: sdk_fixtures::HostedSdk,
    adapter: PaykitAdapter,
}

impl Fixture {
    async fn new() -> Self {
        let database = TestDatabase::create().await;
        run_migrations(database.pool()).await.unwrap();
        let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
        let testnet = EphemeralTestnet::builder()
            .postgres(pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap())
            .build()
            .await
            .unwrap();
        let client = testnet.sdk().unwrap();
        let root = PubkyLocalSecretKey::new(pubky::Keypair::random().secret_key());
        let home = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
        let wallet_auth = PubkySessionBootstrap::with_pubky(client.clone(), "app.bitkit.wallet")
            .unwrap()
            .sign_up(
                &root,
                &home,
                None,
                paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
            )
            .await
            .unwrap();
        let creator = parse_creator(&wallet_auth.public_key.to_app_key()).unwrap();
        let wallet = sdk_fixtures::hosted_sdk(wallet_auth.access, "bitkit", 0).await;
        let grant = PubkySessionBootstrap::with_pubky(client.clone(), "app.paykit.server")
            .unwrap()
            .sign_in(&root, paykit_sdk::PAYKIT_SESSION_CAPABILITIES)
            .await
            .unwrap();
        let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
        let creators = CreatorStore::new(database.pool(), crypto.clone());
        let creator_id = creators
            .create(&CreatorCredentials::new(
                creator.clone(),
                grant
                    .export_session_secret()
                    .await
                    .unwrap()
                    .as_str()
                    .to_owned(),
                root.derive_paykit_identity_secret_key(1).unwrap(),
                Some(BitcoinAccount {
                    xpub: "xpub".to_owned().into(),
                    account_index: 0,
                }),
                None,
            ))
            .await
            .unwrap()
            .id();
        let config = PaykitConfig {
            client_id: pubky::ClientId::new("app.paykit.server").unwrap(),
            app_id: paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
            network: PaykitNetwork::Testnet,
            proposal_acceptance_window: Duration::from_secs(3600),
            payment_window: Duration::from_secs(86400),
            conversion_payment_window: Duration::from_secs(3600),
        };
        let adapter = PaykitAdapter::new(
            creator_id,
            CreatorSessionProvider::with_pubky(creators, creator.clone(), client, &config),
            &config,
        )
        .unwrap();
        let invoices = InvoiceStore::new(database.pool(), crypto);
        Self {
            database,
            testnet,
            creator,
            invoices,
            wallet,
            adapter,
        }
    }

    async fn buyer(&self) -> (PubkyPublicKey, pubky::PubkySession, sdk_fixtures::HostedSdk) {
        let bootstrap =
            PubkySessionBootstrap::with_pubky(self.testnet.sdk().unwrap(), "app.bitkit.wallet")
                .unwrap();
        let root = PubkyLocalSecretKey::new(pubky::Keypair::random().secret_key());
        let home = PubkyPublicKey::from_public_key(&self.testnet.homeserver_app().public_key());
        let auth = bootstrap
            .sign_up(&root, &home, None, "/pub/:rw")
            .await
            .unwrap();
        let key = auth.public_key;
        let session = auth.access.session.clone();
        let sdk = sdk_fixtures::hosted_sdk(auth.access, "bitkit", 0).await;
        (key, session, sdk)
    }

    async fn claim(&self, buyer: &PubkyPublicKey) -> PendingBuyerContact {
        let reader = parse_reader(&buyer.to_app_key()).unwrap();
        let binding = uuid::Uuid::new_v4();
        let address = format!("bitcoin-address-{binding}");
        let payloads = Payloads {
            reader: reader.clone(),
            address: address.clone(),
        };
        self.invoices
            .create_atomic(AtomicInvoiceInput {
                creator: &self.creator,
                reader: &reader,
                bundle_binding: binding.as_bytes(),
                lock_resource_binding: b"buyer-contact-lock",
                payment_request_binding: binding.as_bytes(),
                invoice_payloads: &payloads,
                proposal_acceptance_seconds: 3600,
                payment_window_seconds: 86400,
            })
            .await
            .unwrap();
        let outpoint =
            BitcoinOutpoint::new(&sha256::Hash::hash(binding.as_bytes()).to_string(), 0).unwrap();
        self.invoices
            .apply_bitcoin_observation(&address, &outpoint, 100, 0, true)
            .await
            .unwrap();
        self.invoices.claim_buyer_contact().await.unwrap().unwrap()
    }

    async fn save(&self, pending: &PendingBuyerContact) {
        self.adapter
            .save_buyer_contact(&self.invoices, pending)
            .await
            .unwrap();
        assert!(
            !self
                .invoices
                .buyer_contact_is_pending(pending)
                .await
                .unwrap()
        );
    }
}

struct Payloads {
    reader: ReaderPubky,
    address: String,
}
impl InvoicePayloadFactory for Payloads {
    fn for_child_index(&self, _child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        Ok(InvoicePayloads {
            payment_request_intent: common::payment_intent(&self.reader, self.address.clone()),
        })
    }
}

async fn publish_profile(sdk: &sdk_fixtures::HostedSdk) {
    sdk.publish_paykit_profile(
        PaykitProfile {
            display_name: Some("Bitkit Buyer".into()),
            image_uri: None,
            extra: None,
        },
        None,
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn buyer_profiles_become_private_wallet_contacts_without_overwriting_or_unblocking() {
    let fixture = Fixture::new().await;
    let (buyer_key, _, buyer) = fixture.buyer().await;
    let missing = fixture.claim(&buyer_key).await;
    fixture.save(&missing).await;
    assert!(fixture.wallet.contact_records().await.unwrap().is_empty());
    publish_profile(&buyer).await;
    fixture.save(&missing).await;
    assert!(
        fixture.wallet.contact_records().await.unwrap().is_empty(),
        "missing-profile skips are terminal"
    );

    let (preferred_key, preferred_session, preferred) = fixture.buyer().await;
    preferred_session
        .storage()
        .put(
            paykit_sdk::PUBKY_PROFILE_PATH,
            br#"{"name":"Pubky Buyer","image":"https://example.com/avatar.png"}"#.to_vec(),
        )
        .await
        .unwrap();
    publish_profile(&preferred).await;
    fixture.save(&fixture.claim(&preferred_key).await).await;
    let contact = fixture
        .wallet
        .contact_record(&preferred_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(contact.label.as_deref(), Some("Bitkit Buyer"));
    assert_eq!(
        contact.public_contact_marker_status,
        PublicationStatus::NotPublished
    );

    let (fallback_key, fallback_session, _) = fixture.buyer().await;
    fallback_session
        .storage()
        .put(
            paykit_sdk::PUBKY_PROFILE_PATH,
            br#"{"name":"Pubky Buyer","image":"https://example.com/avatar.png"}"#.to_vec(),
        )
        .await
        .unwrap();
    fixture.save(&fixture.claim(&fallback_key).await).await;
    let fallback = fixture
        .wallet
        .contact_record(&fallback_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fallback.label.as_deref(), Some("Pubky Buyer"));
    assert_eq!(
        fallback.profile.unwrap().image_uri.as_deref(),
        Some("https://example.com/avatar.png")
    );

    let (existing_key, _, existing) = fixture.buyer().await;
    publish_profile(&existing).await;
    fixture
        .wallet
        .save_contact(ContactUpdate {
            public_key: existing_key.clone(),
            label: Some("My label".into()),
        })
        .await
        .unwrap();
    let edited = fixture
        .wallet
        .contact_record(&existing_key)
        .await
        .unwrap()
        .unwrap();
    fixture.save(&fixture.claim(&existing_key).await).await;
    assert_eq!(
        fixture.wallet.contact_record(&existing_key).await.unwrap(),
        Some(edited)
    );

    let (blocked_key, _, blocked) = fixture.buyer().await;
    publish_profile(&blocked).await;
    fixture
        .wallet
        .block_peer(blocked_key.clone())
        .await
        .unwrap();
    fixture.save(&fixture.claim(&blocked_key).await).await;
    assert!(
        fixture
            .wallet
            .contact_record(&blocked_key)
            .await
            .unwrap()
            .is_none()
    );
    let owner = PubkyPublicKey::from_raw_or_app_key(fixture.creator.to_string()).unwrap();
    fixture.save(&fixture.claim(&owner).await).await;
    assert!(
        fixture
            .wallet
            .contact_record(&owner)
            .await
            .unwrap()
            .is_none()
    );
    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_buyer_claim_cannot_recreate_a_contact_after_completion_and_removal() {
    let fixture = Fixture::new().await;
    let (buyer_key, _, buyer) = fixture.buyer().await;
    publish_profile(&buyer).await;
    let slow = fixture.claim(&buyer_key).await;
    // Advance only the scheduling deadline, retaining the first worker's claim.
    sqlx::query("UPDATE buyer_contacts SET next_attempt_at = NOW() WHERE invoice_id = $1")
        .bind(slow.invoice_id)
        .execute(fixture.database.pool())
        .await
        .unwrap();
    let replacement = fixture
        .invoices
        .claim_buyer_contact()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(slow.invoice_id, replacement.invoice_id);
    // Hold database completion after the shared contact write. An independent
    // wallet must not be able to delete in the gap before completion is durable.
    let lock_key = i64::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
    let mut completion_lock = fixture.database.pool().begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *completion_lock)
        .await
        .unwrap();
    sqlx::query(&format!(
        "CREATE FUNCTION hold_contact_completion() RETURNS TRIGGER AS $$
         BEGIN
             PERFORM pg_advisory_xact_lock({lock_key});
             RETURN NEW;
         END;
         $$ LANGUAGE plpgsql"
    ))
    .execute(fixture.database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER hold_contact_completion BEFORE UPDATE ON buyer_contacts
         FOR EACH ROW WHEN (NEW.completed_at IS NOT NULL)
         EXECUTE FUNCTION hold_contact_completion()",
    )
    .execute(fixture.database.pool())
    .await
    .unwrap();
    let competing_delete = async {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                     WHERE datname = current_database() AND wait_event = 'advisory'
                         AND query LIKE 'UPDATE buyer_contacts SET completed_at%')",
                )
                .fetch_one(fixture.database.pool())
                .await
                .unwrap();
                if waiting {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("contact save did not reach database completion");
        let deleted = fixture.wallet.remove_contact(&buyer_key).await;
        completion_lock.rollback().await.unwrap();
        assert!(matches!(
            deleted,
            Err(paykit_sdk::PaykitSdkError::SharedStateBusy { .. })
        ));
    };
    tokio::join!(fixture.save(&replacement), competing_delete);
    assert!(
        fixture
            .wallet
            .contact_record(&buyer_key)
            .await
            .unwrap()
            .is_some()
    );
    fixture.wallet.remove_contact(&buyer_key).await.unwrap();
    fixture.save(&slow).await;
    assert!(
        fixture
            .wallet
            .contact_record(&buyer_key)
            .await
            .unwrap()
            .is_none()
    );
    fixture.database.cleanup().await;
}
