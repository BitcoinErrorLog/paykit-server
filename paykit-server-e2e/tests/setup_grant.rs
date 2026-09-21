use std::{net::IpAddr, sync::Arc, time::Duration};

use paykit_lib::PaykitReceiverPath;
use paykit_sdk::{PubkyAuthCompanionClaim, PubkyLocalSecretKey, PubkySessionBootstrap};
use paykit_server::{
    bitkit_claim::{
        CLAIM_TYPE, QUERY_PARAMETER, encode_unsigned_payload, parse_auth_request,
        required_capabilities,
    },
    bitkit_setup::BitkitAuthStarter,
    config::{BitcoinNetwork, StackRole},
    crypto::Crypto,
    persistence::{CreatorStore, run_migrations},
    real_setup::RealSetupCompleter,
    setup::{PollResult, SetupLimits, SetupService, SystemClock},
    setup_orchestration::{CompanionRelay, PubkyCompanionRelay},
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky::Keypair;
use pubky_testnet::EphemeralTestnet;

static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread")]
async fn wrong_rc55_grant_identity_is_409_equivalent_and_leaves_claim_unconsumed() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(
        &std::env::var("TEST_DATABASE_URL").unwrap(),
    )
    .unwrap();
    let testnet = EphemeralTestnet::builder()
        .postgres(postgres)
        .with_http_relay()
        .build()
        .await
        .unwrap();
    let pubky = testnet.sdk().unwrap();
    let relay_inbox = testnet.http_relay().local_url().join("inbox").unwrap();
    let receiver_path = PaykitReceiverPath::new("bitkit/server").unwrap();
    let capabilities = required_capabilities(&receiver_path);
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "paykit-server")
        .unwrap()
        .with_auth_relay(relay_inbox.as_str())
        .unwrap();
    let companion_relay = Arc::new(PubkyCompanionRelay::new(pubky.client().clone()));
    let creators = CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[1; 32]).unwrap()),
    );
    let completer = Arc::new(RealSetupCompleter::new(
        BitkitAuthStarter::new(bootstrap.clone(), &receiver_path),
        companion_relay.clone(),
        creators,
        BitcoinNetwork::Testnet,
        StackRole::Proof,
        receiver_path,
    ));
    let setup = SetupService::new(
        vec!["https://app.example".into()],
        completer,
        Arc::new(SystemClock::default()),
        SetupLimits {
            max_polls_per_flow: 2,
            max_polls: 2,
            setup_per_ip_per_minute: 2,
            max_pending_setup_flows: 2,
            claim_identity_per_second: SetupLimits::generous_claim_for_tests().0,
            claim_identity_burst: SetupLimits::generous_claim_for_tests().1,
            claim_ip_per_second: SetupLimits::generous_claim_for_tests().2,
            claim_ip_burst: SetupLimits::generous_claim_for_tests().3,
            claim_limiter_max_entries: SetupLimits::TEST_MAX_ENTRIES,
            claim_limiter_idle_ttl: SetupLimits::test_idle_ttl(),
            claim_ip_ipv4_prefix: SetupLimits::TEST_IPV4_PREFIX,
            claim_ip_ipv6_prefix: SetupLimits::TEST_IPV6_PREFIX,
        },
    );

    let expected_creator = PubkyLocalSecretKey::new([8; 32]).public_key();
    let flow = setup
        .begin(
            IpAddr::from([127, 0, 0, 1]),
            "https://app.example/callback",
            "mismatch",
            expected_creator.as_str(),
        )
        .await
        .unwrap();
    let request = parse_auth_request(&flow.authorization_url, &capabilities).unwrap();

    let approved_secret = PubkyLocalSecretKey::new(Keypair::random().secret());
    let approved_keypair = Keypair::from_secret(approved_secret.as_bytes());
    pubky
        .signer(approved_keypair)
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    let payload = encode_unsigned_payload(0, &[0; 78]);
    let claim =
        PubkyAuthCompanionClaim::new(QUERY_PARAMETER, CLAIM_TYPE, payload.to_vec()).unwrap();
    bootstrap
        .approve_auth_with_companion_claim(
            &flow.authorization_url,
            &capabilities,
            &approved_secret,
            &claim,
        )
        .await
        .unwrap();

    assert_eq!(
        setup.complete_and_poll(&flow.flow_id).await,
        PollResult::IdentityMismatch
    );
    let persisted_creators: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(persisted_creators, 0);
    assert!(
        companion_relay
            .receive(&request, Duration::from_secs(1))
            .await
            .unwrap()
            .is_some(),
        "identity mismatch must occur before companion-claim consumption"
    );
}
