use super::*;
use paykit_server::{
    application::connection_status::{
        ConnectionBinding, ConnectionBindingRepository, ConnectionStatusError,
        ConnectionStatusService, PaykitConnectionState, PeerConnectionStateRepository,
    },
    domain::locks::BundleId,
    paykit::{CreatorSessions, PaykitAdapter},
    persistence::PersistenceError,
    workers::outbox::{Adapter, HandoffError, RetryableHandoffCause},
};
use std::{
    future::{Future, poll_fn},
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
};

struct BoundReader(ReaderPubky);

#[async_trait]
impl ConnectionBindingRepository for BoundReader {
    async fn binding(
        &self,
        _: &CreatorPubky,
        _: &BundleId,
    ) -> Result<Option<ConnectionBinding>, PersistenceError> {
        Ok(Some(ConnectionBinding::new(self.0.clone())))
    }
}

struct CountedPeers {
    sessions: CreatorSessions,
    calls: AtomicUsize,
}

#[async_trait]
impl PeerConnectionStateRepository for CountedPeers {
    async fn connection_state(
        &self,
        creator: &CreatorPubky,
        binding: &ConnectionBinding,
    ) -> Result<PaykitConnectionState, ConnectionStatusError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.sessions.connection_state(creator, binding).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn advisory_polls_share_hosted_reads_without_bypassing_handoff_checks() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    let config = config(
        database.database_url(),
        &SigningKey::from_bytes(&[7; 32]),
        "1h",
    );
    let pool = initialize_database(&config).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server").unwrap();
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let creators = CreatorStore::new(&pool, Arc::new(Crypto::from_master_key(&[1; 32]).unwrap()));
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
    let (reader, peer_key, peer_sdk) = create_peer(&bootstrap, &homeserver).await;
    link(
        &fixture.sdk,
        PubkyPublicKey::from_raw_or_app_key(fixture.creator.to_string()).unwrap(),
        &peer_sdk,
        peer_key.clone(),
    )
    .await;
    let creator_id = creators.ready_ids().await.unwrap()[0];
    let peers = Arc::new(CountedPeers {
        sessions: CreatorSessions::new(creators, pubky, config.paykit.clone()),
        calls: 0.into(),
    });
    let adapter = PaykitAdapter::new(
        creator_id,
        peers.sessions.provider(&fixture.creator),
        &config.paykit,
    )
    .unwrap();
    let service =
        ConnectionStatusService::new(Arc::new(BoundReader(reader.clone())), peers.clone());
    let bundle = parse_bundle_id(BUNDLE_A).unwrap();
    let mut polls: Vec<_> = (0..8)
        .map(|_| Box::pin(service.status(&fixture.creator, &bundle)))
        .collect();
    // Register every poll before allowing the first SDK read to finish.
    for poll in &mut polls {
        poll_fn(|cx| {
            assert!(poll.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    for poll in polls {
        assert_eq!(poll.await.unwrap(), PaykitConnectionState::Connected);
    }
    assert_eq!(peers.calls.load(Ordering::SeqCst), 1);

    adapter
        .ensure_link_with_peer(&reader.to_string())
        .await
        .unwrap();

    fixture.sdk.block_peer(peer_key).await.unwrap();
    assert_eq!(
        adapter.ensure_link_with_peer(&reader.to_string()).await,
        Err(HandoffError::Retryable(RetryableHandoffCause::Policy))
    );
    assert_eq!(peers.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        service.status(&fixture.creator, &bundle).await.unwrap(),
        PaykitConnectionState::Blocked
    );
    assert_eq!(peers.calls.load(Ordering::SeqCst), 2);
    pool.close().await;
    database.cleanup().await;
}
