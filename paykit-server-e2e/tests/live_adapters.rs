use std::{
    env,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use paykit_lib::{
    PaykitReceiverCapabilities, PaykitReceiverPath, PaymentAmount, PaymentEndpointIdentifier,
    PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::{
    InMemoryStorage, LinkedPeerState, PaykitSdk, PaykitSdkConfig, PaymentAdapter, PaymentTarget,
    PubkyLocalSecretKey, PubkyPublicKey, PubkySessionAccess, PubkySessionBootstrap,
    PubkySessionProvider, PublicPaymentEndpointCandidate, PublicPaymentEndpointSelectionRequest,
    PublicReceivingDetail, ReceiverNoiseSecretKey,
};
use paykit_server::{
    bitcoin::{ObservationTarget, TrackedOutput},
    config::BitcoinNetwork,
    workers::observer::{ElectrumAdapter, ElectrumPort},
};
use pubky_testnet::pubky::{Keypair, Pubky, PublicStorage};

const STATIC_HOMESERVER: &str = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";

#[derive(Clone)]
struct LiveSessionProvider {
    access: Arc<Mutex<Option<PubkySessionAccess>>>,
}

impl LiveSessionProvider {
    fn new(access: PubkySessionAccess) -> Self {
        Self {
            access: Arc::new(Mutex::new(Some(access))),
        }
    }
}

#[async_trait]
impl PubkySessionProvider for LiveSessionProvider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        Ok(self.access.lock().unwrap().clone())
    }

    async fn load_public_storage(&self) -> paykit_sdk::Result<Option<PublicStorage>> {
        Ok(self
            .access
            .lock()
            .unwrap()
            .as_ref()
            .map(|access| access.outbox_client.public_storage()))
    }

    async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
        *self.access.lock().unwrap() = None;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct LivePaymentAdapter;

#[async_trait]
impl PaymentAdapter for LivePaymentAdapter {
    async fn current_public_receiving_details(
        &self,
    ) -> paykit_sdk::Result<Vec<PublicReceivingDetail>> {
        Ok(Vec::new())
    }

    async fn select_public_payment_endpoints(
        &self,
        request: &PublicPaymentEndpointSelectionRequest,
    ) -> paykit_sdk::Result<Vec<PublicPaymentEndpointCandidate>> {
        Ok(request.candidates.clone())
    }

    async fn build_public_payment_target(
        &self,
        endpoint: &PublicPaymentEndpointCandidate,
    ) -> paykit_sdk::Result<PaymentTarget> {
        Ok(PaymentTarget {
            payload: endpoint.payload.clone(),
        })
    }
}

type LiveSdk = PaykitSdk<InMemoryStorage, LiveSessionProvider, LivePaymentAdapter>;

async fn live_sdk(
    bootstrap: &PubkySessionBootstrap,
    homeserver: &PubkyPublicKey,
    receiver_path: PaykitReceiverPath,
) -> (PubkyPublicKey, LiveSdk) {
    let account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            ReceiverNoiseSecretKey::random(),
            homeserver,
            None,
            &PaykitSdkConfig::new(receiver_path.clone()).required_session_capabilities(),
        )
        .await
        .unwrap();
    let public_key = account.public_key.clone();
    let sdk = PaykitSdk::new(
        InMemoryStorage::default(),
        LiveSessionProvider::new(account.access),
        LivePaymentAdapter,
        PaykitSdkConfig::new(receiver_path),
    )
    .unwrap();
    sdk.initialize().await.unwrap();
    sdk.publish_paykit_receiver_marker(PaykitReceiverCapabilities {
        private_payments: true,
        payment_requests: true,
        receipts: false,
        outgoing_payments: false,
    })
    .await
    .unwrap();
    (public_key, sdk)
}

async fn establish_link(
    payee: &LiveSdk,
    payee_key: PubkyPublicKey,
    payee_path: PaykitReceiverPath,
    payer: &LiveSdk,
    payer_key: PubkyPublicKey,
    payer_path: PaykitReceiverPath,
) {
    payee
        .initiate_link_with_peer(payer_key.clone(), payer_path.clone())
        .await
        .unwrap();
    payer
        .accept_link_with_peer(payee_key.clone(), payee_path.clone())
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut payee_state = LinkedPeerState::Linking;
    let mut payer_state = LinkedPeerState::Linking;
    while payee_state != LinkedPeerState::Linked || payer_state != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "link timed out");
        if payee_state != LinkedPeerState::Linked {
            payee_state = payee
                .advance_link_handshake(payer_key.clone(), payer_path.clone())
                .await
                .unwrap()
                .state;
        }
        if payer_state != LinkedPeerState::Linked {
            payer_state = payer
                .advance_link_handshake(payee_key.clone(), payee_path.clone())
                .await
                .unwrap()
                .state;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Pubky Core static testnet on localhost"]
async fn live_pubky_marker_discovery_and_payment_request_delivery() {
    let pubky = Pubky::testnet().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky);
    let homeserver = PubkyPublicKey::from_raw_or_app_key(STATIC_HOMESERVER).unwrap();
    let payee_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let payer_path = PaykitReceiverPath::new("bitkit/server").unwrap();
    let (payee_key, payee) = live_sdk(&bootstrap, &homeserver, payee_path.clone()).await;
    let (payer_key, payer) = live_sdk(&bootstrap, &homeserver, payer_path.clone()).await;

    let discovered_paths = payer
        .paykit_receiver_paths(payee_key.clone())
        .await
        .unwrap();
    assert!(discovered_paths.contains(&payee_path));
    let marker = payer
        .paykit_receiver_marker(payee_key.clone(), payee_path.clone())
        .await
        .unwrap()
        .unwrap();
    assert!(marker.capabilities.payment_requests);

    establish_link(
        &payee,
        payee_key.clone(),
        payee_path.clone(),
        &payer,
        payer_key.clone(),
        payer_path.clone(),
    )
    .await;

    let reference = uuid::Uuid::new_v4().to_string();
    let proposal = payee
        .propose_payment_request(
            payer_key.clone(),
            payer_path.clone(),
            PaymentRequestTerms {
                amount: PaymentAmount::new("0.00000100", "BTC").unwrap(),
                payment_reference: PaymentReference::new(reference.clone()).unwrap(),
                proposal_expires_at: None,
                recurrence: None,
                accepted_payment_endpoint_identifiers: vec![
                    PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                ],
                metadata: serde_json::Map::new(),
            },
        )
        .await
        .unwrap();
    let send = payee
        .process_outbound_private_messages(payer_key, payer_path)
        .await
        .unwrap();
    assert_eq!(send.attempted.len(), 1);
    assert_eq!(send.sent.len(), 1);
    assert!(send.failed.is_empty());

    let intake = payer
        .receive_private_messages(payee_key, payee_path)
        .await
        .unwrap();
    assert_eq!(intake.stream_item_ids.len(), 1);
    assert!(intake.event_conflicts.is_empty());
    let received = payer.actionable_received_payment_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].payment_request_id, proposal.payment_request_id);
    assert_eq!(
        received[0].terms.as_ref().unwrap().payment_reference,
        reference
    );

    println!(
        "live Pubky smoke: 1 marker discovered, 1 Payment Request sent, 1 Payment Request received"
    );
}

#[tokio::test]
#[ignore = "requires a public Electrum endpoint and known confirmed output"]
async fn live_electrum_observes_known_output_and_confirmations() {
    let endpoint = env::var("PAYKIT_LIVE_ELECTRUM_ENDPOINT").unwrap();
    let network = match env::var("PAYKIT_LIVE_BITCOIN_NETWORK").unwrap().as_str() {
        "mainnet" => BitcoinNetwork::Mainnet,
        "testnet" => BitcoinNetwork::Testnet,
        "signet" => BitcoinNetwork::Signet,
        other => panic!("unsupported PAYKIT_LIVE_BITCOIN_NETWORK: {other}"),
    };
    let address = env::var("PAYKIT_LIVE_BITCOIN_ADDRESS").unwrap();
    let txid = Txid::from_str(&env::var("PAYKIT_LIVE_BITCOIN_TXID").unwrap()).unwrap();
    let vout = env::var("PAYKIT_LIVE_BITCOIN_VOUT")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    let sats = env::var("PAYKIT_LIVE_BITCOIN_SATS")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let minimum_confirmations = env::var("PAYKIT_LIVE_MIN_CONFIRMATIONS")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    let outpoint = OutPoint::new(txid, vout);
    let adapter = ElectrumAdapter::connect(
        endpoint,
        network,
        Duration::from_secs(15),
        200,
        Duration::from_secs(5),
        paykit_server::workers::electrum::DEFAULT_MAX_RESPONSE_BYTES,
    )
    .await
    .unwrap();
    let tip = adapter.probe().await.unwrap();
    let observations = adapter
        .observations(
            tip.height,
            &[ObservationTarget::new(
                address,
                Some(TrackedOutput::new(outpoint, sats)),
            )],
        )
        .await
        .unwrap()
        .outputs;

    let observation = observations
        .iter()
        .find(|observation| observation.outpoint == outpoint)
        .expect("known output must be present in the address history");
    assert_eq!(observation.sats, sats);
    assert!(observation.present);
    assert!(observation.confirmations >= minimum_confirmations);
    println!(
        "live Electrum smoke: known output observed with {} confirmations in {} address-history outputs",
        observation.confirmations,
        observations.len()
    );
}
