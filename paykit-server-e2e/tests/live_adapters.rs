use std::{
    env,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use paykit_lib::{
    PaykitApp, PaykitAppCapabilities, PaykitAppId, PaymentAmount, PaymentEndpointIdentifier,
    PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::{
    LinkedPeerState, PaykitSdk, PaykitSdkConfig, PaymentAdapter, PaymentTarget,
    PubkyLocalSecretKey, PubkyPublicKey, PubkySessionAccess, PubkySessionBootstrap,
    PubkySessionProvider, PubkySharedStateStorage, PublicPaymentEndpointCandidate,
    PublicPaymentEndpointSelectionRequest, PublicReceivingDetail,
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
    async fn select_private_payment_endpoints(
        &self,
        request: &paykit_sdk::PrivatePaymentEndpointSelectionRequest,
    ) -> paykit_sdk::Result<Vec<paykit_sdk::PrivatePaymentEndpointCandidate>> {
        Ok(request.candidates.clone())
    }

    async fn build_private_payment_target(
        &self,
        endpoint: &paykit_sdk::PrivatePaymentEndpointCandidate,
    ) -> paykit_sdk::Result<PaymentTarget> {
        Ok(PaymentTarget {
            payload: endpoint.payload.clone(),
        })
    }

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

type LiveSdk = PaykitSdk<PubkySharedStateStorage, LiveSessionProvider, LivePaymentAdapter>;

async fn live_sdk(
    bootstrap: &PubkySessionBootstrap,
    homeserver: &PubkyPublicKey,
    app_id: PaykitAppId,
    outgoing_payments: bool,
) -> (PubkyPublicKey, LiveSdk) {
    let account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            homeserver,
            None,
            paykit_sdk::PAYKIT_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let public_key = account.public_key.clone();
    let provider = LiveSessionProvider::new(account.access);
    let sdk = PaykitSdk::new(
        PubkySharedStateStorage::new(provider.clone()),
        provider,
        LivePaymentAdapter,
        PaykitSdkConfig::new(app_id.as_str()).unwrap(),
    );
    sdk.initialize().await.unwrap();
    sdk.publish_paykit_app(
        PaykitApp::new(
            "Test App",
            PaykitAppCapabilities {
                private_payments: true,
                payment_requests: true,
                receipts: false,
                outgoing_payments,
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
    (public_key, sdk)
}

async fn establish_link(
    payee: &LiveSdk,
    payee_key: PubkyPublicKey,
    payer: &LiveSdk,
    payer_key: PubkyPublicKey,
) {
    payee
        .initiate_link_with_peer(payer_key.clone())
        .await
        .unwrap();
    payer
        .accept_link_with_peer(payee_key.clone())
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut payee_state = LinkedPeerState::Linking;
    let mut payer_state = LinkedPeerState::Linking;
    while payee_state != LinkedPeerState::Linked || payer_state != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "link timed out");
        if payee_state != LinkedPeerState::Linked {
            payee_state = payee
                .advance_link_handshake(payer_key.clone())
                .await
                .unwrap()
                .state;
        }
        if payer_state != LinkedPeerState::Linked {
            payer_state = payer
                .advance_link_handshake(payee_key.clone())
                .await
                .unwrap()
                .state;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the Pubky static testnet on localhost"]
async fn live_pubky_registry_discovery_and_payment_request_delivery() {
    let pubky = Pubky::testnet().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky, "app.paykit.server").unwrap();
    let homeserver = PubkyPublicKey::from_raw_or_app_key(STATIC_HOMESERVER).unwrap();
    let payee_path = PaykitAppId::new("paykit-server").unwrap();
    let payer_path = PaykitAppId::new("bitkit").unwrap();
    let (payee_key, payee) = live_sdk(&bootstrap, &homeserver, payee_path.clone(), false).await;
    let (payer_key, payer) = live_sdk(&bootstrap, &homeserver, payer_path.clone(), true).await;

    let registry = payer
        .paykit_app_registry(payee_key.clone())
        .await
        .unwrap()
        .unwrap();
    assert!(
        registry
            .apps()
            .get(&payee_path)
            .unwrap()
            .capabilities()
            .payment_requests
    );

    establish_link(&payee, payee_key.clone(), &payer, payer_key.clone()).await;

    let reference = uuid::Uuid::new_v4().to_string();
    let proposal = payee
        .propose_payment_request(
            payer_key.clone(),
            PaymentRequestTerms::builder(
                PaymentAmount::new("0.00000100", "btc").unwrap(),
                PaymentReference::new(reference.clone()).unwrap(),
                vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
            )
            .required_app_id(Some(payee_path.clone()))
            .payment_endpoints(Some(std::collections::HashMap::from([(
                PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                paykit_lib::PaymentEndpointPayload::new(
                    serde_json::json!({
                        "value": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
                    })
                    .to_string(),
                ),
            )])))
            .build()
            .unwrap(),
        )
        .await
        .unwrap();
    let send = payee
        .process_outbound_private_messages(payer_key)
        .await
        .unwrap();
    assert_eq!(send.attempted.len(), 1);
    assert_eq!(send.sent.len(), 1);
    assert!(send.failed.is_empty());

    let intake = payer
        .receive_private_messages(payee_key.clone())
        .await
        .unwrap();
    assert_eq!(intake.stream_item_ids.len(), 1);
    assert!(intake.event_conflicts.is_empty());
    let received = payer.actionable_received_payment_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].payment_request_id, proposal.payment_request_id);
    let resolution = payer
        .resolve_private_payment_request(
            payee_key,
            &paykit_lib::PaymentRequestId::new(proposal.payment_request_id).unwrap(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        resolution.status,
        paykit_sdk::PrivatePaymentResolutionStatus::Payable
    );
    assert_eq!(resolution.private_payment_list_version, None);
    assert_eq!(resolution.payable_endpoints.len(), 1);
    assert_eq!(
        received[0].terms.as_ref().unwrap().payment_reference,
        reference
    );

    println!(
        "live Pubky smoke: 1 App Registry discovered, 1 Payment Request sent, 1 Payment Request received"
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
    let adapter = ElectrumAdapter::connect(endpoint, network, Duration::from_secs(15), 1)
        .await
        .unwrap();
    let observations = adapter
        .observations(&[ObservationTarget::new(
            address,
            Some(TrackedOutput::new(outpoint, sats)),
        )])
        .await
        .unwrap();

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
