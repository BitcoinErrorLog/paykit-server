use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use paykit_sdk::{
    PaymentAdapter, PaymentTarget, PrivatePaymentEndpointCandidate,
    PrivatePaymentEndpointSelectionRequest, PubkySessionAccess, PubkySessionProvider,
    PublicPaymentEndpointCandidate, PublicPaymentEndpointSelectionRequest, PublicReceivingDetail,
};

#[derive(Clone)]
pub struct TestSessionProvider {
    access: Arc<Mutex<Option<PubkySessionAccess>>>,
}

impl TestSessionProvider {
    pub fn new(access: PubkySessionAccess) -> Self {
        Self {
            access: Arc::new(Mutex::new(Some(access))),
        }
    }
}

#[async_trait]
impl PubkySessionProvider for TestSessionProvider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        Ok(self.access.lock().unwrap().clone())
    }

    async fn load_public_storage(
        &self,
    ) -> paykit_sdk::Result<Option<pubky_testnet::pubky::PublicStorage>> {
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

#[derive(Clone, Copy, Default)]
pub struct TestPaymentAdapter;

#[async_trait]
impl PaymentAdapter for TestPaymentAdapter {
    async fn select_private_payment_endpoints(
        &self,
        request: &PrivatePaymentEndpointSelectionRequest,
    ) -> paykit_sdk::Result<Vec<PrivatePaymentEndpointCandidate>> {
        Ok(request.candidates.clone())
    }

    async fn build_private_payment_target(
        &self,
        endpoint: &PrivatePaymentEndpointCandidate,
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

pub type HostedSdk = paykit_sdk::PaykitSdk<
    paykit_sdk::PubkySharedStateStorage,
    TestSessionProvider,
    TestPaymentAdapter,
>;

pub async fn hosted_sdk(access: PubkySessionAccess, app_id: &str, counter_seed: u64) -> HostedSdk {
    let provider = TestSessionProvider::new(access);
    let storage = paykit_sdk::PubkySharedStateStorage::new(provider.clone());
    let sdk = paykit_sdk::PaykitSdk::new(
        storage.clone(),
        provider,
        TestPaymentAdapter,
        paykit_sdk::PaykitSdkConfig::new(app_id).unwrap(),
    );
    sdk.initialize().await.unwrap();
    sdk.publish_paykit_noise_key_authorization().await.unwrap();
    let mut backup = sdk.export_backup_state().await.unwrap();
    backup.next_outbound_private_message_id = counter_seed;
    sdk.restore_backup_state(backup).await.unwrap();
    let app = if app_id == "paykit-server" {
        paykit_server::real_setup::server_app()
    } else {
        paykit_lib::PaykitApp::new(
            "Test App",
            paykit_lib::PaykitAppCapabilities {
                private_payments: true,
                payment_requests: true,
                receipts: true,
                outgoing_payments: true,
            },
        )
        .unwrap()
    };
    sdk.publish_paykit_app(app).await.unwrap();
    sdk
}
