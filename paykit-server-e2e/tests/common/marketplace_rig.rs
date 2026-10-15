//! Shared rig for Marketplace E2E tests: real preparation, lifecycle and status services
//! behind the signed routes over PostgreSQL. Only the BTC/USD feed and the chain are doubles.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use std::str::FromStr;

use async_trait::async_trait;
use axum::{
    Extension, Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{OutPoint, Txid};
use ed25519_dalek::{Signer, SigningKey};
use paykit_sdk::PaykitIdentitySecretKey;
use paykit_server::{
    application::{
        create_invoice::{
            AppRegistryDiscovery, CreateInvoiceError, CreatorReceivingProvider,
            ReaderAuthorization, RegistryDiscoveryError, SessionValidationError, SessionValidator,
        },
        invoice_pricing::ExchangeRates,
        marketplace_lifecycle::MarketplaceLifecycleService,
        marketplace_preparation::PrepareMarketplaceService,
        marketplace_status::MarketplaceStatusService,
    },
    bitcoin::{ObservationTarget, ObservedOutput},
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    http::{
        auth::{SignedServiceAuth, signature_preimage},
        marketplace_lifecycle::marketplace_lifecycle_router,
        marketplace_preparation::marketplace_preparation_router,
        marketplace_status::marketplace_status_router,
    },
    persistence::{CreatorCredentials, CreatorStore, MarketplacePreparationStore, run_migrations},
    workers::observer::{ElectrumPort, ObserverError},
};
use paykit_server_e2e::postgres::TestDatabase;
use tower::ServiceExt;

pub const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
pub const USDT_ADDRESS: &str = super::arbitrum::RECIPIENT;
pub const REFERENCE: &str = "7cceb26d-9042-4ea6-bfcb-01bbd778d76e";
pub const FIXTURES: &str = "marketplace-payment-request-prepare-activate";
pub const STATUS_FIXTURES: &str = "marketplace-payment-request-status";
pub const PREPARE: &str = "/marketplace/payment-requests/prepare";
pub const ACTIVATE: &str = "/marketplace/payment-requests/activate";
pub const STATUS: &str = "/marketplace/payment-requests/status";
pub const VOLATILE: [(&str, &str); 4] = [
    ("invoice_id", "4c6e66c7-8a8b-4d54-b97b-340cedb3e1d0"),
    ("prepare_expires_at", "2026-10-23T09:15:00Z"),
    ("activated_at", "2026-10-23T09:05:00Z"),
    ("payment_deadline", "2026-10-23T09:35:00Z"),
];

pub fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}

/// The buyer is the seller's own Pubky, matching the signed proof fixtures.
pub fn reader() -> ReaderPubky {
    parse_reader(CREATOR).unwrap()
}

pub fn crypto() -> Arc<Crypto> {
    Arc::new(Crypto::from_master_key(&[7; 32]).unwrap())
}

pub fn account_xpub() -> String {
    use bitcoin::{
        Network,
        bip32::{ChildNumber, Xpriv, Xpub},
        secp256k1::Secp256k1,
    };
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Bitcoin, &[42; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account).to_string()
}

pub struct ReadySession;

#[async_trait]
impl SessionValidator for ReadySession {
    async fn validate(&self, _creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        Ok(())
    }
}

pub struct ReadyRegistry;

#[async_trait]
impl AppRegistryDiscovery for ReadyRegistry {
    async fn discover(
        &self,
        _reader: &ReaderPubky,
    ) -> Result<Option<paykit_lib::PaykitAppRegistry>, RegistryDiscoveryError> {
        let mut registry = paykit_lib::PaykitAppRegistry::new(Some(
            paykit_lib::derive_paykit_noise_public_key(&[8; 32]),
        ));
        registry
            .register_app(
                paykit_lib::PaykitAppId::new("bitkit").unwrap(),
                paykit_lib::PaykitApp::new(
                    "Bitkit",
                    paykit_lib::PaykitAppCapabilities {
                        private_payments: false,
                        payment_requests: true,
                        receipts: false,
                        outgoing_payments: true,
                    },
                )
                .unwrap(),
            )
            .unwrap();
        Ok(Some(registry))
    }

    async fn authorization(
        &self,
        _reader: &ReaderPubky,
    ) -> Result<ReaderAuthorization, RegistryDiscoveryError> {
        Ok(ReaderAuthorization::Verified)
    }
}

/// BTC/USD feed double. `failing` makes every read fail, like a stale or down feed.
pub struct Feed {
    pub price: std::sync::Mutex<&'static str>,
    pub failing: AtomicBool,
    pub calls: AtomicUsize,
}

#[async_trait]
impl ExchangeRates for Feed {
    async fn usd_per_btc(&self) -> Result<String, CreateInvoiceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return Err(CreateInvoiceError::Unavailable);
        }
        Ok((*self.price.lock().unwrap()).to_owned())
    }
}

pub struct Rig {
    pub database: TestDatabase,
    pub store: Arc<MarketplacePreparationStore>,
    pub router: Router,
    pub key: SigningKey,
    pub feed: Arc<Feed>,
}

pub fn signed_auth(key: &SigningKey) -> Arc<SignedServiceAuth> {
    let key = pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string();
    let config = Config::from_toml_and_environment(
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
network = "mainnet"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "5s"
# An explicit request budget, so no test result depends on how fast the machine is.
[rate_limits]
signed_requests_per_second = 1000
signed_burst = 5000
"#
        ),
        ConfigEnvironment {
            database_url: Some("postgres://paykit:***@localhost/paykit".into()),
            master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()),
        },
    )
    .unwrap();
    Arc::new(SignedServiceAuth::from_config(&config))
}

#[derive(Clone, Copy)]
pub struct Seller {
    pub bitcoin: bool,
    pub usdt: bool,
}

pub const BOTH_RAILS: Seller = Seller {
    bitcoin: true,
    usdt: true,
};

pub async fn rig(seller: Seller, usdt_enabled: bool) -> Rig {
    rig_with(seller, usdt_enabled, Duration::from_secs(15 * 60), None).await
}

pub async fn rig_with(
    seller: Seller,
    usdt_enabled: bool,
    prepare_ttl: Duration,
    request_deadline: Option<Duration>,
) -> Rig {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let creators = CreatorStore::new(database.pool(), crypto());
    creators
        .create(&CreatorCredentials::new(
            creator(),
            "session-secret".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            seller
                .bitcoin
                .then(|| paykit_server::domain::receiving::BitcoinAccount {
                    xpub: account_xpub().into(),
                    account_index: 0,
                }),
            seller
                .usdt
                .then(|| USDT_ADDRESS.to_owned().try_into().unwrap()),
        ))
        .await
        .unwrap();
    let store = Arc::new(MarketplacePreparationStore::new(database.pool(), crypto()));
    let feed = Arc::new(Feed {
        price: std::sync::Mutex::new("81000"),
        failing: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    let credentials: Arc<dyn CreatorReceivingProvider> = Arc::new(creators);
    let mut preparation = PrepareMarketplaceService::new(
        Arc::new(ReadySession),
        Arc::new(ReadyRegistry),
        credentials,
        store.clone(),
        paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
        BitcoinNetwork::Mainnet,
        Duration::from_secs(24 * 60 * 60),
        prepare_ttl,
    )
    .with_usdt(usdt_enabled)
    .with_conversion_payment_window(Duration::from_secs(60 * 60))
    .with_exchange_rates(feed.clone());
    if let Some(request_deadline) = request_deadline {
        preparation = preparation.with_request_deadline(request_deadline);
    }
    let preparation = Arc::new(preparation);
    let lifecycle = Arc::new(MarketplaceLifecycleService::new(
        store.clone(),
        Duration::from_secs(30 * 60),
    ));
    let status = Arc::new(MarketplaceStatusService::new(store.clone()));
    let key = SigningKey::from_bytes(&[11; 32]);
    let router = marketplace_preparation_router(preparation)
        .merge(marketplace_lifecycle_router(lifecycle))
        .merge(marketplace_status_router(status))
        .layer(Extension(signed_auth(&key)));
    Rig {
        database,
        store,
        router,
        key,
        feed,
    }
}

impl Rig {
    pub async fn post(&self, path: &str, value: serde_json::Value) -> (StatusCode, Vec<u8>) {
        let body = serde_json_canonicalizer::to_vec(&value).unwrap();
        let preimage = signature_preimage("POST", path, &body);
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(
                        "X-Paykit-Signature",
                        URL_SAFE_NO_PAD.encode(self.key.sign(&preimage).to_bytes()),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        (
            status,
            axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
    }

    /// An empty `accepted` omits the optional filter: offer everything the seller enabled.
    pub async fn prepare(
        &self,
        operation: &str,
        amount: &str,
        asset: &str,
        accepted: &[&str],
        window: u64,
    ) -> (StatusCode, Vec<u8>) {
        self.prepare_with_reference(REFERENCE, operation, amount, asset, accepted, window)
            .await
    }

    pub async fn prepare_with_reference(
        &self,
        reference: &str,
        operation: &str,
        amount: &str,
        asset: &str,
        accepted: &[&str],
        window: u64,
    ) -> (StatusCode, Vec<u8>) {
        let mut body = serde_json::json!({
            "creator": CREATOR,
            "reader": reader().to_string(),
            "reference": reference,
            "operation_id": operation,
            "amount": amount,
            "asset": asset,
            "payment_window_seconds": window,
        });
        if !accepted.is_empty() {
            body["accepted_assets"] = serde_json::json!(accepted);
        }
        self.post(PREPARE, body).await
    }

    pub async fn activate(
        &self,
        invoice_id: &str,
        amount: &str,
        asset: &str,
    ) -> (StatusCode, Vec<u8>) {
        self.post(
            ACTIVATE,
            serde_json::json!({
                "creator": CREATOR,
                "invoice_id": invoice_id,
                "amount": amount,
                "asset": asset,
            }),
        )
        .await
    }

    pub async fn status(&self, invoice_id: &str) -> serde_json::Value {
        let (status, body) = self
            .post(
                STATUS,
                serde_json::json!({"creator": CREATOR, "invoice_id": invoice_id}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }

    pub async fn cleanup(self) {
        self.database.cleanup().await;
    }
}

pub fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap()
}

pub fn invoice_id(body: &[u8]) -> String {
    json(body)["invoice_id"].as_str().unwrap().to_owned()
}

pub struct Batch(pub Vec<ObservedOutput>);

#[async_trait]
impl ElectrumPort for Batch {
    async fn observations(
        &self,
        _targets: &[ObservationTarget],
    ) -> Result<Vec<ObservedOutput>, ObserverError> {
        Ok(self.0.clone())
    }
}

pub fn outpoint(byte: u8) -> OutPoint {
    OutPoint::new(
        Txid::from_str(&format!("{byte:02x}{}", "00".repeat(31))).unwrap(),
        u32::from(byte),
    )
}
