use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    extract::Extension,
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::hashes::{Hash, sha256};
use ed25519_dalek::{Signer, SigningKey};
use paykit_lib::{
    PaykitAppId, PaykitAppRegistry, PaymentAmount, PaymentEndpointIdentifier,
    PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::PaykitIdentitySecretKey;
use paykit_server::{
    application::{
        create_invoice::{
            AppRegistryDiscovery, CreateInvoiceError, CreatorReceivingProvider,
            ReaderAuthorization, ReceivingDetails, RegistryDiscoveryError, SessionValidationError,
            SessionValidator,
        },
        invoice_pricing::ExchangeRates,
        payment_request_status::{PaymentRequestStatusOperations, PaymentState},
        provider_v2::{
            ProviderV2CreateRequest, ProviderV2Error, ProviderV2Service, provider_v2_request_hash,
        },
        semantic_intent::DeliveryIntentV1,
    },
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext},
    domain::locks::{
        CreatorPubky, ReaderPubky, parse_addressed_lock_resource, parse_bundle_id, parse_creator,
        parse_reader,
    },
    domain::{
        payment::BitcoinOutpoint,
        provider_v2::{ProviderV2Asset, ProviderV2Payment},
        receiving::USDT_ENDPOINT,
    },
    http::{
        auth::{SignedServiceAuth, signature_preimage},
        provider_v2::provider_v2_router,
    },
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, OutboxStore, PaymentDrainStore,
        PaymentRequestLifecycleStore, PersistenceError, ProviderV2AtomicInvoiceInput,
        run_migrations,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use sqlx::Row;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const PROVIDER_V2_BUNDLE: &str = "000G40R40M30E209185GR38E1W";
const LOCK_RESOURCE: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/app.locks/000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG.json";
mod common;

struct TestPayloads;
impl InvoicePayloadFactory for TestPayloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        Ok(InvoicePayloads {
            payment_request_intent: payment_intent(format!("test-address-{child_index}")),
        })
    }
}

struct UsdtPayloads {
    reader: ReaderPubky,
    amount: &'static str,
    reference: String,
}
impl InvoicePayloadFactory for UsdtPayloads {
    fn for_child_index(&self, _child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let endpoint = PaymentEndpointIdentifier::new(USDT_ENDPOINT).unwrap();
        let terms = PaymentRequestTerms::builder(
            PaymentAmount::new(self.amount, "usdt").unwrap(),
            PaymentReference::new(self.reference.clone()).unwrap(),
            vec![endpoint.clone()],
        )
        .required_app_id(Some(common::app_id()))
        .payment_endpoints(Some(std::collections::HashMap::from([(
            endpoint,
            PaymentEndpointPayload::new(
                serde_json::json!({
                    "value": common::arbitrum::RECIPIENT,
                    "chain_id": paykit_server::domain::receiving::USDT_CHAIN_ID,
                    "token": paykit_server::domain::receiving::USDT_TOKEN
                })
                .to_string(),
            ),
        )])))
        .build()
        .unwrap();
        Ok(InvoicePayloads {
            payment_request_intent: DeliveryIntentV1::payment_request(
                self.reader.to_string(),
                common::app_id(),
                &terms,
            )
            .unwrap(),
        })
    }
}

struct GenerationPayloads(i64);
impl InvoicePayloadFactory for GenerationPayloads {
    fn expected_bitcoin_account_generation(&self) -> Option<i64> {
        Some(self.0)
    }

    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        TestPayloads.for_child_index(child_index)
    }
}

struct ReaderPayloads(ReaderPubky);
impl InvoicePayloadFactory for ReaderPayloads {
    fn expected_bitcoin_account_generation(&self) -> Option<i64> {
        Some(0)
    }

    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        Ok(InvoicePayloads {
            payment_request_intent: common::payment_intent(
                &self.0,
                format!("test-address-{child_index}"),
            ),
        })
    }
}

struct EmptyAddressPayloads;
impl InvoicePayloadFactory for EmptyAddressPayloads {
    fn for_child_index(&self, _child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        Ok(InvoicePayloads {
            payment_request_intent: payment_intent(String::new()),
        })
    }
}

struct CreatorPayloads {
    address_prefix: &'static str,
}

impl InvoicePayloadFactory for CreatorPayloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let address = format!("{}-{child_index}", self.address_prefix);
        Ok(InvoicePayloads {
            payment_request_intent: payment_intent(address.clone()),
        })
    }
}

fn payment_intent(address: String) -> DeliveryIntentV1 {
    common::payment_intent(&reader(), address)
}

static TEST_PAYLOADS: GenerationPayloads = GenerationPayloads(0);

fn crypto() -> Arc<Crypto> {
    Arc::new(Crypto::from_master_key(&[7; 32]).unwrap())
}

fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}

fn second_creator() -> CreatorPubky {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(6..7, &replacement.to_string());
        if let Ok(candidate) = parse_creator(&candidate)
            && candidate != creator()
        {
            return candidate;
        }
    }
    panic!("second valid creator fixture")
}

fn reader() -> ReaderPubky {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &replacement.to_string());
        if let Ok(reader) = parse_reader(&candidate) {
            return reader;
        }
    }
    panic!("valid reader fixture")
}

fn second_reader() -> ReaderPubky {
    parse_reader(&second_creator().to_string()).unwrap()
}

fn regtest_account_xpub() -> String {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let master = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &[42; 32]).unwrap();
    let path: bitcoin::bip32::DerivationPath = "m/84'/1'/0'".parse().unwrap();
    let account = master.derive_priv(&secp, &path).unwrap();
    bitcoin::bip32::Xpub::from_priv(&secp, &account).to_string()
}

struct PanicAdapters;

struct ReadyAdapters;

struct FixedRates;

#[async_trait]
impl ExchangeRates for FixedRates {
    async fn usd_per_btc(&self) -> Result<String, CreateInvoiceError> {
        Ok("100000".to_owned())
    }
}

#[async_trait]
impl SessionValidator for ReadyAdapters {
    async fn validate(&self, _creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        Ok(())
    }
}

#[async_trait]
impl AppRegistryDiscovery for ReadyAdapters {
    async fn discover(
        &self,
        _reader: &ReaderPubky,
    ) -> Result<Option<PaykitAppRegistry>, RegistryDiscoveryError> {
        let mut registry =
            PaykitAppRegistry::new(Some(paykit_lib::derive_paykit_noise_public_key(&[8; 32])));
        registry
            .register_app(
                PaykitAppId::new("bitkit").unwrap(),
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

#[async_trait]
impl SessionValidator for PanicAdapters {
    async fn validate(&self, _creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        panic!("status must not validate a session")
    }
}

#[async_trait]
impl AppRegistryDiscovery for PanicAdapters {
    async fn discover(
        &self,
        _reader: &ReaderPubky,
    ) -> Result<Option<PaykitAppRegistry>, RegistryDiscoveryError> {
        panic!("status must not discover a registry")
    }

    async fn authorization(
        &self,
        _reader: &ReaderPubky,
    ) -> Result<ReaderAuthorization, RegistryDiscoveryError> {
        panic!("status must not read reader authorization")
    }
}

#[async_trait]
impl CreatorReceivingProvider for PanicAdapters {
    async fn receiving(
        &self,
        _creator: &CreatorPubky,
    ) -> Result<ReceivingDetails, PersistenceError> {
        panic!("status must not load receiving adapters")
    }
}

fn provider_v2_service_with_panicking_adapters(store: InvoiceStore) -> ProviderV2Service {
    let adapters = Arc::new(PanicAdapters);
    ProviderV2Service::new(
        adapters.clone(),
        adapters.clone(),
        adapters,
        store,
        PaykitAppId::new("paykit-server").unwrap(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(60),
    )
}

async fn invoice_store(database: &TestDatabase) -> InvoiceStore {
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator(),
            "session-secret".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "xpub-secret".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    InvoiceStore::new(database.pool(), crypto)
}

async fn wait_for_lock_wait(database: &TestDatabase, query_fragment: &str) {
    let pattern = format!("%{query_fragment}%");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let blocked: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity
                 WHERE datname = current_database()
                   AND wait_event_type = 'Lock'
                   AND query LIKE $1",
            )
            .bind(&pattern)
            .fetch_one(database.pool())
            .await
            .unwrap();
            if blocked > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("expected query containing {query_fragment:?} to wait on a lock"));
}

fn input<'a>(
    creator: &'a CreatorPubky,
    reader: &'a ReaderPubky,
    bundle: &'a [u8],
    request: &'a [u8],
) -> AtomicInvoiceInput<'a> {
    AtomicInvoiceInput {
        creator,
        reader,
        bundle_binding: bundle,
        lock_resource_binding: request,
        payment_request_binding: request,
        invoice_payloads: &TEST_PAYLOADS,

        proposal_acceptance_seconds: 60 * 60,
        payment_window_seconds: 24 * 60 * 60,
    }
}

fn provider_v2_input<'a>(
    creator: &'a CreatorPubky,
    reader: &'a ReaderPubky,
    bundle: &'a [u8],
    request_hash: [u8; 32],
    deadline: OffsetDateTime,
) -> ProviderV2AtomicInvoiceInput<'a> {
    ProviderV2AtomicInvoiceInput {
        creator,
        reader,
        bundle_binding: bundle,
        lock_resource_binding: bundle,
        request_hash,
        deadline,
        minimum_confirmations: 1,
        invoice_payloads: &TEST_PAYLOADS,
        proposal_acceptance_seconds: 60,
    }
}

fn provider_request(
    reader: ReaderPubky,
    amount: &str,
    deadline: OffsetDateTime,
) -> ProviderV2CreateRequest {
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    ProviderV2CreateRequest {
        bundle_id: parse_bundle_id(PROVIDER_V2_BUNDLE).unwrap(),
        payment: ProviderV2Payment::parse(
            &creator().to_string(),
            amount,
            "BTC",
            1,
            lock_resource.creator(),
        )
        .unwrap(),
        lock_resource,
        reader,
        deadline,
    }
}

fn provider_request_hash(request: &ProviderV2CreateRequest) -> [u8; 32] {
    provider_v2_request_hash(request).unwrap()
}

fn provider_v2_signed_auth(key: &SigningKey) -> Arc<SignedServiceAuth> {
    let trusted_key = pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string();
    let config = Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:8080"
[signed_services]
trusted_public_keys = ["{trusted_key}"]
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "regtest"
[electrum]
endpoint = "tcp://electrum.example:50001"
[outbox]
poll_interval = "5s"
[limits]
request_body_bytes = 16384
[rate_limits]
signed_requests_per_second = 100
signed_burst = 100
"#,
        ),
        ConfigEnvironment {
            database_url: Some("postgres://paykit:***@localhost/paykit".into()),
            master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()),
        },
    )
    .unwrap();
    Arc::new(SignedServiceAuth::from_config(&config))
}

fn signed_provider_v2_request(key: &SigningKey, path: &str, body: &[u8]) -> Request<Body> {
    let preimage = signature_preimage("POST", path, body);
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes()),
        )
        .body(Body::from(body.to_vec()))
        .unwrap()
}

async fn exact_response_body(response: axum::response::Response) -> String {
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(
        to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn signed_provider_v2_routes_emit_exact_create_replay_and_status_vectors() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let deadline = OffsetDateTime::parse("2099-01-01T00:00:00Z", &Rfc3339).unwrap();
    let request = provider_request(reader(), "1", deadline);
    let created = store
        .create_provider_v2_atomic(provider_v2_input(
            &creator(),
            &reader(),
            PROVIDER_V2_BUNDLE.as_bytes(),
            provider_request_hash(&request),
            deadline,
        ))
        .await
        .unwrap();
    let mut fixed_timestamps = database.pool().begin().await.unwrap();
    sqlx::query(
        "UPDATE invoices
         SET invoice_created_at = '2098-12-31T23:58:00Z',
             proposal_expires_at = '2098-12-31T23:59:00Z',
             payment_deadline = '2099-01-01T00:00:00Z'
         WHERE id = $1",
    )
    .bind(created.invoice_id())
    .execute(&mut *fixed_timestamps)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoice_provider_v2
         SET proposal_expires_at = '2098-12-31T23:59:00Z',
             deadline = '2099-01-01T00:00:00Z'
         WHERE invoice_id = $1",
    )
    .bind(created.invoice_id())
    .execute(&mut *fixed_timestamps)
    .await
    .unwrap();
    fixed_timestamps.commit().await.unwrap();

    let key = SigningKey::from_bytes(&[31; 32]);
    let router = provider_v2_router(Arc::new(provider_v2_service_with_panicking_adapters(
        store.clone(),
    )))
    .layer(Extension(provider_v2_signed_auth(&key)));
    let create_body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": PROVIDER_V2_BUNDLE,
        "lock_resource": LOCK_RESOURCE,
        "reader": reader().to_string(),
        "payment": {
            "recipient_pubky": CREATOR,
            "amount": "1",
            "asset": "BTC",
            "minimum_confirmations": 1
        },
        "deadline": "2099-01-01T00:00:00Z"
    }))
    .unwrap();
    let expected_create = r#"{"invoice_created_at":"2098-12-31T23:58:00Z","proposal_expires_at":"2098-12-31T23:59:00Z","deadline":"2099-01-01T00:00:00Z"}"#;
    let first_create = exact_response_body(
        router
            .clone()
            .oneshot(signed_provider_v2_request(
                &key,
                "/v2/invoices",
                &create_body,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(first_create, expected_create);
    let replay = exact_response_body(
        router
            .clone()
            .oneshot(signed_provider_v2_request(
                &key,
                "/v2/invoices",
                &create_body,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(replay, first_create);

    let status_body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "creator": CREATOR,
        "bundle_id": PROVIDER_V2_BUNDLE
    }))
    .unwrap();
    let absent = exact_response_body(
        router
            .clone()
            .oneshot(signed_provider_v2_request(
                &key,
                "/v2/invoices/status",
                &status_body,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        absent,
        format!(
            r#"{{"creator":"{CREATOR}","bundle_id":"{PROVIDER_V2_BUNDLE}","request_state":"proposed","payment_state":"undetected","invoice_created_at":"2098-12-31T23:58:00Z","proposal_expires_at":"2098-12-31T23:59:00Z","deadline":"2099-01-01T00:00:00Z","asset":"BTC","minimum_confirmations":1,"current_sample":null,"first_threshold_satisfied":null}}"#
        )
    );

    let txid = sha256::Hash::hash(b"provider-v2-http-vector").to_string();
    let outpoint = BitcoinOutpoint::new(&txid, 7).unwrap();
    store
        .apply_bitcoin_observation_at(
            "test-address-0",
            &outpoint,
            100,
            1,
            true,
            OffsetDateTime::parse("2098-12-31T23:59:30Z", &Rfc3339).unwrap(),
        )
        .await
        .unwrap();
    let populated = exact_response_body(
        router
            .clone()
            .oneshot(signed_provider_v2_request(
                &key,
                "/v2/invoices/status",
                &status_body,
            ))
            .await
            .unwrap(),
    )
    .await;
    let sample = format!(
        r#"{{"observed_at":"2098-12-31T23:59:30Z","status":"confirmed","outpoint":{{"txid":"{txid}","vout":7}},"confirmations":1,"amount_matched":true}}"#
    );
    assert_eq!(
        populated,
        format!(
            r#"{{"creator":"{CREATOR}","bundle_id":"{PROVIDER_V2_BUNDLE}","request_state":"proposed","payment_state":"confirmed","invoice_created_at":"2098-12-31T23:58:00Z","proposal_expires_at":"2098-12-31T23:59:00Z","deadline":"2099-01-01T00:00:00Z","asset":"BTC","minimum_confirmations":1,"current_sample":{sample},"first_threshold_satisfied":{sample}}}"#
        )
    );

    assert!(
        store
            .observation_targets_at(deadline + time::Duration::seconds(1))
            .await
            .unwrap()
            .is_empty()
    );
    let after_deadline = exact_response_body(
        router
            .oneshot(signed_provider_v2_request(
                &key,
                "/v2/invoices/status",
                &status_body,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(after_deadline, populated);

    database.cleanup().await;
}

#[tokio::test]
async fn signed_provider_v2_usdt_create_replay_and_status_use_production_terms() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    creators
        .create(&CreatorCredentials::new(
            creator(),
            "session-secret".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: regtest_account_xpub().into(),
                account_index: 0,
            }),
            Some(common::arbitrum::RECIPIENT.to_owned().try_into().unwrap()),
        ))
        .await
        .unwrap();
    let store = InvoiceStore::new(database.pool(), crypto.clone());
    let adapters = Arc::new(ReadyAdapters);
    let service = ProviderV2Service::new(
        adapters.clone(),
        adapters,
        Arc::new(creators),
        store,
        PaykitAppId::new("paykit-server").unwrap(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(60),
    )
    .with_usdt(true)
    .with_exchange_rates(Arc::new(FixedRates));
    let key = SigningKey::from_bytes(&[32; 32]);
    let router =
        provider_v2_router(Arc::new(service)).layer(Extension(provider_v2_signed_auth(&key)));
    let deadline: OffsetDateTime = sqlx::query_scalar(
        "SELECT date_trunc('milliseconds', clock_timestamp() + INTERVAL '30 minutes')",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    let deadline = deadline.format(&Rfc3339).unwrap();
    let create_body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": PROVIDER_V2_BUNDLE,
        "lock_resource": LOCK_RESOURCE,
        "reader": reader().to_string(),
        "payment": {
            "recipient_pubky": CREATOR,
            "amount": "5000001",
            "asset": "USDT",
            "minimum_confirmations": 1
        },
        "deadline": deadline
    }))
    .unwrap();

    let created = exact_response_body(
        router
            .clone()
            .oneshot(signed_provider_v2_request(
                &key,
                "/v2/invoices",
                &create_body,
            ))
            .await
            .unwrap(),
    )
    .await;
    let replay = exact_response_body(
        router
            .clone()
            .oneshot(signed_provider_v2_request(
                &key,
                "/v2/invoices",
                &create_body,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(replay, created);

    let mut changed: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
    changed["payment"]["amount"] = serde_json::Value::String("5000002".into());
    let changed_body = serde_json_canonicalizer::to_vec(&changed).unwrap();
    let conflict = router
        .clone()
        .oneshot(signed_provider_v2_request(
            &key,
            "/v2/invoices",
            &changed_body,
        ))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let status_body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "creator": CREATOR,
        "bundle_id": PROVIDER_V2_BUNDLE
    }))
    .unwrap();
    let status: serde_json::Value = serde_json::from_str(
        &exact_response_body(
            router
                .oneshot(signed_provider_v2_request(
                    &key,
                    "/v2/invoices/status",
                    &status_body,
                ))
                .await
                .unwrap(),
        )
        .await,
    )
    .unwrap();
    assert_eq!(status["asset"], "USDT");
    assert_eq!(status["request_state"], "proposed");
    assert_eq!(status["payment_state"], "undetected");
    assert!(status["bitcoin"].is_null());
    assert!(status["usdt_arbitrum"].is_null());

    let outbox = OutboxStore::new(database.pool(), crypto);
    let claims = outbox
        .claim(uuid::Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(claims.len(), 1);
    let intent = outbox.delivery_intent(&claims[0]).unwrap();
    let terms = intent.terms().unwrap();
    assert_eq!(terms.amount, "5.000001");
    assert_eq!(terms.asset, "usdt");
    assert_eq!(
        terms.accepted_endpoint_identifiers,
        vec!["btc-regtest-p2wpkh".to_owned(), USDT_ENDPOINT.to_owned()]
    );
    assert_eq!(terms.rates.len(), 1);
    assert_eq!(terms.rates[0].asset, "btc");
    assert!(!terms.rates[0].value.is_empty());
    let bitcoin_endpoint: serde_json::Value =
        serde_json::from_str(&terms.payment_endpoints["btc-regtest-p2wpkh"]).unwrap();
    assert!(
        bitcoin_endpoint["value"]
            .as_str()
            .unwrap()
            .starts_with("bcrt1")
    );
    let endpoint: serde_json::Value =
        serde_json::from_str(&terms.payment_endpoints[USDT_ENDPOINT]).unwrap();
    assert_eq!(endpoint["value"], common::arbitrum::RECIPIENT);
    assert_eq!(
        endpoint["chain_id"],
        paykit_server::domain::receiving::USDT_CHAIN_ID
    );
    assert_eq!(
        endpoint["token"],
        paykit_server::domain::receiving::USDT_TOKEN
    );

    database.cleanup().await;
}

#[tokio::test]
async fn provider_v2_usdt_create_replay_conflict_and_restart_status_use_canonical_record() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = parse_reader(CREATOR).unwrap();
    let bundle = parse_bundle_id(PROVIDER_V2_BUNDLE).unwrap();
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let deadline: OffsetDateTime = sqlx::query_scalar(
        "SELECT date_trunc('milliseconds', clock_timestamp() + INTERVAL '30 minutes')",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    let request = ProviderV2CreateRequest {
        bundle_id: bundle.clone(),
        payment: ProviderV2Payment::parse(&creator.to_string(), "50000", "USDT", 1, &creator)
            .unwrap(),
        lock_resource,
        reader: reader.clone(),
        deadline,
    };
    let request_hash = provider_request_hash(&request);
    let proof_fixture = common::arbitrum::fixture(0);
    let payloads = UsdtPayloads {
        reader: reader.clone(),
        amount: "0.05",
        reference: proof_fixture["binding"]["paymentReference"]
            .as_str()
            .unwrap()
            .to_owned(),
    };
    let input = || ProviderV2AtomicInvoiceInput {
        creator: &creator,
        reader: &reader,
        bundle_binding: PROVIDER_V2_BUNDLE.as_bytes(),
        lock_resource_binding: PROVIDER_V2_BUNDLE.as_bytes(),
        request_hash,
        deadline,
        minimum_confirmations: 1,
        invoice_payloads: &payloads,
        proposal_acceptance_seconds: 60,
    };

    let created = store.create_provider_v2_atomic(input()).await.unwrap();
    assert!(!created.replayed());
    let replay = store.create_provider_v2_atomic(input()).await.unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.invoice_id(), created.invoice_id());
    let stored_asset: String =
        sqlx::query_scalar("SELECT asset FROM invoice_provider_v2 WHERE invoice_id = $1")
            .bind(created.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(stored_asset, "USDT");

    let changed_asset = store
        .create_provider_v2_atomic(provider_v2_input(
            &creator,
            &reader,
            PROVIDER_V2_BUNDLE.as_bytes(),
            provider_request_hash(&provider_request(reader.clone(), "5000001", deadline)),
            deadline,
        ))
        .await;
    assert_eq!(changed_asset.unwrap_err(), PersistenceError::Conflict);

    let restarted = InvoiceStore::new(database.pool(), crypto());
    let status = restarted
        .provider_v2_status(&creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.asset, ProviderV2Asset::Usdt);
    assert_eq!(status.payment_state, "undetected");
    assert!(status.current_sample.is_none());
    assert!(status.usdt_arbitrum.is_none());

    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             invoice_id, sdk_payment_request_id, request_state, state_event_id,
             last_stream_item_id, last_event_at, proposal_recorded_at
         ) VALUES ($1, $2, 'proof_submitted', $3, 1, clock_timestamp(), clock_timestamp())",
    )
    .bind(created.invoice_id())
    .bind(
        proof_fixture["binding"]["paymentRequestId"]
            .as_str()
            .unwrap(),
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(database.pool())
    .await
    .unwrap();
    let rpc = common::arbitrum::Rpc::start().await;
    rpc.chain.lock().unwrap().finalized = true;
    let creator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    store
        .observe_usdt_request(
            creator_id,
            &creator,
            &common::arbitrum::record(0),
            &rpc.verifier,
            Some(&bundle),
        )
        .await
        .unwrap();
    let paid = restarted
        .provider_v2_status(&creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paid.payment_state, "confirmed");
    let usdt = paid.usdt_arbitrum.unwrap();
    assert!(usdt.amount_matched);
    assert!(usdt.paid_on_time);
    assert!(usdt.finalized);
    assert!(paid.bitcoin.is_none());

    sqlx::query(
        "UPDATE payment_request_lifecycles
         SET request_state = 'rejected', state_event_id = $1,
             last_stream_item_id = last_stream_item_id + 1,
             last_event_at = clock_timestamp()
         WHERE invoice_id = $2",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(created.invoice_id())
    .execute(database.pool())
    .await
    .unwrap();
    let terminal = restarted
        .provider_v2_status(&creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        terminal.request_state,
        paykit_server::domain::payment_request_lifecycle::PaymentRequestLifecycleState::Rejected
    );
    assert_eq!(terminal.payment_state, "confirmed");
    assert!(terminal.usdt_arbitrum.unwrap().finalized);
    assert!(terminal.bitcoin.is_none());

    let buyer_contact_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM buyer_contacts WHERE invoice_id = $1")
            .bind(created.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(buyer_contact_count, 1);

    // A later Bitcoin observation sweep must not expire timely canonical USDT settlement.
    restarted
        .observation_targets_at(deadline + time::Duration::seconds(1))
        .await
        .unwrap();
    let after_deadline = restarted
        .provider_v2_status(&creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_deadline.payment_state, "confirmed");
    assert!(after_deadline.usdt_arbitrum.unwrap().paid_on_time);

    // Exact duplicate proof remains one immutable observation.
    store
        .observe_usdt_request(
            creator_id,
            &creator,
            &common::arbitrum::record(0),
            &rpc.verifier,
            Some(&bundle),
        )
        .await
        .unwrap();
    let observation_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM usdt_observations WHERE invoice_id = $1")
            .bind(created.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(observation_count, 1);

    let drains = PaymentDrainStore::new(database.pool(), crypto());
    let drain = drains.create(&request.lock_resource).await.unwrap();
    assert!(drain.completed());
    assert_eq!(drain.accepted_count(), 0);
    let cleanup_token = crypto().payment_drain_cleanup_token(drain.drain_id());
    drains
        .cleanup_completed(&request.lock_resource, cleanup_token.as_bytes())
        .await
        .unwrap();
    assert!(
        restarted
            .provider_v2_status(&creator, &bundle)
            .await
            .unwrap()
            .is_some()
    );
    database.cleanup().await;
}

#[tokio::test]
async fn provider_v2_create_is_atomic_replayable_and_cross_version_closed() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let deadline: OffsetDateTime =
        sqlx::query_scalar("SELECT clock_timestamp() + INTERVAL '200 milliseconds'")
            .fetch_one(database.pool())
            .await
            .unwrap();

    let exact_request = provider_request(reader.clone(), "1", deadline);
    let exact_hash = provider_request_hash(&exact_request);

    let created = store
        .create_provider_v2_atomic(provider_v2_input(
            &creator,
            &reader,
            PROVIDER_V2_BUNDLE.as_bytes(),
            exact_hash,
            deadline,
        ))
        .await
        .unwrap();
    assert!(!created.replayed());
    let durable_outbox_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM outbox WHERE invoice_id = $1 AND intent_kind = 'payment_request_proposal'",
    )
    .bind(created.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let service = provider_v2_service_with_panicking_adapters(store.clone());
    let before_deadline = service
        .status(&creator, &parse_bundle_id(PROVIDER_V2_BUNDLE).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before_deadline.deadline, deadline);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let replay_after_deadline = service.create(exact_request.clone()).await.unwrap();
    assert!(replay_after_deadline.replayed());
    assert_eq!(replay_after_deadline.invoice_id(), created.invoice_id());
    let replayed_outbox_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM outbox WHERE invoice_id = $1 AND intent_kind = 'payment_request_proposal'",
    )
    .bind(created.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(replayed_outbox_id, durable_outbox_id);
    for changed in [
        provider_request(second_reader(), "1", deadline),
        provider_request(reader.clone(), "2", deadline),
        provider_request(
            reader.clone(),
            "1",
            deadline + time::Duration::milliseconds(1),
        ),
    ] {
        assert_eq!(
            service.create(changed).await,
            Err(ProviderV2Error::Conflict)
        );
    }

    let replayed = store
        .create_provider_v2_atomic(provider_v2_input(
            &creator,
            &reader,
            PROVIDER_V2_BUNDLE.as_bytes(),
            exact_hash,
            deadline,
        ))
        .await
        .unwrap();
    assert!(replayed.replayed());
    assert_eq!(replayed.invoice_id(), created.invoice_id());
    assert_eq!(replayed.invoice_created_at(), created.invoice_created_at());
    assert_eq!(
        replayed.proposal_expires_at(),
        created.proposal_expires_at()
    );
    assert_eq!(replayed.deadline(), created.deadline());

    assert_eq!(
        store
            .create_provider_v2_atomic(provider_v2_input(
                &creator,
                &reader,
                PROVIDER_V2_BUNDLE.as_bytes(),
                [43; 32],
                deadline,
            ))
            .await,
        Err(PersistenceError::Conflict)
    );
    assert_eq!(
        store
            .create_atomic(input(
                &creator,
                &reader,
                PROVIDER_V2_BUNDLE.as_bytes(),
                b"v1-request",
            ))
            .await,
        Err(PersistenceError::Conflict)
    );

    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM invoices WHERE id = $1),
                (SELECT count(*) FROM invoice_provider_v2 WHERE invoice_id = $1),
                (SELECT count(*) FROM outbox WHERE invoice_id = $1 AND intent_kind = 'payment_request_proposal')",
    )
    .bind(created.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(counts, (1, 1, 1));

    let status = service
        .status(&creator, &parse_bundle_id(PROVIDER_V2_BUNDLE).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.request_state.as_str(), "proposed");
    assert_eq!(status.payment_state, "undetected");
    assert_eq!(status.deadline, deadline);
    assert!(status.current_sample.is_none());
    assert!(status.first_threshold_satisfied.is_none());
    assert!(
        service
            .status(
                &second_creator(),
                &parse_bundle_id(PROVIDER_V2_BUNDLE).unwrap(),
            )
            .await
            .unwrap()
            .is_none()
    );

    database.cleanup().await;
}

#[tokio::test]
async fn provider_v2_concurrent_exact_creates_converge_on_one_invoice_and_outbox() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let deadline: OffsetDateTime =
        sqlx::query_scalar("SELECT clock_timestamp() + INTERVAL '1 hour'")
            .fetch_one(database.pool())
            .await
            .unwrap();

    let first = store.create_provider_v2_atomic(provider_v2_input(
        &creator,
        &reader,
        b"provider-v2-concurrent",
        [45; 32],
        deadline,
    ));
    let second = store.create_provider_v2_atomic(provider_v2_input(
        &creator,
        &reader,
        b"provider-v2-concurrent",
        [45; 32],
        deadline,
    ));
    let (first, second) = tokio::join!(first, second);
    let first = first.unwrap();
    let second = second.unwrap();

    assert_eq!(first.invoice_id(), second.invoice_id());
    assert_ne!(first.replayed(), second.replayed());
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM invoices),
                (SELECT count(*) FROM outbox WHERE intent_kind = 'payment_request_proposal')",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(counts, (1, 1));

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_provider_v2_create_commits_before_drain_and_is_frozen_in_snapshot() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let crypto = crypto();
    let creator = creator();
    let reader = reader();
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let advisory_key = 8_702_502_i64;

    sqlx::raw_sql(
        r#"
        CREATE FUNCTION delay_provider_v2_binding_and_seed_accepted_lifecycle()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(8702502);
            INSERT INTO payment_request_lifecycles (
                invoice_id, sdk_payment_request_id, request_state, state_event_id,
                last_stream_item_id, last_outbound_message_id, last_event_at
            ) VALUES (NEW.invoice_id, '00000000-0000-4000-8000-000000000046',
                      'accepted', 'provider-v2-race-accepted', 1, 1, clock_timestamp());
            RETURN NEW;
        END
        $$;
        CREATE TRIGGER delay_provider_v2_binding
        BEFORE INSERT ON invoice_provider_v2
        FOR EACH ROW EXECUTE FUNCTION delay_provider_v2_binding_and_seed_accepted_lifecycle();
        "#,
    )
    .execute(database.pool())
    .await
    .unwrap();

    let mut blocker = database.acquire_connection().await;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(advisory_key)
        .execute(&mut *blocker)
        .await
        .unwrap();

    let create_store = store.clone();
    let create_creator = creator.clone();
    let create_reader = reader.clone();
    let create = tokio::spawn(async move {
        create_store
            .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
                creator: &create_creator,
                reader: &create_reader,
                bundle_binding: b"provider-v2-delayed-before-drain",
                lock_resource_binding: LOCK_RESOURCE.as_bytes(),
                request_hash: [47; 32],
                deadline: OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
                    + time::Duration::hours(1),
                minimum_confirmations: 1,
                invoice_payloads: &TEST_PAYLOADS,
                proposal_acceptance_seconds: 60,
            })
            .await
    });
    wait_for_lock_wait(&database, "INSERT INTO invoice_provider_v2").await;

    let second_pool = sqlx::PgPool::connect(database.database_url())
        .await
        .unwrap();
    let drain_store = PaymentDrainStore::new(&second_pool, crypto.clone());
    let drain_lock = lock_resource.clone();
    let drain = tokio::spawn(async move { drain_store.create(&drain_lock).await });
    wait_for_lock_wait(&database, "FROM creators").await;

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(advisory_key)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let created = create.await.unwrap().unwrap();
    let frozen = drain.await.unwrap().unwrap();

    assert_eq!(frozen.accepted_count(), 1);
    let frozen_invoice: uuid::Uuid =
        sqlx::query_scalar("SELECT invoice_id FROM payment_drain_items WHERE drain_id = $1")
            .bind(frozen.drain_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(frozen_invoice, created.invoice_id());

    let restarted_invoices = InvoiceStore::new(database.pool(), crypto.clone());
    let replayed_create = restarted_invoices
        .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"provider-v2-delayed-before-drain",
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            request_hash: [47; 32],
            deadline: created.deadline(),
            minimum_confirmations: 1,
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60,
        })
        .await
        .unwrap();
    assert!(replayed_create.replayed());
    assert_eq!(replayed_create.invoice_id(), created.invoice_id());

    let replayed_drain = PaymentDrainStore::new(database.pool(), crypto)
        .create(&lock_resource)
        .await
        .unwrap();
    assert!(replayed_drain.replayed());
    assert_eq!(replayed_drain.drain_id(), frozen.drain_id());
    assert_eq!(replayed_drain.accepted_count(), 1);
    second_pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborted_provider_v2_create_rolls_back_before_drain_snapshot_acknowledgement() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let crypto = crypto();
    let creator = creator();
    let reader = reader();
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let advisory_key = 8_702_503_i64;

    sqlx::raw_sql(
        r#"
        CREATE FUNCTION delay_aborted_provider_v2_binding()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(8702503);
            RETURN NEW;
        END
        $$;
        CREATE TRIGGER delay_aborted_provider_v2_binding
        BEFORE INSERT ON invoice_provider_v2
        FOR EACH ROW EXECUTE FUNCTION delay_aborted_provider_v2_binding();
        "#,
    )
    .execute(database.pool())
    .await
    .unwrap();
    let mut blocker = database.acquire_connection().await;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(advisory_key)
        .execute(&mut *blocker)
        .await
        .unwrap();

    let create_creator = creator.clone();
    let create_reader = reader.clone();
    let create = tokio::spawn(async move {
        store
            .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
                creator: &create_creator,
                reader: &create_reader,
                bundle_binding: b"provider-v2-aborted-before-commit",
                lock_resource_binding: LOCK_RESOURCE.as_bytes(),
                request_hash: [51; 32],
                deadline: OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
                    + time::Duration::hours(1),
                minimum_confirmations: 1,
                invoice_payloads: &TEST_PAYLOADS,
                proposal_acceptance_seconds: 60,
            })
            .await
    });
    wait_for_lock_wait(&database, "INSERT INTO invoice_provider_v2").await;
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(advisory_key)
        .execute(&mut *blocker)
        .await
        .unwrap();

    let drain = tokio::time::timeout(
        Duration::from_secs(5),
        PaymentDrainStore::new(database.pool(), crypto.clone()).create(&lock_resource),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(drain.completed());
    assert_eq!(drain.accepted_count(), 0);
    let invoice_count: i64 = sqlx::query_scalar("SELECT count(*) FROM invoices")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(invoice_count, 0);

    let rejected = InvoiceStore::new(database.pool(), crypto)
        .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"provider-v2-aborted-before-commit",
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            request_hash: [51; 32],
            deadline: OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
                + time::Duration::hours(1),
            minimum_confirmations: 1,
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60,
        })
        .await;
    assert_eq!(rejected, Err(PersistenceError::Conflict));
    database.cleanup().await;
}

#[tokio::test]
async fn aborted_drain_commit_rolls_back_fence_and_snapshot_before_restart_retry() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let crypto = crypto();
    let creator = creator();
    let reader = reader();
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let created = store
        .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"provider-v2-before-aborted-drain",
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            request_hash: [52; 32],
            deadline: OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
                + time::Duration::hours(1),
            minimum_confirmations: 1,
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60,
        })
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             invoice_id, sdk_payment_request_id, request_state, state_event_id,
             last_stream_item_id, last_outbound_message_id, last_event_at
         ) VALUES ($1, '00000000-0000-4000-8000-000000000052', 'accepted',
                   'provider-v2-aborted-drain-accepted', 1, 1, clock_timestamp())",
    )
    .bind(created.invoice_id())
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::raw_sql(
        r#"
        CREATE FUNCTION abort_drain_after_snapshot_item()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'deterministic drain pre-commit crash';
        END
        $$;
        CREATE TRIGGER abort_drain_after_snapshot_item
        AFTER INSERT ON payment_drain_items
        FOR EACH ROW EXECUTE FUNCTION abort_drain_after_snapshot_item();
        "#,
    )
    .execute(database.pool())
    .await
    .unwrap();

    assert_eq!(
        PaymentDrainStore::new(database.pool(), crypto.clone())
            .create(&lock_resource)
            .await,
        Err(PersistenceError::Unavailable)
    );
    let rollback_state: (i64, i64, bool, Option<uuid::Uuid>) = sqlx::query_as(
        "SELECT
             (SELECT COUNT(*) FROM payment_drains),
             (SELECT COUNT(*) FROM payment_drain_items),
             generation.provider_v2_drain_fenced,
             generation.active_drain_id
         FROM lock_payment_generations generation",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(rollback_state, (0, 0, false, None));

    sqlx::raw_sql(
        "DROP TRIGGER abort_drain_after_snapshot_item ON payment_drain_items;
         DROP FUNCTION abort_drain_after_snapshot_item();",
    )
    .execute(database.pool())
    .await
    .unwrap();
    let restarted_pool = sqlx::PgPool::connect(database.database_url())
        .await
        .unwrap();
    let restarted_drains = PaymentDrainStore::new(&restarted_pool, crypto.clone());
    let frozen = restarted_drains.create(&lock_resource).await.unwrap();
    assert_eq!(frozen.accepted_count(), 1);
    let frozen_invoice: uuid::Uuid =
        sqlx::query_scalar("SELECT invoice_id FROM payment_drain_items WHERE drain_id = $1")
            .bind(frozen.drain_id())
            .fetch_one(&restarted_pool)
            .await
            .unwrap();
    assert_eq!(frozen_invoice, created.invoice_id());
    let replay = restarted_drains.create(&lock_resource).await.unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.drain_id(), frozen.drain_id());

    let rejected = InvoiceStore::new(&restarted_pool, crypto)
        .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"provider-v2-after-retried-drain",
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            request_hash: [53; 32],
            deadline: OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
                + time::Duration::hours(1),
            minimum_confirmations: 1,
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60,
        })
        .await;
    assert_eq!(rejected, Err(PersistenceError::Conflict));
    restarted_pool.close().await;
    database.cleanup().await;
}

#[tokio::test]
async fn drain_first_blocks_new_provider_v2_create_across_store_instances() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let crypto = crypto();
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let second_pool = sqlx::PgPool::connect(database.database_url())
        .await
        .unwrap();
    let drain = PaymentDrainStore::new(&second_pool, crypto.clone())
        .create(&lock_resource)
        .await
        .unwrap();
    assert!(drain.completed());

    let restarted_store = InvoiceStore::new(database.pool(), crypto);
    let creator = creator();
    let reader = reader();
    let result = restarted_store
        .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: PROVIDER_V2_BUNDLE.as_bytes(),
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            request_hash: [48; 32],
            deadline: OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
                + time::Duration::hours(1),
            minimum_confirmations: 1,
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60,
        })
        .await;

    assert_eq!(result, Err(PersistenceError::Conflict));
    assert!(
        store
            .provider_v2_status(&creator, &parse_bundle_id(PROVIDER_V2_BUNDLE).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    second_pool.close().await;
    database.cleanup().await;
}

#[tokio::test]
async fn completed_drain_cleanup_keeps_provider_v2_creation_fenced() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let crypto = crypto();
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let drains = PaymentDrainStore::new(database.pool(), crypto.clone());

    let drain = drains.create(&lock_resource).await.unwrap();
    assert!(drain.completed());
    let cleanup_token = crypto.payment_drain_cleanup_token(drain.drain_id());
    drains
        .cleanup_completed(&lock_resource, cleanup_token.as_bytes())
        .await
        .unwrap();

    let creator = creator();
    let reader = reader();
    let result = store
        .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"provider-v2-after-cleanup",
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            request_hash: [46; 32],
            deadline: OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
                + time::Duration::hours(1),
            minimum_confirmations: 1,
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60,
        })
        .await;

    assert_eq!(result, Err(PersistenceError::Conflict));
    database.cleanup().await;
}

#[tokio::test]
async fn cleanup_preserves_included_provider_v2_replay_but_rejects_new_create() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let crypto = crypto();
    let creator = creator();
    let reader = reader();
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let deadline =
        OffsetDateTime::now_utc().replace_nanosecond(0).unwrap() + time::Duration::hours(1);
    let request = provider_request(reader.clone(), "1", deadline);
    let request_hash = provider_request_hash(&request);
    let created = store
        .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: PROVIDER_V2_BUNDLE.as_bytes(),
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            request_hash,
            deadline,
            minimum_confirmations: 1,
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60,
        })
        .await
        .unwrap();
    sqlx::query(
        "UPDATE outbox
         SET status = 'delivered', sdk_outbound_message_id = '1',
             sdk_event_id = 'provider-v2-cleanup-proposed',
             sdk_payment_request_id = '00000000-0000-4000-8000-000000000049'
         WHERE invoice_id = $1 AND intent_kind = 'payment_request_proposal'",
    )
    .bind(created.invoice_id())
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             invoice_id, sdk_payment_request_id, request_state, state_event_id,
             last_stream_item_id, last_outbound_message_id, last_event_at
         ) VALUES ($1, '00000000-0000-4000-8000-000000000049', 'proposed',
                   'provider-v2-cleanup-proposed', 1, 1, clock_timestamp())",
    )
    .bind(created.invoice_id())
    .execute(database.pool())
    .await
    .unwrap();

    let drains = PaymentDrainStore::new(database.pool(), crypto.clone());
    let drain = drains.create(&lock_resource).await.unwrap();
    assert!(drain.completed());
    assert_eq!(drain.cancellation_enqueued_count(), 1);
    let cleanup_token = crypto.payment_drain_cleanup_token(drain.drain_id());
    drains
        .cleanup_completed(&lock_resource, cleanup_token.as_bytes())
        .await
        .unwrap();

    let key = SigningKey::from_bytes(&[32; 32]);
    let router = provider_v2_router(Arc::new(provider_v2_service_with_panicking_adapters(
        store.clone(),
    )))
    .layer(Extension(provider_v2_signed_auth(&key)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let create_body = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": PROVIDER_V2_BUNDLE,
        "lock_resource": LOCK_RESOURCE,
        "reader": reader.to_string(),
        "payment": {
            "recipient_pubky": CREATOR,
            "amount": "1",
            "asset": "BTC",
            "minimum_confirmations": 1
        },
        "deadline": deadline.format(&Rfc3339).unwrap()
    }))
    .unwrap();
    let signature = URL_SAFE_NO_PAD.encode(
        key.sign(&signature_preimage("POST", "/v2/invoices", &create_body))
            .to_bytes(),
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let head = format!(
        "POST /v2/invoices HTTP/1.1\r\nHost: {address}\r\nX-Paykit-Signature: {signature}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        create_body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&create_body).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    shutdown_tx.send(()).unwrap();
    running.await.unwrap().unwrap();

    let replayed = InvoiceStore::new(database.pool(), crypto.clone())
        .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: PROVIDER_V2_BUNDLE.as_bytes(),
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            request_hash,
            deadline,
            minimum_confirmations: 1,
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60,
        })
        .await
        .unwrap();
    assert!(replayed.replayed());
    assert_eq!(replayed.invoice_id(), created.invoice_id());

    let new_result = InvoiceStore::new(database.pool(), crypto)
        .create_provider_v2_atomic(ProviderV2AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"provider-v2-new-after-cleanup",
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            request_hash: [50; 32],
            deadline,
            minimum_confirmations: 1,
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60,
        })
        .await;
    assert_eq!(new_result, Err(PersistenceError::Conflict));
    database.cleanup().await;
}

#[tokio::test]
async fn provider_v2_deadline_gate_resamples_after_creator_row_lock_wait() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let mut blocker = database.pool().begin().await.unwrap();
    sqlx::query("SELECT id FROM creators FOR UPDATE")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let deadline: OffsetDateTime =
        sqlx::query_scalar("SELECT clock_timestamp() + INTERVAL '200 milliseconds'")
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
    let task =
        tokio::spawn(async move { store.provider_v2_deadline_gate(&creator, deadline).await });
    wait_for_lock_wait(&database, "SELECT id FROM creators").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    blocker.commit().await.unwrap();
    assert!(!task.await.unwrap().unwrap());
    database.cleanup().await;
}

#[tokio::test]
async fn provider_v2_fresh_create_uses_database_deadline_fence() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let elapsed: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(database.pool())
        .await
        .unwrap();

    assert!(
        !store
            .provider_v2_deadline_gate(&creator, elapsed)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .create_provider_v2_atomic(provider_v2_input(
                &creator,
                &reader,
                b"elapsed-provider-v2",
                [44; 32],
                elapsed,
            ))
            .await,
        Err(PersistenceError::DeadlineElapsed)
    );
    let invoice_count: i64 = sqlx::query_scalar("SELECT count(*) FROM invoices")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(invoice_count, 0);

    database.cleanup().await;
}

#[tokio::test]
async fn creator_generation_fences_stale_bitcoin_invoice_issuance() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    sqlx::query("UPDATE creators SET bitcoin_account_generation = 1")
        .execute(database.pool())
        .await
        .unwrap();
    let creator = creator();
    let reader = reader();
    let stale = GenerationPayloads(0);
    let current = GenerationPayloads(1);
    let make_input = |bundle: &'static [u8], payloads| AtomicInvoiceInput {
        creator: &creator,
        reader: &reader,
        bundle_binding: bundle,
        lock_resource_binding: bundle,
        payment_request_binding: bundle,
        invoice_payloads: payloads,
        proposal_acceptance_seconds: 60 * 60,
        payment_window_seconds: 24 * 60 * 60,
    };
    assert_eq!(
        store
            .create_atomic(make_input(b"stale-generation", &stale))
            .await,
        Err(PersistenceError::Conflict)
    );
    let created = store
        .create_atomic(make_input(b"current-generation", &current))
        .await
        .unwrap();
    let generation: Option<i64> =
        sqlx::query_scalar("SELECT bitcoin_account_generation FROM invoices WHERE id = $1")
            .bind(created.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(generation, Some(1));
    database.cleanup().await;
}

#[tokio::test]
async fn rotation_cancels_proposed_preserves_accepted_and_exact_replays_old_bundle() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let proposed = store
        .create_atomic(input(
            &creator,
            &reader,
            b"rotation-proposed-bundle",
            b"rotation-proposed-request",
        ))
        .await
        .unwrap();
    let accepted_reader = second_reader();
    let accepted_payloads = ReaderPayloads(accepted_reader.clone());
    let accepted = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &accepted_reader,
            bundle_binding: b"rotation-accepted-bundle",
            lock_resource_binding: b"rotation-accepted-request",
            payment_request_binding: b"rotation-accepted-request",
            invoice_payloads: &accepted_payloads,
            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap();
    let proposed_request_id = uuid::Uuid::new_v4().to_string();
    let accepted_request_id = uuid::Uuid::new_v4().to_string();
    let accepted_owner_proposed_sibling_id = uuid::Uuid::new_v4().to_string();
    for (invoice_id, request_id, state, cursor) in [
        (
            proposed.invoice_id(),
            proposed_request_id.as_str(),
            "proposed",
            1_i64,
        ),
        (
            accepted.invoice_id(),
            accepted_request_id.as_str(),
            "accepted",
            2_i64,
        ),
        (
            accepted.invoice_id(),
            accepted_owner_proposed_sibling_id.as_str(),
            "proposed",
            3_i64,
        ),
    ] {
        sqlx::query(
            "INSERT INTO payment_request_lifecycles
             (invoice_id, sdk_payment_request_id, request_state, last_event_at,
              last_stream_item_id)
             VALUES ($1, $2, $3, NOW(), $4)",
        )
        .bind(invoice_id)
        .bind(request_id)
        .bind(state)
        .bind(cursor)
        .execute(database.pool())
        .await
        .unwrap();
    }
    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto());
    let evidence = lifecycles
        .required_receive_targets_for_creator_rotation(&creator)
        .await
        .unwrap();
    assert_eq!(
        evidence.len(),
        2,
        "a proposed sibling still requires receive before its accepted owner is classified"
    );
    let creators = CreatorStore::new(database.pool(), crypto());
    let current = creators.load(&creator).await.unwrap();
    let replacement = CreatorCredentials::new(
        creator.clone(),
        "rotated-session".into(),
        current.paykit_identity_secret().clone(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: "replacement-xpub".to_owned().into(),
            account_index: 7,
        }),
        None,
    );
    let rotation = creators
        .rotate_bitcoin_account_after_receive(&lifecycles, &replacement, &evidence)
        .await
        .unwrap();
    assert_eq!(rotation.cancellation_pending_count, 2);
    let classifications: Vec<String> = sqlx::query_scalar(
        "SELECT classification FROM creator_bitcoin_account_rotation_items
         ORDER BY classification",
    )
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        classifications,
        vec!["accepted", "cancellation_pending", "cancellation_pending"]
    );
    let mut cancellation_targets: Vec<String> = sqlx::query_scalar(
        "SELECT cancellation_target_payment_request_id FROM outbox
         WHERE intent_kind = 'payment_request_cancellation'",
    )
    .fetch_all(database.pool())
    .await
    .unwrap();
    cancellation_targets.sort();
    let mut expected_targets = vec![proposed_request_id, accepted_owner_proposed_sibling_id];
    expected_targets.sort();
    assert_eq!(cancellation_targets, expected_targets);
    let replay = store
        .create_atomic(input(
            &creator,
            &reader,
            b"rotation-proposed-bundle",
            b"rotation-proposed-request",
        ))
        .await
        .unwrap();
    assert_eq!(replay.invoice_id(), proposed.invoice_id());
    assert!(replay.replayed());
    database.cleanup().await;
}

#[tokio::test]
async fn drain_reuses_authenticated_rotation_cancellation() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let canonical_lock = lock_resource.to_string();
    let created = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"rotation-then-drain-bundle",
            lock_resource_binding: canonical_lock.as_bytes(),
            payment_request_binding: b"rotation-then-drain-request",
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap();
    let request_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO payment_request_lifecycles
         (invoice_id, sdk_payment_request_id, request_state, last_event_at,
          last_stream_item_id)
         VALUES ($1, $2, 'proposed', NOW(), 1)",
    )
    .bind(created.invoice_id())
    .bind(&request_id)
    .execute(database.pool())
    .await
    .unwrap();

    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto());
    let evidence = lifecycles
        .required_receive_targets_for_creator_rotation(&creator)
        .await
        .unwrap();
    let creators = CreatorStore::new(database.pool(), crypto());
    let current = creators.load(&creator).await.unwrap();
    let replacement = CreatorCredentials::new(
        creator,
        "rotated-session".into(),
        current.paykit_identity_secret().clone(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: "replacement-xpub".to_owned().into(),
            account_index: 7,
        }),
        None,
    );
    let rotation = creators
        .rotate_bitcoin_account_after_receive(&lifecycles, &replacement, &evidence)
        .await
        .unwrap();
    assert_eq!(rotation.cancellation_pending_count, 1);
    let rotation_cancellation_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT cancellation_outbox_id
         FROM creator_bitcoin_account_rotation_items
         WHERE classification = 'cancellation_pending'",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    let rotation_only_drain_required: bool =
        sqlx::query_scalar("SELECT cancellation_drain_required FROM outbox WHERE id = $1")
            .bind(rotation_cancellation_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(!rotation_only_drain_required);

    let drain = PaymentDrainStore::new(database.pool(), crypto())
        .create(&lock_resource)
        .await
        .unwrap();
    assert!(drain.completed());
    assert_eq!(drain.cancellation_enqueued_count(), 1);
    let drain_cancellation_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT cancellation_outbox_id FROM payment_drain_cancellations
         WHERE drain_id = $1 AND sdk_payment_request_id = $2",
    )
    .bind(drain.drain_id())
    .bind(&request_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(drain_cancellation_id, rotation_cancellation_id);
    let reused_drain_required: bool =
        sqlx::query_scalar("SELECT cancellation_drain_required FROM outbox WHERE id = $1")
            .bind(rotation_cancellation_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(reused_drain_required);
    let cancellation_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox
         WHERE intent_kind = 'payment_request_cancellation'",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(cancellation_count, 1);
    database.cleanup().await;
}

#[tokio::test]
async fn obsolete_transition_rechecks_concurrent_drain_promotion_under_row_lock() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let created = store
        .create_atomic(input(
            &creator,
            &reader,
            b"obsolete-drain-race-bundle",
            b"obsolete-drain-race-request",
        ))
        .await
        .unwrap();
    let request_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO payment_request_lifecycles
         (invoice_id, sdk_payment_request_id, request_state, last_event_at,
          last_stream_item_id)
         VALUES ($1, $2, 'proposed', NOW(), 1)",
    )
    .bind(created.invoice_id())
    .bind(&request_id)
    .execute(database.pool())
    .await
    .unwrap();

    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto());
    let evidence = lifecycles
        .required_receive_targets_for_creator_rotation(&creator)
        .await
        .unwrap();
    let creators = CreatorStore::new(database.pool(), crypto());
    let current = creators.load(&creator).await.unwrap();
    let replacement = CreatorCredentials::new(
        creator,
        "rotated-session".into(),
        current.paykit_identity_secret().clone(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: "replacement-xpub".to_owned().into(),
            account_index: 7,
        }),
        None,
    );
    creators
        .rotate_bitcoin_account_after_receive(&lifecycles, &replacement, &evidence)
        .await
        .unwrap();
    let cancellation_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT cancellation_outbox_id
         FROM creator_bitcoin_account_rotation_items
         WHERE classification = 'cancellation_pending'",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE payment_request_lifecycles
         SET request_state = 'accepted', state_event_id = $1,
             last_stream_item_id = last_stream_item_id + 1,
             last_event_at = last_event_at + INTERVAL '1 second'
         WHERE invoice_id = $2",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(created.invoice_id())
    .execute(database.pool())
    .await
    .unwrap();

    let outbox = OutboxStore::new(database.pool(), crypto());
    let claim = outbox
        .claim(uuid::Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.id() == cancellation_id)
        .expect("rotation cancellation is claimable");
    assert!(
        outbox
            .rotation_cancellation_target_is_accepted(&claim)
            .await
            .unwrap(),
        "rotation-only acceptance observation permits obsolete transition"
    );

    let mut drain_promotion = database.pool().begin().await.unwrap();
    sqlx::query("SELECT id FROM outbox WHERE id = $1 FOR UPDATE")
        .bind(cancellation_id)
        .fetch_one(&mut *drain_promotion)
        .await
        .unwrap();
    sqlx::query("UPDATE outbox SET cancellation_drain_required = TRUE WHERE id = $1")
        .bind(cancellation_id)
        .execute(&mut *drain_promotion)
        .await
        .unwrap();

    let obsolete = tokio::spawn({
        let outbox = outbox.clone();
        async move { outbox.mark_cancellation_obsolete(&claim).await }
    });
    wait_for_lock_wait(&database, "SELECT id FROM outbox WHERE id = $1 FOR UPDATE").await;
    drain_promotion.commit().await.unwrap();

    assert!(
        !obsolete.await.unwrap().unwrap(),
        "committed drain ownership must fence obsolete transition"
    );
    let retained: (String, Option<String>, bool, bool) = sqlx::query_as(
        "SELECT status, error_class, cancellation_drain_required,
                claim_token IS NOT NULL
         FROM outbox WHERE id = $1",
    )
    .bind(cancellation_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(retained, ("leased".into(), None, true, true));
    database.cleanup().await;
}

#[tokio::test]
async fn drain_rejects_unauthenticated_or_unowned_cancellation() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let lock_resource = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let canonical_lock = lock_resource.to_string();
    let created = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"mismatched-rotation-drain-bundle",
            lock_resource_binding: canonical_lock.as_bytes(),
            payment_request_binding: b"mismatched-rotation-drain-request",
            invoice_payloads: &TEST_PAYLOADS,
            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap();
    let request_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO payment_request_lifecycles
         (invoice_id, sdk_payment_request_id, request_state, last_event_at,
          last_stream_item_id)
         VALUES ($1, $2, 'proposed', NOW(), 1)",
    )
    .bind(created.invoice_id())
    .bind(&request_id)
    .execute(database.pool())
    .await
    .unwrap();

    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto());
    let evidence = lifecycles
        .required_receive_targets_for_creator_rotation(&creator)
        .await
        .unwrap();
    let creators = CreatorStore::new(database.pool(), crypto());
    let current = creators.load(&creator).await.unwrap();
    let replacement = CreatorCredentials::new(
        creator,
        "rotated-session".into(),
        current.paykit_identity_secret().clone(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: "replacement-xpub".to_owned().into(),
            account_index: 7,
        }),
        None,
    );
    creators
        .rotate_bitcoin_account_after_receive(&lifecycles, &replacement, &evidence)
        .await
        .unwrap();
    let cancellation_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT cancellation_outbox_id
         FROM creator_bitcoin_account_rotation_items
         WHERE classification = 'cancellation_pending'",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    let original_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
            .bind(cancellation_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    sqlx::query("UPDATE outbox SET intent_envelope = $1 WHERE id = $2")
        .bind(b"unauthenticated-cancellation".as_slice())
        .bind(cancellation_id)
        .execute(database.pool())
        .await
        .unwrap();

    let drains = PaymentDrainStore::new(database.pool(), crypto());
    assert_eq!(
        drains.create(&lock_resource).await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query("UPDATE outbox SET intent_envelope = $1 WHERE id = $2")
        .bind(original_envelope)
        .bind(cancellation_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM creator_bitcoin_account_rotation_items
         WHERE classification = 'cancellation_pending'",
    )
    .execute(database.pool())
    .await
    .unwrap();

    assert_eq!(
        drains.create(&lock_resource).await,
        Err(PersistenceError::Conflict)
    );
    let durable_drains: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_drains")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(durable_drains, 0);
    database.cleanup().await;
}

#[tokio::test]
async fn rotation_waits_for_admitted_proposal_then_cancels_it() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let created = store
        .create_atomic(input(
            &creator(),
            &reader(),
            b"rotation-worker-first-bundle",
            b"rotation-worker-first-request",
        ))
        .await
        .unwrap();
    let creators = CreatorStore::new(database.pool(), crypto());
    let outbox = OutboxStore::new(database.pool(), crypto());
    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto());
    let creator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    let claim = outbox
        .claim_for_creator(
            uuid::Uuid::new_v4(),
            creator_id,
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap()
        .unwrap();
    let worker_fence = creators
        .acquire_setup_lock_for_creator_id(claim.creator_id())
        .await
        .unwrap();
    assert!(outbox.claim_handoff_eligible(&claim).await.unwrap());

    let current = creators.load(&creator()).await.unwrap();
    let replacement = CreatorCredentials::new(
        creator(),
        "rotated-session".into(),
        current.paykit_identity_secret().clone(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: "replacement-xpub".to_owned().into(),
            account_index: 7,
        }),
        None,
    );
    let evidence = lifecycles
        .required_receive_targets_for_creator_rotation(&creator())
        .await
        .unwrap();
    let rotation_started = Arc::new(tokio::sync::Notify::new());
    let rotation = tokio::spawn({
        let creators = creators.clone();
        let lifecycles = lifecycles.clone();
        let rotation_started = rotation_started.clone();
        async move {
            rotation_started.notify_one();
            let fence = creators.acquire_setup_lock(&creator()).await.unwrap();
            let result = creators
                .rotate_bitcoin_account_after_receive(&lifecycles, &replacement, &evidence)
                .await;
            fence.release().await.unwrap();
            result
        }
    });
    rotation_started.notified().await;
    tokio::task::yield_now().await;
    assert!(
        !rotation.is_finished(),
        "cutover must wait for admitted worker"
    );

    let request_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO payment_request_lifecycles
         (invoice_id, sdk_payment_request_id, request_state, last_event_at, last_stream_item_id)
         VALUES ($1, $2, 'proposed', NOW(), 1)",
    )
    .bind(created.invoice_id())
    .bind(&request_id)
    .execute(database.pool())
    .await
    .unwrap();
    worker_fence.release().await.unwrap();

    assert_eq!(
        rotation.await.unwrap(),
        Err(PersistenceError::Unavailable),
        "newly projected current work must invalidate stale receive evidence"
    );
    let evidence = lifecycles
        .required_receive_targets_for_creator_rotation(&creator())
        .await
        .unwrap();
    let current = creators.load(&creator()).await.unwrap();
    let replacement = CreatorCredentials::new(
        creator(),
        "rotated-session".into(),
        current.paykit_identity_secret().clone(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: "replacement-xpub".to_owned().into(),
            account_index: 7,
        }),
        None,
    );
    let result = creators
        .rotate_bitcoin_account_after_receive(&lifecycles, &replacement, &evidence)
        .await
        .unwrap();
    assert_eq!(result.cancellation_pending_count, 1);
    let cancellation_target: String = sqlx::query_scalar(
        "SELECT cancellation_target_payment_request_id FROM outbox
         WHERE intent_kind = 'payment_request_cancellation'",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(cancellation_target, request_id);
    database.cleanup().await;
}

#[tokio::test]
async fn admitted_proposal_rechecks_eligibility_after_rotation_wins() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let bundle = parse_bundle_id("000G40R40M30E209185GR38E1W").unwrap();
    let created = store
        .create_atomic(input(
            &creator(),
            &reader(),
            bundle.to_string().as_bytes(),
            b"rotation-cutover-first-request",
        ))
        .await
        .unwrap();
    let creators = CreatorStore::new(database.pool(), crypto());
    let outbox = OutboxStore::new(database.pool(), crypto());
    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto());
    let creator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    let claim = outbox
        .claim_for_creator(
            uuid::Uuid::new_v4(),
            creator_id,
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap()
        .unwrap();

    let cutover_fence = creators.acquire_setup_lock(&creator()).await.unwrap();
    let worker_started = Arc::new(tokio::sync::Notify::new());
    let worker = tokio::spawn({
        let creators = creators.clone();
        let outbox = outbox.clone();
        let worker_started = worker_started.clone();
        async move {
            worker_started.notify_one();
            let fence = creators
                .acquire_setup_lock_for_creator_id(claim.creator_id())
                .await
                .unwrap();
            let eligible = outbox.claim_handoff_eligible(&claim).await.unwrap();
            fence.release().await.unwrap();
            eligible
        }
    });
    worker_started.notified().await;
    tokio::task::yield_now().await;
    assert!(
        !worker.is_finished(),
        "worker must wait for durable cutover"
    );

    let current = creators.load(&creator()).await.unwrap();
    let replacement = CreatorCredentials::new(
        creator(),
        "rotated-session".into(),
        current.paykit_identity_secret().clone(),
        Some(paykit_server::domain::receiving::BitcoinAccount {
            xpub: "replacement-xpub".to_owned().into(),
            account_index: 7,
        }),
        None,
    );
    let evidence = lifecycles
        .required_receive_targets_for_creator_rotation(&creator())
        .await
        .unwrap();
    let result = creators
        .rotate_bitcoin_account_after_receive(&lifecycles, &replacement, &evidence)
        .await
        .unwrap();
    assert_eq!(result.cancellation_pending_count, 0);
    cutover_fence.release().await.unwrap();

    assert!(
        !worker.await.unwrap(),
        "suppressed proposal must not reach SDK"
    );
    let classification: String = sqlx::query_scalar(
        "SELECT classification FROM creator_bitcoin_account_rotation_items
         WHERE invoice_id = $1",
    )
    .bind(created.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(classification, "proposal_suppressed");
    let suppressed: (
        String,
        Option<uuid::Uuid>,
        Option<uuid::Uuid>,
        Option<time::OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT status, lease_owner, claim_token, lease_expires_at
             FROM outbox WHERE invoice_id = $1 AND intent_kind = 'payment_request_proposal'",
    )
    .bind(created.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(suppressed, ("permanently_failed".into(), None, None, None));
    let status = PaymentRequestStatusOperations::lookup(&store, &creator(), &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        status.request_state(),
        paykit_server::domain::payment_request_lifecycle::PaymentRequestLifecycleState::Canceled
    );
    assert_eq!(status.payment_state(), PaymentState::Undetected);

    sqlx::query("UPDATE invoices SET payment_expired_at = payment_deadline WHERE id = $1")
        .bind(created.invoice_id())
        .execute(database.pool())
        .await
        .unwrap();
    let expired = PaymentRequestStatusOperations::lookup(&store, &creator(), &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        expired.request_state(),
        paykit_server::domain::payment_request_lifecycle::PaymentRequestLifecycleState::Canceled
    );
    assert_eq!(expired.payment_state(), PaymentState::Expired);
    database.cleanup().await;
}

#[tokio::test]
async fn committed_admissions_coalesce_and_failed_commits_do_not_wake() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let clone = store.clone();
    let creator = creator();
    let reader = reader();
    for bundle in [b"wake-one".as_slice(), b"wake-two"] {
        store
            .create_atomic(input(&creator, &reader, bundle, bundle))
            .await
            .unwrap();
    }
    tokio::time::timeout(std::time::Duration::ZERO, clone.wait_for_admission())
        .await
        .expect("committed work retains a wakeup before the worker waits");
    assert!(
        tokio::time::timeout(std::time::Duration::ZERO, store.wait_for_admission())
            .await
            .is_err()
    );
    let restarted = InvoiceStore::new(database.pool(), crypto());
    assert!(
        tokio::time::timeout(std::time::Duration::ZERO, restarted.wait_for_admission())
            .await
            .is_err()
    );
    assert_eq!(
        paykit_server::persistence::OutboxStore::new(database.pool(), crypto())
            .claim(uuid::Uuid::new_v4(), 16, std::time::Duration::from_secs(30))
            .await
            .unwrap()
            .len(),
        2,
        "periodic claims recover durable work without a process-local hint"
    );

    // A deferred trigger fails COMMIT after the outbox INSERT succeeded.
    sqlx::raw_sql(
        "CREATE FUNCTION reject_admission() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'admission rejected'; END $$;
         CREATE CONSTRAINT TRIGGER reject_admission AFTER INSERT ON outbox
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_admission();",
    )
    .execute(database.pool())
    .await
    .unwrap();
    assert!(
        store
            .create_atomic(input(&creator, &reader, b"wake-failed", b"wake-failed"))
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        2
    );
    assert!(
        tokio::time::timeout(std::time::Duration::ZERO, store.wait_for_admission())
            .await
            .is_err()
    );
    database.cleanup().await;
}

#[tokio::test]
async fn creator_discovery_does_not_lease_and_claims_recheck_due_work() {
    use paykit_server::persistence::OutboxStore;
    use std::time::Duration;
    use uuid::Uuid;

    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let other = second_creator();
    let reader = reader();
    CreatorStore::new(database.pool(), crypto())
        .create(&CreatorCredentials::new(
            other.clone(),
            "other-session".into(),
            PaykitIdentitySecretKey::new([8; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "other-xpub".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    for (owner, bundle, address_prefix) in [
        (&creator, b"first".as_slice(), "first-creator"),
        (&creator, b"second", "first-creator"),
        (&other, b"third", "other-creator"),
    ] {
        let payloads = CreatorPayloads { address_prefix };
        let mut admission = input(owner, &reader, bundle, bundle);
        admission.invoice_payloads = &payloads;
        store.create_atomic(admission).await.unwrap();
    }
    let outbox = OutboxStore::new(database.pool(), crypto());
    let candidates = outbox.due_creator_ids(&[], 16).await.unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        outbox.due_creator_ids(&[], 1).await.unwrap(),
        candidates[..1]
    );
    assert_eq!(
        outbox.due_creator_ids(&candidates[..1], 16).await.unwrap(),
        candidates[1..]
    );
    let queued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE status = 'queued' AND attempt_count = 0 AND claim_token IS NULL",
    ).fetch_one(database.pool()).await.unwrap();
    assert_eq!(queued, 3, "candidate discovery consumed a lease");

    let claim = outbox
        .claim_for_creator(Uuid::new_v4(), candidates[1], Duration::from_secs(30))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.creator_id(), candidates[1]);
    assert!(outbox.claim_handoff_eligible(&claim).await.unwrap());

    sqlx::query(
        "UPDATE outbox SET next_attempt_at = NOW() + INTERVAL '1 hour' WHERE creator_id = $1",
    )
    .bind(candidates[0])
    .execute(database.pool())
    .await
    .unwrap();
    assert!(
        outbox
            .claim_for_creator(Uuid::new_v4(), candidates[0], Duration::from_secs(30))
            .await
            .unwrap()
            .is_none(),
        "claim ignored the current due time"
    );

    sqlx::query("UPDATE outbox SET next_attempt_at = NOW() WHERE creator_id = $1")
        .bind(candidates[0])
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE lock_payment_generations SET current_generation = current_generation + 1 WHERE creator_id = $1")
        .bind(candidates[0]).execute(database.pool()).await.unwrap();
    assert!(
        outbox
            .due_creator_ids(&[candidates[1]], 16)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        outbox
            .claim_for_creator(Uuid::new_v4(), candidates[0], Duration::from_secs(30))
            .await
            .unwrap()
            .is_none(),
        "claim ignored the generation fence"
    );
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(claim.id())
        .execute(database.pool())
        .await
        .unwrap();
    let reclaimed = outbox
        .claim_for_creator(Uuid::new_v4(), claim.creator_id(), Duration::from_secs(30))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.id(), claim.id());
    assert!(!outbox.claim_handoff_eligible(&claim).await.unwrap());
    assert!(outbox.claim_handoff_eligible(&reclaimed).await.unwrap());
    database.cleanup().await;
}

#[tokio::test]
async fn connection_binding_uses_persisted_reader_identity_without_mutating_business_rows() {
    let database = TestDatabase::create().await;
    let invoices = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let bundle = "000G40R40M30E209185GR38E1W";
    invoices
        .create_atomic(input(
            &creator,
            &reader,
            bundle.as_bytes(),
            b"connection-request",
        ))
        .await
        .unwrap();
    let before: Vec<String> =
        sqlx::query_scalar("SELECT row_to_json(o)::text FROM outbox o ORDER BY id")
            .fetch_all(database.pool())
            .await
            .unwrap();
    let binding = invoices
        .connection_binding(&creator, &parse_bundle_id(bundle).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(binding.reader(), &reader);
    assert!(
        invoices
            .connection_binding(&second_creator(), &parse_bundle_id(bundle).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let after: Vec<String> =
        sqlx::query_scalar("SELECT row_to_json(o)::text FROM outbox o ORDER BY id")
            .fetch_all(database.pool())
            .await
            .unwrap();
    assert_eq!(before, after);
    database.cleanup().await;
}

#[tokio::test]
async fn invoice_allocation_encrypts_bound_terms_and_replays() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();

    let first = store
        .create_atomic(input(&creator, &reader, b"bundle-one", b"request-one"))
        .await
        .unwrap();
    assert!(!first.replayed());
    assert_eq!(first.reader_child_index(), 0);

    let protected_payment_row = sqlx::query(
        "SELECT payment_record_envelope, bitcoin_address_lookup_hash FROM invoices WHERE id = $1",
    )
    .bind(first.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let payment_record_envelope =
        protected_payment_row.get::<Vec<u8>, _>("payment_record_envelope");
    let address_lookup_hash =
        protected_payment_row.get::<Vec<u8>, _>("bitcoin_address_lookup_hash");
    assert_eq!(
        address_lookup_hash,
        crypto()
            .bitcoin_address_lookup_hash(b"test-address-0")
            .as_bytes()
            .as_slice()
    );
    assert!(
        !payment_record_envelope
            .windows(b"test-address-0".len())
            .any(|window| window == b"test-address-0")
    );

    let payment_row = sqlx::query("SELECT invoice_id, intent_envelope FROM outbox WHERE id = $1")
        .bind(first.payment_request_outbox_id())
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        payment_row.get::<Option<_>, _>("invoice_id"),
        Some(first.invoice_id())
    );
    for raw in [
        payment_row.get::<Vec<u8>, _>("intent_envelope"),
        sqlx::query_scalar::<_, Vec<u8>>("SELECT invoice_envelope FROM invoices WHERE id = $1")
            .bind(first.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap(),
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT assignment_envelope FROM reader_assignments WHERE id = $1",
        )
        .bind(first.reader_assignment_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
    ] {
        for plaintext in [b"test-address-0".as_slice(), reader.to_string().as_bytes()] {
            assert!(
                !raw.windows(plaintext.len())
                    .any(|window| window == plaintext)
            );
        }
    }

    let original_payment_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
            .bind(first.payment_request_outbox_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    let creator_hash = crypto().lookup_hash(creator.to_string().as_bytes());
    let original_plaintext = crypto()
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(
                creator_hash,
                first.payment_request_outbox_id(),
            ),
            &EncryptedEnvelope::from_bytes(original_payment_envelope.clone()),
        )
        .unwrap();
    let original_intent = DeliveryIntentV1::decode(&original_plaintext).unwrap();
    let original_reference = original_intent.terms().unwrap().payment_reference.clone();
    let original_app_id = original_intent.app_id();

    let replay = store
        .create_atomic(input(&creator, &reader, b"bundle-one", b"request-one"))
        .await
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.invoice_id(), first.invoice_id());
    assert_eq!(
        replay.payment_request_outbox_id(),
        first.payment_request_outbox_id()
    );
    assert_eq!(replay.reader_assignment_id(), first.reader_assignment_id());
    assert_eq!(replay.reader_child_index(), 0);
    let replayed_payment_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
            .bind(replay.payment_request_outbox_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(replayed_payment_envelope, original_payment_envelope);
    let replayed_plaintext = crypto()
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(
                creator_hash,
                replay.payment_request_outbox_id(),
            ),
            &EncryptedEnvelope::from_bytes(replayed_payment_envelope),
        )
        .unwrap();
    let replayed_intent = DeliveryIntentV1::decode(&replayed_plaintext).unwrap();
    assert_eq!(replayed_intent.app_id(), original_app_id);
    assert_eq!(
        replayed_intent.terms().unwrap().payment_reference,
        original_reference
    );
    assert_eq!(replayed_intent, original_intent);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reader_assignments")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM invoices")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM outbox")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .create_atomic(input(&creator, &reader, b"bundle-one", b"changed-request"))
            .await,
        Err(PersistenceError::Conflict)
    );
    assert_eq!(
        store
            .create_atomic(input(
                &creator,
                &second_reader(),
                b"bundle-one",
                b"changed-reader-request",
            ))
            .await,
        Err(PersistenceError::Conflict)
    );

    let second = store
        .create_atomic(input(&creator, &reader, b"bundle-two", b"request-two"))
        .await
        .unwrap();
    assert!(!second.replayed());
    assert_ne!(second.reader_assignment_id(), first.reader_assignment_id());
    assert_eq!(second.reader_child_index(), 1);
    assert_ne!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT bitcoin_address_lookup_hash FROM invoices WHERE id = $1",
        )
        .bind(first.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT bitcoin_address_lookup_hash FROM invoices WHERE id = $1",
        )
        .bind(second.invoice_id())
        .fetch_one(database.pool())
        .await
        .unwrap(),
    );
    let envelope: Vec<u8> = sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
        .bind(second.payment_request_outbox_id())
        .fetch_one(database.pool())
        .await
        .unwrap();
    let plaintext = crypto()
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(
                creator_hash,
                second.payment_request_outbox_id(),
            ),
            &EncryptedEnvelope::from_bytes(envelope),
        )
        .unwrap();
    let second_intent = DeliveryIntentV1::decode(&plaintext).unwrap();
    let first_terms = original_intent.terms().unwrap();
    let second_terms = second_intent.terms().unwrap();
    assert_eq!(
        first_terms.payment_endpoints["btc-bitcoin-p2wpkh"],
        serde_json::json!({"value":"test-address-0"}).to_string()
    );
    assert_eq!(
        second_terms.payment_endpoints["btc-bitcoin-p2wpkh"],
        serde_json::json!({"value":"test-address-1"}).to_string()
    );

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_exact_invoice_allocation_serializes_to_one_durable_result() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let other_store = store.clone();
    let creator = creator();
    let reader = reader();

    let (first, second) = tokio::join!(
        store.create_atomic(input(
            &creator,
            &reader,
            b"concurrent-bundle",
            b"concurrent-request"
        )),
        other_store.create_atomic(input(
            &creator,
            &reader,
            b"concurrent-bundle",
            b"concurrent-request"
        ))
    );
    let first = first.unwrap();
    let second = second.unwrap();

    assert_ne!(first.replayed(), second.replayed());
    assert_eq!(first.invoice_id(), second.invoice_id());
    assert_eq!(first.reader_assignment_id(), second.reader_assignment_id());
    assert_eq!(
        first.payment_request_outbox_id(),
        second.payment_request_outbox_id()
    );
    for (table, expected) in [
        ("reader_assignments", 1_i64),
        ("invoices", 1_i64),
        ("outbox", 1_i64),
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(database.pool())
            .await
            .unwrap();
        assert_eq!(count, expected, "unexpected {table} cardinality");
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        1
    );

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_invoices_for_same_reader_bind_distinct_addresses() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    let (first, second) = tokio::join!(
        store.create_atomic(input(&creator, &reader, b"bundle-a", b"request-a")),
        store.create_atomic(input(&creator, &reader, b"bundle-b", b"request-b")),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.invoice_id(), second.invoice_id());
    assert_ne!(first.reader_child_index(), second.reader_child_index());
    let outbox = paykit_server::persistence::OutboxStore::new(database.pool(), crypto());
    let claims = outbox
        .claim(uuid::Uuid::new_v4(), 10, std::time::Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(claims.len(), 2, "each invoice is immediately claimable");
    let mut destinations = claims
        .iter()
        .map(|claim| {
            outbox
                .delivery_intent(claim)
                .unwrap()
                .terms()
                .unwrap()
                .payment_endpoints["btc-bitcoin-p2wpkh"]
                .clone()
        })
        .collect::<Vec<_>>();
    destinations.sort();
    assert_eq!(
        destinations,
        [
            serde_json::json!({"value": "test-address-0"}).to_string(),
            serde_json::json!({"value": "test-address-1"}).to_string(),
        ]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        2
    );
    database.cleanup().await;
}

#[tokio::test]
async fn atomic_store_rejects_empty_address_and_wrong_reader_before_any_insert() {
    static BAD_PAYLOADS: EmptyAddressPayloads = EmptyAddressPayloads;
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();

    let mut mismatched_address = input(&creator, &reader, b"bad-address", b"bad-address-request");
    mismatched_address.invoice_payloads = &BAD_PAYLOADS;
    assert_eq!(
        store.create_atomic(mismatched_address).await,
        Err(PersistenceError::InvalidInput)
    );

    let other_reader = second_reader();
    assert_eq!(
        store
            .create_atomic(input(
                &creator,
                &other_reader,
                b"bad-reader",
                b"bad-reader-request",
            ))
            .await,
        Err(PersistenceError::CorruptOrMissing)
    );
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM invoices),
            (SELECT COUNT(*) FROM reader_assignments),
            (SELECT COUNT(*) FROM outbox)",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(counts, (0, 0, 0));

    database.cleanup().await;
}

#[tokio::test]
async fn provider_v2_invoice_binding_and_outbox_roll_back_together() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    sqlx::query(
        "CREATE FUNCTION fail_provider_v2_outbox_insert() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.invoice_id IS NOT NULL THEN RAISE EXCEPTION 'forced provider-v2 outbox failure'; END IF; RETURN NEW; END; $$",
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_provider_v2_outbox_insert BEFORE INSERT ON outbox \
         FOR EACH ROW EXECUTE FUNCTION fail_provider_v2_outbox_insert()",
    )
    .execute(database.pool())
    .await
    .unwrap();
    let deadline: OffsetDateTime =
        sqlx::query_scalar("SELECT clock_timestamp() + INTERVAL '1 hour'")
            .fetch_one(database.pool())
            .await
            .unwrap();

    assert!(
        store
            .create_provider_v2_atomic(provider_v2_input(
                &creator,
                &reader,
                b"provider-v2-rollback",
                [93; 32],
                deadline,
            ))
            .await
            .is_err()
    );
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM reader_assignments),
                (SELECT COUNT(*) FROM invoices),
                (SELECT COUNT(*) FROM invoice_provider_v2),
                (SELECT COUNT(*) FROM outbox)",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(counts, (0, 0, 0, 0));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0
    );
    database.cleanup().await;
}

#[tokio::test]
async fn allocation_and_invoice_rollback_on_request_outbox_failure() {
    let database = TestDatabase::create().await;
    let store = invoice_store(&database).await;
    let creator = creator();
    let reader = reader();
    sqlx::query(
        "CREATE FUNCTION fail_payment_request_outbox_insert() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.invoice_id IS NOT NULL THEN RAISE EXCEPTION 'forced payment request outbox failure'; END IF; RETURN NEW; END; $$",
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_payment_request_outbox_insert BEFORE INSERT ON outbox \
         FOR EACH ROW EXECUTE FUNCTION fail_payment_request_outbox_insert()",
    )
    .execute(database.pool())
    .await
    .unwrap();

    assert!(
        store
            .create_atomic(input(
                &creator,
                &reader,
                b"rollback-bundle",
                b"rollback-request",
            ))
            .await
            .is_err()
    );
    for table in ["reader_assignments", "invoices", "outbox"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(database.pool())
            .await
            .unwrap();
        assert_eq!(count, 0, "{table} escaped the failed transaction");
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT next_child_index FROM creators")
            .fetch_one(database.pool())
            .await
            .unwrap(),
        0,
        "allocator increment escaped the failed transaction"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_creators_own_distinct_intents_at_the_same_child_index() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = crypto();
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let first_creator = creator();
    let second_creator = second_creator();
    creators
        .create(&CreatorCredentials::new(
            first_creator.clone(),
            "session-one".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "xpub-one".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    creators
        .create(&CreatorCredentials::new(
            second_creator.clone(),
            "session-two".into(),
            PaykitIdentitySecretKey::new([8; 32], 1).unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: "xpub-two".to_owned().into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();

    let first_store = InvoiceStore::new(database.pool(), crypto.clone());
    let second_store = first_store.clone();
    let reader = reader();
    let first_payloads = CreatorPayloads {
        address_prefix: "creator-one-address",
    };
    let second_payloads = CreatorPayloads {
        address_prefix: "creator-two-address",
    };
    let (first, second) = tokio::join!(
        first_store.create_atomic(AtomicInvoiceInput {
            creator: &first_creator,
            reader: &reader,
            bundle_binding: b"creator-one-bundle",
            lock_resource_binding: b"creator-one-lock",
            payment_request_binding: b"creator-one-request",
            invoice_payloads: &first_payloads,

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        }),
        second_store.create_atomic(AtomicInvoiceInput {
            creator: &second_creator,
            reader: &reader,
            bundle_binding: b"creator-two-bundle",
            lock_resource_binding: b"creator-two-lock",
            payment_request_binding: b"creator-two-request",
            invoice_payloads: &second_payloads,

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.reader_child_index(), 0);
    assert_eq!(second.reader_child_index(), 0);

    let first_hashes: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT bitcoin_address_lookup_hash, derivation_index_lookup_hash
         FROM invoices WHERE id = $1",
    )
    .bind(first.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let second_hashes: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT bitcoin_address_lookup_hash, derivation_index_lookup_hash
         FROM invoices WHERE id = $1",
    )
    .bind(second.invoice_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_ne!(first_hashes.0, second_hashes.0);
    assert_ne!(first_hashes.1, second_hashes.1);

    let first_request = first.payment_request_outbox_id();
    let first_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
            .bind(first_request)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let first_hash = crypto.lookup_hash(first_creator.to_string().as_bytes());
    let second_hash = crypto.lookup_hash(second_creator.to_string().as_bytes());
    let first_payment_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT payment_record_envelope FROM invoices WHERE id = $1")
            .bind(first.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(
        crypto
            .decrypt(
                &EnvelopeContext::invoice_payment_record(second_hash, first.invoice_id()),
                &EncryptedEnvelope::from_bytes(first_payment_envelope.clone()),
            )
            .is_err(),
        "another Creator context decrypted the first Creator payment record"
    );
    assert!(
        crypto
            .decrypt(
                &EnvelopeContext::invoice_payment_record(first_hash, first.invoice_id()),
                &EncryptedEnvelope::from_bytes(first_payment_envelope),
            )
            .is_ok()
    );
    assert!(
        crypto
            .decrypt(
                &EnvelopeContext::outbox_semantic_intent(second_hash, first_request),
                &EncryptedEnvelope::from_bytes(first_envelope.clone()),
            )
            .is_err(),
        "another Creator context decrypted the first Creator intent"
    );
    let plaintext = crypto
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(first_hash, first_request),
            &EncryptedEnvelope::from_bytes(first_envelope),
        )
        .unwrap();
    let intent: DeliveryIntentV1 = postcard::from_bytes(&plaintext).unwrap();
    assert_eq!(
        intent.terms().unwrap().payment_endpoints["btc-bitcoin-p2wpkh"],
        serde_json::json!({"value": "creator-one-address-0"}).to_string()
    );

    database.cleanup().await;
}
