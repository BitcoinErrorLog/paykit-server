//! Headless, disposable Creator setup and Reader payment on a local Pubky testnet.
//! Run through sdk-example/run.sh, which supplies isolated regtest infrastructure.

use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use axum::http::Method;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{
    Address, Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use ed25519_dalek::{Signer, SigningKey};
use locks_core::{
    ids::CreatorPubky,
    lock_policy::{
        AccessPolicy, CONTENT_LOCK_VERSION, ContentLock, Criterion, LockLogic, LockServerConfig,
        VerifierType,
    },
};
use paykit_lib::{PaykitApp, PaykitAppCapabilities, PaymentRequestId};
use paykit_sdk::{
    LinkedPeerState, PAYKIT_SESSION_CAPABILITIES, PaykitSdk, PaykitSdkConfig, PaykitSdkError,
    PaymentAdapter, PaymentRequestRecord, PaymentTarget, PrivatePaymentEndpointCandidate,
    PrivatePaymentEndpointSelectionRequest, PrivatePaymentResolutionStatus, PubkyLocalSecretKey,
    PubkyPublicKey, PubkySessionAccess, PubkySessionBootstrap, PubkySessionProvider,
    PubkySharedStateStorage,
};
use paykit_server::{
    Server,
    bitkit_claim::{QUERY_PARAMETER, encode_unsigned_payload, parse_auth_request},
    bitkit_setup::BitkitAuthStarter,
    config::{BitcoinNetwork, Config, ConfigEnvironment},
    crypto::Crypto,
    paykit::CreatorSessions,
    persistence::{CreatorStore, run_migrations},
    real_setup::RealSetupCompleter,
    setup::{PollResult, SetupLimits, SetupService, SystemClock},
    setup_orchestration::PubkyCompanionRelay,
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky::{Keypair, PubkyHttpClient};
use pubky_testnet::EphemeralTestnet;
use serde_json::{Value, json};

const APP: &str = "sdk-example";
const ENDPOINT: &str = "btc-regtest-p2wpkh";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";
const SATS: u64 = 50_000;

#[derive(Clone)]
struct SessionProvider(Arc<Mutex<Option<PubkySessionAccess>>>);

#[async_trait]
impl PubkySessionProvider for SessionProvider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        Ok(self.0.lock().unwrap().clone())
    }

    async fn load_public_storage(&self) -> paykit_sdk::Result<Option<pubky::PublicStorage>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .as_ref()
            .map(|access| access.outbox_client.public_storage()))
    }

    async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

struct RegtestPayments;

#[async_trait]
impl PaymentAdapter for RegtestPayments {
    async fn select_private_payment_endpoints(
        &self,
        request: &PrivatePaymentEndpointSelectionRequest,
    ) -> paykit_sdk::Result<Vec<PrivatePaymentEndpointCandidate>> {
        Ok(request
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.app_id.as_str() == "paykit-server" && candidate.identifier == ENDPOINT
            })
            .cloned()
            .collect())
    }

    async fn build_private_payment_target(
        &self,
        endpoint: &PrivatePaymentEndpointCandidate,
    ) -> paykit_sdk::Result<PaymentTarget> {
        Ok(PaymentTarget {
            payload: endpoint.payload.clone(),
        })
    }
}

type Sdk = PaykitSdk<PubkySharedStateStorage, SessionProvider, RegtestPayments>;

async fn sdk(access: PubkySessionAccess) -> Result<Sdk> {
    let provider = SessionProvider(Arc::new(Mutex::new(Some(access))));
    let sdk = PaykitSdk::new(
        PubkySharedStateStorage::new(provider.clone()),
        provider,
        RegtestPayments,
        PaykitSdkConfig::new(APP)?,
    );
    sdk.initialize().await?;
    sdk.publish_paykit_noise_key_authorization().await?;
    sdk.publish_paykit_app(PaykitApp::new(
        "SDK example",
        PaykitAppCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: true,
        },
    )?)
    .await?;
    Ok(sdk)
}

async fn rpc(http: &PubkyHttpClient, base: &str, method: &str, params: Value) -> Result<Value> {
    let response: Value = http
        .request(Method::POST, &base)
        .basic_auth("example", Some("example"))
        .json(&json!({"jsonrpc":"1.0", "id":"sdk-example", "method":method, "params":params}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        response["error"].is_null(),
        "Bitcoin RPC {method}: {}",
        response["error"]
    );
    Ok(response["result"].clone())
}

async fn signed_post(
    http: &PubkyHttpClient,
    base: &str,
    path: &str,
    key: &SigningKey,
    body: Value,
) -> Result<Vec<u8>> {
    let body = serde_json_canonicalizer::to_vec(&body)?;
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&body).to_bytes());
    Ok(http
        .request(Method::POST, &format!("{base}{path}"))
        .header("Content-Type", "application/json")
        .header("X-Paykit-Signature", signature)
        .body(body)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?
        .to_vec())
}

async fn authorize_server(
    config: &Config,
    database: &TestDatabase,
    bootstrap: PubkySessionBootstrap,
    root: &PubkyLocalSecretKey,
    client: pubky::Pubky,
) -> Result<()> {
    let creators = CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(config.master_key().as_bytes())?),
    );
    let sessions = CreatorSessions::new(creators.clone(), client, config.paykit.clone());
    let service = SetupService::new(
        vec!["http://localhost:8080".into()],
        Arc::new(RealSetupCompleter::new(
            BitkitAuthStarter::new(bootstrap.clone()),
            Arc::new(PubkyCompanionRelay::new(PubkyHttpClient::new()?)),
            creators,
            sessions,
            BitcoinNetwork::Regtest,
        )),
        Arc::new(SystemClock::default()),
        SetupLimits {
            max_polls_per_flow: 2,
            max_polls: 10,
            setup_per_ip_per_minute: 20,
            max_pending_setup_flows: 10,
        },
    );
    let flow = service
        .begin("127.0.0.1".parse()?, "http://localhost:8080", "sdk-example")
        .await
        .map_err(|error| anyhow::anyhow!("Could not begin Creator setup: {error:?}"))?;
    let request = parse_auth_request(&flow.authorization_url, PAYKIT_SESSION_CAPABILITIES)?;
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Regtest, &Keypair::random().secret_key())?
        .derive_priv(
            &secp,
            &[84, 1, 0].map(|index| ChildNumber::from_hardened_idx(index).unwrap()),
        )?;
    let xpub = Xpub::from_priv(&secp, &account);
    let payload = encode_unsigned_payload(
        0,
        &xpub.encode(),
        &root.derive_paykit_identity_secret_key(1)?,
    );
    let claim = paykit_sdk::PubkyAuthCompanionClaim::new(
        QUERY_PARAMETER,
        request.claim_type(),
        payload.to_vec(),
    )?;
    bootstrap
        .approve_auth_with_companion_claim(
            &flow.authorization_url,
            PAYKIT_SESSION_CAPABILITIES,
            root,
            &claim,
        )
        .await?;
    ensure!(
        service.trigger_completion(&flow.flow_id).await == PollResult::Complete,
        "Creator setup did not complete"
    );
    Ok(())
}

async fn receive_request(sdk: &Sdk, creator: &PubkyPublicKey) -> Result<PaymentRequestRecord> {
    loop {
        match sdk.ensure_link_with_peer(creator.clone(), 8).await {
            Ok(report) if report.state == LinkedPeerState::Linked => {
                let received = sdk.receive_private_messages(creator.clone()).await?;
                ensure!(
                    received.event_conflicts.is_empty(),
                    "Conflicting private events"
                );
                sdk.process_outbound_private_messages(creator.clone())
                    .await?;
                if let Some(request) = sdk
                    .received_payment_requests_from(creator)
                    .await?
                    .into_iter()
                    .find(|request| {
                        request.terms.as_ref().is_some_and(|terms| {
                            terms.metadata.get("bundle_id") == Some(&json!(BUNDLE))
                        })
                    })
                {
                    return Ok(request);
                }
            }
            Ok(_)
            | Err(
                PaykitSdkError::Transport { .. }
                | PaykitSdkError::NotFound { .. }
                | PaykitSdkError::RecoveryRequired { .. },
            ) => {}
            Err(error) => return Err(error.into()),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn checkout(
    base: &str,
    rpc_url: &str,
    locks_key: &SigningKey,
    creator: &PubkyPublicKey,
    reader: &PubkyPublicKey,
    lock_resource: &str,
    payer: &Sdk,
) -> Result<()> {
    let http = &PubkyHttpClient::builder()
        .request_timeout(Duration::from_secs(15))
        .build()?;
    signed_post(
        http,
        base,
        "/invoices",
        locks_key,
        json!({"bundle_id":BUNDLE, "lock_resource":lock_resource, "reader":reader.to_app_key()}),
    )
    .await?;
    println!(
        "Invoice created; waiting for the SDK to complete the link and receive the request..."
    );
    let request = receive_request(payer, creator).await?;
    let terms = request.terms.as_ref().context("Request has no terms")?;
    ensure!(
        terms.amount.asset == "btc"
            && terms.amount.value == "0.00050000"
            && terms.recurrence.is_none(),
        "Unexpected invoice amount or recurrence"
    );
    ensure!(
        terms.required_app_id.as_ref().map(|id| id.as_str()) == Some("paykit-server"),
        "Unexpected payment app"
    );
    let id = PaymentRequestId::new(request.payment_request_id.clone())?;
    let resolved = payer
        .resolve_private_payment_request(creator.clone(), &id, None)
        .await?;
    ensure!(
        resolved.status == PrivatePaymentResolutionStatus::Payable
            && resolved.payable_endpoints.len() == 1,
        "Invoice is not payable"
    );
    let endpoint = &resolved.payable_endpoints[0];
    ensure!(
        terms
            .payment_endpoints
            .as_ref()
            .and_then(|endpoints| endpoints.get(ENDPOINT))
            == Some(&endpoint.target.payload),
        "Resolved endpoint differs from the invoice"
    );
    let payload: Value = serde_json::from_str(&endpoint.target.payload)?;
    let address = Address::from_str(
        payload["value"]
            .as_str()
            .context("Missing Bitcoin address")?,
    )?
    .require_network(Network::Regtest)?;
    payer
        .claim_payment_request_for_execution(creator.clone(), &id)
        .await?;
    payer.accept_payment_request(creator.clone(), &id).await?;
    payer
        .process_outbound_private_messages(creator.clone())
        .await?;

    // The node is a disposable regtest wallet. Never retry sendtoaddress after an ambiguous failure.
    let wallet = format!("{rpc_url}/wallet/payer");
    let txid = rpc(
        http,
        &wallet,
        "sendtoaddress",
        json!([address.to_string(), 0.0005]),
    )
    .await?;
    let mining_address = rpc(http, &wallet, "getnewaddress", json!([])).await?;
    rpc(
        http,
        &wallet,
        "generatetoaddress",
        json!([6, mining_address]),
    )
    .await?;
    println!("Paid {SATS} regtest sats to {address}; transaction {txid}");
    loop {
        let status: Value = serde_json::from_slice(
            &signed_post(
                http,
                base,
                "/transactions/status",
                locks_key,
                json!({"bundle_id":BUNDLE, "creator":creator.to_app_key()}),
            )
            .await?,
        )?;
        if status["status"] == "confirmed"
            && status["amount_matched"] == true
            && status["confirmations"]
                .as_u64()
                .is_some_and(|count| count >= 6)
        {
            println!(
                "PASS: Paykit Server independently observed the invoice payment with six confirmations."
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let postgres = std::env::var("TEST_DATABASE_URL").context("Run sdk-example/run.sh")?;
    let rpc_url = std::env::var("EXAMPLE_BITCOIN_RPC")?;
    let electrum = std::env::var("EXAMPLE_ELECTRUM")?;
    let http = PubkyHttpClient::builder()
        .request_timeout(Duration::from_secs(15))
        .build()?;
    ensure!(
        rpc(&http, &rpc_url, "getblockchaininfo", json!([])).await?["chain"] == "regtest",
        "Only regtest is supported"
    );
    rpc(&http, &rpc_url, "createwallet", json!(["payer"])).await?;
    let wallet = format!("{rpc_url}/wallet/payer");
    let mining_address = rpc(&http, &wallet, "getnewaddress", json!([])).await?;
    rpc(
        &http,
        &wallet,
        "generatetoaddress",
        json!([101, mining_address]),
    )
    .await?;

    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await?;
    let testnet = EphemeralTestnet::builder()
        .postgres(pubky_testnet::pubky_homeserver::ConnectionString::new(
            &postgres,
        )?)
        .build()
        .await?;
    let relay = http_relay::HttpRelay::builder().http_port(0).run().await?;
    let client = testnet.sdk()?;
    let home = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let bootstrap = PubkySessionBootstrap::with_pubky(client.clone(), "app.paykit.sdk-example")?
        .with_auth_relay(relay.local_url().join("inbox")?.as_str())?;
    let creator_root = PubkyLocalSecretKey::new(Keypair::random().secret_key());
    let creator_auth = bootstrap
        .sign_up(
            &creator_root,
            &home,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await?;
    let creator = creator_auth.public_key.clone();
    let _creator_sdk = sdk(creator_auth.access).await?;
    let reader_auth = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            &home,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await?;
    let reader = reader_auth.public_key.clone();
    let payer = sdk(reader_auth.access).await?;
    println!(
        "Creator: {}\nReader: {}",
        creator.to_app_key(),
        reader.to_app_key()
    );

    let locks_pair = Keypair::random();
    let locks_key = SigningKey::from_bytes(&locks_pair.secret_key());
    let config = Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:0"
[locks]
trusted_public_key = "{}"
[setup]
allowed_origins = ["http://localhost:8080"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "regtest"
[electrum]
endpoint = "{electrum}"
poll_interval = "1s"
request_timeout = "2s"
connect_retries = 0
[outbox]
poll_interval = "500ms"
retry_initial = "1s"
retry_max = "2s"
[shutdown]
drain_timeout = "2s"
"#,
            PubkyPublicKey::from_public_key(&locks_pair.public_key()).to_app_key()
        ),
        ConfigEnvironment {
            database_url: Some(database.database_url().into()),
            master_key: Some(URL_SAFE_NO_PAD.encode(Keypair::random().secret_key())),
        },
    )?;
    let server_bootstrap = PubkySessionBootstrap::with_pubky(client.clone(), "app.paykit.server")?
        .with_auth_relay(relay.local_url().join("inbox")?.as_str())?;
    authorize_server(
        &config,
        &database,
        server_bootstrap,
        &creator_root,
        client.clone(),
    )
    .await?;
    println!("Creator authorized: delegated session, Paykit key, and watch-only account.");

    let lock = ContentLock {
        version: CONTENT_LOCK_VERSION,
        creator: CreatorPubky::from_str(&creator.to_app_key())?,
        primary_resource: None,
        secondary_resources: BTreeMap::new(),
        criteria: vec![Criterion {
            criterion_id: "payment".into(),
            verifier_type: VerifierType::PaykitPayment,
            params: json!({"recipient_pubky":creator.to_app_key(), "amount":SATS.to_string(), "asset":"BTC"}),
        }],
        lock_logic: LockLogic::All {
            criteria: vec!["payment".into()],
        },
        access_policy: AccessPolicy {
            requested_credential_ttl_seconds: 900,
        },
        lock_server: LockServerConfig { override_: None },
        created_at: time::OffsetDateTime::now_utc(),
    };
    let lock_path = lock.content_lock_path()?.to_string();
    let lock_writer = bootstrap
        .sign_in(&creator_root, "/pub/app.locks/:rw")
        .await?;
    lock_writer
        .access
        .session
        .storage()
        .put_json(&lock_path, &lock)
        .await?;
    let lock_resource = format!("{}{lock_path}", creator.to_app_key());
    let server = Server::build_with_pubky(config, database.pool().clone(), client).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(server.run_until(listener, async {
        let _ = stopped.await;
    }));
    let result = tokio::time::timeout(
        Duration::from_secs(180),
        checkout(
            &base,
            &rpc_url,
            &locks_key,
            &creator,
            &reader,
            &lock_resource,
            &payer,
        ),
    )
    .await;
    let _ = shutdown.send(());
    task.await??;
    database.cleanup().await;
    match result {
        Ok(result) => result,
        Err(_) => bail!("Timed out waiting for the private request or regtest confirmation"),
    }
}
