#[path = "paykit-reader-demo/payment_instructions.rs"]
mod payment_instructions;
#[path = "paykit-reader-demo/state.rs"]
mod state;

use std::{
    future::Future,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use paykit_sdk::{
    EventIdConflict, LinkedPeerState, PaykitAppCapabilities, PaykitAppId, PaykitSdk,
    PaykitSdkConfig, PaykitSdkError, PrivateStreamParseStatus, PubkyLocalSecretKey, PubkyPublicKey,
    PubkySessionAccess, PubkySessionBootstrap, PubkySessionProvider, PubkySharedStateStorage,
    storage::{StorageAdapter, StorageState},
};
use paykit_server::config::{PAYKIT_APP_ID, PAYKIT_CLIENT_ID};
use pubky::{Pubky, PubkyHttpClient};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

use payment_instructions::{DemoPaymentAdapter, payment_instructions, select_actionable_request};
use state::{EncryptedReaderStateStore, StateInvariants, StateLockError};

const STATE_ENV: &str = "PAYKIT_READER_STATE_PATH";
const TESTNET_HOST_ENV: &str = "PAYKIT_READER_PUBKY_TESTNET_HOST";
const APP_ID_ENV: &str = "PAYKIT_READER_APP_ID";
const SERVER_PUBKY_ENV: &str = "PAYKIT_READER_SERVER_PUBKY";
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    version: u8,
    operation: Operation,
    reader_secret: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Operation {
    Prepare,
    Receive,
    Inspect,
}

struct Config {
    state_path: PathBuf,
    testnet_host: String,
    app_id: PaykitAppId,
    server_pubky: PubkyPublicKey,
}

impl Config {
    fn invariants(&self) -> StateInvariants {
        StateInvariants {
            app_id: self.app_id.as_str().to_owned(),
            server_pubky: self.server_pubky.to_app_key(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    InvalidInput,
    InvalidConfig,
    StateBusy,
    InvalidState,
    ProtocolFailed,
    ReceiveTimeout,
    OutputFailed,
}

impl Failure {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::InvalidConfig => "invalid_config",
            Self::StateBusy => "state_busy",
            Self::InvalidState => "invalid_state",
            Self::ProtocolFailed => "protocol_failed",
            Self::ReceiveTimeout => "receive_timeout",
            Self::OutputFailed => "output_failed",
        }
    }
}

#[derive(Clone)]
struct DemoSessionProvider {
    access: PubkySessionAccess,
    pubky: Pubky,
}

#[async_trait]
impl PubkySessionProvider for DemoSessionProvider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        Ok(Some(self.access.clone()))
    }

    async fn load_public_storage(&self) -> paykit_sdk::Result<Option<pubky::PublicStorage>> {
        Ok(Some(self.pubky.public_storage()))
    }

    async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
        Err(PaykitSdkError::Policy {
            context: "reader demo sessions cannot be cleared".into(),
            source: None,
        })
    }
}

type DemoSdk = PaykitSdk<PubkySharedStateStorage, DemoSessionProvider, DemoPaymentAdapter>;

#[derive(Serialize)]
struct PrepareOutput {
    version: u8,
    status: &'static str,
    reader_pubky: String,
    app_id: String,
}

#[derive(Serialize)]
struct ReceiveOutput {
    version: u8,
    status: &'static str,
    payment_request_id: String,
    address: String,
    asset: &'static str,
    amount_sats: String,
    payment_command: String,
    optional_mining_command: String,
}

#[derive(Serialize)]
struct InspectOutput {
    version: u8,
    status: &'static str,
    connection_state: &'static str,
}

#[derive(Serialize)]
#[serde(untagged)]
enum SuccessOutput {
    Prepare(PrepareOutput),
    Receive(ReceiveOutput),
    Inspect(InspectOutput),
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            write_failure(failure);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Failure> {
    if std::env::args_os().len() != 1 {
        return Err(Failure::InvalidInput);
    }
    let mut input: Input =
        serde_json::from_reader(io::stdin().lock()).map_err(|_| Failure::InvalidInput)?;
    if input.version != 1 {
        input.reader_secret.zeroize();
        return Err(Failure::InvalidInput);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(input.reader_secret.as_bytes())
        .map_err(|_| Failure::InvalidInput);
    input.reader_secret.zeroize();
    let mut decoded = Zeroizing::new(decoded?);
    let reader_secret = Zeroizing::new(
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| Failure::InvalidInput)?,
    );
    decoded.zeroize();
    let config = load_config()?;
    let output = execute(input.operation, reader_secret, config).await?;
    write_success(&output)
}

async fn execute(
    operation: Operation,
    reader_secret: Zeroizing<[u8; 32]>,
    config: Config,
) -> Result<SuccessOutput, Failure> {
    let receive_deadline =
        matches!(operation, Operation::Receive).then(|| Instant::now() + RECEIVE_TIMEOUT);
    let state_store = EncryptedReaderStateStore::new(config.state_path.clone(), *reader_secret);
    let _state_lock = state_store.try_lock().map_err(|error| match error {
        StateLockError::Busy => Failure::StateBusy,
        StateLockError::Invalid => Failure::InvalidState,
    })?;
    let stored = state_store
        .load_optional()
        .map_err(|_| Failure::InvalidState)?;
    let invariants = config.invariants();
    match (operation, stored) {
        (_, Some(state)) if state == invariants => {}
        (_, Some(_)) => return Err(Failure::InvalidState),
        (Operation::Prepare, None) => {}
        (Operation::Receive | Operation::Inspect, None) => return Err(Failure::InvalidState),
    }

    let pubky = configured_testnet_pubky(&config.testnet_host)?;
    let sdk_config =
        PaykitSdkConfig::new(config.app_id.as_str()).map_err(|_| Failure::InvalidConfig)?;
    let mut session = within_receive_deadline(
        receive_deadline,
        PubkySessionBootstrap::with_pubky(pubky.clone(), PAYKIT_CLIENT_ID)
            .map_err(|_| Failure::ProtocolFailed)?
            .sign_in(
                &PubkyLocalSecretKey::new(*reader_secret),
                paykit_sdk::PAYKIT_SESSION_CAPABILITIES,
            ),
    )
    .await?
    .map_err(|_| Failure::ProtocolFailed)?;
    let reader_pubky = session.public_key;
    let registry = within_receive_deadline(
        receive_deadline,
        paykit_lib::get_paykit_app_registry(
            &pubky.public_storage(),
            &reader_pubky
                .to_public_key()
                .map_err(|_| Failure::ProtocolFailed)?,
        ),
    )
    .await?
    .map_err(|_| Failure::ProtocolFailed)?;
    let generation = registry
        .as_ref()
        .map_or(1, |registry| registry.key_generation());
    let key = PubkyLocalSecretKey::new(*reader_secret)
        .derive_paykit_identity_secret_key(generation)
        .map_err(|_| Failure::ProtocolFailed)?;
    session.access.paykit_identity_secret_key = Some(key);
    let provider = DemoSessionProvider {
        access: session.access,
        pubky,
    };
    let storage = PubkySharedStateStorage::new(provider.clone());
    let sdk = PaykitSdk::new(storage.clone(), provider, DemoPaymentAdapter, sdk_config);
    within_receive_deadline(receive_deadline, sdk.initialize())
        .await?
        .map_err(|_| Failure::ProtocolFailed)?;

    match operation {
        Operation::Prepare => {
            let output = prepare(&sdk, &config, reader_pubky).await?;
            // Protocol state is hosted by the SDK; only the local demo binding is retained.
            state_store
                .save(&invariants)
                .map_err(|_| Failure::InvalidState)?;
            Ok(SuccessOutput::Prepare(output))
        }
        Operation::Receive => receive(
            &sdk,
            &storage,
            &config,
            &reader_pubky,
            receive_deadline.expect("receive operation has a deadline"),
        )
        .await
        .map(SuccessOutput::Receive),
        Operation::Inspect => inspect(&sdk, &config).await.map(SuccessOutput::Inspect),
    }
}

async fn inspect(sdk: &DemoSdk, config: &Config) -> Result<InspectOutput, Failure> {
    let peers = sdk
        .linked_peers()
        .await
        .map_err(|_| Failure::InvalidState)?;
    let state = peers
        .iter()
        .find(|peer| peer.counterparty == config.server_pubky)
        .map(|peer| &peer.state);
    Ok(InspectOutput {
        version: 1,
        status: "inspected",
        connection_state: diagnostic_peer_state(state),
    })
}

fn diagnostic_peer_state(state: Option<&LinkedPeerState>) -> &'static str {
    match state {
        None | Some(LinkedPeerState::NotLinked) => "none",
        Some(LinkedPeerState::Linking) => "handshake",
        Some(LinkedPeerState::Linked) => "connected",
        Some(LinkedPeerState::RecoveryRequired) => "recovery_required",
        Some(LinkedPeerState::Blocked) => "blocked",
        Some(_) => "unknown",
    }
}

async fn within_receive_deadline<F, T>(deadline: Option<Instant>, future: F) -> Result<T, Failure>
where
    F: Future<Output = T>,
{
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| Failure::ReceiveTimeout),
        None => Ok(future.await),
    }
}

fn configured_testnet_pubky(host: &str) -> Result<Pubky, Failure> {
    if host.len() > 253
        || host.is_empty()
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    {
        return Err(Failure::InvalidConfig);
    }
    let mut builder = PubkyHttpClient::builder();
    builder.testnet_with_host(host);
    let client = builder.build().map_err(|_| Failure::InvalidConfig)?;
    Ok(Pubky::with_client(client))
}

async fn prepare(
    sdk: &DemoSdk,
    config: &Config,
    reader_pubky: PubkyPublicKey,
) -> Result<PrepareOutput, Failure> {
    let published = sdk
        .publish_paykit_app(
            paykit_lib::PaykitApp::new(
                "Reader Demo",
                PaykitAppCapabilities {
                    private_payments: true,
                    payment_requests: true,
                    receipts: false,
                    outgoing_payments: true,
                },
            )
            .map_err(|_| Failure::ProtocolFailed)?,
        )
        .await
        .map_err(|_| Failure::ProtocolFailed)?;
    let read_back = sdk
        .paykit_app_registry(reader_pubky.clone())
        .await
        .map_err(|_| Failure::ProtocolFailed)?
        .ok_or(Failure::ProtocolFailed)?;
    if published.apps().get(&config.app_id) != read_back.apps().get(&config.app_id) {
        return Err(Failure::ProtocolFailed);
    }
    Ok(PrepareOutput {
        version: 1,
        status: "prepared",
        reader_pubky: reader_pubky.to_app_key(),
        app_id: config.app_id.as_str().to_owned(),
    })
}

async fn receive(
    sdk: &DemoSdk,
    storage: &PubkySharedStateStorage,
    config: &Config,
    reader_pubky: &PubkyPublicKey,
    deadline: Instant,
) -> Result<ReceiveOutput, Failure> {
    if has_persisted_payment_request_failure(storage, &config.server_pubky, &[]).await? {
        return Err(Failure::ProtocolFailed);
    }
    loop {
        require_receive_time_remaining(deadline)?;
        match sdk
            .ensure_link_with_peer(config.server_pubky.clone(), 8)
            .await
        {
            Ok(report) if report.state == LinkedPeerState::Linked => {}
            Ok(_) => {
                wait_for_next_poll(deadline).await?;
                continue;
            }
            Err(error) if retryable_wait_error(&error) => {
                wait_for_next_poll(deadline).await?;
                continue;
            }
            Err(_) => return Err(Failure::ProtocolFailed),
        }

        match sdk
            .receive_private_messages(config.server_pubky.clone())
            .await
        {
            Ok(report) => {
                if has_persisted_payment_request_failure(
                    storage,
                    &config.server_pubky,
                    &report.event_conflicts,
                )
                .await?
                {
                    return Err(Failure::ProtocolFailed);
                }
            }
            Err(error) if retryable_wait_error(&error) => {
                wait_for_next_poll(deadline).await?;
                continue;
            }
            Err(_) => return Err(Failure::ProtocolFailed),
        }

        sdk.process_outbound_private_messages(config.server_pubky.clone())
            .await
            .map_err(|_| Failure::ProtocolFailed)?;
        let requests = sdk
            .received_payment_requests_from(&config.server_pubky)
            .await
            .map_err(|_| Failure::ProtocolFailed)?;

        let Some(request) = select_actionable_request(&requests)? else {
            wait_for_next_poll(deadline).await?;
            continue;
        };
        let request_id = paykit_lib::PaymentRequestId::new(request.payment_request_id.clone())
            .map_err(|_| Failure::ProtocolFailed)?;
        let resolution = sdk
            .resolve_private_payment_request(config.server_pubky.clone(), &request_id, None)
            .await
            .map_err(|_| Failure::ProtocolFailed)?;
        return payment_instructions(request, &resolution, reader_pubky);
    }
}

fn require_receive_time_remaining(deadline: Instant) -> Result<(), Failure> {
    if Instant::now() >= deadline {
        Err(Failure::ReceiveTimeout)
    } else {
        Ok(())
    }
}

async fn wait_for_next_poll(deadline: Instant) -> Result<(), Failure> {
    require_receive_time_remaining(deadline)?;
    tokio::time::sleep_until(std::cmp::min(Instant::now() + POLL_INTERVAL, deadline)).await;
    require_receive_time_remaining(deadline)
}

fn retryable_wait_error(error: &PaykitSdkError) -> bool {
    matches!(
        error,
        PaykitSdkError::Transport { .. }
            | PaykitSdkError::NotFound { .. }
            | PaykitSdkError::RecoveryRequired { .. }
    )
}

async fn has_persisted_payment_request_failure(
    storage: &PubkySharedStateStorage,
    server_pubky: &PubkyPublicKey,
    event_conflicts: &[EventIdConflict],
) -> Result<bool, Failure> {
    let state = storage
        .transaction(|tx| Ok(tx.export_storage_state()))
        .await
        .map_err(|_| Failure::InvalidState)?;
    Ok(has_malformed_request(&state, server_pubky)
        || has_relevant_event_conflict(&state, server_pubky, event_conflicts))
}

fn has_malformed_request(state: &StorageState, server_pubky: &PubkyPublicKey) -> bool {
    state.private_stream_items.iter().any(|item| {
        &item.counterparty == server_pubky
            && item.parse_status == PrivateStreamParseStatus::MalformedRecognized
            && item.known_paykit_kind.as_deref() == Some("paykit.payment_request")
            && !is_other_app(item.parsed_app_id.as_deref())
    })
}

fn is_other_app(app_id: Option<&str>) -> bool {
    app_id
        .and_then(|app_id| PaykitAppId::new(app_id).ok())
        .is_some_and(|app_id| app_id.as_str() != PAYKIT_APP_ID)
}

fn has_relevant_event_conflict(
    state: &StorageState,
    server_pubky: &PubkyPublicKey,
    event_conflicts: &[EventIdConflict],
) -> bool {
    event_conflicts.iter().any(|conflict| {
        // Both sides must have valid foreign origins; unknown or invalid events stay terminal.
        ![
            conflict.first_stream_item_id,
            conflict.conflicting_stream_item_id,
        ]
        .iter()
        .all(|id| {
            state
                .private_stream_items
                .iter()
                .find(|item| item.stream_item_id == *id)
                .is_some_and(|item| {
                    &item.counterparty == server_pubky
                        && item.parse_status == PrivateStreamParseStatus::Valid
                        && is_other_app(item.parsed_app_id.as_deref())
                })
        })
    })
}

fn write_success(value: &SuccessOutput) -> Result<(), Failure> {
    let mut encoded = serde_json::to_vec(value).map_err(|_| Failure::OutputFailed)?;
    encoded.push(b'\n');
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&encoded)
        .and_then(|()| stdout.flush())
        .map_err(|_| Failure::OutputFailed)
}

fn write_failure(failure: Failure) {
    let message = format!("{{\"version\":1,\"error\":\"{}\"}}\n", failure.code());
    let mut stderr = io::stderr().lock();
    if stderr.write_all(message.as_bytes()).is_ok() {
        let _ = stderr.flush();
    }
}

fn required_env(name: &str) -> Result<String, Failure> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(Failure::InvalidConfig)
}

fn load_config() -> Result<Config, Failure> {
    let state_path = PathBuf::from(required_env(STATE_ENV)?);
    let testnet_host = required_env(TESTNET_HOST_ENV)?;
    let app_id = PaykitAppId::new(required_env(APP_ID_ENV)?).map_err(|_| Failure::InvalidConfig)?;
    let server_pubky = PubkyPublicKey::from_raw_or_app_key(required_env(SERVER_PUBKY_ENV)?)
        .map_err(|_| Failure::InvalidConfig)?;
    configured_testnet_pubky(&testnet_host)?;
    Ok(Config {
        state_path,
        testnet_host,
        app_id,
        server_pubky,
    })
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use paykit_sdk::{
        EventIdConflict, PrivateStreamParseStatus, PubkyPublicKey, storage::PrivateStreamItemRecord,
    };
    use tokio::time::Instant;

    use super::{
        Failure, StorageState, diagnostic_peer_state, has_malformed_request,
        has_relevant_event_conflict, within_receive_deadline,
    };

    fn server_pubky() -> PubkyPublicKey {
        PubkyPublicKey::from_raw_or_app_key(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
        )
        .unwrap()
    }

    fn stream_item(stream_item_id: u64, app_id: Option<&str>) -> PrivateStreamItemRecord {
        PrivateStreamItemRecord {
            stream_item_id,
            counterparty: server_pubky(),
            parsed_app_id: app_id.map(str::to_owned),
            receive_batch_id: 1,
            raw_json: "<malformed>".into(),
            parsed_version: Some(1),
            parsed_kind: Some("paykit.payment_request".into()),
            known_paykit_kind: Some("paykit.payment_request".into()),
            parse_status: PrivateStreamParseStatus::MalformedRecognized,
            parse_error: Some("redacted".into()),
            received_at: "2026-01-01T00:00:00Z".parse().unwrap(),
        }
    }

    fn conflict() -> EventIdConflict {
        EventIdConflict {
            event_id: "8a0d8b4c-913f-4e31-9f2c-2a6f5bb4d101".into(),
            first_stream_item_id: 1,
            conflicting_stream_item_id: 2,
        }
    }

    fn conflict_state(app_ids: [Option<&str>; 2]) -> StorageState {
        let mut state = StorageState::default();
        for (index, app_id) in app_ids.into_iter().enumerate() {
            let mut item = stream_item(index as u64 + 1, app_id);
            item.parse_status = PrivateStreamParseStatus::Valid;
            item.parse_error = None;
            state.private_stream_items.push(item);
        }
        state
    }

    #[test]
    fn peer_state_diagnostics_use_closed_secret_free_labels() {
        assert_eq!(diagnostic_peer_state(None), "none");
        assert_eq!(
            diagnostic_peer_state(Some(&paykit_sdk::LinkedPeerState::NotLinked)),
            "none"
        );
        assert_eq!(
            diagnostic_peer_state(Some(&paykit_sdk::LinkedPeerState::Linking)),
            "handshake"
        );
        assert_eq!(
            diagnostic_peer_state(Some(&paykit_sdk::LinkedPeerState::Linked)),
            "connected"
        );
        assert_eq!(
            diagnostic_peer_state(Some(&paykit_sdk::LinkedPeerState::RecoveryRequired)),
            "recovery_required"
        );
        assert_eq!(
            diagnostic_peer_state(Some(&paykit_sdk::LinkedPeerState::Blocked)),
            "blocked"
        );
    }

    #[tokio::test]
    async fn receive_deadline_bounds_awaits_before_the_poll_loop() {
        let result = within_receive_deadline(
            Some(Instant::now() + Duration::from_millis(1)),
            pending::<()>(),
        )
        .await;
        assert_eq!(result, Err(Failure::ReceiveTimeout));
    }

    #[test]
    fn stored_malformed_payment_requests_are_terminal() {
        let counterparty = server_pubky();
        let mut state = StorageState::default();
        state
            .private_stream_items
            .push(stream_item(1, Some("paykit-server")));
        assert!(has_malformed_request(&state, &counterparty));

        state.private_stream_items[0].known_paykit_kind = Some("paykit.receipt_access".into());
        assert!(!has_malformed_request(&state, &counterparty));
    }

    #[test]
    fn malformed_requests_are_ignored_only_with_valid_other_app_ownership() {
        let mut state = StorageState::default();
        state
            .private_stream_items
            .push(stream_item(1, Some("bitkit")));
        assert!(!has_malformed_request(&state, &server_pubky()));

        for app_id in [None, Some(""), Some("../bitkit"), Some("paykit-server")] {
            state.private_stream_items.push(stream_item(2, app_id));
            assert!(has_malformed_request(&state, &server_pubky()));
            state.private_stream_items.pop();
        }
    }

    #[test]
    fn conflicts_between_valid_other_app_events_are_ignored() {
        for apps in [
            [Some("bitkit"), Some("bitkit")],
            [Some("bitkit"), Some("wallet")],
        ] {
            assert!(!has_relevant_event_conflict(
                &conflict_state(apps),
                &server_pubky(),
                &[conflict()],
            ));
        }
    }

    #[test]
    fn conflicts_with_either_server_event_remain_terminal() {
        for apps in [
            [Some("paykit-server"), Some("bitkit")],
            [Some("bitkit"), Some("paykit-server")],
            [Some("paykit-server"), Some("paykit-server")],
        ] {
            assert!(has_relevant_event_conflict(
                &conflict_state(apps),
                &server_pubky(),
                &[conflict()],
            ));
        }
    }

    #[test]
    fn conflicts_without_two_valid_known_origins_remain_terminal() {
        for index in 0..2 {
            for app_id in [None, Some(""), Some("../bitkit")] {
                let mut apps = [Some("bitkit"); 2];
                apps[index] = app_id;
                assert!(has_relevant_event_conflict(
                    &conflict_state(apps),
                    &server_pubky(),
                    &[conflict()],
                ));
            }

            let mut state = conflict_state([Some("bitkit"); 2]);
            state.private_stream_items[index].parse_status =
                PrivateStreamParseStatus::MalformedRecognized;
            assert!(has_relevant_event_conflict(
                &state,
                &server_pubky(),
                &[conflict()]
            ));

            let mut state = conflict_state([Some("bitkit"); 2]);
            state.private_stream_items[index].counterparty = PubkyPublicKey::from_raw_or_app_key(
                "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo",
            )
            .unwrap();
            assert!(has_relevant_event_conflict(
                &state,
                &server_pubky(),
                &[conflict()]
            ));

            state.private_stream_items.remove(index);
            assert!(has_relevant_event_conflict(
                &state,
                &server_pubky(),
                &[conflict()]
            ));
        }
    }
}
