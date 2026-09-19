#[path = "paykit-reader-demo/payment_instructions.rs"]
mod payment_instructions;
#[path = "paykit-reader-demo/state.rs"]
mod state;

use std::{
    future::Future,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use paykit_sdk::{
    LinkedPeerState, PaykitReceiverCapabilities, PaykitReceiverPath, PaykitSdk, PaykitSdkConfig,
    PaykitSdkError, PrivateStreamParseStatus, PubkyLocalSecretKey, PubkyPublicKey,
    PubkySessionAccess, PubkySessionBootstrap, PubkySessionProvider, ReceiverNoiseSecretKey,
    storage::{
        StorageAdapter, StorageState, StorageTransactionCallback, run_storage_state_transaction,
    },
};
use paykit_server::paykit::ExplicitInputsPaymentAdapter;
use pubky::{Pubky, PubkyHttpClient};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

use payment_instructions::{payment_instructions, select_actionable_request};
use state::{EncryptedReaderStateStore, ReaderState, StateInvariants, StateLockError};

const STATE_ENV: &str = "PAYKIT_READER_STATE_PATH";
const TESTNET_HOST_ENV: &str = "PAYKIT_READER_PUBKY_TESTNET_HOST";
const LOCAL_PATH_ENV: &str = "PAYKIT_READER_RECEIVER_PATH";
const SERVER_PUBKY_ENV: &str = "PAYKIT_READER_SERVER_PUBKY";
const SERVER_PATH_ENV: &str = "PAYKIT_READER_SERVER_PATH";
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
}

struct Config {
    state_path: PathBuf,
    testnet_host: String,
    local_receiver_path: PaykitReceiverPath,
    server_pubky: PubkyPublicKey,
    server_receiver_path: PaykitReceiverPath,
}

impl Config {
    fn invariants(&self) -> StateInvariants {
        StateInvariants {
            local_receiver_path: self.local_receiver_path.as_str().to_owned(),
            server_pubky: self.server_pubky.to_app_key(),
            server_receiver_path: self.server_receiver_path.as_str().to_owned(),
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
struct DemoStorage(Arc<Mutex<StorageState>>);

#[async_trait]
impl StorageAdapter for DemoStorage {
    async fn transaction_erased<'a>(
        &self,
        callback: StorageTransactionCallback<'a>,
    ) -> paykit_sdk::Result<Box<dyn std::any::Any + Send>> {
        let mut state = self.0.lock().map_err(|_| PaykitSdkError::Storage {
            context: "reader state lock poisoned".into(),
            source: None,
        })?;
        let (updated, result) = run_storage_state_transaction(state.clone(), callback)?;
        *state = updated;
        Ok(result)
    }
}

impl DemoStorage {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(StorageState::default())))
    }

    fn snapshot(&self) -> Result<StorageState, Failure> {
        self.0
            .lock()
            .map(|state| state.clone())
            .map_err(|_| Failure::InvalidState)
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

type DemoSdk = PaykitSdk<DemoStorage, DemoSessionProvider, ExplicitInputsPaymentAdapter>;

#[derive(Serialize)]
struct PrepareOutput {
    version: u8,
    status: &'static str,
    reader_pubky: String,
    receiver_path: String,
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
#[serde(untagged)]
enum SuccessOutput {
    Prepare(PrepareOutput),
    Receive(ReceiveOutput),
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
    let (sdk_backup, receiver_noise_secret) = match (operation, stored) {
        (_, Some(state)) if state.invariants == invariants => {
            (Some(state.sdk_state), state.receiver_noise_secret)
        }
        (_, Some(_)) => return Err(Failure::InvalidState),
        (Operation::Prepare, None) => (
            None,
            Zeroizing::new(*ReceiverNoiseSecretKey::random().as_bytes()),
        ),
        (Operation::Receive, None) => return Err(Failure::InvalidState),
    };

    let pubky = configured_testnet_pubky(&config.testnet_host)?;
    let sdk_config = PaykitSdkConfig::new(config.local_receiver_path.clone());
    let session = within_receive_deadline(
        receive_deadline,
        PubkySessionBootstrap::with_pubky(pubky.clone(), "paykit.test")
            .unwrap()
            .sign_in(
                &PubkyLocalSecretKey::new(*reader_secret),
                ReceiverNoiseSecretKey::new(*receiver_noise_secret),
                &sdk_config.required_session_capabilities(),
            ),
    )
    .await?
    .map_err(|_| Failure::ProtocolFailed)?;
    let reader_pubky = session.public_key;
    let storage = DemoStorage::new();
    let sdk = PaykitSdk::new(
        storage.clone(),
        DemoSessionProvider {
            access: session.access,
            pubky,
        },
        ExplicitInputsPaymentAdapter,
        sdk_config,
    )
    .map_err(|_| Failure::ProtocolFailed)?;
    within_receive_deadline(receive_deadline, sdk.initialize())
        .await?
        .map_err(|_| Failure::ProtocolFailed)?;
    if let Some(backup) = sdk_backup {
        within_receive_deadline(receive_deadline, sdk.restore_backup_state(backup))
            .await?
            .map_err(|_| Failure::InvalidState)?;
        within_receive_deadline(receive_deadline, sdk.initialize())
            .await?
            .map_err(|_| Failure::InvalidState)?;
    }

    checkpoint(&sdk, &state_store, &receiver_noise_secret, &invariants).await?;

    match operation {
        Operation::Prepare => {
            let output = prepare(&sdk, &config, reader_pubky).await?;
            checkpoint(&sdk, &state_store, &receiver_noise_secret, &invariants).await?;
            Ok(SuccessOutput::Prepare(output))
        }
        Operation::Receive => {
            let result = receive(
                &sdk,
                &storage,
                &state_store,
                &receiver_noise_secret,
                &invariants,
                &config,
                &reader_pubky,
                receive_deadline.expect("receive operation has a deadline"),
            )
            .await;
            checkpoint(&sdk, &state_store, &receiver_noise_secret, &invariants).await?;
            result.map(SuccessOutput::Receive)
        }
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

async fn checkpoint(
    sdk: &DemoSdk,
    store: &EncryptedReaderStateStore,
    receiver_noise_secret: &Zeroizing<[u8; 32]>,
    invariants: &StateInvariants,
) -> Result<(), Failure> {
    let sdk_state = sdk
        .export_backup_state()
        .await
        .map_err(|_| Failure::InvalidState)?;
    store
        .save(&ReaderState {
            sdk_state,
            receiver_noise_secret: Zeroizing::new(**receiver_noise_secret),
            invariants: invariants.clone(),
        })
        .map_err(|_| Failure::InvalidState)
}

async fn prepare(
    sdk: &DemoSdk,
    config: &Config,
    reader_pubky: PubkyPublicKey,
) -> Result<PrepareOutput, Failure> {
    let published = sdk
        .publish_paykit_receiver_marker(PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: false,
        })
        .await
        .map_err(|_| Failure::ProtocolFailed)?;
    let read_back = sdk
        .paykit_receiver_marker(reader_pubky.clone(), config.local_receiver_path.clone())
        .await
        .map_err(|_| Failure::ProtocolFailed)?
        .ok_or(Failure::ProtocolFailed)?;
    if published != read_back {
        return Err(Failure::ProtocolFailed);
    }
    Ok(PrepareOutput {
        version: 1,
        status: "prepared",
        reader_pubky: reader_pubky.to_app_key(),
        receiver_path: config.local_receiver_path.as_str().to_owned(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn receive(
    sdk: &DemoSdk,
    storage: &DemoStorage,
    state_store: &EncryptedReaderStateStore,
    receiver_noise_secret: &Zeroizing<[u8; 32]>,
    invariants: &StateInvariants,
    config: &Config,
    reader_pubky: &PubkyPublicKey,
    deadline: Instant,
) -> Result<ReceiveOutput, Failure> {
    if has_persisted_malformed_payment_request(
        storage,
        &config.server_pubky,
        &config.server_receiver_path,
    )? {
        return Err(Failure::ProtocolFailed);
    }
    loop {
        require_receive_time_remaining(deadline)?;
        match sdk
            .ensure_link_with_peer(
                config.server_pubky.clone(),
                config.server_receiver_path.clone(),
                8,
            )
            .await
        {
            Ok(report) if report.state == LinkedPeerState::Linked => {}
            Ok(_) => {
                checkpoint(sdk, state_store, receiver_noise_secret, invariants).await?;
                wait_for_next_poll(deadline).await?;
                continue;
            }
            Err(error) if retryable_wait_error(&error) => {
                checkpoint(sdk, state_store, receiver_noise_secret, invariants).await?;
                wait_for_next_poll(deadline).await?;
                continue;
            }
            Err(_) => return Err(Failure::ProtocolFailed),
        }
        checkpoint(sdk, state_store, receiver_noise_secret, invariants).await?;

        match sdk
            .receive_private_messages(
                config.server_pubky.clone(),
                config.server_receiver_path.clone(),
            )
            .await
        {
            Ok(report) => {
                checkpoint(sdk, state_store, receiver_noise_secret, invariants).await?;
                if !report.event_conflicts.is_empty()
                    || has_persisted_malformed_payment_request(
                        storage,
                        &config.server_pubky,
                        &config.server_receiver_path,
                    )?
                {
                    return Err(Failure::ProtocolFailed);
                }
            }
            Err(error) if retryable_wait_error(&error) => {
                checkpoint(sdk, state_store, receiver_noise_secret, invariants).await?;
                wait_for_next_poll(deadline).await?;
                continue;
            }
            Err(_) => return Err(Failure::ProtocolFailed),
        }

        let requests = sdk
            .received_payment_requests_from(&config.server_pubky, &config.server_receiver_path)
            .await
            .map_err(|_| Failure::ProtocolFailed)?;
        let private_list = sdk
            .current_private_payment_list(&config.server_pubky, &config.server_receiver_path)
            .await
            .map_err(|_| Failure::ProtocolFailed)?;
        checkpoint(sdk, state_store, receiver_noise_secret, invariants).await?;

        let Some(request) = select_actionable_request(&requests)? else {
            wait_for_next_poll(deadline).await?;
            continue;
        };
        let Some(private_list) = private_list.as_ref() else {
            wait_for_next_poll(deadline).await?;
            continue;
        };
        return payment_instructions(request, private_list, reader_pubky);
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

fn has_persisted_malformed_payment_request(
    storage: &DemoStorage,
    server_pubky: &PubkyPublicKey,
    server_receiver_path: &PaykitReceiverPath,
) -> Result<bool, Failure> {
    Ok(storage.snapshot()?.private_stream_items.iter().any(|item| {
        &item.counterparty == server_pubky
            && &item.counterparty_receiver_path == server_receiver_path
            && item.parse_status == PrivateStreamParseStatus::MalformedRecognized
            && item.known_paykit_kind.as_deref() == Some("paykit.payment_request")
    }))
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
    let local_receiver_path = PaykitReceiverPath::new(required_env(LOCAL_PATH_ENV)?)
        .map_err(|_| Failure::InvalidConfig)?;
    let server_pubky = PubkyPublicKey::from_raw_or_app_key(required_env(SERVER_PUBKY_ENV)?)
        .map_err(|_| Failure::InvalidConfig)?;
    let server_receiver_path = PaykitReceiverPath::new(required_env(SERVER_PATH_ENV)?)
        .map_err(|_| Failure::InvalidConfig)?;
    configured_testnet_pubky(&testnet_host)?;
    Ok(Config {
        state_path,
        testnet_host,
        local_receiver_path,
        server_pubky,
        server_receiver_path,
    })
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use paykit_sdk::{
        PaykitReceiverPath, PrivateStreamParseStatus, PubkyPublicKey,
        storage::PrivateStreamItemRecord,
    };
    use tokio::time::Instant;

    use super::{
        DemoStorage, Failure, has_persisted_malformed_payment_request, within_receive_deadline,
    };

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
    fn malformed_payment_request_remains_terminal_after_checkpoint_and_restart() {
        let counterparty = PubkyPublicKey::from_raw_or_app_key(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
        )
        .unwrap();
        let receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
        let storage = DemoStorage::new();
        storage
            .0
            .lock()
            .unwrap()
            .private_stream_items
            .push(PrivateStreamItemRecord {
                stream_item_id: 1,
                counterparty: counterparty.clone(),
                counterparty_receiver_path: receiver_path.clone(),
                receive_batch_id: 1,
                raw_json: "<malformed>".into(),
                parsed_version: Some(1),
                parsed_kind: Some("paykit.payment_request".into()),
                known_paykit_kind: Some("paykit.payment_request".into()),
                parse_status: PrivateStreamParseStatus::MalformedRecognized,
                parse_error: Some("redacted".into()),
                received_at: "2026-01-01T00:00:00Z".parse().unwrap(),
            });
        assert!(
            has_persisted_malformed_payment_request(&storage, &counterparty, &receiver_path)
                .unwrap()
        );

        storage.0.lock().unwrap().private_stream_items[0].known_paykit_kind =
            Some("paykit.receipt_access".into());
        assert!(
            !has_persisted_malformed_payment_request(&storage, &counterparty, &receiver_path)
                .unwrap()
        );
    }
}
