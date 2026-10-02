use std::{fmt, net::SocketAddr, str::FromStr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use paykit_lib::PaykitAppId;
use pubky::{ClientId, PublicKey};
use rustls_pki_types::ServerName;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgConnectOptions;
use thiserror::Error;
use url::Url;

/// Stable Pubky grant client ID owned by this Paykit Server application.
pub const PAYKIT_CLIENT_ID: &str = "app.paykit.server";

/// Paykit App owning server endpoints and Payment Requests.
pub const PAYKIT_APP_ID: &str = "paykit-server";

#[derive(Debug)]
pub struct Config {
    pub http: HttpConfig,
    pub locks: LocksConfig,
    pub setup: SetupConfig,
    pub paykit: PaykitConfig,
    pub electrum: ElectrumConfig,
    pub outbox: OutboxConfig,
    pub limits: LimitsConfig,
    pub rate_limits: RateLimitsConfig,
    pub shutdown: ShutdownConfig,
    database_url: DatabaseUrl,
    master_key: MasterKey,
    deployment_invariants: DeploymentInvariants,
}

impl Config {
    pub fn from_toml_and_environment(
        toml_source: &str,
        environment: ConfigEnvironment,
    ) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(toml_source).map_err(|_| ConfigError::Toml)?;
        let database_url = DatabaseUrl::parse(environment.database_url)?;
        let master_key = MasterKey::parse(environment.master_key)?;
        let trusted_public_key = TrustedLocksPublicKey::parse(raw.locks.trusted_public_key)?;
        let trusted_locks_key_fingerprint = trusted_public_key.fingerprint();
        let app_id = PaykitAppId::new(raw.paykit.app_id).map_err(|_| ConfigError::InvalidAppId)?;
        if app_id.as_str() != PAYKIT_APP_ID {
            return Err(ConfigError::InvalidAppId);
        }
        let raw_client_id = raw
            .paykit
            .client_id
            .ok_or(ConfigError::MissingPaykitClientId)?;
        let client_id =
            ClientId::new(&raw_client_id).map_err(|_| ConfigError::InvalidPaykitClientId)?;
        if client_id.as_str() != PAYKIT_CLIENT_ID {
            return Err(ConfigError::UnsupportedPaykitClientId);
        }
        let bitcoin_network = BitcoinNetwork::parse(&raw.bitcoin.network)?;

        let listen_addr = raw
            .http
            .listen_addr
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::InvalidListenAddress)?;
        let electrum_endpoint = ElectrumEndpoint::parse(raw.electrum.endpoint)?;
        let allowed_origins = validate_allowed_origins(raw.setup.allowed_origins)?;

        let config = Self {
            http: HttpConfig { listen_addr },
            locks: LocksConfig { trusted_public_key },
            setup: SetupConfig {
                allowed_origins,
                log_authorization_url: raw.setup.log_authorization_url,
            },
            paykit: PaykitConfig {
                client_id: client_id.clone(),
                app_id: app_id.clone(),
                network: PaykitNetwork::parse(&raw.paykit.network)?,
                proposal_acceptance_window: raw.paykit.proposal_acceptance_window,
                payment_window: raw.paykit.payment_window,
            },
            electrum: ElectrumConfig {
                endpoint: electrum_endpoint,
                poll_interval: raw.electrum.poll_interval,
                request_timeout: raw.electrum.request_timeout,
                connect_retries: raw.electrum.connect_retries,
            },
            outbox: OutboxConfig::from(raw.outbox),
            limits: LimitsConfig::from(raw.limits),
            rate_limits: RateLimitsConfig::from(raw.rate_limits),
            shutdown: ShutdownConfig::from(raw.shutdown),
            database_url,
            master_key,
            deployment_invariants: DeploymentInvariants {
                bitcoin_network,
                paykit_client_id: client_id,
                app_id,
                trusted_locks_key_fingerprint,
            },
        };
        config.validate_operational_values()?;
        Ok(config)
    }

    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    pub(crate) fn database_options(&self) -> &PgConnectOptions {
        self.database_url.options()
    }

    pub fn deployment_invariants(&self) -> &DeploymentInvariants {
        &self.deployment_invariants
    }

    pub fn redacted_effective_config(&self) -> String {
        format!("{self:#?}")
    }

    fn validate_operational_values(&self) -> Result<(), ConfigError> {
        for (name, value) in [
            ("electrum.poll_interval", self.electrum.poll_interval),
            ("electrum.request_timeout", self.electrum.request_timeout),
            ("outbox.poll_interval", self.outbox.poll_interval),
            ("outbox.lease_duration", self.outbox.lease_duration),
            ("outbox.retry_initial", self.outbox.retry_initial),
            ("outbox.retry_max", self.outbox.retry_max),
            ("limits.lock_fetch_timeout", self.limits.lock_fetch_timeout),
            ("shutdown.drain_timeout", self.shutdown.drain_timeout),
        ] {
            if value.is_zero() {
                return Err(ConfigError::ZeroDuration(name));
            }
        }
        for (name, value) in [
            ("outbox.batch_size", u64::from(self.outbox.batch_size)),
            ("limits.request_body_bytes", self.limits.request_body_bytes),
            (
                "limits.lock_resource_bytes",
                self.limits.lock_resource_bytes,
            ),
            (
                "rate_limits.signed_requests_per_second",
                self.rate_limits.signed_requests_per_second,
            ),
            ("rate_limits.signed_burst", self.rate_limits.signed_burst),
            (
                "rate_limits.setup_per_ip_per_minute",
                self.rate_limits.setup_per_ip_per_minute,
            ),
            (
                "rate_limits.max_pending_setup_flows",
                self.rate_limits.max_pending_setup_flows,
            ),
            (
                "rate_limits.max_completion_polls_per_flow",
                self.rate_limits.max_completion_polls_per_flow,
            ),
            (
                "rate_limits.max_completion_polls",
                self.rate_limits.max_completion_polls,
            ),
        ] {
            if value == 0 {
                return Err(ConfigError::ZeroValue(name));
            }
        }
        for (name, value) in [
            ("outbox.lease_duration", self.outbox.lease_duration),
            ("outbox.retry_initial", self.outbox.retry_initial),
            ("outbox.retry_max", self.outbox.retry_max),
        ] {
            if value < Duration::from_secs(1) {
                return Err(ConfigError::SubsecondPersistenceDuration(name));
            }
        }
        if self.outbox.retry_initial > self.outbox.retry_max {
            return Err(ConfigError::InconsistentRetries("outbox"));
        }
        if self.paykit.proposal_acceptance_window.is_zero()
            || self.paykit.proposal_acceptance_window.subsec_nanos() != 0
            || self.paykit.payment_window.subsec_nanos() != 0
            || self.paykit.proposal_acceptance_window >= self.paykit.payment_window
        {
            return Err(ConfigError::InvalidInvoiceWindows);
        }
        if self.rate_limits.max_pending_setup_flows > tokio::sync::Semaphore::MAX_PERMITS as u64 {
            return Err(ConfigError::ValueTooLarge(
                "rate_limits.max_pending_setup_flows",
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct ConfigEnvironment {
    pub database_url: Option<String>,
    pub master_key: Option<String>,
}

impl fmt::Debug for ConfigEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigEnvironment")
            .field("database_url", &"<redacted>")
            .field("master_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentInvariants {
    pub bitcoin_network: BitcoinNetwork,
    pub paykit_client_id: ClientId,
    pub app_id: PaykitAppId,
    pub trusted_locks_key_fingerprint: TrustedLocksKeyFingerprint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(ConfigError::InvalidNetwork),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    pub(crate) const fn as_bitcoin_network(&self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Testnet => bitcoin::Network::Testnet,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TrustedLocksPublicKey([u8; 32]);

impl TrustedLocksPublicKey {
    fn parse(value: String) -> Result<Self, ConfigError> {
        let public_key = PublicKey::try_from(value.as_str())
            .map_err(|_| ConfigError::InvalidTrustedLocksPublicKey)?;
        if public_key.to_string() != value {
            return Err(ConfigError::InvalidTrustedLocksPublicKey);
        }
        let bytes = public_key.to_bytes();
        VerifyingKey::from_bytes(&bytes).map_err(|_| ConfigError::InvalidTrustedLocksPublicKey)?;
        Ok(Self(bytes))
    }

    fn fingerprint(&self) -> TrustedLocksKeyFingerprint {
        TrustedLocksKeyFingerprint(Sha256::digest(self.0).into())
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.0).expect("validated trusted Locks public key")
    }
}

impl fmt::Debug for TrustedLocksPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedLocksKeyFingerprint([u8; 32]);

impl TrustedLocksKeyFingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    fn parse(value: Option<String>) -> Result<Self, ConfigError> {
        let value = value.ok_or(ConfigError::MissingMasterKey)?;
        let bytes = decode_base64url_no_pad(&value, ConfigError::InvalidMasterKey)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ConfigError::InvalidMasterKey)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Debug)]
pub struct HttpConfig {
    listen_addr: SocketAddr,
}

impl HttpConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

#[derive(Debug)]
pub struct LocksConfig {
    pub trusted_public_key: TrustedLocksPublicKey,
}

#[derive(Debug)]
pub struct SetupConfig {
    pub allowed_origins: Vec<String>,
    pub log_authorization_url: bool,
}

#[derive(Clone, Debug)]
pub struct PaykitConfig {
    pub client_id: ClientId,
    pub app_id: PaykitAppId,
    pub network: PaykitNetwork,
    pub proposal_acceptance_window: Duration,
    pub payment_window: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaykitNetwork {
    Mainnet,
    Testnet,
}

impl PaykitNetwork {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            _ => Err(ConfigError::InvalidPaykitNetwork),
        }
    }
}

#[derive(Debug)]
pub struct ElectrumConfig {
    endpoint: ElectrumEndpoint,
    pub poll_interval: Duration,
    pub request_timeout: Duration,
    pub connect_retries: u8,
}

impl ElectrumConfig {
    pub fn endpoint(&self) -> &str {
        self.endpoint.as_str()
    }
}

#[derive(Debug)]
pub struct OutboxConfig {
    pub poll_interval: Duration,
    pub batch_size: u32,
    pub lease_duration: Duration,
    pub retry_initial: Duration,
    pub retry_max: Duration,
}

#[derive(Debug)]
pub struct LimitsConfig {
    pub request_body_bytes: u64,
    pub lock_resource_bytes: u64,
    pub lock_fetch_timeout: Duration,
}

#[derive(Debug)]
pub struct RateLimitsConfig {
    pub signed_requests_per_second: u64,
    pub signed_burst: u64,
    pub setup_per_ip_per_minute: u64,
    max_pending_setup_flows: u64,
    pub max_completion_polls_per_flow: u64,
    pub max_completion_polls: u64,
}

impl RateLimitsConfig {
    pub fn max_pending_setup_flows(&self) -> usize {
        usize::try_from(self.max_pending_setup_flows)
            .expect("validated pending setup limit fits usize")
    }
}

#[derive(Debug)]
pub struct ShutdownConfig {
    pub drain_timeout: Duration,
}

struct DatabaseUrl(PgConnectOptions);

impl DatabaseUrl {
    fn parse(value: Option<String>) -> Result<Self, ConfigError> {
        let value = value.ok_or(ConfigError::MissingDatabaseUrl)?;
        let parsed = validate_url("PAYKIT_DATABASE_URL", &value)?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql") {
            return Err(ConfigError::InvalidDatabaseUrlScheme);
        }
        if parsed
            .query_pairs()
            .any(|(key, _)| !supported_postgres_query_key(&key))
        {
            return Err(ConfigError::InvalidDatabaseUrl);
        }
        let options =
            PgConnectOptions::from_str(&value).map_err(|_| ConfigError::InvalidDatabaseUrl)?;
        Ok(Self(options))
    }

    fn options(&self) -> &PgConnectOptions {
        &self.0
    }
}

fn supported_postgres_query_key(key: &str) -> bool {
    matches!(
        key,
        "sslmode"
            | "ssl-mode"
            | "sslrootcert"
            | "ssl-root-cert"
            | "ssl-ca"
            | "sslcert"
            | "ssl-cert"
            | "sslkey"
            | "ssl-key"
            | "statement-cache-capacity"
            | "host"
            | "hostaddr"
            | "port"
            | "dbname"
            | "user"
            | "password"
            | "application_name"
            | "options"
    ) || key
        .strip_prefix("options[")
        .and_then(|key| key.strip_suffix(']'))
        .is_some_and(|key| !key.is_empty())
}

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

struct ElectrumEndpoint(String);

impl ElectrumEndpoint {
    fn parse(value: String) -> Result<Self, ConfigError> {
        validate_electrum_endpoint(&value)?;
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ElectrumEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration TOML is invalid")]
    Toml,
    #[error("PAYKIT_DATABASE_URL is required")]
    MissingDatabaseUrl,
    #[error("PAYKIT_MASTER_KEY is required")]
    MissingMasterKey,
    #[error("PAYKIT_DATABASE_URL must use postgres:// or postgresql://")]
    InvalidDatabaseUrlScheme,
    #[error("PAYKIT_DATABASE_URL is invalid")]
    InvalidDatabaseUrl,
    #[error("PAYKIT_MASTER_KEY must be unpadded base64url encoding of exactly 32 bytes")]
    InvalidMasterKey,
    #[error("locks.trusted_public_key must be a canonical pubky-prefixed public key")]
    InvalidTrustedLocksPublicKey,
    #[error("bitcoin.network must be mainnet, testnet, signet, or regtest")]
    InvalidNetwork,
    #[error("{0} must be a valid absolute URL")]
    InvalidUrl(&'static str),
    #[error("http.listen_addr must be a valid socket address")]
    InvalidListenAddress,
    #[error(
        "electrum.endpoint must be an exact tcp://host:nonzero-port or ssl://DNS-or-IPv4:nonzero-port URL"
    )]
    InvalidElectrumEndpoint,
    #[error(
        "setup.allowed_origins must contain exact HTTP(S) origins or the sole wildcard value *"
    )]
    InvalidOrigin,
    #[error("paykit.app_id must be paykit-server")]
    InvalidAppId,
    #[error("paykit.client_id must be a valid non-empty Pubky client ID")]
    InvalidPaykitClientId,
    #[error("paykit.client_id is required")]
    MissingPaykitClientId,
    #[error("paykit.client_id must be app.paykit.server")]
    UnsupportedPaykitClientId,
    #[error("paykit.network must be mainnet or testnet")]
    InvalidPaykitNetwork,
    #[error("paykit.receiver_path_priority entries must be canonical Paykit receiver app segments")]
    InvalidReceiverPathPriority,
    #[error("paykit.receiver_path_priority must not be empty")]
    EmptyReceiverPathPriority,
    #[error("paykit.receiver_path_priority must not contain duplicates")]
    DuplicateReceiverPathPriority,
    #[error("paykit proposal acceptance window must be positive and shorter than payment window")]
    InvalidInvoiceWindows,
    #[error("{0} must be greater than zero")]
    ZeroDuration(&'static str),
    #[error("{0} must be greater than zero")]
    ZeroValue(&'static str),
    #[error("{0} exceeds the supported maximum")]
    ValueTooLarge(&'static str),
    #[error("{0} must be at least one second")]
    SubsecondPersistenceDuration(&'static str),
    #[error("{0}.retry_initial must not exceed {0}.retry_max")]
    InconsistentRetries(&'static str),
}

fn decode_base64url_no_pad(value: &str, error: ConfigError) -> Result<Vec<u8>, ConfigError> {
    if value.contains('=') {
        return Err(error);
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|_| error)
}

fn validate_url(field: &'static str, value: &str) -> Result<Url, ConfigError> {
    let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidUrl(field))?;
    if parsed.cannot_be_a_base() || parsed.host_str().is_none() {
        return Err(ConfigError::InvalidUrl(field));
    }
    Ok(parsed)
}

pub(crate) fn validate_electrum_endpoint(value: &str) -> Result<(), ConfigError> {
    let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidElectrumEndpoint)?;
    if !matches!(parsed.scheme(), "tcp" | "ssl")
        || parsed.host_str().is_none()
        || parsed.port().is_none()
        || parsed.port() == Some(0)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !parsed.path().is_empty()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.as_str() != value
        || (parsed.scheme() == "ssl" && matches!(parsed.host(), Some(url::Host::Ipv6(_))))
    {
        return Err(ConfigError::InvalidElectrumEndpoint);
    }
    if parsed.scheme() == "ssl"
        && ServerName::try_from(parsed.host_str().expect("validated host").to_owned()).is_err()
    {
        return Err(ConfigError::InvalidElectrumEndpoint);
    }
    Ok(())
}

fn validate_origin(value: &str) -> Result<Url, ConfigError> {
    let parsed =
        validate_url("setup.allowed_origins", value).map_err(|_| ConfigError::InvalidOrigin)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_some_and(|host| host.contains('*'))
    {
        return Err(ConfigError::InvalidOrigin);
    }
    Ok(parsed)
}

fn validate_allowed_origins(values: Vec<String>) -> Result<Vec<String>, ConfigError> {
    if values.iter().any(|value| value == "*") {
        return (values.len() == 1)
            .then(|| vec!["*".to_owned()])
            .ok_or(ConfigError::InvalidOrigin);
    }

    values
        .into_iter()
        .map(|origin| validate_origin(&origin).map(|_| origin))
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    http: RawHttpConfig,
    locks: RawLocksConfig,
    setup: RawSetupConfig,
    paykit: RawPaykitConfig,
    bitcoin: RawBitcoinConfig,
    electrum: RawElectrumConfig,
    outbox: RawOutboxConfig,
    #[serde(default)]
    limits: RawLimitsConfig,
    #[serde(default)]
    rate_limits: RawRateLimitsConfig,
    #[serde(default)]
    shutdown: RawShutdownConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHttpConfig {
    listen_addr: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLocksConfig {
    trusted_public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSetupConfig {
    allowed_origins: Vec<String>,
    #[serde(default)]
    log_authorization_url: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPaykitConfig {
    client_id: Option<String>,
    app_id: String,
    network: String,
    #[serde(
        default = "default_proposal_acceptance_window",
        with = "humantime_serde"
    )]
    proposal_acceptance_window: Duration,
    #[serde(default = "default_payment_window", with = "humantime_serde")]
    payment_window: Duration,
}

const fn default_proposal_acceptance_window() -> Duration {
    Duration::from_secs(60 * 60)
}

const fn default_payment_window() -> Duration {
    Duration::from_secs(24 * 60 * 60)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBitcoinConfig {
    network: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawElectrumConfig {
    endpoint: String,
    #[serde(default = "default_electrum_poll_interval", with = "humantime_serde")]
    poll_interval: Duration,
    #[serde(default = "default_electrum_request_timeout", with = "humantime_serde")]
    request_timeout: Duration,
    #[serde(default = "default_electrum_connect_retries")]
    connect_retries: u8,
}

fn default_electrum_request_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_electrum_connect_retries() -> u8 {
    1
}

fn default_outbox_batch_size() -> u32 {
    16
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOutboxConfig {
    #[serde(with = "humantime_serde")]
    poll_interval: Duration,
    #[serde(default = "default_outbox_batch_size")]
    batch_size: u32,
    #[serde(default = "default_lease_duration", with = "humantime_serde")]
    lease_duration: Duration,
    #[serde(default = "default_retry_initial", with = "humantime_serde")]
    retry_initial: Duration,
    #[serde(default = "default_outbox_retry_max", with = "humantime_serde")]
    retry_max: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimitsConfig {
    #[serde(default = "default_request_body_bytes")]
    request_body_bytes: u64,
    #[serde(default = "default_lock_resource_bytes")]
    lock_resource_bytes: u64,
    #[serde(default = "default_lock_fetch_timeout", with = "humantime_serde")]
    lock_fetch_timeout: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRateLimitsConfig {
    #[serde(default = "default_signed_requests_per_second")]
    signed_requests_per_second: u64,
    #[serde(default = "default_signed_burst")]
    signed_burst: u64,
    #[serde(default = "default_setup_per_ip_per_minute")]
    setup_per_ip_per_minute: u64,
    #[serde(default = "default_max_pending_setup_flows")]
    max_pending_setup_flows: u64,
    #[serde(default = "default_max_completion_polls_per_flow")]
    max_completion_polls_per_flow: u64,
    #[serde(default = "default_max_completion_polls")]
    max_completion_polls: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShutdownConfig {
    #[serde(default = "default_shutdown_drain_timeout", with = "humantime_serde")]
    drain_timeout: Duration,
}

impl Default for RawLimitsConfig {
    fn default() -> Self {
        Self {
            request_body_bytes: default_request_body_bytes(),
            lock_resource_bytes: default_lock_resource_bytes(),
            lock_fetch_timeout: default_lock_fetch_timeout(),
        }
    }
}

impl Default for RawRateLimitsConfig {
    fn default() -> Self {
        Self {
            signed_requests_per_second: default_signed_requests_per_second(),
            signed_burst: default_signed_burst(),
            setup_per_ip_per_minute: default_setup_per_ip_per_minute(),
            max_pending_setup_flows: default_max_pending_setup_flows(),
            max_completion_polls_per_flow: default_max_completion_polls_per_flow(),
            max_completion_polls: default_max_completion_polls(),
        }
    }
}

impl Default for RawShutdownConfig {
    fn default() -> Self {
        Self {
            drain_timeout: default_shutdown_drain_timeout(),
        }
    }
}

impl From<RawOutboxConfig> for OutboxConfig {
    fn from(value: RawOutboxConfig) -> Self {
        Self {
            poll_interval: value.poll_interval,
            batch_size: value.batch_size,
            lease_duration: value.lease_duration,
            retry_initial: value.retry_initial,
            retry_max: value.retry_max,
        }
    }
}

impl From<RawLimitsConfig> for LimitsConfig {
    fn from(value: RawLimitsConfig) -> Self {
        Self {
            request_body_bytes: value.request_body_bytes,
            lock_resource_bytes: value.lock_resource_bytes,
            lock_fetch_timeout: value.lock_fetch_timeout,
        }
    }
}

impl From<RawRateLimitsConfig> for RateLimitsConfig {
    fn from(value: RawRateLimitsConfig) -> Self {
        Self {
            signed_requests_per_second: value.signed_requests_per_second,
            signed_burst: value.signed_burst,
            setup_per_ip_per_minute: value.setup_per_ip_per_minute,
            max_pending_setup_flows: value.max_pending_setup_flows,
            max_completion_polls_per_flow: value.max_completion_polls_per_flow,
            max_completion_polls: value.max_completion_polls,
        }
    }
}

impl From<RawShutdownConfig> for ShutdownConfig {
    fn from(value: RawShutdownConfig) -> Self {
        Self {
            drain_timeout: value.drain_timeout,
        }
    }
}

const fn default_electrum_poll_interval() -> Duration {
    Duration::from_secs(10)
}
const fn default_lease_duration() -> Duration {
    Duration::from_secs(30)
}
const fn default_retry_initial() -> Duration {
    Duration::from_secs(1)
}
const fn default_outbox_retry_max() -> Duration {
    Duration::from_secs(5 * 60)
}

const fn default_request_body_bytes() -> u64 {
    16 * 1024
}
const fn default_lock_resource_bytes() -> u64 {
    256 * 1024
}
const fn default_lock_fetch_timeout() -> Duration {
    Duration::from_secs(10)
}
const fn default_signed_requests_per_second() -> u64 {
    100
}
const fn default_signed_burst() -> u64 {
    200
}
const fn default_setup_per_ip_per_minute() -> u64 {
    10
}
const fn default_max_pending_setup_flows() -> u64 {
    100
}
const fn default_max_completion_polls_per_flow() -> u64 {
    2
}
const fn default_max_completion_polls() -> u64 {
    200
}
const fn default_shutdown_drain_timeout() -> Duration {
    Duration::from_secs(30)
}
