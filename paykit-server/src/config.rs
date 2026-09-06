use std::{fmt, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use paykit_lib::PaykitReceiverPath;
use pubky::PublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

#[derive(Debug)]
pub struct Config {
    pub http: HttpConfig,
    pub locks: LocksConfig,
    /// Optional marketplace transaction-service trust anchors. When present,
    /// requests signed by any of these keys are accepted on the signed
    /// business routes (payment requests and status lookups) exactly like
    /// Lock Server signatures.
    pub marketplace: Option<MarketplaceConfig>,
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
        let raw: RawConfig = toml::from_str(toml_source).map_err(ConfigError::Toml)?;
        let database_url = DatabaseUrl::parse(environment.database_url)?;
        let master_key = MasterKey::parse(environment.master_key)?;
        let trusted_public_key = TrustedLocksPublicKey::parse(raw.locks.trusted_public_key)?;
        let trusted_locks_key_fingerprint = trusted_public_key.fingerprint();
        let receiver_path = PaykitReceiverPath::new(raw.paykit.receiver_path)
            .map_err(|_| ConfigError::InvalidReceiverPath)?;
        let receiver_path_priority = raw
            .paykit
            .receiver_path_priority
            .into_iter()
            .map(ReceiverPathPriority::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if receiver_path_priority.is_empty() {
            return Err(ConfigError::EmptyReceiverPathPriority);
        }
        let mut seen_priority = std::collections::HashSet::new();
        if receiver_path_priority
            .iter()
            .any(|segment| !seen_priority.insert(segment.as_str()))
        {
            return Err(ConfigError::DuplicateReceiverPathPriority);
        }
        let bitcoin_network = BitcoinNetwork::parse(&raw.bitcoin.network)?;

        validate_url("electrum.endpoint", &raw.electrum.endpoint)?;
        let allowed_origins = validate_allowed_origins(raw.setup.allowed_origins)?;
        let marketplace = raw.marketplace.map(MarketplaceConfig::parse).transpose()?;
        let auth_relay = match raw.paykit.auth_relay {
            Some(value) => validate_url("paykit.auth_relay", &value)?,
            None => Url::parse(pubky::DEFAULT_HTTP_RELAY_INBOX)
                .expect("default HTTP relay inbox URL parses"),
        };

        let config = Self {
            http: HttpConfig {
                listen_addr: raw.http.listen_addr,
            },
            locks: LocksConfig { trusted_public_key },
            marketplace,
            setup: SetupConfig { allowed_origins },
            paykit: PaykitConfig {
                receiver_path: receiver_path.clone(),
                receiver_path_priority,
                network: PaykitNetwork::parse(&raw.paykit.network)?,
                auth_relay,
            },
            electrum: ElectrumConfig {
                endpoint: raw.electrum.endpoint,
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
                receiver_path,
                trusted_locks_key_fingerprint,
            },
        };
        config.validate_operational_values()?;
        Ok(config)
    }

    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    pub fn database_url(&self) -> &str {
        self.database_url.as_str()
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
            (
                "rate_limits.claims_per_minute",
                self.rate_limits.claims_per_minute,
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
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ConfigEnvironment {
    pub database_url: Option<String>,
    pub master_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentInvariants {
    pub bitcoin_network: BitcoinNetwork,
    pub receiver_path: PaykitReceiverPath,
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
    pub listen_addr: String,
}

#[derive(Debug)]
pub struct LocksConfig {
    pub trusted_public_key: TrustedLocksPublicKey,
}

/// Trusted marketplace request-signing keys. Every configured key is trusted
/// equally; a request is authentic when any one of them verifies.
#[derive(Debug)]
pub struct MarketplaceConfig {
    pub trusted_keys: Vec<TrustedMarketplaceKey>,
}

impl MarketplaceConfig {
    fn parse(raw: RawMarketplaceConfig) -> Result<Self, ConfigError> {
        if raw.trusted_public_key.is_some() && !raw.trusted_public_keys.is_empty() {
            return Err(ConfigError::ConflictingTrustedMarketplacePublicKeys);
        }
        let values = match raw.trusted_public_key {
            Some(single) => vec![single],
            None => raw.trusted_public_keys,
        };
        if values.is_empty() {
            return Err(ConfigError::EmptyTrustedMarketplacePublicKeys);
        }
        let trusted_keys = values
            .into_iter()
            .map(TrustedMarketplaceKey::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { trusted_keys })
    }
}

/// One trusted marketplace signing key. `key_id` is a short fingerprint
/// prefix safe to log; the key material itself is never rendered.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedMarketplaceKey {
    public_key: TrustedLocksPublicKey,
    key_id: String,
}

impl TrustedMarketplaceKey {
    fn parse(value: String) -> Result<Self, ConfigError> {
        let public_key = TrustedLocksPublicKey::parse(value)
            .map_err(|_| ConfigError::InvalidTrustedMarketplacePublicKey)?;
        let key_id = public_key
            .fingerprint()
            .as_bytes()
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(Self { public_key, key_id })
    }

    /// Stable, secret-free identifier (truncated SHA-256 fingerprint) used in
    /// verification logs.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.public_key.verifying_key()
    }
}

impl fmt::Debug for TrustedMarketplaceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedMarketplaceKey")
            .field("key_id", &self.key_id)
            .field("public_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub struct SetupConfig {
    pub allowed_origins: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PaykitConfig {
    pub receiver_path: PaykitReceiverPath,
    /// Ordered first-segment preference for discovered reader receiver paths.
    pub receiver_path_priority: Vec<ReceiverPathPriority>,
    pub network: PaykitNetwork,
    /// HTTP relay inbox base used both by the SDK auth flows and by the
    /// manual claim loopback that exchanges a caller-supplied AuthToken for
    /// a homeserver session.
    pub auth_relay: Url,
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

/// A canonical Paykit receiver app segment used to rank discovered paths.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReceiverPathPriority(String);

impl ReceiverPathPriority {
    pub fn parse(value: String) -> Result<Self, ConfigError> {
        // Delegate grammar to the dependency-owned receiver-path parser and
        // prove that this supplied segment is its exact canonical first path segment.
        let probe = PaykitReceiverPath::new(format!("{value}/wallet"))
            .map_err(|_| ConfigError::InvalidReceiverPathPriority)?;
        (probe.as_str().split('/').next() == Some(value.as_str()))
            .then_some(Self(value))
            .ok_or(ConfigError::InvalidReceiverPathPriority)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct ElectrumConfig {
    pub endpoint: String,
    pub poll_interval: Duration,
    pub request_timeout: Duration,
    pub connect_retries: u8,
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
    pub max_pending_setup_flows: u64,
    pub max_completion_polls_per_flow: u64,
    pub max_completion_polls: u64,
    /// Process-wide manual claim budget: each claim performs a relay
    /// round-trip and a homeserver session exchange.
    pub claims_per_minute: u64,
}

#[derive(Debug)]
pub struct ShutdownConfig {
    pub drain_timeout: Duration,
}

struct DatabaseUrl(String);

impl DatabaseUrl {
    fn parse(value: Option<String>) -> Result<Self, ConfigError> {
        let value = value.ok_or(ConfigError::MissingDatabaseUrl)?;
        let parsed = validate_url("PAYKIT_DATABASE_URL", &value)?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql") {
            return Err(ConfigError::InvalidDatabaseUrlScheme);
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration TOML is invalid: {0}")]
    Toml(toml::de::Error),
    #[error("PAYKIT_DATABASE_URL is required")]
    MissingDatabaseUrl,
    #[error("PAYKIT_MASTER_KEY is required")]
    MissingMasterKey,
    #[error("PAYKIT_DATABASE_URL must use postgres:// or postgresql://")]
    InvalidDatabaseUrlScheme,
    #[error("PAYKIT_MASTER_KEY must be unpadded base64url encoding of exactly 32 bytes")]
    InvalidMasterKey,
    #[error("locks.trusted_public_key must be a canonical pubky-prefixed public key")]
    InvalidTrustedLocksPublicKey,
    #[error("marketplace trusted public keys must be canonical pubky-prefixed public keys")]
    InvalidTrustedMarketplacePublicKey,
    #[error(
        "marketplace.trusted_public_key and marketplace.trusted_public_keys are mutually exclusive"
    )]
    ConflictingTrustedMarketplacePublicKeys,
    #[error("marketplace.trusted_public_keys must contain at least one key")]
    EmptyTrustedMarketplacePublicKeys,
    #[error("bitcoin.network must be mainnet, testnet, signet, or regtest")]
    InvalidNetwork,
    #[error("{0} must be a valid absolute URL")]
    InvalidUrl(&'static str),
    #[error(
        "setup.allowed_origins must contain exact HTTP(S) origins or the sole wildcard value *"
    )]
    InvalidOrigin,
    #[error("paykit.receiver_path must be a valid Paykit receiver path")]
    InvalidReceiverPath,
    #[error("paykit.network must be mainnet or testnet")]
    InvalidPaykitNetwork,
    #[error("paykit.receiver_path_priority entries must be canonical Paykit receiver app segments")]
    InvalidReceiverPathPriority,
    #[error("paykit.receiver_path_priority must not be empty")]
    EmptyReceiverPathPriority,
    #[error("paykit.receiver_path_priority must not contain duplicates")]
    DuplicateReceiverPathPriority,
    #[error("{0} must be greater than zero")]
    ZeroDuration(&'static str),
    #[error("{0} must be greater than zero")]
    ZeroValue(&'static str),
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
    #[serde(default)]
    marketplace: Option<RawMarketplaceConfig>,
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
struct RawMarketplaceConfig {
    #[serde(default)]
    trusted_public_key: Option<String>,
    #[serde(default)]
    trusted_public_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSetupConfig {
    allowed_origins: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPaykitConfig {
    receiver_path: String,
    #[serde(default = "default_receiver_path_priority")]
    receiver_path_priority: Vec<String>,
    network: String,
    #[serde(default)]
    auth_relay: Option<String>,
}

fn default_receiver_path_priority() -> Vec<String> {
    vec!["bitkit".into()]
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
    #[serde(default = "default_claims_per_minute")]
    claims_per_minute: u64,
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
            claims_per_minute: default_claims_per_minute(),
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
            claims_per_minute: value.claims_per_minute,
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
const fn default_claims_per_minute() -> u64 {
    30
}
const fn default_shutdown_drain_timeout() -> Duration {
    Duration::from_secs(30)
}
