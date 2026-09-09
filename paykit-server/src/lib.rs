/// Application services and explicit side-effect ports.
pub mod application;
/// Bitcoin output observation values and injected transport boundary.
pub mod bitcoin;
/// Bitkit's server-owned companion claim receiver protocol.
pub mod bitkit_claim;
/// SDK-owned normal AUTH initiation bound to the Bitkit claim query pair.
pub mod bitkit_setup;
/// Claim-time address-index history scan (design §B.5).
pub mod chain_history;
pub mod config;
/// Versioned authenticated encryption for persisted private state.
pub mod crypto;
/// Side-effect-free protocol and business value objects.
pub mod domain;
pub mod http;
/// Canonical key identity (tail, display fingerprint) and the claim deny-list.
pub mod key_identity;
/// Manual watch-only account claims authenticated by capability-scoped AuthTokens.
pub mod manual_claim;
/// Identifier-free operational metrics.
pub mod metrics;
/// Concrete per-Creator public Paykit SDK adapter.
pub mod paykit;
/// PostgreSQL persistence primitives and migrations.
pub mod persistence;
/// Concrete normal-AUTH, companion-claim, marker, and encrypted-store setup flow.
pub mod real_setup;
/// Server lifecycle, dependency checks, admission control, and shutdown.
pub mod runtime;
pub mod server;
pub mod setup;
/// Relay receive/ack boundary and durable-before-ack setup orchestration.
pub mod setup_orchestration;
/// Fail-closed database and Creator-state initialization before HTTP bind.
pub mod startup;
/// Durable, at-least-once background workers.
pub mod workers;

pub use server::Server;
