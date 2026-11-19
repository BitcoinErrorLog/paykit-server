//! Black-box end-to-end test scaffold for `paykit-server`.

/// PostgreSQL fixtures used by E2E integration tests.
pub mod postgres;

/// The inbox of a local test HTTP relay, for `PubkySessionBootstrap::with_auth_relay`.
/// A bootstrap without one runs its grant flows through the public Pubky relay.
pub fn auth_relay_inbox(relay: &url::Url) -> String {
    relay
        .join("inbox")
        .expect("a relay URL takes an inbox path")
        .to_string()
}
