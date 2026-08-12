//! Application contract for lock-wide Payment Request draining.

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::domain::locks::PubkyLockResource;
use crate::persistence::PaymentDrainSnapshot;

/// Stable application failures; SQL, SDK, and correlation details stay private.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentDrainError {
    CreatorMismatch,
    Conflict,
    Unavailable,
}

/// Opaque capability that binds cleanup to one immutable drain cycle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PaymentDrainCleanupToken([u8; 32]);

impl std::fmt::Debug for PaymentDrainCleanupToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PaymentDrainCleanupToken(<redacted>)")
    }
}

impl PaymentDrainCleanupToken {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn parse(value: &str) -> Option<Self> {
        if value.len() != 43 || value.contains('=') {
            return None;
        }
        let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()?;
        let token = Self(bytes);
        (token.to_canonical_string() == value).then_some(token)
    }

    pub fn to_canonical_string(self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Secret-free aggregate exposed to Locks. Internal drain identity and replay
/// metadata deliberately remain outside this contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentDrainSummary {
    completed: bool,
    accepted_count: u64,
    terminal_count: u64,
    cancellation_enqueued_count: u64,
    cleanup_token: PaymentDrainCleanupToken,
}

impl PaymentDrainSummary {
    pub const fn new(
        completed: bool,
        accepted_count: u64,
        terminal_count: u64,
        cancellation_enqueued_count: u64,
        cleanup_token: PaymentDrainCleanupToken,
    ) -> Self {
        Self {
            completed,
            accepted_count,
            terminal_count,
            cancellation_enqueued_count,
            cleanup_token,
        }
    }

    pub fn from_snapshot(
        value: PaymentDrainSnapshot,
        cleanup_token: PaymentDrainCleanupToken,
    ) -> Self {
        Self::new(
            value.completed(),
            value.accepted_count(),
            value.terminal_count(),
            value.cancellation_enqueued_count(),
            cleanup_token,
        )
    }

    pub const fn status(&self) -> &'static str {
        if self.completed {
            "completed"
        } else {
            "active"
        }
    }

    pub const fn accepted_count(&self) -> u64 {
        self.accepted_count
    }

    pub const fn terminal_count(&self) -> u64 {
        self.terminal_count
    }

    pub const fn cancellation_enqueued_count(&self) -> u64 {
        self.cancellation_enqueued_count
    }

    pub const fn cleanup_token(&self) -> PaymentDrainCleanupToken {
        self.cleanup_token
    }
}

#[async_trait]
pub trait PaymentDrainOperations: Send + Sync {
    async fn create(
        &self,
        lock_resource: &PubkyLockResource,
    ) -> Result<PaymentDrainSummary, PaymentDrainError>;

    async fn lookup(
        &self,
        lock_resource: &PubkyLockResource,
    ) -> Result<Option<PaymentDrainSummary>, PaymentDrainError>;

    async fn cleanup(
        &self,
        lock_resource: &PubkyLockResource,
        cleanup_token: PaymentDrainCleanupToken,
    ) -> Result<(), PaymentDrainError>;
}

/// Successful immutable drain snapshot.
pub type PaymentDrainResult = PaymentDrainSnapshot;
