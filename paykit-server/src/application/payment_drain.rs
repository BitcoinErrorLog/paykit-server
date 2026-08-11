//! Application contract for lock-wide Payment Request draining.

use async_trait::async_trait;

use crate::domain::locks::PubkyLockResource;
use crate::persistence::PaymentDrainSnapshot;

/// Stable application failures; SQL, SDK, and correlation details stay private.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentDrainError {
    CreatorMismatch,
    Conflict,
    Unavailable,
}

/// Secret-free aggregate exposed to Locks. Internal drain identity and replay
/// metadata deliberately remain outside this contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentDrainSummary {
    completed: bool,
    accepted_count: u64,
    terminal_count: u64,
    cancellation_enqueued_count: u64,
}

impl PaymentDrainSummary {
    pub const fn new(
        completed: bool,
        accepted_count: u64,
        terminal_count: u64,
        cancellation_enqueued_count: u64,
    ) -> Self {
        Self {
            completed,
            accepted_count,
            terminal_count,
            cancellation_enqueued_count,
        }
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
}

impl From<PaymentDrainSnapshot> for PaymentDrainSummary {
    fn from(value: PaymentDrainSnapshot) -> Self {
        Self::new(
            value.completed(),
            value.accepted_count(),
            value.terminal_count(),
            value.cancellation_enqueued_count(),
        )
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
}

/// Successful immutable drain snapshot.
pub type PaymentDrainResult = PaymentDrainSnapshot;
