//! Application contract for lock-wide Payment Request draining.

use crate::persistence::PaymentDrainSnapshot;

/// Stable application failures; SQL, SDK, and correlation details stay private.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentDrainError {
    CreatorMismatch,
    Conflict,
    Unavailable,
}

/// Successful immutable drain snapshot.
pub type PaymentDrainResult = PaymentDrainSnapshot;
