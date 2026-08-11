//! Canonical Paykit SDK Payment Request lifecycle projection values.

use std::fmt;

use time::OffsetDateTime;

#[cfg(test)]
mod tests;

/// Closed persisted spelling of the canonical Paykit SDK lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentRequestLifecycleState {
    Proposed,
    ProposalExpired,
    Accepted,
    Rejected,
    Canceled,
    ProofSubmitted,
    ActiveRecurring,
    RecoveryRequired,
    InvalidConflict,
}

impl PaymentRequestLifecycleState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ProposalExpired => "proposal_expired",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Canceled => "canceled",
            Self::ProofSubmitted => "proof_submitted",
            Self::ActiveRecurring => "active_recurring",
            Self::RecoveryRequired => "recovery_required",
            Self::InvalidConflict => "invalid_conflict",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "proposed" => Some(Self::Proposed),
            "proposal_expired" => Some(Self::ProposalExpired),
            "accepted" => Some(Self::Accepted),
            "rejected" => Some(Self::Rejected),
            "canceled" => Some(Self::Canceled),
            "proof_submitted" => Some(Self::ProofSubmitted),
            "active_recurring" => Some(Self::ActiveRecurring),
            "recovery_required" => Some(Self::RecoveryRequired),
            "invalid_conflict" => Some(Self::InvalidConflict),
            _ => None,
        }
    }
}

pub(crate) fn cursor_stable_transition_allowed(
    existing: PaymentRequestLifecycleState,
    incoming: PaymentRequestLifecycleState,
) -> bool {
    matches!(
        (existing, incoming),
        (
            PaymentRequestLifecycleState::Proposed,
            PaymentRequestLifecycleState::ProposalExpired
        )
    )
}

/// One canonical SDK-derived lifecycle snapshot and its independent source cursors.
#[derive(Clone, PartialEq, Eq)]
pub struct PaymentRequestLifecycleProjection {
    pub payment_request_id: String,
    pub request_state: PaymentRequestLifecycleState,
    pub state_event_id: Option<String>,
    pub last_stream_item_id: Option<u64>,
    pub last_outbound_message_id: Option<u64>,
    pub last_event_at: OffsetDateTime,
}

impl fmt::Debug for PaymentRequestLifecycleProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaymentRequestLifecycleProjection")
            .field("request_state", &self.request_state)
            .field("correlation_metadata", &"<redacted>")
            .finish()
    }
}

/// Durable lifecycle state returned to internal application services.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedPaymentRequestLifecycle {
    pub request_state: PaymentRequestLifecycleState,
    pub last_event_at: OffsetDateTime,
}
