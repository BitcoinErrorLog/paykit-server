//! Canonical Paykit SDK Payment Request lifecycle projection values.

use std::fmt;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::application::semantic_intent::PaymentTermsV1;

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
    ) || (existing != PaymentRequestLifecycleState::InvalidConflict
        && incoming != PaymentRequestLifecycleState::InvalidConflict
        && (existing == PaymentRequestLifecycleState::RecoveryRequired
            || incoming == PaymentRequestLifecycleState::RecoveryRequired))
}

/// Whether a row stored as `invalid_conflict` may take the incoming state at
/// equal source cursors.
///
/// Paykit `v0.1.1-rc3` and later no longer mark a payee's request invalid when it
/// stores an otherwise-valid Acceptance at or after the proposal expiry, such
/// as an in-time Acceptance fetched late. It derives those requests from the
/// same stored events as `accepted`, `proof_submitted` once a Payment Proof
/// arrived, or `canceled` when the Acceptance crossed a payee Cancellation.
/// The projection must carry the Acceptance's local record time and that time
/// must not be earlier than the proposal expiry.
pub(crate) fn late_acceptance_rederivation_allowed(
    existing: PaymentRequestLifecycleState,
    incoming: &PaymentRequestLifecycleProjection,
) -> bool {
    let expires_at = incoming
        .proposal
        .terms
        .proposal_expires_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
    existing == PaymentRequestLifecycleState::InvalidConflict
        && matches!(
            incoming.request_state,
            PaymentRequestLifecycleState::Accepted
                | PaymentRequestLifecycleState::ProofSubmitted
                | PaymentRequestLifecycleState::Canceled
        )
        && incoming
            .acceptance_recorded_at
            .zip(expires_at)
            .is_some_and(|(recorded_at, expires_at)| recorded_at >= expires_at)
}

/// One canonical SDK-derived lifecycle snapshot and its independent source cursors.
#[derive(Clone, PartialEq)]
pub struct PaymentRequestLifecycleProjection {
    pub payment_request_id: String,
    pub proposal: ProposalCorrelation,
    pub request_state: PaymentRequestLifecycleState,
    pub state_event_id: Option<String>,
    pub last_stream_item_id: Option<u64>,
    pub last_outbound_message_id: Option<u64>,
    pub last_event_at: OffsetDateTime,
    /// When the SDK recorded this server's proposal, by the server's clock.
    pub proposal_recorded_at: Option<OffsetDateTime>,
    /// Local time the SDK stored the recorded Acceptance, if any. For the
    /// server this is when it fetched the Acceptance, not when the reader
    /// accepted.
    pub acceptance_recorded_at: Option<OffsetDateTime>,
}

/// Complete persisted-intent fields available in every SDK proposal record.
#[derive(Clone, PartialEq)]
pub struct ProposalCorrelation {
    pub reader_pubky: String,
    pub proposal_app_id: String,
    pub terms: PaymentTermsV1,
}

impl fmt::Debug for ProposalCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProposalCorrelation(<redacted>)")
    }
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

/// Collapses all SDK proposal attempts for one invoice into its strongest
/// observable state. Non-terminal attempts always outrank terminal history;
/// ties use the most recently recorded SDK event, then the stable wire value so
/// equal database timestamps cannot make row order observable.
pub fn aggregate_lifecycle(
    attempts: impl IntoIterator<Item = (PaymentRequestLifecycleState, OffsetDateTime)>,
) -> Option<PersistedPaymentRequestLifecycle> {
    attempts
        .into_iter()
        .max_by_key(|(state, recorded_at)| (aggregate_rank(*state), *recorded_at, state.as_str()))
        .map(
            |(request_state, last_event_at)| PersistedPaymentRequestLifecycle {
                request_state,
                last_event_at,
            },
        )
}

const fn aggregate_rank(state: PaymentRequestLifecycleState) -> u8 {
    match state {
        PaymentRequestLifecycleState::InvalidConflict => 9,
        PaymentRequestLifecycleState::RecoveryRequired => 8,
        PaymentRequestLifecycleState::ProofSubmitted => 7,
        PaymentRequestLifecycleState::ActiveRecurring => 6,
        PaymentRequestLifecycleState::Accepted => 5,
        PaymentRequestLifecycleState::Proposed => 4,
        PaymentRequestLifecycleState::ProposalExpired
        | PaymentRequestLifecycleState::Rejected
        | PaymentRequestLifecycleState::Canceled => 0,
    }
}
