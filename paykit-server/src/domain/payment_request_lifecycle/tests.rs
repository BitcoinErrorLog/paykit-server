use time::OffsetDateTime;

use super::{
    PaymentRequestLifecycleProjection, PaymentRequestLifecycleState,
    cursor_stable_transition_allowed,
};

#[test]
fn only_proposed_to_proposal_expired_is_cursor_stable() {
    assert!(cursor_stable_transition_allowed(
        PaymentRequestLifecycleState::Proposed,
        PaymentRequestLifecycleState::ProposalExpired,
    ));
    assert!(!cursor_stable_transition_allowed(
        PaymentRequestLifecycleState::ProposalExpired,
        PaymentRequestLifecycleState::Proposed,
    ));
    assert!(!cursor_stable_transition_allowed(
        PaymentRequestLifecycleState::Canceled,
        PaymentRequestLifecycleState::Accepted,
    ));
}

#[test]
fn lifecycle_projection_debug_redacts_correlation_metadata() {
    let projection = PaymentRequestLifecycleProjection {
        payment_request_id: "request-secret".into(),
        request_state: PaymentRequestLifecycleState::Accepted,
        state_event_id: Some("event-secret".into()),
        last_stream_item_id: Some(123_456),
        last_outbound_message_id: Some(654_321),
        last_event_at: OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
    };

    let debug = format!("{projection:?}");
    assert!(debug.contains("Accepted"));
    assert!(!debug.contains("request-secret"));
    assert!(!debug.contains("event-secret"));
    assert!(!debug.contains("123456"));
    assert!(!debug.contains("654321"));
}
