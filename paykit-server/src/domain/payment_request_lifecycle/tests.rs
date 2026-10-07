use time::OffsetDateTime;

use super::{
    PaymentRequestLifecycleProjection, PaymentRequestLifecycleState, ProposalCorrelation,
    aggregate_lifecycle, cursor_stable_transition_allowed,
};
use crate::application::semantic_intent::PaymentTermsV1;

#[test]
fn expiry_and_recovery_overlays_are_cursor_stable() {
    assert!(cursor_stable_transition_allowed(
        PaymentRequestLifecycleState::Proposed,
        PaymentRequestLifecycleState::ProposalExpired,
    ));
    assert!(!cursor_stable_transition_allowed(
        PaymentRequestLifecycleState::ProposalExpired,
        PaymentRequestLifecycleState::Proposed,
    ));

    for underlying in [
        PaymentRequestLifecycleState::Proposed,
        PaymentRequestLifecycleState::ProposalExpired,
        PaymentRequestLifecycleState::Accepted,
        PaymentRequestLifecycleState::Rejected,
        PaymentRequestLifecycleState::Canceled,
        PaymentRequestLifecycleState::ProofSubmitted,
        PaymentRequestLifecycleState::ActiveRecurring,
    ] {
        assert!(cursor_stable_transition_allowed(
            underlying,
            PaymentRequestLifecycleState::RecoveryRequired,
        ));
        assert!(cursor_stable_transition_allowed(
            PaymentRequestLifecycleState::RecoveryRequired,
            underlying,
        ));
    }

    assert!(!cursor_stable_transition_allowed(
        PaymentRequestLifecycleState::InvalidConflict,
        PaymentRequestLifecycleState::RecoveryRequired,
    ));
    assert!(!cursor_stable_transition_allowed(
        PaymentRequestLifecycleState::RecoveryRequired,
        PaymentRequestLifecycleState::InvalidConflict,
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
        proposal: ProposalCorrelation {
            reader_pubky: "reader-secret".into(),
            proposal_app_id: "paykit-server".into(),
            terms: PaymentTermsV1 {
                amount: "1".into(),
                asset: "btc".into(),
                rates: Vec::new(),
                payment_reference: "reference-secret".into(),
                proposal_expires_at: None,
                payment_deadline: None,
                accepted_endpoint_identifiers: vec!["endpoint-secret".into()],
                payment_endpoints: [("endpoint-secret".into(), "payload-secret".into())]
                    .into_iter()
                    .collect(),
                metadata: serde_json::Map::new(),
            },
        },
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
    assert!(!debug.contains("reader-secret"));
    assert!(!debug.contains("reference-secret"));
}

#[test]
fn aggregate_lifecycle_prioritizes_every_live_attempt_over_terminal_attempts() {
    let base = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    for (live, expected) in [
        (
            PaymentRequestLifecycleState::Accepted,
            PaymentRequestLifecycleState::Accepted,
        ),
        (
            PaymentRequestLifecycleState::ActiveRecurring,
            PaymentRequestLifecycleState::ActiveRecurring,
        ),
        (
            PaymentRequestLifecycleState::ProofSubmitted,
            PaymentRequestLifecycleState::ProofSubmitted,
        ),
        (
            PaymentRequestLifecycleState::Proposed,
            PaymentRequestLifecycleState::Proposed,
        ),
    ] {
        let aggregate = aggregate_lifecycle([
            (PaymentRequestLifecycleState::Rejected, base),
            (live, base - time::Duration::seconds(1)),
            (
                PaymentRequestLifecycleState::Canceled,
                base + time::Duration::seconds(1),
            ),
        ])
        .unwrap();
        assert_eq!(aggregate.request_state, expected);
    }
}

#[test]
fn aggregate_lifecycle_uses_latest_terminal_attempt() {
    let base = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let aggregate = aggregate_lifecycle([
        (PaymentRequestLifecycleState::Rejected, base),
        (
            PaymentRequestLifecycleState::ProposalExpired,
            base + time::Duration::seconds(1),
        ),
    ])
    .unwrap();

    assert_eq!(
        aggregate.request_state,
        PaymentRequestLifecycleState::ProposalExpired
    );
    assert_eq!(aggregate.last_event_at, base + time::Duration::seconds(1));
}

#[test]
fn aggregate_lifecycle_terminal_ties_are_independent_of_database_row_order() {
    let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let forward = aggregate_lifecycle([
        (PaymentRequestLifecycleState::Rejected, at),
        (PaymentRequestLifecycleState::Canceled, at),
        (PaymentRequestLifecycleState::ProposalExpired, at),
    ])
    .unwrap();
    let reverse = aggregate_lifecycle([
        (PaymentRequestLifecycleState::ProposalExpired, at),
        (PaymentRequestLifecycleState::Canceled, at),
        (PaymentRequestLifecycleState::Rejected, at),
    ])
    .unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(
        forward.request_state,
        PaymentRequestLifecycleState::Rejected
    );
}
