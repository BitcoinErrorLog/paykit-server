use time::{Duration, OffsetDateTime};

use super::{
    PaymentRequestLifecycleProjection, PaymentRequestLifecycleState, ProposalCorrelation,
    aggregate_lifecycle, cursor_stable_transition_allowed, late_acceptance_rederivation_allowed,
};
use crate::application::semantic_intent::PaymentTermsV1;

const PROPOSAL_EXPIRES_AT: &str = "2027-01-15T08:00:00Z";

fn proposal_expiry() -> OffsetDateTime {
    OffsetDateTime::parse(
        PROPOSAL_EXPIRES_AT,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
}

fn rederived(
    request_state: PaymentRequestLifecycleState,
    acceptance_recorded_at: Option<OffsetDateTime>,
) -> PaymentRequestLifecycleProjection {
    PaymentRequestLifecycleProjection {
        payment_request_id: "b7f9c2a1-6d43-4b0e-a8d4-0fe2c712ab33".into(),
        proposal: ProposalCorrelation {
            reader_pubky: "pubky8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo".into(),
            proposal_app_id: "paykit-server".into(),
            terms: PaymentTermsV1 {
                amount: "0.00001000".into(),
                asset: "BTC".into(),
                rates: Vec::new(),
                payment_reference: "8a0d8b4c-913f-4e31-9f2c-2a6f5bb4d201".into(),
                proposal_expires_at: Some(PROPOSAL_EXPIRES_AT.into()),
                payment_deadline: Some("2027-01-16T08:00:00Z".into()),
                accepted_endpoint_identifiers: vec!["btc-bitcoin-p2wpkh".into()],
                payment_endpoints: [("btc-bitcoin-p2wpkh".into(), "payload".into())]
                    .into_iter()
                    .collect(),
                metadata: serde_json::Map::new(),
            },
        },
        request_state,
        state_event_id: Some("4f1d0c2e-5b7a-4c8e-9d3f-2a1b0c9d8e7f".into()),
        last_stream_item_id: Some(3),
        last_outbound_message_id: Some(1),
        last_event_at: proposal_expiry() + Duration::minutes(1),
        proposal_recorded_at: None,
        acceptance_recorded_at,
    }
}

#[test]
fn an_acceptance_fetched_after_proposal_expiry_leaves_invalid_conflict() {
    for recorded_at in [proposal_expiry(), proposal_expiry() + Duration::hours(3)] {
        for incoming in [
            PaymentRequestLifecycleState::Accepted,
            PaymentRequestLifecycleState::ProofSubmitted,
            PaymentRequestLifecycleState::Canceled,
        ] {
            assert!(late_acceptance_rederivation_allowed(
                PaymentRequestLifecycleState::InvalidConflict,
                &rederived(incoming, Some(recorded_at)),
            ));
        }
    }
}

#[test]
fn invalid_conflict_stays_without_a_late_fetched_acceptance() {
    let late = Some(proposal_expiry() + Duration::seconds(1));
    let in_time = Some(proposal_expiry() - Duration::nanoseconds(1));

    // The Acceptance was stored before the proposal expiry, or not at all:
    // Paykit never marked that request invalid for a late fetch.
    for recorded_at in [in_time, None] {
        for incoming in [
            PaymentRequestLifecycleState::Accepted,
            PaymentRequestLifecycleState::ProofSubmitted,
            PaymentRequestLifecycleState::Canceled,
        ] {
            assert!(!late_acceptance_rederivation_allowed(
                PaymentRequestLifecycleState::InvalidConflict,
                &rederived(incoming, recorded_at),
            ));
        }
    }

    // Terms without a proposal expiry, or with one that does not parse.
    for expires_at in [None, Some("not a time".to_owned())] {
        let mut projection = rederived(PaymentRequestLifecycleState::Accepted, late);
        projection.proposal.terms.proposal_expires_at = expires_at;
        assert!(!late_acceptance_rederivation_allowed(
            PaymentRequestLifecycleState::InvalidConflict,
            &projection,
        ));
    }

    // Only the states Paykit now derives for that request.
    for incoming in [
        PaymentRequestLifecycleState::Proposed,
        PaymentRequestLifecycleState::ProposalExpired,
        PaymentRequestLifecycleState::Rejected,
        PaymentRequestLifecycleState::ActiveRecurring,
        PaymentRequestLifecycleState::RecoveryRequired,
        PaymentRequestLifecycleState::InvalidConflict,
    ] {
        assert!(!late_acceptance_rederivation_allowed(
            PaymentRequestLifecycleState::InvalidConflict,
            &rederived(incoming, late),
        ));
    }

    // Only a row stored as invalid.
    for existing in [
        PaymentRequestLifecycleState::Proposed,
        PaymentRequestLifecycleState::ProposalExpired,
        PaymentRequestLifecycleState::Rejected,
        PaymentRequestLifecycleState::Canceled,
        PaymentRequestLifecycleState::RecoveryRequired,
    ] {
        assert!(!late_acceptance_rederivation_allowed(
            existing,
            &rederived(PaymentRequestLifecycleState::Accepted, late),
        ));
    }
}

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
        proposal_recorded_at: None,
        acceptance_recorded_at: None,
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
