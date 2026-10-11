use std::collections::HashMap;

use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestTerms,
};
use paykit_server::application::semantic_intent::DeliveryIntentV1;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const READER: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

fn app_id() -> PaykitAppId {
    PaykitAppId::new("paykit-server").unwrap()
}

fn intent() -> DeliveryIntentV1 {
    let terms = PaymentRequestTerms::builder(
        PaymentAmount::new("0.00000100", "btc").unwrap(),
        PaymentReference::new("7cceb26d-9042-4ea6-bfcb-01bbd778d76e").unwrap(),
        vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
    )
    .required_app_id(Some(app_id()))
    .payment_endpoints(Some(HashMap::from([(
        PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
        PaymentEndpointPayload::new(r#"{"value":"bc1qexample"}"#),
    )])))
    .build()
    .unwrap();
    DeliveryIntentV1::payment_request(READER.to_owned(), app_id(), &terms).unwrap()
}

/// The server stores the deadlines it chose, and later attributes the SDK's
/// projection of the delivered request by exact term equality. The SDK reports a
/// payment deadline in its own canonical RFC 3339 form, which differs from the
/// `time` crate's form whenever the microsecond part has trailing zeros (for
/// example `.86877` versus `.868770`), so the stored form must already be canonical.
#[test]
fn stored_deadlines_equal_the_sdk_projection_for_every_subsecond_shape() {
    let base = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let mut microseconds: Vec<i64> = vec![
        0, 1, 10, 100, 1_000, 10_000, 100_000, 500_000, 868_770, 120_340, 999_990, 123_456, 999_999,
    ];
    microseconds.extend((0..1_000_000).step_by(7_919));
    for micros in microseconds {
        let now = base + Duration::microseconds(micros);
        let proposal_expires_at = now + Duration::minutes(15);
        let payment_deadline = now + Duration::hours(24);
        let mut stored = intent();
        stored
            .set_deadlines(
                proposal_expires_at.format(&Rfc3339).unwrap(),
                payment_deadline.format(&Rfc3339).unwrap(),
            )
            .unwrap();

        let sdk_terms = stored.terms().unwrap().to_sdk().unwrap();
        let projected =
            DeliveryIntentV1::payment_request(READER.to_owned(), app_id(), &sdk_terms).unwrap();
        assert!(
            projected.matches_proposal(READER, "paykit-server", stored.terms().unwrap()),
            "{micros} µs: stored {:?} vs projected {:?}",
            stored.terms().unwrap().payment_deadline,
            projected.terms().unwrap().payment_deadline,
        );

        let terms = stored.terms().unwrap();
        assert_eq!(
            OffsetDateTime::parse(terms.payment_deadline.as_deref().unwrap(), &Rfc3339).unwrap(),
            payment_deadline,
            "{micros} µs: canonicalization must not move the deadline"
        );
        assert_eq!(
            terms.proposal_expires_at.as_deref(),
            Some(proposal_expires_at.format(&Rfc3339).unwrap().as_str()),
            "{micros} µs: the proposal expiry is kept as chosen"
        );
    }
}

#[test]
fn deadlines_that_are_not_rfc3339_or_not_ordered_are_still_rejected() {
    let mut stored = intent();
    assert!(
        stored
            .set_deadlines("not a time".into(), "2030-01-01T00:00:00Z".into())
            .is_err()
    );
    assert!(
        stored
            .set_deadlines("2030-01-01T00:00:00Z".into(), "not a time".into())
            .is_err()
    );
    assert!(
        stored
            .set_deadlines("2030-01-02T00:00:00Z".into(), "2030-01-01T00:00:00Z".into())
            .is_err()
    );
}
