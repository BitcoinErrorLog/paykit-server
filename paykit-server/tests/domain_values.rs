use std::str::FromStr;

use locks_core::ids::{BundleId as RawBundleId, PubkyLockResource as RawPubkyLockResource};
use paykit_server::domain::{
    invoice::{CriterionAmount, CriterionAsset, InvoiceIdentity},
    locks::{
        CreatorPubky, LocksIdentifierParseError, PubkyLockResource, ReaderPubky,
        parse_addressed_lock_resource, parse_bundle_id, parse_creator, parse_reader,
    },
    payment::{BitcoinOutpoint, PaymentBinding, PaymentReference, PaymentStatus},
};

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const READER: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";
const LOCK_ID: &str = "000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG";

fn lock_resource() -> PubkyLockResource {
    parse_addressed_lock_resource(&format!("{CREATOR}/pub/locks.app/{LOCK_ID}.json"))
        .expect("valid canonical lock resource")
}

fn another_creator() -> CreatorPubky {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &replacement.to_string());
        if let Ok(creator) = parse_creator(&candidate)
            && creator.to_string() != CREATOR
        {
            return creator;
        }
    }

    panic!("the canonical identifier provider did not yield a second valid fixture");
}

#[test]
fn domain_canonical_locks_identifiers_parse_at_the_boundary_and_creator_derives_from_resource() {
    let creator = parse_creator(CREATOR).expect("valid creator");
    let reader = parse_reader(READER).expect("valid reader");
    let bundle = parse_bundle_id(BUNDLE).expect("valid bundle");
    let resource = lock_resource();

    assert_eq!(resource.creator(), &creator);
    assert_eq!(
        resource.to_string(),
        format!("{CREATOR}/pub/locks.app/{LOCK_ID}.json")
    );
    assert_eq!(reader.to_string(), READER);
    assert_eq!(bundle.to_string(), BUNDLE);

    assert!(parse_creator("not-a-pubky").is_err());
    assert!(parse_reader("pubky/invalid").is_err());
    assert!(parse_bundle_id("not-a-bundle").is_err());
    assert!(
        parse_addressed_lock_resource(&format!("pubky://{CREATOR}/pub/locks.app/{LOCK_ID}.json"))
            .is_err()
    );
}

#[test]
fn domain_identifier_boundaries_reject_locks_core_normalizations() {
    let noncanonical_bundle = BUNDLE.to_ascii_lowercase();
    let normalized_bundle = RawBundleId::from_str(&noncanonical_bundle)
        .expect("locks-core accepts lowercase BundleId")
        .to_string();
    assert_eq!(normalized_bundle, BUNDLE);
    assert_eq!(
        parse_bundle_id(&noncanonical_bundle),
        Err(LocksIdentifierParseError::NonCanonical { kind: "bundle" })
    );

    let noncanonical_resource = format!(
        "{CREATOR}/pub/locks.app/{}.json",
        LOCK_ID.to_ascii_lowercase()
    );
    let normalized_resource = RawPubkyLockResource::from_str(&noncanonical_resource)
        .expect("locks-core accepts lowercase lock-resource component")
        .to_string();
    assert_eq!(
        normalized_resource,
        format!("{CREATOR}/pub/locks.app/{LOCK_ID}.json")
    );
    assert_eq!(
        parse_addressed_lock_resource(&noncanonical_resource),
        Err(LocksIdentifierParseError::NonCanonical {
            kind: "addressed lock resource"
        })
    );

    assert_eq!(parse_creator(CREATOR).unwrap().to_string(), CREATOR);
    assert_eq!(parse_reader(READER).unwrap().to_string(), READER);
    assert_eq!(parse_bundle_id(BUNDLE).unwrap().to_string(), BUNDLE);
    assert_eq!(
        parse_addressed_lock_resource(&format!("{CREATOR}/pub/locks.app/{LOCK_ID}.json"))
            .unwrap()
            .to_string(),
        format!("{CREATOR}/pub/locks.app/{LOCK_ID}.json")
    );
}

#[test]
fn domain_invoice_identity_is_creator_scoped_and_creator_is_not_a_constructor_input() {
    let bundle = parse_bundle_id(BUNDLE).unwrap();
    let identity = InvoiceIdentity::new(lock_resource(), bundle.clone());
    let same = InvoiceIdentity::new(lock_resource(), bundle.clone());
    let other_creator_resource = parse_addressed_lock_resource(&format!(
        "{}/pub/locks.app/{LOCK_ID}.json",
        another_creator()
    ))
    .expect("a second valid canonical creator");
    let other_creator = InvoiceIdentity::new(other_creator_resource, bundle);

    assert_eq!(identity.creator().to_string(), CREATOR);
    assert_eq!(identity.bundle_id().to_string(), BUNDLE);
    assert_eq!(identity, same);
    assert_ne!(identity, other_creator);
}

#[test]
fn domain_bundle_id_and_invoice_identity_debug_redact_bearer_secret() {
    let bundle = parse_bundle_id(BUNDLE).expect("valid canonical bundle");
    let identity = InvoiceIdentity::new(lock_resource(), bundle.clone());

    for debug_output in [format!("{bundle:?}"), format!("{identity:?}")] {
        assert!(!debug_output.contains(BUNDLE));
        assert!(debug_output.contains("<redacted>"));
    }
    assert!(!format!("{identity:?}").contains(CREATOR));
}

#[test]
fn domain_payment_reference_debug_redacts_canonical_reference() {
    let reference = PaymentReference::new();
    let debug_output = format!("{reference:?}");

    assert!(!debug_output.contains(reference.as_str()));
    assert!(debug_output.contains("<redacted>"));
}

#[test]
fn domain_bitcoin_outpoint_debug_redacts_canonical_outpoint() {
    let txid = "ab".repeat(32);
    let outpoint = BitcoinOutpoint::new(&txid, 7).expect("valid outpoint");
    let debug_output = format!("{outpoint:?}");

    assert!(!debug_output.contains(&txid));
    assert!(debug_output.contains("<redacted>"));
}

#[test]
fn domain_creator_pubky_debug_redacts_canonical_identity() {
    let creator = parse_creator(CREATOR).expect("valid canonical creator");
    let debug_output = format!("{creator:?}");

    assert!(!debug_output.contains(CREATOR));
    assert!(debug_output.contains("<redacted>"));
}

#[test]
fn domain_reader_pubky_debug_redacts_canonical_identity() {
    let reader: ReaderPubky = parse_reader(READER).expect("valid canonical reader");
    let debug_output = format!("{reader:?}");

    assert!(!debug_output.contains(READER));
    assert!(debug_output.contains("<redacted>"));
}

#[test]
fn domain_pubky_lock_resource_debug_redacts_canonical_resource() {
    let resource = lock_resource();
    let canonical_resource = resource.to_string();
    let debug_output = format!("{resource:?}");

    assert!(!debug_output.contains(&canonical_resource));
    assert!(debug_output.contains("<redacted>"));
}

#[test]
fn domain_criterion_accepts_only_exact_btc_and_positive_decimal_u64_satoshis() {
    assert_eq!(CriterionAsset::parse("BTC").unwrap().as_str(), "BTC");
    for invalid in ["btc", "BTC ", " BTC", "ETH", ""] {
        assert!(
            CriterionAsset::parse(invalid).is_err(),
            "{invalid:?} must fail"
        );
    }

    assert_eq!(CriterionAmount::parse("1").unwrap().as_sats(), 1);
    assert_eq!(
        CriterionAmount::parse("18446744073709551615")
            .unwrap()
            .as_sats(),
        u64::MAX
    );
    for invalid in [
        "0",
        "+1",
        "-1",
        "1.0",
        " 1",
        "1 ",
        "1_000",
        "abc",
        "18446744073709551616",
    ] {
        assert!(
            CriterionAmount::parse(invalid).is_err(),
            "{invalid:?} must fail"
        );
    }
}

#[test]
fn domain_bitcoin_outpoint_requires_lowercase_hex_txid_and_u32_vout() {
    let txid = "ab".repeat(32);
    let outpoint = BitcoinOutpoint::new(&txid, u32::MAX).expect("valid outpoint");

    assert_eq!(outpoint.txid(), txid);
    assert_eq!(outpoint.vout(), u32::MAX);
    assert!(BitcoinOutpoint::new(&"AB".repeat(32), 0).is_err());
    assert!(BitcoinOutpoint::new(&"a".repeat(63), 0).is_err());
    assert!(BitcoinOutpoint::new(&format!("{}g", "a".repeat(63)), 0).is_err());
}

#[test]
fn domain_payment_reference_generates_and_preserves_a_v4_uuid() {
    let reference = PaymentReference::new();

    assert_eq!(reference.as_uuid().get_version_num(), 4);
    assert_eq!(
        reference.as_str(),
        reference.as_uuid().hyphenated().to_string()
    );
}

#[test]
fn domain_observations_report_undetected_detected_and_confirmed_facts() {
    let invoice = CriterionAmount::parse("100").unwrap();
    let undetected = PaymentBinding::undetected(invoice.clone()).observation();
    let detected = PaymentBinding::observed(invoice.clone(), 100, 0).observation();
    let confirmed = PaymentBinding::observed(invoice, 100, 3).observation();

    assert_eq!(undetected.status(), PaymentStatus::Undetected);
    assert_eq!(undetected.confirmations(), 0);
    assert!(!undetected.amount_matched());
    assert_eq!(detected.status(), PaymentStatus::Detected);
    assert_eq!(detected.confirmations(), 0);
    assert!(detected.amount_matched());
    assert_eq!(confirmed.status(), PaymentStatus::Confirmed);
    assert_eq!(confirmed.confirmations(), 3);
    assert!(confirmed.amount_matched());
}

#[test]
fn domain_matching_overpayment_and_underpayment_follow_finality_and_replacement_rules() {
    let invoice = CriterionAmount::parse("100").unwrap();
    let matching = PaymentBinding::observed(invoice.clone(), 100, 0);
    let overpayment = PaymentBinding::observed(invoice.clone(), 101, 1);
    let underpayment = PaymentBinding::observed(invoice.clone(), 99, 6);

    assert!(matching.observation().amount_matched());
    assert!(matching.is_replaceable());
    // §B.8.2: the match is exact, so an overpayment is a mismatch and takes
    // the same replaceable, never-final path as an underpayment.
    assert!(!overpayment.observation().amount_matched());
    assert!(overpayment.is_replaceable());
    assert!(!overpayment.is_final());
    assert!(!underpayment.observation().amount_matched());
    assert!(underpayment.is_replaceable());
    assert!(!underpayment.is_final());
}

#[test]
fn domain_final_matching_binding_persists_six_confirmations_and_pre_final_reorg_unfreezes_it() {
    let invoice = CriterionAmount::parse("100").unwrap();
    let pre_final = PaymentBinding::observed(invoice.clone(), 100, 1);
    let regressed = pre_final.regress_to_unseen();
    let final_binding = PaymentBinding::observed(invoice, 100, 7);

    assert!(!pre_final.is_replaceable());
    assert_eq!(regressed.observation().status(), PaymentStatus::Undetected);
    assert!(regressed.is_replaceable());
    assert!(final_binding.is_final());
    assert!(!final_binding.is_replaceable());
    assert_eq!(final_binding.observation().confirmations(), 6);
    assert_eq!(final_binding.regress_to_unseen(), final_binding);
}
