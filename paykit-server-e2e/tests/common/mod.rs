#[allow(dead_code)]
pub mod arbitrum;
#[allow(dead_code)]
pub mod marketplace_rig;

use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestTerms,
};
use paykit_server::{application::semantic_intent::DeliveryIntentV1, domain::locks::ReaderPubky};
use std::collections::HashMap;

pub fn app_id() -> PaykitAppId {
    PaykitAppId::new("paykit-server").unwrap()
}

#[allow(dead_code)]
pub fn payment_intent(reader: &ReaderPubky, address: String) -> DeliveryIntentV1 {
    payment_intent_with_reference(reader, address, uuid::Uuid::new_v4().to_string())
}

#[allow(dead_code)]
pub fn payment_intent_with_reference(
    reader: &ReaderPubky,
    address: String,
    reference: String,
) -> DeliveryIntentV1 {
    payment_intent_with_reference_and_note(reader, address, reference, None)
}

pub fn payment_intent_with_reference_and_note(
    reader: &ReaderPubky,
    address: String,
    reference: String,
    note: Option<&str>,
) -> DeliveryIntentV1 {
    let mut terms = PaymentRequestTerms::builder(
        PaymentAmount::new("0.00000100", "btc").unwrap(),
        PaymentReference::new(reference).unwrap(),
        vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
    )
    .required_app_id(Some(app_id()))
    .payment_endpoints(Some(HashMap::from([(
        PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
        PaymentEndpointPayload::new(serde_json::json!({"value": address}).to_string()),
    )])));
    if let Some(note) = note {
        terms = terms.metadata(serde_json::Map::from_iter([(
            "note".into(),
            serde_json::Value::String(note.into()),
        )]));
    }
    let terms = terms.build().unwrap();
    DeliveryIntentV1::payment_request(reader.to_string(), app_id(), &terms).unwrap()
}

/// Compares a response body with a checked-in fixture, or rewrites the fixture when
/// `PAYKIT_CAPTURE_FIXTURES` is set. Fixtures are the exact bodies emitted by the real
/// services over PostgreSQL; `volatile` replaces, textually, only the values the
/// database or RNG chooses (identifiers and timestamps), keeping every other byte.
#[allow(dead_code)]
pub fn assert_fixture(directory: &str, name: &str, body: &[u8], volatile: &[(&str, &str)]) {
    fn collect(value: &serde_json::Value, field: &str, found: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    match value.as_str() {
                        Some(text) if key == field => found.push(text.to_owned()),
                        _ => collect(value, field, found),
                    }
                }
            }
            serde_json::Value::Array(items) => {
                items.iter().for_each(|item| collect(item, field, found));
            }
            _ => {}
        }
    }
    let mut rendered = String::from_utf8(body.to_vec()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    for (field, replacement) in volatile {
        let mut found = Vec::new();
        collect(&parsed, field, &mut found);
        for original in found {
            rendered = rendered.replace(&format!("\"{original}\""), &format!("\"{replacement}\""));
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/fixtures")
        .join(directory)
        .join(format!("{name}.json"));
    if std::env::var_os("PAYKIT_CAPTURE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, rendered).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing fixture {}; capture with PAYKIT_CAPTURE_FIXTURES=1",
            path.display()
        )
    });
    assert_eq!(rendered, expected, "fixture {directory}/{name}.json");
}

/// The end of a preparation fixed `seconds` from now, as the service fixes it when it
/// accepts a quote. Store-level tests use the host clock, which is the database's.
#[allow(dead_code)]
pub fn deadline_after(seconds: u64) -> Option<time::OffsetDateTime> {
    Some(time::OffsetDateTime::now_utc() + time::Duration::seconds(i64::try_from(seconds).unwrap()))
}
