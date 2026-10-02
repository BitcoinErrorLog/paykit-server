use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestTerms,
};
use paykit_server::{application::semantic_intent::DeliveryIntentV1, domain::locks::ReaderPubky};
use std::collections::HashMap;

pub fn app_id() -> PaykitAppId {
    PaykitAppId::new("paykit-server").unwrap()
}

pub fn payment_intent(reader: &ReaderPubky, address: String) -> DeliveryIntentV1 {
    let terms = PaymentRequestTerms::builder(
        PaymentAmount::new("0.00000100", "btc").unwrap(),
        PaymentReference::new(uuid::Uuid::new_v4().to_string()).unwrap(),
        vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
    )
    .required_app_id(Some(app_id()))
    .payment_endpoints(Some(HashMap::from([(
        PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
        PaymentEndpointPayload::new(serde_json::json!({"value": address}).to_string()),
    )])))
    .build()
    .unwrap();
    DeliveryIntentV1::payment_request(reader.to_string(), app_id(), &terms).unwrap()
}
