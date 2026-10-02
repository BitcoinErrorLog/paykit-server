use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use paykit_lib::{
    PaykitApp, PaykitAppCapabilities, PaykitAppId, PaykitAppRegistry, PaymentAmount,
    PaymentEndpointIdentifier, PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
    PublicKey,
};
use paykit_sdk::OutboundPrivateMessageStatus;
use paykit_server::{
    application::semantic_intent::{DeliveryIntentV1, PaymentTermsV1},
    workers::outbox::{
        Adapter, HandoffError, HandoffFailure, HandoffResult, RetryableHandoffCause,
        RetryableHandoffStage, handoff,
    },
};

fn registry(capable: bool) -> PaykitAppRegistry {
    let mut registry = PaykitAppRegistry::new(Some(
        PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap(),
    ));
    registry
        .register_app(
            PaykitAppId::new("reader").unwrap(),
            PaykitApp::new(
                "Reader",
                PaykitAppCapabilities {
                    private_payments: true,
                    payment_requests: true,
                    receipts: false,
                    outgoing_payments: capable,
                },
            )
            .unwrap(),
        )
        .unwrap();
    registry
}

struct FakeAdapter {
    registry: PaykitAppRegistry,
    link_error: Option<HandoffError>,
    payment_request_calls: Mutex<usize>,
}

#[async_trait]
impl Adapter for FakeAdapter {
    async fn fetch_registry(
        &self,
        _reader: &str,
    ) -> Result<Option<PaykitAppRegistry>, HandoffError> {
        Ok(Some(self.registry.clone()))
    }

    async fn ensure_link_with_peer(&self, _reader: &str) -> Result<(), HandoffError> {
        self.link_error.map_or(Ok(()), Err)
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
        _terms: &PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        *self.payment_request_calls.lock().unwrap() += 1;
        Ok(HandoffResult {
            outbound_message_id: 42,
            event_id: "event-42".into(),
            payment_request_id: "request-42".into(),
        })
    }

    async fn outbound_status(
        &self,
        _outbound_message_id: u64,
    ) -> Result<Option<OutboundPrivateMessageStatus>, HandoffError> {
        Ok(Some(OutboundPrivateMessageStatus::Sent))
    }
}

fn payment_intent() -> DeliveryIntentV1 {
    DeliveryIntentV1::payment_request(
        "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy".into(),
        PaykitAppId::new("paykit-server").unwrap(),
        &PaymentRequestTerms::builder(
            PaymentAmount::new("0.00050000", "btc").unwrap(),
            PaymentReference::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
        )
        .required_app_id(Some(PaykitAppId::new("paykit-server").unwrap()))
        .payment_endpoints(Some(std::collections::HashMap::from([(
            PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
            PaymentEndpointPayload::new("private-address"),
        )])))
        .build()
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn incapable_registry_is_retryable_without_handoff() {
    let changed = registry(false);
    let adapter = FakeAdapter {
        registry: changed,
        link_error: None,
        payment_request_calls: Mutex::new(0),
    };

    assert_eq!(
        handoff(&adapter, &payment_intent()).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::RegistryIncapable
        ))
    );
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn link_failure_has_one_durable_diagnostic_stage() {
    let selected = registry(true);
    let adapter = FakeAdapter {
        registry: selected.clone(),
        link_error: Some(HandoffError::Retryable(RetryableHandoffCause::Transport)),
        payment_request_calls: Mutex::new(0),
    };

    assert_eq!(
        handoff(&adapter, &payment_intent()).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::LinkEstablishment
        ))
    );
}

#[tokio::test]
async fn retry_after_an_ambiguous_handoff_can_propose_twice() {
    let selected = registry(true);
    let adapter = Arc::new(FakeAdapter {
        registry: selected.clone(),
        link_error: None,
        payment_request_calls: Mutex::new(0),
    });
    let intent = payment_intent();

    // A database worker may be reclaimed after the public SDK queued the first
    // proposal but before its fenced state transition; repeating the public API
    // is deliberate at-least-once behavior.
    let first = handoff(adapter.as_ref(), &intent).await.unwrap();
    let second = handoff(adapter.as_ref(), &intent).await.unwrap();
    assert!(matches!(
        (&first, &second),
        (
            HandoffResult { outbound_message_id: 42, event_id, payment_request_id },
            HandoffResult { outbound_message_id: 42, event_id: second_event, payment_request_id: second_request }
        ) if event_id == "event-42" && payment_request_id == "request-42" && second_event == event_id && second_request == payment_request_id
    ));
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 2);
}
