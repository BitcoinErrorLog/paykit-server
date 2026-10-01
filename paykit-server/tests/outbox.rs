use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use paykit_lib::{
    PaykitReceiverCapabilities, PaykitReceiverMarker, PaykitReceiverPath, PaymentAmount,
    PaymentEndpointIdentifier, PaymentReference, PaymentRequestTerms, PublicKey,
};
use paykit_sdk::OutboundPrivateMessageStatus;
use paykit_server::{
    application::semantic_intent::{DeliveryIntentV1, PaymentTermsV1, ReceivingDetailV1},
    workers::outbox::{
        Adapter, HandoffError, HandoffFailure, HandoffResult, RetryableHandoffCause,
        RetryableHandoffStage, handoff,
    },
};

fn marker(path: &str) -> PaykitReceiverMarker {
    PaykitReceiverMarker::new(
        PaykitReceiverPath::new(path).unwrap(),
        PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: true,
        },
        PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap(),
    )
}

struct FakeAdapter {
    marker: PaykitReceiverMarker,
    recovery_marker_error: Option<HandoffError>,
    link_error: Option<HandoffError>,
    payment_request_calls: Mutex<usize>,
    calls: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl Adapter for FakeAdapter {
    async fn fetch_marker(
        &self,
        _reader: &str,
        _path: &str,
    ) -> Result<Option<PaykitReceiverMarker>, HandoffError> {
        self.calls.lock().unwrap().push("fetch_marker");
        Ok(Some(self.marker.clone()))
    }

    async fn observe_recovery_marker(
        &self,
        _reader: &str,
        _path: &str,
    ) -> Result<(), HandoffError> {
        self.calls.lock().unwrap().push("observe_recovery_marker");
        self.recovery_marker_error.map_or(Ok(()), Err)
    }

    async fn ensure_link_with_peer(&self, _reader: &str, _path: &str) -> Result<(), HandoffError> {
        self.calls.lock().unwrap().push("ensure_link_with_peer");
        self.link_error.map_or(Ok(()), Err)
    }

    async fn enqueue_private_payment_list_with_receiving_details(
        &self,
        _reader: &str,
        _path: &str,
        _details: &[ReceivingDetailV1],
    ) -> Result<HandoffResult, HandoffError> {
        Ok(HandoffResult::EndpointPublication {
            outbound_message_id: 41,
        })
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
        _path: &str,
        _terms: &PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        self.calls.lock().unwrap().push("propose_payment_request");
        *self.payment_request_calls.lock().unwrap() += 1;
        Ok(HandoffResult::PaymentRequestProposal {
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

fn payment_intent(marker: &PaykitReceiverMarker) -> DeliveryIntentV1 {
    DeliveryIntentV1::payment_request(
        "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy".into(),
        marker,
        PaykitReceiverPath::new("paykit/server").unwrap(),
        &PaymentRequestTerms {
            amount: PaymentAmount::new("0.00050000", "btc").unwrap(),
            payment_reference: PaymentReference::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            proposal_expires_at: None,
            recurrence: None,
            accepted_payment_endpoint_identifiers: vec![
                PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
            ],
            metadata: Default::default(),
        },
    )
    .unwrap()
}

#[tokio::test]
async fn changed_selected_marker_is_retryable_without_a_reselection() {
    let selected = marker("bitkit/wallet");
    let changed = marker("other/wallet");
    let adapter = FakeAdapter {
        marker: changed,
        recovery_marker_error: None,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    assert_eq!(
        handoff(&adapter, &payment_intent(&selected)).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::MarkerChanged
        ))
    );
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn link_failure_has_one_durable_diagnostic_stage() {
    let selected = marker("bitkit/wallet");
    let adapter = FakeAdapter {
        marker: selected.clone(),
        recovery_marker_error: None,
        link_error: Some(HandoffError::Retryable(RetryableHandoffCause::Transport)),
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    assert_eq!(
        handoff(&adapter, &payment_intent(&selected)).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::LinkEstablishment
        ))
    );
}

#[tokio::test]
async fn retry_after_an_ambiguous_handoff_can_propose_twice() {
    let selected = marker("bitkit/wallet");
    let adapter = Arc::new(FakeAdapter {
        marker: selected.clone(),
        recovery_marker_error: None,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    });
    let intent = payment_intent(&selected);

    // A database worker may be reclaimed after the public SDK queued the first
    // proposal but before its fenced state transition; repeating the public API
    // is deliberate at-least-once behavior.
    let first = handoff(adapter.as_ref(), &intent).await.unwrap();
    let second = handoff(adapter.as_ref(), &intent).await.unwrap();
    assert!(matches!(
        (&first, &second),
        (
            HandoffResult::PaymentRequestProposal { outbound_message_id: 42, event_id, payment_request_id },
            HandoffResult::PaymentRequestProposal { outbound_message_id: 42, event_id: second_event, payment_request_id: second_request }
        ) if event_id == "event-42" && payment_request_id == "request-42" && second_event == event_id && second_request == payment_request_id
    ));
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 2);
}

#[tokio::test]
async fn recovery_marker_observation_precedes_link_ensure_and_enqueue() {
    let selected = marker("bitkit/wallet");
    let adapter = FakeAdapter {
        marker: selected.clone(),
        recovery_marker_error: None,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    handoff(&adapter, &payment_intent(&selected)).await.unwrap();

    assert_eq!(
        *adapter.calls.lock().unwrap(),
        [
            "fetch_marker",
            "observe_recovery_marker",
            "ensure_link_with_peer",
            "propose_payment_request",
        ]
    );
}

#[tokio::test]
async fn recovery_marker_lookup_failure_never_ensures_or_enqueues() {
    let selected = marker("bitkit/wallet");
    let adapter = FakeAdapter {
        marker: selected.clone(),
        recovery_marker_error: Some(HandoffError::Retryable(RetryableHandoffCause::Transport)),
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    assert_eq!(
        handoff(&adapter, &payment_intent(&selected)).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::RecoveryMarkerObservation
        ))
    );
    assert_eq!(
        *adapter.calls.lock().unwrap(),
        ["fetch_marker", "observe_recovery_marker"]
    );
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn confirmed_absent_recovery_marker_continues_to_link_ensure() {
    let selected = marker("bitkit/wallet");
    let adapter = FakeAdapter {
        marker: selected.clone(),
        recovery_marker_error: None,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    handoff(&adapter, &payment_intent(&selected)).await.unwrap();

    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 1);
    assert!(
        adapter
            .calls
            .lock()
            .unwrap()
            .windows(2)
            .any(|calls| calls == ["observe_recovery_marker", "ensure_link_with_peer"])
    );
}
