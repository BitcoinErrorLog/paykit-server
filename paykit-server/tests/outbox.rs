use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use paykit_lib::{
    PaykitApp, PaykitAppCapabilities, PaykitAppId, PaykitAppRegistry, PaymentAmount,
    PaymentEndpointIdentifier, PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
    PublicKey,
};
use paykit_sdk::OutboundPrivateMessageStatus;
use paykit_server::{
    application::{
        create_invoice::ReaderAuthorization,
        semantic_intent::{DeliveryIntentV1, PaymentTermsV1},
    },
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
    authorization: Result<ReaderAuthorization, HandoffError>,
    recovery_marker_error: Option<HandoffError>,
    link_error: Option<HandoffError>,
    payment_request_calls: Mutex<usize>,
    calls: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl Adapter for FakeAdapter {
    async fn fetch_registry(
        &self,
        _reader: &str,
    ) -> Result<Option<PaykitAppRegistry>, HandoffError> {
        self.calls.lock().unwrap().push("fetch_registry");
        Ok(Some(self.registry.clone()))
    }

    async fn fetch_authorization(
        &self,
        _reader: &str,
    ) -> Result<ReaderAuthorization, HandoffError> {
        self.calls.lock().unwrap().push("fetch_authorization");
        self.authorization
    }

    async fn observe_recovery_marker(&self, _reader: &str) -> Result<(), HandoffError> {
        self.calls.lock().unwrap().push("observe_recovery_marker");
        self.recovery_marker_error.map_or(Ok(()), Err)
    }

    async fn ensure_link_with_peer(&self, _reader: &str) -> Result<(), HandoffError> {
        self.calls.lock().unwrap().push("ensure_link_with_peer");
        self.link_error.map_or(Ok(()), Err)
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
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

    async fn cancel_payment_request(
        &self,
        _reader: &str,
        _payment_request_id: &str,
    ) -> Result<HandoffResult, HandoffError> {
        Err(HandoffError::Permanent)
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
        authorization: Ok(ReaderAuthorization::Verified),
        recovery_marker_error: None,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
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
        authorization: Ok(ReaderAuthorization::Verified),
        recovery_marker_error: None,
        link_error: Some(HandoffError::Retryable(RetryableHandoffCause::Transport)),
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
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
        authorization: Ok(ReaderAuthorization::Verified),
        recovery_marker_error: None,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
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
            HandoffResult::PaymentRequestProposal { outbound_message_id: 42, event_id, payment_request_id },
            HandoffResult::PaymentRequestProposal { outbound_message_id: 42, event_id: second_event, payment_request_id: second_request }
        ) if event_id == "event-42" && payment_request_id == "request-42" && second_event == event_id && second_request == payment_request_id
    ));
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 2);
}

#[tokio::test]
async fn recovery_marker_observation_precedes_link_ensure_and_enqueue() {
    let selected = registry(true);
    let adapter = FakeAdapter {
        registry: selected,
        authorization: Ok(ReaderAuthorization::Verified),
        recovery_marker_error: None,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    handoff(&adapter, &payment_intent()).await.unwrap();

    assert_eq!(
        *adapter.calls.lock().unwrap(),
        [
            "fetch_registry",
            "fetch_authorization",
            "observe_recovery_marker",
            "ensure_link_with_peer",
            "propose_payment_request",
        ]
    );
}

#[tokio::test]
async fn recovery_marker_lookup_failure_never_ensures_or_enqueues() {
    let selected = registry(true);
    let adapter = FakeAdapter {
        registry: selected,
        authorization: Ok(ReaderAuthorization::Verified),
        recovery_marker_error: Some(HandoffError::Retryable(RetryableHandoffCause::Transport)),
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    assert_eq!(
        handoff(&adapter, &payment_intent()).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::RecoveryMarkerObservation
        ))
    );
    assert_eq!(
        *adapter.calls.lock().unwrap(),
        [
            "fetch_registry",
            "fetch_authorization",
            "observe_recovery_marker"
        ]
    );
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn confirmed_absent_recovery_marker_continues_to_link_ensure() {
    let selected = registry(true);
    let adapter = FakeAdapter {
        registry: selected,
        authorization: Ok(ReaderAuthorization::Verified),
        recovery_marker_error: None,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    handoff(&adapter, &payment_intent()).await.unwrap();

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

fn adapter_with_authorization(
    authorization: Result<ReaderAuthorization, HandoffError>,
) -> FakeAdapter {
    FakeAdapter {
        registry: registry(true),
        authorization,
        recovery_marker_error: None,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    }
}

#[tokio::test]
async fn missing_or_invalid_reader_authorization_is_retryable_without_link_or_handoff() {
    for (authorization, stage) in [
        (
            ReaderAuthorization::Missing,
            RetryableHandoffStage::ReaderAuthorizationMissing,
        ),
        (
            ReaderAuthorization::Invalid,
            RetryableHandoffStage::ReaderAuthorizationInvalid,
        ),
    ] {
        let adapter = adapter_with_authorization(Ok(authorization));

        assert_eq!(
            handoff(&adapter, &payment_intent()).await,
            Err(HandoffFailure::Retryable(stage))
        );
        assert_eq!(
            *adapter.calls.lock().unwrap(),
            ["fetch_registry", "fetch_authorization"]
        );
        assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
    }
}

#[tokio::test]
async fn reader_authorization_fetch_failure_keeps_its_own_stage() {
    let adapter = adapter_with_authorization(Err(HandoffError::Retryable(
        RetryableHandoffCause::Transport,
    )));

    assert_eq!(
        handoff(&adapter, &payment_intent()).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::ReaderAuthorizationFetch
        ))
    );
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
}
