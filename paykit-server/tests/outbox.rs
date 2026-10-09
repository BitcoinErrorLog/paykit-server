use std::sync::Mutex;

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
                    private_payments: false,
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

    async fn ensure_link_with_peer(&self, _reader: &str) -> Result<(), HandoffError> {
        self.calls.lock().unwrap().push("ensure_link_with_peer");
        self.link_error.map_or(Ok(()), Err)
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
        payment_request_id: paykit_lib::PaymentRequestId,
        _terms: &PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        self.calls.lock().unwrap().push("propose_payment_request");
        *self.payment_request_calls.lock().unwrap() += 1;
        Ok(HandoffResult::PaymentRequestProposal {
            outbound_message_id: 42,
            event_id: "event-42".into(),
            payment_request_id: payment_request_id.to_string(),
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
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    assert_eq!(
        handoff(&adapter, uuid::Uuid::new_v4(), &payment_intent()).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::RegistryIncapable
        ))
    );
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn retry_after_an_ambiguous_handoff_reuses_outbox_id() {
    let selected = registry(true);
    let adapter = FakeAdapter {
        registry: selected.clone(),
        authorization: Ok(ReaderAuthorization::Verified),
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };
    let intent = payment_intent();
    let outbox_id = uuid::Uuid::new_v4();

    let first = handoff(&adapter, outbox_id, &intent).await.unwrap();
    let second = handoff(&adapter, outbox_id, &intent).await.unwrap();
    assert!(matches!(
        (&first, &second),
        (
            HandoffResult::PaymentRequestProposal { outbound_message_id: 42, event_id, payment_request_id },
            HandoffResult::PaymentRequestProposal { outbound_message_id: 42, event_id: second_event, payment_request_id: second_request }
        ) if event_id == "event-42" && payment_request_id == &outbox_id.to_string() && second_event == event_id && second_request == payment_request_id
    ));
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 2);
}

#[tokio::test]
async fn handoff_validates_authorization_and_link_before_enqueue() {
    let selected = registry(true);
    let adapter = FakeAdapter {
        registry: selected,
        authorization: Ok(ReaderAuthorization::Verified),
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    handoff(&adapter, uuid::Uuid::new_v4(), &payment_intent())
        .await
        .unwrap();

    assert_eq!(
        *adapter.calls.lock().unwrap(),
        [
            "fetch_registry",
            "fetch_authorization",
            "ensure_link_with_peer",
            "propose_payment_request",
        ]
    );
}

#[tokio::test]
async fn link_observation_failure_never_enqueues() {
    let selected = registry(true);
    let adapter = FakeAdapter {
        registry: selected,
        authorization: Ok(ReaderAuthorization::Verified),
        link_error: Some(HandoffError::Retryable(
            RetryableHandoffCause::LinkObservation,
        )),
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };

    assert_eq!(
        handoff(&adapter, uuid::Uuid::new_v4(), &payment_intent()).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::LinkEstablishment
        ))
    );
    assert_eq!(
        *adapter.calls.lock().unwrap(),
        [
            "fetch_registry",
            "fetch_authorization",
            "ensure_link_with_peer"
        ]
    );
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
}

fn adapter_with_authorization(
    authorization: Result<ReaderAuthorization, HandoffError>,
) -> FakeAdapter {
    FakeAdapter {
        registry: registry(true),
        authorization,
        link_error: None,
        payment_request_calls: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    }
}

#[tokio::test]
async fn invalid_outbox_id_is_rejected_before_adapter_effects() {
    let adapter = adapter_with_authorization(Ok(ReaderAuthorization::Verified));

    assert_eq!(
        handoff(&adapter, uuid::Uuid::nil(), &payment_intent()).await,
        Err(HandoffFailure::Permanent)
    );
    assert!(adapter.calls.lock().unwrap().is_empty());
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
            handoff(&adapter, uuid::Uuid::new_v4(), &payment_intent()).await,
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
        handoff(&adapter, uuid::Uuid::new_v4(), &payment_intent()).await,
        Err(HandoffFailure::Retryable(
            RetryableHandoffStage::ReaderAuthorizationFetch
        ))
    );
    assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn pending_links_are_distinct_from_failed_link_operations() {
    for (cause, expected) in [
        (
            RetryableHandoffCause::LinkPending,
            RetryableHandoffStage::LinkPending,
        ),
        (
            RetryableHandoffCause::Transport,
            RetryableHandoffStage::LinkEstablishment,
        ),
        (
            RetryableHandoffCause::Storage,
            RetryableHandoffStage::LinkEstablishment,
        ),
    ] {
        let mut adapter = adapter_with_authorization(Ok(ReaderAuthorization::Verified));
        adapter.link_error = Some(HandoffError::Retryable(cause));
        assert_eq!(
            handoff(&adapter, uuid::Uuid::new_v4(), &payment_intent()).await,
            Err(HandoffFailure::Retryable(expected))
        );
        assert_eq!(*adapter.payment_request_calls.lock().unwrap(), 0);
    }
}
