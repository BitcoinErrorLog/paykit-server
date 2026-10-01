use crate::{bitkit_claim::ClaimError, persistence::PersistenceError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupStage {
    AuthComplete,
    IdentityValidate,
    SessionExport,
    RelayReceive,
    ClaimVerify,
    XpubValidate,
    LockAcquire,
    CreatorLoad,
    AppPublish,
    AppReadback,
    Persistence,
    LockRelease,
    RelayAck,
}

impl SetupStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AuthComplete => "auth_complete",
            Self::IdentityValidate => "identity_validate",
            Self::SessionExport => "session_export",
            Self::RelayReceive => "relay_receive",
            Self::ClaimVerify => "claim_verify",
            Self::XpubValidate => "xpub_validate",
            Self::LockAcquire => "lock_acquire",
            Self::CreatorLoad => "creator_load",
            Self::AppPublish => "app_publish",
            Self::AppReadback => "app_readback",
            Self::Persistence => "persistence",
            Self::LockRelease => "lock_release",
            Self::RelayAck => "relay_ack",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupOutcome {
    Started,
    Succeeded,
    Failed,
    Absent,
}

impl SetupOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Absent => "absent",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupFailureClass {
    None,
    InvalidIdentity,
    Transport,
    BodyAbsent,
    InvalidRequest,
    InvalidPayload,
    InvalidEnvelope,
    Authentication,
    Storage,
    ReadbackMismatch,
    InvalidData,
    NotFound,
    Policy,
    PaymentAdapter,
    RecoveryRequired,
    DeploymentMismatch,
    CorruptState,
    AccountMismatch,
    Conflict,
    Unknown,
}

impl SetupFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::InvalidIdentity => "invalid_identity",
            Self::Transport => "transport",
            Self::BodyAbsent => "body_absent",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidPayload => "invalid_payload",
            Self::InvalidEnvelope => "invalid_envelope",
            Self::Authentication => "authentication",
            Self::Storage => "storage",
            Self::ReadbackMismatch => "readback_mismatch",
            Self::InvalidData => "invalid_data",
            Self::NotFound => "not_found",
            Self::Policy => "policy",
            Self::PaymentAdapter => "payment_adapter",
            Self::RecoveryRequired => "recovery_required",
            Self::DeploymentMismatch => "deployment_mismatch",
            Self::CorruptState => "corrupt_state",
            Self::AccountMismatch => "account_mismatch",
            Self::Conflict => "conflict",
            Self::Unknown => "unknown",
        }
    }
}

pub(crate) fn claim_failure_class(error: &ClaimError) -> SetupFailureClass {
    match error {
        ClaimError::InvalidAuthRequest => SetupFailureClass::InvalidRequest,
        ClaimError::InvalidPayload => SetupFailureClass::InvalidPayload,
        ClaimError::InvalidEnvelope => SetupFailureClass::InvalidEnvelope,
        ClaimError::AuthenticationFailed => SetupFailureClass::Authentication,
    }
}

pub(crate) fn registry_failure_class(error: &paykit_lib::PaykitError) -> SetupFailureClass {
    match error {
        paykit_lib::PaykitError::Transport { .. } => SetupFailureClass::Transport,
        paykit_lib::PaykitError::NotFound(_) => SetupFailureClass::NotFound,
        paykit_lib::PaykitError::InvalidData { .. } | paykit_lib::PaykitError::Validation(_) => {
            SetupFailureClass::InvalidData
        }
    }
}

pub(crate) fn sdk_failure_class(error: &paykit_sdk::PaykitSdkError) -> SetupFailureClass {
    match error {
        paykit_sdk::PaykitSdkError::Storage { .. } => SetupFailureClass::Storage,
        paykit_sdk::PaykitSdkError::Identity { .. } => SetupFailureClass::InvalidIdentity,
        paykit_sdk::PaykitSdkError::Transport { .. } => SetupFailureClass::Transport,
        paykit_sdk::PaykitSdkError::NotFound { .. } => SetupFailureClass::NotFound,
        paykit_sdk::PaykitSdkError::Protocol { .. } => SetupFailureClass::InvalidRequest,
        paykit_sdk::PaykitSdkError::Policy { .. } => SetupFailureClass::Policy,
        paykit_sdk::PaykitSdkError::PaymentAdapter { .. } => SetupFailureClass::PaymentAdapter,
        paykit_sdk::PaykitSdkError::RecoveryRequired { .. } => SetupFailureClass::RecoveryRequired,
        _ => SetupFailureClass::Unknown,
    }
}

pub(crate) fn persistence_failure_class(error: &PersistenceError) -> SetupFailureClass {
    match error {
        PersistenceError::DeploymentMismatch => SetupFailureClass::DeploymentMismatch,
        PersistenceError::CorruptOrMissing => SetupFailureClass::CorruptState,
        PersistenceError::ReauthenticationMismatch => SetupFailureClass::AccountMismatch,
        PersistenceError::Unavailable => SetupFailureClass::Storage,
        PersistenceError::Conflict => SetupFailureClass::Conflict,
    }
}

pub(crate) fn emit_setup_stage(stage: SetupStage, outcome: SetupOutcome, class: SetupFailureClass) {
    let stage = stage.as_str();
    let outcome = outcome.as_str();
    let class = class.as_str();
    match outcome {
        "failed" | "absent" => tracing::warn!(
            event = "paykit_setup_completion",
            stage,
            outcome,
            class,
            "Paykit setup completion stage"
        ),
        _ => tracing::info!(
            event = "paykit_setup_completion",
            stage,
            outcome,
            class,
            "Paykit setup completion stage"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing::{Event, Subscriber};
    use tracing_subscriber::{Layer, layer::Context, prelude::*};

    use super::*;

    type CapturedEvents = Vec<Vec<(String, String)>>;

    #[derive(Clone, Default)]
    struct EventCapture(Arc<Mutex<CapturedEvents>>);

    impl<S> Layer<S> for EventCapture
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            let mut fields = Vec::new();
            event.record(&mut FieldVisitor(&mut fields));
            self.0.lock().unwrap().push(fields);
        }
    }

    struct FieldVisitor<'a>(&'a mut Vec<(String, String)>);

    impl tracing::field::Visit for FieldVisitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
            self.0.push((field.name().to_owned(), format!("{value:?}")));
        }
    }

    #[test]
    fn emits_only_closed_secret_free_fields() {
        let capture = EventCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            emit_setup_stage(
                SetupStage::RelayReceive,
                SetupOutcome::Absent,
                SetupFailureClass::BodyAbsent,
            );
        });

        let events = capture.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        let fields = &events[0];
        for name in ["event", "stage", "outcome", "class", "message"] {
            assert!(fields.iter().any(|(field, _)| field == name));
        }
        for forbidden in [
            "flow_id",
            "creator",
            "authorization_url",
            "relay",
            "secret",
            "session",
            "xpub",
            "payload",
            "error",
        ] {
            assert!(fields.iter().all(|(name, _)| name != forbidden));
        }
    }

    #[test]
    fn vocabulary_is_stable() {
        assert_eq!(SetupStage::AuthComplete.as_str(), "auth_complete");
        assert_eq!(SetupStage::ClaimVerify.as_str(), "claim_verify");
        assert_eq!(SetupStage::XpubValidate.as_str(), "xpub_validate");
        assert_eq!(SetupStage::AppPublish.as_str(), "app_publish");
        assert_eq!(SetupStage::AppReadback.as_str(), "app_readback");
        assert_eq!(SetupStage::Persistence.as_str(), "persistence");
        assert_eq!(SetupStage::LockRelease.as_str(), "lock_release");
        assert_eq!(SetupStage::RelayAck.as_str(), "relay_ack");
    }

    #[test]
    fn typed_failures_map_to_distinct_closed_classes() {
        for (error, expected) in [
            (
                paykit_lib::PaykitError::Transport {
                    context: "not logged".into(),
                    source: anyhow::anyhow!("not logged"),
                },
                SetupFailureClass::Transport,
            ),
            (
                paykit_lib::PaykitError::NotFound("not logged".into()),
                SetupFailureClass::NotFound,
            ),
            (
                paykit_lib::PaykitError::InvalidData {
                    context: "not logged".into(),
                    source: None,
                },
                SetupFailureClass::InvalidData,
            ),
            (
                paykit_lib::PaykitError::Validation("not logged".into()),
                SetupFailureClass::InvalidData,
            ),
        ] {
            assert_eq!(registry_failure_class(&error), expected);
        }

        for (error, expected) in [
            (
                paykit_sdk::PaykitSdkError::Storage {
                    context: "not logged".into(),
                    source: None,
                },
                SetupFailureClass::Storage,
            ),
            (
                paykit_sdk::PaykitSdkError::Identity {
                    context: "not logged".into(),
                    source: None,
                },
                SetupFailureClass::InvalidIdentity,
            ),
            (
                paykit_sdk::PaykitSdkError::Transport {
                    context: "not logged".into(),
                    source: None,
                },
                SetupFailureClass::Transport,
            ),
            (
                paykit_sdk::PaykitSdkError::NotFound {
                    context: "not logged".into(),
                    source: None,
                },
                SetupFailureClass::NotFound,
            ),
            (
                paykit_sdk::PaykitSdkError::Protocol {
                    context: "not logged".into(),
                    source: None,
                },
                SetupFailureClass::InvalidRequest,
            ),
            (
                paykit_sdk::PaykitSdkError::Policy {
                    context: "not logged".into(),
                    source: None,
                },
                SetupFailureClass::Policy,
            ),
            (
                paykit_sdk::PaykitSdkError::PaymentAdapter {
                    context: "not logged".into(),
                    source: None,
                },
                SetupFailureClass::PaymentAdapter,
            ),
            (
                paykit_sdk::PaykitSdkError::RecoveryRequired {
                    context: "not logged".into(),
                    source: None,
                },
                SetupFailureClass::RecoveryRequired,
            ),
        ] {
            assert_eq!(sdk_failure_class(&error), expected);
        }

        for (error, expected) in [
            (
                PersistenceError::DeploymentMismatch,
                SetupFailureClass::DeploymentMismatch,
            ),
            (
                PersistenceError::CorruptOrMissing,
                SetupFailureClass::CorruptState,
            ),
            (
                PersistenceError::ReauthenticationMismatch,
                SetupFailureClass::AccountMismatch,
            ),
            (PersistenceError::Unavailable, SetupFailureClass::Storage),
            (PersistenceError::Conflict, SetupFailureClass::Conflict),
        ] {
            assert_eq!(persistence_failure_class(&error), expected);
        }
    }

    #[test]
    fn mapped_failure_emission_does_not_format_source_error() {
        let error = paykit_lib::PaykitError::InvalidData {
            context: "sensitive source detail".into(),
            source: Some(anyhow::anyhow!("sensitive nested source detail")),
        };
        let capture = EventCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            emit_setup_stage(
                SetupStage::AppReadback,
                SetupOutcome::Failed,
                registry_failure_class(&error),
            );
        });

        let events = capture.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            events[0]
                .iter()
                .any(|(name, value)| { name == "class" && value.contains("invalid_data") })
        );
        assert!(
            events[0]
                .iter()
                .all(|(_, value)| !value.contains("sensitive source detail"))
        );
        assert!(
            events[0]
                .iter()
                .all(|(_, value)| !value.contains("sensitive nested source detail"))
        );
    }
}
