//! Bounded external-I/O seams for the Bitkit companion receiver.
//!
//! The verifier is server-owned (`bitkit_claim`); these seams isolate only the
//! Pubky relay and durable app-publication side effects so no unverified relay body can
//! reach persistence.

use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use pubky::{HttpRelayInboxChannel, PubkyHttpClient};

use crate::bitkit_claim::{
    AuthRequest, ClaimError, PAYKIT_ACCESS_CLAIM, VerifiedCompanionClaim, decrypt_and_verify,
    decrypt_and_verify_reconnect, derive_channel_id,
};
use crate::setup_diagnostics::{
    SetupFailureClass, SetupOutcome, SetupStage, claim_failure_class, emit_setup_stage,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompanionRelayError {
    InvalidRequest,
    Transport,
}

impl CompanionRelayError {
    fn failure_class(self) -> SetupFailureClass {
        match self {
            Self::InvalidRequest => SetupFailureClass::InvalidRequest,
            Self::Transport => SetupFailureClass::Transport,
        }
    }

    fn into_claim_error(self) -> ClaimError {
        match self {
            Self::InvalidRequest => ClaimError::InvalidAuthRequest,
            Self::Transport => ClaimError::InvalidEnvelope,
        }
    }
}

#[async_trait]
pub trait CompanionRelay: Send + Sync {
    async fn receive(
        &self,
        request: &AuthRequest,
        deadline: Duration,
    ) -> Result<Option<Vec<u8>>, CompanionRelayError>;
    /// Called only after credential persistence and app publication/read-back.
    async fn acknowledge(&self, request: &AuthRequest) -> Result<(), CompanionRelayError>;
}

/// The production relay boundary uses Pubky's public raw inbox channel, not
/// `EncryptedHttpRelayInboxChannel`: Bitkit's channel derivation is distinct
/// from its XSalsa20 key.
#[derive(Clone)]
pub struct PubkyCompanionRelay {
    client: PubkyHttpClient,
}

impl PubkyCompanionRelay {
    pub fn new(client: PubkyHttpClient) -> Self {
        Self { client }
    }
    fn channel(&self, request: &AuthRequest) -> Result<HttpRelayInboxChannel, CompanionRelayError> {
        HttpRelayInboxChannel::new(request.relay().clone(), derive_channel_id(request))
            .map_err(|_| CompanionRelayError::InvalidRequest)
    }
}

#[async_trait]
impl CompanionRelay for PubkyCompanionRelay {
    async fn receive(
        &self,
        request: &AuthRequest,
        deadline: Duration,
    ) -> Result<Option<Vec<u8>>, CompanionRelayError> {
        self.channel(request)?
            .poll(&self.client, Some(deadline))
            .await
            .map_err(|_| CompanionRelayError::Transport)
    }
    async fn acknowledge(&self, request: &AuthRequest) -> Result<(), CompanionRelayError> {
        self.channel(request)?
            .ack(&self.client)
            .await
            .map(|_| ())
            .map_err(|_| CompanionRelayError::Transport)
    }
}

#[async_trait]
pub trait VerifiedSetupCommit: Send + Sync {
    /// Must persist validated credentials, publish and read back the server app,
    /// and mark setup complete. It is deliberately invoked
    /// only after normal AUTH identity and claim signature agree.
    async fn publish_readback_and_commit(
        &self,
        claim: VerifiedCompanionClaim,
    ) -> Result<(), ClaimError>;
}

/// Receives one claim and enforces the no-ack-before-durable-commit invariant.
pub async fn receive_verify_commit<R, C>(
    relay: &R,
    commit: &C,
    request: &AuthRequest,
    creator: &VerifyingKey,
    deadline: Duration,
) -> Result<bool, ClaimError>
where
    R: CompanionRelay + ?Sized,
    C: VerifiedSetupCommit + ?Sized,
{
    emit_setup_stage(
        SetupStage::RelayReceive,
        SetupOutcome::Started,
        SetupFailureClass::None,
    );
    let body = match relay.receive(request, deadline).await {
        Ok(Some(body)) => {
            emit_setup_stage(
                SetupStage::RelayReceive,
                SetupOutcome::Succeeded,
                SetupFailureClass::None,
            );
            body
        }
        Ok(None) => {
            emit_setup_stage(
                SetupStage::RelayReceive,
                SetupOutcome::Absent,
                SetupFailureClass::BodyAbsent,
            );
            return Ok(false);
        }
        Err(error) => {
            emit_setup_stage(
                SetupStage::RelayReceive,
                SetupOutcome::Failed,
                error.failure_class(),
            );
            return Err(error.into_claim_error());
        }
    };
    emit_setup_stage(
        SetupStage::ClaimVerify,
        SetupOutcome::Started,
        SetupFailureClass::None,
    );
    let verified = if request.claim_type() == PAYKIT_ACCESS_CLAIM {
        decrypt_and_verify_reconnect(&body, request, creator).map(VerifiedCompanionClaim::Reconnect)
    } else {
        decrypt_and_verify(&body, request, creator).map(VerifiedCompanionClaim::Setup)
    };
    let claim = match verified {
        Ok(claim) => {
            emit_setup_stage(
                SetupStage::ClaimVerify,
                SetupOutcome::Succeeded,
                SetupFailureClass::None,
            );
            claim
        }
        Err(error) => {
            emit_setup_stage(
                SetupStage::ClaimVerify,
                SetupOutcome::Failed,
                claim_failure_class(&error),
            );
            return Err(error);
        }
    };
    commit.publish_readback_and_commit(claim).await?;
    emit_setup_stage(
        SetupStage::RelayAck,
        SetupOutcome::Started,
        SetupFailureClass::None,
    );
    if let Err(error) = relay.acknowledge(request).await {
        emit_setup_stage(
            SetupStage::RelayAck,
            SetupOutcome::Failed,
            error.failure_class(),
        );
        return Err(error.into_claim_error());
    }
    emit_setup_stage(
        SetupStage::RelayAck,
        SetupOutcome::Succeeded,
        SetupFailureClass::None,
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use crypto_secretbox::{
        XSalsa20Poly1305,
        aead::{Aead, KeyInit},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tracing::{Event, Subscriber, instrument::WithSubscriber};
    use tracing_subscriber::{Layer, layer::Context, prelude::*};

    type CapturedEventFields = Vec<Vec<(String, String)>>;

    #[derive(Clone, Default)]
    struct EventCapture(Arc<Mutex<CapturedEventFields>>);

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

    struct Relay {
        body: Vec<u8>,
        acks: AtomicUsize,
    }
    #[async_trait]
    impl CompanionRelay for Relay {
        async fn receive(
            &self,
            _: &AuthRequest,
            _: Duration,
        ) -> Result<Option<Vec<u8>>, CompanionRelayError> {
            Ok(Some(self.body.clone()))
        }
        async fn acknowledge(&self, _: &AuthRequest) -> Result<(), CompanionRelayError> {
            self.acks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    struct FailingRelay(CompanionRelayError);
    #[async_trait]
    impl CompanionRelay for FailingRelay {
        async fn receive(
            &self,
            _: &AuthRequest,
            _: Duration,
        ) -> Result<Option<Vec<u8>>, CompanionRelayError> {
            Err(self.0)
        }
        async fn acknowledge(&self, _: &AuthRequest) -> Result<(), CompanionRelayError> {
            Err(self.0)
        }
    }
    struct FailingAckRelay {
        body: Vec<u8>,
    }
    #[async_trait]
    impl CompanionRelay for FailingAckRelay {
        async fn receive(
            &self,
            _: &AuthRequest,
            _: Duration,
        ) -> Result<Option<Vec<u8>>, CompanionRelayError> {
            Ok(Some(self.body.clone()))
        }
        async fn acknowledge(&self, _: &AuthRequest) -> Result<(), CompanionRelayError> {
            Err(CompanionRelayError::Transport)
        }
    }
    struct Commit {
        calls: AtomicUsize,
        result: Result<(), ClaimError>,
    }
    #[async_trait]
    impl VerifiedSetupCommit for Commit {
        async fn publish_readback_and_commit(
            &self,
            _: VerifiedCompanionClaim,
        ) -> Result<(), ClaimError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }
    fn request() -> AuthRequest {
        let client_public_key = pubky::Keypair::from_secret(&[7; 32]).public_key();
        crate::bitkit_claim::parse_auth_request(&format!(
            "pubkyauth://signin_grant?caps={}&relay=https://relay.example/inbox&secret=AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM&cid=app.paykit.server&cpk={}&x-bitkit-claim=paykit-access-v1.watch-only-account-v1",
            crate::bitkit_claim::LOCAL_DEMO_CAPABILITIES,
            client_public_key.as_inner(),
        ), crate::bitkit_claim::LOCAL_DEMO_CAPABILITIES)
        .unwrap()
    }
    fn body(secret: &[u8; 32], key: &SigningKey) -> Vec<u8> {
        let mut payload = zeroize::Zeroizing::new([0; crate::bitkit_claim::UNSIGNED_PAYLOAD_LEN]);
        payload[84..92].copy_from_slice(&1u64.to_be_bytes());
        payload[0] = 1;
        payload[5] = 0;
        let mut input = zeroize::Zeroizing::new(
            b"x-bitkit-claim|paykit-access-v1.watch-only-account-v1|".to_vec(),
        );
        input.extend_from_slice(&Sha256::digest(secret));
        input.extend_from_slice(payload.as_slice());
        let mut signed = zeroize::Zeroizing::new(payload.to_vec());
        signed.extend_from_slice(&key.sign(&input).to_bytes());
        let nonce = [4; 24];
        let ciphertext = XSalsa20Poly1305::new(secret.into())
            .encrypt((&nonce).into(), signed.as_slice())
            .unwrap();
        [nonce.to_vec(), ciphertext].concat()
    }
    #[tokio::test]
    async fn no_durable_commit_or_ack_precedes_verified_claim_and_app_publication() {
        let request = request();
        let key = SigningKey::from_bytes(&[8; 32]);
        let relay = Relay {
            body: body(request.secret(), &key),
            acks: AtomicUsize::new(0),
        };
        let failed = Commit {
            calls: AtomicUsize::new(0),
            result: Err(ClaimError::InvalidEnvelope),
        };
        assert_eq!(
            receive_verify_commit(
                &relay,
                &failed,
                &request,
                &key.verifying_key(),
                Duration::from_secs(1)
            )
            .await,
            Err(ClaimError::InvalidEnvelope)
        );
        assert_eq!(failed.calls.load(Ordering::SeqCst), 1);
        assert_eq!(relay.acks.load(Ordering::SeqCst), 0);
        let commit = Commit {
            calls: AtomicUsize::new(0),
            result: Ok(()),
        };
        assert!(
            receive_verify_commit(
                &relay,
                &commit,
                &request,
                &key.verifying_key(),
                Duration::from_secs(1)
            )
            .await
            .unwrap()
        );
        assert_eq!(commit.calls.load(Ordering::SeqCst), 1);
        assert_eq!(relay.acks.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn bad_signature_never_calls_repository_or_ack() {
        let request = request();
        let signer = SigningKey::from_bytes(&[8; 32]);
        let relay = Relay {
            body: body(request.secret(), &signer),
            acks: AtomicUsize::new(0),
        };
        let commit = Commit {
            calls: AtomicUsize::new(0),
            result: Ok(()),
        };
        let other = SigningKey::from_bytes(&[9; 32]);
        let capture = EventCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        assert_eq!(
            receive_verify_commit(
                &relay,
                &commit,
                &request,
                &other.verifying_key(),
                Duration::from_secs(1)
            )
            .with_subscriber(subscriber)
            .await,
            Err(ClaimError::AuthenticationFailed)
        );
        assert_eq!(commit.calls.load(Ordering::SeqCst), 0);
        assert_eq!(relay.acks.load(Ordering::SeqCst), 0);
        let events = capture.0.lock().unwrap();
        assert!(events.iter().any(|fields| {
            fields
                .iter()
                .any(|(name, value)| name == "stage" && value.contains("claim_verify"))
                && fields
                    .iter()
                    .any(|(name, value)| name == "outcome" && value.contains("failed"))
                && fields
                    .iter()
                    .any(|(name, value)| name == "class" && value.contains("authentication"))
        }));
    }

    #[tokio::test]
    async fn relay_receive_transport_failure_is_classified_before_coarse_mapping() {
        let request = request();
        let key = SigningKey::from_bytes(&[8; 32]);
        let relay = FailingRelay(CompanionRelayError::Transport);
        let commit = Commit {
            calls: AtomicUsize::new(0),
            result: Ok(()),
        };
        let capture = EventCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());

        assert_eq!(
            receive_verify_commit(
                &relay,
                &commit,
                &request,
                &key.verifying_key(),
                Duration::from_secs(1),
            )
            .with_subscriber(subscriber)
            .await,
            Err(ClaimError::InvalidEnvelope)
        );
        assert!(capture.0.lock().unwrap().iter().any(|fields| {
            fields
                .iter()
                .any(|(name, value)| name == "class" && value.contains("transport"))
        }));
    }

    #[tokio::test]
    async fn relay_ack_transport_failure_is_classified_after_commit() {
        let request = request();
        let key = SigningKey::from_bytes(&[8; 32]);
        let relay = FailingAckRelay {
            body: body(request.secret(), &key),
        };
        let commit = Commit {
            calls: AtomicUsize::new(0),
            result: Ok(()),
        };
        let capture = EventCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());

        assert_eq!(
            receive_verify_commit(
                &relay,
                &commit,
                &request,
                &key.verifying_key(),
                Duration::from_secs(1),
            )
            .with_subscriber(subscriber)
            .await,
            Err(ClaimError::InvalidEnvelope)
        );
        assert_eq!(commit.calls.load(Ordering::SeqCst), 1);
        assert!(capture.0.lock().unwrap().iter().any(|fields| {
            fields
                .iter()
                .any(|(name, value)| name == "stage" && value.contains("relay_ack"))
                && fields
                    .iter()
                    .any(|(name, value)| name == "outcome" && value.contains("failed"))
                && fields
                    .iter()
                    .any(|(name, value)| name == "class" && value.contains("transport"))
        }));
    }

    #[tokio::test]
    async fn successful_orchestration_emits_ordered_secret_free_stage_events() {
        let request = request();
        let key = SigningKey::from_bytes(&[8; 32]);
        let relay = Relay {
            body: body(request.secret(), &key),
            acks: AtomicUsize::new(0),
        };
        let commit = Commit {
            calls: AtomicUsize::new(0),
            result: Ok(()),
        };
        let capture = EventCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());

        assert!(
            receive_verify_commit(
                &relay,
                &commit,
                &request,
                &key.verifying_key(),
                Duration::from_secs(1),
            )
            .with_subscriber(subscriber)
            .await
            .unwrap()
        );

        let events = capture.0.lock().unwrap();
        let stages = events
            .iter()
            .filter_map(|fields| {
                let event = fields.iter().find(|(name, _)| name == "event")?.1.as_str();
                event.contains("paykit_setup_completion").then(|| {
                    let stage = fields
                        .iter()
                        .find(|(name, _)| name == "stage")
                        .unwrap()
                        .1
                        .clone();
                    let outcome = fields
                        .iter()
                        .find(|(name, _)| name == "outcome")
                        .unwrap()
                        .1
                        .clone();
                    (stage, outcome)
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(stages.len(), 6);
        for (index, (stage, outcome)) in [
            ("relay_receive", "started"),
            ("relay_receive", "succeeded"),
            ("claim_verify", "started"),
            ("claim_verify", "succeeded"),
            ("relay_ack", "started"),
            ("relay_ack", "succeeded"),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(stages[index].0.contains(stage));
            assert!(stages[index].1.contains(outcome));
        }
    }
}
