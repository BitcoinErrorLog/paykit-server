//! Authenticated Bitkit setup with delegated Paykit authority.
//!
//! Credentials are validated and persisted before SDK app publication. Failed
//! publication leaves retryable credentials, never registry compensation.

use async_trait::async_trait;
use bitcoin::bip32::Xpub;
use ed25519_dalek::VerifyingKey;
use paykit_lib::{PaykitApp, PaykitAppCapabilities, PaykitNoiseKeyAuthorization};
use paykit_sdk::{
    PaykitSdk, PaykitSdkConfig, PubkySessionAccess, PubkySessionProvider, PubkySharedStateStorage,
};
use std::{any::Any, sync::Arc, time::Duration};
use zeroize::Zeroizing;

use crate::{
    application::create_invoice::derive_bip84_p2wpkh_address,
    bitkit_claim::{ClaimError, VerifiedCompanionClaim},
    bitkit_setup::{BitkitAuthStarter, StartedBitkitAuth},
    config::{BitcoinNetwork, PAYKIT_APP_ID},
    domain::locks::{CreatorPubky, parse_creator},
    paykit::{CreatorSessions, ExplicitInputsPaymentAdapter},
    persistence::{CreatorCredentials, CreatorStore},
    setup::{Completion, SetupAttempt, SetupCompleter, StartedSetup},
    setup_diagnostics::{
        SetupFailureClass, SetupOutcome, SetupStage, claim_failure_class, emit_setup_stage,
        persistence_failure_class, registry_failure_class, sdk_failure_class,
    },
    setup_orchestration::{CompanionRelay, receive_verify_commit},
};

fn stage_result<T, E>(
    stage: SetupStage,
    result: Result<T, E>,
    classify: fn(&E) -> SetupFailureClass,
) -> Result<T, ClaimError> {
    match result {
        Ok(value) => {
            emit_setup_stage(stage, SetupOutcome::Succeeded, SetupFailureClass::None);
            Ok(value)
        }
        Err(error) => {
            emit_setup_stage(stage, SetupOutcome::Failed, classify(&error));
            Err(ClaimError::InvalidEnvelope)
        }
    }
}

/// Server capabilities for receiving payments and issuing Payment Requests.
pub fn server_app() -> PaykitApp {
    PaykitApp::new(
        "Paykit Server",
        PaykitAppCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: false,
        },
    )
    .expect("static server app is valid")
}

/// App publication is owned by the SDK's shared-state and App Registry locks.
#[async_trait]
pub trait AppPublisher: Send + Sync {
    async fn verify_key(&self, access: &PubkySessionAccess) -> Result<(), ClaimError>;
    /// Receives the process-shared live handle after persistence; do not restore
    /// its grant independently, which would invalidate concurrent workers' bearers.
    async fn publish(&self, access: PubkySessionAccess) -> Result<(), ClaimError>;
}

#[derive(Clone, Default)]
pub struct SharedAppPublisher;

#[derive(Clone)]
struct SetupSessionProvider(PubkySessionAccess);

#[async_trait]
impl PubkySessionProvider for SetupSessionProvider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        Ok(Some(self.0.clone()))
    }
    async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
        Err(paykit_sdk::PaykitSdkError::Policy {
            context: "setup does not revoke grants".into(),
            source: None,
        })
    }
    async fn load_public_storage(&self) -> paykit_sdk::Result<Option<pubky::PublicStorage>> {
        Ok(Some(self.0.outbox_client.public_storage()))
    }
}

/// Verifies delegated material against a verified, identity-signed authorization.
pub fn verify_authorized_key(
    authorization: &PaykitNoiseKeyAuthorization,
    key: &paykit_sdk::PaykitIdentitySecretKey,
) -> Result<(), ClaimError> {
    let noise_secret = Zeroizing::new(paykit_lib::derive_paykit_noise_secret_key(key.as_bytes()));
    if authorization.key_generation() != key.key_generation()
        || authorization.noise_public_key()
            != &paykit_lib::derive_paykit_noise_public_key(key.as_bytes())
        || authorization.noise_static_public_key()
            != &paykit_lib::pubky_noise::derive_static_public_key(&noise_secret)
    {
        return Err(ClaimError::AuthenticationFailed);
    }
    Ok(())
}

#[async_trait]
impl AppPublisher for SharedAppPublisher {
    async fn verify_key(&self, access: &PubkySessionAccess) -> Result<(), ClaimError> {
        let key = access
            .paykit_identity_secret_key
            .as_ref()
            .ok_or(ClaimError::InvalidPayload)?;
        let owner = access
            .public_key()
            .and_then(|key| key.to_public_key())
            .map_err(|_| ClaimError::AuthenticationFailed)?;
        let authorization = paykit_lib::get_paykit_noise_key_authorization(
            &access.outbox_client.public_storage(),
            &owner,
        )
        .await
        .map_err(|error| {
            emit_setup_stage(
                SetupStage::IdentityValidate,
                SetupOutcome::Failed,
                registry_failure_class(&error),
            );
            ClaimError::InvalidEnvelope
        })?
        .ok_or(ClaimError::AuthenticationFailed)?;
        stage_result(
            SetupStage::IdentityValidate,
            verify_authorized_key(&authorization, key),
            claim_failure_class,
        )
    }

    async fn publish(&self, access: PubkySessionAccess) -> Result<(), ClaimError> {
        let provider = SetupSessionProvider(access);
        let storage = PubkySharedStateStorage::new(provider.clone());
        let sdk = PaykitSdk::new(
            storage,
            provider,
            ExplicitInputsPaymentAdapter,
            PaykitSdkConfig::new(PAYKIT_APP_ID).map_err(|_| ClaimError::InvalidPayload)?,
        );
        // This merges only our app under SDK locks and preserves other apps and history.
        let registry = stage_result(
            SetupStage::AppPublish,
            sdk.publish_paykit_app(server_app()).await,
            sdk_failure_class,
        )?;
        let owner = sdk
            .identity_status()
            .await
            .map_err(|_| ClaimError::InvalidEnvelope)?
            .and_then(|status| status.public_key)
            .ok_or(ClaimError::AuthenticationFailed)?;
        let readback = sdk
            .paykit_app_registry(owner)
            .await
            .map_err(|_| ClaimError::InvalidEnvelope)?
            .ok_or(ClaimError::InvalidEnvelope)?;
        let app_id = paykit_lib::PaykitAppId::new(PAYKIT_APP_ID).expect("static app id");
        if readback.apps().get(&app_id) != registry.apps().get(&app_id) {
            emit_setup_stage(
                SetupStage::AppReadback,
                SetupOutcome::Failed,
                SetupFailureClass::ReadbackMismatch,
            );
            return Err(ClaimError::InvalidEnvelope);
        }
        emit_setup_stage(
            SetupStage::AppReadback,
            SetupOutcome::Succeeded,
            SetupFailureClass::None,
        );
        Ok(())
    }
}

#[derive(Clone)]
pub struct RealSetupCompleter {
    starter: BitkitAuthStarter,
    relay: Arc<dyn CompanionRelay>,
    publisher: Arc<dyn AppPublisher>,
    creators: CreatorStore,
    sessions: CreatorSessions,
    bitcoin_network: BitcoinNetwork,
    relay_deadline: Duration,
}

impl RealSetupCompleter {
    /// Uses the same Creator session cache as delivery workers and status queries.
    pub fn new(
        starter: BitkitAuthStarter,
        relay: Arc<dyn CompanionRelay>,
        creators: CreatorStore,
        sessions: CreatorSessions,
        bitcoin_network: BitcoinNetwork,
    ) -> Self {
        Self::with_app_publisher(
            starter,
            relay,
            Arc::new(SharedAppPublisher),
            creators,
            sessions,
            bitcoin_network,
        )
    }

    pub fn with_app_publisher(
        starter: BitkitAuthStarter,
        relay: Arc<dyn CompanionRelay>,
        publisher: Arc<dyn AppPublisher>,
        creators: CreatorStore,
        sessions: CreatorSessions,
        bitcoin_network: BitcoinNetwork,
    ) -> Self {
        Self {
            starter,
            relay,
            publisher,
            creators,
            sessions,
            bitcoin_network,
            relay_deadline: Duration::from_secs(30),
        }
    }
}

struct BitkitSetupAttempt {
    auth: StartedBitkitAuth,
    expected_creator: Option<CreatorPubky>,
}
impl SetupAttempt for BitkitSetupAttempt {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

#[async_trait]
impl SetupCompleter for RealSetupCompleter {
    async fn start(&self) -> Result<StartedSetup, Completion> {
        let started = self
            .starter
            .start()
            .await
            .map_err(|_| Completion::TransientUnavailable)?;
        Ok(StartedSetup::new(
            started.authorization_url.clone(),
            Box::new(BitkitSetupAttempt {
                auth: started,
                expected_creator: None,
            }),
        ))
    }

    async fn start_reconnect(&self, creator: &CreatorPubky) -> Result<StartedSetup, Completion> {
        self.creators
            .load_optional(creator)
            .await
            .map_err(|_| Completion::TransientUnavailable)?
            .ok_or(Completion::DefinitiveFailure)?;
        let started = self
            .starter
            .start_reconnect()
            .await
            .map_err(|_| Completion::TransientUnavailable)?;
        Ok(StartedSetup::new(
            started.authorization_url.clone(),
            Box::new(BitkitSetupAttempt {
                auth: started,
                expected_creator: Some(creator.clone()),
            }),
        ))
    }

    async fn complete(&self, attempt: Box<dyn SetupAttempt>) -> Completion {
        let Ok(attempt) = attempt.into_any().downcast::<BitkitSetupAttempt>() else {
            return Completion::DefinitiveFailure;
        };
        let BitkitSetupAttempt {
            auth: attempt,
            expected_creator,
        } = *attempt;
        let capabilities = attempt.capabilities().to_owned();
        let auth = match stage_result(
            SetupStage::AuthComplete,
            attempt.auth_request.complete(None, &capabilities).await,
            sdk_failure_class,
        ) {
            Ok(auth) => auth,
            Err(_) => return Completion::DefinitiveFailure,
        };
        let owner = match auth.public_key.to_public_key() {
            Ok(owner) => owner,
            Err(_) => return Completion::DefinitiveFailure,
        };
        let creator = match parse_creator(&auth.public_key.to_app_key()) {
            Ok(creator) => creator,
            Err(_) => return Completion::DefinitiveFailure,
        };
        if expected_creator
            .as_ref()
            .is_some_and(|expected| expected != &creator)
        {
            return Completion::DefinitiveFailure;
        }
        let verifying_key = match VerifyingKey::from_bytes(owner.as_bytes()) {
            Ok(key) => key,
            Err(_) => return Completion::DefinitiveFailure,
        };
        let session_secret = match stage_result(
            SetupStage::SessionExport,
            auth.export_session_secret().await,
            sdk_failure_class,
        ) {
            Ok(secret) => Zeroizing::new(secret.into_inner()),
            Err(_) => return Completion::DefinitiveFailure,
        };
        let commit = CreatorSetupCommit {
            access: auth.access,
            creator,
            session_secret,
            creators: self.creators.clone(),
            sessions: self.sessions.clone(),
            publisher: self.publisher.clone(),
            bitcoin_network: self.bitcoin_network.clone(),
            reconnect: expected_creator.is_some(),
        };
        match receive_verify_commit(
            self.relay.as_ref(),
            &commit,
            &attempt.request,
            &verifying_key,
            self.relay_deadline,
        )
        .await
        {
            Ok(true) => Completion::DurableSuccess,
            Ok(false) | Err(_) => Completion::DefinitiveFailure,
        }
    }
}

struct CreatorSetupCommit {
    access: PubkySessionAccess,
    creator: crate::domain::locks::CreatorPubky,
    session_secret: Zeroizing<String>,
    creators: CreatorStore,
    sessions: CreatorSessions,
    publisher: Arc<dyn AppPublisher>,
    bitcoin_network: BitcoinNetwork,
    reconnect: bool,
}

#[async_trait]
impl crate::setup_orchestration::VerifiedSetupCommit for CreatorSetupCommit {
    async fn publish_readback_and_commit(
        &self,
        claim: VerifiedCompanionClaim,
    ) -> Result<(), ClaimError> {
        let lock = stage_result(
            SetupStage::LockAcquire,
            self.creators.acquire_setup_lock(&self.creator).await,
            persistence_failure_class,
        )?;
        let result = async {
            let existing = stage_result(
                SetupStage::CreatorLoad,
                self.creators.load_optional(&self.creator).await,
                persistence_failure_class,
            )?;
            // Account binding comes only from initial setup, never a reconnect payload.
            let (xpub, account_index, key) = match (self.reconnect, claim, existing.as_ref()) {
                (false, VerifiedCompanionClaim::Setup(claim), None) => (
                    stage_result(
                        SetupStage::XpubValidate,
                        validate_xpub(
                            &claim.serialized_xpub,
                            claim.account_index,
                            &self.bitcoin_network,
                        ),
                        claim_failure_class,
                    )?,
                    claim.account_index,
                    claim.paykit_identity_secret_key,
                ),
                (true, VerifiedCompanionClaim::Reconnect(key), Some(existing)) => {
                    (existing.xpub().to_owned(), existing.account_index(), key)
                }
                _ => return Err(ClaimError::InvalidPayload),
            };
            let mut access = self.access.clone();
            access.paykit_identity_secret_key = Some(key.clone());
            let credentials = CreatorCredentials::new(
                self.creator.clone(),
                self.session_secret.to_string(),
                key,
                xpub,
                account_index,
            );
            if let Some(existing) = &existing {
                existing
                    .validate_reauthentication(&credentials)
                    .map_err(|_| ClaimError::InvalidPayload)?;
            }
            // Key authorization is verified before either credential or shared-state writes.
            self.publisher.verify_key(&access).await?;
            let persisted = if existing.is_some() {
                self.creators.reauthenticate(&credentials).await
            } else {
                self.creators.create(&credentials).await.map(|_| ())
            };
            stage_result(
                SetupStage::Persistence,
                persisted,
                persistence_failure_class,
            )?;
            // Restoring a Pubky grant replaces its bearer. Publication and workers must
            // therefore share the same cached handle after credentials are persisted.
            let access = self
                .sessions
                .provider(&self.creator)
                .load_session_access()
                .await
                .map_err(|_| ClaimError::InvalidEnvelope)?
                .ok_or(ClaimError::InvalidEnvelope)?;
            self.publisher.publish(access).await?;
            self.creators
                .mark_setup_complete(&self.creator)
                .await
                .map_err(|_| ClaimError::InvalidEnvelope)
        }
        .await;
        let unlocked = lock.release().await;
        result?;
        stage_result(SetupStage::LockRelease, unlocked, persistence_failure_class)
    }
}

/// Validates a BIP84 account xpub against the configured Bitcoin network and index.
pub fn validate_xpub(
    serialized_xpub: &[u8; 78],
    account_index: u32,
    configured_network: &BitcoinNetwork,
) -> Result<String, ClaimError> {
    let xpub = Xpub::decode(serialized_xpub).map_err(|_| ClaimError::InvalidPayload)?;
    let canonical = xpub.to_string();
    derive_bip84_p2wpkh_address(&canonical, account_index, configured_network, 0)
        .map_err(|_| ClaimError::InvalidPayload)?;
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_app_does_not_execute_payments_or_receive_receipts() {
        let capabilities = server_app().capabilities();
        assert!(capabilities.private_payments && capabilities.payment_requests);
        assert!(!capabilities.receipts && !capabilities.outgoing_payments);
    }

    #[test]
    fn delegated_key_must_match_authorized_material_and_generation() {
        let key = paykit_sdk::PaykitIdentitySecretKey::new([9; 32], 2).unwrap();
        let authorization = PaykitNoiseKeyAuthorization::sign(
            &pubky::Keypair::random(),
            &paykit_lib::derive_paykit_noise_secret_key(key.as_bytes()),
            2,
        )
        .unwrap();
        assert_eq!(verify_authorized_key(&authorization, &key), Ok(()));
        for wrong in [
            paykit_sdk::PaykitIdentitySecretKey::new([8; 32], 2).unwrap(),
            paykit_sdk::PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
        ] {
            assert_eq!(
                verify_authorized_key(&authorization, &wrong),
                Err(ClaimError::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn delegated_key_rejects_authorized_static_key_substitution() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let identity = pubky::Keypair::random();
        let key = paykit_sdk::PaykitIdentitySecretKey::new([9; 32], 2).unwrap();
        let authorization = PaykitNoiseKeyAuthorization::sign(
            &identity,
            &paykit_lib::derive_paykit_noise_secret_key(key.as_bytes()),
            key.key_generation(),
        )
        .unwrap();
        let substituted_static_key = [8; 32];
        let signed_bytes = [
            b"paykit.noise_key_authorization/v1\0".as_slice(),
            authorization.owner().as_bytes(),
            authorization.noise_public_key().as_bytes(),
            &substituted_static_key,
            &key.key_generation().to_be_bytes(),
        ]
        .concat();
        let mut wire = serde_json::to_value(&authorization).unwrap();
        wire["noise_static_public_key"] = serde_json::json!("08".repeat(32));
        wire["signature"] =
            serde_json::json!(STANDARD.encode(identity.sign(&signed_bytes).to_bytes()));
        let substituted: PaykitNoiseKeyAuthorization = serde_json::from_value(wire).unwrap();
        assert_eq!(
            substituted.noise_public_key(),
            authorization.noise_public_key()
        );
        assert_eq!(
            verify_authorized_key(&substituted, &key),
            Err(ClaimError::AuthenticationFailed)
        );
    }
}
