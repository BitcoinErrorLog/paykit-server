//! Bounded external-I/O seams for the Bitkit companion receiver.
//!
//! The verifier is server-owned (`bitkit_claim`); these seams isolate only the
//! Pubky relay and durable/marker side effects so no unverified relay body can
//! reach persistence.

use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use pubky::{HttpRelayInboxChannel, PubkyHttpClient};

use crate::bitkit_claim::{
    AuthRequest, ClaimError, WatchOnlyAccountClaim, decrypt_and_verify, derive_channel_id,
};

#[async_trait]
pub trait CompanionRelay: Send + Sync {
    async fn receive(
        &self,
        request: &AuthRequest,
        deadline: Duration,
    ) -> Result<Option<Vec<u8>>, ClaimError>;
    /// Called only after marker publication/read-back and durable state commit.
    async fn acknowledge(&self, request: &AuthRequest) -> Result<(), ClaimError>;
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
    fn channel(&self, request: &AuthRequest) -> Result<HttpRelayInboxChannel, ClaimError> {
        HttpRelayInboxChannel::new(request.relay().clone(), derive_channel_id(request.secret()))
            .map_err(|_| ClaimError::InvalidAuthRequest)
    }
}

#[async_trait]
impl CompanionRelay for PubkyCompanionRelay {
    async fn receive(
        &self,
        request: &AuthRequest,
        deadline: Duration,
    ) -> Result<Option<Vec<u8>>, ClaimError> {
        self.channel(request)?
            .poll(&self.client, Some(deadline))
            .await
            .map_err(|_| ClaimError::InvalidEnvelope)
    }
    async fn acknowledge(&self, request: &AuthRequest) -> Result<(), ClaimError> {
        self.channel(request)?
            .ack(&self.client)
            .await
            .map(|_| ())
            .map_err(|_| ClaimError::InvalidEnvelope)
    }
}

#[async_trait]
pub trait VerifiedSetupCommit: Send + Sync {
    /// Must publish and read back the receiver marker, then commit encrypted
    /// creator credentials and SDK `StorageState`. It is deliberately invoked
    /// only after normal AUTH identity and claim signature agree.
    async fn publish_readback_and_commit(
        &self,
        claim: WatchOnlyAccountClaim,
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
    let Some(body) = relay.receive(request, deadline).await? else {
        return Ok(false);
    };
    let claim = decrypt_and_verify(&body, request.secret(), creator)?;
    commit.publish_readback_and_commit(claim).await?;
    relay.acknowledge(request).await?;
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        ) -> Result<Option<Vec<u8>>, ClaimError> {
            Ok(Some(self.body.clone()))
        }
        async fn acknowledge(&self, _: &AuthRequest) -> Result<(), ClaimError> {
            self.acks.fetch_add(1, Ordering::SeqCst);
            Ok(())
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
            _: WatchOnlyAccountClaim,
        ) -> Result<(), ClaimError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }
    fn request() -> AuthRequest {
        crate::bitkit_claim::parse_auth_request(&format!(
            "pubkyauth://signin_grant?caps={}&relay=https://relay.example/inbox&secret=AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM&cid=paykit.test&cpk=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo&x-bitkit-claim=watch-only-account-v1",
            crate::bitkit_claim::LOCAL_DEMO_CAPABILITIES
        ), crate::bitkit_claim::LOCAL_DEMO_CAPABILITIES)
        .unwrap()
    }
    fn body(secret: &[u8; 32], key: &SigningKey) -> Vec<u8> {
        let mut payload = [0; 84];
        payload[0] = 1;
        payload[5] = 0;
        let mut input = b"x-bitkit-claim|watch-only-account-v1|".to_vec();
        input.extend_from_slice(&Sha256::digest(secret));
        input.extend_from_slice(&payload);
        let mut signed = payload.to_vec();
        signed.extend_from_slice(&key.sign(&input).to_bytes());
        let nonce = [4; 24];
        let ciphertext = XSalsa20Poly1305::new(secret.into())
            .encrypt((&nonce).into(), signed.as_slice())
            .unwrap();
        [nonce.to_vec(), ciphertext].concat()
    }
    #[tokio::test]
    async fn no_durable_commit_or_ack_precedes_verified_claim_and_marker_readback() {
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
        assert_eq!(
            receive_verify_commit(
                &relay,
                &commit,
                &request,
                &other.verifying_key(),
                Duration::from_secs(1)
            )
            .await,
            Err(ClaimError::AuthenticationFailed)
        );
        assert_eq!(commit.calls.load(Ordering::SeqCst), 0);
        assert_eq!(relay.acks.load(Ordering::SeqCst), 0);
    }
}
