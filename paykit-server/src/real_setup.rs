//! Real server-side orchestration for one Bitkit setup flow.
//!
//! Normal Pubky AUTH is completed before the companion envelope is accepted.
//! The companion signature is verified against that authenticated creator, then
//! xpub validation, marker publish/read-back, encrypted persistence, and relay
//! acknowledgement happen in that order.

use std::{any::Any, sync::Arc, time::Duration};

use async_trait::async_trait;
use bitcoin::bip32::Xpub;
use ed25519_dalek::VerifyingKey;
use paykit_lib::{PaykitReceiverCapabilities, PaykitReceiverMarker, PaykitReceiverPath};
use paykit_sdk::{ReceiverNoiseSecretKey, storage::StorageState};

use crate::{
    application::create_invoice::derive_bip84_p2wpkh_address,
    bitkit_claim::{ClaimError, WatchOnlyAccountClaim},
    bitkit_setup::{BitkitAuthStarter, StartedBitkitAuth},
    config::{BitcoinNetwork, StackRole},
    domain::locks::parse_creator,
    key_identity::{MAX_CLAIMABLE_ACCOUNT_INDEX, canonical_key_tail, is_deny_listed},
    persistence::{CreatorCredentials, CreatorStore},
    setup::{Completion, SetupAttempt, SetupCompleter, StartedSetup},
    setup_orchestration::{CompanionRelay, receive_verify_commit},
};

fn default_marker_capabilities() -> PaykitReceiverCapabilities {
    PaykitReceiverCapabilities {
        private_payments: true,
        payment_requests: true,
        receipts: false,
        outgoing_payments: false,
    }
}

/// Marker I/O is a narrow test seam. Production uses [`DirectMarkerPublisher`],
/// which calls Paykit's Pubky helpers directly.
#[async_trait]
pub trait MarkerPublisher: Send + Sync {
    async fn publish_and_readback(
        &self,
        session: &pubky::PubkySession,
        public_storage_client: &pubky::Pubky,
        owner: &paykit_lib::PublicKey,
        marker: &PaykitReceiverMarker,
    ) -> Result<(), ClaimError>;
    async fn remove(
        &self,
        session: &pubky::PubkySession,
        receiver_path: &PaykitReceiverPath,
    ) -> Result<(), ClaimError>;
}

/// Production marker publisher: publish to the authenticated creator's
/// homeserver and independently read it back through public storage.
#[derive(Clone, Default)]
pub struct DirectMarkerPublisher;

#[async_trait]
impl MarkerPublisher for DirectMarkerPublisher {
    async fn publish_and_readback(
        &self,
        session: &pubky::PubkySession,
        public_storage_client: &pubky::Pubky,
        owner: &paykit_lib::PublicKey,
        marker: &PaykitReceiverMarker,
    ) -> Result<(), ClaimError> {
        paykit_lib::publish_paykit_receiver_marker(session, marker)
            .await
            .map_err(|_| ClaimError::InvalidEnvelope)?;
        let readback = paykit_lib::get_paykit_receiver_marker(
            &public_storage_client.public_storage(),
            owner,
            &marker.receiver_path,
        )
        .await
        .map_err(|_| ClaimError::InvalidEnvelope)?;
        (readback == Some(marker.clone()))
            .then_some(())
            .ok_or(ClaimError::InvalidEnvelope)
    }

    async fn remove(
        &self,
        session: &pubky::PubkySession,
        receiver_path: &PaykitReceiverPath,
    ) -> Result<(), ClaimError> {
        paykit_lib::remove_paykit_receiver_marker(session, receiver_path)
            .await
            .map_err(|_| ClaimError::InvalidEnvelope)
    }
}

/// Concrete server-owned `SetupCompleter` composed from the normal SDK auth
/// starter, Pubky companion relay, direct marker I/O, and encrypted CreatorStore.
#[derive(Clone)]
pub struct RealSetupCompleter {
    starter: BitkitAuthStarter,
    relay: Arc<dyn CompanionRelay>,
    marker_publisher: Arc<dyn MarkerPublisher>,
    creators: CreatorStore,
    bitcoin_network: BitcoinNetwork,
    stack_role: StackRole,
    receiver_path: PaykitReceiverPath,
    marker_capabilities: PaykitReceiverCapabilities,
    relay_deadline: Duration,
}

impl RealSetupCompleter {
    pub fn new(
        starter: BitkitAuthStarter,
        relay: Arc<dyn CompanionRelay>,
        creators: CreatorStore,
        bitcoin_network: BitcoinNetwork,
        stack_role: StackRole,
        receiver_path: PaykitReceiverPath,
    ) -> Self {
        Self::with_marker_publisher(
            starter,
            relay,
            Arc::new(DirectMarkerPublisher),
            creators,
            bitcoin_network,
            stack_role,
            receiver_path,
        )
    }

    pub fn with_marker_publisher(
        starter: BitkitAuthStarter,
        relay: Arc<dyn CompanionRelay>,
        marker_publisher: Arc<dyn MarkerPublisher>,
        creators: CreatorStore,
        bitcoin_network: BitcoinNetwork,
        stack_role: StackRole,
        receiver_path: PaykitReceiverPath,
    ) -> Self {
        Self {
            starter,
            relay,
            marker_publisher,
            creators,
            bitcoin_network,
            stack_role,
            receiver_path,
            marker_capabilities: default_marker_capabilities(),
            relay_deadline: Duration::from_secs(30),
        }
    }
}

struct BitkitSetupAttempt(StartedBitkitAuth);

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
            Box::new(BitkitSetupAttempt(started)),
        ))
    }

    async fn complete(&self, attempt: Box<dyn SetupAttempt>) -> Completion {
        let Ok(attempt) = attempt.into_any().downcast::<BitkitSetupAttempt>() else {
            return Completion::DefinitiveFailure;
        };
        let attempt = attempt.0;
        let capabilities = attempt.capabilities().to_owned();

        // The authenticated identity is not available until the normal auth
        // flow completes. Start with a fresh Noise key, then replace it with
        // the persisted key before any marker/persistence work on reauth.
        let auth = match attempt
            .auth_request
            .complete(None, ReceiverNoiseSecretKey::random(), &capabilities)
            .await
        {
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
        let verifying_key = match VerifyingKey::from_bytes(owner.as_bytes()) {
            Ok(key) => key,
            Err(_) => return Completion::DefinitiveFailure,
        };
        let session_secret = auth.export_session_secret().into_inner();
        let commit = CreatorSetupCommit {
            session: auth.access.session,
            public_storage_client: auth.access.outbox_client,
            owner,
            creator,
            session_secret,
            initial_noise_secret: auth.access.receiver_noise_secret_key,
            creators: self.creators.clone(),
            marker_publisher: self.marker_publisher.clone(),
            bitcoin_network: self.bitcoin_network.clone(),
            stack_role: self.stack_role,
            receiver_path: self.receiver_path.clone(),
            marker_capabilities: self.marker_capabilities,
            // The companion flow performs no claim-time history scan (§B.5
            // binds the manual claim endpoint); no cursor floor is applied.
            next_child_index_floor: None,
            // ...and §B.8.6's claim-channel checks bind the claim endpoint
            // too, so a companion setup is shared_manual by construction.
            allocation: crate::allocation::ClaimAllocation::companion_default(),
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
            // No relay body is not a successful setup and the consumed auth
            // request cannot be safely replayed.
            Ok(false) | Err(_) => Completion::DefinitiveFailure,
        }
    }
}

/// One authenticated watch-only account commit: xpub validation, marker
/// publish/read-back, and encrypted credential persistence under the
/// creator-scoped advisory lock. Shared by the Bitkit companion setup flow
/// and the manual claim endpoint, which authenticate the creator through
/// different channels but must persist the exact same account record.
pub(crate) struct CreatorSetupCommit {
    pub(crate) session: pubky::PubkySession,
    pub(crate) public_storage_client: pubky::Pubky,
    pub(crate) owner: paykit_lib::PublicKey,
    pub(crate) creator: crate::domain::locks::CreatorPubky,
    pub(crate) session_secret: String,
    pub(crate) initial_noise_secret: ReceiverNoiseSecretKey,
    pub(crate) creators: CreatorStore,
    pub(crate) marker_publisher: Arc<dyn MarkerPublisher>,
    pub(crate) bitcoin_network: BitcoinNetwork,
    pub(crate) stack_role: StackRole,
    pub(crate) receiver_path: PaykitReceiverPath,
    pub(crate) marker_capabilities: PaykitReceiverCapabilities,
    /// Claim-scan start index (design §B.5) applied to the creator's
    /// derivation cursor inside the commit critical section. `None` for the
    /// Bitkit companion flow, which does not scan; the manual claim endpoint
    /// always sets it.
    pub(crate) next_child_index_floor: Option<i64>,
    /// The claim's allocation decision (design §B.8.6), persisted inside the
    /// same commit. The companion flow sets
    /// [`ClaimAllocation::companion_default`]: it carries no `claim_channel`
    /// assertion and performs no claim-time scan, so it is `shared_manual`
    /// by construction. On re-authentication the store may only keep or
    /// downgrade the existing mode — never edit a creator into `exclusive`.
    pub(crate) allocation: crate::allocation::ClaimAllocation,
}

/// What a claim commit persisted: the derivation cursor pair (when a
/// claim-scan floor applied) and the creator row's allocation status after
/// the commit — the values the claim response reports.
pub(crate) struct ClaimCommitReport {
    pub(crate) next_child_index: Option<i64>,
    /// The creator's immutable claim-time child index (W1.13 r3), read back
    /// from the row in the same critical section: written once at creation,
    /// never moved by re-claims or invoice allocation.
    pub(crate) first_child_index: Option<i64>,
    pub(crate) allocation_mode: String,
    pub(crate) downgrade_reason: Option<String>,
}

impl CreatorSetupCommit {
    pub(crate) fn marker_capabilities() -> PaykitReceiverCapabilities {
        default_marker_capabilities()
    }
    /// The commit shared by both setup flows, additionally reporting the
    /// creator's resulting derivation cursor when a claim-scan floor was
    /// applied and the PERSISTED allocation status (design §B.8.6), so the
    /// manual claim response returns the actual `next_child_index` (design
    /// §B.6) and the row's mode — a re-claim may keep or downgrade, so the
    /// response must reflect the record, not the request.
    pub(crate) async fn publish_readback_and_commit_reporting(
        &self,
        claim: WatchOnlyAccountClaim,
    ) -> Result<ClaimCommitReport, ClaimError> {
        let xpub = validate_xpub(
            &claim.serialized_xpub,
            claim.account_index,
            &self.bitcoin_network,
            self.stack_role,
        )?;
        // The canonical 65-byte tail (chain code + public key, version-byte
        // independent) the fingerprint-to-seller binding keys on; it is
        // written in the same transaction as the claim commit below.
        let key_tail = canonical_key_tail(
            &Xpub::decode(&claim.serialized_xpub)
                .map_err(|_| ClaimError::InvalidPayload)?
                .encode(),
        );
        let setup_lock = self
            .creators
            .acquire_setup_lock(&self.creator)
            .await
            .map_err(|_| ClaimError::InvalidEnvelope)?;
        let commit_result = async {
            let existing = self
                .creators
                .load_optional(&self.creator)
                .await
                .map_err(|_| ClaimError::InvalidEnvelope)?;
            let noise_secret = existing
                .as_ref()
                .map(|credentials| credentials.receiver_noise_secret().clone())
                .unwrap_or_else(|| self.initial_noise_secret.clone());
            let marker = PaykitReceiverMarker::new(
                self.receiver_path.clone(),
                self.marker_capabilities,
                noise_secret.public_key(),
            );
            self.marker_publisher
                .publish_and_readback(
                    &self.session,
                    &self.public_storage_client,
                    &self.owner,
                    &marker,
                )
                .await?;
            let credentials = CreatorCredentials::new(
                self.creator.clone(),
                self.session_secret.clone(),
                noise_secret,
                xpub,
                claim.account_index,
            );
            let persisted_allocation = match existing {
                Some(_) => self
                    .creators
                    .reauthenticate(&credentials, &key_tail, &self.allocation)
                    .await
                    .map(|status| (status.allocation_mode, status.downgrade_reason)),
                None => self
                    .creators
                    .create(
                        &credentials,
                        &StorageState::default(),
                        &key_tail,
                        &self.allocation,
                        // The claim-time child index (W1.13 r3): the scan's
                        // start index for a manual claim, 0 for the
                        // companion flow, which performs no scan and leaves
                        // the cursor at its initial 0.
                        self.next_child_index_floor.unwrap_or(0),
                    )
                    .await
                    .map(|_| {
                        (
                            self.allocation.mode.as_str().to_owned(),
                            self.allocation
                                .downgrade_reason
                                .map(|reason| reason.as_str().to_owned()),
                        )
                    }),
            };
            let (allocation_mode, downgrade_reason) = match persisted_allocation {
                Ok(persisted) => persisted,
                Err(error) => {
                    // Publication and Postgres cannot share a transaction. This
                    // creator-scoped lock covers load, publication, persistence,
                    // and compensation, so a failed first creator cannot remove a
                    // concurrent winner's receiver marker. Reauth never removes
                    // its existing marker.
                    if existing.is_none() {
                        let _ = self
                            .marker_publisher
                            .remove(&self.session, &self.receiver_path)
                            .await;
                    }
                    return Err(match error {
                        crate::persistence::PersistenceError::ReauthenticationMismatch => {
                            ClaimError::AccountMismatch
                        }
                        crate::persistence::PersistenceError::KeyClaimedByOtherSeller => {
                            ClaimError::KeyClaimedByOtherSeller
                        }
                        _ => ClaimError::InvalidEnvelope,
                    });
                }
            };
            // Apply the claim-scan start index inside the same critical
            // section as the commit, monotonically: a re-claim of the same
            // account never moves the cursor backwards over an already
            // allocated child index.
            match self.next_child_index_floor {
                Some(floor) => self
                    .creators
                    .advance_next_child_index(&self.creator, floor)
                    .await
                    .map(|cursor| ClaimCommitReport {
                        next_child_index: Some(cursor.next_child_index),
                        first_child_index: Some(cursor.first_child_index),
                        allocation_mode,
                        downgrade_reason,
                    })
                    .map_err(|_| ClaimError::InvalidEnvelope),
                None => Ok(ClaimCommitReport {
                    next_child_index: None,
                    first_child_index: None,
                    allocation_mode,
                    downgrade_reason,
                }),
            }
        }
        .await;
        let unlock_result = setup_lock.release().await;
        match (commit_result, unlock_result) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(_)) => Err(ClaimError::InvalidEnvelope),
            (Ok(report), Ok(())) => Ok(report),
        }
    }
}

#[async_trait]
impl crate::setup_orchestration::VerifiedSetupCommit for CreatorSetupCommit {
    async fn publish_readback_and_commit(
        &self,
        claim: WatchOnlyAccountClaim,
    ) -> Result<(), ClaimError> {
        self.publish_readback_and_commit_reporting(claim)
            .await
            .map(|_| ())
    }
}

/// Validates the exact 78-byte BIP32 account xpub bytes and returns bitcoin's
/// canonical Base58 rendering. Mainnet uses xpub version bytes; testnet,
/// signet, and regtest use tpub version bytes.
///
/// Gate order (design B.6, claim-path ordering): parse the 78 bytes, then the
/// depth-3/hardened-child-number cross-check (inside the first-address
/// derivation), then the bounded account range `0..=99` (both roles — r4
/// reversed r3's refusal of account 0), then the deny-list on canonical key
/// data, which every stack whose role is not `proof` enforces.
pub fn validate_xpub(
    serialized_xpub: &[u8; 78],
    account_index: u32,
    configured_network: &BitcoinNetwork,
    stack_role: StackRole,
) -> Result<String, ClaimError> {
    let xpub = Xpub::decode(serialized_xpub).map_err(|_| ClaimError::InvalidPayload)?;
    let canonical = xpub.to_string();
    let first_address =
        derive_bip84_p2wpkh_address(&canonical, account_index, configured_network, 0)
            .map_err(|_| ClaimError::InvalidPayload)?;
    if account_index > MAX_CLAIMABLE_ACCOUNT_INDEX {
        return Err(ClaimError::AccountIndexOutOfRange);
    }
    // Deny on the canonical 65-byte tail (chain code + public key), never on
    // the submitted string: the xpub and zpub encodings of one key normalize
    // to identical bytes, so one entry catches both. The derived first
    // address is checked as belt-and-braces.
    if stack_role != StackRole::Proof
        && is_deny_listed(&canonical_key_tail(&xpub.encode()), &first_address)
    {
        return Err(ClaimError::KeyDenyListed);
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    #[test]
    fn setup_marker_disables_unsupported_receipts_and_outgoing_payments() {
        let capabilities = super::default_marker_capabilities();

        assert!(capabilities.private_payments);
        assert!(capabilities.payment_requests);
        assert!(!capabilities.receipts);
        assert!(!capabilities.outgoing_payments);
    }
}
