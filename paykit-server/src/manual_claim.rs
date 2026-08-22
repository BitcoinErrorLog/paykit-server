//! Manual watch-only account claims for clients that cannot run the Bitkit
//! companion flow (browser apps never hold the identity secret).
//!
//! The caller supplies a fresh Pubky `AuthToken` whose capabilities exactly
//! match the receiver-path session capabilities the companion flow requests,
//! plus the BIP84 account xpub and index in plaintext. The authenticated
//! token signer is the creator: possession of a capability-scoped token is
//! the same proof of identity the companion flow's normal Pubky AUTH leg
//! establishes, and the xpub attestation moves from the companion envelope
//! signature to this authenticated request body.
//!
//! The token is exchanged for a real homeserver session by looping it
//! through the configured HTTP relay into the SDK's own auth flow — the
//! exact channel a signer (Pubky Ring / Bitkit) would use — so session
//! minting, capability validation, and cookie handling stay owned by the
//! `pubky` crate. After the session exists, marker publication and encrypted
//! credential persistence reuse the companion flow's commit path unchanged.

use std::{str::FromStr, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::bip32::Xpub;
use paykit_lib::PaykitReceiverPath;
use paykit_sdk::{PubkyPublicKey, PubkySessionAccess, ReceiverNoiseSecretKey};
use pubky::{
    AuthFlowKind, AuthToken, Capabilities, EncryptedHttpRelayInboxChannel, Pubky, PubkyAuthFlow,
    PubkySession,
};
use rand::{TryRngCore, rngs::OsRng};
use url::Url;

use crate::{
    bitkit_claim::{ClaimError, WatchOnlyAccountClaim, required_capabilities},
    config::BitcoinNetwork,
    domain::locks::{CreatorPubky, parse_creator},
    persistence::CreatorStore,
    real_setup::{CreatorSetupCommit, MarkerPublisher, validate_xpub},
    setup_orchestration::VerifiedSetupCommit,
};

/// How long the claim waits for the relay round-trip and homeserver session
/// exchange before reporting the dependency unavailable.
const SESSION_MINT_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum length of a serialized v0 AuthToken: 64-byte signature, 10-byte
/// namespace, and 1 version byte precede the variable-length remainder.
/// `AuthToken::verify` indexes the version byte directly, so the length is
/// guarded before delegating to it.
const MIN_TOKEN_LENGTH: usize = 75;

#[derive(Clone, Debug)]
pub struct ManualClaimRequest {
    /// Unpadded base64url encoding of the serialized Pubky `AuthToken`.
    pub auth_token: String,
    /// Base58 BIP32 account extended public key (depth 3, hardened child
    /// number equal to `account_index`, version bytes for the configured
    /// network kind).
    pub account_xpub: String,
    pub account_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManualClaimOutcome {
    /// Canonical pubky-prefixed creator identity that now owns the account.
    pub creator: String,
    pub account_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManualClaimError {
    /// The token bytes did not verify as a Pubky `AuthToken`, or the
    /// homeserver refused the session exchange for them.
    InvalidToken,
    /// The token's capabilities are not exactly the receiver-path session
    /// capabilities this deployment requires.
    InvalidCapabilities,
    /// The xpub is not a valid BIP84 account key for the configured network
    /// and account index.
    InvalidXpub,
    /// A different account is already persisted for this creator.
    AccountMismatch,
    /// The relay or the creator's homeserver could not complete the session
    /// exchange; the claim is retryable.
    SessionUnavailable,
    /// Marker publication or durable persistence failed; retryable.
    Unavailable,
}

/// Session minting is a narrow seam so unit tests can exercise validation,
/// identity binding, and commit mapping without a live relay and homeserver;
/// production always uses [`RelayLoopbackSessionMinter`], and the E2E suite
/// exercises the real minter against an ephemeral Pubky testnet.
#[async_trait::async_trait]
pub trait SessionMinter: Send + Sync {
    async fn mint(
        &self,
        token_bytes: &[u8],
        capabilities: &Capabilities,
    ) -> Result<PubkySession, ManualClaimError>;
}

/// Production session minter: posts the caller's token onto a fresh
/// encrypted relay channel and completes the SDK auth flow subscribed to it,
/// which performs the `/session` exchange with the signer's homeserver.
pub struct RelayLoopbackSessionMinter {
    pubky: Pubky,
    auth_relay: Url,
}

impl RelayLoopbackSessionMinter {
    pub fn new(pubky: Pubky, auth_relay: Url) -> Self {
        Self { pubky, auth_relay }
    }
}

#[async_trait::async_trait]
impl SessionMinter for RelayLoopbackSessionMinter {
    async fn mint(
        &self,
        token_bytes: &[u8],
        capabilities: &Capabilities,
    ) -> Result<PubkySession, ManualClaimError> {
        let mut secret = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut secret)
            .map_err(|_| ManualClaimError::SessionUnavailable)?;
        let flow = PubkyAuthFlow::builder(capabilities, AuthFlowKind::signin())
            .relay(self.auth_relay.clone())
            .client(self.pubky.client().clone())
            .client_secret(secret)
            .start()
            .map_err(|_| ManualClaimError::SessionUnavailable)?;
        let channel = EncryptedHttpRelayInboxChannel::new(self.auth_relay.clone(), secret)
            .map_err(|_| ManualClaimError::SessionUnavailable)?;
        channel
            .produce(self.pubky.client(), token_bytes)
            .await
            .map_err(|_| ManualClaimError::SessionUnavailable)?;
        let session = tokio::time::timeout(SESSION_MINT_TIMEOUT, flow.await_approval())
            .await
            .map_err(|_| ManualClaimError::SessionUnavailable)?
            .map_err(|error| match error {
                pubky::Error::Authentication(_) => ManualClaimError::InvalidToken,
                pubky::Error::Request(request)
                    if matches!(
                        &request,
                        pubky::errors::RequestError::Server { status, .. }
                            if status.is_client_error()
                    ) =>
                {
                    ManualClaimError::InvalidToken
                }
                _ => ManualClaimError::SessionUnavailable,
            })?;
        Ok(session)
    }
}

/// Application service behind `POST /v0/accounts/claim`.
pub struct ManualClaimService {
    pubky: Pubky,
    minter: Arc<dyn SessionMinter>,
    creators: CreatorStore,
    marker_publisher: Arc<dyn MarkerPublisher>,
    bitcoin_network: BitcoinNetwork,
    receiver_path: PaykitReceiverPath,
    required_capabilities: String,
}

impl ManualClaimService {
    pub fn new(
        pubky: Pubky,
        minter: Arc<dyn SessionMinter>,
        creators: CreatorStore,
        marker_publisher: Arc<dyn MarkerPublisher>,
        bitcoin_network: BitcoinNetwork,
        receiver_path: PaykitReceiverPath,
    ) -> Self {
        let required_capabilities = required_capabilities(&receiver_path);
        Self {
            pubky,
            minter,
            creators,
            marker_publisher,
            bitcoin_network,
            receiver_path,
            required_capabilities,
        }
    }

    /// The exact capabilities string a claim token must carry.
    pub fn required_capabilities(&self) -> &str {
        &self.required_capabilities
    }

    pub async fn claim(
        &self,
        request: ManualClaimRequest,
    ) -> Result<ManualClaimOutcome, ManualClaimError> {
        let token_bytes = URL_SAFE_NO_PAD
            .decode(request.auth_token.as_bytes())
            .map_err(|_| ManualClaimError::InvalidToken)?;
        if token_bytes.len() < MIN_TOKEN_LENGTH {
            return Err(ManualClaimError::InvalidToken);
        }
        let token = AuthToken::verify(&token_bytes).map_err(|_| ManualClaimError::InvalidToken)?;
        if token.capabilities().to_string() != self.required_capabilities {
            return Err(ManualClaimError::InvalidCapabilities);
        }
        let claim = validate_claimed_account(
            &request.account_xpub,
            request.account_index,
            &self.bitcoin_network,
        )?;

        let capabilities = Capabilities::try_from(self.required_capabilities.as_str())
            .map_err(|_| ManualClaimError::InvalidCapabilities)?;
        let session = self.minter.mint(&token_bytes, &capabilities).await?;

        // The relay channel is unauthenticated, so bind the minted session to
        // the exact token signer this request presented.
        if session.info().public_key() != token.public_key() {
            return Err(ManualClaimError::InvalidToken);
        }
        let public_key = PubkyPublicKey::from_public_key(session.info().public_key());
        let owner = public_key
            .to_public_key()
            .map_err(|_| ManualClaimError::InvalidToken)?;
        let creator: CreatorPubky =
            parse_creator(&public_key.to_app_key()).map_err(|_| ManualClaimError::InvalidToken)?;
        let session_secret = session.export_secret();

        let access = PubkySessionAccess {
            session: session.clone(),
            outbox_client: self.pubky.clone(),
            local_secret_key: None,
            receiver_noise_secret_key: ReceiverNoiseSecretKey::random(),
        };
        access
            .validate_for_capabilities(&self.required_capabilities)
            .map_err(|_| ManualClaimError::InvalidCapabilities)?;

        let commit = CreatorSetupCommit {
            session,
            public_storage_client: self.pubky.clone(),
            owner,
            creator: creator.clone(),
            session_secret,
            initial_noise_secret: access.receiver_noise_secret_key,
            creators: self.creators.clone(),
            marker_publisher: self.marker_publisher.clone(),
            bitcoin_network: self.bitcoin_network.clone(),
            receiver_path: self.receiver_path.clone(),
            marker_capabilities: CreatorSetupCommit::marker_capabilities(),
        };
        commit
            .publish_readback_and_commit(claim)
            .await
            .map_err(|error| match error {
                ClaimError::AccountMismatch => ManualClaimError::AccountMismatch,
                _ => ManualClaimError::Unavailable,
            })?;
        Ok(ManualClaimOutcome {
            creator: creator.to_string(),
            account_index: request.account_index,
        })
    }

    /// Whether a watch-only account record exists for the creator. Used by
    /// the marketplace to report Bitcoin availability per seller.
    pub async fn account_exists(&self, creator: &CreatorPubky) -> Result<bool, ManualClaimError> {
        self.creators
            .load_optional(creator)
            .await
            .map(|credentials| credentials.is_some())
            .map_err(|_| ManualClaimError::Unavailable)
    }
}

/// Parses the base58 account xpub, then reuses the companion flow's exact
/// validation (network kind, depth 3, hardened child number equal to the
/// account index, derivable external chain).
fn validate_claimed_account(
    account_xpub: &str,
    account_index: u32,
    network: &BitcoinNetwork,
) -> Result<WatchOnlyAccountClaim, ManualClaimError> {
    let xpub = Xpub::from_str(account_xpub).map_err(|_| ManualClaimError::InvalidXpub)?;
    let serialized_xpub = xpub.encode();
    validate_xpub(&serialized_xpub, account_index, network)
        .map_err(|_| ManualClaimError::InvalidXpub)?;
    Ok(WatchOnlyAccountClaim {
        account_index,
        serialized_xpub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regtest_account_tpub(account_index: u32) -> String {
        use bitcoin::{
            Network,
            bip32::{ChildNumber, Xpriv},
            secp256k1::Secp256k1,
        };
        let secp = Secp256k1::new();
        let account = Xpriv::new_master(Network::Regtest, &[7; 32])
            .unwrap()
            .derive_priv(
                &secp,
                &[
                    ChildNumber::from_hardened_idx(84).unwrap(),
                    ChildNumber::from_hardened_idx(1).unwrap(),
                    ChildNumber::from_hardened_idx(account_index).unwrap(),
                ],
            )
            .unwrap();
        Xpub::from_priv(&secp, &account).to_string()
    }

    #[test]
    fn accepts_a_network_correct_account_xpub_at_its_hardened_index() {
        let claim = validate_claimed_account(&regtest_account_tpub(3), 3, &BitcoinNetwork::Regtest)
            .unwrap();
        assert_eq!(claim.account_index, 3);
        assert_eq!(
            Xpub::decode(&claim.serialized_xpub).unwrap().to_string(),
            regtest_account_tpub(3)
        );
    }

    #[test]
    fn rejects_wrong_network_wrong_index_and_garbage() {
        assert_eq!(
            validate_claimed_account(&regtest_account_tpub(0), 0, &BitcoinNetwork::Mainnet),
            Err(ManualClaimError::InvalidXpub)
        );
        assert_eq!(
            validate_claimed_account(&regtest_account_tpub(0), 1, &BitcoinNetwork::Regtest),
            Err(ManualClaimError::InvalidXpub)
        );
        assert_eq!(
            validate_claimed_account("not-an-xpub", 0, &BitcoinNetwork::Regtest),
            Err(ManualClaimError::InvalidXpub)
        );
    }
}
