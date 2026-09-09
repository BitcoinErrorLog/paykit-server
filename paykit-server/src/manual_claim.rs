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
    allocation::{
        CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1, CLAIM_CHANNEL_MANUAL, REQUESTED_MODE_PASTED_AUTO,
        decide_allocation,
    },
    application::create_invoice::derive_bip84_p2wpkh_address,
    bitkit_claim::{ClaimError, WatchOnlyAccountClaim, required_capabilities},
    chain_history::{ChainHistoryPort, ClaimScanError, scan_claim_start_index},
    config::{BitcoinNetwork, StackRole},
    domain::locks::{CreatorPubky, parse_creator},
    key_identity::{canonical_key_tail, key_fingerprint},
    persistence::{CreatorStatusRecord, CreatorStore},
    real_setup::{CreatorSetupCommit, MarkerPublisher, validate_xpub},
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
    /// The channel the Shop client asserts (design §B.8.6): `manual` or
    /// `bitkit_watch_only_v1`, recorded on the creator row. `None` is
    /// treated — and recorded — as `manual`: a bare key carries nothing to
    /// corroborate. Any other value is refused with `unknown_claim_channel`.
    pub claim_channel: Option<String>,
    /// The allocation mode the client requests, when it requests one. The
    /// server decides the mode from the §B.8.6 corroborating checks and
    /// honors no request — but a request for `pasted_auto` is refused
    /// unconditionally with `allocation_mode_not_enabled` (§B.8.6 r6).
    pub allocation_mode: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManualClaimOutcome {
    /// Canonical pubky-prefixed creator identity that now owns the account.
    pub creator: String,
    pub account_index: u32,
    /// The creator's derivation cursor after the claim-time history scan
    /// (design §B.5/§B.6): the child index the next invoice address derives
    /// from.
    pub next_child_index: i64,
    /// The claim-time child index (W1.13 r3), persisted on the creator row
    /// and stable forever: `first_derived_address` derives at this index,
    /// and the seller status surface reports the same value.
    pub first_child_index: i64,
    /// Hex of the first 8 bytes of SHA-256 over the canonical 78-byte key
    /// serialization; the client recomputes it locally and refuses to enable
    /// Bitcoin on mismatch (design §B.6).
    pub key_fingerprint: String,
    /// The account's derived address at the returned `next_child_index`, on
    /// this stack's network (design §B.6).
    pub first_derived_address: String,
    /// This stack's identity, `{stack_role}:{instance_uuid}` (the
    /// `stack_id` contract).
    pub stack_id: String,
    /// The creator's allocation mode after this claim (design §B.8.6), as
    /// persisted on the creator row: `exclusive` or `shared_manual`.
    pub allocation_mode: String,
    /// The fixed §B.8.8 downgrade-reason identifier recorded on the creator
    /// row; `None` for an `exclusive` creator with no recorded reason.
    pub downgrade_reason: Option<String>,
}

/// The authenticated seller's own allocation status (design §B.8.6), as
/// served by `GET /v0/accounts/{creator}/status`. The Ring-verification
/// client fails closed without `key_fingerprint` (it compares the hash
/// against its local key before enabling the Bitcoin rail) and
/// `first_derived_address`; both derive from the persisted account record
/// with the exact functions the claim response uses, so they equal the
/// claim response's values for the same creator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SellerAllocationStatus {
    /// The creator's persisted allocation mode: `exclusive` or
    /// `shared_manual`.
    pub allocation_mode: String,
    /// The claim channel recorded at claim time; `None` for a companion-flow
    /// setup, which carries no channel assertion.
    pub claim_channel: Option<String>,
    /// The fixed §B.8.8 downgrade-reason identifier recorded on the creator
    /// row; `None` when no downgrade reason was ever assigned.
    pub downgrade_reason: Option<String>,
    /// Hex of the first 8 bytes of SHA-256 over the canonical 78-byte key
    /// serialization — the same value the claim response emits.
    pub key_fingerprint: String,
    /// The account's derived address at the persisted CLAIM-TIME child index
    /// (`first_child_index`, W1.13 r3), on this stack's network — the same
    /// value the claim response emitted, forever. It never derives at the
    /// mutable cursor: invoice allocation advances `next_child_index`, and a
    /// status derived there would drift away from the claim response.
    pub first_derived_address: String,
    /// The persisted BIP84 account index; with the seller's own xpub it
    /// re-derives `first_derived_address` at `first_child_index`.
    pub account_index: u32,
    /// The immutable claim-time child index the claim response's
    /// `first_derived_address` was derived at.
    pub first_child_index: u32,
    /// The mutable derivation cursor the next invoice address derives from.
    /// Informational: it moves as invoices are allocated.
    pub next_child_index: u32,
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
    /// The account index is outside the bounded claimable range 0..=99
    /// (design §B.6 r4).
    AccountIndexOutOfRange,
    /// The canonical key material is a known-public test-vector key; refused
    /// on every stack whose role is not `proof` (design §B.6).
    KeyDenyListed,
    /// The canonical key tail was ever claimed by a different creator on
    /// this stack, whether or not that claim is still active (design §B.8.5).
    KeyClaimedByOtherSeller,
    /// A different account is already persisted for this creator.
    AccountMismatch,
    /// The claim-time history scan could not reach Electrum (connect,
    /// timeout, or malformed response). The claim is refused — never
    /// defaulted to index 0 (design §B.5) — and is retryable.
    ClaimScanUnavailable,
    /// The claim-time history scan found usage in every window up to the
    /// 1,000-address bound; the seller must claim a fresh, dedicated account.
    AccountHistoryTooDeep,
    /// The relay or the creator's homeserver could not complete the session
    /// exchange; the claim is retryable.
    SessionUnavailable,
    /// Marker publication or durable persistence failed; retryable.
    Unavailable,
    /// The claim requested `allocation_mode = 'pasted_auto'`. Refused
    /// unconditionally — on every code path, under every configuration, and
    /// with no enabling flag anywhere (design §B.8.6 r6, Sol P1).
    AllocationModeNotEnabled,
    /// The claim asserted a `claim_channel` other than §B.8.6's two values
    /// (`manual`, `bitkit_watch_only_v1`). Refused — fail closed: an unknown
    /// channel is never canonicalized silently and never persisted verbatim.
    UnknownClaimChannel,
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

/// Read-only fingerprint↔seller pre-check seam (design §B.8.5). The
/// authoritative check is the binding write inside the claim-commit
/// transaction; this lookup runs before the chain scan so a refused claim
/// never reaches Electrum. Production uses the real [`CreatorStore`]; unit
/// tests script it.
#[async_trait::async_trait]
pub trait ClaimedKeyLookup: Send + Sync {
    async fn key_tail_claimed_by_other(
        &self,
        key_tail: &[u8; 65],
        creator: &CreatorPubky,
    ) -> Result<bool, ManualClaimError>;
}

#[async_trait::async_trait]
impl ClaimedKeyLookup for CreatorStore {
    async fn key_tail_claimed_by_other(
        &self,
        key_tail: &[u8; 65],
        creator: &CreatorPubky,
    ) -> Result<bool, ManualClaimError> {
        CreatorStore::key_tail_claimed_by_other(self, key_tail, creator)
            .await
            .map_err(|_| ManualClaimError::Unavailable)
    }
}

/// Application service behind `POST /v0/accounts/claim`.
pub struct ManualClaimService {
    pubky: Pubky,
    minter: Arc<dyn SessionMinter>,
    creators: CreatorStore,
    claimed_keys: Arc<dyn ClaimedKeyLookup>,
    marker_publisher: Arc<dyn MarkerPublisher>,
    history: Arc<dyn ChainHistoryPort>,
    bitcoin_network: BitcoinNetwork,
    stack_role: StackRole,
    stack_id: String,
    receiver_path: PaykitReceiverPath,
    required_capabilities: String,
}

impl ManualClaimService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pubky: Pubky,
        minter: Arc<dyn SessionMinter>,
        creators: CreatorStore,
        claimed_keys: Arc<dyn ClaimedKeyLookup>,
        marker_publisher: Arc<dyn MarkerPublisher>,
        history: Arc<dyn ChainHistoryPort>,
        bitcoin_network: BitcoinNetwork,
        stack_role: StackRole,
        stack_id: String,
        receiver_path: PaykitReceiverPath,
    ) -> Self {
        let required_capabilities = required_capabilities(&receiver_path);
        Self {
            pubky,
            minter,
            creators,
            claimed_keys,
            marker_publisher,
            history,
            bitcoin_network,
            stack_role,
            stack_id,
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
        // Pure request-shape validation is the FIRST thing the claim path
        // does — before token verification, before any gate, on every code
        // path and under every configuration. The HTTP layer runs the same
        // check before its rate-limit charge (W1.13 r3 P2).
        validate_request_shape(&request)?;
        let token = self.verify_claim_token(&request.auth_token)?;
        // A missing channel is treated — and recorded — as `manual`
        // (design §B.8.6: a paste is "a bare key and nothing else").
        let channel = request
            .claim_channel
            .clone()
            .unwrap_or_else(|| CLAIM_CHANNEL_MANUAL.to_owned());
        // Claim gate order (design §B.6): xpub parse → depth/child-number
        // cross-check → bounded account range → deny-list (role-gated) →
        // fingerprint↔seller check → chain scan → session mint/persist.
        // Every gate before the scan refuses without touching Electrum.
        //
        // The depth/child-number cross-check is scoped by channel (design
        // §B.8.6): under `bitkit_watch_only_v1` a declared-vs-hardened
        // mismatch DOWNGRADES with `account_index_mismatch` — the claim is
        // accepted on the key's own hardened child index, which is the only
        // self-consistent (xpub, index) pair invoice derivation can use —
        // while every other channel keeps the §B.6 refusal ("the submitted
        // account_index is cross-checked against the key bytes and cannot be
        // misdeclared").
        let validated = validate_claimed_account(
            &request.account_xpub,
            request.account_index,
            &channel,
            &self.bitcoin_network,
            self.stack_role,
        )?;
        let claim = validated.claim;

        // Fingerprint↔seller pre-check (design §B.8.5). The claiming creator
        // is the verified token's signer — the session minted below is
        // required to match it — so a refused claim never reaches Electrum.
        // The authoritative check is the binding write inside the
        // claim-commit transaction, which the primary key serializes. This
        // is the one §B.8.6 corroborating fact that stays a refusal: §B.8.5
        // makes a key shared by two sellers a hard `key_claimed_by_other_seller`.
        let key_tail = canonical_key_tail(&claim.serialized_xpub);
        let token_creator: CreatorPubky =
            parse_creator(&PubkyPublicKey::from_public_key(token.public_key()).to_app_key())
                .map_err(|_| ManualClaimError::InvalidToken)?;
        if self
            .claimed_keys
            .key_tail_claimed_by_other(&key_tail, &token_creator)
            .await?
        {
            return Err(ManualClaimError::KeyClaimedByOtherSeller);
        }

        // Claim-time address-index scan (design §B.5): derive the account's
        // external chain in windows of 20 until a fully empty window, bounded
        // at 1,000 addresses. The scan runs before the relay round-trip and
        // any persistence, and any Electrum failure refuses the claim — an
        // unscanned claim is exactly the P1-A condition the design forbids.
        let canonical_xpub = Xpub::decode(&claim.serialized_xpub)
            .map_err(|_| ManualClaimError::InvalidXpub)?
            .to_string();
        let scan = scan_claim_start_index(
            self.history.as_ref(),
            &canonical_xpub,
            claim.account_index,
            &self.bitcoin_network,
        )
        .await
        .map_err(|error| match error {
            ClaimScanError::Unavailable => ManualClaimError::ClaimScanUnavailable,
            ClaimScanError::HistoryTooDeep => ManualClaimError::AccountHistoryTooDeep,
        })?;

        // The §B.8.6 corroborating checks, evaluated AFTER the gates and the
        // scan from data already computed — no additional Electrum calls.
        // Any failure downgrades with a named §B.8.8 reason; none refuses.
        let allocation = decide_allocation(
            &channel,
            request.account_index,
            validated.index_mismatch,
            scan.saw_history,
        );

        let capabilities = Capabilities::try_from(self.required_capabilities.as_str())
            .map_err(|_| ManualClaimError::InvalidCapabilities)?;
        let session = self.minter.mint(&token.serialize(), &capabilities).await?;

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
            stack_role: self.stack_role,
            receiver_path: self.receiver_path.clone(),
            marker_capabilities: CreatorSetupCommit::marker_capabilities(),
            next_child_index_floor: Some(i64::from(scan.start_index)),
            allocation: allocation.clone(),
        };
        let key_fingerprint = key_fingerprint(&claim.serialized_xpub);
        let report = commit
            .publish_readback_and_commit_reporting(claim.clone())
            .await
            .map_err(|error| match error {
                ClaimError::AccountMismatch => ManualClaimError::AccountMismatch,
                ClaimError::KeyClaimedByOtherSeller => ManualClaimError::KeyClaimedByOtherSeller,
                _ => ManualClaimError::Unavailable,
            })?;
        let next_child_index = report
            .next_child_index
            .unwrap_or(i64::from(scan.start_index));
        // The claim-time child index (W1.13 r3), persisted on the creator
        // row at creation and read back in the commit's critical section.
        // The claim response's address derives at THIS index — identical to
        // `next_child_index` on a first claim, and stable across re-claims
        // and invoice allocation, so the claim response and the seller
        // status surface always agree.
        let first_child_index = report.first_child_index.unwrap_or(next_child_index);
        // The address at the claim-time index: derived with the same
        // function invoice addresses use, on this stack's network (design
        // §B.6).
        let first_derived_address = derive_bip84_p2wpkh_address(
            &canonical_xpub,
            claim.account_index,
            &self.bitcoin_network,
            first_child_index,
        )
        .map_err(|_| ManualClaimError::Unavailable)?;
        Ok(ManualClaimOutcome {
            creator: creator.to_string(),
            account_index: claim.account_index,
            next_child_index,
            first_child_index,
            key_fingerprint,
            first_derived_address,
            stack_id: self.stack_id.clone(),
            // The PERSISTED mode: a re-claim may only keep or downgrade, so
            // the response reports the creator row, never the request's own
            // decision (design §B.8.6 — no edit moves a creator into
            // `exclusive`).
            allocation_mode: report.allocation_mode,
            downgrade_reason: report.downgrade_reason,
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

    /// Verifies a capability-scoped claim token OFFLINE and returns the
    /// creator its signer identity binds. Used by the authenticated seller
    /// status surface; the claim path uses the same verification before the
    /// relay session exchange.
    pub fn authenticate_claim_token(
        &self,
        auth_token: &str,
    ) -> Result<CreatorPubky, ManualClaimError> {
        let token = self.verify_claim_token(auth_token)?;
        parse_creator(&PubkyPublicKey::from_public_key(token.public_key()).to_app_key())
            .map_err(|_| ManualClaimError::InvalidToken)
    }

    /// The authenticated seller's own allocation status (design §B.8.6):
    /// mode, recorded claim channel, downgrade reason if any, and the two
    /// evidence fields the Ring-verification client fails closed without —
    /// `key_fingerprint` and `first_derived_address`, derived from the
    /// persisted xpub by the exact functions the claim response uses (no
    /// Electrum, no I/O beyond the creator row read). Detection evidence
    /// metadata is §B.8.7's (W1.14) and not yet recorded.
    pub async fn allocation_status(
        &self,
        creator: &CreatorPubky,
    ) -> Result<Option<SellerAllocationStatus>, ManualClaimError> {
        let Some(record) = self
            .creators
            .allocation_status(creator)
            .await
            .map_err(|_| ManualClaimError::Unavailable)?
        else {
            return Ok(None);
        };
        let (key_fingerprint, first_derived_address) =
            status_evidence(&record, &self.bitcoin_network)?;
        Ok(Some(SellerAllocationStatus {
            allocation_mode: record.allocation.allocation_mode,
            claim_channel: record.allocation.claim_channel,
            downgrade_reason: record.allocation.downgrade_reason,
            key_fingerprint,
            first_derived_address,
            account_index: record.account_index,
            first_child_index: u32::try_from(record.first_child_index)
                .map_err(|_| ManualClaimError::Unavailable)?,
            next_child_index: u32::try_from(record.next_child_index)
                .map_err(|_| ManualClaimError::Unavailable)?,
        }))
    }

    /// Decodes and verifies the `AuthToken` and its exact capability set —
    /// the offline half of claim authentication, shared by the claim path
    /// and the seller status surface.
    fn verify_claim_token(&self, auth_token: &str) -> Result<AuthToken, ManualClaimError> {
        let token_bytes = URL_SAFE_NO_PAD
            .decode(auth_token.as_bytes())
            .map_err(|_| ManualClaimError::InvalidToken)?;
        if token_bytes.len() < MIN_TOKEN_LENGTH {
            return Err(ManualClaimError::InvalidToken);
        }
        let token = AuthToken::verify(&token_bytes).map_err(|_| ManualClaimError::InvalidToken)?;
        if token.capabilities().to_string() != self.required_capabilities {
            return Err(ManualClaimError::InvalidCapabilities);
        }
        Ok(token)
    }
}

/// Pure request-shape validation needing no I/O (W1.13 r3 P2). The HTTP
/// claim handler runs this BEFORE its rate-limit charge so unauthenticated
/// garbage requests never consume claim capacity; `claim` re-runs it as the
/// first gate, so every code path refuses identically. Everything after it
/// — token verification, the claim scan, persistence — is I/O-bearing and
/// stays behind the rate limit.
///
/// Two refusals, in this order:
/// - `allocation_mode = 'pasted_auto'` is refused unconditionally (design
///   §B.8.6 r6, Sol P1): no configuration flag, operator toggle or
///   per-seller override exists anywhere.
/// - An unknown `claim_channel` is refused (fail closed, design §B.8.6: the
///   field is one of `manual` | `bitkit_watch_only_v1`) — never
///   canonicalized silently, never persisted verbatim.
pub fn validate_request_shape(request: &ManualClaimRequest) -> Result<(), ManualClaimError> {
    if request.allocation_mode.as_deref() == Some(REQUESTED_MODE_PASTED_AUTO) {
        return Err(ManualClaimError::AllocationModeNotEnabled);
    }
    if let Some(channel) = request.claim_channel.as_deref()
        && !matches!(
            channel,
            CLAIM_CHANNEL_MANUAL | CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1
        )
    {
        return Err(ManualClaimError::UnknownClaimChannel);
    }
    Ok(())
}

/// The status surface's two evidence fields, derived from the persisted
/// account record by the exact functions the claim response uses (design
/// §B.6). The address derives at the record's immutable CLAIM-TIME index
/// `first_child_index` (W1.13 r3) — never at the mutable `next_child_index`
/// cursor, which invoice allocation advances — so the status emits the
/// claim response's address forever.
fn status_evidence(
    record: &CreatorStatusRecord,
    network: &BitcoinNetwork,
) -> Result<(String, String), ManualClaimError> {
    let serialized_xpub = Xpub::from_str(&record.xpub)
        .map_err(|_| ManualClaimError::Unavailable)?
        .encode();
    let first_derived_address = derive_bip84_p2wpkh_address(
        &record.xpub,
        record.account_index,
        network,
        record.first_child_index,
    )
    .map_err(|_| ManualClaimError::Unavailable)?;
    Ok((key_fingerprint(&serialized_xpub), first_derived_address))
}

/// The validated claim plus the §B.8.6 index-agreement fact: whether the
/// declared `account_index` disagrees with the key's own hardened child
/// number. Under `bitkit_watch_only_v1` a mismatch is not a refusal — it
/// downgrades the claim with `account_index_mismatch` — so the fact is
/// reported to the allocation decision rather than folded into an error.
struct ValidatedClaim {
    claim: WatchOnlyAccountClaim,
    index_mismatch: bool,
}

/// Parses the base58 account xpub, then reuses the companion flow's exact
/// validation (network kind, depth 3, hardened child number equal to the
/// account index, bounded account range, role-gated deny-list, derivable
/// external chain). The named range and deny-list refusals pass through; a
/// client presenting zpub form is rejected here — zpub→xpub normalization is
/// the client's job (SLIP-132 version-byte rewrite before POST, design §B.6).
///
/// The declared-vs-hardened cross-check is channel-scoped (design §B.8.6):
/// under `bitkit_watch_only_v1` a disagreement DOWNGRADES the claim rather
/// than refusing it, and the claim proceeds on the key's own hardened child
/// index — the only (xpub, index) pair the invoice derivation path can use,
/// so the account stays sellable in `shared_manual`. Every other channel
/// keeps the §B.6 refusal: a paste cannot misdeclare its index.
fn validate_claimed_account(
    account_xpub: &str,
    account_index: u32,
    channel: &str,
    network: &BitcoinNetwork,
    stack_role: StackRole,
) -> Result<ValidatedClaim, ManualClaimError> {
    let xpub = Xpub::from_str(account_xpub).map_err(|_| ManualClaimError::InvalidXpub)?;
    let serialized_xpub = xpub.encode();
    // The key's own hardened child number IS its account index (design
    // §B.6): a BIP84 account xpub is depth 3 with a hardened child. A key
    // without that shape has no account semantics at all and stays a hard
    // refusal on every channel.
    if xpub.depth != 3 {
        return Err(ManualClaimError::InvalidXpub);
    }
    let key_index = match xpub.child_number {
        bitcoin::bip32::ChildNumber::Hardened { index } => index,
        bitcoin::bip32::ChildNumber::Normal { .. } => return Err(ManualClaimError::InvalidXpub),
    };
    let index_mismatch = key_index != account_index;
    let effective_index = if index_mismatch {
        if channel == CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1 {
            key_index
        } else {
            return Err(ManualClaimError::InvalidXpub);
        }
    } else {
        account_index
    };
    validate_xpub(&serialized_xpub, effective_index, network, stack_role).map_err(|error| {
        match error {
            ClaimError::AccountIndexOutOfRange => ManualClaimError::AccountIndexOutOfRange,
            ClaimError::KeyDenyListed => ManualClaimError::KeyDenyListed,
            _ => ManualClaimError::InvalidXpub,
        }
    })?;
    Ok(ValidatedClaim {
        claim: WatchOnlyAccountClaim {
            account_index: effective_index,
            serialized_xpub,
        },
        index_mismatch,
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
        let validated = validate_claimed_account(
            &regtest_account_tpub(3),
            3,
            CLAIM_CHANNEL_MANUAL,
            &BitcoinNetwork::Regtest,
            StackRole::Proof,
        )
        .unwrap();
        assert_eq!(validated.claim.account_index, 3);
        assert!(!validated.index_mismatch);
        assert_eq!(
            Xpub::decode(&validated.claim.serialized_xpub)
                .unwrap()
                .to_string(),
            regtest_account_tpub(3)
        );
    }

    #[test]
    fn rejects_wrong_network_wrong_index_and_garbage() {
        assert_eq!(
            validate_claimed_account(
                &regtest_account_tpub(0),
                0,
                CLAIM_CHANNEL_MANUAL,
                &BitcoinNetwork::Mainnet,
                StackRole::Proof
            )
            .map(|validated| validated.claim),
            Err(ManualClaimError::InvalidXpub)
        );
        // The declared-vs-hardened cross-check keeps its §B.6 refusal on the
        // manual channel (§B.8.6 downgrades it only under the Bitkit one).
        assert_eq!(
            validate_claimed_account(
                &regtest_account_tpub(0),
                1,
                CLAIM_CHANNEL_MANUAL,
                &BitcoinNetwork::Regtest,
                StackRole::Proof
            )
            .map(|validated| validated.claim),
            Err(ManualClaimError::InvalidXpub)
        );
        assert_eq!(
            validate_claimed_account(
                "not-an-xpub",
                0,
                CLAIM_CHANNEL_MANUAL,
                &BitcoinNetwork::Regtest,
                StackRole::Proof
            )
            .map(|validated| validated.claim),
            Err(ManualClaimError::InvalidXpub)
        );
    }

    #[test]
    fn bitkit_channel_mismatch_proceeds_on_the_keys_own_hardened_index() {
        // Declared 4 against an account-2 key: the Bitkit channel downgrades
        // (§B.8.6) instead of refusing, on the key's own index.
        let validated = validate_claimed_account(
            &regtest_account_tpub(2),
            4,
            CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1,
            &BitcoinNetwork::Regtest,
            StackRole::Proof,
        )
        .unwrap();
        assert!(validated.index_mismatch);
        assert_eq!(validated.claim.account_index, 2);
    }

    fn status_record(
        xpub: String,
        first_child_index: i64,
        next_child_index: i64,
    ) -> CreatorStatusRecord {
        CreatorStatusRecord {
            allocation: crate::persistence::CreatorAllocationStatus {
                allocation_mode: "shared_manual".to_owned(),
                claim_channel: Some("manual".to_owned()),
                downgrade_reason: None,
            },
            xpub,
            account_index: 3,
            first_child_index,
            next_child_index,
        }
    }

    #[test]
    fn status_evidence_derives_at_first_child_index_not_the_moved_cursor() {
        // W1.13 r3 P1: invoice allocation has advanced the cursor from the
        // claim-time index 24 to 31. The status address must still be the
        // claim response's address — derived at `first_child_index`.
        let xpub = regtest_account_tpub(3);
        let record = status_record(xpub.clone(), 24, 31);
        let (fingerprint, address) = status_evidence(&record, &BitcoinNetwork::Regtest).unwrap();
        assert_eq!(
            address,
            derive_bip84_p2wpkh_address(&xpub, 3, &BitcoinNetwork::Regtest, 24).unwrap(),
            "the status address derives at the immutable claim-time index"
        );
        assert_ne!(
            address,
            derive_bip84_p2wpkh_address(&xpub, 3, &BitcoinNetwork::Regtest, 31).unwrap(),
            "...and never at the mutable derivation cursor"
        );
        assert_eq!(
            fingerprint,
            key_fingerprint(&Xpub::from_str(&xpub).unwrap().encode())
        );
    }

    #[test]
    fn request_shape_validation_refuses_the_reserved_mode_then_unknown_channels() {
        let request = |channel: Option<&str>, mode: Option<&str>| ManualClaimRequest {
            auth_token: String::new(),
            account_xpub: String::new(),
            account_index: 0,
            claim_channel: channel.map(str::to_owned),
            allocation_mode: mode.map(str::to_owned),
        };
        assert_eq!(
            validate_request_shape(&request(Some("manual"), Some(REQUESTED_MODE_PASTED_AUTO))),
            Err(ManualClaimError::AllocationModeNotEnabled),
            "the reserved-mode refusal precedes the channel check"
        );
        assert_eq!(
            validate_request_shape(&request(Some("carrier_pigeon"), None)),
            Err(ManualClaimError::UnknownClaimChannel)
        );
        assert_eq!(
            validate_request_shape(&request(Some("manual"), None)),
            Ok(())
        );
        assert_eq!(
            validate_request_shape(&request(Some("bitkit_watch_only_v1"), None)),
            Ok(())
        );
        assert_eq!(validate_request_shape(&request(None, None)), Ok(()));
    }
}
