//! Claim-time address-index history scan (design §B.5, P1-A part 2).
//!
//! Before a watch-only account is claimed, the server derives the account's
//! external chain (`0/0 … 0/19`, then windows of 20) and asks Electrum only
//! whether each script has any history — transactions are never fetched.
//! Windows continue until a fully empty window is found (the BIP44 gap limit
//! means a standards-compliant wallet cannot have a used address beyond an
//! empty window of 20). An unused account keeps start index 0; a used account
//! starts at `last_used_index + 1 + 20`. The scan is bounded at
//! [`CLAIM_SCAN_MAX_WINDOWS`] windows (1,000 addresses); past the bound the
//! claim is refused and the seller must use a fresh account. Any Electrum
//! failure refuses the claim rather than defaulting to index 0: an unscanned
//! claim is exactly the P1-A condition the design forbids.

use std::str::FromStr;

use bitcoin::{Address, ScriptBuf};

use crate::{application::create_invoice::derive_bip84_p2wpkh_address, config::BitcoinNetwork};

/// Addresses per scan window: the BIP44 gap limit.
pub const CLAIM_SCAN_WINDOW: u32 = 20;

/// Hard bound on a claim scan: 50 windows × 20 addresses = 1,000 derived
/// addresses. Exceeding it refuses the claim (design §B.5 "use a fresh
/// account") and bounds the Electrum cost of a claim.
pub const CLAIM_SCAN_MAX_WINDOWS: u32 = 50;

/// Forward gap applied past the last used index when history is found, so the
/// server never derives onto an address a wallet may already have handed out.
const USED_ACCOUNT_START_GAP: u32 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimScanError {
    /// Electrum could not answer (connect, timeout, or a malformed response).
    /// The claim must be refused, never defaulted to index 0.
    Unavailable,
    /// History was found in every window up to the bound; the seller must
    /// claim a fresh, dedicated account instead.
    HistoryTooDeep,
}

/// History-presence boundary for the claim-time address-index scan.
///
/// [`ChainHistoryPort::history_presence_batch`] is the single choke-point
/// through which every claim-scan Electrum RPC is routed: a later slice can
/// charge each batched call against the shared Electrum request limiter here
/// without touching the scan loop or the observer. The observer tick never
/// calls this port; the scan runs only in the claim handler.
#[async_trait::async_trait]
pub trait ChainHistoryPort: Send + Sync {
    /// Reports, per script, whether the script has any history at all.
    ///
    /// Implementations issue ONE batched `blockchain.scripthash.get_history`
    /// for the whole slice (presence only; no transaction fetches) and return
    /// exactly one presence flag per requested script, in request order.
    async fn history_presence_batch(
        &self,
        scripts: &[ScriptBuf],
    ) -> Result<Vec<bool>, ClaimScanError>;
}

/// The claim scan's result: the derivation cursor the account must start at,
/// plus whether ANY history was seen at all. `saw_history` is the §B.8.6
/// corroborating fact a `bitkit_watch_only_v1` claim is checked against — a
/// freshly reserved Shop account is empty, and any history at all means this
/// is not one (downgrade `account_has_history`); it is reported explicitly
/// rather than inferred from `start_index != 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimScan {
    /// The child index the account's derivation cursor must start at: 0 for
    /// an unused account, `last_used_index + 1 + 20` otherwise.
    pub start_index: u32,
    /// Whether the scan found history on any derived address.
    pub saw_history: bool,
}

/// Scans the claimed BIP84 account's external chain and returns the child
/// index the account's derivation cursor must start at. Only counts and
/// window indices are logged — never the xpub, addresses, or scripthashes.
pub async fn scan_claim_start_index(
    port: &dyn ChainHistoryPort,
    canonical_xpub: &str,
    account_index: u32,
    network: &BitcoinNetwork,
) -> Result<ClaimScan, ClaimScanError> {
    let mut last_used: Option<u32> = None;
    for window in 0..CLAIM_SCAN_MAX_WINDOWS {
        let first = window * CLAIM_SCAN_WINDOW;
        let mut scripts = Vec::with_capacity(CLAIM_SCAN_WINDOW as usize);
        for offset in 0..CLAIM_SCAN_WINDOW {
            let address = derive_bip84_p2wpkh_address(
                canonical_xpub,
                account_index,
                network,
                i64::from(first + offset),
            )
            .map_err(|_| ClaimScanError::Unavailable)?;
            scripts.push(
                Address::from_str(&address)
                    .map_err(|_| ClaimScanError::Unavailable)?
                    .assume_checked()
                    .script_pubkey(),
            );
        }
        let presence = port.history_presence_batch(&scripts).await?;
        if presence.len() != scripts.len() {
            // A malformed port answer is an Electrum failure, not an empty
            // window: refuse rather than scan on truncated data.
            return Err(ClaimScanError::Unavailable);
        }
        for (offset, used) in presence.iter().enumerate() {
            if *used {
                last_used = Some(first + offset as u32);
            }
        }
        let window_used = presence.iter().any(|used| *used);
        tracing::debug!(window, window_used, "claim history scan window complete");
        if !window_used {
            let start = last_used
                .map(|index| index + 1 + USED_ACCOUNT_START_GAP)
                .unwrap_or(0);
            tracing::info!(
                windows = window + 1,
                start_index = start,
                "claim history scan complete"
            );
            return Ok(ClaimScan {
                start_index: start,
                saw_history: last_used.is_some(),
            });
        }
    }
    tracing::warn!(
        windows = CLAIM_SCAN_MAX_WINDOWS,
        "claim history scan exceeded the address bound; refusing the claim"
    );
    Err(ClaimScanError::HistoryTooDeep)
}
