//! Creator allocation mode (design §B.8.6, D1/D2, W1.13).
//!
//! A creator's `allocation_mode` decides whether chain observation may move
//! an order to `paid` automatically. The canary scope is `exclusive` and
//! `shared_manual` only (D8): `pasted_auto` exists in the schema's check
//! constraint so the r4 analysis stays addressable (§B.8.6 r6), but no code
//! path, flag, migration or seller action produces it — a claim requesting
//! it is refused unconditionally with `allocation_mode_not_enabled`, and
//! there is deliberately no [`AllocationMode::PastedAuto`] variant to
//! construct.
//!
//! The claim distinguishes a Bitkit exclusive claim from a paste by the
//! `claim_channel` field on `POST /v0/accounts/claim` — `manual` or
//! `bitkit_watch_only_v1` (§B.8.6). A missing channel is treated — and
//! recorded — as `manual`; any other value is refused with
//! `unknown_claim_channel` (fail closed: unknown channels are never
//! canonicalized silently and never persisted). For
//! `bitkit_watch_only_v1` the server verifies four corroborating facts for
//! itself — corroborated provenance, never proof (D7): the declared account
//! index is at least 1, the declared index equals the key's own hardened
//! child number, the §B.5 claim scan found no history at all, and the
//! fingerprint has never been claimed by another seller (the §B.8.5 binding,
//! which stays a hard refusal upstream of this decision). Any other failure
//! downgrades the claim to `shared_manual` with one of §B.8.8's five fixed
//! reason identifiers rather than refusing it.

/// The `claim_channel` value a Bitkit watch-only claim asserts (§B.8.6).
pub const CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1: &str = "bitkit_watch_only_v1";

/// The `claim_channel` value a manual paste or file import asserts (§B.8.6).
/// A missing `claim_channel` is treated — and recorded — as this channel:
/// §B.8.6 gives the server nothing to corroborate for "a bare key and
/// nothing else". A present channel that is neither this nor the Bitkit
/// value never reaches the allocation decision: the claim refuses it with
/// `unknown_claim_channel` (fail closed).
pub const CLAIM_CHANNEL_MANUAL: &str = "manual";

/// The `allocation_mode` request value that is refused unconditionally, on
/// every code path and under every configuration, with
/// `allocation_mode_not_enabled` (§B.8.6 r6, Sol P1). There is no
/// configuration flag, operator toggle or per-seller override.
pub const REQUESTED_MODE_PASTED_AUTO: &str = "pasted_auto";

/// The two allocation modes any code path can produce (canary scope, D8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationMode {
    /// Automatic `paid` from chain observation: a `bitkit_watch_only_v1`
    /// claim that passed every corroborating check.
    Exclusive,
    /// Seller-confirmed payment (§B.8.8): the default and every downgrade.
    SharedManual,
}

impl AllocationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::SharedManual => "shared_manual",
        }
    }
}

/// §B.8.8's five fixed downgrade-reason identifiers. The seller-visible copy
/// for each is fixed in §B.8.8 and rendered by the Shop client (W1.16); the
/// server only ever stores and returns the identifier. Only the four
/// claim-time reasons are constructed here;
/// [`DowngradeReason::UnassignedSentinelEvidence`] is §B.8.7's
/// sentinel-detection reason (W1.14) and exists so the seller status surface
/// can name a persisted value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DowngradeReason {
    /// The claim was not asserted on the Bitkit channel: a paste, a file
    /// import, or any other `claim_channel`.
    ClaimChannelNotBitkit,
    /// `account_index = 0`: the wallet's main account, which Bitkit's
    /// reservation refuses to allocate for Shop.
    AccountIndexZero,
    /// The declared account index disagrees with the key's own hardened
    /// child number.
    AccountIndexMismatch,
    /// The §B.5 claim scan found any history at all on the account.
    AccountHasHistory,
    /// §B.8.7 definitive downgrade evidence (W1.14); no W1.13 code path
    /// constructs it.
    #[allow(dead_code)]
    UnassignedSentinelEvidence,
}

impl DowngradeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaimChannelNotBitkit => "claim_channel_not_bitkit",
            Self::AccountIndexZero => "account_index_zero",
            Self::AccountIndexMismatch => "account_index_mismatch",
            Self::AccountHasHistory => "account_has_history",
            Self::UnassignedSentinelEvidence => "unassigned_sentinel_evidence",
        }
    }
}

/// The allocation decision one claim commit persists: the channel, the
/// mode, and the downgrade reason when the mode is `shared_manual` because
/// of a failed corroborating check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimAllocation {
    /// The `claim_channel` from the claim request (one of §B.8.6's two
    /// values — unknown channels are refused before this point); `None` for
    /// the Bitkit companion flow, which carries no channel assertion.
    pub channel: Option<String>,
    pub mode: AllocationMode,
    pub downgrade_reason: Option<DowngradeReason>,
}

impl ClaimAllocation {
    /// The companion flow's allocation: §B.8.6's channel assertion and its
    /// corroborating checks exist only on `POST /v0/accounts/claim`, and the
    /// companion flow performs no claim-time history scan
    /// (`real_setup.rs`'s `next_child_index_floor: None`), so it can never
    /// satisfy the scan-clean check. It is `shared_manual` by construction,
    /// with no channel and no downgrade reason recorded.
    pub fn companion_default() -> Self {
        Self {
            channel: None,
            mode: AllocationMode::SharedManual,
            downgrade_reason: None,
        }
    }

    /// Test and fixture default for direct [`crate::persistence::CreatorStore`]
    /// writes outside any claim path.
    pub fn shared_manual_default() -> Self {
        Self::companion_default()
    }
}

/// Decides a claim's allocation from the corroborating facts the server
/// verified for itself (§B.8.6). Evaluated after the existing claim gates
/// (parse, depth/range, role-gated deny-list, the §B.8.5 fingerprint↔seller
/// binding) and the §B.5 scan, from the scan result and key data already
/// computed — it performs no I/O and no additional Electrum calls.
///
/// * `channel`: the `claim_channel` submitted (already defaulted to `manual`
///   when absent; unknown values are refused upstream, and any non-Bitkit
///   value reaching here still fails safe to a downgrade).
/// * `declared_index`: the `account_index` the client submitted.
/// * `index_mismatch`: whether the declared index disagrees with the key's
///   own hardened child number.
/// * `saw_history`: whether the §B.5 scan found any history at all.
///
/// Failures are checked in the design's listed order (index ≥ 1, then index
/// agreement, then scan-clean), each downgrading with its fixed §B.8.8
/// identifier; the §B.8.5 fingerprint check is a refusal upstream and never
/// reaches this function.
pub fn decide_allocation(
    channel: &str,
    declared_index: u32,
    index_mismatch: bool,
    saw_history: bool,
) -> ClaimAllocation {
    let downgrade_reason = if channel != CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1 {
        Some(DowngradeReason::ClaimChannelNotBitkit)
    } else if declared_index == 0 {
        Some(DowngradeReason::AccountIndexZero)
    } else if index_mismatch {
        Some(DowngradeReason::AccountIndexMismatch)
    } else if saw_history {
        Some(DowngradeReason::AccountHasHistory)
    } else {
        None
    };
    ClaimAllocation {
        channel: Some(channel.to_owned()),
        mode: match downgrade_reason {
            None => AllocationMode::Exclusive,
            Some(_) => AllocationMode::SharedManual,
        },
        downgrade_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bitkit_claim_passing_every_check_is_exclusive() {
        let allocation = decide_allocation(CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1, 3, false, false);
        assert_eq!(allocation.mode, AllocationMode::Exclusive);
        assert_eq!(allocation.downgrade_reason, None);
        assert_eq!(
            allocation.channel.as_deref(),
            Some(CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1)
        );
    }

    #[test]
    fn every_non_bitkit_channel_downgrades_with_claim_channel_not_bitkit() {
        // Unknown channels never reach this function — the claim refuses
        // them with `unknown_claim_channel` — but the decision itself stays
        // fail-safe: anything that is not the Bitkit channel is not
        // exclusive.
        for channel in [CLAIM_CHANNEL_MANUAL, "paste", "carrier_pigeon"] {
            // Even an otherwise-perfect claim: the channel alone decides.
            let allocation = decide_allocation(channel, 3, false, false);
            assert_eq!(allocation.mode, AllocationMode::SharedManual, "{channel}");
            assert_eq!(
                allocation.downgrade_reason,
                Some(DowngradeReason::ClaimChannelNotBitkit),
                "{channel}"
            );
        }
    }

    #[test]
    fn each_failed_check_downgrades_with_its_fixed_identifier() {
        assert_eq!(
            decide_allocation(CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1, 0, false, false).downgrade_reason,
            Some(DowngradeReason::AccountIndexZero)
        );
        assert_eq!(
            decide_allocation(CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1, 5, true, false).downgrade_reason,
            Some(DowngradeReason::AccountIndexMismatch)
        );
        assert_eq!(
            decide_allocation(CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1, 5, false, true).downgrade_reason,
            Some(DowngradeReason::AccountHasHistory)
        );
        // The design's listed order decides when several checks fail.
        assert_eq!(
            decide_allocation(CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1, 0, true, true).downgrade_reason,
            Some(DowngradeReason::AccountIndexZero)
        );
    }

    #[test]
    fn reason_identifiers_are_exactly_the_five_fixed_strings() {
        assert_eq!(
            DowngradeReason::ClaimChannelNotBitkit.as_str(),
            "claim_channel_not_bitkit"
        );
        assert_eq!(
            DowngradeReason::AccountIndexZero.as_str(),
            "account_index_zero"
        );
        assert_eq!(
            DowngradeReason::AccountIndexMismatch.as_str(),
            "account_index_mismatch"
        );
        assert_eq!(
            DowngradeReason::AccountHasHistory.as_str(),
            "account_has_history"
        );
        assert_eq!(
            DowngradeReason::UnassignedSentinelEvidence.as_str(),
            "unassigned_sentinel_evidence"
        );
    }
}
