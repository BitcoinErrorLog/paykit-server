//! Unassigned-sentinel detection (design §B.8.7, W1.14): the creator-level
//! backstop for `exclusive` creators.
//!
//! A `bitkit_watch_only_v1` creator's exclusivity claim means the account
//! sees NO chain activity outside server-assigned invoice addresses. The
//! sentinel re-derives the account's never-assigned address window
//! (`[next_child_index, next_child_index + SENTINEL_SCAN_WINDOW)` — the
//! BIP44 gap window, the same bound the §B.5 claim scan uses) inside the
//! existing §B.7 observer tick and treats qualifying outputs there as
//! account-wide evidence. The only transition evidence can drive is the
//! one-way downgrade `exclusive → shared_manual` with the fixed
//! `unassigned_sentinel_evidence` reason; the sentinel never upgrades,
//! never auto-pays, and never classifies an assigned-address payment
//! (under/over/late — buyer typo, dust or overpayment) as account-wide
//! evidence: those stay invoice-specific.
//!
//! The downgrade predicate is implemented exactly once, in
//! [`downgrade_predicate`]:
//!
//! ```text
//! confirmed && value >= sentinel_min_value_sats && distinct_hits >= sentinel_hit_count
//! ```
//!
//! `confirmed` means at least one confirmation at observation time;
//! mempool-only outputs are durable candidates, never evidence.
//! `distinct_hits` counts distinct `txid:vout` outpoints per creator (the
//! persistence layer's `UNIQUE (creator_id, outpoint_lookup_hash)` key makes
//! replays idempotent). The atomic persistence, the assignment-serializing
//! lock, and the exactly-once seller event live in
//! [`crate::persistence::CreatorStore`].

use std::time::Duration;

use bitcoin::OutPoint;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{chain_history::CLAIM_SCAN_WINDOW, config::BitcoinNetwork};

/// Default sentinel minimum value: the relay-standard dust threshold for
/// the only output type this server derives — BIP84 P2WPKH, 98 vbytes × 3
/// sat/vbyte (Bitcoin Core's witness-program dust rule). Below it an output
/// is uneconomic spam: never a candidate, never evidence.
pub const DEFAULT_MIN_VALUE_SATS: u64 = 294;
/// Default distinct-outpoint hit count: one qualifying confirmed output is
/// definitive §B.8.7 evidence.
pub const DEFAULT_HIT_COUNT: u64 = 1;
/// Default per-creator re-scan cadence: no creator is re-admitted within
/// ten minutes of its last completed scan.
pub const DEFAULT_RESCAN_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Default freshness SLO: the age alert reports the oldest admitted
/// exclusive creator whose last completed scan is more than one hour old.
/// It reports only — it never gates creation and never mutates the mode.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(60 * 60);
/// Default sentinel sub-budget capacity: one tick never accounts more than
/// 1,000 sentinel Electrum requests against the subordinate allowance
/// (itself 10% of the shared bucket's post-live remainder by default).
pub const DEFAULT_MAX_REQUESTS_PER_TICK: u32 = 1000;
/// Default sentinel sub-budget sustained refill: 5 accounted requests per
/// second. The actual wire rate is bounded by the shared Electrum bucket
/// every sentinel request is also charged against.
pub const DEFAULT_MAX_REQUESTS_PER_SECOND: u32 = 5;
/// Addresses scanned per creator per scan: the BIP44 gap-limit window the
/// §B.5 claim scan already derives (`0/0 … 0/19`). Fixed, not configurable.
pub const SENTINEL_SCAN_WINDOW: u32 = CLAIM_SCAN_WINDOW;

/// The two policy numbers the downgrade predicate is evaluated against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentinelThresholds {
    /// Minimum output value: the relay-standard dust floor.
    pub min_value_sats: u64,
    /// Distinct-outpoint hit count required to downgrade.
    pub hit_count: u64,
}

/// The §B.8.7 definitive downgrade predicate, implemented once and reused
/// by the atomic persistence path and every test:
/// `confirmed && value >= sentinel_min_value_sats && distinct_hits >=
/// sentinel_hit_count`. `confirmed` is ≥ 1 confirmation at observation
/// time; `distinct_hits` counts the creator's distinct evidence outpoints
/// INCLUDING the outpoint under evaluation.
pub fn downgrade_predicate(
    confirmed: bool,
    value_sats: u64,
    distinct_hits: u64,
    thresholds: &SentinelThresholds,
) -> bool {
    confirmed && value_sats >= thresholds.min_value_sats && distinct_hits >= thresholds.hit_count
}

/// The sentinel's operational policy (from the `[sentinel]` config
/// section). The budget is a SUBORDINATE sub-budget of the shared global
/// Electrum bucket, not a second endpoint quota: one tick's sentinel
/// allowance defaults to 10% of the shared bucket's remaining balance after
/// every live invoice target is satisfied (zero when any live target was
/// deferred), hard-capped by `max_requests_per_tick` and the sustained
/// `max_requests_per_second` sub-budget refill, and every admitted sentinel
/// request is additionally charged against the shared bucket itself — so
/// sentinel scans never consume more than leftover global tokens, never
/// defer a live target, and can never push aggregate endpoint traffic past
/// the configured `electrum.*` quota.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentinelPolicy {
    pub thresholds: SentinelThresholds,
    /// Per-creator re-admission cadence.
    pub rescan_interval: Duration,
    /// Freshness SLO for the oldest admitted exclusive creator's scan.
    pub max_age: Duration,
    /// Sentinel sub-budget capacity per tick (a cap on the subordinate
    /// allowance, never additional endpoint capacity).
    pub max_requests_per_tick: u32,
    /// Sentinel sub-budget sustained refill rate.
    pub max_requests_per_second: u32,
    /// Addresses derived per creator per scan (the BIP44 gap window).
    pub scan_window: u32,
}

impl Default for SentinelPolicy {
    fn default() -> Self {
        Self {
            thresholds: SentinelThresholds {
                min_value_sats: DEFAULT_MIN_VALUE_SATS,
                hit_count: DEFAULT_HIT_COUNT,
            },
            rescan_interval: DEFAULT_RESCAN_INTERVAL,
            max_age: DEFAULT_MAX_AGE,
            max_requests_per_tick: DEFAULT_MAX_REQUESTS_PER_TICK,
            max_requests_per_second: DEFAULT_MAX_REQUESTS_PER_SECOND,
            scan_window: SENTINEL_SCAN_WINDOW,
        }
    }
}

impl SentinelPolicy {
    /// Creators one tick may plan at most: one whole window scan per
    /// creator inside the sub-budget's per-tick capacity. The tick's
    /// actual admission is bounded further by the subordinate allowance
    /// and the shared bucket's leftover balance.
    pub fn per_tick_creator_limit(&self) -> i64 {
        i64::from((self.max_requests_per_tick / self.scan_window).max(1))
    }
}

/// The durable classification of one observed unassigned-address outpoint
/// (migration 0016's CHECK vocabulary).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentinelClassification {
    /// Mempool-only qualifying-value output: durable, never evidence.
    Candidate,
    /// Confirmed qualifying-value output at a never-assigned address:
    /// counts one distinct hit.
    Evidence,
    /// The output's derivation index was assigned to an invoice before the
    /// sentinel's atomic re-check committed: never evidence, never
    /// downgrades.
    SupersededByAssignment,
}

impl SentinelClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Evidence => "evidence",
            Self::SupersededByAssignment => "superseded_by_assignment",
        }
    }
}

/// One output observed at a never-assigned derived address during one
/// creator's window scan. The address and outpoint never appear in logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentinelFinding {
    derivation_index: i64,
    address: String,
    outpoint: OutPoint,
    value_sats: u64,
    confirmations: u32,
}

impl SentinelFinding {
    pub fn new(
        derivation_index: i64,
        address: String,
        outpoint: OutPoint,
        value_sats: u64,
        confirmations: u32,
    ) -> Self {
        Self {
            derivation_index,
            address,
            outpoint,
            value_sats,
            confirmations,
        }
    }

    pub fn derivation_index(&self) -> i64 {
        self.derivation_index
    }
    pub fn address(&self) -> &str {
        &self.address
    }
    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }
    pub fn value_sats(&self) -> u64 {
        self.value_sats
    }
    pub fn confirmations(&self) -> u32 {
        self.confirmations
    }
    /// ≥ 1 confirmation at observation time.
    pub fn confirmed(&self) -> bool {
        self.confirmations >= 1
    }
    /// The canonical `txid:vout` text (the audit identity sealed in the
    /// evidence envelope and keyed for the lookup hash).
    pub fn outpoint_text(&self) -> String {
        self.outpoint.to_string()
    }
}

/// One exclusive creator admitted to a sentinel re-scan, with the key data
/// the tick needs to derive the never-assigned window. The xpub never
/// appears in logs.
pub struct SentinelScanTarget {
    creator_id: Uuid,
    xpub: Zeroizing<String>,
    account_index: u32,
    /// The creator's derivation cursor at plan time: the window is
    /// `[window_start, window_start + scan_window)`.
    window_start: i64,
}

impl SentinelScanTarget {
    pub fn new(
        creator_id: Uuid,
        xpub: Zeroizing<String>,
        account_index: u32,
        window_start: i64,
    ) -> Self {
        Self {
            creator_id,
            xpub,
            account_index,
            window_start,
        }
    }

    pub fn creator_id(&self) -> Uuid {
        self.creator_id
    }
    pub fn xpub(&self) -> &str {
        &self.xpub
    }
    pub fn account_index(&self) -> u32 {
        self.account_index
    }
    pub fn window_start(&self) -> i64 {
        self.window_start
    }
}

/// The result of one creator's atomic sentinel apply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SentinelScanOutcome {
    /// False when the creator's CURRENT mode was not `exclusive` at lock
    /// time. Usually that means nothing was written; the one exception is
    /// the §B.8.7 in-flight commit: a scan admitted while the creator was
    /// exclusive whose result lands after another scan already downgraded
    /// it (`shared_manual` with reason `unassigned_sentinel_evidence`)
    /// still commits its evidence/candidate rows below — never a second
    /// transition, event or alert, and never the cadence stamp.
    pub admitted: bool,
    /// Fresh evidence rows inserted (or promoted) by this scan.
    pub evidence: u64,
    /// Durable mempool-only candidate rows written by this scan.
    pub candidates: u64,
    /// Findings recorded `superseded_by_assignment`.
    pub superseded: u64,
    /// This scan performed the `exclusive → shared_manual` transition.
    pub downgraded: bool,
}

/// Why a sentinel window derivation failed (logged counts only; key
/// material is never logged).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentinelScanError {
    Derivation,
}

/// Derives one creator's never-assigned scan window:
/// `(derivation_index, address)` for every index in
/// `[window_start, window_start + window)`. This is the exact derivation
/// invoice allocation performs, so a hit at one of these addresses is an
/// address the server COULD assign later — the atomic apply re-checks
/// assignment under the creator row lock before recording evidence.
pub fn scan_window_addresses(
    xpub: &str,
    account_index: u32,
    network: &BitcoinNetwork,
    window_start: i64,
    window: u32,
) -> Result<Vec<(i64, String)>, SentinelScanError> {
    let mut addresses = Vec::with_capacity(window as usize);
    for offset in 0..window {
        let index = window_start
            .checked_add(i64::from(offset))
            .ok_or(SentinelScanError::Derivation)?;
        let address = crate::application::create_invoice::derive_bip84_p2wpkh_address(
            xpub,
            account_index,
            network,
            index,
        )
        .map_err(|_| SentinelScanError::Derivation)?;
        addresses.push((index, address));
    }
    Ok(addresses)
}

/// One durable evidence row served to the authenticated seller status
/// surface (§B.8.7 detection evidence metadata). Everything here is the
/// seller's own account data; none of it is ever logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentinelEvidenceRecord {
    pub classification: String,
    pub derivation_index: i64,
    /// The never-assigned derived address the output paid (the seller's own
    /// account data, served owner-only; never logged).
    pub address: String,
    /// The canonical `txid:vout`.
    pub outpoint: String,
    pub value_sats: u64,
    pub confirmations: i32,
    pub first_observed_at: time::OffsetDateTime,
    pub last_observed_at: time::OffsetDateTime,
}

/// The event-kind vocabulary of the durable seller-alert table (migration
/// 0016's CHECK). Exactly one kind exists in W1.14.
pub const SENTINEL_EVENT_KIND_DOWNGRADE: &str = "sentinel_downgrade";

/// The durable, owner-visible §B.8.7 alert: exactly one row per downgrade,
/// served to the authenticated seller on the status surface with stable
/// event kind, fixed reason identifier, transition time and the seller's
/// durable acknowledgement. All fields are static identifiers/timestamps —
/// no address, xpub, outpoint, value or free text is ever interpolated.
/// `acknowledged_at = None` means UNREAD; the owner's acknowledge call sets
/// it exactly once and it is never cleared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentinelAlertRecord {
    /// The fixed event kind (`sentinel_downgrade`).
    pub event_kind: String,
    /// The fixed §B.8.8 reason identifier (`unassigned_sentinel_evidence`).
    pub reason: String,
    /// When the mode transition (and the alert) committed.
    pub created_at: time::OffsetDateTime,
    /// The seller's durable read receipt; `None` while unread.
    pub acknowledged_at: Option<time::OffsetDateTime>,
}
