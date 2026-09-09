//! Direct Bitcoin observation boundary for invoice-specific addresses.

use std::{fmt, time::Duration};

use bitcoin::OutPoint;

use crate::config::BitcoinNetwork;

/// One invoice address whose direct outputs should be observed.
#[derive(Clone, PartialEq, Eq)]
pub struct ObservationTarget {
    address: String,
    current: Option<TrackedOutput>,
}

impl ObservationTarget {
    pub fn new(address: impl Into<String>, current: Option<TrackedOutput>) -> Self {
        Self {
            address: address.into(),
            current,
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn current(&self) -> Option<&TrackedOutput> {
        self.current.as_ref()
    }
}

impl fmt::Debug for ObservationTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservationTarget")
            .field("address", &"<redacted>")
            .field("has_current", &self.current.is_some())
            .finish()
    }
}

/// The currently bound pre-final output needed to detect factual disappearance.
#[derive(Clone, PartialEq, Eq)]
pub struct TrackedOutput {
    outpoint: OutPoint,
    sats: u64,
}

impl TrackedOutput {
    pub fn new(outpoint: OutPoint, sats: u64) -> Self {
        Self { outpoint, sats }
    }

    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    pub fn sats(&self) -> u64 {
        self.sats
    }
}

impl fmt::Debug for TrackedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrackedOutput")
            .field("outpoint", &"<redacted>")
            .field("sats", &"<redacted>")
            .finish()
    }
}

/// One output returned by the injected Electrum adapter. Attribution is
/// address-scoped and does not consume payer-originated messages.
#[derive(Clone, PartialEq, Eq)]
pub struct ObservedOutput {
    pub network: BitcoinNetwork,
    pub address: String,
    pub outpoint: OutPoint,
    pub sats: u64,
    pub confirmations: u32,
    pub confirmed_height: Option<u32>,
    /// False models an output removed by a replacement or reorganization.
    pub present: bool,
}

impl fmt::Debug for ObservedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedOutput")
            .field("network", &self.network)
            .field("address", &"<redacted>")
            .field("outpoint", &"<redacted>")
            .field("sats", &"<redacted>")
            .field("confirmations", &self.confirmations)
            .field("confirmed_height", &self.confirmed_height)
            .field("present", &self.present)
            .finish()
    }
}

impl ObservedOutput {
    pub fn status(&self) -> &'static str {
        if !self.present {
            "undetected"
        } else if self.confirmations == 0 {
            "detected"
        } else {
            "confirmed"
        }
    }
}

/// The exact-amount settlement predicate (design §B.8.2): an observed output
/// settles an invoice only when it pays exactly the required amount. An
/// overpayment is a mismatch and takes the same manual-review path as an
/// underpayment; the per-invoice amount nonce is absorbed in the price and
/// is never refunded on chain.
pub fn amount_matches(present: bool, observed_sats: u64, required_sats: u64) -> bool {
    present && observed_sats == required_sats
}

/// The durable binding currently associated with an invoice address.
///
/// An exact-amount output freezes after its first confirmation, but a
/// confirmed amount mismatch (under- or overpayment) remains replaceable. An
/// exact-amount output finalizes at six confirmations; callers report its
/// count as exactly six thereafter.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectBinding {
    outpoint: String,
    sats: u64,
    confirmations: u32,
    present: bool,
}

impl fmt::Debug for DirectBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectBinding")
            .field("outpoint", &"<redacted>")
            .field("sats", &"<redacted>")
            .field("confirmations", &self.confirmations)
            .field("present", &self.present)
            .finish()
    }
}

impl DirectBinding {
    pub fn new(outpoint: impl Into<String>, sats: u64, confirmations: u32, present: bool) -> Self {
        Self {
            outpoint: outpoint.into(),
            sats,
            confirmations,
            present,
        }
    }

    pub fn outpoint(&self) -> &str {
        &self.outpoint
    }

    pub fn is_final(&self, required_sats: u64) -> bool {
        amount_matches(self.present, self.sats, required_sats) && self.confirmations >= 6
    }

    pub fn reported_confirmations(&self, required_sats: u64) -> u32 {
        if amount_matches(self.present, self.sats, required_sats) {
            self.confirmations.min(6)
        } else {
            self.confirmations
        }
    }

    /// Chooses whether an incoming direct observation updates this binding,
    /// replaces it, or is ignored due to a temporary/final matching freeze.
    pub fn action_for(&self, incoming: &ObservedOutput, required_sats: u64) -> ObservationAction {
        self.action_for_values(
            &incoming.outpoint.to_string(),
            incoming.sats,
            incoming.confirmations,
            incoming.present,
            required_sats,
        )
    }

    pub fn action_for_values(
        &self,
        outpoint: &str,
        _sats: u64,
        _confirmations: u32,
        present: bool,
        required_sats: u64,
    ) -> ObservationAction {
        if outpoint == self.outpoint || !present {
            return ObservationAction::Update;
        }
        if self.is_final(required_sats) {
            return ObservationAction::Ignore;
        }
        if self.sats != required_sats || !self.present || self.confirmations == 0 {
            ObservationAction::Replace
        } else {
            ObservationAction::Ignore
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationAction {
    Update,
    Replace,
    Ignore,
}

/// One scheduled observation target. Observing a target costs exactly one
/// Electrum `script_list_unspent` lookup regardless of the address's
/// history or UTXO count, so the plan carries no request-cost bookkeeping:
/// `staleness` (the age of the last successful observation, or of the
/// invoice itself when it has never been observed) is the only scheduling
/// input, and the oldest target is always first.
#[derive(Clone, PartialEq, Eq)]
pub struct PlannedObservation {
    target: ObservationTarget,
    staleness: Duration,
}

impl PlannedObservation {
    pub fn new(target: ObservationTarget, staleness: Duration) -> Self {
        Self { target, staleness }
    }

    pub fn target(&self) -> &ObservationTarget {
        &self.target
    }

    pub fn staleness(&self) -> Duration {
        self.staleness
    }
}

impl fmt::Debug for PlannedObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlannedObservation")
            .field("target", &self.target)
            .field("staleness", &self.staleness)
            .finish()
    }
}
