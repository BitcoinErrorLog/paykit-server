//! Read-only payment status lookup backed only by durable invoice facts.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    allocation::AllocationMode,
    domain::locks::{BundleId, CreatorPubky},
    persistence::{InvoiceStore, PersistenceError},
};

/// Validated payment facts read from one persisted invoice. Every variant
/// carries the creator's CURRENT database allocation mode (W1.14, design
/// D.3 F9): the automatic paid transition gates on it at transition time,
/// never on a claim-time cached copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistedPaymentStatus {
    Undetected {
        late_settlement: bool,
        allocation_mode: AllocationMode,
    },
    Detected {
        confirmations: u32,
        amount_matched: bool,
        late_settlement: bool,
        allocation_mode: AllocationMode,
    },
    Confirmed {
        confirmations: u32,
        amount_matched: bool,
        late_settlement: bool,
        allocation_mode: AllocationMode,
    },
}

impl PersistedPaymentStatus {
    /// The creator's current database allocation mode.
    pub fn allocation_mode(&self) -> AllocationMode {
        match self {
            Self::Undetected {
                allocation_mode, ..
            }
            | Self::Detected {
                allocation_mode, ..
            }
            | Self::Confirmed {
                allocation_mode, ..
            } => *allocation_mode,
        }
    }
}

/// Narrow read-only durable status boundary.
#[async_trait]
pub trait StatusRepository: Send + Sync {
    async fn status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<PersistedPaymentStatus>, PersistenceError>;
}

#[async_trait]
impl StatusRepository for InvoiceStore {
    async fn status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<PersistedPaymentStatus>, PersistenceError> {
        InvoiceStore::payment_status(self, creator, bundle_id).await
    }
}

/// The versioned Paykit Bitcoin status contract identifier emitted on
/// every `/transactions/status` response (W1.14).
///
/// - `paykit.bitcoin_status/v1` (never emitted by this build): the
///   pre-W1.14 observation triple (`status`, `confirmations`,
///   `amount_matched` + `late_settlement`) with no allocation mode.
/// - `paykit.bitcoin_status/v2` (this build): `allocation_mode` is
///   MANDATORY on every Paykit Bitcoin status, always one of the exact
///   strings `exclusive` / `shared_manual`, always the creator's CURRENT
///   database mode read at request time.
///
/// The automatic paid transition's consumer (marketplace W1.15) MUST fail
/// closed — route to manual review, never auto-confirm — when the field is
/// absent, the contract version is not this identifier, or the mode is not
/// exactly `exclusive`. W1.14 ships only the producer half: this
/// dependency is deployment-blocking until W1.15 consumes the field and
/// passes a real cross-repo test.
pub const BITCOIN_STATUS_CONTRACT_V2: &str = "paykit.bitcoin_status/v2";

/// The exact, secret-free Locks-facing status response. `late_settlement`
/// marks an observation recorded in the §B.9 expiry tail: it is a factual
/// observation, never a settlement — the marketplace routes it to
/// `manual_review` and it can never drive `paid`, even when it reports
/// `confirmed` with an exact amount (§B.9, §B.8.8). `allocation_mode` is
/// the creator's CURRENT database mode (W1.14, design D.3 F9): the
/// automatic paid transition reads it here, at transition time, and pays
/// automatically only while it is `exclusive` — a sentinel downgrade
/// landing after invoice creation routes the order to the existing
/// manual-review/seller-confirm path instead. The response is contract
/// version [`BITCOIN_STATUS_CONTRACT_V2`]: the mode is always present, an
/// unknown persisted mode fails the read closed
/// ([`PersistenceError::CorruptOrMissing`]) rather than emitting a value a
/// consumer could ignore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentStatusResponse {
    status: &'static str,
    confirmations: u32,
    amount_matched: bool,
    late_settlement: bool,
    allocation_mode: AllocationMode,
}

impl PaymentStatusResponse {
    fn new(
        status: &'static str,
        confirmations: u32,
        amount_matched: bool,
        late_settlement: bool,
        allocation_mode: AllocationMode,
    ) -> Self {
        Self {
            status,
            confirmations,
            amount_matched,
            late_settlement,
            allocation_mode,
        }
    }

    pub fn status(&self) -> &'static str {
        self.status
    }

    pub fn confirmations(&self) -> u32 {
        self.confirmations
    }

    pub fn amount_matched(&self) -> bool {
        self.amount_matched
    }

    pub fn late_settlement(&self) -> bool {
        self.late_settlement
    }

    /// The creator's CURRENT database allocation mode (`exclusive` or
    /// `shared_manual`), read at transition time.
    pub fn allocation_mode(&self) -> AllocationMode {
        self.allocation_mode
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentStatusError {
    NotFound,
    Unavailable,
}

/// Looks up factual payment status without session validation, lock fetching,
/// invoice decryption, observer access, or other external I/O.
pub struct PaymentStatusService {
    repository: Arc<dyn StatusRepository>,
}

impl PaymentStatusService {
    pub fn new(repository: Arc<dyn StatusRepository>) -> Self {
        Self { repository }
    }

    pub async fn status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<PaymentStatusResponse, PaymentStatusError> {
        let persisted = self
            .repository
            .status(creator, bundle_id)
            .await
            .map_err(|_| PaymentStatusError::Unavailable)?
            .ok_or(PaymentStatusError::NotFound)?;
        Ok(match persisted {
            PersistedPaymentStatus::Undetected {
                late_settlement,
                allocation_mode,
            } => {
                PaymentStatusResponse::new("undetected", 0, false, late_settlement, allocation_mode)
            }
            PersistedPaymentStatus::Detected {
                confirmations,
                amount_matched,
                late_settlement,
                allocation_mode,
            } => PaymentStatusResponse::new(
                "detected",
                confirmations,
                amount_matched,
                late_settlement,
                allocation_mode,
            ),
            PersistedPaymentStatus::Confirmed {
                confirmations,
                amount_matched,
                late_settlement,
                allocation_mode,
            } => PaymentStatusResponse::new(
                "confirmed",
                confirmations,
                amount_matched,
                late_settlement,
                allocation_mode,
            ),
        })
    }
}
