//! Two-phase creation and activation (design §B.11): the shared state
//! machine behind the signed `activate` and `void` routes, and the §B.11.3
//! response bodies both creation entrypoints return from phase 1.
//!
//! Phase 1 (prepare) leaves the invoice `prepared` — baselined, never
//! observed, never published (§B.11.5). Phase 2 (`activate`) verifies the
//! echoed `stack_id` and `total_sats`, takes the §B.4.6 tick-1 snapshot, and
//! flips `prepared → observing` together with both outbox rows in one
//! transaction. `void` cancels a `prepared` invoice. Both phase-2 operations
//! are idempotent per §B.11.6 and are never gated by offer availability or
//! the creation kill switch (§C.16: refusing them would strand exactly the
//! `prepared` invoices the switch exists to drain).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use serde::Serialize;
use uuid::Uuid;

use crate::{
    application::create_invoice::{CreateInvoiceError, DeadlineClock, SystemDeadlineClock},
    persistence::{ActivationWrite, InvoicePhaseView, InvoiceStore, PersistenceError, VoidWrite},
    workers::observer::{CreationSnapshot, ElectrumPort, RequestLimiter},
};

/// One phase-2 request's deadline. The activation path performs one
/// Electrum round (the tick-1 snapshot) plus one state transaction; it
/// reuses the creation path's budget shape so a stalled snapshot can never
/// hold the handler open.
const REQUEST_DEADLINE: Duration = Duration::from_secs(15);

/// The prepare (phase-1) response body, verbatim §B.11.3. `total_sats` is
/// authoritative (`amount_sats + nonce_sats`): the figure the marketplace
/// must charge, display and record. The address is deliberately absent —
/// only its fingerprint leaves this server before activation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrepareBody {
    pub invoice_id: Uuid,
    pub state: String,
    pub stack_id: String,
    pub allocation_mode: String,
    pub nonce_sats: u64,
    pub total_sats: u64,
    pub expires_at: Option<String>,
    pub prepare_expires_at: Option<String>,
    pub derived_address_fingerprint: String,
}

/// The activate (phase-2) response body, verbatim §B.11.3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActivateBody {
    pub invoice_id: Uuid,
    pub state: String,
    pub activated_at: Option<String>,
    pub expires_at: Option<String>,
    pub total_sats: u64,
}

/// The void response body, verbatim §B.11.3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VoidBody {
    pub invoice_id: Uuid,
    pub state: String,
    pub voided_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivateRequest {
    pub invoice_id: Uuid,
    /// Echo of the `stack_id` phase 1 returned for this invoice — never a
    /// value re-derived from configuration (§B.11.3).
    pub stack_id: String,
    /// Guard, not an instruction: must equal the stored nonce'd total.
    pub total_sats: u64,
    /// The marketplace's retry counter: logged, never trusted.
    pub activation_attempt: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoidRequest {
    pub invoice_id: Uuid,
    pub stack_id: String,
    /// The marketplace's void reason: logged, never trusted.
    pub reason: String,
}

/// Named refusals of the two-phase state machine, mapped one-to-one onto
/// the §B.11.3 error table at the HTTP boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoPhaseError {
    UnknownInvoice,
    StackIdentityMismatch,
    ActivationTotalMismatch,
    PrepareExpired,
    InvoiceFinalized,
    BaselineInProgress,
    DeadlineExceeded,
    Unavailable,
}

/// Builds the phase-1 body from the stored view, or the §B.11.6 named
/// refusal a phase-1 replay against a void state must produce. `prepared`,
/// `observing` and `expired_tail` all return the stored body (the state is
/// echoed verbatim); anything final is a refusal, never a success.
pub fn prepare_outcome(
    view: &InvoicePhaseView,
    stack_id: &str,
) -> Result<PrepareBody, CreateInvoiceError> {
    match view.baseline_state.as_str() {
        "prepared" | "observing" | "expired_tail" => Ok(PrepareBody {
            invoice_id: view.invoice_id,
            state: view.baseline_state.clone(),
            stack_id: stack_id.to_owned(),
            allocation_mode: view.allocation_mode.clone(),
            nonce_sats: view.nonce_sats,
            total_sats: view.total_sats,
            expires_at: rfc3339(view.expires_at),
            prepare_expires_at: rfc3339(view.prepare_expires_at),
            derived_address_fingerprint: view.derived_address_fingerprint.clone(),
        }),
        "void_prepare_expired" => Err(CreateInvoiceError::PrepareExpired),
        "void_baseline_failed" | "void_cancelled" | "expired_final" => {
            Err(CreateInvoiceError::InvoiceFinalized)
        }
        "awaiting_baseline" => Err(CreateInvoiceError::BaselineInProgress),
        _ => Err(CreateInvoiceError::Unavailable),
    }
}

fn activate_body(view: &InvoicePhaseView) -> ActivateBody {
    ActivateBody {
        invoice_id: view.invoice_id,
        state: view.baseline_state.clone(),
        activated_at: rfc3339(view.activated_at),
        expires_at: rfc3339(view.expires_at),
        total_sats: view.total_sats,
    }
}

fn void_body(view: &InvoicePhaseView) -> VoidBody {
    VoidBody {
        invoice_id: view.invoice_id,
        state: view.baseline_state.clone(),
        // Both void states are final, so the row's `updated_at` is the void
        // (or reap) commit time and never moves again.
        voided_at: rfc3339(Some(view.updated_at)),
    }
}

fn rfc3339(value: Option<time::OffsetDateTime>) -> Option<String> {
    value.map(|timestamp| {
        timestamp
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    })
}

pub struct TwoPhaseService {
    store: Arc<InvoiceStore>,
    electrum: Arc<dyn ElectrumPort>,
    electrum_limiter: RequestLimiter,
    snapshot_slots: Arc<tokio::sync::Semaphore>,
    max_creation_history_entries: usize,
    max_transaction_bytes: usize,
    stack_id: String,
    clock: Arc<dyn DeadlineClock>,
}

impl TwoPhaseService {
    pub fn new(
        store: Arc<InvoiceStore>,
        electrum: Arc<dyn ElectrumPort>,
        electrum_limiter: RequestLimiter,
        snapshot_slots: Arc<tokio::sync::Semaphore>,
        max_creation_history_entries: usize,
        max_transaction_bytes: usize,
        stack_id: String,
    ) -> Self {
        Self {
            store,
            electrum,
            electrum_limiter,
            snapshot_slots,
            max_creation_history_entries,
            max_transaction_bytes,
            stack_id,
            clock: Arc::new(SystemDeadlineClock),
        }
    }

    /// Phase 2 (design §B.11.3): verify the echoed stack identity and the
    /// echoed total, take the §B.4.6 tick-1 snapshot, and activate — or
    /// replay the stored body when the invoice already activated.
    pub async fn activate(&self, request: ActivateRequest) -> Result<ActivateBody, TwoPhaseError> {
        let started = self.clock.now();
        // The echoed stack_id names the stack the marketplace believes
        // issued this invoice; a mismatch is refused before any invoice
        // lookup so a retried cross-stack delivery can never touch a live
        // invoice that happens to share the id (§B.11.3, r8).
        if request.stack_id != self.stack_id {
            return Err(TwoPhaseError::StackIdentityMismatch);
        }
        let view = self.load_view(request.invoice_id).await?;
        match view.baseline_state.as_str() {
            // Idempotent replay (§B.11.6): the same body, no writes — no
            // second tick-1 snapshot, no re-enqueue.
            "observing" | "expired_tail" => return Ok(activate_body(&view)),
            "prepared" => {}
            "void_prepare_expired" => return Err(TwoPhaseError::PrepareExpired),
            // §B.11.1: the void states, `expired_final` and the two
            // resolved states are all final — activation against any of
            // them is the named finalized refusal.
            "void_baseline_failed"
            | "void_cancelled"
            | "expired_final"
            | "resolved_paid_manually"
            | "resolved_closed" => {
                return Err(TwoPhaseError::InvoiceFinalized);
            }
            "awaiting_baseline" => return Err(TwoPhaseError::BaselineInProgress),
            _ => return Err(TwoPhaseError::Unavailable),
        }
        // `total_sats` is echoed as a guard, not an instruction: a mismatch
        // against the stored total means the marketplace persisted the
        // pre-nonce amount (the exact R3-3 bug) and must NOT activate.
        if view.total_sats != request.total_sats {
            return Err(TwoPhaseError::ActivationTotalMismatch);
        }
        tracing::info!(
            activation_attempt = request.activation_attempt,
            "activating prepared invoice"
        );
        // §B.4.6: the tick-1 snapshot is taken inside activation, BEFORE
        // the state transaction, so no row lock is held across Electrum
        // I/O. A snapshot failure changes nothing: the invoice stays
        // `prepared` and the marketplace's activation outbox retries.
        let snapshot = self
            .tick_one_snapshot(&view.bitcoin_address, started)
            .await?;
        match self
            .store
            .activate_invoice(
                request.invoice_id,
                &snapshot.unconfirmed_outputs,
                &snapshot.unconfirmed_inputs,
            )
            .await
        {
            Ok(Some(ActivationWrite::Activated | ActivationWrite::AlreadyActive)) => {
                let view = self.load_view(request.invoice_id).await?;
                Ok(activate_body(&view))
            }
            Ok(None) => Err(TwoPhaseError::UnknownInvoice),
            Err(PersistenceError::PrepareExpired) => Err(TwoPhaseError::PrepareExpired),
            Err(PersistenceError::InvoiceFinalized) => Err(TwoPhaseError::InvoiceFinalized),
            Err(PersistenceError::BaselineInProgress) => Err(TwoPhaseError::BaselineInProgress),
            Err(_) => Err(TwoPhaseError::Unavailable),
        }
    }

    /// Cancellation (design §B.11.3): `prepared → void_cancelled`,
    /// idempotent on replay, and refused with the named errors for every
    /// other state per §B.11.6.
    pub async fn void(&self, request: VoidRequest) -> Result<VoidBody, TwoPhaseError> {
        if request.stack_id != self.stack_id {
            return Err(TwoPhaseError::StackIdentityMismatch);
        }
        // §B.11.1's resolved states are final: a resolved invoice was
        // published and its money question answered, so voiding it would
        // vanish a published request — the same `invoice_finalized`
        // refusal §B.11.6 gives `observing`/`expired_tail`. The store's
        // row lock below remains authoritative for every other state.
        let view = self.load_view(request.invoice_id).await?;
        if matches!(
            view.baseline_state.as_str(),
            "resolved_paid_manually" | "resolved_closed"
        ) {
            return Err(TwoPhaseError::InvoiceFinalized);
        }
        tracing::info!(reason = %request.reason, "voiding prepared invoice");
        match self.store.void_invoice(request.invoice_id).await {
            Ok(Some(VoidWrite::Voided | VoidWrite::AlreadyVoid)) => {
                let view = self.load_view(request.invoice_id).await?;
                Ok(void_body(&view))
            }
            Ok(None) => Err(TwoPhaseError::UnknownInvoice),
            Err(PersistenceError::InvoiceFinalized) => Err(TwoPhaseError::InvoiceFinalized),
            Err(PersistenceError::BaselineInProgress) => Err(TwoPhaseError::BaselineInProgress),
            Err(_) => Err(TwoPhaseError::Unavailable),
        }
    }

    async fn load_view(&self, invoice_id: Uuid) -> Result<InvoicePhaseView, TwoPhaseError> {
        self.store
            .prepare_view(invoice_id)
            .await
            .map_err(|_| TwoPhaseError::Unavailable)?
            .ok_or(TwoPhaseError::UnknownInvoice)
    }

    /// The §B.4.6 composed first-tick snapshot: one bounded Electrum round
    /// over the derived address, charged against the shared request limiter
    /// and admitted through the same snapshot-slot semaphore creation uses.
    async fn tick_one_snapshot(
        &self,
        address: &str,
        started: Instant,
    ) -> Result<CreationSnapshot, TwoPhaseError> {
        let remaining = self.remaining(started)?;
        self.electrum_limiter
            .reserve_or_wait(3, Instant::now() + remaining.min(Duration::from_secs(2)))
            .await
            .map_err(|_| TwoPhaseError::Unavailable)?;
        let remaining = self.remaining(started)?;
        let slot = tokio::time::timeout(remaining, self.snapshot_slots.clone().acquire_owned())
            .await
            .map_err(|_| TwoPhaseError::DeadlineExceeded)?
            .map_err(|_| TwoPhaseError::Unavailable)?;
        let remaining = self.remaining(started)?;
        match tokio::time::timeout(
            remaining,
            self.electrum.creation_snapshot(
                address,
                self.max_creation_history_entries,
                self.max_transaction_bytes,
                &self.electrum_limiter,
                slot,
            ),
        )
        .await
        {
            Err(_) => Err(TwoPhaseError::DeadlineExceeded),
            Ok(Err(_)) => Err(TwoPhaseError::Unavailable),
            Ok(Ok(snapshot)) => Ok(snapshot),
        }
    }

    fn remaining(&self, started: Instant) -> Result<Duration, TwoPhaseError> {
        let remaining = REQUEST_DEADLINE
            .checked_sub(self.clock.now().saturating_duration_since(started))
            .ok_or(TwoPhaseError::DeadlineExceeded)?;
        if remaining.is_zero() {
            return Err(TwoPhaseError::DeadlineExceeded);
        }
        Ok(remaining)
    }
}
