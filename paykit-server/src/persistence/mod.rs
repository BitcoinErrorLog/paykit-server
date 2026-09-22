//! PostgreSQL persistence primitives.

mod creators;
mod deployment;
mod invoices;
mod migrations;
mod outbox;
pub(crate) mod sdk_state;

pub use creators::{
    ChildIndexCursor, CreatorAllocationStatus, CreatorCredentials, CreatorSetupLock,
    CreatorStatusRecord, CreatorStore, PersistedCreator,
};
pub use deployment::{DeploymentStore, PersistenceError, StackIdentity};
pub(crate) use invoices::BitcoinObservationInput;
pub use invoices::{
    ActivationWrite, AtomicInvoiceInput, AtomicInvoiceResult, ExpiryTransitions, InvoicePhaseView,
    InvoicePreflight, InvoiceStore, NewReaderPayloadFactory, NewReaderPayloads,
    OBSERVER_LEADERSHIP_LEASE_NAME, ObserverLease, PendingCandidate, PgObserverLeadership,
    ResolveWrite, VoidWrite,
};
pub use migrations::{
    MIGRATION_ADVISORY_LOCK_KEY, MigrationLock, run_migrations, verify_migrations_applied,
};
pub use outbox::{
    ClaimedHandoff, ClaimedOutbox, HANDOFF_UNRESOLVED_SDK_INVOKED_UNATTRIBUTED,
    HANDOFF_UNRESOLVED_SDK_NOT_INVOKED, HandoffFenceSeam, HandoffRelease, HandoffResult,
    OutboxRetryClass, OutboxStore, SeamHook, UnattributedInspection,
};
pub use sdk_state::{PostgresStorageAdapter, SdkStateStore};
