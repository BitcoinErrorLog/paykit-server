//! PostgreSQL persistence primitives.

mod creators;
mod deployment;
mod invoices;
mod migrations;
mod outbox;
pub(crate) mod sdk_state;

pub use creators::{CreatorCredentials, CreatorSetupLock, CreatorStore, PersistedCreator};
pub use deployment::{DeploymentStore, PersistenceError};
pub(crate) use invoices::BitcoinObservationInput;
pub use invoices::{
    AtomicInvoiceInput, AtomicInvoiceResult, InvoicePreflight, InvoiceStore,
    NewReaderPayloadFactory, NewReaderPayloads, OBSERVER_LEADERSHIP_LOCK_KEY, PendingCandidate,
    PgObserverLeadership,
};
pub use migrations::{MIGRATION_ADVISORY_LOCK_KEY, MigrationLock, run_migrations};
pub use outbox::{ClaimedHandoff, ClaimedOutbox, HandoffResult, OutboxRetryClass, OutboxStore};
pub use sdk_state::{PostgresStorageAdapter, SdkStateStore};
