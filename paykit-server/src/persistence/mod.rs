//! PostgreSQL persistence primitives.

mod creators;
mod deployment;
mod invoices;
mod migrations;
mod outbox;

pub use creators::{CreatorCredentials, CreatorSetupLock, CreatorStore, PersistedCreator};
pub use deployment::{DeploymentStore, PersistenceError};
pub(crate) use invoices::BitcoinObservationInput;
pub use invoices::{
    AtomicInvoiceInput, AtomicInvoiceResult, InvoicePayloadFactory, InvoicePayloads,
    InvoicePreflight, InvoiceStore,
};
pub use migrations::{MIGRATION_ADVISORY_LOCK_KEY, MigrationLock, run_migrations};
pub use outbox::{ClaimedHandoff, ClaimedOutbox, HandoffResult, OutboxRetryClass, OutboxStore};
