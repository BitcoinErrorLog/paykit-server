//! PostgreSQL persistence primitives.

mod creators;
mod deployment;
mod invoices;
mod migrations;
mod outbox;
mod payment_request_lifecycles;
pub(crate) mod sdk_state;

pub use creators::{CreatorCredentials, CreatorSetupLock, CreatorStore, PersistedCreator};
pub use deployment::{DeploymentStore, PersistenceError};
pub(crate) use invoices::BitcoinObservationInput;
pub use invoices::{
    AtomicInvoiceInput, AtomicInvoiceResult, InvoicePreflight, InvoiceStore,
    NewReaderPayloadFactory, NewReaderPayloads,
};
pub use migrations::{MIGRATION_ADVISORY_LOCK_KEY, MigrationLock, run_migrations};
pub use outbox::{ClaimedHandoff, ClaimedOutbox, HandoffResult, OutboxRetryClass, OutboxStore};
pub use payment_request_lifecycles::{PaymentRequestLifecycleApply, PaymentRequestLifecycleStore};
pub use sdk_state::{PostgresStorageAdapter, SdkStateStore};
