//! PostgreSQL persistence primitives.

mod creators;
mod deployment;
mod invoices;
mod marketplace_preparations;
mod migrations;
mod outbox;
mod payment_drains;
mod payment_request_lifecycles;

pub use creators::{CreatorCredentials, CreatorSetupLock, CreatorStore, PersistedCreator};
pub use deployment::{DeploymentStore, PersistenceError};
pub(crate) use invoices::BitcoinObservationInput;
pub use invoices::{
    AtomicInvoiceInput, AtomicInvoiceResult, InvoicePayloadFactory, InvoicePayloads,
    InvoicePreflight, InvoiceStore, PendingBuyerContact,
};
pub use marketplace_preparations::{
    MarketplaceActivationInput, MarketplaceActivationResult, MarketplaceLifecyclePersistenceError,
    MarketplacePreparationInput, MarketplacePreparationPayloadFactory,
    MarketplacePreparationPayloads, MarketplacePreparationPreflight, MarketplacePreparationResult,
    MarketplacePreparationStore, MarketplaceResolutionOutcome, MarketplaceResolutionResult,
    MarketplaceVoidResult,
};
pub use migrations::{MIGRATION_ADVISORY_LOCK_KEY, MigrationLock, run_migrations};
pub use outbox::{ClaimedHandoff, ClaimedOutbox, HandoffResult, OutboxRetryClass, OutboxStore};
pub use payment_drains::{PaymentDrainSnapshot, PaymentDrainStore};
pub use payment_request_lifecycles::{
    PaymentRequestLifecycleApply, PaymentRequestLifecycleStore, RequiredReceiveTarget,
};
