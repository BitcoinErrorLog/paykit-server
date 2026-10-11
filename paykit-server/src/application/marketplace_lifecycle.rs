//! Signed Marketplace activation and void lifecycle commands.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    domain::locks::CreatorPubky,
    persistence::{
        MarketplaceActivationInput, MarketplaceActivationResult,
        MarketplaceLifecyclePersistenceError, MarketplacePreparationStore,
        MarketplaceResolutionOutcome, MarketplaceResolutionResult, MarketplaceVoidResult,
        PersistenceError,
    },
};

pub struct ActivateMarketplaceRequest {
    pub creator: CreatorPubky,
    pub invoice_id: Uuid,
    pub total_sats: u64,
}

pub struct VoidMarketplaceRequest {
    pub creator: CreatorPubky,
    pub invoice_id: Uuid,
}

pub struct ResolveMarketplaceRequest {
    pub creator: CreatorPubky,
    pub invoice_id: Uuid,
    pub outcome: MarketplaceResolutionOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarketplaceLifecycleError {
    InvalidRequest,
    PrepareExpired,
    LifecycleTerminal,
    InvoiceActive,
    TotalMismatch,
    ResolutionConflict,
    NotFound,
    Unavailable,
    Internal,
}

#[async_trait]
pub trait MarketplaceLifecyclePersistence: Send + Sync {
    async fn activate(
        &self,
        input: MarketplaceActivationInput<'_>,
    ) -> Result<Option<MarketplaceActivationResult>, MarketplaceLifecyclePersistenceError>;

    async fn void(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<MarketplaceVoidResult>, MarketplaceLifecyclePersistenceError>;

    async fn resolve(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
        outcome: MarketplaceResolutionOutcome,
    ) -> Result<Option<MarketplaceResolutionResult>, MarketplaceLifecyclePersistenceError>;
}

#[async_trait]
impl MarketplaceLifecyclePersistence for MarketplacePreparationStore {
    async fn activate(
        &self,
        input: MarketplaceActivationInput<'_>,
    ) -> Result<Option<MarketplaceActivationResult>, MarketplaceLifecyclePersistenceError> {
        MarketplacePreparationStore::activate(self, input).await
    }

    async fn void(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<MarketplaceVoidResult>, MarketplaceLifecyclePersistenceError> {
        MarketplacePreparationStore::void(self, creator, invoice_id).await
    }

    async fn resolve(
        &self,
        creator: &CreatorPubky,
        invoice_id: Uuid,
        outcome: MarketplaceResolutionOutcome,
    ) -> Result<Option<MarketplaceResolutionResult>, MarketplaceLifecyclePersistenceError> {
        MarketplacePreparationStore::resolve(self, creator, invoice_id, outcome).await
    }
}

pub struct MarketplaceLifecycleService {
    store: Arc<dyn MarketplaceLifecyclePersistence>,
    proposal_acceptance_window: Duration,
}

impl MarketplaceLifecycleService {
    pub fn new(
        store: Arc<dyn MarketplaceLifecyclePersistence>,
        proposal_acceptance_window: Duration,
    ) -> Self {
        Self {
            store,
            proposal_acceptance_window,
        }
    }

    pub async fn activate(
        &self,
        request: ActivateMarketplaceRequest,
    ) -> Result<MarketplaceActivationResult, MarketplaceLifecycleError> {
        if request.total_sats == 0 || self.proposal_acceptance_window.is_zero() {
            return Err(MarketplaceLifecycleError::InvalidRequest);
        }
        self.store
            .activate(MarketplaceActivationInput {
                creator: &request.creator,
                invoice_id: request.invoice_id,
                total_sats: request.total_sats,
                proposal_acceptance_window: self.proposal_acceptance_window,
            })
            .await
            .map_err(map_store)?
            .ok_or(MarketplaceLifecycleError::NotFound)
    }

    pub async fn void(
        &self,
        request: VoidMarketplaceRequest,
    ) -> Result<MarketplaceVoidResult, MarketplaceLifecycleError> {
        self.store
            .void(&request.creator, request.invoice_id)
            .await
            .map_err(map_store)?
            .ok_or(MarketplaceLifecycleError::NotFound)
    }

    pub async fn resolve(
        &self,
        request: ResolveMarketplaceRequest,
    ) -> Result<MarketplaceResolutionResult, MarketplaceLifecycleError> {
        self.store
            .resolve(&request.creator, request.invoice_id, request.outcome)
            .await
            .map_err(map_store)?
            .ok_or(MarketplaceLifecycleError::NotFound)
    }
}

fn map_store(error: MarketplaceLifecyclePersistenceError) -> MarketplaceLifecycleError {
    match error {
        MarketplaceLifecyclePersistenceError::PrepareExpired => {
            MarketplaceLifecycleError::PrepareExpired
        }
        MarketplaceLifecyclePersistenceError::LifecycleTerminal => {
            MarketplaceLifecycleError::LifecycleTerminal
        }
        MarketplaceLifecyclePersistenceError::InvoiceActive => {
            MarketplaceLifecycleError::InvoiceActive
        }
        MarketplaceLifecyclePersistenceError::TotalMismatch => {
            MarketplaceLifecycleError::TotalMismatch
        }
        MarketplaceLifecyclePersistenceError::ResolutionConflict => {
            MarketplaceLifecycleError::ResolutionConflict
        }
        MarketplaceLifecyclePersistenceError::Persistence(PersistenceError::InvalidInput) => {
            MarketplaceLifecycleError::InvalidRequest
        }
        MarketplaceLifecyclePersistenceError::Persistence(PersistenceError::Unavailable) => {
            MarketplaceLifecycleError::Unavailable
        }
        MarketplaceLifecyclePersistenceError::Persistence(
            PersistenceError::DeploymentMismatch
            | PersistenceError::CorruptOrMissing
            | PersistenceError::ReauthenticationMismatch
            | PersistenceError::Conflict,
        ) => MarketplaceLifecycleError::Internal,
    }
}
