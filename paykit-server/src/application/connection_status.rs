//! Read-only Paykit Noise connection state bound to a persisted invoice.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::OnceCell;

use crate::{
    domain::locks::{BundleId, CreatorPubky, ReaderPubky},
    persistence::{InvoiceStore, PersistenceError},
};

/// Exact reader identity binding accepted when the invoice was created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionBinding {
    reader: ReaderPubky,
}

impl ConnectionBinding {
    pub fn new(reader: ReaderPubky) -> Self {
        Self { reader }
    }

    pub fn reader(&self) -> &ReaderPubky {
        &self.reader
    }
}

/// Closed projection of the Creator's shared peer state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaykitConnectionState {
    None,
    Handshake,
    Connected,
    RecoveryRequired,
    Blocked,
}

#[async_trait]
pub trait ConnectionBindingRepository: Send + Sync {
    async fn binding(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<ConnectionBinding>, PersistenceError>;
}

#[async_trait]
pub trait PeerConnectionStateRepository: Send + Sync {
    async fn connection_state(
        &self,
        creator: &CreatorPubky,
        binding: &ConnectionBinding,
    ) -> Result<PaykitConnectionState, ConnectionStatusError>;
}

#[async_trait]
impl ConnectionBindingRepository for InvoiceStore {
    async fn binding(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<Option<ConnectionBinding>, PersistenceError> {
        self.connection_binding(creator, bundle_id).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionStatusError {
    NotFound,
    Busy,
    Unavailable,
}

type PendingPeerState = OnceCell<Result<PaykitConnectionState, ConnectionStatusError>>;

/// Resolves caller-supplied public identity only to persisted server-owned binding data.
/// Overlapping reads of the same Creator/Reader share an advisory observation;
/// completed results are not reused. Never use this display state to authorize payments.
pub struct ConnectionStatusService {
    bindings: Arc<dyn ConnectionBindingRepository>,
    peers: Arc<dyn PeerConnectionStateRepository>,
    pending: Mutex<HashMap<(String, String), Weak<PendingPeerState>>>,
}

impl ConnectionStatusService {
    pub fn new(
        bindings: Arc<dyn ConnectionBindingRepository>,
        peers: Arc<dyn PeerConnectionStateRepository>,
    ) -> Self {
        Self {
            bindings,
            peers,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub async fn status(
        &self,
        creator: &CreatorPubky,
        bundle_id: &BundleId,
    ) -> Result<PaykitConnectionState, ConnectionStatusError> {
        let binding = self
            .bindings
            .binding(creator, bundle_id)
            .await
            .map_err(|error| {
                crate::diagnostics::failure(
                    "connection_status",
                    "invoice_binding_load",
                    error.diagnostic_label(),
                );
                ConnectionStatusError::Unavailable
            })?
            .ok_or(ConnectionStatusError::NotFound)?;
        let pending = self.pending_peer_state(creator, &binding);
        pending
            .get_or_init(|| self.peers.connection_state(creator, &binding))
            .await
            .inspect_err(|error| {
                crate::diagnostics::failure(
                    "connection_status",
                    "peer_state_load",
                    match error {
                        ConnectionStatusError::NotFound => "not_found",
                        ConnectionStatusError::Busy => "shared_state_busy",
                        ConnectionStatusError::Unavailable => "unavailable",
                    },
                );
            })
    }

    fn pending_peer_state(
        &self,
        creator: &CreatorPubky,
        binding: &ConnectionBinding,
    ) -> Arc<PendingPeerState> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Weak entries retain neither completed results nor canceled requests.
        // OnceCell lets another waiter retry initialization if its owner is canceled.
        pending.retain(|_, read| read.upgrade().is_some_and(|read| read.get().is_none()));
        let key = (creator.to_string(), binding.reader().to_string());
        if let Some(read) = pending.get(&key).and_then(Weak::upgrade) {
            return read;
        }
        let read = Arc::new(OnceCell::new());
        pending.insert(key, Arc::downgrade(&read));
        read
    }
}
