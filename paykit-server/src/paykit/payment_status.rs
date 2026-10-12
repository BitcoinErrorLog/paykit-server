use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, Weak},
};

use tokio::sync::OnceCell;

use super::*;

type ReceiveResult = Result<(Vec<RequiredReceiveTarget>, ReceiveHealth), PaymentRequestStatusError>;
type PendingReceive = OnceCell<ReceiveResult>;

/// Shared by adapters using the same Creator session provider. Only receive
/// evidence is shared; every caller still reads current transactional status.
#[derive(Default)]
pub(super) struct PaymentRequestRefreshes {
    pending: Mutex<HashMap<(String, String), Weak<PendingReceive>>>,
}

impl PaymentRequestRefreshes {
    pub(super) async fn receive(
        &self,
        app: &PaykitAppId,
        bundle: &BundleId,
        refresh: impl Future<Output = ReceiveResult>,
    ) -> ReceiveResult {
        let pending = self.pending_receive(app, bundle);
        pending.get_or_init(|| refresh).await.clone()
    }

    fn pending_receive(&self, app: &PaykitAppId, bundle: &BundleId) -> Arc<PendingReceive> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Weak entries retain neither completed results nor canceled requests.
        // OnceCell lets another waiter retry a canceled initializer.
        pending.retain(|_, read| read.upgrade().is_some_and(|read| read.get().is_none()));
        let key = (app.to_string(), bundle.to_string());
        if let Some(read) = pending.get(&key).and_then(Weak::upgrade) {
            return read;
        }
        let read = Arc::new(OnceCell::new());
        pending.insert(key, Arc::downgrade(&read));
        read
    }
}

impl std::fmt::Debug for PaymentRequestRefreshes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PaymentRequestRefreshes { .. }")
    }
}

#[cfg(test)]
mod tests;
