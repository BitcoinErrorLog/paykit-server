//! Request-scoped, identifier-free failure diagnostics.

use std::{cell::Cell, future::Future};

use uuid::Uuid;

struct RequestContext {
    request_id: Uuid,
    operation: &'static str,
    failure_emitted: Cell<bool>,
}

tokio::task_local! {
    static REQUEST_CONTEXT: RequestContext;
}

pub(crate) async fn scope<T>(
    request_id: Uuid,
    operation: &'static str,
    future: impl Future<Output = T>,
) -> (T, bool) {
    REQUEST_CONTEXT
        .scope(
            RequestContext {
                request_id,
                operation,
                failure_emitted: Cell::new(false),
            },
            async {
                let output = future.await;
                let failure_emitted = REQUEST_CONTEXT.with(|context| context.failure_emitted.get());
                (output, failure_emitted)
            },
        )
        .await
}

/// Emits at most one failure event for one request. Call at the narrowest point
/// where a bounded, secret-free cause is known; outer mappings may call again as
/// a fallback without producing duplicate warnings.
pub(crate) fn failure(_operation: &'static str, stage: &'static str, category: &'static str) {
    let _ = REQUEST_CONTEXT.try_with(|context| {
        if context.failure_emitted.replace(true) {
            return;
        }
        tracing::warn!(
            event = "paykit_request_failure",
            operation = context.operation,
            stage,
            category,
            request_id = %context.request_id.hyphenated(),
            "Paykit request failed"
        );
    });
}
