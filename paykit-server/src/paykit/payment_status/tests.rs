use std::{
    future::poll_fn,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
};
use tokio::sync::Semaphore;

use super::*;
use crate::domain::locks::parse_bundle_id;

struct HeldReceive {
    calls: AtomicUsize,
    active: AtomicUsize,
    permits: Semaphore,
}

struct Active<'a>(&'a AtomicUsize);

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl HeldReceive {
    fn new() -> Self {
        Self {
            calls: 0.into(),
            active: 0.into(),
            permits: Semaphore::new(0),
        }
    }

    async fn run(&self, error: Option<PaymentRequestStatusError>) -> ReceiveResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = Active(&self.active);
        self.permits.acquire().await.unwrap().forget();
        error.map_or_else(|| Ok((Vec::new(), ReceiveHealth::Available)), Err)
    }
}

async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn matching_receives_share_success_and_failure_but_not_completed_evidence() {
    let app = PaykitAppId::new("paykit-server").unwrap();
    let bundle = parse_bundle_id("000G40R40M30E209185GR38E1W").unwrap();
    for error in [
        None,
        Some(PaymentRequestStatusError::Unavailable),
        Some(PaymentRequestStatusError::Conflict),
    ] {
        let refreshes = PaymentRequestRefreshes::default();
        let work = HeldReceive::new();
        let mut first = Box::pin(refreshes.receive(&app, &bundle, work.run(error)));
        let mut waiter = Box::pin(refreshes.receive(&app, &bundle, work.run(error)));
        assert_pending(first.as_mut()).await;
        assert_pending(waiter.as_mut()).await;
        assert_eq!(work.calls.load(Ordering::SeqCst), 1);
        work.permits.add_permits(1);
        assert_eq!(first.as_mut().await.err(), error);
        assert_eq!(waiter.await.err(), error);
        // Keeping a completed caller alive must not cache receive evidence.
        let mut next = Box::pin(refreshes.receive(
            &app,
            &bundle,
            work.run(Some(PaymentRequestStatusError::Unavailable)),
        ));
        assert_pending(next.as_mut()).await;
        assert_eq!(work.calls.load(Ordering::SeqCst), 2);
        work.permits.add_permits(1);
        assert_eq!(next.await, Err(PaymentRequestStatusError::Unavailable));
    }
}

#[tokio::test]
async fn different_bundles_apps_and_creator_providers_do_not_share_receive() {
    let refreshes = PaymentRequestRefreshes::default();
    let other_creator = PaymentRequestRefreshes::default();
    let work = HeldReceive::new();
    let app = PaykitAppId::new("paykit-server").unwrap();
    let other_app = PaykitAppId::new("other-app").unwrap();
    let bundle = parse_bundle_id("000G40R40M30E209185GR38E1W").unwrap();
    let other_bundle = parse_bundle_id("000G40R40M30E209185GR38E2W").unwrap();
    let mut calls = vec![
        Box::pin(refreshes.receive(&app, &bundle, work.run(None))),
        Box::pin(refreshes.receive(&app, &other_bundle, work.run(None))),
        Box::pin(refreshes.receive(&other_app, &bundle, work.run(None))),
        Box::pin(other_creator.receive(&app, &bundle, work.run(None))),
    ];
    for call in &mut calls {
        assert_pending(call.as_mut()).await;
    }
    assert_eq!(work.calls.load(Ordering::SeqCst), 4);
    work.permits.add_permits(4);
    for call in calls {
        assert!(call.await.is_ok());
    }
}

#[tokio::test]
async fn cancellation_retries_only_a_dropped_initializer_without_overlapping_work() {
    let app = PaykitAppId::new("paykit-server").unwrap();
    let bundle = parse_bundle_id("000G40R40M30E209185GR38E1W").unwrap();
    for cancel_initializer in [false, true] {
        let refreshes = PaymentRequestRefreshes::default();
        let work = HeldReceive::new();
        let mut first = Box::pin(refreshes.receive(&app, &bundle, work.run(None)));
        let mut waiter = Box::pin(refreshes.receive(&app, &bundle, work.run(None)));
        assert_pending(first.as_mut()).await;
        assert_pending(waiter.as_mut()).await;
        let mut remaining = if cancel_initializer {
            drop(first);
            assert_eq!(work.active.load(Ordering::SeqCst), 0);
            waiter
        } else {
            drop(waiter);
            first
        };
        assert_pending(remaining.as_mut()).await;
        assert_eq!(work.active.load(Ordering::SeqCst), 1);
        assert_eq!(
            work.calls.load(Ordering::SeqCst),
            if cancel_initializer { 2 } else { 1 }
        );
        work.permits.add_permits(1);
        assert!(remaining.await.is_ok());
        assert_eq!(work.active.load(Ordering::SeqCst), 0);
    }
}
