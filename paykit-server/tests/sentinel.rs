//! W1.14 unassigned-sentinel domain tests: the single downgrade predicate,
//! the resolved default constants, and the sentinel's own token-budget
//! arithmetic. Real-Postgres seams (atomic downgrade, lock ordering,
//! supersession, idempotence) live in paykit-server-e2e/tests/sentinel.rs.

use std::{sync::Arc, time::Duration};

use paykit_server::sentinel::{
    DEFAULT_HIT_COUNT, DEFAULT_MAX_AGE, DEFAULT_MAX_REQUESTS_PER_SECOND,
    DEFAULT_MAX_REQUESTS_PER_TICK, DEFAULT_MIN_VALUE_SATS, DEFAULT_RESCAN_INTERVAL,
    SENTINEL_SCAN_WINDOW, SentinelPolicy, SentinelThresholds, downgrade_predicate,
};
use paykit_server::workers::observer::RequestLimiter;

fn thresholds() -> SentinelThresholds {
    SentinelThresholds {
        min_value_sats: 294,
        hit_count: 1,
    }
}

#[test]
fn the_default_constants_are_the_design_resolved_values() {
    // P2WPKH relay-standard dust: 98 vbytes x 3 sat/vbyte (the server derives
    // BIP84 P2WPKH accounts only).
    assert_eq!(DEFAULT_MIN_VALUE_SATS, 294);
    assert_eq!(DEFAULT_HIT_COUNT, 1);
    assert_eq!(DEFAULT_RESCAN_INTERVAL, Duration::from_secs(10 * 60));
    assert_eq!(DEFAULT_MAX_AGE, Duration::from_secs(60 * 60));
    assert_eq!(DEFAULT_MAX_REQUESTS_PER_TICK, 1000);
    assert_eq!(DEFAULT_MAX_REQUESTS_PER_SECOND, 5);
    assert_eq!(SENTINEL_SCAN_WINDOW, 20);
    let policy = SentinelPolicy::default();
    assert_eq!(policy.thresholds.min_value_sats, 294);
    assert_eq!(policy.thresholds.hit_count, 1);
    assert_eq!(policy.rescan_interval, Duration::from_secs(10 * 60));
    assert_eq!(policy.max_age, Duration::from_secs(60 * 60));
    assert_eq!(policy.max_requests_per_tick, 1000);
    assert_eq!(policy.max_requests_per_second, 5);
    assert_eq!(policy.scan_window, 20);
}

#[test]
fn the_predicate_requires_confirmation_value_and_hits_together() {
    let thresholds = thresholds();
    // The qualifying case: confirmed, at the dust minimum, first hit.
    assert!(downgrade_predicate(true, 294, 1, &thresholds));
    assert!(downgrade_predicate(true, 295, 1, &thresholds));
    assert!(downgrade_predicate(true, 100_000, 3, &thresholds));
    // Below the value minimum: never, however many hits.
    assert!(!downgrade_predicate(true, 293, 1, &thresholds));
    assert!(!downgrade_predicate(true, 293, 9, &thresholds));
    assert!(!downgrade_predicate(true, 0, 1, &thresholds));
    // Mempool-only (unconfirmed): a candidate, never evidence.
    assert!(!downgrade_predicate(false, 294, 1, &thresholds));
    assert!(!downgrade_predicate(false, 1_000_000, 5, &thresholds));
    // Below the distinct-hit count.
    assert!(!downgrade_predicate(true, 294, 0, &thresholds));
    let two_hit = SentinelThresholds {
        min_value_sats: 294,
        hit_count: 2,
    };
    assert!(!downgrade_predicate(true, 294, 1, &two_hit));
    assert!(downgrade_predicate(true, 294, 2, &two_hit));
}

#[test]
fn the_sentinel_sub_budget_is_subordinate_to_the_one_shared_endpoint_quota() {
    // One shared global bucket (the electrum.* quota). The sentinel's
    // sub-budget only ACCOUNTS its configured caps; every sentinel request
    // is charged against the shared bucket's leftover balance, so live +
    // sentinel + non-tick callers can never jointly exceed the quota.
    let policy = SentinelPolicy::default();
    let sub_budget = RequestLimiter::new(
        u64::from(policy.max_requests_per_tick),
        u64::from(policy.max_requests_per_second),
    );
    let shared = RequestLimiter::new(1000, 5);

    // The live tick charges the shared bucket first: probe (2) + lookups.
    let probe = shared.try_reserve(2).expect("probe reservation");
    assert_eq!(probe.granted(), 2);
    let live = shared.reserve_up_to(20);
    assert_eq!(live.granted(), 20);

    // The subordinate allowance: 10% of the shared bucket's REMAINING
    // balance after live admission, accounted in the sub-budget...
    let allowance = shared.available() / 10;
    assert_eq!(allowance, 97, "(1000 - 22) / 10");
    let sub_grant = sub_budget.reserve_up_to(allowance).granted();
    assert_eq!(sub_grant, 97);
    // ...then charged against the shared bucket itself.
    let sentinel = shared.reserve_up_to(sub_grant);
    assert_eq!(sentinel.granted(), 97);
    // Aggregate this tick: 2 + 20 + 97 = 119 <= 1000, and 881 tokens (the
    // ~90% the sentinel must leave) remain for non-tick callers.
    assert_eq!(shared.available(), 1000 - 2 - 20 - 97);

    // When live consumption drains the shared bucket, the sentinel
    // allowance is ZERO — sentinel work can never be why a live target or
    // the next tick's probe defers.
    let drained = shared.reserve_up_to(u64::MAX);
    assert_eq!(drained.granted(), 881);
    assert_eq!(shared.available() / 10, 0);
    assert_eq!(shared.reserve_up_to(u64::MAX).granted(), 0);

    // The sustained aggregate rate is the shared bucket's 5/second: after
    // a 40 s rewind exactly 200 tokens refill, bounded by the 1,000 cap —
    // no second per-second quota exists for the sentinel to add to.
    shared.rewind_refill_clock(Duration::from_secs(40));
    assert_eq!(shared.available(), 200);
}

#[test]
fn concurrent_live_and_sentinel_callers_never_exceed_the_shared_quota() {
    // Simultaneous load: live-tick admission, a sentinel allowance charge
    // and non-tick callers race one shared bucket of capacity 100 with no
    // refill. The joint grant is exactly the capacity, never more, no
    // matter the interleaving.
    use std::sync::atomic::{AtomicU64, Ordering};

    let shared = RequestLimiter::new(100, 0);
    let granted = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    // A live tick: probe reservation + one reserve_up_to batch.
    {
        let shared = shared.clone();
        let granted = granted.clone();
        handles.push(std::thread::spawn(move || {
            let probe = shared.try_reserve(2).expect("probe reservation");
            let batch = shared.reserve_up_to(50);
            granted.fetch_add(probe.granted() + batch.granted(), Ordering::Relaxed);
        }));
    }
    // A sentinel phase: 10% of leftover, charged against the shared bucket.
    {
        let shared = shared.clone();
        let granted = granted.clone();
        handles.push(std::thread::spawn(move || {
            let allowance = shared.available() / 10;
            let charge = shared.reserve_up_to(allowance);
            granted.fetch_add(charge.granted(), Ordering::Relaxed);
        }));
    }
    // Non-tick callers racing single reservations.
    for _ in 0..32 {
        let shared = shared.clone();
        let granted = granted.clone();
        handles.push(std::thread::spawn(move || {
            if let Ok(permit) = shared.try_reserve(1) {
                granted.fetch_add(permit.granted(), Ordering::Relaxed);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("caller thread panicked");
    }
    let total = granted.load(Ordering::Relaxed);
    assert!(
        total <= 100,
        "the joint live+sentinel+non-tick grant never exceeds the shared capacity: {total}"
    );
    assert_eq!(
        total + shared.available(),
        100,
        "every granted token came out of the one shared bucket"
    );
}

#[test]
fn the_per_tick_creator_limit_derives_from_the_budget_and_window() {
    let policy = SentinelPolicy::default();
    assert_eq!(
        policy.per_tick_creator_limit(),
        50,
        "1000 / 20-address window"
    );
    let tight = SentinelPolicy {
        max_requests_per_tick: 25,
        ..SentinelPolicy::default()
    };
    assert_eq!(tight.per_tick_creator_limit(), 1);
}
