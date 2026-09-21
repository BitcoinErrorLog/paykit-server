//! Per-key token-bucket limiter for claim-time HTTP routes (`GET /setup`).
//!
//! One bucket is kept per identity (creator pubky) and another per peer IP.
//! Burst is the starting token count; tokens refill from elapsed wall time
//! at `rate_per_second` up to `burst`. A refused request does not charge.

use std::{collections::HashMap, sync::Mutex, time::Duration};

/// Token-bucket limiter keyed by an opaque identity or IP string.
#[derive(Debug)]
pub struct KeyedRequestLimiter {
    rate_per_second: u64,
    burst: u64,
    inner: Mutex<HashMap<String, TokenBucket>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimLimitExceeded {
    pub retry_after_secs: u64,
}

#[derive(Debug)]
struct TokenBucket {
    rate_per_second: u64,
    burst: u64,
    tokens: u64,
    remainder: u128,
    last: Duration,
}

impl KeyedRequestLimiter {
    pub fn new(rate_per_second: u64, burst: u64) -> Self {
        Self {
            rate_per_second,
            burst,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Seconds a refused caller should wait before retrying one request.
    pub fn retry_after_secs(&self) -> u64 {
        retry_after_secs(self.rate_per_second)
    }

    /// Charges one token for `key` at `now`, or returns the retry-after
    /// without charging when the bucket is empty.
    pub fn permit(&self, key: &str, now: Duration) -> Result<(), ClaimLimitExceeded> {
        let mut buckets = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = buckets
            .entry(key.to_owned())
            .or_insert_with(|| TokenBucket::new(self.rate_per_second, self.burst, now));
        if bucket.try_take(now) {
            Ok(())
        } else {
            Err(ClaimLimitExceeded {
                retry_after_secs: self.retry_after_secs(),
            })
        }
    }
}

impl TokenBucket {
    fn new(rate_per_second: u64, burst: u64, now: Duration) -> Self {
        Self {
            rate_per_second,
            burst,
            tokens: burst,
            remainder: 0,
            last: now,
        }
    }

    fn try_take(&mut self, now: Duration) -> bool {
        let elapsed = now.saturating_sub(self.last);
        self.last = now;
        if self.tokens == self.burst {
            self.remainder = 0;
        } else {
            let accrued = elapsed
                .as_nanos()
                .saturating_mul(u128::from(self.rate_per_second))
                .saturating_add(self.remainder);
            let added = accrued / 1_000_000_000;
            self.remainder = accrued % 1_000_000_000;
            self.tokens = self
                .tokens
                .saturating_add(u64::try_from(added).unwrap_or(u64::MAX))
                .min(self.burst);
            if self.tokens == self.burst {
                self.remainder = 0;
            }
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

fn retry_after_secs(_rate_per_second: u64) -> u64 {
    // Config rejects a zero rate, so one second is always enough to
    // refill at least one token at the minimum admitted rate of 1/s.
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refuses_until_refill() {
        let limiter = KeyedRequestLimiter::new(1, 2);
        let t0 = Duration::from_secs(0);
        limiter.permit("alice", t0).expect("burst 1");
        limiter.permit("alice", t0).expect("burst 2");
        assert_eq!(
            limiter.permit("alice", t0),
            Err(ClaimLimitExceeded {
                retry_after_secs: 1
            })
        );
        limiter
            .permit("alice", Duration::from_secs(1))
            .expect("one token refills after one second at 1/s");
        assert_eq!(
            limiter.permit("alice", Duration::from_secs(1)),
            Err(ClaimLimitExceeded {
                retry_after_secs: 1
            })
        );
    }

    #[test]
    fn keys_are_isolated() {
        let limiter = KeyedRequestLimiter::new(1, 1);
        let t0 = Duration::from_secs(0);
        limiter.permit("alice", t0).expect("alice burst");
        assert_eq!(
            limiter.permit("alice", t0),
            Err(ClaimLimitExceeded {
                retry_after_secs: 1
            })
        );
        limiter
            .permit("bob", t0)
            .expect("bob has a separate bucket");
    }

    #[test]
    fn refill_does_not_exceed_burst() {
        let limiter = KeyedRequestLimiter::new(10, 2);
        let t0 = Duration::from_secs(0);
        limiter.permit("k", t0).unwrap();
        limiter.permit("k", t0).unwrap();
        limiter
            .permit("k", Duration::from_secs(60))
            .expect("long idle refills to burst, not unbounded");
        limiter.permit("k", Duration::from_secs(60)).unwrap();
        assert_eq!(
            limiter.permit("k", Duration::from_secs(60)),
            Err(ClaimLimitExceeded {
                retry_after_secs: 1
            })
        );
    }
}
