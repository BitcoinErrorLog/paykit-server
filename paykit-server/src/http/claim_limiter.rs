//! Per-key token-bucket limiter for claim-time HTTP routes (`GET /setup`).
//!
//! One bucket is kept per identity (creator pubky) and another per client IP
//! prefix. Burst is the starting token count; tokens refill from elapsed wall
//! time at `rate_per_second` up to `burst`. A refused request does not charge.
//!
//! The store is bounded: at most `max_entries` live buckets, with LRU eviction
//! under churn and a TTL sweep of idle buckets. Entry count is logged on every
//! mutation.
//!
//! Client IP for the IP bucket is resolved by [`client_ip`]: hops `0` uses the
//! TCP peer; hops `≥1` takes the Nth `X-Forwarded-For` hop from the right
//! (never a spoofable leading hop unless it is also the last remaining hop),
//! then `X-Real-IP`, then the peer.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::Duration,
};

/// Token-bucket limiter keyed by an opaque identity or IP-prefix string.
#[derive(Debug)]
pub struct KeyedRequestLimiter {
    rate_per_second: u64,
    burst: u64,
    max_entries: usize,
    idle_ttl: Duration,
    inner: Mutex<LruStore>,
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

#[derive(Debug)]
struct Node {
    key: String,
    bucket: TokenBucket,
    last_touch: Duration,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Doubly-linked LRU: `head` is most recently used, `tail` is least.
#[derive(Debug, Default)]
struct LruStore {
    nodes: Vec<Node>,
    index: HashMap<String, usize>,
    head: Option<usize>,
    tail: Option<usize>,
    free: Vec<usize>,
}

impl KeyedRequestLimiter {
    pub fn new(rate_per_second: u64, burst: u64, max_entries: usize, idle_ttl: Duration) -> Self {
        Self {
            rate_per_second,
            burst,
            max_entries: max_entries.max(1),
            idle_ttl,
            inner: Mutex::new(LruStore::default()),
        }
    }

    /// Seconds a refused caller should wait before retrying one request.
    pub fn retry_after_secs(&self) -> u64 {
        retry_after_secs(self.rate_per_second)
    }

    /// Live bucket count. Tests use this as the memory bound.
    pub fn len(&self) -> usize {
        self.lock_store().index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock_store().index.is_empty()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.lock_store().index.contains_key(key)
    }

    /// Charges one token for `key` at `now`, or returns the retry-after
    /// without charging when the bucket is empty.
    pub fn permit(&self, key: &str, now: Duration) -> Result<(), ClaimLimitExceeded> {
        let mut store = self.lock_store();
        let idle_evicted = store.sweep_idle(now, self.idle_ttl);
        if idle_evicted > 0 {
            tracing::info!(
                target: "paykit.claim_limiter",
                entries = store.index.len(),
                max_entries = self.max_entries,
                evicted = idle_evicted,
                reason = "idle",
                "claim limiter idle sweep"
            );
        }

        let idx = if let Some(&idx) = store.index.get(key) {
            store.unlink(idx);
            store.push_head(idx);
            store.nodes[idx].last_touch = now;
            idx
        } else {
            let mut capacity_evicted = 0usize;
            while store.index.len() >= self.max_entries {
                if !store.evict_lru() {
                    break;
                }
                capacity_evicted += 1;
            }
            if capacity_evicted > 0 {
                tracing::info!(
                    target: "paykit.claim_limiter",
                    entries = store.index.len(),
                    max_entries = self.max_entries,
                    evicted = capacity_evicted,
                    reason = "capacity",
                    "claim limiter LRU eviction"
                );
            }
            let bucket = TokenBucket::new(self.rate_per_second, self.burst, now);
            let idx = store.alloc(key.to_owned(), bucket, now);
            store.index.insert(key.to_owned(), idx);
            store.push_head(idx);
            idx
        };

        tracing::debug!(
            target: "paykit.claim_limiter",
            entries = store.index.len(),
            max_entries = self.max_entries,
            "claim limiter store size"
        );

        if store.nodes[idx].bucket.try_take(now) {
            Ok(())
        } else {
            Err(ClaimLimitExceeded {
                retry_after_secs: self.retry_after_secs(),
            })
        }
    }

    fn lock_store(&self) -> std::sync::MutexGuard<'_, LruStore> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl LruStore {
    fn sweep_idle(&mut self, now: Duration, idle_ttl: Duration) -> usize {
        if idle_ttl.is_zero() {
            return 0;
        }
        let mut evicted = 0usize;
        while let Some(idx) = self.tail {
            if now.saturating_sub(self.nodes[idx].last_touch) < idle_ttl {
                break;
            }
            if !self.evict_lru() {
                break;
            }
            evicted += 1;
        }
        evicted
    }

    fn evict_lru(&mut self) -> bool {
        let Some(idx) = self.tail else {
            return false;
        };
        let key = self.nodes[idx].key.clone();
        self.unlink(idx);
        self.index.remove(&key);
        self.free.push(idx);
        true
    }

    fn unlink(&mut self, idx: usize) {
        let prev = self.nodes[idx].prev;
        let next = self.nodes[idx].next;
        match prev {
            Some(p) => self.nodes[p].next = next,
            None => self.head = next,
        }
        match next {
            Some(n) => self.nodes[n].prev = prev,
            None => self.tail = prev,
        }
        self.nodes[idx].prev = None;
        self.nodes[idx].next = None;
    }

    fn push_head(&mut self, idx: usize) {
        self.nodes[idx].prev = None;
        self.nodes[idx].next = self.head;
        if let Some(head) = self.head {
            self.nodes[head].prev = Some(idx);
        } else {
            self.tail = Some(idx);
        }
        self.head = Some(idx);
    }

    fn alloc(&mut self, key: String, bucket: TokenBucket, now: Duration) -> usize {
        let node = Node {
            key,
            bucket,
            last_touch: now,
            prev: None,
            next: None,
        };
        if let Some(idx) = self.free.pop() {
            self.nodes[idx] = node;
            idx
        } else {
            let idx = self.nodes.len();
            self.nodes.push(node);
            idx
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

/// Resolve the client IP used to key claim-IP and per-IP setup windows.
///
/// * `trusted_proxy_hops == 0` ignores forwarding headers and returns `peer`
///   (local/dev).
/// * `trusted_proxy_hops >= 1` takes the Nth `X-Forwarded-For` hop from the
///   right — the hop a trusted proxy appended — so spoofed leading entries
///   are ignored. A missing or unparseable XFF hop falls back to `X-Real-IP`
///   (Railway overwrites this header) and then to `peer`.
pub fn client_ip(
    peer: IpAddr,
    trusted_proxy_hops: u32,
    x_forwarded_for: Option<&str>,
    x_real_ip: Option<&str>,
) -> IpAddr {
    if trusted_proxy_hops == 0 {
        return canonicalize_ip(peer);
    }
    if let Some(xff) = x_forwarded_for {
        let hops: Vec<&str> = xff
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect();
        if hops.len() >= trusted_proxy_hops as usize {
            let idx = hops.len() - trusted_proxy_hops as usize;
            if let Some(ip) = parse_forwarded_hop(hops[idx]) {
                return ip;
            }
        }
    }
    if let Some(real) = x_real_ip.and_then(parse_forwarded_hop) {
        return real;
    }
    canonicalize_ip(peer)
}

fn parse_forwarded_hop(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim().trim_matches('"').trim_matches('\'');
    let raw = raw
        .strip_prefix("for=")
        .or_else(|| raw.strip_prefix("For="))
        .unwrap_or(raw)
        .trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("unknown") {
        return None;
    }
    let unbracketed = raw
        .strip_prefix('[')
        .and_then(|rest| rest.split(']').next())
        .unwrap_or(raw);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Some(canonicalize_ip(ip));
    }
    if let Some((host, port)) = unbracketed.rsplit_once(':')
        && !host.contains(':')
        && port.bytes().all(|b| b.is_ascii_digit())
        && let Ok(ip) = host.parse::<IpAddr>()
    {
        return Some(canonicalize_ip(ip));
    }
    None
}

/// Claim-IP bucket key: IPv4 uses `ipv4_prefix` (default /32), IPv6 uses
/// `ipv6_prefix` (default /64). IPv4-mapped IPv6 is treated as IPv4.
pub fn ip_prefix_key(ip: IpAddr, ipv4_prefix: u8, ipv6_prefix: u8) -> String {
    match canonicalize_ip(ip) {
        IpAddr::V4(v4) => {
            let prefix = ipv4_prefix.min(32);
            format!("{}/{}", mask_ipv4(v4, prefix), prefix)
        }
        IpAddr::V6(v6) => {
            let prefix = ipv6_prefix.min(128);
            format!("{}/{}", mask_ipv6(v6, prefix), prefix)
        }
    }
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        other => other,
    }
}

fn mask_ipv4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let bits = u32::from(prefix.min(32));
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn mask_ipv6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let bits = usize::from(prefix.min(128));
    let oct = ip.octets();
    let mut out = [0u8; 16];
    let full_bytes = bits / 8;
    let rem = bits % 8;
    out[..full_bytes].copy_from_slice(&oct[..full_bytes]);
    if rem > 0 && full_bytes < 16 {
        out[full_bytes] = oct[full_bytes] & (0xFFu8 << (8 - rem));
    }
    Ipv6Addr::from(out)
}

fn retry_after_secs(_rate_per_second: u64) -> u64 {
    // Config rejects a zero rate, so one second is always enough to
    // refill at least one token at the minimum admitted rate of 1/s.
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(rate: u64, burst: u64) -> KeyedRequestLimiter {
        KeyedRequestLimiter::new(rate, burst, 1_024, Duration::from_secs(60))
    }

    #[test]
    fn burst_then_refuses_until_refill() {
        let limiter = limiter(1, 2);
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
        let limiter = limiter(1, 1);
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
        let limiter = limiter(10, 2);
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

    #[test]
    fn eviction_under_churn_keeps_memory_bounded() {
        let limiter = KeyedRequestLimiter::new(1, 1, 16, Duration::from_secs(60));
        let t0 = Duration::from_secs(0);
        for i in 0..16 {
            limiter
                .permit(&format!("k{i}"), t0)
                .expect("initial fill fits");
        }
        assert_eq!(limiter.len(), 16);
        limiter.permit("k0", t0).ok();
        limiter
            .permit("k16", t0)
            .expect("new key is admitted by evicting LRU");
        assert_eq!(limiter.len(), 16);
        assert!(limiter.contains("k0"), "recently used key is retained");
        assert!(
            !limiter.contains("k1"),
            "least-recently-used key is evicted"
        );

        for i in 17..80 {
            limiter.permit(&format!("k{i}"), t0).ok();
            assert!(
                limiter.len() <= 16,
                "store must stay at max_entries under churn, got {}",
                limiter.len()
            );
        }
        assert_eq!(limiter.len(), 16);
    }

    #[test]
    fn idle_sweep_drops_untouched_buckets() {
        let ttl = Duration::from_secs(10);
        let limiter = KeyedRequestLimiter::new(1, 1, 32, ttl);
        let t0 = Duration::from_secs(0);
        limiter.permit("stale", t0).unwrap();
        limiter.permit("fresh", t0).unwrap();
        assert_eq!(limiter.len(), 2);

        let mid = ttl - Duration::from_secs(1);
        limiter.permit("fresh", mid).ok();

        let later = ttl + Duration::from_secs(1);
        limiter.permit("fresh", later).ok();
        limiter.permit("new", later).unwrap();
        assert!(
            !limiter.contains("stale"),
            "idle bucket past TTL must be swept"
        );
        assert!(limiter.contains("fresh"));
        assert!(limiter.contains("new"));
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn ipv6_slash64_rotation_shares_one_bucket_key() {
        let a: IpAddr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:1111:2222:3333:4444".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(
            ip_prefix_key(a, 32, 64),
            ip_prefix_key(b, 32, 64),
            "addresses in the same /64 share a bucket key"
        );
        assert_ne!(ip_prefix_key(a, 32, 64), ip_prefix_key(other, 32, 64));

        let limiter = limiter(1, 1);
        let t0 = Duration::from_secs(0);
        let key = ip_prefix_key(a, 32, 64);
        limiter.permit(&key, t0).unwrap();
        assert_eq!(
            limiter.permit(&ip_prefix_key(b, 32, 64), t0),
            Err(ClaimLimitExceeded {
                retry_after_secs: 1
            }),
            "/64 rotation must not mint a fresh burst"
        );
        limiter
            .permit(&ip_prefix_key(other, 32, 64), t0)
            .expect("a different /64 has its own bucket");
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn ipv4_slash32_is_the_host_and_mapped_v6_is_v4() {
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(ip_prefix_key(a, 32, 64), "192.0.2.1/32");
        assert_ne!(ip_prefix_key(a, 32, 64), ip_prefix_key(b, 32, 64));
        assert_eq!(
            ip_prefix_key(a, 32, 64),
            ip_prefix_key(mapped, 32, 64),
            "IPv4-mapped IPv6 must bucket as the embedded IPv4 /32"
        );
    }

    fn peer() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    #[test]
    fn hops_zero_ignores_headers_and_returns_peer() {
        let spoofed = "203.0.113.1, 198.51.100.7";
        assert_eq!(
            client_ip(peer(), 0, Some(spoofed), Some("198.51.100.9")),
            peer()
        );
    }

    #[test]
    fn no_header_returns_peer() {
        assert_eq!(client_ip(peer(), 1, None, None), peer());
        assert_eq!(client_ip(peer(), 1, Some(" "), Some("")), peer());
    }

    #[test]
    fn hops_one_takes_last_xff_and_ignores_spoofed_leading_entries() {
        let xff = "203.0.113.1, 192.0.2.2, 198.51.100.7";
        assert_eq!(
            client_ip(peer(), 1, Some(xff), Some("203.0.113.9")),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        assert_ne!(
            client_ip(peer(), 1, Some(xff), None),
            "203.0.113.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn hops_two_skips_the_last_proxy_hop() {
        let xff = "203.0.113.1, 198.51.100.7, 10.0.0.2";
        assert_eq!(
            client_ip(peer(), 2, Some(xff), None),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn hops_one_falls_back_to_x_real_ip_when_xff_missing() {
        assert_eq!(
            client_ip(peer(), 1, None, Some("198.51.100.9")),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn too_few_xff_hops_does_not_take_the_first_spoofed_entry() {
        assert_eq!(
            client_ip(
                peer(),
                3,
                Some("203.0.113.1, 198.51.100.7"),
                Some("198.51.100.9")
            ),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn railway_edge_ula_pool_shares_a_slash64() {
        let a: IpAddr = "fd12:0:8:0:2000:9d:8000:1".parse().unwrap();
        let b: IpAddr = "fd12:0:8:0:2000:f1:8000:1".parse().unwrap();
        assert_eq!(ip_prefix_key(a, 32, 64), "fd12:0:8::/64");
        assert_eq!(
            ip_prefix_key(a, 32, 64),
            ip_prefix_key(b, 32, 64),
            "Railway edge TCP peers on fd12:0:8:0::/64 collapse to one claim-IP bucket"
        );
    }
}
