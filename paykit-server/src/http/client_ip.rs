use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::http::HeaderMap;

const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Returns the client address that keys per-IP policy.
///
/// With zero trusted hops this is the TCP peer and forwarding headers are ignored. Otherwise each
/// trusted proxy appends one `X-Forwarded-For` entry, so the client is the entry
/// `trusted_proxy_hops` positions from the right across all header lines. Entries further left are
/// client-supplied and never read. A missing or non-IP entry at that position yields the TCP peer.
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trusted_proxy_hops: u8) -> IpAddr {
    let Some(position) = usize::from(trusted_proxy_hops).checked_sub(1) else {
        return peer.ip();
    };
    headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .rev()
        .flat_map(|value| value.as_bytes().rsplit(|byte| *byte == b','))
        .nth(position)
        .and_then(forwarded_ip)
        .unwrap_or_else(|| peer.ip())
}

/// Parses one `X-Forwarded-For` entry: a bare IP address, `IPv4:port`, `[IPv6]`, or
/// `[IPv6]:port`. IPv4-mapped IPv6 is reduced to IPv4 because proxies render the same IPv4
/// client either way depending on their listening socket.
fn forwarded_ip(entry: &[u8]) -> Option<IpAddr> {
    let entry = std::str::from_utf8(entry.trim_ascii()).ok()?;
    entry
        .parse::<IpAddr>()
        .ok()
        .or_else(|| entry.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .or_else(|| {
            entry
                .strip_prefix('[')?
                .strip_suffix(']')?
                .parse::<Ipv6Addr>()
                .ok()
                .map(IpAddr::V6)
        })
        .map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn proxy() -> SocketAddr {
        "10.0.0.1:443".parse().unwrap()
    }

    fn headers(lines: &[&[u8]]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(X_FORWARDED_FOR, HeaderValue::from_bytes(line).unwrap());
        }
        headers
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn selects_the_trusted_forwarded_entry_or_falls_back_to_the_peer() {
        let peer = proxy().ip();
        let client = ip("203.0.113.7");
        let client_v6 = ip("2001:db8::7");
        let cases: &[(u8, &[&[u8]], IpAddr)] = &[
            (0, &[], peer),
            (0, &[b"203.0.113.7"], peer),
            (1, &[], peer),
            (1, &[b"203.0.113.7"], client),
            (1, &[b"198.51.100.1, 203.0.113.7"], client),
            (1, &[b"203.0.113.7, 198.51.100.1"], ip("198.51.100.1")),
            (2, &[b"198.51.100.1, 203.0.113.7, 192.0.2.10"], client),
            (2, &[b"203.0.113.7"], peer),
            (3, &[b"198.51.100.1, 203.0.113.7"], peer),
            (1, &[b"203.0.113.7, not-an-ip"], peer),
            (1, &[b"203.0.113.7, unknown"], peer),
            (1, &[b"203.0.113.7,"], peer),
            (1, &[b"203.0.113.7, 2001:db8::7]"], peer),
            (2, &[b"198.51.100.1", b"203.0.113.7, 192.0.2.10"], client),
            (2, &[b"198.51.100.1, 203.0.113.7", b"192.0.2.10"], client),
            (1, &[b"\xff\xfe", b"203.0.113.7"], client),
            (1, &[b"  198.51.100.1 ,\t203.0.113.7\t "], client),
            (1, &[b"203.0.113.7:4711"], client),
            (1, &[b"::ffff:203.0.113.7"], client),
            (1, &[b"2001:db8::7"], client_v6),
            (1, &[b"[2001:db8::7]"], client_v6),
            (1, &[b"[2001:db8::7]:4711"], client_v6),
            (
                8,
                &[b"198.51.100.1, 203.0.113.7, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6, 10.0.0.7, 10.0.0.8"],
                client,
            ),
        ];

        for (hops, lines, expected) in cases {
            assert_eq!(
                client_ip(proxy(), &headers(lines), *hops),
                *expected,
                "hops={hops} lines={lines:?}"
            );
        }
    }

    #[test]
    fn zero_hops_returns_the_peer_address_unchanged() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:443".parse().unwrap();

        assert_eq!(
            client_ip(mapped, &headers(&[b"203.0.113.7"]), 0),
            mapped.ip()
        );
    }
}
