//! Deterministic selection of a reader's publicly discoverable Paykit receiver.
//!
//! Discovery deliberately returns every public candidate.  A marker is usable
//! only when it advertises both private payments and Payment Requests and is not
//! at this server's own receiver path; selection then applies the operator's
//! first-segment priority and canonical full-path lexical tie break.
//!
//! A reader who is also a claimed creator publishes this server's receiver path
//! (for example `bitkit/server`) next to their wallet's (`bitkit/wallet`). That
//! marker is a Paykit Server claim inbox, which no wallet answers on, so it is
//! never a delivery target for the reader's Payment Requests.

use paykit_lib::{PaykitReceiverMarker, PaykitReceiverPath};

use crate::config::ReceiverPathPriority;

/// A validated public marker selected for one invoice intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedReaderMarker {
    pub receiver_path: PaykitReceiverPath,
    pub marker: PaykitReceiverMarker,
}

/// Select a capable marker without depending on listing order.
pub fn select_reader_marker(
    candidates: impl IntoIterator<Item = PaykitReceiverMarker>,
    priority: &[ReceiverPathPriority],
    server_receiver_path: &PaykitReceiverPath,
) -> Option<SelectedReaderMarker> {
    let mut capable = candidates
        .into_iter()
        .filter(|marker| {
            marker.capabilities.private_payments
                && marker.capabilities.payment_requests
                && marker.receiver_path != *server_receiver_path
        })
        .collect::<Vec<_>>();
    capable.sort_by_key(|marker| rank(marker, priority));
    capable
        .into_iter()
        .next()
        .map(|marker| SelectedReaderMarker {
            receiver_path: marker.receiver_path.clone(),
            marker,
        })
}

fn rank(marker: &PaykitReceiverMarker, priority: &[ReceiverPathPriority]) -> (usize, String) {
    let path = marker.receiver_path.as_str();
    let first_segment = path.split('/').next().unwrap_or_default();
    let priority_index = priority
        .iter()
        .position(|configured| configured.as_str() == first_segment)
        .unwrap_or(priority.len());
    (priority_index, path.into())
}

#[cfg(test)]
mod tests {
    use paykit_lib::{PaykitReceiverCapabilities, PublicKey};

    use super::*;

    fn marker(path: &str, capable: bool) -> PaykitReceiverMarker {
        PaykitReceiverMarker::new(
            PaykitReceiverPath::new(path).unwrap(),
            PaykitReceiverCapabilities {
                private_payments: capable,
                payment_requests: capable,
                receipts: false,
                outgoing_payments: false,
            },
            PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy")
                .unwrap(),
        )
    }

    fn priority(values: &[&str]) -> Vec<ReceiverPathPriority> {
        values
            .iter()
            .map(|value| ReceiverPathPriority::parse((*value).into()).unwrap())
            .collect()
    }

    #[test]
    fn prefers_bitkit_then_lexical_full_path_and_filters_capabilities() {
        let selected = select_reader_marker(
            [
                marker("other/wallet", true),
                marker("other/server", true),
                marker("bitkit/wallet", true),
                marker("bitkit/server", false),
            ],
            &priority(&["bitkit"]),
            &server_path(),
        )
        .unwrap();
        assert_eq!(selected.receiver_path.as_str(), "bitkit/wallet");

        let selected = select_reader_marker(
            [marker("other/wallet", true), marker("other/server", true)],
            &priority(&["bitkit"]),
            &server_path(),
        )
        .unwrap();
        assert_eq!(selected.receiver_path.as_str(), "other/server");
    }

    fn server_path() -> PaykitReceiverPath {
        PaykitReceiverPath::new("paykit/server").unwrap()
    }

    #[test]
    fn never_selects_the_servers_own_claim_inbox_path() {
        // A reader who also claimed a creator account on a server using
        // `bitkit/server` publishes both markers; both rank first under the
        // `bitkit` priority and the lexical tie-break used to pick the inbox.
        let server = PaykitReceiverPath::new("bitkit/server").unwrap();
        let selected = select_reader_marker(
            [marker("bitkit/server", true), marker("bitkit/wallet", true)],
            &priority(&["bitkit"]),
            &server,
        )
        .unwrap();
        assert_eq!(selected.receiver_path.as_str(), "bitkit/wallet");

        assert_eq!(
            select_reader_marker(
                [marker("bitkit/server", true)],
                &priority(&["bitkit"]),
                &server
            ),
            None
        );
    }

    #[test]
    fn configured_priority_overrides_the_default_order() {
        let selected = select_reader_marker(
            [marker("bitkit/wallet", true), marker("other/server", true)],
            &priority(&["other", "bitkit"]),
            &server_path(),
        )
        .unwrap();
        assert_eq!(selected.receiver_path.as_str(), "other/server");
    }
}
