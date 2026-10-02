//! Identity-wide reader capability discovery.

use paykit_lib::PaykitAppRegistry;

/// A reader needs at least one app capable of receiving and paying requests.
pub fn reader_is_capable(registry: &PaykitAppRegistry) -> bool {
    registry.noise_public_key().is_some()
        && registry.apps().values().any(|app| {
            let capabilities = app.capabilities();
            capabilities.private_payments
                && capabilities.payment_requests
                && capabilities.outgoing_payments
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use paykit_lib::{PaykitApp, PaykitAppCapabilities, PaykitAppId};

    #[test]
    fn any_capable_app_is_sufficient_without_priority_or_default_selection() {
        let mut registry =
            PaykitAppRegistry::new(Some(paykit_lib::derive_paykit_noise_public_key(&[9; 32])));
        registry
            .register_app(
                PaykitAppId::new("paykit-server").unwrap(),
                crate::real_setup::server_app(),
            )
            .unwrap();
        assert!(!reader_is_capable(&registry));
        registry
            .register_app(
                PaykitAppId::new("another-wallet").unwrap(),
                PaykitApp::new(
                    "Wallet",
                    PaykitAppCapabilities {
                        private_payments: true,
                        payment_requests: true,
                        receipts: false,
                        outgoing_payments: true,
                    },
                )
                .unwrap(),
            )
            .unwrap();
        assert!(reader_is_capable(&registry));
        assert!(!reader_is_capable(&PaykitAppRegistry::new(None)));
    }
}
