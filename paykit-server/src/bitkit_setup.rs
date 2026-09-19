//! Concrete SDK AUTH start boundary for Bitkit setup.

use url::Url;

use crate::bitkit_claim::{
    AuthRequest, CLAIM_TYPE, ClaimError, QUERY_PARAMETER, parse_auth_request, required_capabilities,
};
use paykit_lib::PaykitReceiverPath;

/// A secret-bearing request is retained only in the in-memory flow. Callers may
/// render `authorization_url` inside the server-origin iframe but must never put
/// it in postMessage or completion responses.
pub struct StartedBitkitAuth {
    pub authorization_url: String,
    pub request: AuthRequest,
    pub auth_request: paykit_sdk::PubkyAuthRequest,
    capabilities: String,
}

impl StartedBitkitAuth {
    pub fn capabilities(&self) -> &str {
        &self.capabilities
    }
}

impl core::fmt::Debug for StartedBitkitAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartedBitkitAuth")
            .field("authorization_url", &"<redacted>")
            .finish()
    }
}

/// Starts the normal SDK-owned sign-in request and safely binds the exact
/// Bitkit query pair. This is the production construction path; mocks remain
/// confined to the setup-flow tests.
#[derive(Clone, Debug)]
pub struct BitkitAuthStarter {
    bootstrap: paykit_sdk::PubkySessionBootstrap,
    capabilities: String,
}

impl BitkitAuthStarter {
    pub fn new(
        bootstrap: paykit_sdk::PubkySessionBootstrap,
        receiver_path: &PaykitReceiverPath,
    ) -> Self {
        Self {
            bootstrap,
            capabilities: required_capabilities(receiver_path),
        }
    }

    pub async fn start(&self) -> Result<StartedBitkitAuth, ClaimError> {
        let request = self
            .bootstrap
            .start_sign_in_auth(&self.capabilities)
            .await
            .map_err(|_| ClaimError::InvalidAuthRequest)?;
        let authorization_url =
            append_bitkit_claim(request.authorization_url(), &self.capabilities)?;
        let companion = parse_auth_request(&authorization_url, &self.capabilities)?;
        Ok(StartedBitkitAuth {
            authorization_url,
            request: companion,
            auth_request: request,
            capabilities: self.capabilities.clone(),
        })
    }
}

pub fn append_bitkit_claim(
    auth_url: &str,
    expected_capabilities: &str,
) -> Result<String, ClaimError> {
    let mut url = Url::parse(auth_url).map_err(|_| ClaimError::InvalidAuthRequest)?;
    if url.query_pairs().any(|(key, _)| key == QUERY_PARAMETER) {
        return Err(ClaimError::InvalidAuthRequest);
    }
    url.query_pairs_mut()
        .append_pair(QUERY_PARAMETER, CLAIM_TYPE);
    let value = url.to_string();
    parse_auth_request(&value, expected_capabilities)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitkit_claim::LOCAL_DEMO_CAPABILITIES;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    #[tokio::test]
    async fn rc55_builder_generates_complete_unique_bitkit_grant_and_retains_pop_state() {
        let bootstrap = paykit_sdk::PubkySessionBootstrap::new("paykit.test")
            .unwrap()
            .with_auth_relay("https://relay.example/inbox")
            .unwrap();
        let starter = BitkitAuthStarter::new(
            bootstrap,
            &PaykitReceiverPath::new("bitkit/server").unwrap(),
        );

        let first = starter.start().await.unwrap();
        let second = starter.start().await.unwrap();
        let first_url = Url::parse(&first.authorization_url).unwrap();
        assert_eq!(first_url.host_str(), Some("signin_grant"));

        let mut values = std::collections::BTreeMap::<String, Vec<String>>::new();
        for (key, value) in first_url.query_pairs() {
            values
                .entry(key.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        for name in ["caps", "relay", "secret", "cid", "cpk", QUERY_PARAMETER] {
            assert_eq!(values.get(name).map(Vec::len), Some(1), "{name}");
        }
        assert_eq!(values["caps"][0], LOCAL_DEMO_CAPABILITIES);
        assert_eq!(values["relay"][0], "https://relay.example/inbox");
        assert_eq!(values["cid"][0], "paykit.test");
        assert_eq!(values[QUERY_PARAMETER][0], CLAIM_TYPE);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&values["secret"][0]).unwrap().len(),
            32
        );

        let details = paykit_sdk::parse_pubky_auth_url(&first.authorization_url).unwrap();
        assert_eq!(details.capabilities, LOCAL_DEMO_CAPABILITIES);
        assert_eq!(details.client_id, "paykit.test");

        // rc55 validates that the retained private PoP key corresponds to the
        // generated cpk, even with the companion query pair preserved.
        let state = first.auth_request.save_state().unwrap();
        paykit_sdk::PubkyAuthRequestState::new(
            first.authorization_url.clone(),
            *state.client_key_secret(),
        )
        .unwrap();

        let second_url = Url::parse(&second.authorization_url).unwrap();
        let first_secret = values["secret"][0].as_str();
        let second_secret = second_url
            .query_pairs()
            .find(|(key, _)| key == "secret")
            .unwrap()
            .1;
        let first_cpk = values["cpk"][0].as_str();
        let second_cpk = second_url
            .query_pairs()
            .find(|(key, _)| key == "cpk")
            .unwrap()
            .1;
        assert_ne!(first_secret, second_secret);
        assert_ne!(first_cpk, second_cpk);
    }

    #[test]
    fn appends_one_exact_companion_query_pair_without_exposing_or_replacing_auth_values() {
        let secret = URL_SAFE_NO_PAD.encode([1; 32]);
        let url = format!(
            "pubkyauth://signin_grant?caps={LOCAL_DEMO_CAPABILITIES}&relay=https%3A%2F%2Frelay.example%2Finbox&secret={secret}&cid=paykit.test&cpk=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo"
        );
        let augmented = append_bitkit_claim(&url, LOCAL_DEMO_CAPABILITIES).unwrap();
        assert!(augmented.contains("x-bitkit-claim=watch-only-account-v1"));
        assert_eq!(
            parse_auth_request(&augmented, LOCAL_DEMO_CAPABILITIES)
                .unwrap()
                .secret(),
            &[1; 32]
        );
        assert_eq!(
            append_bitkit_claim(&augmented, LOCAL_DEMO_CAPABILITIES),
            Err(ClaimError::InvalidAuthRequest)
        );
    }
}
