use std::time::Duration;

use paykit_server::config::{
    Config, ConfigEnvironment, ConfigError, MAX_TRUSTED_PROXY_HOPS, PaykitNetwork,
};

const KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn second_key() -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
    pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(signing_key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string()
}

fn weak_key() -> String {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&[0; 32]).unwrap();
    assert!(verifying_key.is_weak());
    pubky::PublicKey::from(pubky::pkarr::PublicKey::try_from(verifying_key.as_bytes()).unwrap())
        .to_string()
}

fn environment() -> ConfigEnvironment {
    ConfigEnvironment {
        database_url: Some("postgres://paykit:secret@localhost/paykit".to_owned()),
        master_key: Some(MASTER_KEY.to_owned()),
    }
}

fn valid_toml() -> String {
    format!(
        r#"
[http]
listen_addr = "127.0.0.1:8080"

[signed_services]
trusted_public_keys = ["{KEY}"]

[setup]
allowed_origins = ["https://app.example"]

[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"

[bitcoin]
network = "testnet"

[electrum]
endpoint = "ssl://electrum.example:50002"

[outbox]
poll_interval = "5s"
"#
    )
}

fn trusted_services_toml(keys: &str) -> String {
    valid_toml().replace(
        &format!("trusted_public_keys = [\"{KEY}\"]"),
        &format!("trusted_public_keys = [{keys}]"),
    )
}

#[test]
fn trusted_service_allowlist_accepts_two_distinct_canonical_keys() {
    let second = second_key();
    let source = trusted_services_toml(&format!("\"{KEY}\", \"{second}\""));
    let config = Config::from_toml_and_environment(&source, environment()).unwrap();
    assert_eq!(config.signed_services.trusted_public_keys.len(), 2);
}

#[test]
fn trusted_service_allowlist_rejects_empty_invalid_and_duplicate_keys() {
    let duplicate = format!("\"{KEY}\", \"{KEY}\"");
    let weak = format!("\"{}\"", weak_key());
    let cases = [
        ("", ConfigError::EmptyTrustedServicePublicKeys),
        ("\"not-a-key\"", ConfigError::InvalidTrustedServicePublicKey),
        (weak.as_str(), ConfigError::InvalidTrustedServicePublicKey),
        (
            duplicate.as_str(),
            ConfigError::DuplicateTrustedServicePublicKey,
        ),
    ];

    for (keys, expected) in cases {
        let error = Config::from_toml_and_environment(&trusted_services_toml(keys), environment())
            .unwrap_err();
        assert_eq!(error, expected);
    }
}

#[test]
fn legacy_single_locks_key_is_rejected_after_explicit_allowlist_cutover() {
    let legacy = valid_toml().replace(
        &format!("[signed_services]\ntrusted_public_keys = [\"{KEY}\"]"),
        &format!("[locks]\ntrusted_public_key = \"{KEY}\""),
    );
    let error = Config::from_toml_and_environment(&legacy, environment()).unwrap_err();
    assert_eq!(error, ConfigError::LegacyLocksTrustedPublicKey);
    assert_eq!(
        error.to_string(),
        "[locks] trusted_public_key was replaced by [signed_services] trusted_public_keys"
    );
}

#[test]
fn effective_config_redacts_every_trusted_service_key() {
    let second = second_key();
    let source = trusted_services_toml(&format!("\"{KEY}\", \"{second}\""));
    let rendered = Config::from_toml_and_environment(&source, environment())
        .unwrap()
        .redacted_effective_config();
    assert!(!rendered.contains(KEY));
    assert!(!rendered.contains(&second));
    assert!(rendered.contains("<redacted>"));
}

fn local_compose_toml() -> String {
    format!(
        r#"
[http]
listen_addr = "0.0.0.0:3001"

[signed_services]
trusted_public_keys = ["{KEY}"]

[setup]
allowed_origins = ["http://localhost:8080"]

[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"

[bitcoin]
network = "regtest"

[electrum]
endpoint = "tcp://fulcrum:50001"
poll_interval = "1s"

[outbox]
poll_interval = "500ms"
"#
    )
}

#[test]
fn setup_authorization_url_logging_defaults_to_disabled() {
    let config = Config::from_toml_and_environment(&valid_toml(), environment()).unwrap();

    assert!(!config.setup.log_authorization_url);
}

#[test]
fn invoice_windows_default_to_one_hour_acceptance_and_conversion_and_twenty_four_hour_payment() {
    let config = Config::from_toml_and_environment(&valid_toml(), environment()).unwrap();

    assert_eq!(
        config.paykit.proposal_acceptance_window,
        Duration::from_secs(60 * 60)
    );
    assert_eq!(
        config.paykit.conversion_payment_window,
        Duration::from_secs(3600)
    );
    assert_eq!(
        config.paykit.payment_window,
        Duration::from_secs(24 * 60 * 60)
    );
}

#[test]
fn invoice_windows_require_positive_acceptance_strictly_before_payment() {
    for windows in [
        "conversion_payment_window = \"1s\"",
        "conversion_payment_window = \"1500ms\"",
        "proposal_acceptance_window = \"0s\"\npayment_window = \"24h\"",
        "proposal_acceptance_window = \"24h\"\npayment_window = \"24h\"",
        "proposal_acceptance_window = \"25h\"\npayment_window = \"24h\"",
    ] {
        let input = valid_toml().replace(
            "network = \"testnet\"",
            &format!("network = \"testnet\"\n{windows}"),
        );
        assert!(Config::from_toml_and_environment(&input, environment()).is_err());
    }
}

#[test]
fn invoice_windows_reject_subsecond_precision_that_storage_cannot_preserve() {
    let input = valid_toml().replacen(
        "network = \"testnet\"",
        "network = \"testnet\"\nproposal_acceptance_window = \"1500ms\"\npayment_window = \"2500ms\"",
        1,
    );

    assert!(matches!(
        Config::from_toml_and_environment(&input, environment()),
        Err(ConfigError::InvalidInvoiceWindows)
    ));
}

#[test]
fn setup_authorization_url_logging_accepts_explicit_true() {
    let input = valid_toml().replace(
        "allowed_origins = [\"https://app.example\"]",
        "allowed_origins = [\"https://app.example\"]\nlog_authorization_url = true",
    );
    let config = Config::from_toml_and_environment(&input, environment()).unwrap();

    assert!(config.setup.log_authorization_url);
}

#[test]
fn setup_still_rejects_unknown_keys() {
    let input = valid_toml().replace(
        "allowed_origins = [\"https://app.example\"]",
        "allowed_origins = [\"https://app.example\"]\nlog_authorisation_url = true",
    );

    assert!(Config::from_toml_and_environment(&input, environment()).is_err());
}

#[test]
fn parses_exact_local_compose_config_contract() {
    let config = Config::from_toml_and_environment(&local_compose_toml(), environment())
        .expect("local Compose configuration");

    assert_eq!(config.http.listen_addr().to_string(), "0.0.0.0:3001");
    assert_eq!(config.setup.allowed_origins, vec!["http://localhost:8080"]);
    assert_eq!(config.paykit.network, PaykitNetwork::Testnet);
    assert_eq!(config.paykit.client_id.as_str(), "app.paykit.server");
    assert_eq!(
        config.deployment_invariants().paykit_client_id.as_str(),
        "app.paykit.server"
    );
    assert_eq!(config.paykit.app_id.as_str(), "paykit-server");
    assert_eq!(
        config.deployment_invariants().bitcoin_network.as_str(),
        "regtest"
    );

    assert_eq!(config.electrum.endpoint(), "tcp://fulcrum:50001");
    assert_eq!(config.electrum.poll_interval, Duration::from_secs(1));
    assert_eq!(config.outbox.poll_interval, Duration::from_millis(500));
}

#[test]
fn local_compose_config_rejects_unknown_keys() {
    let input = format!("unknown = true\n{}", local_compose_toml());

    assert!(Config::from_toml_and_environment(&input, environment()).is_err());
}

#[test]
fn accepts_supported_paykit_network_and_rejects_retired_url_keys() {
    let config = Config::from_toml_and_environment(&valid_toml(), environment())
        .expect("supported Paykit network");
    assert_eq!(config.paykit.network, PaykitNetwork::Testnet);

    let retired = valid_toml().replacen(
        "network = \"testnet\"",
        "network = \"testnet\"\nrelay_url = \"https://relay.example\"\nhomeserver_url = \"https://homeserver.example\"",
        1,
    );
    assert!(Config::from_toml_and_environment(&retired, environment()).is_err());
}

#[test]
fn trusted_proxy_hops_defaults_to_zero_and_rejects_values_above_the_maximum() {
    let with_hops = |hops: &str| {
        valid_toml().replace(
            "listen_addr = \"127.0.0.1:8080\"",
            &format!("listen_addr = \"127.0.0.1:8080\"\ntrusted_proxy_hops = {hops}"),
        )
    };

    let default = Config::from_toml_and_environment(&valid_toml(), environment()).unwrap();
    assert_eq!(default.http.trusted_proxy_hops(), 0);
    for hops in [0, 1, MAX_TRUSTED_PROXY_HOPS] {
        let config =
            Config::from_toml_and_environment(&with_hops(&hops.to_string()), environment())
                .unwrap();
        assert_eq!(config.http.trusted_proxy_hops(), hops);
    }
    assert!(matches!(
        Config::from_toml_and_environment(
            &with_hops(&(MAX_TRUSTED_PROXY_HOPS + 1).to_string()),
            environment()
        ),
        Err(ConfigError::ValueTooLarge("http.trusted_proxy_hops"))
    ));
    for invalid in ["-1", "256", "\"1\"", "1.0"] {
        assert!(matches!(
            Config::from_toml_and_environment(&with_hops(invalid), environment()),
            Err(ConfigError::Toml)
        ));
    }
}

#[test]
fn rejects_unknown_toml_fields() {
    let config = valid_toml().replace(
        "listen_addr = \"127.0.0.1:8080\"",
        "listen_addr = \"127.0.0.1:8080\"\nextra = true",
    );

    assert!(Config::from_toml_and_environment(&config, environment()).is_err());
}

#[test]
fn requires_a_nonempty_paykit_client_id() {
    let missing = valid_toml().replace("client_id = \"app.paykit.server\"\n", "");
    let empty = valid_toml().replace("client_id = \"app.paykit.server\"", "client_id = \"\"");
    let other = valid_toml().replace(
        "client_id = \"app.paykit.server\"",
        "client_id = \"other.paykit.server\"",
    );

    assert!(matches!(
        Config::from_toml_and_environment(&missing, environment()),
        Err(ConfigError::MissingPaykitClientId)
    ));
    assert!(Config::from_toml_and_environment(&empty, environment()).is_err());
    assert!(Config::from_toml_and_environment(&other, environment()).is_err());
}

#[test]
fn rejects_removed_retention_section() {
    let config = format!("{}\n[retention]\ncleanup_batch_size = 100\n", valid_toml());

    assert!(Config::from_toml_and_environment(&config, environment()).is_err());
}

#[test]
fn rejects_removed_inbox_section() {
    let config = format!(
        "{}\n[inbox]\npoll_interval = \"5s\"\nbatch_size = 100\n",
        valid_toml()
    );

    assert!(Config::from_toml_and_environment(&config, environment()).is_err());
}

#[test]
fn requires_environment_only_database_url_and_master_key() {
    let missing_database_url = ConfigEnvironment {
        database_url: None,
        ..environment()
    };
    let missing_master_key = ConfigEnvironment {
        master_key: None,
        ..environment()
    };

    assert!(Config::from_toml_and_environment(&valid_toml(), missing_database_url).is_err());
    assert!(Config::from_toml_and_environment(&valid_toml(), missing_master_key).is_err());

    let toml_secret = format!(
        "PAYKIT_DATABASE_URL = \"postgres://toml.example/paykit\"\n{}",
        valid_toml()
    );
    assert!(Config::from_toml_and_environment(&toml_secret, environment()).is_err());
}

#[test]
fn rejects_non_postgresql_database_url() {
    let non_postgresql = ConfigEnvironment {
        database_url: Some("https://database.example/paykit".to_owned()),
        ..environment()
    };

    assert!(Config::from_toml_and_environment(&valid_toml(), non_postgresql).is_err());
}

#[test]
fn config_environment_debug_redacts_both_secrets() {
    let environment = ConfigEnvironment {
        database_url: Some("postgres://debug-user:debug-password@example.test/paykit".into()),
        master_key: Some("debug-master-key".into()),
    };

    let rendered = format!("{environment:?}");
    assert!(!rendered.contains("debug-password"));
    assert!(!rendered.contains("debug-master-key"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn rejects_malformed_master_key_and_accepts_32_byte_base64url_without_padding() {
    let malformed = ConfigEnvironment {
        master_key: Some("not/base64".to_owned()),
        ..environment()
    };
    let padded = ConfigEnvironment {
        master_key: Some(format!("{MASTER_KEY}=")),
        ..environment()
    };
    assert!(Config::from_toml_and_environment(&valid_toml(), malformed).is_err());
    assert!(Config::from_toml_and_environment(&valid_toml(), padded).is_err());

    let config = Config::from_toml_and_environment(&valid_toml(), environment()).unwrap();
    assert_eq!(config.master_key().as_bytes().len(), 32);
}

#[test]
fn rejects_invalid_network_origin_key_zero_values_and_inconsistent_retries() {
    for (name, replacement) in [
        ("network", "network = \"unsupported\""),
        (
            "allowed_origins",
            "allowed_origins = [\"https://*.example\"]",
        ),
        (
            "trusted_public_keys",
            "trusted_public_keys = [\"not-a-key\"]",
        ),
        ("poll_interval", "poll_interval = \"0s\""),
        ("request_timeout", "request_timeout = \"0s\""),
        ("outbox_batch_size", "batch_size = 0"),
    ] {
        let input = match name {
            "network" => valid_toml().replacen("network = \"testnet\"", replacement, 1),

            "allowed_origins" => {
                valid_toml().replace("allowed_origins = [\"https://app.example\"]", replacement)
            }
            "trusted_public_keys" => {
                valid_toml().replace(&format!("trusted_public_keys = [\"{KEY}\"]"), replacement)
            }
            "poll_interval" => valid_toml().replace(
                "endpoint = \"ssl://electrum.example:50002\"",
                "endpoint = \"ssl://electrum.example:50002\"\npoll_interval = \"0s\"",
            ),
            "request_timeout" => valid_toml().replace(
                "endpoint = \"ssl://electrum.example:50002\"",
                "endpoint = \"ssl://electrum.example:50002\"\nrequest_timeout = \"0s\"",
            ),
            "outbox_batch_size" => valid_toml().replace(
                "poll_interval = \"5s\"",
                "poll_interval = \"5s\"\nbatch_size = 0",
            ),
            _ => unreachable!(),
        };
        assert!(
            Config::from_toml_and_environment(&input, environment()).is_err(),
            "{name} should be rejected"
        );
    }

    let inconsistent_retries = format!(
        "{}\n[outbox]\nretry_initial = \"5m\"\nretry_max = \"1s\"\n",
        valid_toml()
    );
    assert!(Config::from_toml_and_environment(&inconsistent_retries, environment()).is_err());

    for invalid_app_id in ["", "../paykit-server", "bitkit"] {
        let input = valid_toml().replace(
            "app_id = \"paykit-server\"",
            &format!("app_id = \"{invalid_app_id}\""),
        );
        assert!(
            Config::from_toml_and_environment(&input, environment()).is_err(),
            "{invalid_app_id} should be rejected"
        );
    }
}

#[test]
fn rejects_public_keys_without_the_pubky_prefix() {
    for unprefixed in [
        KEY.strip_prefix("pubky").unwrap(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let input = valid_toml().replace(
            &format!("trusted_public_keys = [\"{KEY}\"]"),
            &format!("trusted_public_keys = [\"{unprefixed}\"]"),
        );

        assert!(Config::from_toml_and_environment(&input, environment()).is_err());
    }
}

#[test]
fn wildcard_setup_origin_must_be_the_only_configured_origin() {
    let wildcard = valid_toml().replace(
        "allowed_origins = [\"https://app.example\"]",
        "allowed_origins = [\"*\"]",
    );
    let config = Config::from_toml_and_environment(&wildcard, environment()).unwrap();
    assert_eq!(config.setup.allowed_origins, vec!["*".to_owned()]);

    let mixed = valid_toml().replace(
        "allowed_origins = [\"https://app.example\"]",
        "allowed_origins = [\"*\", \"https://app.example\"]",
    );
    assert!(Config::from_toml_and_environment(&mixed, environment()).is_err());
}

#[test]
fn parses_accepted_durations_and_uses_ledger_defaults() {
    let config = Config::from_toml_and_environment(&valid_toml(), environment()).unwrap();

    assert_eq!(config.electrum.poll_interval, Duration::from_secs(10));
    assert_eq!(config.electrum.request_timeout, Duration::from_secs(10));
    assert_eq!(config.electrum.connect_retries, 1);
    assert_eq!(config.outbox.poll_interval, Duration::from_secs(5));
    assert_eq!(config.outbox.batch_size, 16);
    assert_eq!(config.outbox.lease_duration, Duration::from_secs(30));
    assert_eq!(config.outbox.retry_initial, Duration::from_secs(1));
    assert_eq!(config.outbox.retry_max, Duration::from_secs(5 * 60));
    assert_eq!(config.outbox.rapid_link_retry_attempts, 120);
    assert_eq!(
        config.outbox.rapid_link_retry_interval,
        Duration::from_millis(1_000)
    );

    assert_eq!(config.limits.request_body_bytes, 16 * 1024);
    assert_eq!(config.limits.lock_resource_bytes, 256 * 1024);
    assert_eq!(config.limits.lock_fetch_timeout, Duration::from_secs(10));
    assert_eq!(config.rate_limits.signed_requests_per_second, 100);
    assert_eq!(config.rate_limits.signed_burst, 200);
    assert_eq!(config.rate_limits.setup_per_ip_per_minute, 10);
    assert_eq!(config.rate_limits.max_pending_setup_flows(), 100);
    assert_eq!(config.rate_limits.max_completion_polls_per_flow, 2);
    assert_eq!(config.rate_limits.max_completion_polls, 200);
    assert_eq!(config.shutdown.drain_timeout, Duration::from_secs(30));

    let input = valid_toml().replace(
        "endpoint = \"ssl://electrum.example:50002\"",
        "endpoint = \"ssl://electrum.example:50002\"\npoll_interval = \"30s\"",
    );
    let configured = Config::from_toml_and_environment(&input, environment()).unwrap();
    assert_eq!(configured.electrum.poll_interval, Duration::from_secs(30));
}

#[test]
fn rapid_link_retry_policy_accepts_custom_attempts_and_millisecond_interval() {
    let input = valid_toml().replace(
        "poll_interval = \"5s\"",
        "poll_interval = \"5s\"\nrapid_link_retry_attempts = 240\nrapid_link_retry_interval_ms = 500",
    );
    let config = Config::from_toml_and_environment(&input, environment()).unwrap();

    assert_eq!(config.outbox.rapid_link_retry_attempts, 240);
    assert_eq!(
        config.outbox.rapid_link_retry_interval,
        Duration::from_millis(500)
    );
}

#[test]
fn rapid_link_retry_policy_rejects_zero_and_out_of_range_values() {
    for field in [
        "rapid_link_retry_attempts = 0",
        "rapid_link_retry_attempts = 2147483648",
        "rapid_link_retry_interval_ms = 0",
        "rapid_link_retry_interval_ms = 4294967296",
    ] {
        let input = valid_toml().replace(
            "poll_interval = \"5s\"",
            &format!("poll_interval = \"5s\"\n{field}"),
        );

        assert!(
            Config::from_toml_and_environment(&input, environment()).is_err(),
            "{field} should be rejected"
        );
    }
}

#[test]
fn rejects_subsecond_persistence_lease_and_retry_durations() {
    for (section, field) in [
        ("outbox", "lease_duration"),
        ("outbox", "retry_initial"),
        ("outbox", "retry_max"),
    ] {
        let input = valid_toml().replace(
            "poll_interval = \"5s\"",
            &format!("poll_interval = \"5s\"\n{field} = \"999ms\""),
        );
        let error = Config::from_toml_and_environment(&input, environment()).unwrap_err();
        assert!(
            error.to_string().contains("at least one second"),
            "{section}.{field}: {error}"
        );
    }
}

#[test]
fn accepts_one_second_persistence_lease_and_retry_durations() {
    let input = valid_toml().replace(
        "poll_interval = \"5s\"",
        "poll_interval = \"5s\"\nlease_duration = \"1s\"\nretry_initial = \"1s\"\nretry_max = \"1s\"",
    );
    assert!(Config::from_toml_and_environment(&input, environment()).is_ok());
}

#[test]
fn effective_config_is_redacted_and_exposes_typed_deployment_invariants() {
    let config = Config::from_toml_and_environment(&valid_toml(), environment()).unwrap();
    let effective = config.redacted_effective_config();

    assert!(!effective.contains("postgres://paykit:secret@localhost/paykit"));
    assert!(!effective.contains(MASTER_KEY));
    assert!(effective.contains("<redacted>"));
    assert_eq!(
        config.deployment_invariants().bitcoin_network.as_str(),
        "testnet"
    );
    assert_eq!(
        config.deployment_invariants().app_id.as_str(),
        "paykit-server"
    );
    assert_eq!(config.signed_services.trusted_public_keys.len(), 1);
}

#[test]
fn rejects_outbox_batch_size_above_the_supported_integer_range() {
    let oversized = valid_toml().replace(
        "poll_interval = \"5s\"",
        "poll_interval = \"5s\"\nbatch_size = 4294967296",
    );
    assert!(Config::from_toml_and_environment(&oversized, environment()).is_err());
}

#[test]
fn usdt_requires_an_explicit_protected_rpc_and_redacts_credentials() {
    assert!(
        Config::from_toml_and_environment(&valid_toml(), environment())
            .unwrap()
            .usdt
            .is_none()
    );
    for url in [
        "https://arbitrum.example/private-key",
        "http://127.0.0.1:8545/",
    ] {
        let config = Config::from_toml_and_environment(
            &format!("{}\n[usdt]\nrpc_url = \"{url}\"", valid_toml()),
            environment(),
        )
        .unwrap();
        assert!(config.usdt.is_some());
        assert!(!format!("{:?}", config.usdt).contains(url));
    }
    for url in [
        "http://arbitrum.example/",
        "https://user:password@rpc.example/",
        "https://rpc.example/#secret",
    ] {
        assert!(
            Config::from_toml_and_environment(
                &format!("{}\n[usdt]\nrpc_url = \"{url}\"", valid_toml()),
                environment()
            )
            .is_err()
        );
    }
}
