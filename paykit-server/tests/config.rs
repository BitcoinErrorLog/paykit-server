use std::time::Duration;

use paykit_server::config::{
    Config, ConfigEnvironment, ConfigError, LISTUNSPENT_RESPONSE_ENVELOPE_BYTES, PaykitNetwork,
};
use paykit_server::workers::electrum::{
    LISTUNSPENT_ITEM_BYTES_UPPER_BOUND, MAX_MAX_RESPONSE_BYTES, MIN_MAX_RESPONSE_BYTES,
};

const KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

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

[locks]
trusted_public_key = "{KEY}"

[setup]
allowed_origins = ["https://app.example"]

[paykit]
receiver_path = "paykit/server"
network = "testnet"

[bitcoin]
network = "testnet"
[deployment]
stack_role = "proof"

[electrum]
endpoint = "ssl://electrum.example:50002"

[outbox]
poll_interval = "5s"
"#
    )
}

fn local_compose_toml() -> String {
    format!(
        r#"
[http]
listen_addr = "0.0.0.0:3001"

[locks]
trusted_public_key = "{KEY}"

[setup]
allowed_origins = ["http://localhost:8080"]

[paykit]
receiver_path = "bitkit/server"
receiver_path_priority = ["bitkit"]
network = "testnet"

[bitcoin]
network = "regtest"
[deployment]
stack_role = "proof"

[electrum]
endpoint = "tcp://fulcrum:50001"
poll_interval = "1s"

[outbox]
poll_interval = "500ms"
"#
    )
}

#[test]
fn parses_exact_local_compose_config_contract() {
    let config = Config::from_toml_and_environment(&local_compose_toml(), environment())
        .expect("local Compose configuration");

    assert_eq!(config.http.listen_addr, "0.0.0.0:3001");
    assert_eq!(config.setup.allowed_origins, vec!["http://localhost:8080"]);
    assert_eq!(config.paykit.network, PaykitNetwork::Testnet);
    assert_eq!(config.paykit.receiver_path.as_str(), "bitkit/server");
    assert_eq!(config.paykit.receiver_path_priority.len(), 1);
    assert_eq!(config.paykit.receiver_path_priority[0].as_str(), "bitkit");
    assert_eq!(
        config.deployment_invariants().bitcoin_network.as_str(),
        "regtest"
    );
    assert_eq!(
        config
            .deployment_invariants()
            .trusted_locks_key_fingerprint
            .as_bytes(),
        &[
            182, 46, 134, 127, 162, 243, 58, 254, 98, 213, 214, 177, 100, 46, 22, 33, 213, 67, 48,
            120, 70, 178, 165, 123, 137, 126, 113, 9, 25, 183, 103, 9,
        ]
    );
    assert_eq!(config.electrum.endpoint, "tcp://fulcrum:50001");
    assert_eq!(config.electrum.poll_interval, Duration::from_secs(1));
    assert_eq!(config.outbox.poll_interval, Duration::from_millis(500));
}

#[test]
fn bitcoin_creation_flag_requires_explicit_enablement() {
    let omitted = Config::from_toml_and_environment(&valid_toml(), environment())
        .expect("configuration with omitted creation flag");
    assert!(!omitted.bitcoin.creation_enabled);

    let enabled_toml = valid_toml().replace(
        "[bitcoin]\nnetwork = \"testnet\"",
        "[bitcoin]\ncreation_enabled = true\nnetwork = \"testnet\"",
    );
    let enabled = Config::from_toml_and_environment(&enabled_toml, environment())
        .expect("configuration with explicit creation enablement");
    assert!(enabled.bitcoin.creation_enabled);

    let disabled_toml = valid_toml().replace(
        "[bitcoin]\nnetwork = \"testnet\"",
        "[bitcoin]\ncreation_enabled = false\nnetwork = \"testnet\"",
    );
    let disabled = Config::from_toml_and_environment(&disabled_toml, environment())
        .expect("configuration with explicit creation disablement");
    assert!(!disabled.bitcoin.creation_enabled);
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
fn rejects_unknown_toml_fields() {
    let config = valid_toml().replace(
        "listen_addr = \"127.0.0.1:8080\"",
        "listen_addr = \"127.0.0.1:8080\"\nextra = true",
    );

    assert!(Config::from_toml_and_environment(&config, environment()).is_err());
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
        ("trusted_public_key", "trusted_public_key = \"not-a-key\""),
        ("poll_interval", "poll_interval = \"0s\""),
        ("request_timeout", "request_timeout = \"0s\""),
        ("outbox_batch_size", "batch_size = 0"),
    ] {
        let input = match name {
            "network" => valid_toml().replacen("network = \"testnet\"", replacement, 1),

            "allowed_origins" => {
                valid_toml().replace("allowed_origins = [\"https://app.example\"]", replacement)
            }
            "trusted_public_key" => {
                valid_toml().replace(&format!("trusted_public_key = \"{KEY}\""), replacement)
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

    // Retired observation-scheduler and client-retry keys fail loudly
    // instead of being silently ignored (the electrum section denies
    // unknown fields). connect_retries is retired: electrum-client call
    // retries are pinned at zero so each admitted target is exactly one
    // request charged against the sustained budget.
    for retired_key in [
        "max_target_requests = 500",
        "overrun_lane_interval_ticks = 10",
        "connect_retries = 1",
    ] {
        let input = valid_toml().replace(
            "endpoint = \"ssl://electrum.example:50002\"",
            &format!("endpoint = \"ssl://electrum.example:50002\"\n{retired_key}"),
        );
        assert!(
            Config::from_toml_and_environment(&input, environment()).is_err(),
            "retired key {retired_key} should be rejected"
        );
    }

    for invalid_receiver_path in ["/paykit/receiver", "paykit/receiver", "paykit/server/extra"] {
        let input = valid_toml().replace(
            "receiver_path = \"paykit/server\"",
            &format!("receiver_path = \"{invalid_receiver_path}\""),
        );
        assert!(
            Config::from_toml_and_environment(&input, environment()).is_err(),
            "{invalid_receiver_path} should be rejected"
        );
    }
}

#[test]
fn rejects_zero_max_history_items_per_window_with_literal_message() {
    let input = valid_toml().replace(
        "endpoint = \"ssl://electrum.example:50002\"",
        "endpoint = \"ssl://electrum.example:50002\"\nmax_history_items_per_window = 0",
    );

    let error = Config::from_toml_and_environment(&input, environment())
        .expect_err("max_history_items_per_window = 0 should be rejected");
    assert_eq!(
        error.to_string(),
        "electrum.max_history_items_per_window must be greater than zero"
    );
}

#[test]
fn rejects_zero_max_concurrent_claim_scans_with_literal_message() {
    let input = valid_toml().replace(
        "endpoint = \"ssl://electrum.example:50002\"",
        "endpoint = \"ssl://electrum.example:50002\"\nmax_concurrent_claim_scans = 0",
    );

    let error = Config::from_toml_and_environment(&input, environment())
        .expect_err("max_concurrent_claim_scans = 0 should be rejected");
    assert_eq!(
        error.to_string(),
        "electrum.max_concurrent_claim_scans must be greater than zero"
    );
}

#[test]
fn rejects_zero_claim_scan_window_deadline_with_literal_message() {
    let input = valid_toml().replace(
        "endpoint = \"ssl://electrum.example:50002\"",
        "endpoint = \"ssl://electrum.example:50002\"\nclaim_scan_window_deadline = \"0s\"",
    );

    let error = Config::from_toml_and_environment(&input, environment())
        .expect_err("claim_scan_window_deadline = \"0s\" should be rejected");
    assert_eq!(
        error.to_string(),
        "electrum.claim_scan_window_deadline must be greater than zero"
    );
}

#[test]
fn applies_documented_claim_scan_defaults_when_keys_are_absent() {
    let config = Config::from_toml_and_environment(&valid_toml(), environment())
        .expect("default claim-scan bounds");

    assert_eq!(config.electrum.max_history_items_per_window, 2_000);
    assert_eq!(
        config.electrum.claim_scan_window_deadline,
        Duration::from_secs(5)
    );
    assert_eq!(config.electrum.max_concurrent_claim_scans, 2);
}

#[test]
fn rejects_public_keys_without_the_pubky_prefix() {
    for unprefixed in [
        KEY.strip_prefix("pubky").unwrap(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let input = valid_toml().replace(
            &format!("trusted_public_key = \"{KEY}\""),
            &format!("trusted_public_key = \"{unprefixed}\""),
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
    assert_eq!(config.electrum.max_requests_per_tick, 1000);
    assert_eq!(config.electrum.max_requests_per_second, 5);
    assert_eq!(config.electrum.max_utxos_per_address, 200);
    assert_eq!(config.electrum.address_deadline, Duration::from_secs(5));
    assert_eq!(config.electrum.max_response_bytes, 1024 * 1024);
    assert_eq!(config.outbox.poll_interval, Duration::from_secs(5));
    assert_eq!(config.outbox.batch_size, 16);
    assert_eq!(config.outbox.lease_duration, Duration::from_secs(30));
    assert_eq!(config.outbox.retry_initial, Duration::from_secs(1));
    assert_eq!(config.outbox.retry_max, Duration::from_secs(5 * 60));

    assert_eq!(config.limits.request_body_bytes, 16 * 1024);
    assert_eq!(config.limits.lock_resource_bytes, 256 * 1024);
    assert_eq!(config.limits.lock_fetch_timeout, Duration::from_secs(10));
    assert_eq!(config.rate_limits.signed_requests_per_second, 100);
    assert_eq!(config.rate_limits.signed_burst, 200);
    assert_eq!(config.rate_limits.setup_per_ip_per_minute, 10);
    assert_eq!(config.rate_limits.max_pending_setup_flows, 100);
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
        config.deployment_invariants().receiver_path.as_str(),
        "paykit/server"
    );
    assert_ne!(
        config
            .deployment_invariants()
            .trusted_locks_key_fingerprint
            .as_bytes(),
        &[0; 32]
    );
}

#[test]
fn rejects_outbox_batch_size_above_the_supported_integer_range() {
    let oversized = valid_toml().replace(
        "poll_interval = \"5s\"",
        "poll_interval = \"5s\"\nbatch_size = 4294967296",
    );
    assert!(Config::from_toml_and_environment(&oversized, environment()).is_err());
}

fn electrum_toml(extra: &str) -> String {
    valid_toml().replace(
        "endpoint = \"ssl://electrum.example:50002\"",
        &format!("endpoint = \"ssl://electrum.example:50002\"\n{extra}"),
    )
}

#[test]
fn rejects_electrum_budgets_with_zero_post_probe_capacity() {
    // Every tick reserves two requests for the active probe, so the
    // effective per-tick budget —
    // min(max_requests_per_tick,
    //     max_requests_per_second * poll_interval seconds)
    // — must exceed 2, or every tick would probe successfully while
    // admitting zero address lookups forever.
    for (name, extra) in [
        // Hard-cap floor: 2 leaves nothing after the probe reservation.
        ("tick cap at floor", "max_requests_per_tick = 2"),
        ("tick cap below floor", "max_requests_per_tick = 1"),
        // Rate-derived floor: 2/s x 1s = 2 requests per tick.
        (
            "rate allowance at floor",
            "poll_interval = \"1s\"\nmax_requests_per_second = 2",
        ),
        (
            "rate allowance below floor",
            "poll_interval = \"1s\"\nmax_requests_per_second = 1",
        ),
    ] {
        let error =
            Config::from_toml_and_environment(&electrum_toml(extra), environment()).unwrap_err();
        assert!(
            error.to_string().contains("reserved probe requests"),
            "{name}: {error}"
        );
    }
}

#[test]
fn rejects_a_response_cap_below_the_64kib_floor_with_the_literal_message() {
    let error = Config::from_toml_and_environment(
        &electrum_toml("max_response_bytes = 65535"),
        environment(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "electrum.max_response_bytes must be at least 65536 bytes (64 KiB)"
    );
}

#[test]
fn accepts_a_response_cap_at_the_64kib_floor() {
    assert!(
        Config::from_toml_and_environment(
            &electrum_toml("max_response_bytes = 65536"),
            environment()
        )
        .is_ok()
    );
}

#[test]
fn accepts_a_response_cap_at_the_16mib_ceiling() {
    assert!(
        Config::from_toml_and_environment(
            &electrum_toml("max_response_bytes = 16777216"),
            environment()
        )
        .is_ok()
    );
}

#[test]
fn rejects_a_response_cap_above_the_16mib_ceiling_with_the_literal_message() {
    let error = Config::from_toml_and_environment(
        &electrum_toml("max_response_bytes = 16777217"),
        environment(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "electrum.max_response_bytes must be at most 16777216 bytes (16 MiB)"
    );
    // u64::MAX is refused too — the TOML layer rejects it before
    // validation because the `toml` crate's integer type is i64, so the
    // diagnostic is the TOML parse error rather than the range message.
    assert!(
        Config::from_toml_and_environment(
            &electrum_toml("max_response_bytes = 18446744073709551615"),
            environment()
        )
        .is_err()
    );
}

#[test]
fn the_utxo_item_cap_must_fit_inside_the_response_byte_cap() {
    // Default configuration: 200 items × the per-item wire bound +
    // envelope ≪ 1 MiB.
    assert!(Config::from_toml_and_environment(&valid_toml(), environment()).is_ok());
    // The largest item cap the 16 MiB byte-cap ceiling admits is
    // floor((ceiling − envelope) / per-item bound); one item more and
    // the byte cap would poison the item cap's own maximum reply, so
    // startup refuses the coupling with a literal diagnostic naming
    // both fields and the arithmetic.
    let max_items = (MAX_MAX_RESPONSE_BYTES - LISTUNSPENT_RESPONSE_ENVELOPE_BYTES)
        / LISTUNSPENT_ITEM_BYTES_UPPER_BOUND;
    let error = Config::from_toml_and_environment(
        &electrum_toml(&format!(
            "max_utxos_per_address = {}\nmax_response_bytes = {}",
            max_items + 1,
            MAX_MAX_RESPONSE_BYTES
        )),
        environment(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "electrum.max_utxos_per_address {} × {} B exceeds electrum.max_response_bytes {}",
            max_items + 1,
            LISTUNSPENT_ITEM_BYTES_UPPER_BOUND,
            MAX_MAX_RESPONSE_BYTES
        )
    );
    // Exactly max_items fits inside the ceiling: accepted.
    assert!(
        Config::from_toml_and_environment(
            &electrum_toml(&format!(
                "max_utxos_per_address = {}\nmax_response_bytes = {}",
                max_items, MAX_MAX_RESPONSE_BYTES
            )),
            environment(),
        )
        .is_ok()
    );
}

#[test]
fn the_utxo_item_cap_at_the_response_byte_floor_refuses_a_self_poisoning_config() {
    // At the response byte cap's 64 KiB floor the largest admitted item
    // cap is floor((floor − envelope) / per-item bound); one item more
    // would self-poison its own largest legitimate reply, so startup
    // refuses it.
    let max_items = (MIN_MAX_RESPONSE_BYTES - LISTUNSPENT_RESPONSE_ENVELOPE_BYTES)
        / LISTUNSPENT_ITEM_BYTES_UPPER_BOUND;
    let error = Config::from_toml_and_environment(
        &electrum_toml(&format!(
            "max_utxos_per_address = {}\nmax_response_bytes = {}",
            max_items + 1,
            MIN_MAX_RESPONSE_BYTES
        )),
        environment(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "electrum.max_utxos_per_address {} × {} B exceeds electrum.max_response_bytes {}",
            max_items + 1,
            LISTUNSPENT_ITEM_BYTES_UPPER_BOUND,
            MIN_MAX_RESPONSE_BYTES
        )
    );
    // The default (200 items, 1 MiB) stays accepted.
    assert!(Config::from_toml_and_environment(&valid_toml(), environment()).is_ok());
}

fn mainnet_toml(endpoint: &str) -> String {
    valid_toml()
        .replace(
            "network = \"testnet\"\n[deployment]",
            "network = \"mainnet\"\n[deployment]",
        )
        .replace(
            "endpoint = \"ssl://electrum.example:50002\"",
            &format!("endpoint = \"{endpoint}\""),
        )
}

#[test]
fn refuses_a_plaintext_electrum_endpoint_on_mainnet_with_a_literal_diagnostic() {
    let error = Config::from_toml_and_environment(
        &mainnet_toml("tcp://electrum.example:50001"),
        environment(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "bitcoin.network mainnet requires an ssl:// electrum.endpoint; \
         the tcp:// scheme is plaintext and refused"
    );
}

#[test]
fn accepts_an_ssl_electrum_endpoint_on_mainnet() {
    assert!(
        Config::from_toml_and_environment(
            &mainnet_toml("ssl://electrum.example:50002"),
            environment()
        )
        .is_ok()
    );
}

#[test]
fn refuses_a_malformed_ssl_electrum_endpoint_on_mainnet_at_config_load() {
    // `ssl://host:port/tcp://` carries a path the endpoint parser
    // refuses; delegating the pre-check to the parser refuses it at
    // config load with the same literal adapter construction would use,
    // instead of later at startup.
    let error = Config::from_toml_and_environment(
        &mainnet_toml("ssl://electrum.example:50002/tcp://"),
        environment(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "electrum endpoint scheme must be tcp:// or ssl://"
    );
}

#[test]
fn refuses_an_uppercase_ssl_scheme_on_mainnet() {
    // Fail closed on scheme case: `SSL://` is refused even though the
    // URL parser would normalize it to `ssl`.
    let error = Config::from_toml_and_environment(
        &mainnet_toml("SSL://electrum.example:50002"),
        environment(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "bitcoin.network mainnet requires an ssl:// electrum.endpoint; \
         the SSL:// scheme is plaintext and refused"
    );
}

#[test]
fn accepts_a_plaintext_electrum_endpoint_on_regtest() {
    // Local fulcrum-style endpoints have no TLS: the plaintext refusal
    // is a mainnet-only invariant.
    let regtest = local_compose_toml();
    let config = Config::from_toml_and_environment(&regtest, environment())
        .expect("regtest keeps accepting tcp:// endpoints");
    assert_eq!(config.electrum.endpoint, "tcp://fulcrum:50001");
}

#[test]
fn accepts_electrum_budgets_one_above_the_post_probe_floor() {
    for (name, extra) in [
        ("tick cap floor + 1", "max_requests_per_tick = 3"),
        (
            "rate allowance floor + 1",
            "poll_interval = \"1s\"\nmax_requests_per_second = 3",
        ),
    ] {
        assert!(
            Config::from_toml_and_environment(&electrum_toml(extra), environment()).is_ok(),
            "{name} should be accepted"
        );
    }
}

#[test]
fn rejects_zero_electrum_max_utxos_per_address_and_address_deadline() {
    for extra in ["max_utxos_per_address = 0", "address_deadline = \"0s\""] {
        assert!(
            Config::from_toml_and_environment(&electrum_toml(extra), environment()).is_err(),
            "{extra} should be rejected"
        );
    }
}

/// §B.9's `expiry_tail` feeds integer seconds to
/// `make_interval(secs => i64)`, so a value whose whole seconds exceed
/// `i64::MAX` is refused at startup — before any runtime conversion.
/// The input below is 2562047788015216 h = 9223372036854777600 s,
/// strictly greater than `i64::MAX` = 9223372036854775807 s yet inside
/// `Duration`'s `u64` range, so it parses cleanly and only the bound
/// can reject it.
#[test]
fn rejects_expiry_tail_that_does_not_fit_postgres_make_interval_seconds() {
    let input = valid_toml().replace(
        "[bitcoin]\nnetwork = \"testnet\"",
        "[bitcoin]\nnetwork = \"testnet\"\nexpiry_tail = \"2562047788015216h\"",
    );
    let error = Config::from_toml_and_environment(&input, environment()).expect_err("expiry_tail");
    match error {
        ConfigError::DurationExceedsPostgresInterval(name) => {
            assert_eq!(name, "bitcoin.expiry_tail");
        }
        other => panic!("expiry_tail: expected DurationExceedsPostgresInterval, got {other}"),
    }
}

/// `max_request_expiry` carries no interval bound: it never reaches
/// `make_interval` — it bounds `expires_at` at request time with
/// checked calendar arithmetic that fails closed as
/// `expires_at_over_maximum` (see the `validate_expires_at` unit
/// tests). Exactly `i64::MAX` seconds therefore parses and is accepted
/// at startup; a prepare under it can never panic.
#[test]
fn accepts_max_request_expiry_at_i64_max_seconds() {
    let input = valid_toml().replace(
        "[bitcoin]\nnetwork = \"testnet\"",
        "[bitcoin]\nnetwork = \"testnet\"\nmax_request_expiry = \"9223372036854775807s\"",
    );
    let config = Config::from_toml_and_environment(&input, environment())
        .expect("max_request_expiry is bounded at request time, not at startup");
    assert_eq!(
        config.bitcoin.max_request_expiry,
        Duration::from_secs(i64::MAX as u64)
    );
}

fn marketplace_toml(section: &str) -> String {
    format!("{}\n[marketplace]\n{section}\n", valid_toml())
}

#[test]
fn marketplace_single_key_form_still_parses_with_a_loggable_key_id() {
    let config = Config::from_toml_and_environment(
        &marketplace_toml(&format!("trusted_public_key = \"{KEY}\"")),
        environment(),
    )
    .expect("single-key marketplace form");

    let marketplace = config.marketplace.expect("marketplace config");
    assert_eq!(marketplace.trusted_keys.len(), 1);
    assert_eq!(marketplace.trusted_keys[0].key_id().len(), 16);
}

fn second_pubky_key() -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
    pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(signing_key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string()
}

#[test]
fn marketplace_list_form_parses_multiple_trusted_keys() {
    let second_key = second_pubky_key();
    let config = Config::from_toml_and_environment(
        &marketplace_toml(&format!(
            "trusted_public_keys = [\"{KEY}\", \"{second_key}\"]"
        )),
        environment(),
    )
    .expect("list marketplace form");

    let marketplace = config.marketplace.expect("marketplace config");
    assert_eq!(marketplace.trusted_keys.len(), 2);
    assert_ne!(
        marketplace.trusted_keys[0].key_id(),
        marketplace.trusted_keys[1].key_id()
    );
}

#[test]
fn marketplace_malformed_list_fails_fast_at_startup() {
    for section in [
        "trusted_public_keys = [\"not-a-key\"]",
        "trusted_public_keys = []",
        "trusted_public_keys = [\"pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo\", \"not-a-key\"]",
        "trusted_public_key = \"not-a-key\"",
        "",
    ] {
        let result = Config::from_toml_and_environment(&marketplace_toml(section), environment());
        assert!(result.is_err(), "{section} should be rejected");
    }
}

#[test]
fn marketplace_config_trusted_public_key_accepts_prefixed_and_rejects_bare_forms() {
    // Synthetic throwaway key derived from a clearly-fake fixed seed ([4; 32]);
    // no real seed or production key material is used anywhere here.
    let synthetic = second_pubky_key();
    assert!(synthetic.starts_with("pubky"));
    assert_eq!(synthetic.len(), 57, "pubky-prefixed form must be 57 chars");
    let bare = &synthetic["pubky".len()..];
    assert_eq!(bare.len(), 52, "bare z-base-32 form must be 52 chars");
    assert!(
        bare.chars()
            .all(|ch| "ybndrfg8ejkmcpqxot1uwisza345h769".contains(ch)),
        "bare form must stay inside the z-base-32 alphabet"
    );

    // (a) pubky-prefixed 57-char key parses in both single and list forms.
    let prefixed_single = Config::from_toml_and_environment(
        &marketplace_toml(&format!("trusted_public_key = \"{synthetic}\"")),
        environment(),
    );
    assert!(
        prefixed_single.is_ok(),
        "prefixed single form should parse: {:?}",
        prefixed_single.err()
    );
    let prefixed_list = Config::from_toml_and_environment(
        &marketplace_toml(&format!(
            "trusted_public_keys = [\"{synthetic}\", \"{KEY}\"]"
        )),
        environment(),
    );
    assert!(
        prefixed_list.is_ok(),
        "prefixed list form should parse: {:?}",
        prefixed_list.err()
    );

    // (b) bare 52-char z-base-32 key (no `pubky` prefix) does not parse.
    for section in [
        format!("trusted_public_key = \"{bare}\""),
        format!("trusted_public_keys = [\"{bare}\"]"),
        format!("trusted_public_keys = [\"{KEY}\", \"{bare}\"]"),
    ] {
        let result = Config::from_toml_and_environment(&marketplace_toml(&section), environment());
        assert!(result.is_err(), "bare form should be rejected: {section}");
    }
}

#[test]
fn marketplace_trusted_public_keys_rejects_duplicates() {
    let section = format!("trusted_public_keys = [\"{KEY}\", \"{KEY}\"]");
    let error =
        Config::from_toml_and_environment(&marketplace_toml(&section), environment()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("must not contain duplicates"), "{message}");
    // The error names the duplicate's log-safe key_id, never key material.
    let key_id = {
        let config = Config::from_toml_and_environment(
            &marketplace_toml(&format!("trusted_public_key = \"{KEY}\"")),
            environment(),
        )
        .expect("single-key form");
        config.marketplace.expect("marketplace config").trusted_keys[0]
            .key_id()
            .to_owned()
    };
    assert!(message.contains(&key_id), "{message}");
    assert!(!message.contains(KEY), "{message}");
}

#[test]
fn marketplace_single_and_list_forms_are_mutually_exclusive() {
    let section = format!("trusted_public_key = \"{KEY}\"\ntrusted_public_keys = [\"{KEY}\"]");
    let error =
        Config::from_toml_and_environment(&marketplace_toml(&section), environment()).unwrap_err();
    assert!(error.to_string().contains("mutually exclusive"), "{error}");
}

#[test]
fn deployment_stack_role_is_required_and_named_when_missing_or_unrecognised() {
    let missing_section = valid_toml().replace("[deployment]\nstack_role = \"proof\"\n", "");
    let error = Config::from_toml_and_environment(&missing_section, environment()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "[deployment] stack_role is required and must be production or proof"
    );

    let missing_value = valid_toml().replace("stack_role = \"proof\"\n", "");
    let error = Config::from_toml_and_environment(&missing_value, environment()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "[deployment] stack_role is required and must be production or proof"
    );

    let unrecognised = valid_toml().replace("stack_role = \"proof\"", "stack_role = \"staging\"");
    let error = Config::from_toml_and_environment(&unrecognised, environment()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "[deployment] stack_role must be production or proof"
    );

    let config = Config::from_toml_and_environment(&valid_toml(), environment()).unwrap();
    assert_eq!(config.deployment_invariants().stack_role.as_str(), "proof");
    let production = valid_toml()
        .replace("stack_role = \"proof\"", "stack_role = \"production\"")
        .replace(
            "network = \"testnet\"\n[deployment]",
            "network = \"mainnet\"\n[deployment]",
        );
    let config = Config::from_toml_and_environment(&production, environment()).unwrap();
    assert_eq!(
        config.deployment_invariants().stack_role.as_str(),
        "production"
    );
}

// ---------------------------------------------------------------------------
// W1.14 [sentinel] section (design §B.8.7): documented defaults, safe
// nonzero bounds, and the closed-schema contract.
// ---------------------------------------------------------------------------

fn sentinel_toml(extra: &str) -> String {
    valid_toml().replace("[outbox]", &format!("[sentinel]\n{extra}\n\n[outbox]"))
}

#[test]
fn applies_documented_sentinel_defaults_when_the_section_is_absent() {
    let config = Config::from_toml_and_environment(&valid_toml(), environment())
        .expect("the sentinel section is optional with design defaults");

    assert_eq!(config.sentinel.min_value_sats, 294);
    assert_eq!(config.sentinel.hit_count, 1);
    assert_eq!(
        config.sentinel.rescan_interval,
        Duration::from_secs(10 * 60)
    );
    assert_eq!(config.sentinel.max_age, Duration::from_secs(60 * 60));
    assert_eq!(config.sentinel.max_requests_per_tick, 1000);
    assert_eq!(config.sentinel.max_requests_per_second, 5);
    let policy = config.sentinel.policy();
    assert_eq!(policy.thresholds.min_value_sats, 294);
    assert_eq!(policy.thresholds.hit_count, 1);
    assert_eq!(policy.scan_window, 20, "the BIP44 gap window is fixed");
    assert_eq!(policy.per_tick_creator_limit(), 50);
}

#[test]
fn parses_explicit_sentinel_values() {
    let config = Config::from_toml_and_environment(
        &sentinel_toml(
            "min_value_sats = 1000\nhit_count = 3\nrescan_interval = \"15m\"\nmax_age = \"2h\"\nmax_requests_per_tick = 200\nmax_requests_per_second = 2",
        ),
        environment(),
    )
    .expect("explicit sentinel values parse");

    assert_eq!(config.sentinel.min_value_sats, 1000);
    assert_eq!(config.sentinel.hit_count, 3);
    assert_eq!(
        config.sentinel.rescan_interval,
        Duration::from_secs(15 * 60)
    );
    assert_eq!(config.sentinel.max_age, Duration::from_secs(2 * 60 * 60));
    assert_eq!(config.sentinel.max_requests_per_tick, 200);
    assert_eq!(config.sentinel.max_requests_per_second, 2);
}

#[test]
fn rejects_zero_sentinel_values_with_literal_messages() {
    for (extra, message) in [
        (
            "min_value_sats = 0",
            "sentinel.min_value_sats must be greater than zero",
        ),
        (
            "hit_count = 0",
            "sentinel.hit_count must be greater than zero",
        ),
        (
            "max_requests_per_tick = 0",
            "sentinel.max_requests_per_tick must be greater than zero",
        ),
        (
            "max_requests_per_second = 0",
            "sentinel.max_requests_per_second must be greater than zero",
        ),
        (
            "rescan_interval = \"0s\"",
            "sentinel.rescan_interval must be greater than zero",
        ),
        (
            "max_age = \"0s\"",
            "sentinel.max_age must be greater than zero",
        ),
        (
            "rescan_interval = \"500ms\"",
            "sentinel.rescan_interval must be at least one second",
        ),
    ] {
        let error = Config::from_toml_and_environment(&sentinel_toml(extra), environment())
            .expect_err(&format!("{extra} should be rejected"));
        assert_eq!(error.to_string(), message, "{extra}");
    }
}

#[test]
fn rejects_unknown_sentinel_keys_fail_closed() {
    let error = Config::from_toml_and_environment(&sentinel_toml("enabled = true"), environment())
        .expect_err("unknown sentinel keys are rejected");
    assert!(error.to_string().contains("enabled"));
}

#[test]
fn sentinel_config_is_redacted_in_the_effective_config() {
    let config =
        Config::from_toml_and_environment(&sentinel_toml("min_value_sats = 546"), environment())
            .unwrap();
    let effective = config.redacted_effective_config();

    assert!(effective.contains("SentinelConfig"), "{effective}");
    assert!(effective.contains("min_value_sats: 546"), "{effective}");
    assert!(!effective.contains(MASTER_KEY));
}
