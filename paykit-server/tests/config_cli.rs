use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const DATABASE_URL: &str = "postgres://paykit:deployment-check-secret@127.0.0.1:1/paykit";

fn config(client_id: bool) -> String {
    format!(
        r#"[http]
listen_addr = "127.0.0.1:3001"
[signed_services]
trusted_public_keys = ["{KEY}"]
[setup]
allowed_origins = ["http://127.0.0.1:8080"]
[paykit]
{}app_id = "paykit-server"
network = "mainnet"
[bitcoin]
network = "regtest"
[electrum]
endpoint = "tcp://127.0.0.1:50001"
[outbox]
poll_interval = "5s"
"#,
        if client_id {
            "client_id = \"app.paykit.server\"\n"
        } else {
            ""
        }
    )
}

fn run_check(source: &str, extra_args: &[&str]) -> std::process::Output {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("paykit-check-config-{nonce}.toml"));
    fs::write(&path, source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_paykit-server"))
        .arg("--check-config")
        .args(extra_args)
        .env("PAYKIT_CONFIG", &path)
        .env("PAYKIT_DATABASE_URL", DATABASE_URL)
        .env("PAYKIT_MASTER_KEY", MASTER_KEY)
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();
    output
}

#[test]
fn check_config_validates_without_connecting_to_postgres() {
    let output = run_check(&config(true), &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "configuration valid"
    );
}

#[test]
fn checked_in_example_config_is_valid() {
    let source = include_str!("../../config/paykit-server.example.toml").replace(
        "# trusted_public_keys = [\"pubky<locks-key>\", \"pubky<marketplace-key>\"]",
        &format!("trusted_public_keys = [\"{KEY}\"]"),
    );
    let output = run_check(&source, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_config_reports_missing_client_id_without_secrets() {
    let output = run_check(&config(false), &[]);
    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("paykit.client_id"), "{combined}");
    assert!(!combined.contains(MASTER_KEY));
    assert!(!combined.contains(DATABASE_URL));
    assert!(!combined.contains("deployment-check-secret"));
}

#[test]
fn unknown_arguments_fail_closed() {
    let output = run_check(&config(true), &["--unexpected"]);
    assert!(!output.status.success());
}

#[test]
fn check_config_rejects_runtime_invalid_bind_and_electrum_values() {
    for (source, expected) in [
        (
            config(true).replace("127.0.0.1:3001", "not-a-socket-address"),
            "http.listen_addr",
        ),
        (
            config(true).replace(
                "listen_addr = \"127.0.0.1:3001\"",
                "listen_addr = \"127.0.0.1:3001\"\ntrusted_proxy_hops = 9",
            ),
            "http.trusted_proxy_hops",
        ),
        (
            config(true).replace(
                "tcp://127.0.0.1:50001",
                "tcp://127.0.0.1:50001/path?query=yes",
            ),
            "electrum.endpoint",
        ),
        (
            config(true).replace("tcp://127.0.0.1:50001", "TCP://127.0.0.1:50001"),
            "electrum.endpoint",
        ),
        (
            config(true).replace("tcp://127.0.0.1:50001", "tcp://127.0.0.1:50001/"),
            "electrum.endpoint",
        ),
        (
            config(true).replace("tcp://127.0.0.1:50001", "tcp://127.0.0.1:0"),
            "electrum.endpoint",
        ),
        (
            config(true).replace("tcp://127.0.0.1:50001", "ssl://[::1]:50002"),
            "electrum.endpoint",
        ),
        (
            config(true).replace("tcp://127.0.0.1:50001", "ssl://-bad.example:50002"),
            "electrum.endpoint",
        ),
    ] {
        let output = run_check(&source, &[]);
        assert!(!output.status.success());
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(combined.contains(expected), "{combined}");
    }
}

#[test]
fn check_config_rejects_sqlx_invalid_database_options() {
    for database_url in [
        "postgres://paykit@127.0.0.1:5432/paykit?port=bogus",
        "postgres://paykit@127.0.0.1:5432/paykit?sslmode=bogus",
        "postgres://paykit@127.0.0.1:5432/paykit?sslmod=verify-full",
    ] {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("paykit-check-config-{nonce}.toml"));
        fs::write(&path, config(true)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_paykit-server"))
            .arg("--check-config")
            .env("PAYKIT_CONFIG", &path)
            .env("PAYKIT_DATABASE_URL", database_url)
            .env("PAYKIT_MASTER_KEY", MASTER_KEY)
            .output()
            .unwrap();
        fs::remove_file(path).unwrap();
        assert!(!output.status.success());
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(combined.contains("PAYKIT_DATABASE_URL"), "{combined}");
        assert!(!combined.contains(database_url));
    }
}

#[test]
fn check_config_rejects_pending_setup_capacity_above_tokio_limit() {
    let source = format!(
        "{}\n[rate_limits]\nmax_pending_setup_flows = {}\n",
        config(true),
        tokio::sync::Semaphore::MAX_PERMITS + 1
    );
    let output = run_check(&source, &[]);
    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("rate_limits.max_pending_setup_flows"),
        "{combined}"
    );
}

#[test]
fn malformed_toml_error_does_not_echo_endpoint_source() {
    let sentinel = "tcp://endpoint-secret.example:50001";
    let source = config(true).replace(
        "endpoint = \"tcp://127.0.0.1:50001\"",
        &format!("endpoint = \"{sentinel}"),
    );
    let output = run_check(&source, &[]);
    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("configuration TOML is invalid"));
    assert!(!combined.contains(sentinel));
}
