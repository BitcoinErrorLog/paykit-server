use std::{fs, process::Command};

const KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const INVARIANT_REFUSAL: &str =
    "deployment invariant refused: stack_role=production requires bitcoin.network=mainnet";

fn fixture(network: &str, deployment: &str) -> String {
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
network = "{network}"

[deployment]
{deployment}

[electrum]
endpoint = "ssl://electrum.example:50002"

[outbox]
poll_interval = "5s"
"#
    )
}

fn run(source: &str) -> std::process::Output {
    let path = std::env::temp_dir().join(format!(
        "paykit-check-config-{}-{}.toml",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::write(&path, source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_paykit-server"))
        .arg("--check-config")
        .arg(&path)
        .env(
            "PAYKIT_DATABASE_URL",
            "postgres://paykit:secret@localhost/paykit",
        )
        .env("PAYKIT_MASTER_KEY", MASTER_KEY)
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();
    output
}

#[test]
fn rendered_mainnet_production_config_passes_without_connecting() {
    let output = run(&fixture("mainnet", "stack_role = \"production\""));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "config ok: network=mainnet stack_role=production\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn unknown_deployment_key_is_refused_with_deny_unknown_fields() {
    let output = run(&fixture(
        "mainnet",
        "stack_role = \"production\"\nunknown_gate = true",
    ));
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("unknown field `unknown_gate`"), "{stderr}");
}

#[test]
fn production_regtest_is_refused_with_the_deployment_invariant_line() {
    let output = run(&fixture("regtest", "stack_role = \"production\""));
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("{INVARIANT_REFUSAL}\n")
    );
}
