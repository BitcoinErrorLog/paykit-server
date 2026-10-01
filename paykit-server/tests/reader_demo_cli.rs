use std::{
    fs::{self, OpenOptions},
    io::Write,
    process::{Command, Output, Stdio},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

const STATE_ENV: &str = "PAYKIT_READER_STATE_PATH";
const TESTNET_HOST_ENV: &str = "PAYKIT_READER_PUBKY_TESTNET_HOST";
const APP_ID_ENV: &str = "PAYKIT_READER_APP_ID";
const SERVER_PUBKY_ENV: &str = "PAYKIT_READER_SERVER_PUBKY";
const SERVER_PUBKY: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

fn valid_input(operation: &str) -> Value {
    json!({
        "version": 1,
        "operation": operation,
        "reader_secret": URL_SAFE_NO_PAD.encode([7; 32]),
    })
}

fn configure_valid(command: &mut Command, state_path: &str) {
    command
        .env(STATE_ENV, state_path)
        .env(TESTNET_HOST_ENV, "localhost")
        .env(APP_ID_ENV, "bitkit")
        .env(SERVER_PUBKY_ENV, SERVER_PUBKY);
}

fn run_helper(input: &Value, configure: impl FnOnce(&mut Command)) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_paykit-reader-demo"));
    command
        .env_remove(STATE_ENV)
        .env_remove(TESTNET_HOST_ENV)
        .env_remove(APP_ID_ENV)
        .env_remove(SERVER_PUBKY_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure(&mut command);
    let mut child = command.spawn().unwrap();
    serde_json::to_writer(child.stdin.as_mut().unwrap(), input).unwrap();
    child.stdin.take().unwrap().flush().unwrap();
    child.wait_with_output().unwrap()
}

fn assert_failure(output: &Output, code: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("{{\"version\":1,\"error\":\"{code}\"}}\n").as_bytes()
    );
}

#[test]
fn reader_helper_rejects_unknown_missing_and_unsupported_stdin_fields() {
    let mut unknown = valid_input("prepare");
    unknown["counterparty"] = json!("must-not-come-from-stdin");
    let mut cases = vec![
        unknown,
        json!([]),
        json!({
            "version": 2,
            "operation": "prepare",
            "reader_secret": URL_SAFE_NO_PAD.encode([7; 32]),
        }),
        json!({
            "version": 1,
            "operation": "other",
            "reader_secret": URL_SAFE_NO_PAD.encode([7; 32]),
        }),
    ];
    for field in ["version", "operation", "reader_secret"] {
        let mut missing = valid_input("prepare");
        missing.as_object_mut().unwrap().remove(field);
        cases.push(missing);
    }

    for input in cases {
        assert_failure(&run_helper(&input, |_| {}), "invalid_input");
    }
}

#[test]
fn reader_helper_requires_an_unpadded_base64url_secret_of_exactly_32_bytes() {
    for secret in [
        URL_SAFE_NO_PAD.encode([7; 31]),
        URL_SAFE_NO_PAD.encode([7; 33]),
        format!("{}=", URL_SAFE_NO_PAD.encode([7; 32])),
        "not_base64url!".to_owned(),
    ] {
        let mut input = valid_input("prepare");
        input["reader_secret"] = json!(secret);
        assert_failure(&run_helper(&input, |_| {}), "invalid_input");
    }
}

#[test]
fn reader_helper_requires_all_approved_environment_fields() {
    let state_path = format!("/tmp/paykit-reader-state-{}", uuid::Uuid::new_v4());
    for omitted in [STATE_ENV, TESTNET_HOST_ENV, APP_ID_ENV, SERVER_PUBKY_ENV] {
        let output = run_helper(&valid_input("prepare"), |command| {
            configure_valid(command, &state_path);
            command.env_remove(omitted);
        });
        assert_failure(&output, "invalid_config");
    }
}

#[test]
fn receive_without_state_and_corrupt_state_fail_closed_before_network_access() {
    let missing = format!("/tmp/paykit-reader-missing-{}", uuid::Uuid::new_v4());
    let output = run_helper(&valid_input("receive"), |command| {
        configure_valid(command, &missing);
    });
    assert_failure(&output, "invalid_state");

    let corrupt = format!("/tmp/paykit-reader-corrupt-{}", uuid::Uuid::new_v4());
    fs::write(&corrupt, [2_u8, 0, 1]).unwrap();
    let output = run_helper(&valid_input("receive"), |command| {
        configure_valid(command, &corrupt);
    });
    assert_failure(&output, "invalid_state");
    fs::remove_file(corrupt).unwrap();
}

#[test]
fn reader_helper_rejects_concurrent_state_ownership() {
    let state = format!("/tmp/paykit-reader-locked-{}", uuid::Uuid::new_v4());
    let lock_path = std::path::Path::new(&state).with_extension("lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    lock.try_lock().unwrap();

    let output = run_helper(&valid_input("receive"), |command| {
        configure_valid(command, &state);
    });

    assert_failure(&output, "state_busy");
    drop(lock);
    fs::remove_file(lock_path).unwrap();
}

#[test]
fn reader_helper_redacts_stdin_and_environment_on_failure() {
    let mut input = valid_input("prepare");
    input["reader_secret"] = json!(format!("{}=", URL_SAFE_NO_PAD.encode([7; 32])));
    let state = "/tmp/private-reader-state-value";
    let output = run_helper(&input, |command| configure_valid(command, state));
    assert_failure(&output, "invalid_input");
    let stderr = String::from_utf8(output.stderr).unwrap();
    for sensitive in [
        input["reader_secret"].as_str().unwrap(),
        state,
        SERVER_PUBKY,
    ] {
        assert!(!stderr.contains(sensitive));
    }
}
