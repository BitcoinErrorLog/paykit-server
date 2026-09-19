use std::{
    io::{self, Read, Write},
    net::TcpListener,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use paykit_sdk::{PaykitSdkError, PubkySessionBootstrap, ReceiverNoiseSecretKey};
use paykit_server::bitkit_claim::{
    CLAIM_TYPE, LOCAL_DEMO_CAPABILITIES, QUERY_PARAMETER, UNSIGNED_PAYLOAD_LEN, decrypt_and_verify,
    derive_channel_id, encode_unsigned_payload, parse_unsigned_payload,
};
use paykit_server::bitkit_setup::append_bitkit_claim;
use pubky::{HttpRelayInboxChannel, PubkyHttpClient};
use serde_json::{Value, json};

const HELPER_DEADLINE: Duration = Duration::from_secs(5);
const FIXTURE_DEADLINE: Duration = Duration::from_secs(4);
const RELAY_TASK_DEADLINE: Duration = Duration::from_secs(7);
const HELPER_TIMEOUT: &str = "helper process exceeded test deadline";

fn account_xpub(network: Network, account_index: u32) -> Xpub {
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(network, &[42; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(account_index).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account)
}

fn auth_url(relay: &str, auth_secret: &[u8; 32]) -> String {
    format!(
        "pubkyauth://signin_grant?caps={LOCAL_DEMO_CAPABILITIES}&relay={relay}&secret={}&cid=paykit.test&cpk=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo&{QUERY_PARAMETER}={CLAIM_TYPE}",
        URL_SAFE_NO_PAD.encode(auth_secret)
    )
}

fn valid_input(relay: &str) -> Value {
    json!({
        "version": 1,
        "auth_url": auth_url(relay, &[9; 32]),
        "creator_secret": URL_SAFE_NO_PAD.encode([7; 32]),
        "account_xpub": account_xpub(Network::Testnet, 0).to_string(),
        "account_index": 0,
    })
}

fn spawn_helper() -> Child {
    Command::new(env!("CARGO_BIN_EXE_paykit-companion-auth"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_with_output_deadline(mut child: Child, deadline: Duration) -> Result<Output, &'static str> {
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            return Err(HELPER_TIMEOUT);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout).unwrap();
    }
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_end(&mut stderr).unwrap();
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn run_helper(input: &Value) -> Output {
    let mut child = spawn_helper();
    serde_json::to_writer(child.stdin.as_mut().unwrap(), input).unwrap();
    child.stdin.take().unwrap().flush().unwrap();
    wait_with_output_deadline(child, HELPER_DEADLINE).expect(HELPER_TIMEOUT)
}

#[test]
fn helper_deadline_kills_and_reaps_without_waiting_for_product_io() {
    let child = spawn_helper();

    let error = wait_with_output_deadline(child, Duration::ZERO).unwrap_err();

    assert_eq!(error, HELPER_TIMEOUT);
}

#[test]
fn unsigned_payload_encoder_matches_the_canonical_84_byte_parser_fixture() {
    let account_index = 7;
    let serialized_xpub = account_xpub(Network::Testnet, account_index).encode();

    let encoded = encode_unsigned_payload(account_index, &serialized_xpub);

    assert_eq!(encoded.len(), UNSIGNED_PAYLOAD_LEN);
    assert_eq!(encoded[0], 1);
    assert_eq!(&encoded[1..5], &account_index.to_be_bytes());
    assert_eq!(encoded[5], 0);
    assert_eq!(&encoded[6..], &serialized_xpub);
    let parsed = parse_unsigned_payload(&encoded).unwrap();
    assert_eq!(parsed.account_index, account_index);
    assert_eq!(parsed.serialized_xpub, serialized_xpub);
}

#[test]
fn helper_rejects_unknown_missing_fields_and_non_object_input() {
    let mut unknown = valid_input("http://127.0.0.1:1/inbox");
    unknown["extra"] = json!(true);
    let mut invalid = vec![unknown, json!([])];
    for field in [
        "version",
        "auth_url",
        "creator_secret",
        "account_xpub",
        "account_index",
    ] {
        let mut missing = valid_input("http://127.0.0.1:1/inbox");
        missing.as_object_mut().unwrap().remove(field);
        invalid.push(missing);
    }

    for input in invalid {
        let output = run_helper(&input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).unwrap(), "invalid input\n");
    }
}

#[test]
fn helper_requires_protocol_version_one() {
    for version in [0, 2] {
        let mut input = valid_input("http://127.0.0.1:1/inbox");
        input["version"] = json!(version);
        let output = run_helper(&input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).unwrap(), "invalid input\n");
    }

    let output = run_helper(&valid_input("http://127.0.0.1:1/inbox"));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "companion authentication failed\n"
    );
}

#[test]
fn helper_requires_an_unpadded_base64url_secret_of_exactly_32_bytes() {
    for creator_secret in [
        URL_SAFE_NO_PAD.encode([7; 31]),
        URL_SAFE_NO_PAD.encode([7; 33]),
        format!("{}=", URL_SAFE_NO_PAD.encode([7; 32])),
        "not_base64url!".to_owned(),
    ] {
        let mut input = valid_input("http://127.0.0.1:1/inbox");
        input["creator_secret"] = json!(creator_secret);
        let output = run_helper(&input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).unwrap(), "invalid input\n");
    }
}

#[test]
fn helper_rejects_non_tpub_non_account_and_mismatched_account_keys() {
    let secp = Secp256k1::new();
    let testnet_master = Xpub::from_priv(
        &secp,
        &Xpriv::new_master(Network::Testnet, &[42; 32]).unwrap(),
    );
    let invalid = [
        account_xpub(Network::Bitcoin, 0).to_string(),
        testnet_master.to_string(),
        account_xpub(Network::Testnet, 1).to_string(),
        "not-an-xpub".to_owned(),
    ];

    for account_xpub in invalid {
        let mut input = valid_input("http://127.0.0.1:1/inbox");
        input["account_xpub"] = json!(account_xpub);
        let output = run_helper(&input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).unwrap(), "invalid input\n");
    }
}

#[test]
fn helper_rejects_account_indexes_outside_the_bip32_hardened_index_range() {
    let mut input = valid_input("http://127.0.0.1:1/inbox");
    input["account_index"] = json!(1_u64 << 31);

    let output = run_helper(&input);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "invalid input\n");
}

#[test]
fn helper_failure_is_coarse_and_redacts_every_sensitive_input() {
    let input = valid_input("http://127.0.0.1:1/inbox/private-channel");

    let output = run_helper(&input);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr, "companion authentication failed\n");
    for sensitive in [
        input["auth_url"].as_str().unwrap(),
        input["creator_secret"].as_str().unwrap(),
        input["account_xpub"].as_str().unwrap(),
        "private-channel",
    ] {
        assert!(!stderr.contains(sensitive));
    }
}

#[test]
fn helper_attempts_the_companion_channel_before_normal_auth_approval() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let relay = format!("http://{}/inbox", listener.local_addr().unwrap());
    let expected_channel = derive_channel_id(&[9; 32]);
    let server = std::thread::spawn(move || {
        let started = Instant::now();
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if started.elapsed() >= FIXTURE_DEADLINE {
                        return Err("ordering fixture accept exceeded test deadline");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err("ordering fixture accept failed"),
            }
        };
        stream.set_nonblocking(true).unwrap();
        let mut request_line = Vec::new();
        loop {
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(0) => return Err("ordering fixture request ended before request line"),
                Ok(_) => {
                    request_line.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if started.elapsed() >= FIXTURE_DEADLINE {
                        return Err("ordering fixture read exceeded test deadline");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err("ordering fixture read failed"),
            }
        }
        stream
            .write_all(
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .map_err(|_| "ordering fixture response failed")?;
        String::from_utf8(request_line).map_err(|_| "ordering fixture request line was not UTF-8")
    });

    let output = run_helper(&valid_input(&relay));
    let first_request = server
        .join()
        .unwrap()
        .expect("ordering fixture failed without sensitive details");

    assert!(!output.status.success());
    assert!(first_request.contains(&expected_channel), "{first_request}");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "companion authentication failed\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn helper_reports_coarse_failure_without_panicking_when_success_stdout_is_broken() {
    let relay = http_relay::HttpRelay::builder()
        .http_port(0)
        .run()
        .await
        .unwrap();
    let inbox = relay.local_url().join("inbox").unwrap();
    let input = valid_input(inbox.as_str());
    let sensitive = [
        input["auth_url"].as_str().unwrap().to_owned(),
        input["creator_secret"].as_str().unwrap().to_owned(),
        input["account_xpub"].as_str().unwrap().to_owned(),
    ];

    let output = tokio::time::timeout(
        RELAY_TASK_DEADLINE,
        tokio::task::spawn_blocking(move || {
            let mut child = spawn_helper();
            drop(child.stdout.take());
            serde_json::to_writer(child.stdin.as_mut().unwrap(), &input).unwrap();
            child.stdin.take().unwrap().flush().unwrap();
            wait_with_output_deadline(child, HELPER_DEADLINE).expect(HELPER_TIMEOUT)
        }),
    )
    .await
    .expect("relay test task exceeded test deadline")
    .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr, "companion authentication failed\n");
    assert!(!stderr.contains("panicked"), "{stderr}");
    for sensitive in sensitive {
        assert!(!stderr.contains(&sensitive));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn helper_delivers_the_exact_companion_envelope_and_rc55_consumes_the_grant() {
    let relay = http_relay::HttpRelay::builder()
        .http_port(0)
        .run()
        .await
        .unwrap();
    let inbox = relay.local_url().join("inbox").unwrap();
    let bootstrap = PubkySessionBootstrap::new("paykit.test")
        .unwrap()
        .with_auth_relay(inbox.as_str())
        .unwrap();
    let request = bootstrap
        .start_sign_in_auth(LOCAL_DEMO_CAPABILITIES)
        .await
        .unwrap();
    let authorization_url =
        append_bitkit_claim(request.authorization_url(), LOCAL_DEMO_CAPABILITIES).unwrap();
    let url = url::Url::parse(&authorization_url).unwrap();
    let auth_secret: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            url.query_pairs()
                .find(|(key, _)| key == "secret")
                .unwrap()
                .1
                .as_bytes(),
        )
        .unwrap()
        .try_into()
        .unwrap();
    let mut input = valid_input(inbox.as_str());
    input["auth_url"] = json!(authorization_url);

    let output = tokio::time::timeout(
        RELAY_TASK_DEADLINE,
        tokio::task::spawn_blocking(move || run_helper(&input)),
    )
    .await
    .expect("relay test task exceeded test deadline")
    .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(output.stdout, b"{\"version\":1,\"status\":\"approved\"}\n");
    assert!(output.stderr.is_empty());

    let client = PubkyHttpClient::new().unwrap();
    let claim_channel = HttpRelayInboxChannel::new(inbox, derive_channel_id(&auth_secret)).unwrap();
    let encrypted_claim = claim_channel
        .poll(&client, Some(Duration::from_secs(1)))
        .await
        .unwrap()
        .unwrap();
    let creator = pubky::Keypair::from_secret(&[7; 32]);
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(creator.public_key().as_bytes()).unwrap();
    let claim = decrypt_and_verify(&encrypted_claim, &auth_secret, &verifying_key).unwrap();
    assert_eq!(claim.account_index, 0);
    assert_eq!(
        claim.serialized_xpub,
        account_xpub(Network::Testnet, 0).encode()
    );

    let result = request
        .complete(
            None,
            ReceiverNoiseSecretKey::random(),
            LOCAL_DEMO_CAPABILITIES,
        )
        .await;
    // The real rc55 completer consumed and verified the relay approval before
    // reaching the expected homeserver lookup failure: this fixture identity
    // is deliberately not registered and this test starts no homeserver.
    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
}
