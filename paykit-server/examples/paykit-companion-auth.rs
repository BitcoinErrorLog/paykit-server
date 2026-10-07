use std::{
    ffi::OsString,
    io::{self, Read, Write},
    process::ExitCode,
    str::FromStr,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::bip32::Xpub;
use paykit_sdk::{
    PubkyAuthCompanionClaim, PubkyLocalSecretKey, PubkySessionBootstrap, parse_pubky_auth_url,
};
use paykit_server::{
    bitkit_claim::{
        LOCAL_DEMO_CAPABILITIES, QUERY_PARAMETER, encode_unsigned_payload, parse_auth_request,
    },
    config::{BitcoinNetwork, PAYKIT_CLIENT_ID},
    real_setup::validate_xpub,
};
use serde::Deserialize;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const MAX_STDIN_BYTES: u64 = 32 * 1024;
const MAX_AUTH_URL_BYTES: usize = 16 * 1024;
const SUCCESS: &[u8] = b"{\"version\":1,\"status\":\"approved\"}\n";
const INVALID_INPUT: &[u8] = b"invalid input\n";
const AUTHENTICATION_FAILED: &[u8] = b"companion authentication failed\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    version: u8,
    auth_url: Zeroizing<String>,
    creator_secret: Zeroizing<String>,
    account_xpub: String,
    account_index: u32,
    key_generation: u64,
}

struct ApprovalRequest {
    auth_url: Zeroizing<String>,
    creator_secret: PubkyLocalSecretKey,
    claim: PubkyAuthCompanionClaim,
}

trait Approval {
    async fn approve(&self, request: ApprovalRequest) -> Result<(), ()>;
}

struct SdkApproval;

impl Approval for SdkApproval {
    async fn approve(&self, request: ApprovalRequest) -> Result<(), ()> {
        PubkySessionBootstrap::new(PAYKIT_CLIENT_ID)
            .map_err(|_| ())?
            .approve_auth_with_companion_claim(
                request.auth_url.as_str(),
                LOCAL_DEMO_CAPABILITIES,
                &request.creator_secret,
                &request.claim,
            )
            .await
            .map_err(|_| ())
    }
}

enum Failure {
    InvalidInput,
    Authentication,
}

#[tokio::main]
async fn main() -> ExitCode {
    let approval = SdkApproval;
    if run_with(
        std::env::args_os().collect(),
        io::stdin().lock(),
        io::stdout().lock(),
        io::stderr().lock(),
        &approval,
    )
    .await
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn run_with(
    args: Vec<OsString>,
    stdin: impl Read,
    mut stdout: impl Write,
    mut stderr: impl Write,
    approval: &impl Approval,
) -> bool {
    match execute(args, stdin, &mut stdout, approval).await {
        Ok(()) => true,
        Err(Failure::InvalidInput) => {
            write_coarse(&mut stderr, INVALID_INPUT);
            false
        }
        Err(Failure::Authentication) => {
            write_coarse(&mut stderr, AUTHENTICATION_FAILED);
            false
        }
    }
}

fn write_coarse(mut writer: impl Write, message: &[u8]) {
    if writer.write_all(message).is_ok() {
        let _ = writer.flush();
    }
}

async fn execute(
    args: Vec<OsString>,
    stdin: impl Read,
    stdout: &mut impl Write,
    approval: &impl Approval,
) -> Result<(), Failure> {
    if args.len() != 1 {
        return Err(Failure::InvalidInput);
    }
    let mut body = Zeroizing::new(Vec::new());
    stdin
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| Failure::InvalidInput)?;
    if body.len() as u64 > MAX_STDIN_BYTES {
        return Err(Failure::InvalidInput);
    }
    let input = serde_json::from_slice::<Input>(&body);
    body.zeroize();
    let input = input.map_err(|_| Failure::InvalidInput)?;
    let request = validate(input)?;
    approval
        .approve(request)
        .await
        .map_err(|_| Failure::Authentication)?;
    stdout
        .write_all(SUCCESS)
        .and_then(|()| stdout.flush())
        .map_err(|_| Failure::Authentication)
}

fn validate(input: Input) -> Result<ApprovalRequest, Failure> {
    if input.version != 1 || input.auth_url.len() > MAX_AUTH_URL_BYTES || input.auth_url.is_empty()
    {
        return Err(Failure::InvalidInput);
    }
    let parsed_url = Url::parse(input.auth_url.as_str()).map_err(|_| Failure::InvalidInput)?;
    if parsed_url.scheme() != "pubkyauth"
        || parsed_url.fragment().is_some()
        || parsed_url.to_string() != input.auth_url.as_str()
    {
        return Err(Failure::InvalidInput);
    }
    let auth = parse_pubky_auth_url(input.auth_url.as_str()).map_err(|_| Failure::InvalidInput)?;
    if auth.client_id != PAYKIT_CLIENT_ID || auth.capabilities != LOCAL_DEMO_CAPABILITIES {
        return Err(Failure::InvalidInput);
    }
    let companion_request = parse_auth_request(input.auth_url.as_str(), LOCAL_DEMO_CAPABILITIES)
        .map_err(|_| Failure::InvalidInput)?;

    let mut creator_secret_bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(input.creator_secret.as_bytes())
            .map_err(|_| Failure::InvalidInput)?,
    );
    let canonical_creator_secret =
        Zeroizing::new(URL_SAFE_NO_PAD.encode(creator_secret_bytes.as_slice()));
    if creator_secret_bytes.len() != 32
        || canonical_creator_secret.as_str() != input.creator_secret.as_str()
        || input.account_index >= (1 << 31)
        || input.key_generation == 0
    {
        return Err(Failure::InvalidInput);
    }
    let mut creator_secret_array = [0_u8; 32];
    creator_secret_array.copy_from_slice(&creator_secret_bytes);
    let creator_secret = PubkyLocalSecretKey::new(creator_secret_array);
    creator_secret_array.zeroize();
    creator_secret_bytes.zeroize();

    let xpub = Xpub::from_str(&input.account_xpub).map_err(|_| Failure::InvalidInput)?;
    if !input.account_xpub.starts_with("tpub") || input.account_xpub != xpub.to_string() {
        return Err(Failure::InvalidInput);
    }
    validate_xpub(
        &xpub.encode(),
        input.account_index,
        &BitcoinNetwork::Regtest,
    )
    .map_err(|_| Failure::InvalidInput)?;
    let key = creator_secret
        .derive_paykit_identity_secret_key(input.key_generation)
        .map_err(|_| Failure::InvalidInput)?;
    let payload = encode_unsigned_payload(input.account_index, &xpub.encode(), &key);
    let claim = PubkyAuthCompanionClaim::new(
        QUERY_PARAMETER,
        companion_request.claim_type(),
        payload.to_vec(),
    )
    .map_err(|_| Failure::Authentication)?;
    Ok(ApprovalRequest {
        auth_url: input.auth_url,
        creator_secret,
        claim,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        io::{Read, Write},
        net::TcpListener,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use bitcoin::{
        Network,
        bip32::{ChildNumber, Xpriv, Xpub},
        secp256k1::Secp256k1,
    };
    use paykit_server::bitkit_claim::{
        ClaimError, LOCAL_DEMO_CAPABILITIES, QUERY_PARAMETER, decrypt_and_verify,
        derive_channel_id, parse_auth_request, parse_unsigned_payload, setup_claim_selection,
    };
    use pubky::{
        Capabilities, EncryptedHttpRelayInboxChannel, GrantClaims, HttpRelayInboxChannel, Keypair,
        PubkyHttpClient,
    };
    use serde_json::{Value, json};

    use super::{Approval, ApprovalRequest, PAYKIT_CLIENT_ID, SdkApproval, run_with};

    const FIXTURE_DEADLINE: Duration = Duration::from_secs(5);

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
        let client_public_key = pubky::Keypair::from_secret(&[8; 32]).public_key();
        let selection = setup_claim_selection();
        format!(
            "pubkyauth://signin_grant?caps={LOCAL_DEMO_CAPABILITIES}&relay={relay}&secret={}&cid=app.paykit.server&cpk={}&{QUERY_PARAMETER}={selection}",
            URL_SAFE_NO_PAD.encode(auth_secret),
            client_public_key.as_inner(),
        )
    }

    fn valid_input() -> Value {
        json!({
            "version": 1,
            "auth_url": auth_url("http://127.0.0.1:1/inbox", &[9; 32]),
            "creator_secret": URL_SAFE_NO_PAD.encode([7; 32]),
            "account_xpub": account_xpub(Network::Testnet, 0).to_string(),
            "account_index": 0,
            "key_generation": 2,
        })
    }

    #[derive(Default)]
    struct RecordingApproval {
        requests: Mutex<Vec<ApprovalRequest>>,
        fail: bool,
    }

    impl RecordingApproval {
        fn failing() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                fail: true,
            }
        }
    }

    impl Approval for RecordingApproval {
        async fn approve(&self, request: ApprovalRequest) -> Result<(), ()> {
            self.requests.lock().unwrap().push(request);
            if self.fail { Err(()) } else { Ok(()) }
        }
    }

    async fn run(
        input: &Value,
        args: Vec<OsString>,
        approval: &impl Approval,
    ) -> (bool, Vec<u8>, Vec<u8>) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let success = run_with(
            args,
            serde_json::to_vec(input).unwrap().as_slice(),
            &mut stdout,
            &mut stderr,
            approval,
        )
        .await;
        (success, stdout, stderr)
    }

    async fn assert_invalid(input: &Value) {
        let approval = RecordingApproval::default();
        let (success, stdout, stderr) = run(input, vec!["helper".into()], &approval).await;
        assert!(!success);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"invalid input\n");
        assert!(approval.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn closed_v1_schema_rejects_unknown_missing_and_non_object_input() {
        let mut values = vec![json!([])];
        let mut unknown = valid_input();
        unknown["extra"] = json!(true);
        values.push(unknown);
        for field in [
            "version",
            "auth_url",
            "creator_secret",
            "account_xpub",
            "account_index",
            "key_generation",
        ] {
            let mut missing = valid_input();
            missing.as_object_mut().unwrap().remove(field);
            values.push(missing);
        }
        for value in values {
            assert_invalid(&value).await;
        }
    }

    #[tokio::test]
    async fn version_must_be_exactly_one() {
        let mut zero_generation = valid_input();
        zero_generation["key_generation"] = json!(0);
        assert_invalid(&zero_generation).await;
        for version in [0, 2] {
            let mut input = valid_input();
            input["version"] = json!(version);
            assert_invalid(&input).await;
        }
    }

    #[tokio::test]
    async fn argv_must_contain_only_the_executable() {
        let approval = RecordingApproval::default();
        for args in [vec![], vec!["helper".into(), "secret".into()]] {
            let (success, stdout, stderr) = run(&valid_input(), args, &approval).await;
            assert!(!success);
            assert!(stdout.is_empty());
            assert_eq!(stderr, b"invalid input\n");
        }
        assert!(approval.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn sdk_approval_construction_is_zero_cost() {
        let _approval = SdkApproval;
    }

    #[tokio::test]
    async fn invalid_argv_and_stdin_never_enter_approval_initialization_or_call_path() {
        struct PanicIfEntered {
            calls: AtomicUsize,
        }

        impl Approval for PanicIfEntered {
            async fn approve(&self, _: ApprovalRequest) -> Result<(), ()> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                panic!("approval path entered for invalid input");
            }
        }

        let approval = PanicIfEntered {
            calls: AtomicUsize::new(0),
        };
        for (args, stdin) in [
            (vec!["helper".into(), "unexpected".into()], b"{}".as_slice()),
            (vec!["helper".into()], b"not-json".as_slice()),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let success = run_with(args, stdin, &mut stdout, &mut stderr, &approval).await;
            assert!(!success);
            assert!(stdout.is_empty());
            assert_eq!(stderr, b"invalid input\n");
        }
        assert_eq!(approval.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn creator_secret_is_canonical_unpadded_base64url_with_32_bytes() {
        for value in [
            URL_SAFE_NO_PAD.encode([7; 31]),
            URL_SAFE_NO_PAD.encode([7; 33]),
            format!("{}=", URL_SAFE_NO_PAD.encode([7; 32])),
            "not_base64url!".to_owned(),
        ] {
            let mut input = valid_input();
            input["creator_secret"] = json!(value);
            assert_invalid(&input).await;
        }
    }

    #[tokio::test]
    async fn xpub_must_be_canonical_regtest_account_key_for_the_exact_index() {
        let secp = Secp256k1::new();
        let shallow = Xpub::from_priv(
            &secp,
            &Xpriv::new_master(Network::Testnet, &[42; 32]).unwrap(),
        );
        for value in [
            account_xpub(Network::Bitcoin, 0).to_string(),
            shallow.to_string(),
            account_xpub(Network::Testnet, 1).to_string(),
            "not-an-xpub".to_owned(),
        ] {
            let mut input = valid_input();
            input["account_xpub"] = json!(value);
            assert_invalid(&input).await;
        }

        let mut outside_range = valid_input();
        outside_range["account_index"] = json!(1_u64 << 31);
        assert_invalid(&outside_range).await;
    }

    #[tokio::test]
    async fn auth_url_requires_canonical_bounded_exact_contract() {
        let valid = valid_input();
        let url = valid["auth_url"].as_str().unwrap();
        let selection = setup_claim_selection();
        let cases = [
            url.replacen("pubkyauth", "https", 1),
            url.replace("cid=app.paykit.server", "cid=other.paykit.server"),
            url.replace(LOCAL_DEMO_CAPABILITIES, "/pub/paykit/v0/bitkit/server/:rw"),
            url.replace(&selection, "other-claim-v1"),
            url.replace(&selection, "watch-only-account-v1"),
            url.replace(&selection, "paykit-access-v1"),
            url.replace(&selection, "paykit-access-v1..watch-only-account-v1"),
            url.replace(
                &selection,
                "paykit-access-v1.watch-only-account-v1.paykit-access-v1",
            ),
            format!("{url}&{QUERY_PARAMETER}={selection}"),
            format!("{url}#fragment"),
            format!("{url}&padding={}", "a".repeat(16 * 1024)),
        ];
        for (case, url) in cases.into_iter().enumerate() {
            let mut input = valid_input();
            input["auth_url"] = json!(url);
            let approval = RecordingApproval::default();
            let (success, stdout, stderr) = run(&input, vec!["helper".into()], &approval).await;
            assert!(!success, "case {case}");
            assert!(stdout.is_empty());
            assert_eq!(stderr, b"invalid input\n");
            assert!(approval.requests.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn accepted_provenance_gap_does_not_bind_cpk_relay_or_auth_secret_to_server_state() {
        for url in [
            auth_url("http://127.0.0.1:2345/other", &[9; 32]),
            auth_url("http://127.0.0.1:3456/inbox", &[10; 32]),
            auth_url("http://127.0.0.1:4567/inbox", &[11; 32]).replace(
                &pubky::Keypair::from_secret(&[8; 32])
                    .public_key()
                    .to_string(),
                &pubky::Keypair::from_secret(&[12; 32])
                    .public_key()
                    .to_string(),
            ),
        ] {
            let mut input = valid_input();
            input["auth_url"] = json!(url);
            let approval = RecordingApproval::default();
            let (success, stdout, stderr) = run(&input, vec!["helper".into()], &approval).await;
            assert!(success);
            assert_eq!(stdout, b"{\"version\":1,\"status\":\"approved\"}\n");
            assert!(stderr.is_empty());
            assert_eq!(approval.requests.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn success_is_exact_and_uses_existing_claim_payload_helpers() {
        let input = valid_input();
        let approval = RecordingApproval::default();
        let (success, stdout, stderr) = run(&input, vec!["helper".into()], &approval).await;
        assert!(success);
        assert_eq!(stdout, b"{\"version\":1,\"status\":\"approved\"}\n");
        assert!(stderr.is_empty());
        let requests = approval.requests.lock().unwrap();
        let request = &requests[0];
        assert_eq!(request.auth_url.as_str(), input["auth_url"]);
        assert!(
            request
                .auth_url
                .contains("x-bitkit-claim=paykit-access-v1.watch-only-account-v1")
        );
        assert_eq!(request.claim.unsigned_payload().len(), 124);
        let parsed = parse_unsigned_payload(request.claim.unsigned_payload()).unwrap();
        assert_eq!(parsed.account_index, 0);
        assert_eq!(parsed.paykit_identity_secret_key.key_generation(), 2);
        assert_eq!(
            parsed.serialized_xpub,
            account_xpub(Network::Testnet, 0).encode()
        );
    }

    #[tokio::test]
    async fn approval_failure_is_coarse_and_redacts_all_sensitive_inputs() {
        let input = valid_input();
        let approval = RecordingApproval::failing();
        let (success, stdout, stderr) = run(&input, vec!["helper".into()], &approval).await;
        assert!(!success);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"companion authentication failed\n");
        for sensitive in ["auth_url", "creator_secret", "account_xpub"] {
            assert!(!String::from_utf8_lossy(&stderr).contains(input[sensitive].as_str().unwrap()));
        }
    }

    #[tokio::test]
    async fn broken_success_stdout_maps_to_coarse_authentication_failure() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("closed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("closed"))
            }
        }
        let approval = RecordingApproval::default();
        let mut stderr = Vec::new();
        let success = run_with(
            vec!["helper".into()],
            serde_json::to_vec(&valid_input()).unwrap().as_slice(),
            Broken,
            &mut stderr,
            &approval,
        )
        .await;
        assert!(!success);
        assert_eq!(stderr, b"companion authentication failed\n");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn canonical_sdk_delivers_both_permission_list_orders_with_exact_binding() {
        for selection in [
            setup_claim_selection(),
            "watch-only-account-v1.paykit-access-v1".into(),
        ] {
            assert_sdk_delivers_selection(&selection).await;
        }
    }

    async fn assert_sdk_delivers_selection(selection: &str) {
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let inbox = relay.local_url().join("inbox").unwrap();
        let auth_secret = [9; 32];
        let mut input = valid_input();
        input["auth_url"] = json!(
            auth_url(inbox.as_str(), &auth_secret).replace(&setup_claim_selection(), selection)
        );
        let request =
            parse_auth_request(input["auth_url"].as_str().unwrap(), LOCAL_DEMO_CAPABILITIES)
                .unwrap();
        assert_eq!(request.claim_type(), selection);

        let (success, stdout, stderr) = run(&input, vec!["helper".into()], &SdkApproval).await;

        assert!(success, "{}", String::from_utf8_lossy(&stderr));
        assert_eq!(stdout, b"{\"version\":1,\"status\":\"approved\"}\n");
        assert!(stderr.is_empty());

        let client = PubkyHttpClient::new().unwrap();
        let claim_channel =
            HttpRelayInboxChannel::new(inbox.clone(), derive_channel_id(&request)).unwrap();
        let encrypted_claim = claim_channel
            .poll(&client, Some(Duration::from_secs(1)))
            .await
            .unwrap()
            .unwrap();
        let creator = Keypair::from_secret(&[7; 32]);
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(creator.public_key().as_bytes()).unwrap();
        let claim = decrypt_and_verify(&encrypted_claim, &request, &verifying_key).unwrap();
        assert_eq!(claim.account_index, 0);
        assert_eq!(
            claim.serialized_xpub,
            account_xpub(Network::Testnet, 0).encode()
        );
        assert_eq!(
            claim.paykit_identity_secret_key,
            paykit_sdk::PubkyLocalSecretKey::new([7; 32])
                .derive_paykit_identity_secret_key(2)
                .unwrap()
        );
        let reordered = selection.split('.').rev().collect::<Vec<_>>().join(".");
        let changed_url = input["auth_url"]
            .as_str()
            .unwrap()
            .replace(selection, &reordered);
        let changed_request = parse_auth_request(&changed_url, LOCAL_DEMO_CAPABILITIES).unwrap();
        assert_ne!(
            derive_channel_id(&request),
            derive_channel_id(&changed_request)
        );
        assert_eq!(
            decrypt_and_verify(&encrypted_claim, &changed_request, &verifying_key),
            Err(ClaimError::AuthenticationFailed)
        );

        let auth_channel = EncryptedHttpRelayInboxChannel::new(inbox, auth_secret).unwrap();
        let grant_bytes = auth_channel
            .poll(&client, Some(Duration::from_secs(1)))
            .await
            .unwrap()
            .unwrap();
        let grant = GrantClaims::decode(std::str::from_utf8(&grant_bytes).unwrap()).unwrap();
        assert_eq!(grant.iss, creator.public_key());
        assert_eq!(grant.client_id.as_str(), PAYKIT_CLIENT_ID);
        assert_eq!(
            Capabilities::from(grant.caps).to_string(),
            LOCAL_DEMO_CAPABILITIES
        );
        assert_eq!(grant.cnf, Keypair::from_secret(&[8; 32]).public_key());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn canonical_sdk_attempts_encrypted_companion_delivery_before_grant_approval() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let relay = format!("http://{}/inbox", listener.local_addr().unwrap());
        let request =
            parse_auth_request(&auth_url(&relay, &[9; 32]), LOCAL_DEMO_CAPABILITIES).unwrap();
        let expected_channel = derive_channel_id(&request);
        let fixture = std::thread::spawn(move || {
            let started = Instant::now();
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(value) => break value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            started.elapsed() < FIXTURE_DEADLINE,
                            "fixture accept timed out"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(FIXTURE_DEADLINE)).unwrap();
            let mut request_line = Vec::new();
            loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request_line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            String::from_utf8(request_line).unwrap()
        });
        let mut input = valid_input();
        input["auth_url"] = json!(auth_url(&relay, &[9; 32]));
        let (success, stdout, stderr) = run(&input, vec!["helper".into()], &SdkApproval).await;
        let first_request = fixture.join().unwrap();
        assert!(!success);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"companion authentication failed\n");
        assert!(first_request.contains(&expected_channel), "{first_request}");
    }
}
