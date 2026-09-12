use std::{
    io::{self, Write},
    process::ExitCode,
    str::FromStr,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::bip32::Xpub;
use paykit_sdk::{PubkyAuthCompanionClaim, PubkyLocalSecretKey, PubkySessionBootstrap};
use paykit_server::{
    bitkit_claim::{CLAIM_TYPE, LOCAL_DEMO_CAPABILITIES, QUERY_PARAMETER, encode_unsigned_payload},
    config::{BitcoinNetwork, StackRole},
    real_setup::validate_xpub,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    version: u8,
    auth_url: String,
    creator_secret: String,
    account_xpub: String,
    account_index: u32,
}

enum Failure {
    InvalidInput,
    Authentication,
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = run().await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::InvalidInput) => {
            write_failure(b"invalid input\n");
            ExitCode::FAILURE
        }
        Err(Failure::Authentication) => {
            write_failure(b"companion authentication failed\n");
            ExitCode::FAILURE
        }
    }
}

fn write_failure(message: &[u8]) {
    let mut stderr = io::stderr().lock();
    if stderr.write_all(message).is_ok() {
        let _ = stderr.flush();
    }
}

async fn run() -> Result<(), Failure> {
    if std::env::args_os().len() != 1 {
        return Err(Failure::InvalidInput);
    }
    let input: Input =
        serde_json::from_reader(io::stdin().lock()).map_err(|_| Failure::InvalidInput)?;
    if input.version != 1 {
        return Err(Failure::InvalidInput);
    }
    let creator_secret: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&input.creator_secret)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Failure::InvalidInput)?;
    if input.account_index >= (1 << 31) {
        return Err(Failure::InvalidInput);
    }
    let xpub = Xpub::from_str(&input.account_xpub).map_err(|_| Failure::InvalidInput)?;
    if !input.account_xpub.starts_with("tpub") || input.account_xpub != xpub.to_string() {
        return Err(Failure::InvalidInput);
    }
    // A local CLI encoding helper, not a claim path: validate under the proof
    // role so the deny-list (a server-side claim gate) does not apply here.
    validate_xpub(
        &xpub.encode(),
        input.account_index,
        &BitcoinNetwork::Regtest,
        StackRole::Proof,
    )
    .map_err(|_| Failure::InvalidInput)?;
    let payload = encode_unsigned_payload(input.account_index, &xpub.encode());
    let claim = PubkyAuthCompanionClaim::new(QUERY_PARAMETER, CLAIM_TYPE, payload.to_vec())
        .map_err(|_| Failure::Authentication)?;
    let bootstrap = PubkySessionBootstrap::new().map_err(|_| Failure::Authentication)?;
    bootstrap
        .approve_auth_with_companion_claim(
            &input.auth_url,
            LOCAL_DEMO_CAPABILITIES,
            &PubkyLocalSecretKey::new(creator_secret),
            &claim,
        )
        .await
        .map_err(|_| Failure::Authentication)?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(b"{\"version\":1,\"status\":\"approved\"}\n")
        .and_then(|()| stdout.flush())
        .map_err(|_| Failure::Authentication)?;
    Ok(())
}
