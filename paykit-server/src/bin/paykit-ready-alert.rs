use std::{
    collections::BTreeMap,
    env, fs,
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const DEFAULT_URL: &str = "https://paykit-shop.pubky.app/health/ready";
const WINDOW_SECONDS: u64 = 5 * 60;
const CRITICAL_AGE_SECONDS: i64 = 900;
const EXPECTED_MAX_ATTEMPTS: u32 = 20;
const EXPECTED_MAX_AGE_SECONDS: u64 = 3600;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    status: String,
    #[allow(dead_code)] // Parsed to enforce the complete public readiness contract.
    stack_id: String,
    postgres: String,
    electrum: Electrum,
    bitcoin_creation_enabled: bool,
    bitcoin_offer_available: bool,
    #[allow(dead_code)] // Parsed to enforce the complete public readiness contract.
    electrum_tip_height: Option<u32>,
    #[allow(dead_code)] // Parsed to enforce the complete public readiness contract.
    electrum_tip_age_seconds: Option<u64>,
    paykit_delivery: String,
    outbox: String,
    outbox_terminal_failure_count: i64,
    outbox_oldest_terminal_failure_age_seconds: Option<i64>,
    outbox_terminal_failures_by_class: BTreeMap<String, i64>,
    outbox_link_establishment_max_attempts: u32,
    outbox_link_establishment_max_age_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Electrum {
    state: String,
    available: bool,
    #[allow(dead_code)] // Parsed to enforce the complete public readiness contract.
    tip_height: Option<u32>,
    #[allow(dead_code)] // Parsed to enforce the complete public readiness contract.
    tip_age_secs: Option<u64>,
    #[allow(dead_code)] // Parsed to enforce the complete public readiness contract.
    last_probe_at: Option<u64>,
    genesis_ok: bool,
}

#[derive(Default, Deserialize, Serialize)]
struct State {
    samples: Vec<Sample>,
}

#[derive(Deserialize, Serialize)]
struct Sample {
    at: u64,
    terminal_count: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Ok,
    Warning,
    Critical,
    Failure,
}

impl Decision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Failure => "failure",
        }
    }

    const fn exit_code(self) -> u8 {
        match self {
            Self::Ok | Self::Warning => 0,
            Self::Critical | Self::Failure => 1,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut url = DEFAULT_URL.to_owned();
    let mut state_file = PathBuf::from("/data/paykit-ready-alert-state.json");
    let mut check_only = false;
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return usage();
                };
                url = value.clone();
            }
            "--state-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return usage();
                };
                state_file = value.into();
            }
            "--check-only" => check_only = true,
            _ => return usage(),
        }
        index += 1;
    }

    let now = match unix_seconds() {
        Some(now) => now,
        None => return ExitCode::from(1),
    };
    let mut state = load_state(&state_file).unwrap_or_default();
    let decision = match fetch_and_evaluate(&url, &mut state, now).await {
        Ok(decision) => decision,
        Err(()) => Decision::Failure,
    };
    if !check_only && save_state(&state_file, &state).is_err() {
        eprintln!("ready alert state unavailable");
        return ExitCode::from(1);
    }

    // Deliberately static: no endpoint, status body, identifiers, or secrets.
    println!("paykit ready alert decision={}", decision.as_str());
    if let Ok(webhook) = env::var("ALERT_WEBHOOK_URL") {
        if !webhook.is_empty() && decision != Decision::Ok {
            if deliver(&webhook, decision).await.is_err() {
                eprintln!("ready alert delivery failed");
                return ExitCode::from(1);
            }
        }
    } else {
        println!("no webhook configured");
    }
    ExitCode::from(decision.exit_code())
}

fn usage() -> ExitCode {
    eprintln!("usage: paykit-ready-alert [--url URL] [--state-file PATH] [--check-only]");
    ExitCode::from(2)
}

async fn fetch_and_evaluate(url: &str, state: &mut State, now: u64) -> Result<Decision, ()> {
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let ready = response.json::<Ready>().await.map_err(|_| ())?;
    let decision = evaluate(&ready, state, now)?;
    state
        .samples
        .retain(|sample| now.saturating_sub(sample.at) <= WINDOW_SECONDS);
    state.samples.push(Sample {
        at: now,
        terminal_count: ready.outbox_terminal_failure_count,
    });
    Ok(decision)
}

fn evaluate(ready: &Ready, state: &State, now: u64) -> Result<Decision, ()> {
    if ready.status != "ready"
        || ready.postgres != "ready"
        || ready.electrum.state != "ready"
        || !ready.electrum.available
        || !ready.electrum.genesis_ok
        || ready.paykit_delivery != "ready"
        || ready.outbox != "ready"
        || !ready.bitcoin_creation_enabled
        || !ready.bitcoin_offer_available
        || ready.outbox_link_establishment_max_attempts != EXPECTED_MAX_ATTEMPTS
        || ready.outbox_link_establishment_max_age_seconds != EXPECTED_MAX_AGE_SECONDS
        || !ready.outbox_terminal_failures_by_class.keys().all(|class| {
            matches!(
                class.as_str(),
                "handoff_unresolved" | "dependency_failed" | "permanently_failed"
            )
        })
    {
        return Ok(Decision::Failure);
    }
    let earliest = state
        .samples
        .iter()
        .filter(|sample| now.saturating_sub(sample.at) <= WINDOW_SECONDS)
        .map(|sample| sample.terminal_count)
        .min()
        .unwrap_or(ready.outbox_terminal_failure_count);
    let transitions = ready.outbox_terminal_failure_count.saturating_sub(earliest);
    if ready
        .outbox_oldest_terminal_failure_age_seconds
        .unwrap_or_default()
        > CRITICAL_AGE_SECONDS
        || transitions >= 5
    {
        Ok(Decision::Critical)
    } else if transitions > 0 {
        Ok(Decision::Warning)
    } else {
        Ok(Decision::Ok)
    }
}

async fn deliver(webhook: &str, decision: Decision) -> Result<(), ()> {
    reqwest::Client::new()
        .post(webhook)
        .json(&serde_json::json!({"service":"paykit-ready-alert","decision":decision.as_str()}))
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?;
    Ok(())
}

fn load_state(path: &PathBuf) -> Result<State, ()> {
    let bytes = fs::read(path).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn save_state(path: &PathBuf, state: &State) -> Result<(), ()> {
    let parent = path.parent().ok_or(())?;
    fs::create_dir_all(parent).map_err(|_| ())?;
    let encoded = serde_json::to_vec(state).map_err(|_| ())?;
    fs::write(path, encoded).map_err(|_| ())
}

fn unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> Ready {
        Ready {
            status: "ready".into(),
            stack_id: "stack".into(),
            postgres: "ready".into(),
            electrum: Electrum {
                state: "ready".into(),
                available: true,
                tip_height: Some(1),
                tip_age_secs: Some(1),
                last_probe_at: Some(1),
                genesis_ok: true,
            },
            bitcoin_creation_enabled: true,
            bitcoin_offer_available: true,
            electrum_tip_height: Some(1),
            electrum_tip_age_seconds: Some(1),
            paykit_delivery: "ready".into(),
            outbox: "ready".into(),
            outbox_terminal_failure_count: 1,
            outbox_oldest_terminal_failure_age_seconds: None,
            outbox_terminal_failures_by_class: BTreeMap::new(),
            outbox_link_establishment_max_attempts: 20,
            outbox_link_establishment_max_age_seconds: 3600,
        }
    }

    #[test]
    fn evaluates_transition_and_age_boundaries() {
        let mut report = ready();
        assert_eq!(
            evaluate(&report, &State::default(), 1_000).unwrap(),
            Decision::Ok
        );
        report.outbox_terminal_failure_count = 2;
        let state = State {
            samples: vec![Sample {
                at: 999,
                terminal_count: 1,
            }],
        };
        assert_eq!(evaluate(&report, &state, 1_000).unwrap(), Decision::Warning);
        report.outbox_terminal_failure_count = 6;
        assert_eq!(
            evaluate(&report, &state, 1_000).unwrap(),
            Decision::Critical
        );
        report.outbox_oldest_terminal_failure_age_seconds = Some(901);
        assert_eq!(
            evaluate(&report, &state, 1_000).unwrap(),
            Decision::Critical
        );
    }

    #[test]
    fn fails_closed_on_contract_drift() {
        let mut report = ready();
        report.outbox_link_establishment_max_age_seconds = 1;
        assert_eq!(
            evaluate(&report, &State::default(), 1).unwrap(),
            Decision::Failure
        );
        report.outbox_link_establishment_max_age_seconds = 3600;
        report
            .outbox_terminal_failures_by_class
            .insert("unknown".into(), 1);
        assert_eq!(
            evaluate(&report, &State::default(), 1).unwrap(),
            Decision::Failure
        );
    }
}
