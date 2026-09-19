use std::{env, process::ExitCode, sync::Arc};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use paykit_server::{
    crypto::Crypto,
    persistence::{OutboxStore, UnattributedInspection},
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const REASON: &str = "sdk_invoked_unattributed";

#[tokio::main]
async fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let list = args.as_slice() == ["--list"];
    let event_id = if list {
        None
    } else if args.len() == 2 && args[0] == "--event-id" {
        Uuid::parse_str(&args[1]).ok()
    } else {
        eprintln!("usage: paykit-inspect-unattributed (--event-id UUID | --list)");
        return ExitCode::from(2);
    };
    if !list && event_id.is_none() {
        eprintln!("invalid event id");
        return ExitCode::from(2);
    }

    let Some(database_url) = env::var("PAYKIT_READONLY_DATABASE_URL").ok() else {
        eprintln!("PAYKIT_READONLY_DATABASE_URL is required");
        return ExitCode::from(2);
    };
    let Some(master_key) = env::var("PAYKIT_MASTER_KEY").ok() else {
        eprintln!("PAYKIT_MASTER_KEY is required");
        return ExitCode::from(2);
    };
    let Ok(master_key) = URL_SAFE_NO_PAD.decode(master_key) else {
        eprintln!("PAYKIT_MASTER_KEY is invalid");
        return ExitCode::from(2);
    };
    let Ok(crypto) = Crypto::from_master_key(&master_key) else {
        eprintln!("PAYKIT_MASTER_KEY is invalid");
        return ExitCode::from(2);
    };
    let pool = match PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(_) => {
            eprintln!("inspection database unavailable");
            return ExitCode::from(1);
        }
    };
    let store = OutboxStore::new(&pool, Arc::new(crypto));
    if let Some(event_id) = event_id {
        return match store.inspect_unattributed(event_id).await {
            Ok(result) => {
                println!("inspection outcome={}", outcome(result));
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("inspection unavailable");
                ExitCode::from(1)
            }
        };
    }

    let event_ids: Result<Vec<Uuid>, _> = sqlx::query_scalar(
        "SELECT id FROM outbox_terminal_events \
         WHERE acknowledged_at IS NULL AND event_class = 'handoff_unresolved' AND reason = $1",
    )
    .bind(REASON)
    .fetch_all(&pool)
    .await;
    let Ok(event_ids) = event_ids else {
        eprintln!("inspection unavailable");
        return ExitCode::from(1);
    };
    let mut counts = [0_u64; 7];
    for event_id in event_ids {
        match store.inspect_unattributed(event_id).await {
            Ok(result) => counts[outcome_index(result)] += 1,
            Err(_) => {
                eprintln!("inspection unavailable");
                return ExitCode::from(1);
            }
        }
    }
    for (index, name) in OUTCOMES.iter().enumerate() {
        println!("inspection {name}={}", counts[index]);
    }
    ExitCode::SUCCESS
}

const OUTCOMES: [&str; 7] = [
    "not_found",
    "unique_pending",
    "unique_sent",
    "unique_terminal",
    "ambiguous",
    "already_owned",
    "indeterminate",
];

const fn outcome(result: UnattributedInspection) -> &'static str {
    OUTCOMES[outcome_index(result)]
}

const fn outcome_index(result: UnattributedInspection) -> usize {
    match result {
        UnattributedInspection::NotFound => 0,
        UnattributedInspection::UniquePending => 1,
        UnattributedInspection::UniqueSent => 2,
        UnattributedInspection::UniqueTerminal => 3,
        UnattributedInspection::Ambiguous => 4,
        UnattributedInspection::AlreadyOwned => 5,
        UnattributedInspection::Indeterminate => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_are_closed_and_identifier_free() {
        assert_eq!(OUTCOMES.len(), 7);
        assert_eq!(outcome(UnattributedInspection::UniqueSent), "unique_sent");
    }
}
