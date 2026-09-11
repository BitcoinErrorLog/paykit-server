use std::{env, fs, process::ExitCode};

use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment},
    startup::{InitializedDatabase, initialize_database},
};

#[tokio::main]
async fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "--check-config") {
        if args.len() != 2 {
            eprintln!("usage: paykit-server --check-config <path>");
            return ExitCode::from(2);
        }
        return match load_config(&args[1]) {
            Ok(config) => {
                println!(
                    "config ok: network={} stack_role={}",
                    config.deployment_invariants().bitcoin_network.as_str(),
                    config.deployment_invariants().stack_role.as_str()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(2)
            }
        };
    }
    match run_server().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_server() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .init();
    let config_path =
        env::var("PAYKIT_CONFIG").map_err(|_| anyhow::anyhow!("PAYKIT_CONFIG is required"))?;
    let config = load_config(&config_path)?;
    let InitializedDatabase {
        pool,
        stack_identity,
    } = initialize_database(&config).await?;
    let electrum_host = url::Url::parse(&config.electrum.endpoint)
        .ok()
        .and_then(|endpoint| endpoint.host_str().map(str::to_owned))
        .unwrap_or_else(|| "<unparseable>".to_owned());
    tracing::info!(
        bitcoin_network = config.deployment_invariants().bitcoin_network.as_str(),
        stack_role = config.deployment_invariants().stack_role.as_str(),
        stack_id = stack_identity.stack_id(),
        electrum_host = electrum_host,
        version = env!("CARGO_PKG_VERSION"),
        "deployment invariants verified; the stack role is adopted once on \
         first boot and every later boot refuses a mismatch"
    );
    let listen_addr = config.http.listen_addr.clone();
    let server = Server::build(config, pool, stack_identity).await?;
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    server.run(listener).await?;
    Ok(())
}

fn load_config(path: &str) -> anyhow::Result<Config> {
    let source =
        fs::read_to_string(path).map_err(|_| anyhow::anyhow!("configuration could not be read"))?;
    Ok(Config::from_toml_and_environment(
        &source,
        ConfigEnvironment {
            database_url: env::var("PAYKIT_DATABASE_URL").ok(),
            master_key: env::var("PAYKIT_MASTER_KEY").ok(),
        },
    )?)
}
