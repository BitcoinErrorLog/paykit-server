use std::{env, fs};

use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment},
    startup::initialize_database,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .init();
    let config_path =
        env::var("PAYKIT_CONFIG").map_err(|_| anyhow::anyhow!("PAYKIT_CONFIG is required"))?;
    let source = fs::read_to_string(config_path)
        .map_err(|_| anyhow::anyhow!("configuration could not be read"))?;
    let config = Config::from_toml_and_environment(
        &source,
        ConfigEnvironment {
            database_url: env::var("PAYKIT_DATABASE_URL").ok(),
            master_key: env::var("PAYKIT_MASTER_KEY").ok(),
        },
    )?;
    let pool = initialize_database(&config).await?;
    let electrum_host = url::Url::parse(&config.electrum.endpoint)
        .ok()
        .and_then(|endpoint| endpoint.host_str().map(str::to_owned))
        .unwrap_or_else(|| "<unparseable>".to_owned());
    tracing::info!(
        bitcoin_network = config.deployment_invariants().bitcoin_network.as_str(),
        stack_role = config.deployment_invariants().stack_role.as_str(),
        electrum_host = electrum_host,
        version = env!("CARGO_PKG_VERSION"),
        "deployment invariants verified; the stack role is adopted once on \
         first boot and every later boot refuses a mismatch"
    );
    let listen_addr = config.http.listen_addr.clone();
    let server = Server::build(config, pool).await?;
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    server.run(listener).await?;
    Ok(())
}
